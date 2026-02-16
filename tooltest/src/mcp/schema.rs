use rmcp::model::JsonObject;
use schemars::{generate::SchemaSettings, JsonSchema, Schema};
use serde_json::Value as JsonValue;
use std::sync::{Arc, OnceLock};

/// Recursively removes the `nullable` keyword from a JSON Schema object.
///
/// This is a workaround for rmcp upstream, which generates `nullable` keywords
/// in output schemas via `schema_for_type()`. The `nullable` keyword is not part
/// of JSON Schema 2020-12 (it's an OpenAPI 3.0 extension) and causes validation
/// failures with strict schema validators like mcporter.
///
/// TODO: Remove this workaround when rmcp fixes upstream:
/// <https://github.com/modelcontextprotocol/rust-sdk/issues/663>
pub(crate) fn strip_nullable_from_object(obj: &mut JsonObject) {
    // Remove nullable if present
    obj.remove("nullable");
    // Recursively process all values
    for value in obj.values_mut() {
        strip_nullable_from_value(value);
    }
}

fn strip_nullable_from_value(value: &mut JsonValue) {
    match value {
        JsonValue::Object(obj) => {
            strip_nullable_from_object(obj);
        }
        JsonValue::Array(arr) => {
            for item in arr {
                strip_nullable_from_value(item);
            }
        }
        _ => {}
    }
}

pub(super) fn tooltest_input_schema() -> Arc<JsonObject> {
    default_tooltest_input_schema()
}

fn default_tooltest_input_schema() -> Arc<JsonObject> {
    static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
    SCHEMA
        .get_or_init(inline_schema_for_type::<tooltest_core::TooltestInput>)
        .clone()
}

fn inline_schema_for_type<T: JsonSchema>() -> Arc<JsonObject> {
    inline_schema_for_type_inner::<T>(serde_json::to_value)
}

fn fallback_schema_object(comment: String) -> JsonObject {
    let mut object = JsonObject::new();
    object.insert("type".to_string(), JsonValue::String("object".to_string()));
    object.insert("$comment".to_string(), JsonValue::String(comment));
    object
}

fn inline_schema_for_type_inner<T: JsonSchema>(
    to_value: fn(Schema) -> Result<JsonValue, serde_json::Error>,
) -> Arc<JsonObject> {
    let mut settings = SchemaSettings::draft2020_12();
    settings.inline_subschemas = true;
    // Note: AddNullable is intentionally NOT included here. The `nullable` keyword
    // is an OpenAPI 3.0 extension, not part of JSON Schema 2020-12. Including it
    // causes validation failures with strict schema validators like mcporter.
    // See: https://github.com/modelcontextprotocol/rust-sdk/issues/663
    let generator = settings.into_generator();
    let schema = generator.into_root_schema_for::<T>();
    let value = match to_value(schema) {
        Ok(value) => value,
        Err(error) => {
            return Arc::new(fallback_schema_object(format!(
                "failed to serialize schema: {error}"
            )));
        }
    };
    let object = match value {
        JsonValue::Object(object) => object,
        _ => fallback_schema_object("schema serialization produced non-object value".to_string()),
    };
    Arc::new(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inline_schema_for_type_falls_back_on_serialize_error() {
        fn fail(_schema: Schema) -> Result<JsonValue, serde_json::Error> {
            Err(<serde_json::Error as serde::ser::Error>::custom("boom"))
        }

        let schema = inline_schema_for_type_inner::<tooltest_core::TooltestInput>(fail);
        assert_eq!(
            schema.get("type").and_then(|value| value.as_str()),
            Some("object")
        );
        assert!(schema
            .get("$comment")
            .and_then(|value| value.as_str())
            .is_some());
    }

    #[test]
    fn inline_schema_for_type_falls_back_when_value_is_not_object() {
        fn not_object(_schema: Schema) -> Result<JsonValue, serde_json::Error> {
            Ok(JsonValue::Null)
        }

        let schema = inline_schema_for_type_inner::<tooltest_core::TooltestInput>(not_object);
        assert_eq!(
            schema.get("type").and_then(|value| value.as_str()),
            Some("object")
        );
        assert_eq!(
            schema.get("$comment").and_then(|value| value.as_str()),
            Some("schema serialization produced non-object value")
        );
    }

    #[test]
    fn strip_nullable_removes_top_level_nullable() {
        let mut schema = json!({
            "type": "string",
            "nullable": true
        })
        .as_object()
        .unwrap()
        .clone();
        strip_nullable_from_object(&mut schema);
        assert!(!schema.contains_key("nullable"));
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("string"));
    }

    #[test]
    fn strip_nullable_removes_nested_nullable() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "nullable": true
                },
                "count": {
                    "type": "integer"
                }
            },
            "nullable": false
        })
        .as_object()
        .unwrap()
        .clone();
        strip_nullable_from_object(&mut schema);
        assert!(!schema.contains_key("nullable"));
        let props = schema.get("properties").unwrap().as_object().unwrap();
        let name = props.get("name").unwrap().as_object().unwrap();
        assert!(!name.contains_key("nullable"));
        let count = props.get("count").unwrap().as_object().unwrap();
        assert!(!count.contains_key("nullable"));
    }

    #[test]
    fn strip_nullable_handles_arrays() {
        let mut schema = json!({
            "anyOf": [
                {"type": "string", "nullable": true},
                {"type": "null"}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        strip_nullable_from_object(&mut schema);
        let any_of = schema.get("anyOf").unwrap().as_array().unwrap();
        let first = any_of[0].as_object().unwrap();
        assert!(!first.contains_key("nullable"));
    }

    #[test]
    fn strip_nullable_preserves_other_keys() {
        let mut schema = json!({
            "type": "string",
            "nullable": true,
            "minLength": 1,
            "description": "A string field"
        })
        .as_object()
        .unwrap()
        .clone();
        strip_nullable_from_object(&mut schema);
        assert!(!schema.contains_key("nullable"));
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("string"));
        assert_eq!(schema.get("minLength").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(
            schema.get("description").and_then(|v| v.as_str()),
            Some("A string field")
        );
    }
}
