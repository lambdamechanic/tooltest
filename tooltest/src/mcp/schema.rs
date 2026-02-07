use rmcp::model::JsonObject;
use schemars::{generate::SchemaSettings, transform::AddNullable, JsonSchema, Schema};
use serde_json::Value as JsonValue;
use std::sync::{Arc, OnceLock};

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
    settings.transforms = vec![Box::new(AddNullable::default())];
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

    #[test]
    fn inline_schema_for_type_falls_back_on_serialize_error() {
        fn fail(_schema: Schema) -> Result<JsonValue, serde_json::Error> {
            Err(<serde_json::Error as serde::ser::Error>::custom(
                "boom",
            ))
        }

        let schema = inline_schema_for_type_inner::<tooltest_core::TooltestInput>(fail);
        assert_eq!(
            schema.get("type").and_then(|value| value.as_str()),
            Some("object")
        );
        assert!(schema.get("$comment").and_then(|value| value.as_str()).is_some());
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
}
