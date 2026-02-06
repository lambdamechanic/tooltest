use rmcp::model::JsonObject;
use schemars::{generate::SchemaSettings, transform::AddNullable, JsonSchema};
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
    let mut settings = SchemaSettings::draft2020_12();
    settings.inline_subschemas = true;
    settings.transforms = vec![Box::new(AddNullable::default())];
    let generator = settings.into_generator();
    let schema = generator.into_root_schema_for::<T>();
    let value = serde_json::to_value(schema).expect("failed to serialize schema");
    let object: JsonObject =
        serde_json::from_value(value).expect("schema serialization produced non-object value");
    Arc::new(object)
}
