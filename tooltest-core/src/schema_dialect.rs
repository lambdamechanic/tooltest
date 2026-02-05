pub const DRAFT202012: &str = "https://json-schema.org/draft/2020-12/schema";
pub const DRAFT201909: &str = "https://json-schema.org/draft/2019-09/schema";
pub const DRAFT7_HTTP: &str = "http://json-schema.org/draft-07/schema";
pub const DRAFT7_HTTPS: &str = "https://json-schema.org/draft-07/schema";
pub const DRAFT6_HTTP: &str = "http://json-schema.org/draft-06/schema";
pub const DRAFT6_HTTPS: &str = "https://json-schema.org/draft-06/schema";
pub const DRAFT4_HTTP: &str = "http://json-schema.org/draft-04/schema";
pub const DRAFT4_HTTPS: &str = "https://json-schema.org/draft-04/schema";

pub const DEFAULT_JSON_SCHEMA_DIALECT: &str = DRAFT202012;
pub(crate) const DEFAULT_SCHEMA_ID: &str = DRAFT202012;

pub(crate) fn normalize_schema_id(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed.strip_suffix('#').unwrap_or(trimmed)
}
