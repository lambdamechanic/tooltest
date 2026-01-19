#[test]
fn core_readme_mentions_api_dsl_and_schema_usage() {
    let readme = include_str!("../../README.md");

    assert!(readme.contains("## Core API"));
    assert!(readme.contains("## JSON DSL"));
    assert!(readme.contains("## Schema usage"));
}
