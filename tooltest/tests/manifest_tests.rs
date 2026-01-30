use std::fs;
use tooltest_test_support as _;

fn table_has_dep(table: &toml::value::Table, name: &str) -> bool {
    table.contains_key(name)
}

fn has_publish_dependency(value: &toml::Value, name: &str) -> bool {
    let table = match value.as_table() {
        Some(table) => table,
        None => return false,
    };

    let deps = table
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .map(|deps| table_has_dep(deps, name))
        .unwrap_or(false);
    let build_deps = table
        .get("build-dependencies")
        .and_then(toml::Value::as_table)
        .map(|deps| table_has_dep(deps, name))
        .unwrap_or(false);

    if deps || build_deps {
        return true;
    }

    let target = match table.get("target").and_then(toml::Value::as_table) {
        Some(target) => target,
        None => return false,
    };

    target.values().any(|target_table| {
        let target_table = match target_table.as_table() {
            Some(target_table) => target_table,
            None => return false,
        };
        target_table
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .map(|deps| table_has_dep(deps, name))
            .unwrap_or(false)
            || target_table
                .get("build-dependencies")
                .and_then(toml::Value::as_table)
                .map(|deps| table_has_dep(deps, name))
                .unwrap_or(false)
    })
}

#[test]
fn tooltest_manifest_has_no_tooltest_test_support_publish_dependency() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let manifest_path = format!("{manifest_dir}/Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");
    let manifest = manifest.parse::<toml::Value>().expect("parse Cargo.toml");

    assert!(
        !has_publish_dependency(&manifest, "tooltest-test-support"),
        "tooltest-test-support must not appear in publish dependencies"
    );
}
