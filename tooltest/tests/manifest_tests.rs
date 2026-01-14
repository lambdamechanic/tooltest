use std::fs;

fn is_publish_dependency_section(section: &str) -> bool {
    let section = section.trim();
    if section.contains("dev-dependencies") {
        return false;
    }
    section.ends_with("dependencies")
}

#[test]
fn tooltest_manifest_has_no_tooltest_test_support_publish_dependency() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let manifest_path = format!("{manifest_dir}/Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");
    let mut section = String::new();

    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains("tooltest-test-support") {
            continue;
        }
        if is_publish_dependency_section(&section) {
            panic!(
                "tooltest-test-support must not appear in publish dependencies (section: [{section}])"
            );
        }
    }
}
