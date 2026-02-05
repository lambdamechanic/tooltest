use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::lint::{LintConfigSource, LintDefinition, LintLevel, LintPhase, LintSuite};
use crate::lints::{
    CoverageLint, JsonSchemaDialectCompatLint, MaxStructuredContentBytesLint, MaxToolsLint,
    McpSchemaMinVersionLint, MissingStructuredContentLint, NoCrashLint,
};
use crate::CoverageRule;

const DEFAULT_TOOLTEST_TOML: &str = include_str!("default_tooltest.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LintConfigFile {
    #[serde(default)]
    version: Option<u32>,
    lints: Vec<LintConfigEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LintConfigEntry {
    id: String,
    level: LintLevel,
    #[serde(default)]
    params: Option<toml::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaxToolsParams {
    max: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct McpSchemaMinVersionParams {
    min_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JsonSchemaDialectCompatParams {
    allowlist: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaxStructuredContentBytesParams {
    max_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct CoverageParams {
    #[serde(default)]
    rules: Vec<CoverageRule>,
}

pub fn default_tooltest_toml() -> &'static str {
    DEFAULT_TOOLTEST_TOML
}

pub fn load_lint_suite() -> Result<LintSuite, String> {
    load_lint_suite_with_env(std::env::current_dir(), home_config_path())
}

pub(crate) fn load_lint_suite_from(
    start_dir: &Path,
    home_config: Option<&Path>,
) -> Result<LintSuite, String> {
    if let Some(path) = find_repo_config(start_dir) {
        return load_lint_suite_from_path(&path)
            .map(|suite| suite.with_source(LintConfigSource::Repo));
    }
    if let Some(path) = home_config.filter(|path| path.exists()) {
        return load_lint_suite_from_path(path)
            .map(|suite| suite.with_source(LintConfigSource::Home));
    }
    parse_lint_suite(DEFAULT_TOOLTEST_TOML).map(|suite| suite.with_source(LintConfigSource::Default))
}

fn load_lint_suite_with_env(
    cwd: Result<PathBuf, std::io::Error>,
    home_config: Option<PathBuf>,
) -> Result<LintSuite, String> {
    let cwd = cwd.map_err(|error| format!("failed to read cwd: {error}"))?;
    load_lint_suite_from(&cwd, home_config.as_deref())
}

fn load_lint_suite_from_path(path: &Path) -> Result<LintSuite, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read lint config '{}': {error}", path.display()))?;
    parse_lint_suite(&contents)
        .map_err(|error| format!("invalid lint config '{}': {error}", path.display()))
}

fn parse_lint_suite(contents: &str) -> Result<LintSuite, String> {
    let config: LintConfigFile = toml::from_str(contents).map_err(|error| format!("{error}"))?;
    let version = config.version.unwrap_or(1);
    if version != 1 {
        return Err(format!("unsupported lint config version {version}"));
    }

    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    for lint in config.lints {
        if !seen.insert(lint.id.clone()) {
            return Err(format!("duplicate lint id '{}'", lint.id));
        }
        let rule = build_lint_rule(&lint)?;
        rules.push(rule);
    }
    Ok(LintSuite::new(rules))
}

fn build_lint_rule(entry: &LintConfigEntry) -> Result<std::sync::Arc<dyn crate::LintRule>, String> {
    match entry.id.as_str() {
        "max_tools" => {
            let params: MaxToolsParams = require_params(entry, "max_tools")?;
            let definition =
                definition_with_params(entry, LintPhase::List, serde_json::to_value(&params).ok());
            Ok(std::sync::Arc::new(MaxToolsLint::new(
                definition, params.max,
            )))
        }
        "mcp_schema_min_version" => {
            let params: McpSchemaMinVersionParams =
                require_params(entry, "mcp_schema_min_version")?;
            let definition =
                definition_with_params(entry, LintPhase::List, serde_json::to_value(&params).ok());
            let lint = McpSchemaMinVersionLint::new(definition, params.min_version)?;
            Ok(std::sync::Arc::new(lint))
        }
        "json_schema_dialect_compat" => {
            let params: JsonSchemaDialectCompatParams =
                require_params(entry, "json_schema_dialect_compat")?;
            let definition =
                definition_with_params(entry, LintPhase::List, serde_json::to_value(&params).ok());
            Ok(std::sync::Arc::new(JsonSchemaDialectCompatLint::new(
                definition,
                params.allowlist,
            )))
        }
        "max_structured_content_bytes" => {
            let params: MaxStructuredContentBytesParams =
                require_params(entry, "max_structured_content_bytes")?;
            let definition = definition_with_params(
                entry,
                LintPhase::Response,
                serde_json::to_value(&params).ok(),
            );
            Ok(std::sync::Arc::new(MaxStructuredContentBytesLint::new(
                definition,
                params.max_bytes,
            )))
        }
        "missing_structured_content" => {
            reject_params(entry, "missing_structured_content")?;
            let definition = definition_with_params(entry, LintPhase::Response, None);
            Ok(std::sync::Arc::new(MissingStructuredContentLint::new(
                definition,
            )))
        }
        "coverage" => {
            let params: CoverageParams = optional_params(entry)?;
            let definition =
                definition_with_params(entry, LintPhase::Run, serde_json::to_value(&params).ok());
            let lint = CoverageLint::new(definition, params.rules)?;
            Ok(std::sync::Arc::new(lint))
        }
        "no_crash" => {
            reject_params(entry, "no_crash")?;
            let definition = definition_with_params(entry, LintPhase::Run, None);
            let lint = NoCrashLint::new(definition)?;
            Ok(std::sync::Arc::new(lint))
        }
        other => Err(format!("unknown lint id '{other}'")),
    }
}

fn definition_with_params(
    entry: &LintConfigEntry,
    phase: LintPhase,
    params: Option<serde_json::Value>,
) -> LintDefinition {
    let mut definition = LintDefinition::new(entry.id.clone(), phase, entry.level.clone());
    if let Some(params) = params {
        definition = definition.with_params(params);
    }
    definition
}

fn require_params<T: for<'de> Deserialize<'de>>(
    entry: &LintConfigEntry,
    lint_id: &str,
) -> Result<T, String> {
    let value = entry
        .params
        .clone()
        .ok_or_else(|| format!("lint '{lint_id}' missing params"))?;
    value
        .try_into()
        .map_err(|error| format!("invalid params for lint '{lint_id}': {error}"))
}

fn optional_params<T: for<'de> Deserialize<'de> + Default>(
    entry: &LintConfigEntry,
) -> Result<T, String> {
    match entry.params.clone() {
        Some(value) => value
            .try_into()
            .map_err(|error| format!("invalid params for lint '{}': {error}", entry.id)),
        None => Ok(T::default()),
    }
}

fn reject_params(entry: &LintConfigEntry, lint_id: &str) -> Result<(), String> {
    if entry.params.is_some() {
        return Err(format!("lint '{lint_id}' does not accept params"));
    }
    Ok(())
}

fn find_repo_config(start_dir: &Path) -> Option<PathBuf> {
    let git_root = find_git_root(start_dir)?;
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join("tooltest.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == git_root {
            break;
        }
        current = dir.parent();
    }
    None
}

fn find_git_root(start_dir: &Path) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

fn home_config_path() -> Option<PathBuf> {
    home_config_path_from(std::env::var_os("HOME"))
}

fn home_config_path_from(home: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let home = home?;
    Some(PathBuf::from(home).join(".config").join("tooltest.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("tooltest-lint-{name}-{pid}-{nanos}"))
    }

    fn write_config(path: &Path, contents: &str) {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).expect("create config dir");
        fs::write(path, contents).expect("write config");
    }

    fn assert_lint_present(levels: &std::collections::HashMap<&str, LintLevel>, lint: &str) {
        assert!(levels.contains_key(lint), "missing lint {lint}");
    }

    fn assert_allowlist_entry(allowlist: &std::collections::HashSet<String>, entry: &str) {
        assert!(allowlist.contains(entry), "missing allowlist entry {entry}");
    }

    #[test]
    fn repo_config_overrides_home_config() {
        let repo_root = temp_dir("repo-root");
        let nested = repo_root.join("nested");
        fs::create_dir_all(repo_root.join(".git")).expect("git dir");
        fs::create_dir_all(&nested).expect("nested");
        let repo_config = repo_root.join("tooltest.toml");
        write_config(
            &repo_config,
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = 1
"#,
        );

        let home_root = temp_dir("home");
        let home_config = home_root.join(".config").join("tooltest.toml");
        write_config(
            &home_config,
            r#"
[[lints]]
id = "missing_structured_content"
level = "warning"
"#,
        );

        let suite = load_lint_suite_from(&nested, Some(&home_config)).expect("suite");
        assert!(suite.has_enabled("max_tools"));
        assert!(!suite.has_enabled("missing_structured_content"));
        assert_eq!(suite.source(), LintConfigSource::Repo);

        let _ = fs::remove_dir_all(repo_root);
        let _ = fs::remove_dir_all(home_root);
    }

    #[test]
    fn home_config_used_when_repo_missing() {
        let root = temp_dir("home-only");
        fs::create_dir_all(&root).expect("create dir");
        let home_root = temp_dir("home-config");
        let home_config = home_root.join(".config").join("tooltest.toml");
        write_config(
            &home_config,
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = 1
"#,
        );

        let suite = load_lint_suite_from(&root, Some(&home_config)).expect("suite");
        assert!(suite.has_enabled("max_tools"));
        assert_eq!(suite.source(), LintConfigSource::Home);

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(home_root);
    }

    #[test]
    fn repo_search_stops_at_git_root() {
        let root = temp_dir("git-root");
        let repo_root = root.join("repo");
        let nested = repo_root.join("nested");
        fs::create_dir_all(repo_root.join(".git")).expect("git dir");
        fs::create_dir_all(&nested).expect("nested");
        write_config(
            &root.join("tooltest.toml"),
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = 1
"#,
        );
        assert!(find_repo_config(&nested).is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_config_uses_default() {
        let root = temp_dir("default");
        fs::create_dir_all(&root).expect("create dir");
        let suite = load_lint_suite_from(&root, None).expect("suite");
        assert!(suite.has_enabled("no_crash"));
        assert!(suite.has_enabled("mcp_schema_min_version"));
        assert!(suite.has_enabled("missing_structured_content"));
        assert_eq!(suite.source(), LintConfigSource::Default);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repo_config_ignored_without_git_root() {
        let root = temp_dir("no-git-root");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("nested");
        write_config(
            &root.join("tooltest.toml"),
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = 1
"#,
        );

        let home_root = temp_dir("no-git-home");
        let home_config = home_root.join(".config").join("tooltest.toml");
        write_config(
            &home_config,
            r#"
[[lints]]
id = "json_schema_dialect_compat"
level = "warning"
[lints.params]
allowlist = ["http://json-schema.org/draft-04/schema"]
"#,
        );

        let suite = load_lint_suite_from(&nested, Some(&home_config)).expect("suite");
        assert!(suite.has_enabled("json_schema_dialect_compat"));
        assert!(!suite.has_enabled("max_tools"));
        assert_eq!(suite.source(), LintConfigSource::Home);

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(home_root);
    }

    #[test]
    fn unknown_lint_id_rejected() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "unknown"
level = "warning"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("unknown lint id"));
    }

    #[test]
    fn duplicate_lint_id_rejected() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "error"

[[lints]]
id = "no_crash"
level = "error"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("duplicate lint id"));
    }

    #[test]
    fn invalid_level_rejected() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "nope"
"#,
        )
        .err()
        .expect("error");
        let has_unknown = error.contains("unknown variant");
        let has_invalid = error.contains("invalid");
        assert!(has_unknown | has_invalid);
    }

    #[test]
    fn unsupported_version_rejected() {
        let error = parse_lint_suite(
            r#"
version = 2
[[lints]]
id = "no_crash"
level = "error"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("unsupported lint config version"));
    }

    #[test]
    fn missing_version_defaults_to_one() {
        let suite = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "error"
"#,
        )
        .expect("suite");
        assert!(suite.has_enabled("no_crash"));
    }

    #[test]
    fn load_lint_suite_reports_missing_cwd() {
        let error = load_lint_suite_with_env(
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing cwd",
            )),
            None,
        )
        .err()
        .expect("error");
        assert!(error.contains("failed to read cwd"));
    }

    #[test]
    fn home_config_path_reads_home() {
        let temp = temp_dir("home-env");
        fs::create_dir_all(&temp).expect("create dir");
        let path = home_config_path_from(Some(temp.clone().into())).expect("home path");
        assert!(path.ends_with(".config/tooltest.toml"));
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn home_config_path_handles_missing_home() {
        assert!(home_config_path_from(None).is_none());
    }

    #[test]
    fn write_config_creates_parent_directory() {
        let root = temp_dir("write-config");
        let config_path = root.join("nested").join("tooltest.toml");
        write_config(
            &config_path,
            r#"
[[lints]]
id = "no_crash"
level = "error"
"#,
        );
        assert!(config_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_config_handles_simple_path() {
        let config_path = PathBuf::from("tooltest.toml");
        let root = temp_dir("write-relative");
        fs::create_dir_all(&root).expect("create dir");
        let full_path = root.join(&config_path);
        write_config(
            &full_path,
            r#"
[[lints]]
id = "no_crash"
level = "error"
"#,
        );
        assert!(full_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_config_handles_path_without_parent() {
        let config_path = Path::new("tooltest-temp-config.toml");
        write_config(
            config_path,
            r#"
[[lints]]
id = "no_crash"
level = "error"
"#,
        );
        assert!(config_path.exists());
        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn load_lint_suite_from_path_reports_missing_file() {
        let root = temp_dir("missing-file");
        fs::create_dir_all(&root).expect("create dir");
        let missing = root.join("tooltest.toml");
        let error = load_lint_suite_from_path(&missing).err().expect("error");
        assert!(error.contains("failed to read lint config"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_lint_suite_from_path_reports_invalid_config() {
        let root = temp_dir("invalid-config");
        fs::create_dir_all(&root).expect("create dir");
        let config_path = root.join("tooltest.toml");
        write_config(
            &config_path,
            r#"
[[lints]]
id = "unknown"
level = "warning"
"#,
        );
        let error = load_lint_suite_from_path(&config_path)
            .err()
            .expect("error");
        assert!(error.contains("invalid lint config"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parse_lint_suite_accepts_all_lints() {
        let suite = parse_lint_suite(
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = 1

[[lints]]
id = "mcp_schema_min_version"
level = "warning"
[lints.params]
min_version = "2024-01-01"

[[lints]]
id = "json_schema_dialect_compat"
level = "warning"
[lints.params]
allowlist = ["http://json-schema.org/draft-04/schema"]

[[lints]]
id = "max_structured_content_bytes"
level = "warning"
[lints.params]
max_bytes = 64

[[lints]]
id = "missing_structured_content"
level = "warning"

[[lints]]
id = "coverage"
level = "error"
[lints.params]
rules = [{ rule = "percent_called", min_percent = 0.0 }]

[[lints]]
id = "no_crash"
level = "error"
"#,
        )
        .expect("suite");
        assert!(suite.has_enabled("max_tools"));
        assert!(suite.has_enabled("mcp_schema_min_version"));
        assert!(suite.has_enabled("json_schema_dialect_compat"));
        assert!(suite.has_enabled("max_structured_content_bytes"));
        assert!(suite.has_enabled("missing_structured_content"));
        assert!(suite.has_enabled("coverage"));
        assert!(suite.has_enabled("no_crash"));
    }

    #[test]
    fn default_config_includes_required_lints_and_defaults() {
        let suite = parse_lint_suite(DEFAULT_TOOLTEST_TOML).expect("suite");
        let mut levels = std::collections::HashMap::new();
        let mut params_by_id = std::collections::HashMap::new();
        for rule in suite.rules() {
            let definition = rule.definition();
            levels.insert(definition.id.as_str(), definition.level.clone());
            if let Some(params) = definition.params.clone() {
                params_by_id.insert(definition.id.as_str(), params);
            }
        }

        let expected_lints = [
            "no_crash",
            "mcp_schema_min_version",
            "missing_structured_content",
            "max_tools",
            "json_schema_dialect_compat",
            "max_structured_content_bytes",
            "coverage",
        ];
        for lint in expected_lints {
            assert_lint_present(&levels, lint);
        }

        assert_eq!(levels["no_crash"], LintLevel::Error);
        assert_eq!(levels["mcp_schema_min_version"], LintLevel::Warning);
        assert_eq!(levels["missing_structured_content"], LintLevel::Warning);
        assert_eq!(levels["max_tools"], LintLevel::Disabled);
        assert_eq!(levels["json_schema_dialect_compat"], LintLevel::Disabled);
        assert_eq!(levels["max_structured_content_bytes"], LintLevel::Disabled);
        assert_eq!(levels["coverage"], LintLevel::Disabled);

        let allowlist = params_by_id
            .get("json_schema_dialect_compat")
            .and_then(|params| params.get("allowlist"))
            .and_then(|value| value.as_array())
            .expect("allowlist");
        let allowlist: std::collections::HashSet<_> = allowlist
            .iter()
            .filter_map(|value| value.as_str().map(|entry| entry.to_string()))
            .collect();
        let required = [
            "https://json-schema.org/draft/2020-12/schema",
            "https://json-schema.org/draft/2019-09/schema",
            "http://json-schema.org/draft-07/schema",
            "http://json-schema.org/draft-06/schema",
            "http://json-schema.org/draft-04/schema",
        ];
        for entry in required {
            assert_allowlist_entry(&allowlist, entry);
        }
    }

    #[test]
    #[should_panic(expected = "missing lint missing-lint")]
    fn assert_lint_present_panics_when_missing() {
        let levels = std::collections::HashMap::new();
        assert_lint_present(&levels, "missing-lint");
    }

    #[test]
    #[should_panic(expected = "missing allowlist entry missing-schema")]
    fn assert_allowlist_entry_panics_when_missing() {
        let allowlist = std::collections::HashSet::new();
        assert_allowlist_entry(&allowlist, "missing-schema");
    }

    #[test]
    fn parse_lint_suite_rejects_invalid_min_version() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "mcp_schema_min_version"
level = "warning"
[lints.params]
min_version = "not-a-date"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("invalid minimum protocol version"));
    }

    #[test]
    fn parse_lint_suite_rejects_invalid_coverage_rules() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "coverage"
level = "error"
[lints.params]
rules = [{ rule = "percent_called", min_percent = 101.0 }]
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("min_percent"));
    }

    #[test]
    fn parse_lint_suite_rejects_missing_params() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "max_tools"
level = "error"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("missing params"));
    }

    #[test]
    fn parse_lint_suite_rejects_missing_params_for_min_version() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "mcp_schema_min_version"
level = "warning"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("missing params"));
    }

    #[test]
    fn parse_lint_suite_rejects_missing_params_for_schema_allowlist() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "json_schema_dialect_compat"
level = "warning"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("missing params"));
    }

    #[test]
    fn parse_lint_suite_rejects_missing_params_for_structured_bytes() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "max_structured_content_bytes"
level = "warning"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("missing params"));
    }

    #[test]
    fn parse_lint_suite_rejects_params_for_missing_structured_content() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "missing_structured_content"
level = "warning"
[lints.params]
max = 1
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("does not accept params"));
    }

    #[test]
    fn parse_lint_suite_rejects_invalid_params() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "max_tools"
level = "error"
[lints.params]
max = "nope"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("invalid params"));
    }

    #[test]
    fn parse_lint_suite_rejects_invalid_optional_params() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "coverage"
level = "error"
[lints.params]
rules = "nope"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("invalid params"));
    }

    #[test]
    fn coverage_params_optional() {
        let suite = parse_lint_suite(
            r#"
[[lints]]
id = "coverage"
level = "error"
"#,
        )
        .expect("suite");
        assert!(suite.has_enabled("coverage"));
    }

    #[test]
    fn reject_params_for_no_crash() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "error"
[lints.params]
max = 1
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("does not accept params"));
    }

    #[test]
    fn fixed_severity_lint_rejected_when_not_error() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "warning"
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("no_crash lint must be configured at error level"));
    }

    #[test]
    fn coverage_params_default_when_missing() {
        let suite = parse_lint_suite(
            r#"
[[lints]]
id = "coverage"
level = "warning"
"#,
        )
        .expect("suite");
        assert!(suite.has_enabled("coverage"));
    }

    #[test]
    fn reject_params_for_fixed_severity_lint() {
        let error = parse_lint_suite(
            r#"
[[lints]]
id = "no_crash"
level = "error"
[lints.params]
foo = 1
"#,
        )
        .err()
        .expect("error");
        assert!(error.contains("does not accept params"));
    }
}
