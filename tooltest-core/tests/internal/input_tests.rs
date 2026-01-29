use std::collections::BTreeMap;

use serde_json::json;

use crate::{
    TooltestHttpTarget, TooltestInput, TooltestStdioTarget, TooltestTarget, TooltestTargetConfig,
};

fn stdio_input() -> TooltestInput {
    TooltestInput {
        target: TooltestTarget {
            stdio: Some(TooltestStdioTarget {
                command: "server".to_string(),
                args: Vec::new(),
                env: BTreeMap::new(),
                cwd: None,
            }),
            http: None,
        },
        cases: 32,
        min_sequence_len: 1,
        max_sequence_len: 3,
        lenient_sourcing: false,
        mine_text: false,
        dump_corpus: false,
        log_corpus_deltas: false,
        no_lenient_sourcing: false,
        state_machine_config: None,
        tool_allowlist: Vec::new(),
        tool_blocklist: Vec::new(),
        in_band_error_forbidden: false,
        pre_run_hook: None,
        full_trace: false,
        show_uncallable: false,
        uncallable_limit: 1,
    }
}

#[test]
fn shared_input_defaults_match_cli_defaults() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");

    let options = input.to_runner_options().expect("runner options");
    assert_eq!(options.cases, 32);
    assert_eq!(options.sequence_len, 1..=3);

    let run_config = input.to_run_config().expect("run config");
    assert!(!run_config.state_machine.lenient_sourcing);
    assert!(!run_config.state_machine.mine_text);
    assert!(!run_config.state_machine.dump_corpus);
    assert!(!run_config.state_machine.log_corpus_deltas);
    assert!(!run_config.in_band_error_forbidden);
    assert!(!run_config.full_trace);
    assert!(!run_config.show_uncallable);
    assert_eq!(run_config.uncallable_limit, 1);
    assert!(run_config.pre_run_hook.is_none());
}

#[test]
fn shared_input_validate_accepts_valid_input() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    input.validate().expect("valid input");
}

#[test]
fn shared_input_validate_rejects_invalid_sequence_len() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "min_sequence_len": 0
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.validate().unwrap_err();
    assert!(error.contains("min-sequence-len"));
}

#[test]
fn shared_input_rejects_missing_target() {
    let payload = json!({
        "cases": 10
    });
    let error = serde_json::from_value::<TooltestInput>(payload).unwrap_err();
    assert!(error.to_string().contains("target"));
}

#[test]
fn shared_input_rejects_top_level_stdio_shorthand() {
    let payload = json!({
        "stdio": { "command": "server" }
    });
    let error = serde_json::from_value::<TooltestInput>(payload).unwrap_err();
    assert!(error.to_string().contains("unknown field"));
    assert!(error.to_string().contains("stdio"));
}

#[test]
fn shared_input_rejects_empty_target() {
    let payload = json!({ "target": {} });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("target must include"));
}

#[test]
fn shared_input_rejects_multiple_transports() {
    let payload = json!({
        "target": {
            "stdio": { "command": "server" },
            "http": { "url": "http://localhost:8080/mcp" }
        }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("exactly one"));
}

#[test]
fn shared_input_rejects_invalid_http_url() {
    let payload = json!({
        "target": {
            "http": { "url": "localhost:8080/mcp" }
        }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("invalid http url"));
}

#[test]
fn shared_input_rejects_unparseable_http_url() {
    let payload = json!({
        "target": {
            "http": { "url": "http://[::1" }
        }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("invalid http url"));
}

#[test]
fn shared_input_rejects_env_list_for_stdio() {
    let payload = json!({
        "target": {
            "stdio": {
                "command": "server",
                "env": ["KEY=VALUE"]
            }
        }
    });
    let error = serde_json::from_value::<TooltestInput>(payload).unwrap_err();
    assert!(error.to_string().contains("map"));
}

#[test]
fn shared_input_rejects_env_list_for_pre_run_hook() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "pre_run_hook": {
            "command": "echo ok",
            "env": ["KEY=VALUE"]
        }
    });
    let error = serde_json::from_value::<TooltestInput>(payload).unwrap_err();
    assert!(error.to_string().contains("map"));
}

#[test]
fn shared_input_rejects_invalid_sequence_len() {
    let mut input = stdio_input();
    input.min_sequence_len = 0;
    let error = input.to_runner_options().unwrap_err();
    assert!(error.contains("min-sequence-len"));
}

#[test]
fn shared_input_rejects_inverted_sequence_len() {
    let mut input = stdio_input();
    input.min_sequence_len = 4;
    input.max_sequence_len = 2;
    let error = input.to_runner_options().unwrap_err();
    assert!(error.contains("min-sequence-len"));
}

#[test]
fn shared_input_rejects_uncallable_limit_under_one() {
    let mut input = stdio_input();
    input.uncallable_limit = 0;
    let error = input.to_run_config().unwrap_err();
    assert!(error.contains("uncallable-limit"));
}

#[test]
fn shared_input_run_config_rejects_invalid_target() {
    let payload = json!({ "target": {} });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_run_config().unwrap_err();
    assert!(error.contains("target"));
}

#[test]
fn shared_input_applies_state_machine_overrides() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "state_machine_config": {
            "lenient_sourcing": false,
            "mine_text": false,
            "dump_corpus": false,
            "log_corpus_deltas": false,
            "seed_numbers": [1],
            "seed_strings": ["seed"],
            "coverage_rules": []
        },
        "lenient_sourcing": true,
        "mine_text": true
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let run_config = input.to_run_config().expect("run config");
    assert!(run_config.state_machine.lenient_sourcing);
    assert!(run_config.state_machine.mine_text);
}

#[test]
fn shared_input_applies_dump_and_log_flags() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "dump_corpus": true,
        "log_corpus_deltas": true
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let run_config = input.to_run_config().expect("run config");
    assert!(run_config.state_machine.dump_corpus);
    assert!(run_config.state_machine.log_corpus_deltas);
}

#[test]
fn shared_input_applies_no_lenient_override() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "state_machine_config": {
            "lenient_sourcing": true,
            "seed_numbers": [],
            "seed_strings": [],
            "coverage_rules": []
        },
        "no_lenient_sourcing": true
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let run_config = input.to_run_config().expect("run config");
    assert!(!run_config.state_machine.lenient_sourcing);
}

#[test]
fn shared_input_rejects_lenient_conflict() {
    let mut input = stdio_input();
    input.lenient_sourcing = true;
    input.no_lenient_sourcing = true;
    let error = input.validate().unwrap_err();
    assert!(error.contains("lenient-sourcing"));
}

#[test]
fn shared_input_builds_tool_filters() {
    let mut input = stdio_input();
    input.tool_allowlist = vec!["foo".to_string()];
    input.tool_blocklist = vec!["bar".to_string()];

    let run_config = input.to_run_config().expect("run config");
    let predicate = run_config.predicate.expect("predicate");
    let name_predicate = run_config.tool_filter.expect("name predicate");

    assert!(predicate("foo", &json!({})), "foo should pass");
    assert!(!predicate("bar", &json!({})), "bar should be blocked");
    assert!(!predicate("baz", &json!({})), "baz should be filtered");

    assert!(name_predicate("foo"));
    assert!(!name_predicate("bar"));
    assert!(!name_predicate("baz"));
}

#[test]
fn shared_input_builds_allowlist_only_filter() {
    let mut input = stdio_input();
    input.tool_allowlist = vec!["foo".to_string()];

    let run_config = input.to_run_config().expect("run config");
    let predicate = run_config.predicate.expect("predicate");
    let name_predicate = run_config.tool_filter.expect("name predicate");

    assert!(predicate("foo", &json!({})));
    assert!(!predicate("bar", &json!({})));
    assert!(name_predicate("foo"));
    assert!(!name_predicate("bar"));
}

#[test]
fn shared_input_builds_blocklist_only_filter() {
    let mut input = stdio_input();
    input.tool_blocklist = vec!["bar".to_string()];

    let run_config = input.to_run_config().expect("run config");
    let predicate = run_config.predicate.expect("predicate");
    let name_predicate = run_config.tool_filter.expect("name predicate");

    assert!(predicate("foo", &json!({})));
    assert!(!predicate("bar", &json!({})));
    assert!(name_predicate("foo"));
    assert!(!name_predicate("bar"));
}

#[test]
fn shared_input_builds_target_config() {
    let input = stdio_input();
    let config = input.to_target_config().expect("target");
    match config {
        TooltestTargetConfig::Stdio(stdio) => {
            assert_eq!(stdio.command, "server");
        }
        TooltestTargetConfig::Http(_) => panic!("unexpected http config"),
    }

    let http_payload = json!({
        "target": {
            "http": { "url": "http://localhost:8080/mcp", "auth_token": "Bearer token" }
        }
    });
    let input: TooltestInput = serde_json::from_value(http_payload).expect("input");
    let config = input.to_target_config().expect("target");
    match config {
        TooltestTargetConfig::Http(http) => {
            assert_eq!(http.url, "http://localhost:8080/mcp");
            assert_eq!(http.auth_token.as_deref(), Some("Bearer token"));
        }
        TooltestTargetConfig::Stdio(_) => panic!("unexpected stdio config"),
    }
}

#[test]
fn shared_input_accepts_http_target_struct() {
    let input = TooltestInput {
        target: TooltestTarget {
            stdio: None,
            http: Some(TooltestHttpTarget {
                url: "http://localhost:8080/mcp".to_string(),
                auth_token: None,
            }),
        },
        ..stdio_input()
    };

    let config = input.to_target_config().expect("target");
    match config {
        TooltestTargetConfig::Http(http) => {
            assert_eq!(http.url, "http://localhost:8080/mcp");
        }
        TooltestTargetConfig::Stdio(_) => panic!("unexpected stdio config"),
    }
}

#[test]
fn shared_input_rejects_empty_stdio_command() {
    let payload = json!({
        "target": { "stdio": { "command": "   " } }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("stdio command"));
}

#[test]
fn shared_input_rejects_url_without_host() {
    let payload = json!({
        "target": { "http": { "url": "file:///tmp/mcp" } }
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_target_config().unwrap_err();
    assert!(error.contains("missing host"));
}

#[test]
fn shared_input_applies_pre_run_hook_and_flags() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "pre_run_hook": {
            "command": "echo ok",
            "env": { "KEY": "VALUE" },
            "cwd": "/tmp"
        },
        "in_band_error_forbidden": true,
        "full_trace": true,
        "show_uncallable": true,
        "uncallable_limit": 2
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let run_config = input.to_run_config().expect("run config");
    assert!(run_config.in_band_error_forbidden);
    assert!(run_config.full_trace);
    assert!(run_config.show_uncallable);
    assert_eq!(run_config.uncallable_limit, 2);
    let hook = run_config.pre_run_hook.expect("hook");
    assert_eq!(hook.command, "echo ok");
    assert_eq!(hook.env.get("KEY").map(String::as_str), Some("VALUE"));
    assert_eq!(hook.cwd.as_deref(), Some("/tmp"));
}

#[test]
fn shared_input_to_configs_builds_all_parts() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "cases": 10,
        "min_sequence_len": 2,
        "max_sequence_len": 4
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let config = input.to_configs().expect("configs");
    match config.target {
        TooltestTargetConfig::Stdio(stdio) => assert_eq!(stdio.command, "server"),
        TooltestTargetConfig::Http(_) => panic!("unexpected http config"),
    }
    assert_eq!(config.runner_options.cases, 10);
    assert_eq!(config.runner_options.sequence_len, 2..=4);
}

#[test]
fn shared_input_to_configs_rejects_invalid_input() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "min_sequence_len": 0
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_configs().unwrap_err();
    assert!(error.contains("min-sequence-len"));
}

#[test]
fn shared_input_to_configs_rejects_run_config_error() {
    let payload = json!({
        "target": { "stdio": { "command": "server" } },
        "lenient_sourcing": true,
        "no_lenient_sourcing": true
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_configs().unwrap_err();
    assert!(error.contains("lenient-sourcing"));
}

#[test]
fn shared_input_to_configs_rejects_invalid_target() {
    let payload = json!({
        "target": {}
    });
    let input: TooltestInput = serde_json::from_value(payload).expect("input");
    let error = input.to_configs().unwrap_err();
    assert!(error.contains("target"));
}
