use std::collections::BTreeMap;
use std::fs;

use tooltest_core::{
    StateMachineConfig, TooltestHttpTarget, TooltestInput, TooltestPreRunHook, TooltestStdioTarget,
    TooltestTarget, TooltestTargetHttp, TooltestTargetStdio,
};

use crate::cli::{Cli, Command};

pub fn parse_env_vars(entries: Vec<String>) -> Result<BTreeMap<String, String>, String> {
    let mut env = BTreeMap::new();
    for entry in entries {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid env entry: '{entry}'"))?;
        if key.is_empty() {
            return Err(format!("invalid env entry: '{entry}'"));
        }
        env.insert(key.to_string(), value.to_string());
    }
    Ok(env)
}

pub fn parse_state_machine_config(raw: &str) -> Result<StateMachineConfig, String> {
    let payload = if let Some(path) = raw.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|error| format!("failed to read state-machine-config: {error}"))?
    } else {
        raw.to_string()
    };
    let input: StateMachineConfig = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid state-machine-config: {error}"))?;
    Ok(input)
}

pub(super) fn build_tooltest_input(cli: &Cli) -> Result<TooltestInput, String> {
    let state_machine_config = match cli.state_machine_config.as_deref() {
        Some(raw) => Some(parse_state_machine_config(raw)?),
        None => None,
    };
    let pre_run_hook = cli.pre_run_hook.as_ref().map(|command| TooltestPreRunHook {
        command: command.clone(),
        env: BTreeMap::new(),
        cwd: None,
    });
    let target = match &cli.command {
        Command::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            let env = parse_env_vars(env.clone())?;
            TooltestTarget::Stdio(TooltestTargetStdio {
                stdio: TooltestStdioTarget {
                    command: command.clone(),
                    args: args.clone(),
                    env,
                    cwd: cwd.clone(),
                },
            })
        }
        Command::Http { url, auth_token } => TooltestTarget::Http(TooltestTargetHttp {
            http: TooltestHttpTarget {
                url: url.clone(),
                auth_token: auth_token.clone(),
            },
        }),
        Command::Mcp { .. } => return Err("mcp command does not accept tooltest input".to_string()),
        Command::Config { .. } => {
            return Err("config command does not accept tooltest input".to_string())
        }
    };
    Ok(TooltestInput {
        target,
        cases: cli.cases,
        min_sequence_len: cli.min_sequence_len,
        max_sequence_len: cli.max_sequence_len,
        lenient_sourcing: cli.lenient_sourcing,
        mine_text: cli.mine_text,
        dump_corpus: cli.dump_corpus,
        log_corpus_deltas: cli.log_corpus_deltas,
        no_lenient_sourcing: cli.no_lenient_sourcing,
        state_machine_config,
        tool_allowlist: cli.tool_allowlist.clone(),
        tool_blocklist: cli.tool_blocklist.clone(),
        in_band_error_forbidden: cli.in_band_error_forbidden,
        pre_run_hook,
        full_trace: cli.full_trace,
        show_uncallable: cli.show_uncallable,
        uncallable_limit: cli.uncallable_limit,
    })
}
