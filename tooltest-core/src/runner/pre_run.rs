use std::process::ExitStatus;

use tokio::process::Command;

use crate::{RunConfig, RunFailure};

pub(super) async fn run_pre_run_hook(config: &RunConfig) -> Result<(), RunFailure> {
    let Some(hook) = config.pre_run_hook.as_ref() else {
        return Ok(());
    };

    let mut command = Command::new("sh");
    command.arg("-c").arg(&hook.command);
    if !hook.env.is_empty() {
        command.envs(&hook.env);
    }
    if let Some(cwd) = &hook.cwd {
        command.current_dir(cwd);
    }

    let output = command.output().await.map_err(|error| {
        pre_run_failure(
            format!("pre-run hook failed to start: {error}"),
            None,
            None,
            String::new(),
            error.to_string(),
        )
    })?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(pre_run_failure(
        "pre-run hook failed",
        output.status.code(),
        exit_signal(&output.status),
        stdout,
        stderr,
    ))
}

fn pre_run_failure(
    reason: impl Into<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
) -> RunFailure {
    RunFailure {
        reason: reason.into(),
        code: Some("pre_run_hook_failed".to_string()),
        details: Some(serde_json::json!({
            "exit_code": exit_code,
            "signal": signal,
            "stdout": stdout,
            "stderr": stderr,
        })),
    }
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}
