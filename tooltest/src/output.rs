use std::process::ExitCode;

use serde::Serialize;
use tooltest_core::{CoverageWarningReason, RunOutcome, RunResult, RunWarning, RunWarningCode};

pub(super) fn maybe_dump_corpus(dump_corpus: bool, json: bool, result: &RunResult) {
    if dump_corpus && !json {
        if let Some(corpus) = &result.corpus {
            let payload = serde_json::to_string_pretty(corpus)
                .unwrap_or("<failed to serialize corpus>".to_string());
            eprintln!("corpus:\n{payload}");
        }
    }
}

#[derive(Serialize)]
struct CliError<'a> {
    status: &'static str,
    message: &'a str,
}

pub(super) fn error_exit(message: &str, json: bool) -> ExitCode {
    if json {
        let payload = CliError {
            status: "error",
            message,
        };
        let output = serde_json::to_string_pretty(&payload).unwrap_or(message.to_string());
        eprintln!("{output}");
    } else {
        eprintln!("{message}");
    }
    ExitCode::from(2)
}

pub(super) fn exit_code_for_result(result: &RunResult) -> ExitCode {
    match &result.outcome {
        RunOutcome::Success => ExitCode::SUCCESS,
        RunOutcome::Failure(_) => ExitCode::from(1),
    }
}

#[cfg_attr(coverage, inline(never))]
pub(super) fn format_run_result_human(result: &RunResult) -> String {
    let mut output = String::new();
    match &result.outcome {
        RunOutcome::Success => {
            output.push_str("Outcome: success\n");
        }
        RunOutcome::Failure(failure) => {
            output.push_str("Outcome: failure\n");
            output.push_str(&format!("Reason: {}\n", failure.reason));
            if let Some(code) = &failure.code {
                output.push_str(&format!("Code: {code}\n"));
            }
            if let Some(details) = &failure.details {
                let details = serde_json::to_string_pretty(details)
                    .unwrap_or("<failed to serialize failure details>".to_string());
                output.push_str("Details:\n");
                output.push_str(&details);
                output.push('\n');
            }
        }
    }

    if let Some(coverage) = &result.coverage {
        if !coverage.warnings.is_empty() {
            output.push_str("Coverage warnings:\n");
            for warning in &coverage.warnings {
                output.push_str(&format!(
                    "- {}: {}\n",
                    warning.tool,
                    format_coverage_warning_reason(&warning.reason)
                ));
            }
        }
        if coverage.failures.values().any(|count| *count > 0) {
            output.push_str("Coverage failures:\n");
            for (tool, count) in &coverage.failures {
                if *count > 0 {
                    output.push_str(&format!("- {tool}: {count}\n"));
                }
            }
        }
        if !coverage.uncallable_traces.is_empty() {
            output.push_str("Uncallable traces:\n");
            for (tool, calls) in &coverage.uncallable_traces {
                output.push_str(&format!("- {tool}:\n"));
                if calls.is_empty() {
                    output.push_str("  (no calls)\n");
                    continue;
                }
                for call in calls {
                    output.push_str("  - timestamp: ");
                    output.push_str(&call.timestamp);
                    output.push('\n');
                    let arguments = match call.input.arguments.clone() {
                        Some(arguments) => serde_json::Value::Object(arguments),
                        None => serde_json::Value::Object(serde_json::Map::new()),
                    };
                    let args_payload = serde_json::to_string_pretty(&arguments)
                        .unwrap_or("<failed to serialize uncallable arguments>".to_string());
                    output.push_str("    arguments:\n");
                    for line in args_payload.lines() {
                        output.push_str("      ");
                        output.push_str(line);
                        output.push('\n');
                    }
                    if let Some(result) = call.output.as_ref() {
                        let output_payload = serde_json::to_string_pretty(result)
                            .unwrap_or("<failed to serialize uncallable output>".to_string());
                        output.push_str("    output:\n");
                        for line in output_payload.lines() {
                            output.push_str("      ");
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                    if let Some(result) = call.error.as_ref() {
                        let error_payload = serde_json::to_string_pretty(result)
                            .unwrap_or("<failed to serialize uncallable error>".to_string());
                        output.push_str("    error:\n");
                        for line in error_payload.lines() {
                            output.push_str("      ");
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
            }
        }
    }

    if !result.warnings.is_empty() {
        output.push_str("Warnings:\n");
        for warning in &result.warnings {
            output.push_str(&format!(
                "- {}: {}\n",
                format_run_warning_code(&warning.code),
                format_run_warning_message(warning)
            ));
        }
    }

    if !result.trace.is_empty() {
        let trace = serde_json::to_string_pretty(&result.trace)
            .unwrap_or("<failed to serialize trace>".to_string());
        output.push_str("Trace:\n");
        output.push_str(&trace);
        output.push('\n');
    }

    output
}

fn format_coverage_warning_reason(reason: &CoverageWarningReason) -> &'static str {
    match reason {
        CoverageWarningReason::MissingString => "missing_string",
        CoverageWarningReason::MissingInteger => "missing_integer",
        CoverageWarningReason::MissingNumber => "missing_number",
        CoverageWarningReason::MissingRequiredValue => "missing_required_value",
    }
}

pub(super) fn format_run_warning_code(code: &RunWarningCode) -> &str {
    code.as_str()
}

fn format_run_warning_message(warning: &RunWarning) -> String {
    if let Some(tool) = &warning.tool {
        format!("{} ({tool})", warning.message)
    } else {
        warning.message.clone()
    }
}
