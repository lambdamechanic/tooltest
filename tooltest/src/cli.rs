use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tooltest", version, about = "CLI wrapper for tooltest-core")]
pub struct Cli {
    /// Number of proptest cases to execute.
    #[arg(long, default_value_t = 32)]
    pub cases: u32,
    /// Minimum sequence length per generated run.
    #[arg(long, default_value_t = 1)]
    pub min_sequence_len: usize,
    /// Maximum sequence length per generated run.
    #[arg(long, default_value_t = 3)]
    pub max_sequence_len: usize,
    /// Allow schema-based generation when corpus lacks required values.
    #[arg(long)]
    pub lenient_sourcing: bool,
    /// Mine whitespace-delimited text tokens into the state corpus.
    #[arg(long)]
    pub mine_text: bool,
    /// Dump the final state-machine corpus after the run completes.
    #[arg(long)]
    pub dump_corpus: bool,
    /// Log newly mined corpus values after each tool response.
    #[arg(long)]
    pub log_corpus_deltas: bool,
    /// Disable schema-based generation when corpus lacks required values.
    #[arg(long, conflicts_with = "lenient_sourcing")]
    pub no_lenient_sourcing: bool,
    /// State-machine config as inline JSON or @path to a JSON file.
    #[arg(long, value_name = "JSON|@PATH")]
    pub state_machine_config: Option<String>,
    /// Allowlist tool names eligible for invocation generation (repeatable).
    #[arg(long = "tool-allowlist")]
    pub tool_allowlist: Vec<String>,
    /// Blocklist tool names excluded from invocation generation (repeatable).
    #[arg(long = "tool-blocklist")]
    pub tool_blocklist: Vec<String>,
    /// Fail the run when a tool result reports `isError = true`.
    /// By default, tool error responses are allowed and do not fail the run.
    #[arg(long)]
    pub in_band_error_forbidden: bool,

    /// Shell command to execute before validation and each run.
    #[arg(long)]
    pub pre_run_hook: Option<String>,
    /// Emit JSON output instead of human-readable output.
    #[arg(long)]
    pub json: bool,
    /// Include tool responses in the trace output.
    #[arg(long)]
    pub full_trace: bool,
    /// Include uncallable tool traces when coverage validation fails.
    #[arg(long)]
    pub show_uncallable: bool,
    /// Number of calls per tool to include in uncallable traces.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(usize))]
    pub uncallable_limit: usize,
    /// Emit all per-case traces to a file (JSON lines).
    #[arg(long, value_name = "PATH")]
    pub trace_all: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Run against a stdio MCP endpoint.
    Stdio {
        /// Command to execute.
        #[arg(long)]
        command: String,
        /// Command arguments (repeatable).
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Environment variables (KEY=VALUE).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Working directory.
        #[arg(long)]
        cwd: Option<String>,
    },
    /// Run against an HTTP MCP endpoint.
    Http {
        /// MCP endpoint URL.
        #[arg(long)]
        url: String,
        /// Authorization bearer token.
        #[arg(long)]
        auth_token: Option<String>,
    },
    /// Run the tooltest MCP server.
    Mcp {
        /// Use stdio transport for the MCP server (default and only supported).
        #[arg(long)]
        stdio: bool,
    },
    /// Manage tooltest configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
pub enum ConfigCommand {
    /// Emit the default tooltest.toml configuration.
    Default,
}
