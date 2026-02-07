#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::process::ExitCode;

use clap::Parser;
use tooltest::{run, Cli};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();
    let cli = Cli::parse();
    run(cli).await
}
