use std::process::ExitCode;

use clap::Parser;
use tooltest_cli::{run, Cli};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default())
        .target(env_logger::Target::Stderr)
        .init();
    let cli = Cli::parse();
    run(cli).await
}
