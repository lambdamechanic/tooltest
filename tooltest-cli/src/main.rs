use std::process::ExitCode;

use clap::Parser;
use tooltest_cli::{run, Cli};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli).await
}
