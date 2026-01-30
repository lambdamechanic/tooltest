#[path = "../../tests/support/flaky_stdio_server.rs"]
mod flaky_stdio_server;

fn main() {
    flaky_stdio_server::run_main();
}
