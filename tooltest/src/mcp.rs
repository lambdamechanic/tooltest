mod schema;
mod server;
mod transport;
mod worker;

#[cfg(test)]
mod tests;

pub async fn run_stdio() -> Result<(), String> {
    server::run_stdio().await
}
