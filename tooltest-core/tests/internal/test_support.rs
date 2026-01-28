use crate::{SessionDriver, SessionError};
use tooltest_test_support::{ListToolsTransport, RunnerTransport};

pub async fn connect_runner_transport(
    transport: RunnerTransport,
) -> Result<SessionDriver, SessionError> {
    SessionDriver::connect_with_transport::<
        RunnerTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}

pub async fn connect_list_tools_transport(
    transport: ListToolsTransport,
) -> Result<SessionDriver, SessionError> {
    SessionDriver::connect_with_transport::<
        ListToolsTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}
