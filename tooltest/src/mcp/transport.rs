use futures::stream::Stream;
use rmcp::model::{
    ClientJsonRpcMessage, ClientNotification, ClientRequest, InitializeRequest,
    InitializeRequestParam, InitializedNotification, NumberOrString,
};
use rmcp::RoleServer;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(super) struct NoopSink;

impl futures::Sink<rmcp::service::TxJsonRpcMessage<RoleServer>> for NoopSink {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        _item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub(super) type TestStream = rmcp::service::RxJsonRpcMessage<RoleServer>;

pub(super) struct TestStreamState {
    messages: VecDeque<TestStream>,
    panic_on_empty: bool,
}

impl TestStreamState {
    fn new(messages: Vec<TestStream>, panic_on_empty: bool) -> Self {
        Self {
            messages: VecDeque::from(messages),
            panic_on_empty,
        }
    }
}

impl Stream for TestStreamState {
    type Item = TestStream;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(message) = self.messages.pop_front() {
            return Poll::Ready(Some(message));
        }
        if self.panic_on_empty {
            panic!("test transport exhausted");
        }
        Poll::Ready(None)
    }
}

pub(super) fn stdio_test_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], false),
    )
}

pub(super) fn stdio_bad_transport() -> (NoopSink, TestStreamState) {
    (NoopSink, TestStreamState::new(Vec::new(), false))
}

pub(super) fn stdio_panic_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], true),
    )
}
