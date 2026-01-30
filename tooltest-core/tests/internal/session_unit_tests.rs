use super::{http_transport_config, log_io, log_io_message};
use crate::HttpConfig;
use std::sync::Once;

struct TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, _record: &log::Record<'_>) {}

    fn flush(&self) {}
}

fn init_logger() {
    static INIT: Once = Once::new();
    static LOGGER: TestLogger = TestLogger;
    INIT.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Debug);
    });
}

#[test]
fn http_transport_config_strips_bearer_prefix() {
    let config = HttpConfig {
        url: "https://example.com/mcp".to_string(),
        auth_token: Some("Bearer test-token".to_string()),
    };
    let transport_config = http_transport_config(&config);
    assert_eq!(transport_config.auth_header.as_deref(), Some("test-token"));
}

#[test]
fn http_transport_config_preserves_raw_token() {
    let config = HttpConfig {
        url: "https://example.com/mcp".to_string(),
        auth_token: Some("raw-token".to_string()),
    };
    let transport_config = http_transport_config(&config);
    assert_eq!(transport_config.auth_header.as_deref(), Some("raw-token"));
}

#[test]
fn http_transport_config_skips_missing_token() {
    let config = HttpConfig {
        url: "https://example.com/mcp".to_string(),
        auth_token: None,
    };
    let transport_config = http_transport_config(&config);
    assert!(transport_config.auth_header.is_none());
}

#[test]
fn log_io_message_emits_with_debug_logger() {
    init_logger();
    log_io_message("tooltest io log");
}

#[test]
fn log_io_serializes_payload() {
    init_logger();
    log_io("label", &serde_json::json!({"ok": true}));
}

#[test]
fn log_io_handles_serialize_error() {
    init_logger();
    struct BrokenSerialize;
    impl serde::Serialize for BrokenSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    log_io("label", &BrokenSerialize);
}
