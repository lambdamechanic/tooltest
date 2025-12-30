use super::http_transport_config;
use crate::HttpConfig;

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
