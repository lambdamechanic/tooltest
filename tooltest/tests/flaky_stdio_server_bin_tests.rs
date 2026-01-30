use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::process::{Command, Stdio};

use rmcp::model::{
    CallToolRequest, CallToolRequestParam, ClientJsonRpcMessage, ClientRequest, Extensions,
    JsonRpcRequest, JsonRpcVersion2_0, RequestId,
};
use serde_json::Value as JsonValue;
use tooltest_test_support as _;

const BUCKET_MODULO: u64 = 50;
const CRASH_BUCKET: u64 = 0;

fn hash_value(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn find_value_for_bucket(target: u64) -> String {
    for idx in 0..5000 {
        let value = format!("value-{idx}");
        if hash_value(&value) % BUCKET_MODULO == target {
            return value;
        }
    }
    panic!("no value found for bucket {target}");
}

fn call_tool_line(value: &str) -> String {
    let mut arguments = serde_json::Map::new();
    arguments.insert("value".to_string(), JsonValue::String(value.to_string()));
    let request = ClientRequest::CallToolRequest(CallToolRequest {
        method: Default::default(),
        params: CallToolRequestParam {
            name: "flaky_echo".to_string().into(),
            arguments: Some(arguments),
        },
        extensions: Extensions::default(),
    });
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(1),
        request,
    });
    serde_json::to_string(&message).expect("serialize request")
}

#[test]
fn flaky_stdio_server_crashes_on_crash_bucket() {
    let server = env!("CARGO_BIN_EXE_tooltest_flaky_stdio_server");
    let value = find_value_for_bucket(CRASH_BUCKET);
    let line = call_tool_line(&value);
    let mut child = Command::new(server)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn flaky server");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{line}").expect("write request");
    }

    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(101));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("crash bucket hit"));
}
