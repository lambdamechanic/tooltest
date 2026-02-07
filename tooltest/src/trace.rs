use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tooltest_core::{TraceEntry, TraceSink};

#[derive(Clone)]
pub(super) struct TraceFileSink {
    pub(super) path: String,
    pub(super) file: Arc<Mutex<fs::File>>,
    pub(super) write_failed: Arc<AtomicBool>,
    pub(super) serialize: fn(&serde_json::Value) -> Result<String, serde_json::Error>,
}

impl TraceFileSink {
    #[cfg_attr(coverage, inline(never))]
    pub(super) fn new(path: &str) -> Result<Self, String> {
        let path = path.to_string();
        let header = r#"{"format":"trace_all_v1"}"#;
        let mut file = match fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) => return Err(format!("failed to write trace file '{path}': {error}")),
        };
        use std::io::Write;
        let header_line = format!("{header}\n");
        if let Err(error) = file.write_all(header_line.as_bytes()) {
            return Err(format!("failed to write trace file '{path}': {error}"));
        }
        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
            write_failed: Arc::new(AtomicBool::new(false)),
            serialize: serde_json::to_string
                as fn(&serde_json::Value) -> Result<String, serde_json::Error>,
        })
    }
}

impl TraceSink for TraceFileSink {
    fn record(&self, case_index: u64, trace: &[TraceEntry]) {
        let payload = serde_json::json!({
            "case": case_index,
            "trace": trace,
        });
        let line = match (self.serialize)(&payload) {
            Ok(line) => line,
            Err(error) => {
                if !self
                    .write_failed
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    eprintln!("failed to serialize trace output for '{}': {error}", self.path);
                }
                return;
            }
        };
        let mut file = match self.file.lock() {
            Ok(file) => file,
            Err(_) => return,
        };
        let result = {
            use std::io::Write;
            file.write_all(line.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
        };
        if result.is_err()
            && !self
                .write_failed
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!("failed to append trace output to '{}'", self.path);
        }
    }
}
