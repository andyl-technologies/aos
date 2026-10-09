//! Passive, opt-in export of bounded records from the fixture-owned stderr FD.
//!
//! Copied rows remain advisory. Neither producer stages nor nearby byte offsets
//! authenticate a completed quantum, guest setup, or native operation receipt.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INTERVAL: Duration = Duration::from_secs(5);
const MAX_CYCLE_BYTES: u64 = 512 * 1024;
const MAX_RECORD_BYTES: usize = 4096;
const MAX_KEYS: usize = 32;
const MAX_FRAME_BYTES: usize = 2048;
const MAX_PERIODIC_FRAMES: usize = 900;
const MAX_TERMINAL_FRAMES: usize = 4;
const MAX_TOTAL_BYTES: usize = (MAX_PERIODIC_FRAMES + MAX_TERMINAL_FRAMES) * MAX_FRAME_BYTES;
const PREFIXES: [&str; 5] = [
    "CRUCIBLE-RUNTIME-PROGRESS-V1",
    "CRUCIBLE-RUNTIME-BOOT-V1",
    "CRUCIBLE-EXACT-RESUME-PROGRESS-V1",
    "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1",
    "CRUCIBLE-HOST-WAIT-V1",
];

/// One flight-wide file and quota, shared across owned service restarts.
pub(super) struct ProgressOutput {
    state: Mutex<OutputState>,
}

struct OutputState {
    file: File,
    periodic: usize,
    terminal: usize,
    bytes: usize,
}

impl ProgressOutput {
    pub(super) fn from_environment() -> io::Result<Option<Arc<Self>>> {
        // Disabled tests neither open files nor start threads or sample time.
        let enabled = std::env::var_os("CRUCIBLE_TEST_LIVE_PROGRESS").as_deref()
            == Some(std::ffi::OsStr::new("1"));
        if !enabled {
            return Ok(None);
        }
        let path = std::env::var_os("CRUCIBLE_TEST_LIVE_PROGRESS_FILE");
        Self::configured(enabled, path.as_deref())
    }

    fn configured(enabled: bool, path: Option<&std::ffi::OsStr>) -> io::Result<Option<Arc<Self>>> {
        if !enabled {
            return Ok(None);
        }
        let path = path.ok_or_else(|| io::Error::other("live progress output path is missing"))?;
        Self::create(Path::new(path)).map(Some)
    }

    fn create(path: &Path) -> io::Result<Arc<Self>> {
        // Exclusive creation rejects existing files and symlink targets. This
        // file is owned by this fixture, never discovered from a directory.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(Arc::new(Self {
            state: Mutex::new(OutputState {
                file,
                periodic: 0,
                terminal: 0,
                bytes: 0,
            }),
        }))
    }

    fn emit(&self, mut frame: Value, terminal: bool) -> io::Result<()> {
        let mut encoded = serde_json::to_vec(&frame).map_err(io::Error::other)?;
        if encoded.len() + 1 > MAX_FRAME_BYTES {
            let record = frame["record"].take();
            let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
            frame["record_unavailable"] = json!({
                "reason": "encoded-frame-limit",
                "encoded_bytes": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(&bytes)),
            });
            encoded = serde_json::to_vec(&frame).map_err(io::Error::other)?;
        }
        if encoded.len() + 1 > MAX_FRAME_BYTES {
            return Err(io::Error::other("bounded progress frame exceeds limit"));
        }
        encoded.push(b'\n');
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("progress sink poisoned"))?;
        if (terminal && state.terminal >= MAX_TERMINAL_FRAMES)
            || (!terminal && state.periodic >= MAX_PERIODIC_FRAMES)
        {
            return Ok(());
        }
        if state.bytes.saturating_add(encoded.len()) > MAX_TOTAL_BYTES {
            return Err(io::Error::other("flight progress byte quota exhausted"));
        }
        // Reserve before IO: an error cannot cause repeated writes past quota.
        if terminal {
            state.terminal += 1;
        } else {
            state.periodic += 1;
        }
        state.bytes += encoded.len();
        state.file.write_all(&encoded)
    }
}

struct Record {
    line: String,
    offset: u64,
    observed: Instant,
}

#[derive(Default)]
struct Records {
    partial: Vec<u8>,
    partial_start: u64,
    skipping: bool,
    offset: u64,
    generation: u64,
    malformed: u64,
    oversized: u64,
    omitted_keys: u64,
    unrelated: u64,
    rows: BTreeMap<String, Record>,
    next_key: usize,
}

impl Records {
    fn ingest(&mut self, bytes: &[u8], now: Instant) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.skipping {
                    self.finish_line(now);
                }
                self.partial.clear();
                self.skipping = false;
                self.partial_start = self.offset + 1;
            } else if !self.skipping {
                if self.partial.len() < MAX_RECORD_BYTES {
                    self.partial.push(byte);
                } else {
                    self.oversized = self.oversized.saturating_add(1);
                    self.partial.clear();
                    self.skipping = true;
                }
            }
            self.offset = self.offset.saturating_add(1);
        }
    }

    fn finish_line(&mut self, now: Instant) {
        let Ok(line) = std::str::from_utf8(&self.partial) else {
            self.malformed = self.malformed.saturating_add(1);
            return;
        };
        let Some(prefix) = PREFIXES.iter().find(|prefix| {
            line.strip_prefix(**prefix)
                .is_some_and(|suffix| suffix.starts_with(' '))
        }) else {
            self.unrelated = self.unrelated.saturating_add(1);
            return;
        };
        // Keep producer stage separately: a newer before row cannot be hidden
        // by a cached older after row. Keys are source text, not guest identity.
        let key = format!("{}|{}|{}", prefix, field(line, "stage"), source_key(line));
        if !self.rows.contains_key(&key) && self.rows.len() >= MAX_KEYS {
            self.omitted_keys = self.omitted_keys.saturating_add(1);
            return;
        }
        self.rows.insert(
            key,
            Record {
                line: line.to_owned(),
                offset: self.partial_start,
                observed: now,
            },
        );
    }

    fn sample(&mut self, now: Instant) -> Value {
        let record = if self.rows.is_empty() {
            Value::Null
        } else {
            let index = self.next_key % self.rows.len();
            self.next_key = self.next_key.wrapping_add(1);
            let (key, record) = self.rows.iter().nth(index).expect("bounded cache index");
            json!({
                "key": key,
                "source_offset": record.offset,
                "observed_age_ms": now.saturating_duration_since(record.observed).as_millis(),
                "producer_age": "unknown",
                "line": record.line,
            })
        };
        json!({
            "record": record,
            "cursor": self.offset,
            "source_generation": self.generation,
            "partial_bytes": self.partial.len(),
            "partial_oversized": self.skipping,
            "malformed": self.malformed,
            "oversized": self.oversized,
            "omitted_keys": self.omitted_keys,
            "unrelated": self.unrelated,
            "retained_keys": self.rows.len(),
        })
    }

    fn truncated(&mut self) {
        let generation = self.generation.saturating_add(1);
        *self = Self {
            generation,
            ..Self::default()
        };
    }
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_ascii_whitespace()
        .find_map(|token| {
            token
                .strip_prefix(name)
                .and_then(|suffix| suffix.strip_prefix('='))
        })
        .unwrap_or("unavailable")
}

fn source_key(line: &str) -> &str {
    // Debug-quoted node names are copied whole when present. No interpretation
    // of a quoted name supplies authority or a canonical protocol identity.
    if let Some((_, suffix)) = line.split_once(" node=")
        && suffix.starts_with('"')
    {
        let mut escaped = false;
        for (index, character) in suffix.char_indices().skip(1) {
            if character == '"' && !escaped {
                return &suffix[..=index];
            }
            escaped = character == '\\' && !escaped;
        }
        return "unavailable";
    }
    let node = field(line, "node");
    if node != "unavailable" {
        node
    } else {
        field(line, "slot")
    }
}

enum ObserverCommand {
    Stop(String),
    // Tests request a real owned-FD cycle deterministically, without sleeping
    // or changing the production cadence used by fixture start/stop callers.
    Sample(mpsc::Sender<()>),
}

/// Owns exactly one reader thread; stop and Drop both wake and join it.
pub(super) struct OwnedProgressObserver {
    control: mpsc::Sender<ObserverCommand>,
    worker: Option<JoinHandle<()>>,
}

impl OwnedProgressObserver {
    pub(super) fn start(
        mut source: File,
        service_pid: u32,
        output: Arc<ProgressOutput>,
    ) -> io::Result<Self> {
        let metadata = source.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other(
                "owned service stderr is not a regular file",
            ));
        }
        source.seek(SeekFrom::Start(0))?;
        let identity = (metadata.dev(), metadata.ino());
        let (control, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("flight-stderr-progress".into())
            .spawn(move || {
                run_observer(source, service_pid, identity, output, receiver);
            })?;
        Ok(Self {
            control,
            worker: Some(worker),
        })
    }

    pub(super) fn stop(&mut self, reason: &str) {
        if let Some(worker) = self.worker.take() {
            let _ = self
                .control
                .send(ObserverCommand::Stop(reason.chars().take(160).collect()));
            // Observer failures are diagnostic only. The caller retains its
            // original service status and cleanup result regardless of join.
            let _ = worker.join();
        }
    }
}

impl Drop for OwnedProgressObserver {
    fn drop(&mut self) {
        self.stop("fixture-observer-drop;service-status-not-inferred");
    }
}

fn run_observer(
    mut source: File,
    service_pid: u32,
    identity: (u64, u64),
    output: Arc<ProgressOutput>,
    receiver: mpsc::Receiver<ObserverCommand>,
) {
    let mut records = Records::default();
    loop {
        let (terminal, acknowledgment) = match receiver.recv_timeout(INTERVAL) {
            Ok(ObserverCommand::Stop(reason)) => (Some(reason), None),
            Ok(ObserverCommand::Sample(acknowledgment)) => (None, Some(acknowledgment)),
            Err(mpsc::RecvTimeoutError::Timeout) => (None, None),
            Err(mpsc::RecvTimeoutError::Disconnected) => (Some("owner-disconnected".into()), None),
        };
        let cycle = read_cycle(&mut source, &mut records);
        let mut frame = records.sample(Instant::now());
        frame["format"] = json!("CRUCIBLE-TEST-LIVE-PROGRESS-V1");
        frame["advisory"] = json!(true);
        frame["authentication"] = json!("none;producer-stages-are-not-completion-receipts");
        frame["service_pid"] = json!(service_pid);
        frame["source_device"] = json!(identity.0);
        frame["source_inode"] = json!(identity.1);
        frame["producer_budget_remaining"] = json!("unknown");
        match &cycle {
            Ok(backlog) => frame["unread_bytes"] = json!(backlog),
            Err(error) => frame["observer_io_error"] = json!(error.to_string()),
        }
        if let Some(reason) = &terminal {
            // SIGKILL is not labeled OOM; only separately retained matching
            // kernel evidence can support that diagnosis.
            frame["terminal_reason"] = json!(reason);
        }
        let emitted = output.emit(frame, terminal.is_some());
        if let Some(acknowledgment) = acknowledgment {
            let _ = acknowledgment.send(());
        }
        if terminal.is_some() || cycle.is_err() || emitted.is_err() {
            break;
        }
    }
}

fn read_cycle(source: &mut File, records: &mut Records) -> io::Result<u64> {
    let length = source.metadata()?.len();
    if length < records.offset {
        source.seek(SeekFrom::Start(0))?;
        records.truncated();
    }
    // Freeze the length: a continuously writing service cannot extend a cycle.
    let admitted = length.saturating_sub(records.offset).min(MAX_CYCLE_BYTES);
    let mut remaining = admitted;
    let mut buffer = [0_u8; 8192];
    let now = Instant::now();
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = source.read(&mut buffer[..maximum])?;
        if read == 0 {
            break;
        }
        records.ingest(&buffer[..read], now);
        remaining -= read as u64;
    }
    Ok(length.saturating_sub(records.offset))
}

#[cfg(test)]
#[path = "service_progress_tests.rs"]
mod tests;
