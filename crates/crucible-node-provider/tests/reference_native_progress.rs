//! Actual positive native work with a separately held completion response.
//!
//! These component tests authenticate the native socket peer and original
//! commands. They do not qualify a public provider or mint runtime authority.

// crucible-lint: allow panic-shortcut -- Authentic native fixture failures must fail the test
// crucible-lint: allow rust-allow -- Authentic native fixture failures must fail the test
#![allow(
    clippy::unwrap_used,
    reason = "Authentic native fixture failures must fail the test"
)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crucible_node_contract::{Id, Phase, Position, U64, canonical};
use crucible_node_provider::reference_device::{DeviceGrant, NativeProgressRecord};
use crucible_node_provider::transport::{FrameReader, write_frame};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde_json::{Value, json};

const FRAME_BYTES: usize = 65_536;

struct NativeFixture {
    child: Child,
    directory: PathBuf,
    control: UnixStream,
    progress: UnixStream,
    reaped: bool,
}

impl NativeFixture {
    fn spawn() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("native-progress-{}-{sequence}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let control_path = directory.join("native.sock");
        let progress_path = directory.join("progress.sock");
        let control_listener = UnixListener::bind(&control_path).unwrap();
        let progress_listener = UnixListener::bind(&progress_path).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_crucible-reference-progress-device"))
            .args([&control_path, &progress_path])
            .env_clear()
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut pending = PendingChild {
            child: Some(child),
            directory: directory.clone(),
        };
        let original_pid = pending.child.as_ref().unwrap().id();
        let control = accept_original(&control_listener, original_pid);
        let progress = accept_original(&progress_listener, original_pid);

        Self {
            child: pending.child.take().unwrap(),
            directory,
            control,
            progress,
            reaped: false,
        }
    }

    fn exchange(&mut self, request: &Value) -> Value {
        write_frame(&mut self.control, request, FRAME_BYTES).unwrap();
        FrameReader::new(&mut self.control, FRAME_BYTES)
            .unwrap()
            .read()
            .unwrap()
            .unwrap()
    }

    fn initialize_and_acknowledge_zero_window(&mut self) -> (Value, Value) {
        let initialize = json!({"command":"initialize","owner":"progress-owner","incarnation":"progress-child","generation":"1"});
        let ready = self.exchange(&initialize);
        assert_eq!(ready["child_pid"], self.child.id().to_string());
        let first = grant(0);
        self.exchange(&json!({"command":"stage","grant":first,"input":[]}));
        let completed = self.exchange(&json!({"command":"activate","window":first.window_id}));
        assert_eq!(completed["output"]["checksum"], "0");
        let closed = self.exchange(&json!({"command":"close","window":first.window_id}));
        assert_eq!(closed["application_parked"], true);
        self.exchange(&json!({"command":"acknowledge","window":first.window_id}));
        (initialize, ready)
    }

    fn start_original_positive_window(&mut self) -> (NativeProgressRecord, Value, Value) {
        self.initialize_and_acknowledge_zero_window();
        let input = br#"{"bytes_processed":"0","checksum":"0"}"#.to_vec();
        assert_eq!(input.len(), 38);
        let stage = json!({"command":"stage","grant":grant(1),"input":input});
        assert_eq!(self.exchange(&stage)["result"], "staged");
        let activate = json!({"command":"activate","window":grant(1).window_id});
        write_frame(&mut self.control, &activate, FRAME_BYTES).unwrap();
        let record = FrameReader::new(&mut self.progress, FRAME_BYTES)
            .unwrap()
            .read()
            .unwrap()
            .unwrap();
        let record: NativeProgressRecord = serde_json::from_value(record).unwrap();
        assert_eq!(record.child_pid.get(), u64::from(self.child.id()));
        assert_eq!(
            record.stage_request.as_slice(),
            canonical::canonical_json(&stage).unwrap()
        );
        assert_eq!(
            record.activate_request.as_slice(),
            canonical::canonical_json(&activate).unwrap()
        );
        assert_eq!(record.grant, grant(1));
        assert_eq!(record.consumed_prefix.get(), 1);
        assert_eq!(record.checksum_before_window.get(), 0);
        assert_eq!(record.checksum_after_prefix.get(), u64::from(input[0]));
        let predecessor = record.predecessor.0.as_ref().unwrap();
        let closed =
            canonical::parse_json(predecessor.close_response.as_slice(), FRAME_BYTES).unwrap();
        assert_eq!(closed["grant"], serde_json::to_value(grant(0)).unwrap());
        assert_eq!(
            closed["output"],
            json!({"bytes_processed":"0","checksum":"0"})
        );
        assert_eq!(closed["application_parked"], true);
        assert!(self.child.try_wait().unwrap().is_none());
        (record, stage, activate)
    }

    fn assert_completion_held(&mut self) {
        let mut descriptors = [PollFd::new(&self.control, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        // The deadline checks native transport availability, never modeled time.
        assert_eq!(poll(&mut descriptors, Some(&timeout)).unwrap(), 0);
    }

    fn reap(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.reaped = true;
        assert!(self.child.try_wait().unwrap().is_some());
    }
}

impl Drop for NativeFixture {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct PendingChild {
    child: Option<Child>,
    directory: PathBuf,
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn accept_original(listener: &UnixListener, original_pid: u32) -> UnixStream {
    let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 3,
        tv_nsec: 0,
    };
    assert_eq!(poll(&mut descriptors, Some(&timeout)).unwrap(), 1);
    let (stream, _) = listener.accept().unwrap();
    let credentials = rustix::net::sockopt::socket_peercred(&stream).unwrap();
    assert_eq!(credentials.pid.as_raw_nonzero().get(), original_pid as i32);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}

fn grant(index: u64) -> DeviceGrant {
    DeviceGrant {
        owner_id: Id::new("progress-owner").unwrap(),
        incarnation_id: Id::new("progress-child").unwrap(),
        generation: U64::new(1),
        window_id: Id::new(format!("progress-window/{index}")).unwrap(),
        input_batch_id: Id::new(format!("progress-input/{index}")).unwrap(),
        quantum: U64::new(index),
        start: Position::new(U64::new(index * 1000), U64::new(0), Phase::Delivery),
        publication: Position::new(
            U64::new((index + 1) * 1000),
            U64::new(0),
            Phase::Publication,
        ),
        host_budget_ns: U64::new(3_000_000_000),
    }
}

#[test]
fn actual_positive_native_work_precedes_held_response_and_original_reap() {
    let mut native = NativeFixture::spawn();
    let (record, _, _) = native.start_original_positive_window();
    native.assert_completion_held();
    native.reap();
    assert_eq!(
        FrameReader::new(&mut native.control, FRAME_BYTES)
            .unwrap()
            .read()
            .unwrap(),
        None
    );
    assert_eq!(record.consumed_prefix.get(), 1);
    assert_eq!(record.checksum_after_prefix.get(), 123);
}

#[test]
fn actual_release_completes_only_remaining_original_bytes() {
    let mut native = NativeFixture::spawn();
    native.start_original_positive_window();
    native.assert_completion_held();
    native.progress.write_all(&[1]).unwrap();
    let completed = FrameReader::new(&mut native.control, FRAME_BYTES)
        .unwrap()
        .read()
        .unwrap()
        .unwrap();
    let expected = br#"{"bytes_processed":"0","checksum":"0"}"#
        .iter()
        .fold(0_u64, |checksum, byte| {
            checksum.wrapping_mul(257).wrapping_add(u64::from(*byte))
        });
    assert_eq!(
        completed["output"],
        json!({"bytes_processed":"38","checksum":expected.to_string()})
    );
    assert_eq!(
        native.exchange(&json!({"command":"close","window":grant(1).window_id}))["output"],
        completed["output"]
    );
    native.reap();
}

#[test]
fn actual_empty_source_window_completes_without_selecting_progress() {
    let mut native = NativeFixture::spawn();
    native.initialize_and_acknowledge_zero_window();
    assert_eq!(
        native.exchange(&json!({"command":"stage","grant":grant(1),"input":[]}))["result"],
        "staged"
    );
    let completed = native.exchange(&json!({"command":"activate","window":grant(1).window_id}));
    assert_eq!(
        completed["output"],
        json!({"bytes_processed":"0","checksum":"0"})
    );
    assert_eq!(
        native.exchange(&json!({"command":"close","window":grant(1).window_id}))["output"],
        completed["output"]
    );
    let mut descriptors = [PollFd::new(&native.progress, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    assert_eq!(poll(&mut descriptors, Some(&timeout)).unwrap(), 0);
    native.reap();
}
