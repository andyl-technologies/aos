//! Actual connection closure and fixed readiness under the original transport.
//!
//! The purpose here is a test-only protocol model, not an actor admission issuer.

// crucible-lint: allow panic-shortcut -- this caught-panic control asserts terminal replay refusal and physical connection closure; the model issues no actor or native grant.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::io::BufRead;
use std::rc::Rc;

use super::*;

struct PanicDecoder {
    quarantined: Rc<Cell<bool>>,
}

impl BackingTransportPurpose for PanicDecoder {
    fn prepare(
        &mut self,
        _geometry: BackingTransportGeometry,
        _contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        panic!("the protocol-only control never calls an admission constructor")
    }

    fn remaining(&self) -> Result<Duration, OriginalActorAccountError> {
        Ok(Duration::from_secs(1))
    }

    fn check_original(&self) -> Result<(), OriginalActorAccountError> {
        Ok(())
    }

    fn check_original_post(&self) -> Result<(), OriginalActorAccountError> {
        Ok(())
    }

    fn quarantine(&mut self) {
        self.quarantined.set(true);
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        &self,
        _bytes: &[u8],
    ) -> Result<Frame<T>, BackingTransportCause> {
        panic!("decoder panicked after the actual command response arrived")
    }
}

#[test]
fn caught_bind_panic_refuses_replay_and_closes_actual_connection() {
    let (stream, mut monitor) = UnixStream::pair().unwrap();
    monitor.write_all(b"{\"return\":{}}\n").unwrap();
    let mut client = QmpClient {
        stream: BufReader::new(stream),
        greeting: QmpGreeting {
            version_present: true,
            capabilities_present: true,
        },
        job_poll_policy: QmpJobPollPolicy::default(),
        io_timeout_policy: QmpIoTimeoutPolicy::default(),
        predeclared_debug_guest_endpoint: false,
        poisoned: false,
        host_supervisor: None,
        selectable_reset_correlation: 0,
        selectable_reset_observation: 0,
        readonly_backing_correlation: 0,
    };
    let (output, peer) = UnixStream::pair().unwrap();
    let (cancellation, _cancellation_peer) = UnixStream::pair().unwrap();
    let quarantined = Rc::new(Cell::new(false));
    let mut transfer = QmpReadOnlyBackingTransfer {
        client: &mut client,
        output,
        peer: Some(peer),
        cancellation: cancellation.into(),
        line: Vec::with_capacity(LINE_BYTES),
        data: vec![0; DATA_BYTES],
        first: None,
        output_imported: false,
        cancellation_imported: false,
        phase: Phase::Prepared,
        binding: None,
        purpose: PanicDecoder {
            quarantined: Rc::clone(&quarantined),
        },
    };

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = transfer.bind_current_stop();
    }));

    assert!(panic.is_err());
    assert_eq!(transfer.phase, Phase::Binding);
    assert_eq!(transfer.client.readonly_backing_correlation, 1);
    assert!(transfer.bind_current_stop().is_err());
    assert_eq!(transfer.client.readonly_backing_correlation, 1);
    drop(transfer);
    assert!(quarantined.get());
    assert!(client.ensure_usable().is_err());

    // Drain the one real query, then witness EOF from poisoned socket shutdown.
    let mut command = String::new();
    let mut monitor = BufReader::new(monitor);
    monitor.read_line(&mut command).unwrap();
    assert!(command.contains(QMP_QUERY_PAUSED_CPU_COMMAND));
    let mut trailing = [0];
    assert_eq!(monitor.read(&mut trailing).unwrap(), 0);
}

#[test]
fn fixed_readiness_observes_cancellation_without_consuming_it() {
    let (qmp, mut monitor) = UnixStream::pair().unwrap();
    let (output, mut writer) = UnixStream::pair().unwrap();
    let (mut cancellation, mut signaller) = UnixStream::pair().unwrap();
    monitor.write_all(b"q").unwrap();
    writer.write_all(b"d").unwrap();

    let (command_ready, canceled) = qmp
        .poll_qmp_backing_progress(
            output.as_fd(),
            cancellation.as_fd(),
            false,
            true,
            Duration::ZERO,
        )
        .unwrap();
    assert!(
        !command_ready,
        "completed commands are excluded from readiness"
    );
    assert!(!canceled);

    signaller.write_all(b"c").unwrap();
    let (command_ready, canceled) = qmp
        .poll_qmp_backing_progress(
            output.as_fd(),
            cancellation.as_fd(),
            true,
            true,
            Duration::ZERO,
        )
        .unwrap();
    assert!(command_ready);
    assert!(canceled);

    let mut unchanged_signal = [0];
    cancellation.read_exact(&mut unchanged_signal).unwrap();
    assert_eq!(unchanged_signal, *b"c");
}

struct ProtocolDecoder {
    cuts: Rc<Cell<usize>>,
    quarantined: Rc<Cell<bool>>,
}

impl BackingTransportPurpose for ProtocolDecoder {
    fn prepare(
        &mut self,
        _geometry: BackingTransportGeometry,
        _contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        panic!("this manually assembled protocol model grants no actor admission")
    }

    fn remaining(&self) -> Result<Duration, OriginalActorAccountError> {
        Ok(Duration::from_secs(1))
    }

    fn check_original(&self) -> Result<(), OriginalActorAccountError> {
        let cuts = self.cuts.get();
        if cuts >= 256 {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.cuts.set(cuts + 1);
        Ok(())
    }

    fn check_original_post(&self) -> Result<(), OriginalActorAccountError> {
        Ok(())
    }

    fn quarantine(&mut self) {
        self.quarantined.set(true);
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        &self,
        bytes: &[u8],
    ) -> Result<Frame<T>, BackingTransportCause> {
        serde_json::from_slice(bytes).map_err(BackingTransportCause::Json)
    }
}

#[derive(Default)]
struct RecordingSink {
    feeds: usize,
    finished: bool,
}

impl QmpReadOnlyBackingSink for RecordingSink {
    fn feed(&mut self, _bytes: &[u8]) -> Result<(), QmpReadOnlyBackingStreamError> {
        self.feeds += 1;
        Ok(())
    }

    fn finish(
        &mut self,
        _receipt: &QmpReadOnlyBackingReceipt,
    ) -> Result<(), QmpReadOnlyBackingStreamError> {
        self.finished = true;
        Ok(())
    }
}

#[test]
fn command_rejection_before_data_eof_is_first_and_terminal() {
    rejected_backing_reply("CommandNotFound", "observer unavailable", true);
}

#[test]
fn nonordinary_stop_refuses_even_after_actual_data_eof() {
    rejected_backing_reply("GenericError", "ordinary stopped origin required", false);
}

fn rejected_backing_reply(class: &str, description: &str, keep_data_open: bool) {
    let (stream, mut monitor) = UnixStream::pair().unwrap();
    let rejected = serde_json::json!({"error": {"class": class, "desc": description}});
    let replies = format!("{{\"return\":{{}}}}\n{{\"return\":{{}}}}\n{rejected}\n");
    monitor.write_all(replies.as_bytes()).unwrap();
    let mut client = QmpClient {
        stream: BufReader::new(stream),
        greeting: QmpGreeting {
            version_present: true,
            capabilities_present: true,
        },
        job_poll_policy: QmpJobPollPolicy::default(),
        io_timeout_policy: QmpIoTimeoutPolicy::default(),
        predeclared_debug_guest_endpoint: false,
        poisoned: false,
        host_supervisor: None,
        selectable_reset_correlation: 0,
        selectable_reset_observation: 0,
        readonly_backing_correlation: 1,
    };
    let (output, peer) = UnixStream::pair().unwrap();
    output.set_nonblocking(true).unwrap();
    // These protocol models exercise both command-before-EOF and EOF-before-
    // rejection. Neither a local EOF nor this modeled response issues a grant.
    let _open_data_endpoint = keep_data_open.then(|| peer.try_clone().unwrap());
    let (cancellation, _signaller) = UnixStream::pair().unwrap();
    let cuts = Rc::new(Cell::new(0));
    let quarantined = Rc::new(Cell::new(false));
    let mut transfer = QmpReadOnlyBackingTransfer {
        client: &mut client,
        output,
        peer: Some(peer),
        cancellation: cancellation.into(),
        line: Vec::with_capacity(LINE_BYTES),
        data: vec![0; DATA_BYTES],
        first: None,
        output_imported: false,
        cancellation_imported: false,
        phase: Phase::Bound,
        binding: Some(QmpReadOnlyBackingBinding {
            correlation: 1,
            generation: 7,
        }),
        purpose: ProtocolDecoder {
            cuts: Rc::clone(&cuts),
            quarantined: Rc::clone(&quarantined),
        },
    };
    let mut sink = RecordingSink::default();

    assert!(transfer.export(&mut sink).is_err());

    assert!(matches!(
        &transfer.first_failure().unwrap().primary,
        BackingTransportCause::Qmp(QmpError::Command {
            command: QmpCommandKind::ExportBackingMaterial,
            class: observed_class,
            description: observed_description,
        }) if observed_class == class && observed_description == description
    ));
    assert_eq!(sink.feeds, 0);
    assert!(!sink.finished);
    assert!(quarantined.get());
    assert!(transfer.client.ensure_usable().is_err());
    let observed_cuts = cuts.get();
    assert!(transfer.export(&mut sink).is_err());
    assert_eq!(
        cuts.get(),
        observed_cuts,
        "refused exports perform no replay effects"
    );
}
