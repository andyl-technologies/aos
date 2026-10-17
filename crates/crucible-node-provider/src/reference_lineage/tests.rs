//! Native loop data invariants; these checks grant no installed source authority.

// crucible-lint: allow panic-shortcut -- A mismatch invalidates the original native loop fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_node_contract::{Phase, Position, U64, canonical};

use super::{execution::NativeWindow, *};
use crate::reference_device::DeviceGrant;

pub(super) fn stage(quantum: u64, payloads: &[&[u8]]) -> LineageStage {
    let mut input = Vec::new();
    let mut entries = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let byte_start = U64::new(input.len() as u64);
        input.extend_from_slice(payload);
        entries.push(StagedLineageEntry {
            event_index: U64::new(index as u64),
            payload: canonical::content_ref(payload, "application/octet-stream").unwrap(),
            byte_start,
            byte_end: U64::new(input.len() as u64),
        });
    }
    LineageStage {
        schema_version: 1,
        grant: DeviceGrant {
            owner_id: crucible_node_contract::Id::new("native-owner").unwrap(),
            incarnation_id: crucible_node_contract::Id::new("native-incarnation").unwrap(),
            generation: U64::new(1),
            window_id: crucible_node_contract::Id::new(format!("window-{quantum}")).unwrap(),
            input_batch_id: crucible_node_contract::Id::new(format!("input-{quantum}")).unwrap(),
            quantum: U64::new(quantum),
            start: Position {
                time_ps: U64::new(quantum * 50),
                microstep: U64::new(0),
                phase: Phase::BoundaryControl,
            },
            publication: Position {
                time_ps: U64::new(quantum * 50 + 50),
                microstep: U64::new(0),
                phase: Phase::Publication,
            },
            host_budget_ns: U64::new(20_000_000),
        },
        original_batch: canonical::content_ref(
            format!("original ordered batch {quantum}").as_bytes(),
            "application/json",
        )
        .unwrap(),
        entries,
        input,
    }
}

#[test]
fn actual_entry_loop_retains_equal_payloads_and_explicit_empty_event_order() {
    let original = stage(0, &[b"same", b"", b"same"]);
    let mut checksum = 0;
    let mut native = NativeWindow::prepare(original.clone(), checksum, None).unwrap();
    assert!(native.close().is_err());
    let output = native.activate(&mut checksum).unwrap();
    assert_eq!(output.bytes_processed.get(), 8);
    assert_eq!(native.activate(&mut checksum).unwrap(), output);
    assert_eq!(checksum, output.checksum.get());
    let closed = native.close().unwrap();
    closed.validate_against(&original, None).unwrap();
    assert_eq!(closed.consumed.len(), 3);
    assert_eq!(closed.consumed[1].event_index.get(), 1);
    assert_eq!(closed.consumed[1].byte_start, closed.consumed[1].byte_end);
    assert_eq!(
        closed.consumed[0].checksum_after,
        closed.consumed[1].checksum_after
    );
    assert_eq!(native.close().unwrap(), closed);
    assert!(native.activate(&mut checksum).is_err());
    assert_eq!(
        native.acknowledgement(&original.grant.window_id).unwrap(),
        closed.identity().unwrap()
    );
}

#[test]
fn equal_flattened_bytes_do_not_replace_original_batch_identity() {
    let original = stage(0, &[b"same", b"same"]);
    let mut changed = original.clone();
    changed.original_batch = canonical::content_ref(
        b"same bytes under reordered original events",
        "application/json",
    )
    .unwrap();
    assert_eq!(original.input, changed.input);
    assert_ne!(original.identity().unwrap(), changed.identity().unwrap());
    let mut native = NativeWindow::prepare(original.clone(), 0, None).unwrap();
    native.activate(&mut 0).unwrap();
    assert!(
        native
            .close()
            .unwrap()
            .validate_against(&changed, None)
            .is_err()
    );
}

#[test]
fn bad_ranges_indexes_and_exhausted_entry_credit_refuse_before_execution() {
    let original = stage(0, &[b"ab", b"cd"]);
    for changed in [
        {
            let mut changed = original.clone();
            changed.entries[1].byte_start = U64::new(1);
            changed
        },
        {
            let mut changed = original.clone();
            changed.entries[1].byte_end = U64::new(u64::MAX);
            changed
        },
        {
            let mut changed = original.clone();
            changed.entries.swap(0, 1);
            changed
        },
        {
            let mut changed = original.clone();
            changed.input.push(0);
            changed
        },
        stage(0, &[b"" as &[u8]; 65]),
    ] {
        assert!(NativeWindow::prepare(changed, 0, None).is_err());
    }
}

#[test]
fn checksum_state_chain_remains_original_across_empty_later_window() {
    let first = stage(0, &[b"initial"]);
    let mut checksum = 0;
    let mut native = NativeWindow::prepare(first.clone(), checksum, None).unwrap();
    native.activate(&mut checksum).unwrap();
    let predecessor = native.close().unwrap();
    let next = stage(1, &[b""]);
    let mut native = NativeWindow::prepare(
        next.clone(),
        checksum,
        Some(predecessor.identity().unwrap()),
    )
    .unwrap();
    native.activate(&mut checksum).unwrap();
    let closed = native.close().unwrap();
    closed.validate_against(&next, Some(&predecessor)).unwrap();
    assert_eq!(closed.output.checksum, predecessor.output.checksum);
    assert_eq!(closed.consumed.len(), 1);
    assert!(closed.validate_against(&next, None).is_err());
    let mut foreign = predecessor.clone();
    foreign.grant.generation = U64::new(2);
    assert!(closed.validate_against(&next, Some(&foreign)).is_err());
    assert!(NativeWindow::prepare(next, checksum, None).is_err());
}

#[test]
fn changed_native_entry_receipt_cannot_hide_reordering_or_omission() {
    let original = stage(0, &[b"equal", b"equal", b""]);
    let mut native = NativeWindow::prepare(original.clone(), 0, None).unwrap();
    native.activate(&mut 0).unwrap();
    let original_receipt = native.close().unwrap();
    for changed in [
        {
            let mut changed = original_receipt.clone();
            changed.consumed.swap(0, 1);
            changed
        },
        {
            let mut changed = original_receipt.clone();
            changed.consumed.pop();
            changed
        },
        {
            let mut changed = original_receipt.clone();
            changed.consumed[1].checksum_after = U64::new(0);
            changed
        },
    ] {
        assert!(changed.validate_against(&original, None).is_err());
    }
}

#[test]
fn native_successor_does_not_decode_legacy_stage_or_missing_nullable_ancestry() {
    let original = stage(0, &[]);
    let mut native = NativeWindow::prepare(original.clone(), 0, None).unwrap();
    native.activate(&mut 0).unwrap();
    let mut value = serde_json::to_value(native.close().unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("previous_closed");
    assert!(serde_json::from_value::<NativeLineageReceipt>(value).is_err());
    assert!(
        serde_json::from_value::<super::protocol::Request>(serde_json::json!({
            "command": "stage", "grant": original.grant, "input": []
        }))
        .is_err()
    );
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_LINEAGE_DEVICE pointing to this source-built successor child"]
fn actual_distinct_child_retains_original_empty_entries_and_previous_native_closure() {
    use super::protocol::{DIALECT, MAX_FRAME_BYTES, Request, Response};
    use crate::transport::{FrameReader, write_frame};
    use std::{
        fs::DirBuilder,
        os::unix::{fs::DirBuilderExt, net::UnixListener},
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct RootGuard(std::path::PathBuf);
    impl Drop for RootGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = RootGuard(std::env::temp_dir().join(format!(
        "crucible-lineage-child-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )));
    DirBuilder::new().mode(0o700).create(&root.0).unwrap();
    let socket = root.0.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let executable = std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_DEVICE").unwrap();
    let mut child = ChildGuard(
        Command::new(executable)
            .arg(&socket)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline =
        crate::operational_time::OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connected) => break connected,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(child.0.try_wait().unwrap().is_none());
                assert!(!deadline.is_expired());
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("native child connection failed: {error}"),
        }
    };
    let peer = rustix::net::sockopt::socket_peercred(&stream).unwrap();
    assert_eq!(peer.pid.as_raw_nonzero().get() as u32, child.0.id());
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut call = |request: Request| {
        write_frame(
            &mut stream,
            &serde_json::to_value(request).unwrap(),
            MAX_FRAME_BYTES,
        )
        .unwrap();
        serde_json::from_value::<Response>(
            FrameReader::new(&mut stream, MAX_FRAME_BYTES)
                .unwrap()
                .read()
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    let first = stage(0, &[b"same", b"", b"same"]);
    assert!(matches!(call(Request::Initialize {
        dialect: DIALECT.into(), owner: first.grant.owner_id.clone(),
        incarnation: first.grant.incarnation_id.clone(), generation: first.grant.generation,
    }), Response::Ready { dialect, child_pid, .. } if dialect == DIALECT && child_pid.get() == u64::from(child.0.id())));
    assert!(
        matches!(call(Request::Stage { dialect: DIALECT.into(), original: Box::new(first.clone()) }), Response::Staged { original } if original == first.identity().unwrap())
    );
    let window = first.grant.window_id.clone();
    assert!(
        matches!(call(Request::Activate { window: window.clone() }), Response::Completed { output, .. } if output.bytes_processed.get() == 8)
    );
    let Response::Closed {
        original: first_receipt,
    } = call(Request::Close {
        window: window.clone(),
    })
    else {
        panic!("original native closure missing");
    };
    first_receipt.validate_against(&first, None).unwrap();
    assert_eq!(first_receipt.consumed.len(), 3);
    let Response::Closed { original: retry } = call(Request::Close {
        window: window.clone(),
    }) else {
        panic!("original closed retry missing");
    };
    assert_eq!(retry, first_receipt);
    for _ in 0..2 {
        assert!(
            matches!(call(Request::Acknowledge { window: window.clone() }), Response::Acknowledged { window: actual } if actual == window)
        );
    }

    let next = stage(1, &[b""]);
    assert!(
        matches!(call(Request::Stage { dialect: DIALECT.into(), original: Box::new(next.clone()) }), Response::Staged { original } if original == next.identity().unwrap())
    );
    assert!(
        matches!(call(Request::Activate { window: next.grant.window_id.clone() }), Response::Completed { output, .. } if output.checksum == first_receipt.output.checksum)
    );
    let Response::Closed { original: second } = call(Request::Close {
        window: next.grant.window_id.clone(),
    }) else {
        panic!("second native closure missing");
    };
    second
        .validate_against(&next, Some(&first_receipt))
        .unwrap();
    assert_eq!(
        second.previous_closed,
        Some(first_receipt.identity().unwrap())
    );
    assert_eq!(second.consumed.len(), 1);
    assert_eq!(second.consumed[0].byte_start, second.consumed[0].byte_end);
    drop(stream);
    // The command-loop EOF ends the actual child. Reaping confirms this fixture
    // retains no native process; it establishes no world publication authority.
    assert!(!child.0.wait().unwrap().success());
}
