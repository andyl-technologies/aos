//! Exact pending-row bounds and safe destination ownership.

use super::*;
use std::os::unix::net::UnixStream;

fn record(token: u32, reason: usize) -> PendingRecord {
    PendingRecord {
        pid: u32::MAX,
        callback: u64::MAX,
        raw: u64::MAX,
        token,
        identity: None,
        settlement: None,
        reason,
    }
}

#[test]
fn minimum_distinct_reason_and_independent_cap_do_not_spend_on_other_callbacks() {
    let notices = PendingNotices::new(Some(50_000));
    for token in 0..50_000 {
        assert!(notices.record(record(token, 1)).is_none());
    }
    assert_eq!(
        notices
            .inventory
            .lock()
            .unwrap_or_else(|error| panic!("inventory: {error}"))
            .count,
        0
    );
    assert!(notices.record(record(54_008, 1)).is_some());
    assert!(notices.record(record(54_008, 1)).is_none());
    assert!(notices.record(record(54_010, 1)).is_some());
    assert!(notices.record(record(54_008, 1)).is_none());
    assert!(notices.record(record(54_008, 3)).is_some());
    assert!(notices.record(record(54_009, 3)).is_none());
    for token in (54_012..54_038).step_by(2) {
        assert!(notices.record(record(token, 1)).is_some());
    }
    assert!(notices.record(record(54_038, 1)).is_none());
    assert_eq!(
        notices
            .inventory
            .lock()
            .unwrap_or_else(|error| panic!("inventory: {error}"))
            .count,
        usize::from(MAX_ROWS)
    );
    notices.reset();
    assert!(notices.record(record(54_008, 1)).is_some());
}

#[test]
fn fixed_row_is_bounded_and_unsupported_socket_is_not_mutated() {
    let context = SettlementContext {
        callback: u64::MAX,
        raw: u64::MAX,
        token: u32::MAX - 1,
        frontier: u64::MAX,
        capture: Some(u32::MAX),
    };
    let mut row = record(u32::MAX - 1, 3);
    row.settlement = Some(context);
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let mut state = super::super::super::tests::test_live_state(129, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("state: {error}"));
    state.control_callback_witness =
        std::sync::Arc::new(super::super::ControlCallbackWitness::new(true));
    let backing =
        crucible_shmem::SetupRegionBackingIdentity::from_parts(u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|| panic!("valid identity"));
    state = state.attach_control_stage_identity(backing, u32::MAX, u64::MAX);
    row.identity = state.control_stage_identity;
    assert!(row.identity.is_some());
    let mut bytes = Vec::new();
    row.write_to(&mut bytes)
        .unwrap_or_else(|error| panic!("row: {error}"));
    assert!(bytes.len() <= 512);
    let text = String::from_utf8(bytes).unwrap_or_else(|error| panic!("ASCII: {error}"));
    assert!(text.ends_with("reason=publication-backpressure\n"));
    assert!(text.contains("frontier=18446744073709551615 capture=4294967295"));

    let (socket, mut peer) = UnixStream::pair().unwrap_or_else(|error| panic!("socket: {error}"));
    assert_eq!(
        destination(&socket).err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    use std::io::Read;
    (&socket)
        .write_all(b"original")
        .unwrap_or_else(|error| panic!("original write: {error}"));
    let mut received = [0; 8];
    peer.read_exact(&mut received)
        .unwrap_or_else(|error| panic!("original read: {error}"));
    assert_eq!(&received, b"original");
}

#[test]
fn no_destination_is_opened_before_both_opt_ins_are_admitted() {
    for (aggregate, minimum) in [
        (None, None),
        (None, Some("50000")),
        (Some("0"), Some("50000")),
        (Some("257"), Some("50000")),
        (Some("16"), None),
        (Some("16"), Some("050000")),
    ] {
        let notices =
            PendingNotices::from_settings(aggregate.map(OsStr::new), minimum.map(OsStr::new));
        assert!(notices.destination.is_none());
        assert_eq!(notices.owner_pid, 0);
        assert!(notices.minimum.is_none());
    }
}

#[test]
fn contention_and_poison_drop_without_spending_or_waiting() {
    let notices = PendingNotices::new(Some(0));
    let guard = notices
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("inventory: {error}"));
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert!(notices.record(record(2, 1)).is_none());
                notices.reset();
            })
            .join()
            .unwrap_or_else(|error| std::panic::resume_unwind(error));
    });
    assert_eq!(guard.count, 0);
    drop(guard);
    assert!(notices.record(record(2, 1)).is_some());
    let poisoned = PendingNotices::new(Some(0));
    std::thread::scope(|scope| {
        let result = scope
            .spawn(|| {
                let _guard = poisoned
                    .inventory
                    .lock()
                    .unwrap_or_else(|error| panic!("inventory: {error}"));
                panic!("intentional diagnostic mutex poison");
            })
            .join();
        assert!(result.is_err());
    });
    assert!(poisoned.record(record(2, 1)).is_none());
    poisoned.reset();
    assert!(poisoned.record(record(4, 1)).is_none());
}

#[test]
fn mismatched_settlement_never_lends_another_callback_request_or_coordinate() {
    use std::os::unix::fs::FileExt;
    let path =
        std::env::temp_dir().join(format!("crucible-pending-context-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    std::fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink capture: {error}"));
    let mut witness = super::super::ControlCallbackWitness::new(true);
    witness.pending = PendingNotices::new(Some(0));
    witness.pending.destination = Some(Mutex::new(
        file.try_clone()
            .unwrap_or_else(|error| panic!("capture: {error}")),
    ));
    let context = witness.settlement_context(Some(7), 8, 2, 6, Some(9));
    witness.retain_settlement(
        context,
        super::super::settlement::SettlementReason::PumpActive,
    );
    for (callback, raw, token) in [(6, 8, 2), (7, 9, 2), (7, 8, 4)] {
        witness.reset_pending();
        witness.report_pending(callback, raw, token, None);
    }
    let length = file
        .metadata()
        .unwrap_or_else(|error| panic!("capture stat: {error}"))
        .len();
    let mut bytes = vec![0; length as usize];
    file.read_exact_at(&mut bytes, 0)
        .unwrap_or_else(|error| panic!("capture read: {error}"));
    let rows = String::from_utf8(bytes).unwrap_or_else(|error| panic!("ASCII: {error}"));
    assert_eq!(rows.lines().count(), 3);
    for row in rows.lines() {
        assert!(row.contains("device=unavailable inode=unavailable length=unavailable slot=unavailable generation=unavailable"));
        assert!(row.ends_with("frontier=unavailable capture=unavailable reason=unavailable"));
    }
}
