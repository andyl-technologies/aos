//! Budget, retry attribution and bounded advisory capture contracts.

use super::*;
use std::ffi::OsStr;
use std::os::unix::net::UnixStream;

#[test]
fn disabled_setting_and_duplicate_inventory_keep_independent_budget() {
    for setting in [None, Some("0"), Some("257"), Some("0256"), Some("invalid")] {
        let witness = DeviceWaitWitness::from_setting(setting.map(OsStr::new));
        assert!(witness.request(7, None).is_none());
        assert_eq!(
            witness
                .inventory
                .lock()
                .unwrap_or_else(|e| panic!("inventory: {e}"))
                .count,
            0
        );
    }

    let witness = DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    let request = witness.request(7, None);
    for _ in 0..300 {
        witness.emit(
            request,
            "pending",
            (None, None, None),
            (None, None),
            "deferred",
        );
    }
    assert_eq!(
        witness
            .inventory
            .lock()
            .unwrap_or_else(|e| panic!("inventory: {e}"))
            .count,
        1
    );
    for target in 0..300 {
        witness.emit(
            request,
            "armed",
            (Some(0), Some(target), Some(target)),
            (None, None),
            "pending",
        );
    }
    assert_eq!(
        witness
            .inventory
            .lock()
            .unwrap_or_else(|e| panic!("inventory: {e}"))
            .count,
        256
    );
}

#[test]
fn widest_record_is_one_bounded_row_and_old_context_is_not_replaced() {
    let mut witness = DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    let mut request = witness
        .request(u32::MAX, None)
        .unwrap_or_else(|| panic!("enabled request"));
    request.pid = u32::MAX;
    request.current = Some(u64::MAX);
    request.deadline = Some(u64::MAX);
    request.exact_deadline = Some(crate::ExactDeadlineReport::Armed {
        deadline_ps: u64::MAX,
    });
    let backing =
        crucible_shmem::SetupRegionBackingIdentity::from_parts(u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|| panic!("identity"));
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let mut state = super::super::tests::test_live_state(129, 1, 0, &slot)
        .unwrap_or_else(|e| panic!("state: {e}"));
    state.control_callback_witness =
        std::sync::Arc::new(super::super::ControlCallbackWitness::new(true));
    state = state.attach_control_stage_identity(backing, u32::MAX, u64::MAX);
    request.identity = state.control_stage_identity;
    let record = Record {
        request,
        phase: "completion",
        raw: Some(u64::MAX),
        target: Some(u64::MAX),
        arm: Some(u64::MAX),
        status: Some(i32::MIN),
        echo_target: Some(i64::MIN),
        result: "deferred",
    };
    let mut row = Vec::new();
    record
        .write_to(&mut row)
        .unwrap_or_else(|e| panic!("record: {e}"));
    assert!(row.len() <= 512, "{} bytes", row.len());
    assert_eq!(row.iter().filter(|b| **b == b'\n').count(), 1);

    witness.emit(
        Some(request),
        "pending",
        (None, None, None),
        (None, None),
        "deferred",
    );
    witness.rebind();
    assert_eq!(
        witness
            .inventory
            .lock()
            .unwrap_or_else(|e| panic!("inventory: {e}"))
            .count,
        0
    );
    let new = witness
        .request(8, None)
        .unwrap_or_else(|| panic!("new request"));
    assert_eq!(request.request, u32::MAX);
    assert_eq!(new.request, 8);
    witness.owner_pid = witness.owner_pid.wrapping_add(1);
    assert!(witness.request(9, None).is_none());
    witness.emit(
        Some(request),
        "completion",
        (Some(0), Some(1), Some(0)),
        (Some(0), Some(1)),
        "completed",
    );
    assert_eq!(
        witness
            .inventory
            .lock()
            .unwrap_or_else(|e| panic!("inventory: {e}"))
            .count,
        0
    );
}

#[test]
fn inventory_contention_and_unsupported_destination_never_block_callback() {
    let witness = DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    let request = witness.request(7, None);
    let guard = witness
        .inventory
        .lock()
        .unwrap_or_else(|e| panic!("inventory: {e}"));
    witness.emit(
        request,
        "pending",
        (None, None, None),
        (None, None),
        "deferred",
    );
    assert_eq!(guard.count, 0);
    drop(guard);

    let (writer, mut reader) = UnixStream::pair().unwrap_or_else(|e| panic!("socket: {e}"));
    reader
        .set_nonblocking(true)
        .unwrap_or_else(|e| panic!("nonblock: {e}"));
    assert!(destination(&writer).is_err());
    let mut byte = [0];
    assert_eq!(
        std::io::Read::read(&mut reader, &mut byte)
            .err()
            .unwrap_or_else(|| panic!("unsupported capture delivered bytes"))
            .kind(),
        io::ErrorKind::WouldBlock
    );
}
