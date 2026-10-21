//! Budget, retry attribution and bounded advisory capture contracts.

use super::*;
use std::ffi::OsStr;
use std::os::unix::net::UnixStream;

#[test]
fn disabled_setting_and_duplicate_inventory_keep_independent_budget() {
    for setting in [None, Some("0"), Some("257"), Some("0256"), Some("invalid")] {
        let witness = DeviceWaitWitness::from_setting(setting.map(OsStr::new));
        assert!(witness.request(7, None, 0).is_none());
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
    let request = witness.request(7, None, 0);
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
        .request(u32::MAX, None, 0)
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
        .request(8, None, 0)
        .unwrap_or_else(|| panic!("new request"));
    assert_eq!(request.request, u32::MAX);
    assert_eq!(new.request, 8);
    witness.owner_pid = witness.owner_pid.wrapping_add(1);
    assert!(witness.request(9, None, 0).is_none());
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
    let request = witness.request(7, None, 0);
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

#[test]
fn coordinate_floor_skips_earlier_waits_without_spending_allowance() {
    let witness = DeviceWaitWitness::from_settings(Some(OsStr::new("1")), Some(OsStr::new("500")));

    assert!(witness.request(7, None, 499).is_none());
    let late = witness.request(7, None, 500);

    assert!(late.is_some());
    witness.emit(late, "entered", (None, None, None), (None, None), "pending");
    assert_eq!(
        witness
            .inventory
            .lock()
            .unwrap_or_else(|e| panic!("inventory: {e}"))
            .count,
        1
    );
}

#[test]
fn noncanonical_coordinate_floor_disables_the_witness() {
    for minimum in ["", "0500", "-1", "9223372036854775808", "invalid"] {
        let witness =
            DeviceWaitWitness::from_settings(Some(OsStr::new("256")), Some(OsStr::new(minimum)));
        assert!(witness.request(7, None, u64::MAX).is_none(), "{minimum:?}");
    }

    let unfloored = DeviceWaitWitness::from_settings(Some(OsStr::new("256")), None);
    assert!(unfloored.request(7, None, 0).is_some());
}

fn captured_publications(witness: &mut DeviceWaitWitness) -> std::fs::File {
    let capture = tempfile_capture();
    witness.destination = Some(Mutex::new(
        capture
            .try_clone()
            .unwrap_or_else(|e| panic!("duplicate: {e}")),
    ));
    capture
}

fn tempfile_capture() -> std::fs::File {
    let path = std::env::temp_dir().join(format!(
        "crucible-device-wait-publications-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("capture: {e}"));
    std::fs::remove_file(&path).unwrap_or_else(|e| panic!("unlink: {e}"));
    file
}

fn rows(capture: &mut std::fs::File) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    capture
        .seek(SeekFrom::Start(0))
        .unwrap_or_else(|e| panic!("seek: {e}"));
    let mut text = String::new();
    capture
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("read: {e}"));
    text.lines().map(str::to_owned).collect()
}

#[test]
fn publication_rows_need_an_explicit_floor() {
    let mut unfloored = DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    let mut capture = captured_publications(&mut unfloored);

    unfloored.observe_publication("sim-publication", "reached", 2, 100, None);

    assert!(rows(&mut capture).is_empty());
}

#[test]
fn a_repeated_publication_names_its_publisher_once() {
    let mut witness =
        DeviceWaitWitness::from_settings(Some(OsStr::new("1")), Some(OsStr::new("100")));
    let mut capture = captured_publications(&mut witness);

    witness.observe_publication("sim-publication", "reached", 1, 99, None);
    for _ in 0..1000 {
        witness.observe_publication("sim-publication", "reached", 2, 100, None);
    }
    witness.observe_publication("max-advance", "raw-ceiling", 2, 100, Some(2));

    assert_eq!(
        rows(&mut capture),
        [
            "CRUCIBLE-DEVICE-WAIT-V1 phase=publication pid={pid} boundary=sim-publication kind=reached raw=2 current=100 value=unavailable",
            "CRUCIBLE-DEVICE-WAIT-V1 phase=publication pid={pid} boundary=max-advance kind=raw-ceiling raw=2 current=100 value=2",
        ]
        .map(|row| row.replace("{pid}", &std::process::id().to_string()))
    );
}

#[test]
fn publication_allowance_is_bounded_and_renewed_by_rebind() {
    let mut witness =
        DeviceWaitWitness::from_settings(Some(OsStr::new("1")), Some(OsStr::new("1")));
    let mut capture = captured_publications(&mut witness);

    for raw in 0..100 {
        witness.observe_publication("sim-publication", "reached", raw, 1, None);
    }
    assert_eq!(rows(&mut capture).len(), MAX_PUBLICATION_ROWS);

    witness.rebind();
    witness.observe_publication("sim-publication", "reached", 0, 1, None);

    assert_eq!(rows(&mut capture).len(), MAX_PUBLICATION_ROWS + 1);
}
