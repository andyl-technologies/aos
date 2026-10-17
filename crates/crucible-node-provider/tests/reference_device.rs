//! Real source-built child lifecycle, immutable input and output-custody checks.

// crucible-lint: allow panic-shortcut -- These reference device tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::time::Duration;

use crucible_node_contract::{Id, Phase, Position, U64};
use crucible_node_provider::reference_device::{
    DeviceGrant, DeviceStatus, MAX_INPUT_BYTES, ReferenceDevice,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn grant(index: u64) -> DeviceGrant {
    DeviceGrant {
        owner_id: id("checksum-owner"),
        incarnation_id: id("checksum-child"),
        generation: U64::new(1),
        window_id: id(&format!("window/{index}")),
        input_batch_id: id(&format!("batch/{index}")),
        quantum: U64::new(index),
        start: Position::new(U64::new(index * 1000), U64::new(0), Phase::Delivery),
        publication: Position::new(
            U64::new((index + 1) * 1000),
            U64::new(0),
            Phase::Publication,
        ),
        host_budget_ns: U64::new(1_000_000_000),
    }
}

fn spawn() -> ReferenceDevice {
    ReferenceDevice::spawn(
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-device")),
        &std::env::temp_dir(),
        id("checksum-owner"),
        id("checksum-child"),
        U64::new(1),
        Duration::from_secs(3),
    )
    .unwrap()
}

#[test]
fn actual_child_preserves_input_cut_and_original_outputs_until_publication_ack() {
    let mut device = spawn();
    let first = grant(0);
    assert_eq!(device.status(), DeviceStatus::Parked);
    assert!(device.child_pid() > 0);

    device.stage(first.clone(), &[1, 2]).unwrap();
    device.stage(first.clone(), &[1, 2]).unwrap();
    assert_eq!(device.status(), DeviceStatus::Staged);
    assert!(device.stage(first.clone(), &[9]).is_err());
    assert!(device.close(&first).is_err());
    assert!(device.acknowledge_publication(&first).is_err());

    device.activate(&first).unwrap();
    device.activate(&first).unwrap();
    let receipt = device.close(&first).unwrap();
    assert_eq!(receipt, device.close(&first).unwrap());
    assert_eq!(receipt.output.bytes_processed.get(), 2);
    assert_eq!(receipt.output.checksum.get(), 259);
    assert_eq!(receipt.grant.publication.time_ps.get(), 1000);
    assert!(receipt.application_parked);
    assert_eq!(device.status(), DeviceStatus::ClosedPending);
    device.validate_receipt(&receipt).unwrap();

    let mut forged = receipt.clone();
    forged.output.checksum = U64::new(260);
    assert!(device.validate_receipt(&forged).is_err());
    assert!(device.stage(grant(1), &[3]).is_err());
    assert!(device.activate(&first).is_err());

    device.acknowledge_publication(&first).unwrap();
    device.acknowledge_publication(&first).unwrap();
    assert!(device.validate_receipt(&receipt).is_err());
    assert!(device.stage(first.clone(), &[1, 2]).is_err());

    let second = grant(1);
    device.stage(second.clone(), &[3]).unwrap();
    device.activate(&second).unwrap();
    let next = device.close(&second).unwrap();
    assert_eq!(next.output.checksum.get(), 66566);
    assert_eq!(next.grant.publication.time_ps.get(), 2000);
    assert!(device.quarantine().unwrap());
    assert_eq!(device.status(), DeviceStatus::Reaped);
}

#[test]
fn input_overflow_stale_owner_and_changed_quantum_refuse_before_child_execution() {
    let mut device = spawn();
    let first = grant(0);
    assert!(
        device
            .stage(first.clone(), &vec![0; MAX_INPUT_BYTES + 1])
            .is_err()
    );
    assert_eq!(device.status(), DeviceStatus::Parked);

    let mut stale = first.clone();
    stale.generation = U64::new(2);
    assert!(device.stage(stale, &[1]).is_err());
    let mut future = first.clone();
    future.quantum = U64::new(1);
    assert!(device.stage(future, &[1]).is_err());

    device.stage(first.clone(), &[]).unwrap();
    device.activate(&first).unwrap();
    let receipt = device.close(&first).unwrap();
    assert_eq!(receipt.output.bytes_processed.get(), 0);
    assert_eq!(receipt.output.checksum.get(), 0);
    assert!(device.quarantine().unwrap());
}

#[test]
fn total_budget_expiry_disconnects_reaps_and_never_retries_uncertain_work() {
    let mut device = spawn();
    let mut first = grant(0);
    first.host_budget_ns = U64::new(1);
    device.stage(first.clone(), &[1, 2, 3]).unwrap();

    assert!(device.activate(&first).is_err());
    assert!(matches!(
        device.status(),
        DeviceStatus::Quarantined | DeviceStatus::Reaped
    ));
    assert!(device.activate(&first).is_err());
    assert!(device.close(&first).is_err());
    assert!(device.stage(grant(1), &[4]).is_err());
    assert!(device.quarantine().unwrap());
    assert_eq!(device.status(), DeviceStatus::Reaped);
}

#[test]
fn quarantine_disconnects_and_reaps_a_device_with_unpublished_output() {
    let mut device = spawn();
    let first = grant(0);
    device.stage(first.clone(), &[7]).unwrap();
    device.activate(&first).unwrap();
    let receipt = device.close(&first).unwrap();

    assert!(device.quarantine().unwrap());
    assert!(device.quarantine().unwrap());
    assert!(device.validate_receipt(&receipt).is_err());
    assert!(device.acknowledge_publication(&first).is_err());
    assert!(device.stage(grant(1), &[8]).is_err());
}

#[test]
fn dropped_driver_reaps_its_actual_parked_child() {
    let device = spawn();
    let pid = device.child_pid();
    drop(device);

    for _ in 0..3000 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("mandatory supervisor did not reap dropped reference child");
}

#[test]
fn actual_child_refuses_malformed_private_protocol_and_exits() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};

    let directory =
        std::env::temp_dir().join(format!("crucible-device-invalid-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let socket = directory.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucible-reference-device"))
        .arg(&socket)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut connected = None;
    for _ in 0..3000 {
        match listener.accept() {
            Ok((stream, _)) => {
                connected = Some(stream);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("reference fixture connection failed: {error}"),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let Some(mut stream) = connected else {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("reference child did not connect");
    };
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(&2_u32.to_be_bytes()).unwrap();
    stream.write_all(b"{}").unwrap();

    let mut exit = None;
    for _ in 0..3000 {
        if let Some(status) = child.try_wait().unwrap() {
            exit = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if exit.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert!(exit.is_some_and(|status| !status.success()));
    drop(stream);
    drop(listener);
    std::fs::remove_file(socket).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn dropped_unpublished_window_transfers_complete_native_custody_to_supervisor() {
    use crucible_node_provider::reference_device::{
        acknowledge_supervised_containment, supervised_devices,
    };

    let mut device = spawn();
    let first = grant(0);
    device.stage(first.clone(), &[4, 5]).unwrap();
    device.activate(&first).unwrap();
    let receipt = device.close(&first).unwrap();
    let supervision_id = device.supervision_id();
    drop(device);

    let mut retained = None;
    for _ in 0..3000 {
        retained = supervised_devices()
            .into_iter()
            .find(|record| record.supervision_id == supervision_id);
        if retained.as_ref().is_some_and(|record| record.reaped) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let retained = retained.unwrap();
    assert!(retained.reaped);
    assert_eq!(retained.grant, Some(first));
    assert_eq!(retained.input, vec![4, 5]);
    assert_eq!(retained.output, Some(receipt.output.clone()));
    assert_eq!(retained.receipt, Some(receipt));

    acknowledge_supervised_containment(supervision_id).unwrap();
    assert!(
        !supervised_devices()
            .iter()
            .any(|record| record.supervision_id == supervision_id)
    );
}
