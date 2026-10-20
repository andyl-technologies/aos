//! Owning journal preflight and actual native failure-custody regressions.

// crucible-lint: allow panic-shortcut -- Failure invalidates exact original native custody in this fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::{
    journal::{MAX_NATIVE_JOURNAL_BYTES, NativeCommandKnowledge},
    tests::stage,
};
use super::*;

struct AuxiliaryChild(Child);

impl Drop for AuxiliaryChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "lineage-driver-fixture-{}-{}",
            std::process::id(),
            DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reclaimed(queue: &LineageCustodyQueue, token: U64) {
    let deadline = ExchangeBudget::after(Duration::from_secs(5)).unwrap();
    while !queue
        .retained()
        .iter()
        .any(|status| status.reservation == token && status.reclaimed)
    {
        assert!(
            !deadline.is_expired(),
            "original native group was not reclaimed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn launch(root: &Root, queue: LineageCustodyQueue) -> NativeLineageDevice {
    let original = stage(0, &[]);
    NativeLineageDevice::spawn(
        Path::new(&std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_DEVICE").unwrap()),
        &root.0,
        original.grant.owner_id,
        original.grant.incarnation_id,
        original.grant.generation,
        Duration::from_secs(2),
        queue,
    )
    .unwrap()
}

#[test]
fn partial_raw_response_and_header_are_retained_on_read_failure() {
    let body = br#"{"result":"completed","window":"original","output":{}}"#;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body[..17]);
    let mut wire = Vec::with_capacity(MAX_FRAME_BYTES + 4);
    assert!(read_response(&mut bytes.as_slice(), &mut wire).is_err());
    assert_eq!(wire, bytes);

    let excessive = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
    let mut wire = Vec::with_capacity(MAX_FRAME_BYTES + 4);
    assert!(read_response(&mut excessive.as_slice(), &mut wire).is_err());
    assert_eq!(wire, excessive);
}

#[test]
fn final_received_response_crossing_original_expiry_stays_raw_and_unknown() {
    struct DelayedFinalFragment<'a> {
        io: DeadlineIo<'a>,
        remaining: usize,
    }

    impl Read for DelayedFinalFragment<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let count = self.io.read(bytes)?;
            self.remaining -= count;
            if self.remaining == 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
            Ok(count)
        }
    }

    let request = Request::Acknowledge {
        window: Id::new("original").unwrap(),
    };
    let body = canonical::canonical_json(
        &serde_json::to_value(Response::Acknowledged {
            window: Id::new("original").unwrap(),
        })
        .unwrap(),
    )
    .unwrap();
    let mut response = (body.len() as u32).to_be_bytes().to_vec();
    response.extend_from_slice(&body);
    let mut journal = Journal::new().unwrap();
    let index = journal.reserve(&request).unwrap();
    let (mut socket, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&response).unwrap();
    let budget = ExchangeBudget::after(Duration::from_millis(200)).unwrap();
    let mut reader = DelayedFinalFragment {
        io: DeadlineIo::new(&mut socket, budget),
        remaining: response.len(),
    };

    let result = read_response_with_budget(
        &mut reader,
        &mut journal.commands[index].response_wire,
        budget,
    );
    journal.charge_response(index);

    assert!(
        matches!(result, Err(ProviderError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut)
    );
    assert_eq!(journal.commands[index].response_wire_bytes(), response);
    assert_eq!(
        journal.commands[index].knowledge(),
        NativeCommandKnowledge::Unknown
    );
}

#[test]
fn response_credit_is_reserved_before_an_original_command_is_appended() {
    let request = Request::Activate {
        window: Id::new("original").unwrap(),
    };
    let mut journal = Journal::new().unwrap();
    let original = canonical::canonical_json(&serde_json::to_value(&request).unwrap()).unwrap();
    while journal.reserve(&request).is_ok() {
        let index = journal.commands.len() - 1;
        journal.commands[index]
            .response_wire
            .resize(MAX_FRAME_BYTES + 4, 0);
        journal.charge_response(index);
    }
    let count = journal.commands.len();
    let retained = journal
        .commands
        .iter()
        .map(|record| record.request.len() + record.response_wire.len())
        .sum::<usize>();
    assert!(retained <= MAX_NATIVE_JOURNAL_BYTES);
    assert!(retained + original.len() + MAX_FRAME_BYTES + 4 > MAX_NATIVE_JOURNAL_BYTES);
    assert!(journal.reserve(&request).is_err());
    assert_eq!(journal.commands.len(), count);
    assert_eq!(journal.commands.last().unwrap().request_bytes(), original);
    assert_eq!(
        journal.commands.last().unwrap().knowledge(),
        NativeCommandKnowledge::Unknown
    );
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_driver_retains_all_original_receipts_and_empty_ancestry_after_reaping() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut device = launch(&root, queue.clone());
    assert_eq!(device.commands().len(), 1);
    let first = stage(0, &[b"same", b"", b"same"]);
    device.stage(first.clone()).unwrap();
    device.stage(first.clone()).unwrap();
    let output = device.activate().unwrap();
    assert_eq!(output.bytes_processed.get(), 8);
    let first_closed = device.close().unwrap();
    first_closed.validate_against(&first, None).unwrap();
    device.acknowledge_publication(&first_closed).unwrap();
    device.acknowledge_publication(&first_closed).unwrap();
    assert_eq!(device.commands().len(), 5);
    assert!(device.windows()[0].acknowledged());

    let next = stage(1, &[b""]);
    device.stage(next.clone()).unwrap();
    device.activate().unwrap();
    let held = device.close().unwrap();
    held.validate_against(&next, Some(&first_closed)).unwrap();
    assert_eq!(held.previous_closed, Some(first_closed.identity().unwrap()));
    assert_eq!(device.status(), LineageDeviceStatus::ClosedPending);
    let token = device.reservation();
    let exact = device
        .commands()
        .iter()
        .map(|record| {
            (
                record.request_bytes().to_vec(),
                record.response_wire_bytes().to_vec(),
                record.knowledge(),
            )
        })
        .collect::<Vec<_>>();
    drop(device);
    reclaimed(&queue, token);
    for (index, original) in exact.iter().enumerate() {
        assert_eq!(&queue.read_command(token, index).unwrap(), original);
    }
    assert_eq!(
        queue.read_window(token, 0).unwrap().closure(),
        Some(&first_closed)
    );
    let retained = queue.read_window(token, 1).unwrap();
    assert_eq!(retained.stage(), &next);
    assert_eq!(retained.closure(), Some(&held));
    assert!(!retained.acknowledged());
    queue.acknowledge_containment(token).unwrap();
    assert!(queue.read_window(token, 1).is_err());
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_transport_loss_keeps_original_output_and_unknown_close_without_retry() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut device = launch(&root, queue.clone());
    let original = stage(0, &[b"same", b"", b"same"]);
    device.stage(original.clone()).unwrap();
    let output = device.activate().unwrap();
    device
        .session_mut()
        .unwrap()
        .child
        .as_mut()
        .unwrap()
        .kill()
        .unwrap();
    assert!(device.close().is_err());
    assert_eq!(device.status(), LineageDeviceStatus::Quarantined);
    let last = device.commands().last().unwrap();
    assert_eq!(last.knowledge(), NativeCommandKnowledge::Unknown);
    let original_close = canonical::canonical_json(
        &serde_json::to_value(Request::Close {
            window: original.grant.window_id.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(last.request_bytes(), original_close);
    let count = device.commands().len();
    assert!(device.close().is_err());
    assert!(device.activate().is_err());
    assert_eq!(device.commands().len(), count);
    assert_eq!(device.windows()[0].output(), Some(&output));
    assert!(device.windows()[0].closure().is_none());
    let token = device.reservation();
    drop(device);
    reclaimed(&queue, token);
    let retained = queue.read_window(token, 0).unwrap();
    assert_eq!(retained.stage(), &original);
    assert_eq!(retained.output(), Some(&output));
    let (request, _, knowledge) = queue.read_command(token, count - 1).unwrap();
    assert_eq!(request, original_close);
    assert_eq!(knowledge, NativeCommandKnowledge::Unknown);
    queue.acknowledge_containment(token).unwrap();
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the separately source-built legacy child"]
fn actual_wrong_dialect_readiness_retains_child_and_original_raw_initialization() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let original = stage(0, &[]);
    let result = NativeLineageDevice::spawn(
        Path::new(&std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap()),
        &root.0,
        original.grant.owner_id.clone(),
        original.grant.incarnation_id.clone(),
        original.grant.generation,
        Duration::from_secs(2),
        queue.clone(),
    );
    assert!(result.is_err());
    let deadline = ExchangeBudget::after(Duration::from_secs(5)).unwrap();
    let token = loop {
        if let Some(status) = queue.retained().first() {
            break status.reservation;
        }
        assert!(!deadline.is_expired());
        std::thread::sleep(Duration::from_millis(1));
    };
    reclaimed(&queue, token);
    let (request, _, knowledge) = queue.read_command(token, 0).unwrap();
    assert_eq!(
        request,
        canonical::canonical_json(
            &serde_json::to_value(Request::Initialize {
                dialect: DIALECT.into(),
                owner: original.grant.owner_id,
                incarnation: original.grant.incarnation_id,
                generation: original.grant.generation
            })
            .unwrap()
        )
        .unwrap()
    );
    assert_eq!(knowledge, NativeCommandKnowledge::Unknown);
    assert_eq!(queue.retained()[0].windows, 0);
    queue.acknowledge_containment(token).unwrap();
}

#[test]
#[ignore = "internal child of the actual complete-private-group reclamation fixture"]
fn auxiliary_group_wait_fixture() {
    assert_eq!(
        std::env::var("CRUCIBLE_LINEAGE_AUXILIARY_FIXTURE").unwrap(),
        "1"
    );
    std::thread::sleep(Duration::from_secs(30));
    panic!("parent did not reclaim its original auxiliary process");
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_group_census_retains_custody_until_secondary_child_is_reaped() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut device = launch(&root, queue.clone());
    device.stage(stage(0, &[b"held"])).unwrap();
    device.activate().unwrap();
    let original = device.close().unwrap();
    let token = device.reservation();
    let group = device.session.as_ref().unwrap().pid;
    let mut auxiliary = AuxiliaryChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "reference_lineage::driver::tests::auxiliary_group_wait_fixture",
                "--ignored",
            ])
            .env_clear()
            .env("CRUCIBLE_LINEAGE_AUXILIARY_FIXTURE", "1")
            .process_group(i32::try_from(group).unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    drop(device);

    let deadline = ExchangeBudget::after(Duration::from_secs(5)).unwrap();
    while !super::super::kernel::exited_without_reaping(&auxiliary.0).unwrap() {
        assert!(!deadline.is_expired());
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        !queue
            .retained()
            .iter()
            .any(|status| status.reservation == token && status.reclaimed)
    );
    assert!(queue.acknowledge_containment(token).is_err());
    // Its zombie still belongs to the original private group. Waiting on the
    // actual auxiliary Child, rather than absence of the leader, settles it.
    assert!(!auxiliary.0.wait().unwrap().success());
    reclaimed(&queue, token);
    assert_eq!(
        queue.read_window(token, 0).unwrap().closure(),
        Some(&original)
    );
    queue.acknowledge_containment(token).unwrap();
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_window_credit_refuses_before_replacing_last_native_closure() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut device = launch(&root, queue.clone());
    for quantum in 0..MAX_WINDOWS {
        device.stage(stage(quantum as u64, &[b""])).unwrap();
        device.activate().unwrap();
        let closed = device.close().unwrap();
        device.acknowledge_publication(&closed).unwrap();
    }
    let commands = device.commands().len();
    let original = device.windows().last().unwrap().closure().unwrap().clone();
    assert!(device.stage(stage(MAX_WINDOWS as u64, &[b"new"])).is_err());
    assert_eq!(device.status(), LineageDeviceStatus::Parked);
    assert_eq!(device.commands().len(), commands);
    assert_eq!(device.windows().len(), MAX_WINDOWS);
    assert_eq!(device.windows().last().unwrap().closure(), Some(&original));
    let token = device.reservation();
    drop(device);
    reclaimed(&queue, token);
    assert_eq!(
        queue.read_window(token, MAX_WINDOWS - 1).unwrap().closure(),
        Some(&original)
    );
    queue.acknowledge_containment(token).unwrap();
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_original_activation_budget_fences_later_effects_and_retains_raw_attempt() {
    let root = Root::new();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut device = launch(&root, queue.clone());
    let mut original = stage(0, &[b"budget input"]);
    original.grant.host_budget_ns = U64::new(1);
    device.stage(original.clone()).unwrap();
    assert!(device.activate().is_err());
    assert_eq!(device.status(), LineageDeviceStatus::Quarantined);
    let commands = device.commands().len();
    assert_eq!(
        device.commands().last().unwrap().knowledge(),
        NativeCommandKnowledge::Unknown
    );
    assert!(device.windows()[0].measured_host_ns().is_some());
    assert!(device.activate().is_err());
    assert!(device.close().is_err());
    assert_eq!(device.commands().len(), commands);
    let token = device.reservation();
    drop(device);
    reclaimed(&queue, token);
    assert_eq!(queue.read_window(token, 0).unwrap().stage(), &original);
    assert_eq!(
        queue.read_command(token, commands - 1).unwrap().2,
        NativeCommandKnowledge::Unknown
    );
    queue.acknowledge_containment(token).unwrap();
}
