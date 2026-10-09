//! Actual mapped geometry and original request publication ordering controls.
//!
//! Full authorization/phase bodies remain labeled external providers. These
//! controls authenticate shared-memory framing and ordering, not native RR
//! closure, UART execution, accepted output, or host ledger retirement.

use super::*;
use crate::{RegionAllocation, RegionConfig, mmap_setup_region};
use crucible_protocol::native_console::*;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, mpsc};

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Layout(#[from] crate::RegionLayoutError),
    #[error(transparent)]
    Serialization(#[from] crate::RegionSerializationError),
    #[error(transparent)]
    Mapping(#[from] crate::SetupRegionMapError),
    #[error(transparent)]
    Shape(#[from] NativeConsoleError),
    #[error(transparent)]
    Slot(#[from] crate::NodeSlotError),
    #[error(transparent)]
    Lookahead(#[from] crate::LookaheadGateError),
    #[error(transparent)]
    Access(#[from] crate::MappedSetupRegionAccessError),
    #[error(transparent)]
    Receive(#[from] mpsc::RecvError),
    #[error(transparent)]
    Send(#[from] mpsc::SendError<()>),
    #[error("mapped request publisher panicked")]
    ThreadPanicked,
}

fn mapping(vm_count: u32) -> Result<Arc<crate::MappedSetupRegion>, FixtureError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let allocation = RegionAllocation::new_model(RegionConfig::new(vm_count, 4))?;
    let bytes = allocation.setup_region_bytes()?;
    let path = std::env::temp_dir().join(format!(
        "crucible-console-clamp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::fs::remove_file(path)?;
    file.set_len(bytes.len() as u64)?;
    file.write_all_at(&bytes, 0)?;
    Ok(Arc::new(mmap_setup_region(
        file.as_fd(),
        bytes.len() as u64,
    )?))
}

fn external_body() -> NativeConsoleAuthorization {
    NativeConsoleAuthorization {
        publication: 2,
        owner: NativeConsoleOwner {
            slot: 0,
            region: [4; 16],
            process: 8,
            authorization: 10,
        },
        logical_generation: 3,
        advance: 2,
        prior_sequence: 0,
        prior_ring_end: 0,
        allowance: 2,
        phase_token: 5,
        phase: NativeConsolePhase::Grant,
    }
}

#[test]
fn real_region_console_segments_are_disjoint_and_reject_reserved_slots() -> Result<(), FixtureError>
{
    let mapped = mapping(2)?;
    let first = mapped.native_console_segment(0)?;
    let second = mapped.native_console_segment(1)?;

    first.authorization.publish(external_body())?;
    assert_eq!(first.authorization.snapshot()?, external_body());
    assert!(second.authorization.snapshot().is_err());
    assert!(mapped.native_console_segment(2).is_err());
    assert!(
        mapped
            .native_console_segment(crate::SLOT_NET_ROUTER as u32)
            .is_err()
    );
    assert_eq!(
        crate::NODE_SLOT_CONTROL_BOUNDARY_PUBLICATION_CLAIM_OFFSET,
        140,
    );
    assert_eq!(crate::NODE_SLOT_SIZE, 256);
    assert_eq!(mapped.node_slot(0)?.control_boundary_token(), 1);
    assert!(mapped.node_slot(0)?.try_snapshot().is_some());
    assert_eq!(first.records.len(), NATIVE_CONSOLE_CAPACITY as usize);
    assert_eq!(second.records.len(), NATIVE_CONSOLE_CAPACITY as usize);
    Ok(())
}

#[test]
fn real_reader_refuses_prepared_fields_until_original_request_release() -> Result<(), FixtureError>
{
    let mapped = mapping(1)?;
    let slot = mapped.node_slot(0)?;
    for _ in 0..2 {
        slot.publish_scheduler_advance(
            crate::authorize_advance_ceiling(0, 100, None)?,
            crate::AdvanceStopCondition::Ceiling,
        )?;
    }
    let paired = NativeConsoleClamp {
        publication: 2,
        advance: 4,
        request: 0,
        capture: 3,
        fault_frontier: 7,
        ceiling: 100,
        stop: 0,
        kind: crucible_protocol::native_console::NativeConsoleControlKind::Acceptance,
        last_issued: Some(external_body()),
    };
    let (prepared_tx, prepared_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let writer_mapping = Arc::clone(&mapped);

    let writer = std::thread::spawn(move || -> Result<u32, FixtureError> {
        let table = writer_mapping.native_console_segment(0)?.clamp;
        let prepared = table.prepare(paired)?;
        Ok(writer_mapping
            .node_slot(0)?
            .request_control_boundary_with_prepared_fields(
                paired.fault_frontier,
                Some(paired.capture),
                |request| {
                    prepared.commit_before_request(request);
                    // Rendezvous observes the genuine interval before its CAS.
                    prepared_tx
                        .send(())
                        .unwrap_or_else(|error| panic!("reader must remain live: {error}"));
                    release_rx
                        .recv()
                        .unwrap_or_else(|error| panic!("reader must release writer: {error}"));
                },
                |_| {},
            )?)
    });

    prepared_rx.recv()?;
    let early = mapped.native_console_clamp_for_request(0);
    let early_request = slot.control_boundary_token();
    let prepared_fields = mapped
        .native_console_segment(0)
        .map(|segment| segment.clamp.snapshot());
    let competing_called = std::cell::Cell::new(false);
    let competing = slot.request_control_boundary_with_prepared_fields(
        paired.fault_frontier,
        Some(paired.capture),
        |_| competing_called.set(true),
        |_| panic!("a refused competing writer cannot retain custody"),
    );
    let ordinary_competing = slot.request_control_boundary(99, None);
    let fields_after_competition = mapped.native_console_segment(0)?.clamp.snapshot();
    release_tx.send(())?;
    let request = writer.join().map_err(|_| FixtureError::ThreadPanicked)??;
    let visible = mapped.native_console_clamp_for_request(0)?;

    assert!(early.is_err());
    assert!(matches!(
        competing,
        Err(crate::NodeSlotError::ControlBoundaryPublicationBusy)
    ));
    assert!(matches!(
        ordinary_competing,
        Err(crate::NodeSlotError::ControlBoundaryPublicationBusy)
    ));
    assert!(!competing_called.get());
    assert_eq!(fields_after_competition?, prepared_fields??);
    assert_eq!(early_request, 1);
    assert_eq!(visible.request, 2);
    assert_eq!(request, 2);
    assert_eq!(visible.advance, 4);
    assert_eq!(visible.last_issued, Some(external_body()));
    assert_eq!(visible.last_issued.map(|body| body.advance), Some(2));
    Ok(())
}

#[test]
fn request_publication_claim_releases_on_unwind_before_another_writer() {
    let slot = crate::NodeSlot::new(crate::KIND_VM);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slot.request_control_boundary_with_prepared_fields(
            7,
            None,
            |_| panic!("controlled pre-publication failure"),
            |_| panic!("unpublished request cannot retain custody"),
        )
    }));

    assert!(failure.is_err());
    assert_eq!(slot.control_boundary_token(), 1);
    let request = slot
        .request_control_boundary(9, None)
        .unwrap_or_else(|error| panic!("unwind must release the original claim: {error}"));
    assert_eq!(request, 2);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 9);
}

#[test]
fn request_claim_survives_writer_process_exit_without_authorizing_pair() -> Result<(), FixtureError>
{
    const CHILD_MAPPING: &str = "CRUCIBLE_TEST_REQUEST_WRITER_MAPPING";
    if let Some(path) = std::env::var_os(CHILD_MAPPING) {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let mapped = mmap_setup_region(file.as_fd(), file.metadata()?.len())?;
        let paired = NativeConsoleClamp {
            publication: 2,
            advance: 4,
            request: 0,
            capture: 3,
            fault_frontier: 7,
            ceiling: 100,
            stop: 0,
            kind: crucible_protocol::native_console::NativeConsoleControlKind::Acceptance,
            last_issued: Some(external_body()),
        };
        let prepared = mapped.native_console_segment(0)?.clamp.prepare(paired)?;
        mapped
            .node_slot(0)?
            .request_control_boundary_with_prepared_fields(
                7,
                Some(3),
                |request| {
                    prepared.commit_before_request(request);
                    // Actual owned-process exit skips lexical cleanup. The parent
                    // must not recover this claim by pretending its writer finished.
                    std::process::exit(23);
                },
                |_| panic!("the terminated writer cannot publish a request"),
            )?;
        panic!("child must exit inside the original claimed publication");
    }

    static NEXT_PROCESS: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "crucible-console-dead-publisher-{}-{}",
        std::process::id(),
        NEXT_PROCESS.fetch_add(1, Ordering::Relaxed),
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    let cleanup = MappingPathCleanup(path);
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
    let image = allocation.setup_region_bytes()?;
    file.set_len(image.len() as u64)?;
    file.write_all_at(&image, 0)?;
    let mapped = mmap_setup_region(file.as_fd(), image.len() as u64)?;
    let slot = mapped.node_slot(0)?;
    for _ in 0..2 {
        slot.publish_scheduler_advance(
            crate::authorize_advance_ceiling(0, 100, None)?,
            crate::AdvanceStopCondition::Ceiling,
        )?;
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "native_console::clamp_tests::request_claim_survives_writer_process_exit_without_authorizing_pair",
            "--nocapture",
        ])
        .env(CHILD_MAPPING, &cleanup.0)
        .output()?;

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(
        mapped.native_console_segment(0)?.clamp.snapshot()?.request,
        2
    );
    assert!(slot.try_snapshot().is_none());
    assert!(mapped.native_console_clamp_for_request(0).is_err());
    assert!(matches!(
        slot.request_control_boundary(7, Some(3)),
        Err(crate::NodeSlotError::ControlBoundaryPublicationBusy),
    ));
    assert!(slot.clone().try_snapshot().is_none());
    Ok(())
}

struct MappingPathCleanup(std::path::PathBuf);

impl Drop for MappingPathCleanup {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}

#[test]
fn setup_serialization_refuses_an_unfinished_request_claim() -> Result<(), FixtureError> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
    let slot = &allocation.slots()[0];
    slot.control_boundary_publication_claim
        .store(1, Ordering::Release);

    assert!(matches!(
        allocation.setup_region_bytes(),
        Err(crate::RegionSerializationError::NodeSlotPublicationBusy { index: 0 }),
    ));
    assert!(matches!(
        allocation.clone().setup_region_bytes(),
        Err(crate::RegionSerializationError::NodeSlotPublicationBusy { index: 0 }),
    ));
    Ok(())
}
