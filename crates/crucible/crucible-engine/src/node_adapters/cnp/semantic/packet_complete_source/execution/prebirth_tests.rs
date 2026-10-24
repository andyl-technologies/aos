//! Exercises actual Source prebirth banks without installing native authority.
//!
//! The existing closed declaration fixture constructs a real unassociated
//! Source. Reservations retain data only; no child is launched and no scope,
//! current native witness, readiness, whole admission or capture ticket is made.

use super::super::tests::{coordinator, installation, producer, storage_selection};
use super::*;
use crate::node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticProcessSlot};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
};

type TestResult = Result<(), String>;

const BACKEND_BYTES: usize = 4096;

fn source() -> Result<PacketCompleteSemanticSource, String> {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .map_err(|failure| format!("{failure:?}"))?;
    source
        .bind_original_capture_profile(PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(1024 * 1024),
            native_after_protocol_bytes: U64::new(1024 * 1024),
            host_protocol_bytes: U64::new(2 * 1024 * 1024),
        })
        .map_err(|failure| format!("{failure:?}"))?;
    assert!(source.authenticate_current_native().is_err());
    Ok(source)
}

fn requested() -> usize {
    BACKEND_BYTES
        + COMPLETE_EVIDENCE_ROLES * size_of::<InputPayload>()
        + COMPLETE_BORN_ROLES * size_of::<born::OriginalBornObject>()
}

fn allocation_identity(
    source: &PacketCompleteSemanticSource,
) -> Result<(usize, usize, usize, usize, usize), String> {
    let execution = source
        .capture_execution
        .try_borrow()
        .map_err(|error| error.to_string())?;
    let execution = execution.as_ref().ok_or("original execution absent")?;
    let bank = execution
        .backend_bank
        .as_ref()
        .ok_or("original backend bank absent")?;
    assert!(
        !execution.started
            && !execution.failed
            && !execution.wire_attempted
            && !execution.transferred
    );
    assert!(execution.backend.is_none() && execution.dependency_plan.is_none());
    Ok((
        bank.allocated_bytes(),
        execution.evidence.as_ptr() as usize,
        execution.evidence.capacity(),
        execution.born.as_ptr() as usize,
        execution.born.capacity(),
    ))
}

#[test]
fn execution_reservation_owns_actual_prebirth_banks_without_native_authority() -> TestResult {
    let mut source = source()?;
    source
        .reserve_original_complete_capture_execution(BACKEND_BYTES, requested())
        .map_err(|failure| format!("{failure:?}"))?;
    let execution = source
        .capture_execution
        .try_borrow()
        .map_err(|error| error.to_string())?;
    let execution = execution.as_ref().ok_or("original execution absent")?;

    assert_eq!(
        execution
            .backend_bank
            .as_ref()
            .ok_or("backend bank absent")?
            .allocated_bytes(),
        BACKEND_BYTES
    );
    assert!(execution.evidence.is_empty() && execution.born.is_empty());
    assert_eq!(execution.evidence.capacity(), COMPLETE_EVIDENCE_ROLES);
    assert_eq!(execution.born.capacity(), COMPLETE_BORN_ROLES);
    assert_eq!(
        execution
            .retained_storage(requested())
            .map_err(|failure| format!("{failure:?}"))?,
        requested()
    );
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

#[test]
fn execution_reservation_one_short_preserves_same_unallocated_source() -> TestResult {
    let mut source = source()?;
    assert!(
        source
            .reserve_original_complete_capture_execution(BACKEND_BYTES, requested() - 1)
            .is_err()
    );
    assert!(
        source
            .capture_execution
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );
    assert!(!source.complete_bytes_launch_reserved.get());

    source
        .reserve_original_complete_capture_execution(BACKEND_BYTES, requested())
        .map_err(|failure| format!("{failure:?}"))?;
    assert_eq!(allocation_identity(&source)?.0, BACKEND_BYTES);
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

#[test]
fn second_execution_reservation_keeps_same_original_allocations() -> TestResult {
    let mut source = source()?;
    source
        .reserve_original_complete_capture_execution(BACKEND_BYTES, requested())
        .map_err(|failure| format!("{failure:?}"))?;
    let original = allocation_identity(&source)?;

    assert!(
        source
            .reserve_original_complete_capture_execution(BACKEND_BYTES * 2, requested() * 2)
            .is_err()
    );
    assert_eq!(allocation_identity(&source)?, original);
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

struct UnlaunchedSlot {
    identity_reads: Rc<Cell<usize>>,
    retained: Rc<RefCell<Vec<CnpSemanticProcessCustody>>>,
}

impl CnpSemanticProcessSlot for UnlaunchedSlot {
    fn identity(&self) -> U64 {
        self.identity_reads.set(self.identity_reads.get() + 1);
        U64::new(41)
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        self.retained.borrow_mut().push(custody);
    }
}

#[test]
fn execution_reservation_refuses_after_actual_unlaunched_launch_reservation() -> TestResult {
    let mut source = source()?;
    let executable = source
        .installation()
        .provider
        .implementation
        .artifacts
        .iter()
        .find(|artifact| artifact.role.as_str() == "executable")
        .ok_or("fixture executable declaration absent")?
        .content
        .clone();
    let identity_reads = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(Vec::new()));
    let launch = source
        .reserve_original_complete_bytes_launch(
            PathBuf::from("unlaunched-complete-execution-control"),
            executable,
            Box::new(UnlaunchedSlot {
                identity_reads: Rc::clone(&identity_reads),
                retained: Rc::clone(&retained),
            }),
        )
        .map_err(|failure| format!("{failure:?}"))?;
    assert_eq!(identity_reads.get(), 1);
    assert!(source.complete_bytes_launch_reserved.get());

    assert!(
        source
            .reserve_original_complete_capture_execution(BACKEND_BYTES, requested())
            .is_err()
    );
    assert!(
        source
            .capture_execution
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );
    assert!(source.authenticate_current_native().is_err());
    drop(launch);
    assert!(source.complete_bytes_launch_reserved.get());
    assert!(
        source
            .reserve_original_complete_capture_execution(BACKEND_BYTES, requested())
            .is_err()
    );
    assert!(
        source
            .capture_execution
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );
    assert!(
        retained
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_empty()
    );
    assert_eq!(identity_reads.get(), 1);
    Ok(())
}

#[test]
fn selected_report_return_bank_has_independent_prechild_credit() -> TestResult {
    let ordinary = execution_reservation_requested_bytes(BACKEND_BYTES, false, usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    let selected = execution_reservation_requested_bytes(BACKEND_BYTES, true, usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(ordinary, requested());
    assert_eq!(
        selected - ordinary,
        allocation_report_capacity()
            + size_of::<InputPayload>()
            + size_of::<born::OriginalBornObject>()
    );
    assert!(execution_reservation_requested_bytes(BACKEND_BYTES, true, selected - 1).is_err());
    assert_eq!(
        execution_reservation_requested_bytes(BACKEND_BYTES, true, selected)
            .map_err(|error| format!("{error:?}"))?,
        selected
    );
    assert!(execution_reservation_requested_bytes(usize::MAX, true, usize::MAX).is_err());
    Ok(())
}

#[test]
fn execution_reservation_freezes_report_selection_before_native_association() -> TestResult {
    let mut source = source()?;
    let demand = source
        .original_complete_capture_execution_reservation_requested_data(BACKEND_BYTES)
        .map_err(|error| format!("{error:?}"))?;
    source
        .reserve_original_complete_capture_execution(BACKEND_BYTES, demand)
        .map_err(|error| format!("{error:?}"))?;
    let identity = allocation_identity(&source)?;
    assert!(source.bind_original_capture_allocation_selection(Some(
        crucible_node_transport::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12
    )).is_err());
    assert_eq!(allocation_identity(&source)?, identity);
    let slots = source
        .capture_execution
        .try_borrow()
        .map_err(|error| error.to_string())?;
    let execution = slots.as_ref().ok_or("execution absent")?;
    assert!(!execution.allocation_selected);
    assert_eq!(execution.allocation_bank.capacity(), 0);
    assert!(execution.allocation.is_none());
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

#[test]
fn typed_execution_reservation_uses_same_calculation_and_retains_actual_banks() -> TestResult {
    let source = source()?;
    let demand = source
        .original_complete_capture_execution_reservation_requested_data_with_error::<RuntimeError>(
            BACKEND_BYTES,
        )
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        demand,
        source
            .original_complete_capture_execution_reservation_requested_data(BACKEND_BYTES)
            .map_err(|error| format!("{error:?}"))?
    );
    assert!(matches!(
        source.reserve_original_complete_capture_execution_with_error::<RuntimeError>(
            BACKEND_BYTES,
            demand - 1
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(
        source
            .capture_execution
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );
    source
        .reserve_original_complete_capture_execution_with_error::<RuntimeError>(
            BACKEND_BYTES,
            demand,
        )
        .map_err(|error| format!("{error:?}"))?;
    let identity = allocation_identity(&source)?;
    assert!(
        source
            .reserve_original_complete_capture_execution_with_error::<RuntimeError>(
                BACKEND_BYTES,
                demand
            )
            .is_err()
    );
    assert_eq!(allocation_identity(&source)?, identity);
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

#[test]
fn typed_execution_reservation_checks_creator_before_busy_owner_loan() -> TestResult {
    let mut source = source()?;
    source.process = source.process.wrapping_add(1);
    let _busy = source.capture_execution.borrow_mut();
    assert!(matches!(source.original_complete_capture_execution_reservation_requested_data_with_error::<RuntimeError>(BACKEND_BYTES), Err(RuntimeError::ForeignAuthority)));
    assert!(matches!(
        source.reserve_original_complete_capture_execution_with_error::<RuntimeError>(
            BACKEND_BYTES,
            requested()
        ),
        Err(RuntimeError::ForeignAuthority)
    ));
    Ok(())
}
