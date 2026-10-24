//! Exact native Compute callback loans for original staged token reservations.
//!
//! The private producer installs a loan only after authentic native admission,
//! exact original allocation lookup and paired-ring begin. Device callbacks can
//! query the loan but cannot install it. Queries borrow the same retained full
//! request/stage/consumed-commit bodies without reconstructing device tokens.
//! This module supplies no constructor adoption, Ready or native retirement.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::sync::Arc;

use crucible_qemu_protocol::whole_control::{
    body::WholeRequest,
    staged::body::{StageCommit, StageReceipt, StageReferences},
};

use super::whole_journals::{WholeJournalError, WholeJournals};

thread_local! {
    static ACTIVE: RefCell<Option<NativeComputeInputScope>> = const { RefCell::new(None) };
    static REFUSED: Cell<bool> = const { Cell::new(false) };
}

/// Keeps a real input-owner guard held while asserting no callback revocation.
#[cfg(test)]
pub(super) fn assert_guarded_input_owner_unchanged(callback: impl FnOnce()) {
    ACTIVE.with(|active| {
        let _guard = active.borrow_mut();
        let before = REFUSED.get();
        callback();
        assert_eq!(REFUSED.get(), before);
    });
}

struct NativeComputeInputScope {
    journals: Arc<WholeJournals>,
    process: u32,
    epoch: u64,
    sequence: u64,
    boundary_ps: u64,
    orderly_revocation: bool,
}

impl Drop for NativeComputeInputScope {
    fn drop(&mut self) {
        if !self.orderly_revocation
            && self.process == std::process::id()
            && let Ok(compute) = self.journals.compute(self.sequence)
        {
            // Thread exit or an abandoned callback revokes token admission and
            // retains uncertainty in the same constructor-owned allocation.
            compute.refuse();
        }
    }
}

/// Installs the literal native callback's original Compute input loan.
///
/// This is a private producer operation, called after paired begin succeeds.
/// Portable request correlation is an additional check; the native callback
/// and original constructor retain source admission authority.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(super) fn begin_native_compute_input_scope(
    journals: Arc<WholeJournals>,
    epoch: u64,
    sequence: u64,
    allocation: *mut c_void,
) -> Result<(), WholeJournalError> {
    // A second Begin first removes every old loan, before parsing another
    // allocation. Failure cannot leave previously consumable credits alive.
    let stale = ACTIVE.with(|active| {
        let Ok(mut active) = active.try_borrow_mut() else {
            REFUSED.set(true);
            return true;
        };
        let old = active.take();
        let present = old.is_some();
        drop(old);
        present
    });
    if stale || REFUSED.get() {
        REFUSED.set(true);
        if let Ok(compute) = journals.compute_allocation(sequence, allocation) {
            compute.refuse();
        }
        return Err(WholeJournalError::Ownership);
    }
    let compute = journals.compute_allocation(sequence, allocation)?;
    let request = WholeRequest::decode_staged(compute.request_body()?)
        .map_err(|_| WholeJournalError::Correlation)?;
    if epoch != request.epoch || sequence != request.sequence || compute.is_uncertain() {
        return Err(WholeJournalError::Correlation);
    }
    ACTIVE.with(|active| {
        let mut active = active
            .try_borrow_mut()
            .map_err(|_| WholeJournalError::Ownership)?;
        if active.is_some() {
            compute.refuse();
            return Err(WholeJournalError::Ownership);
        }
        *active = Some(NativeComputeInputScope {
            journals: Arc::clone(&journals),
            process: std::process::id(),
            epoch,
            sequence,
            boundary_ps: request.start_ps,
            orderly_revocation: false,
        });
        Ok(())
    })
}

/// Advances input eligibility only in the same literal native Compute loan.
///
/// The producer calls this with the source's actual service boundary before
/// servicing due records. Future staged completions cannot pass the device poll
/// gate merely because they occur somewhere in the original grant interval.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(super) fn advance_native_compute_input_boundary(
    epoch: u64,
    sequence: u64,
    allocation: *mut c_void,
    time_ps: u64,
) -> Result<(), WholeJournalError> {
    let result = ACTIVE.with(|active| {
        let mut active = active
            .try_borrow_mut()
            .map_err(|_| WholeJournalError::Ownership)?;
        let scope = active.as_mut().ok_or(WholeJournalError::Missing)?;
        if REFUSED.get()
            || scope.process != std::process::id()
            || scope.epoch != epoch
            || scope.sequence != sequence
        {
            return Err(WholeJournalError::Correlation);
        }
        let compute = scope.journals.compute_allocation(sequence, allocation)?;
        let request = WholeRequest::decode_staged(compute.request_body()?)
            .map_err(|_| WholeJournalError::Correlation)?;
        if compute.is_uncertain() || time_ps < scope.boundary_ps || time_ps > request.limit_ps {
            return Err(WholeJournalError::Correlation);
        }
        scope.boundary_ps = time_ps;
        Ok(())
    });
    if result.is_err() {
        refuse_native_compute_input_scope();
    }
    result
}

/// Revokes input permission before any fallible scope-end observation.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(super) fn revoke_native_compute_input_scope() {
    ACTIVE.with(|active| {
        if let Ok(mut active) = active.try_borrow_mut()
            && let Some(mut scope) = active.take()
        {
            scope.orderly_revocation = true;
        }
    });
}

/// Revokes and retains sticky uncertainty without a native getter or ring read.
pub(super) fn refuse_native_compute_input_scope() {
    REFUSED.set(true);
    ACTIVE.with(|active| {
        if let Ok(mut active) = active.try_borrow_mut() {
            // Drop records failure only in the current original PID. The
            // separate mapping owner revokes its exact TLS ring permit too.
            active.take();
        }
    });
}

/// Checks an original token reservation against the current native callback loan.
///
/// The stage allocation is the actual stable constructor-owned journal address,
/// compared as an identity and never dereferenced. Its committed full input
/// record must occur in this original request and inside its authentic interval.
pub(crate) fn reservation_current(original_stage_allocation: usize, record_index: u32) -> bool {
    ACTIVE.with(|active| {
        let Ok(active) = active.try_borrow() else {
            return false;
        };
        let Some(scope) = active.as_ref() else {
            return false;
        };
        !REFUSED.get()
            && scope.process == std::process::id()
            && scope
                .matches_reservation(original_stage_allocation, record_index)
                .unwrap_or(false)
    })
}

impl NativeComputeInputScope {
    fn matches_reservation(
        &self,
        allocation: usize,
        record_index: u32,
    ) -> Result<bool, WholeJournalError> {
        let compute = self.journals.compute(self.sequence)?;
        if compute.is_uncertain() {
            return Ok(false);
        }
        let request = WholeRequest::decode_staged(compute.request_body()?)
            .map_err(|_| WholeJournalError::Correlation)?;
        if request.epoch != self.epoch || request.sequence != self.sequence {
            return Ok(false);
        }
        let references = StageReferences::decode(request.input_inventory)
            .map_err(|_| WholeJournalError::Correlation)?;
        for reference in references.records() {
            let stage = self.journals.stage(reference.stage_sequence)?;
            if std::ptr::from_ref(stage) as usize != allocation
                || record_index < reference.first_record
                || record_index >= reference.first_record + reference.record_count
            {
                continue;
            }
            let body = stage.body()?;
            let receipt = StageReceipt::decode(stage.receipt_body()?)
                .map_err(|_| WholeJournalError::Correlation)?;
            let consumed = StageCommit::decode(stage.consumed_commit_body()?)
                .map_err(|_| WholeJournalError::Correlation)?;
            if body.scope != request.scope
                || body.native_epoch != self.epoch
                || body.digest() != reference.stage_body_digest
                || receipt.stage_cut != reference.stage_cut
                || consumed.stage_body_digest != reference.stage_body_digest
                || consumed.stage_cut != reference.stage_cut
            {
                return Ok(false);
            }
            let Some(record) = body.queue_inventory.records().nth(record_index as usize) else {
                return Ok(false);
            };
            return Ok(record.time_ps >= request.start_ps
                && record.time_ps <= self.boundary_ps
                && record.time_ps < request.limit_ps);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Original journal/TLS component controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crucible_qemu_protocol::whole_control::{
        WholeControlProfile,
        body::WholeOperationQuota,
        staged::{StagedControlProfile, body::StageInventory, queue_plan::QueuePlan},
    };

    const STAGE: &[u8] = include_bytes!(
        "../../../crucible-qemu-protocol/src/whole_control/testdata/native-stage.bin"
    );
    const RECEIPT: &[u8] = include_bytes!(
        "../../../crucible-qemu-protocol/src/whole_control/testdata/native-stage-receipt.bin"
    );
    const COMMIT: &[u8] = include_bytes!(
        "../../../crucible-qemu-protocol/src/whole_control/testdata/native-stage-commit.bin"
    );
    const PLAN: &[u8] = include_bytes!(
        "../../../crucible-qemu-protocol/src/whole_control/testdata/native-queue-plan.bin"
    );
    const REFERENCES: &[u8] = include_bytes!(
        "../../../crucible-qemu-protocol/src/whole_control/testdata/native-stage-references.bin"
    );

    fn journals() -> Arc<WholeJournals> {
        journals_delayed_record(0)
    }

    fn journals_delayed_record(delay: u64) -> Arc<WholeJournals> {
        let native_stage = StageInventory::decode(STAGE).unwrap();
        let mut stage_bytes = STAGE.to_vec();
        if delay != 0 {
            // This is a distinct modeled future-input fixture, not the native
            // vector's issued receipt. Public encoding retains its full record.
            let mut record = native_stage.queue_inventory.records().next().unwrap();
            record.time_ps += delay;
            record.frame_delivery_icount = record.time_ps;
            let length = 216
                + record.node.len()
                + record.port.len()
                + record.lane.len()
                + record.media_type.len()
                + record.common_envelope.len()
                + record.payload.len();
            let mut inventory = vec![0; 8 + length];
            inventory[..4].copy_from_slice(&1u32.to_be_bytes());
            record.encode_into(&mut inventory[8..]).unwrap();
            crucible_qemu_protocol::whole_control::staged::body::StageInventoryParts {
                scope: native_stage.scope,
                native_epoch: native_stage.native_epoch,
                stage_sequence: native_stage.stage_sequence,
                stage_operation: native_stage.stage_operation,
                batch: native_stage.batch,
                node: native_stage.node,
                cutoff_ps: native_stage.cutoff_ps,
                cutoff_microstep: native_stage.cutoff_microstep,
                common_inventory_digest: native_stage.common_inventory_digest,
                common_batch: native_stage.common_batch,
                queue_inventory: &inventory,
            }
            .encode_into(&mut stage_bytes)
            .unwrap();
        }
        let stage = StageInventory::decode(&stage_bytes).unwrap();
        let mut receipt = StageReceipt::decode(RECEIPT).unwrap();
        receipt.stage_body_digest = stage.digest();
        let receipt_bytes = receipt.encode().unwrap();
        let plan = QueuePlan::decode(PLAN).unwrap().digest();
        let commit = StageCommit::for_receipt(&stage, &receipt, plan)
            .unwrap()
            .encode()
            .unwrap();
        let mut references = REFERENCES.to_vec();
        references[24..56].copy_from_slice(&stage.digest());
        let profile = StagedControlProfile {
            compute: WholeControlProfile {
                scope: stage.scope,
                operation_capacity: 2,
                body_byte_limit: 1024,
                native_history_byte_limit: 1_000_000,
                provider_history_byte_limit: 1_000_000,
                administrative_read_attempt_limit: 100,
                administrative_read_byte_limit: 100_000,
                administrative_write_attempt_limit: 100,
                administrative_write_byte_limit: 100_000,
                deadline_monotonic_ns: 1,
                cpu_retirement_limit: 100,
                event_step_limit: 100,
                input_byte_limit: 100,
                input_record_limit: 10,
                output_byte_limit: 100,
                output_record_limit: 10,
            },
            input_stage_limit: 3,
            stage_body_byte_limit: 1024,
        };
        let journals = Arc::new(WholeJournals::new(&profile, 0).unwrap());
        let original = journals.stage(1).unwrap();
        original.retain_body(&stage_bytes).unwrap();
        original.retain_receipt(&receipt_bytes, plan).unwrap();
        original.retain_commit(&commit, plan).unwrap();
        let time = stage.queue_inventory.records().next().unwrap().time_ps;
        let request = WholeRequest {
            scope: stage.scope,
            epoch: stage.native_epoch,
            sequence: 1,
            grant_digest: [1; 32],
            binding_digest: [2; 32],
            start_ps: time - delay,
            limit_ps: time + 50,
            quota: WholeOperationQuota {
                input_bytes: 8,
                input_records: 1,
                output_bytes: 0,
                output_records: 0,
                cpu_retirements: 1,
                event_steps: 1,
            },
            input_inventory: &references,
        };
        let mut body = vec![0; 256 + references.len()];
        request.encode_staged_into(&mut body).unwrap();
        journals.compute(1).unwrap().retain_request(&body).unwrap();
        journals
    }

    fn begin(journals: &Arc<WholeJournals>) {
        let allocation = std::ptr::from_ref(journals.compute(1).unwrap())
            .cast_mut()
            .cast();
        let epoch = journals.stage(1).unwrap().body().unwrap().native_epoch;
        begin_native_compute_input_scope(Arc::clone(journals), epoch, 1, allocation).unwrap();
    }

    #[test]
    fn original_committed_reference_matches_only_exact_thread_allocation_and_record() {
        let journals = journals();
        let stage = journals.stage(1).unwrap();
        let allocation = std::ptr::from_ref(stage) as usize;
        assert!(!reservation_current(allocation, 0));

        // Native admission is modeled in this journal component. Production
        // installs this loan only from its literal authenticated C callback.
        begin(&journals);
        assert!(!reservation_current(allocation, 0));
        stage.retain_consumed_commit(COMMIT).unwrap();
        assert!(reservation_current(allocation, 0));
        assert!(!reservation_current(allocation + 1, 0));
        assert!(!reservation_current(allocation, 1));
        assert!(
            !std::thread::spawn(move || reservation_current(allocation, 0))
                .join()
                .unwrap()
        );

        revoke_native_compute_input_scope();
        assert!(!reservation_current(allocation, 0));
        assert!(!journals.compute(1).unwrap().is_uncertain());
    }

    #[test]
    fn explicit_refusal_and_thread_exit_revoke_and_retain_uncertain_original() {
        let journals = journals();
        begin(&journals);
        refuse_native_compute_input_scope();
        assert!(journals.compute(1).unwrap().is_uncertain());

        let other = super::tests::journals();
        let retained = Arc::clone(&other);
        std::thread::spawn(move || begin(&retained)).join().unwrap();
        assert!(other.compute(1).unwrap().is_uncertain());
    }

    #[test]
    fn foreign_compute_allocation_is_compared_without_dereferencing_it() {
        let journals = journals();
        let epoch = journals.stage(1).unwrap().body().unwrap().native_epoch;
        assert_eq!(
            begin_native_compute_input_scope(
                journals,
                epoch,
                1,
                std::ptr::without_provenance_mut(1)
            ),
            Err(WholeJournalError::Ownership)
        );
    }
    #[test]
    fn future_completion_is_ineligible_until_the_same_native_service_boundary() {
        let journals = journals_delayed_record(50);
        let stage = journals.stage(1).unwrap();
        stage
            .retain_consumed_commit(stage.commit_body().unwrap())
            .unwrap();
        let stage_allocation = std::ptr::from_ref(stage) as usize;
        let compute_allocation = std::ptr::from_ref(journals.compute(1).unwrap())
            .cast_mut()
            .cast();
        let body = stage.body().unwrap();
        let epoch = body.native_epoch;
        let due = body.queue_inventory.records().next().unwrap().time_ps;
        begin(&journals);
        assert!(!reservation_current(stage_allocation, 0));

        // The component models literal native service admission; this method
        // cannot install a missing loan or prove source readiness itself.
        advance_native_compute_input_boundary(epoch, 1, compute_allocation, due).unwrap();
        assert!(reservation_current(stage_allocation, 0));
        assert!(
            advance_native_compute_input_boundary(epoch, 1, compute_allocation, due - 50).is_err()
        );
        assert!(!reservation_current(stage_allocation, 0));
        assert!(journals.compute(1).unwrap().is_uncertain());
    }
}
