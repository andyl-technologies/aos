//! Releases Stop cleanup proof after actual Core and native Source22 retirement.
//!
//! The prospective identity comes only from the atomic native N+4-row append:
//! Stop/current Recover completion and any older pending Recover supersession.
//! The private token owns the remaining C/Source native originals while the
//! entire Core model/read/clock prefix retires. Only real lower positive
//! completion releases a witness to the immediate Kernel/current-C checker.

use super::*;
use crate::closed_controller_append::require_current_map;
use crate::journal::{JournalTransaction, RecordNamespace};
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2 as Cut;
use aos_sandbox_protocol::domain_ledger::operation::effect_key;
use aos_sandbox_protocol::public_api::projection::{PROJECTION_KEY_PREFIX, PublicProjectionKindV1};
use sha2::{Digest as _, Sha256};

const PROJECTION_KEY_BYTES: usize = PROJECTION_KEY_PREFIX.len() + 1 + 16;

/// Retains completed native Stop/Recover terminal custody after Source disposal.
///
/// This value proves only one exact same-Controller completion. It cannot
/// append, retry, sign, renew a deadline or adopt historical Source authority.
#[must_use = "check this witness immediately against the same current Controller"]
pub struct ControllerHostStopCleanupCompletionV1 {
    controller: crate::journal::ExecutionObservationJournalIdentityV4,
    cut: Cut,
    target: OperationId,
    recovery: OperationId,
    projection_key: [u8; PROJECTION_KEY_BYTES],
    terminal_digests: [[u8; 32]; 4],
}

/// Holds only the actual native originals awaiting final upper graph retirement.
///
/// Runtime must drop its whole SDK/Root/Session/cold/model graph before invoking
/// completion. The lower native owner independently checks the genuine armed
/// scope and permanently latches the actual last-owner conjunction.
#[must_use = "drop every upper native graph before completing Source22 disposal"]
pub struct ControllerHostStopCleanupPositiveDisposalV1<'source> {
    native: ControllerCreateProvisioningReceivingV1,
    source_native: SourceProvisioningCurrentnessOriginalV1,
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    completion: ControllerHostStopCleanupCompletionV1,
    response: aos_proto::aos::sandbox::v1::Operation,
}

/// Retains native disposal while the actual SDK and Core graph retire in place.
///
/// Construction follows the same complete terminal and owed-post checks as
/// native disposal. This pending value lends no completion method. Its private
/// slot borrow keeps the actual Core payload occupied until Runtime has dropped
/// the SDK; consuming retirement then releases the Source-only disposer.
///
/// The pending stage cannot invoke native positive completion directly.
///
/// ```compile_fail
/// use aos_sandbox::{Journal, controller_lifecycle_stop::ControllerHostStopCleanupPendingDisposalV1};
/// fn complete_early(pending: ControllerHostStopCleanupPendingDisposalV1<'_, '_>, controller: &mut Journal) {
///     pending.complete_after_disposal_v1(controller);
/// }
/// ```
///
/// Its native state and occupied-slot association cannot be adopted by callers.
///
/// ```compile_fail
/// use aos_sandbox::controller_lifecycle_stop::{ControllerHostStopCleanupPendingDisposalV1, ControllerLifecycleStopOriginalV4};
/// fn adopt(slot: &mut Option<ControllerLifecycleStopOriginalV4>) {
///     let pending = ControllerHostStopCleanupPendingDisposalV1 { owner: slot, disposal: None };
/// }
/// ```
#[must_use = "drop the SDK, then retire the same Core slot before native completion"]
pub struct ControllerHostStopCleanupPendingDisposalV1<'owner, 'source> {
    owner: &'owner mut Option<ControllerLifecycleStopOriginalV4>,
    disposal: Option<ControllerHostStopCleanupPositiveDisposalV1<'source>>,
}

impl<'source> ControllerHostStopCleanupPendingDisposalV1<'_, 'source> {
    /// Destroys the actual Core graph in its resident slot before native release.
    ///
    /// The same Runtime caller must first drop its SDK/Root/Session/cold graph.
    /// The lower disposer independently checks the real native last-owner
    /// conjunction before either native positive transition can complete.
    /// No replacement Core original or whole-Core move is constructed here.
    #[doc(hidden)]
    pub fn retire_core_in_place_once_v1(
        mut self,
    ) -> ControllerHostStopCleanupPositiveDisposalV1<'source> {
        *self.owner = None;
        match self.disposal.take() {
            Some(disposal) => disposal,
            None => std::process::abort(),
        }
    }
}

impl Drop for ControllerHostStopCleanupPendingDisposalV1<'_, '_> {
    fn drop(&mut self) {
        // Abandonment or a destructor unwind cannot clear the slot and expose
        // completion. Preserve the existing fail-stop native custody law.
        if self.disposal.is_some() {
            std::process::abort();
        }
    }
}

pub(super) fn receiving_demand_v1() -> Result<ResourceVector> {
    let bytes = std::mem::size_of::<ControllerHostStopCleanupPositiveDisposalV1<'_>>()
        .checked_mul(3)
        .and_then(|n| {
            n.checked_add(
                std::mem::size_of::<ControllerHostStopCleanupPendingDisposalV1<'_, '_>>()
                    .checked_mul(3)?,
            )
        })
        .and_then(|n| {
            n.checked_add(
                std::mem::size_of::<ControllerHostStopCleanupCompletionV1>().checked_mul(3)?,
            )
        })
        .and_then(|n| {
            n.checked_add(std::mem::size_of::<ControllerLifecycleStopOriginalV4>().checked_mul(2)?)
        })
        .and_then(|n| {
            n.checked_add(
                std::mem::size_of::<crate::OperatorCleanupRecoveryCompletionV2>().checked_mul(3)?,
            )
        })
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(CLOSED)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

impl ControllerHostStopCleanupCompletionV1 {
    pub(crate) fn require_recovery_current_v1(
        &self,
        controller: &Journal,
        recovery: OperationId,
    ) -> Result<()> {
        if recovery != self.recovery
            || !self
                .controller
                .is_same_original_v4(&controller.execution_observation_identity_v4())
        {
            return Err(CLOSED);
        }
        require_current_map(controller, self.cut)?;
        let effect = effect_key(self.target, 0);
        let keys: [(RecordNamespace, &[u8]); 4] = [
            (RecordNamespace::Effect, &effect),
            (RecordNamespace::Operation, self.target.as_bytes()),
            (RecordNamespace::DesiredState, &self.projection_key),
            (RecordNamespace::Operation, self.recovery.as_bytes()),
        ];
        for ((namespace, key), expected) in keys.into_iter().zip(self.terminal_digests) {
            let value = controller.get(namespace, key).ok_or(CLOSED)?;
            let actual: [u8; 32] = Sha256::digest(value).into();
            if actual != expected {
                return Err(CLOSED);
            }
        }
        Ok(())
    }
}

// Only the completed native actor calls this DATA reduction. Retaining fixed
// commitments lets every transaction/model payload drop before Source positive
// completion; the immediate checker still binds the same full cut and rows.
// Every extra supersession row must first match its retained canonical owner;
// the complete C cut then retains that entire tail through native disposal.
fn terminal_commitments<'rows>(
    transaction: &JournalTransaction,
    target: OperationId,
    recovery: OperationId,
    expected_supersession: impl Iterator<Item = &'rows crate::JournalRecord>,
) -> Result<([u8; PROJECTION_KEY_BYTES], [[u8; 32]; 4])> {
    let [effect, operation, projection, metadata, superseded @ ..] = transaction.records() else {
        return Err(CLOSED);
    };
    if !superseded.iter().eq(expected_supersession) {
        return Err(CLOSED);
    }
    let projection_key: [u8; PROJECTION_KEY_BYTES] =
        projection.key().try_into().map_err(|_| CLOSED)?;
    if target == recovery
        || effect.namespace() != RecordNamespace::Effect
        || effect.key() != effect_key(target, 0)
        || operation.namespace() != RecordNamespace::Operation
        || operation.key() != target.as_bytes()
        || projection.namespace() != RecordNamespace::DesiredState
        || !projection_key.starts_with(PROJECTION_KEY_PREFIX)
        || projection_key[PROJECTION_KEY_PREFIX.len()] != PublicProjectionKindV1::Sandbox as u8
        || metadata.namespace() != RecordNamespace::Operation
        || metadata.key() != recovery.as_bytes()
    {
        return Err(CLOSED);
    }
    let mut digests = [[0; 32]; 4];
    for (row, digest) in transaction.records().iter().zip(&mut digests) {
        *digest = Sha256::digest(row.value().ok_or(CLOSED)?).into();
    }
    Ok((projection_key, digests))
}

impl<'owner, 'source> ControllerHostStopCleanupSourceLoanV1<'owner, 'source> {
    /// Prepares actual native disposal after all terminal and owed-post joins.
    ///
    /// The returned pending owner retains the actual Core slot and extracted
    /// native originals. It releases the Source-only positive disposer only
    /// after SDK retirement and in-place destruction of the same Core graph.
    /// No response or usable Kernel proof escapes before real Source22 disposal.
    ///
    /// # Errors
    /// Refuses failed or incomplete A8/C/metadata/posts, a changed Controller,
    /// expired final paired clock, repeated retirement or missing native owner.
    #[doc(hidden)]
    pub fn prepare_positive_disposal_once_v1(
        self,
        controller: &Journal,
    ) -> Result<ControllerHostStopCleanupPendingDisposalV1<'owner, 'source>> {
        let original = self.original()?;
        positive(&original.posts)?;
        if original.failure().is_some() || held_owner(self.owner).failure_v4().is_some() {
            return Err(CLOSED);
        }
        let terminal = original.terminal.as_deref().ok_or(CLOSED)?;
        let cut = terminal.require_complete()?;
        let first = *positive(&original.first)?;
        let cutoff = *positive(&original.cutoff)?;
        require_cleanup_clock(
            held_owner(self.owner).host_turn.cleanup_after_clock_data_v1()?,
            first,
            cutoff,
            terminal.expiry,
        )?;
        require_current_map(controller, cut)?;
        if !original
            .controller
            .is_same_original_v4(&controller.execution_observation_identity_v4())
        {
            return Err(CLOSED);
        }
        if !matches!(held_owner(self.owner).native, Some(Ok(_))) {
            return Err(CLOSED);
        }

        let owner = held_owner_mut(self.owner);
        let terminal = owner
            .cleanup
            .as_mut()
            .and_then(|value| value.terminal.as_deref_mut())
            .ok_or(CLOSED)?;
        let recovery = terminal.recovery.ok_or(CLOSED)?;
        terminal.require_supersession_after_v1(controller)?;
        let (projection_key, terminal_digests) = terminal_commitments(
            terminal.stage.transaction.as_ref().ok_or(CLOSED)?,
            owner.operation,
            recovery,
            terminal.supersession_rows_v1(),
        )?;
        let completion = ControllerHostStopCleanupCompletionV1 {
            controller: controller.execution_observation_identity_v4(),
            cut,
            target: owner.operation,
            recovery,
            projection_key,
            terminal_digests,
        };
        completion.require_recovery_current_v1(controller, completion.recovery)?;
        let response = terminal.response.take().ok_or(CLOSED)?;
        let source_native = owner.host_turn.take_cleanup_native_after_posts_v1()?;
        let native = match owner.native.take() {
            Some(Ok(native)) => native,
            original => {
                owner.native = original;
                return Err(CLOSED);
            }
        };
        let bank = Arc::clone(&owner.bank);
        let profile = Arc::clone(&owner.profile);
        let disposal = ControllerHostStopCleanupPositiveDisposalV1 {
            native,
            source_native,
            source: self.source,
            bank,
            profile,
            completion,
            response,
        };
        // The actual slot remains exclusively borrowed and occupied. Runtime
        // drops the SDK first, then the pending owner destroys this Core graph
        // in place before it can release the Source-only positive disposer.
        Ok(ControllerHostStopCleanupPendingDisposalV1 {
            owner: self.owner,
            disposal: Some(disposal),
        })
    }
}

impl ControllerHostStopCleanupPositiveDisposalV1<'_> {
    /// Completes actual parked C and Source disposition before public release.
    ///
    /// # Errors
    /// Refuses changed exact C terminal/cut, another native owner, a live upper
    /// Session graph or any permanently latched native retirement conjunction.
    #[doc(hidden)]
    pub fn complete_after_disposal_v1(
        mut self,
        controller: &mut Journal,
    ) -> Result<(
        aos_proto::aos::sandbox::v1::Operation,
        ControllerHostStopCleanupCompletionV1,
    )> {
        self.completion
            .require_recovery_current_v1(controller, self.completion.recovery)?;
        let bank = self
            .bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.complete_stop_cleanup_native_after_disposal_v1(
            &mut self.native,
            controller,
            self.profile.as_ref(),
        )?;
        bank.dispose_provisioning_source_native_v1(
            &mut self.source_native,
            &self.native,
            controller,
            self.source.journal(),
            self.profile.as_ref(),
        )?;
        Ok((self.response, self.completion))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalRecord;

    // These are passive row commitments, never a native completion original.
    fn transaction(recovery_value: u8) -> JournalTransaction {
        let target = OperationId::from_bytes([1; 16]);
        let recovery = OperationId::from_bytes([2; 16]);
        let mut projection = PROJECTION_KEY_PREFIX.to_vec();
        projection.push(PublicProjectionKindV1::Sandbox as u8);
        projection.extend_from_slice(&[3; 16]);
        JournalTransaction::new(
            [4; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(target, 0).to_vec(),
                    vec![5],
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    target.as_bytes().to_vec(),
                    vec![6],
                ),
                JournalRecord::put(RecordNamespace::DesiredState, projection, vec![7]),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    recovery.as_bytes().to_vec(),
                    vec![recovery_value],
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn fixed_commitments_preserve_each_literal_member_after_payload_drop() {
        let target = OperationId::from_bytes([1; 16]);
        let recovery = OperationId::from_bytes([2; 16]);
        let original = transaction(8);
        let commitments = terminal_commitments(&original, target, recovery, std::iter::empty()).unwrap();

        drop(original);

        assert_eq!(commitments.0.len(), PROJECTION_KEY_BYTES);
        assert_eq!(commitments.1[0], <[u8; 32]>::from(Sha256::digest([5])));
        let changed = terminal_commitments(&transaction(9), target, recovery, std::iter::empty()).unwrap();
        assert_eq!(commitments.1[..3], changed.1[..3]);
        assert_ne!(commitments.1[3], changed.1[3]);
    }

    #[test]
    fn fixed_commitments_refuse_foreign_or_deleted_members() {
        let target = OperationId::from_bytes([1; 16]);
        let recovery = OperationId::from_bytes([2; 16]);
        let original = transaction(8);
        assert!(terminal_commitments(&original, recovery, target, std::iter::empty()).is_err());
        assert!(terminal_commitments(&original, target, target, std::iter::empty()).is_err());
        let mut rows = original.records().to_vec();
        rows[3] = JournalRecord::delete(RecordNamespace::Operation, recovery.as_bytes().to_vec());
        let deleted = JournalTransaction::new([9; 16], rows).unwrap();
        assert!(terminal_commitments(&deleted, target, recovery, std::iter::empty()).is_err());
    }

    #[test]
    fn commitments_require_the_entire_retained_supersession_tail() {
        let target = OperationId::from_bytes([1; 16]);
        let recovery = OperationId::from_bytes([2; 16]);
        let original = transaction(8);
        let tail = [
            JournalRecord::put(RecordNamespace::Operation, vec![21; 16], vec![31]),
            JournalRecord::put(RecordNamespace::Operation, vec![22; 16], vec![32]),
        ];
        let mut rows = original.records().to_vec();
        rows.extend_from_slice(&tail);
        let extended = JournalTransaction::new([23; 16], rows).unwrap();
        let core = terminal_commitments(&original, target, recovery, std::iter::empty()).unwrap();

        assert_eq!(terminal_commitments(&extended, target, recovery, tail.iter()).unwrap(), core);
        assert!(terminal_commitments(&extended, target, recovery, tail[..1].iter()).is_err());
        assert!(terminal_commitments(&extended, target, recovery, std::iter::empty()).is_err());
        assert!(terminal_commitments(&extended, target, recovery, tail.iter().rev()).is_err());
        let substituted = [tail[0].clone(), JournalRecord::put(
            RecordNamespace::Operation, vec![22; 16], vec![33])];
        assert!(terminal_commitments(&extended, target, recovery, substituted.iter()).is_err());
    }
}
