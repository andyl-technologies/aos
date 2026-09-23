//! Joins public Cache source membership to protected and physical pin owners.

use aos_filesystem_view_core::ObjectSource;
use aos_sandbox::Journal;
use aos_sandbox::cache_residency::{
    CacheOwnerErrorV1, CacheOwnerPinIdV1, CacheOwnerPinPresenceV1, CacheOwnerPinSettlementErrorV1,
    CacheOwnerPinSettlementV1, CachePinV1, CacheResidencyCommitOutcomeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
    PhysicalPartitionId, PublicLogicalPinAcquisitionCommitV1, PublicLogicalPinAcquisitionErrorV1,
    ValidatedPublicLogicalPinAcquisitionV1,
};
use aos_sandbox::cli_model::DormantSandboxRequestKindV1;
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;
use aos_sandbox_core::{NodeId, OperationId};

use crate::cache_source_membership::{
    CacheCompiledSourceLimitsV1, CompiledCacheSourceMembershipErrorV1,
    with_compiled_cache_source_membership_v1,
};

/// Retains every required outcome of one public logical pin acquisition.
#[must_use = "public completion requires a confirmed protected and physical pin"]
pub enum PublicCachePinExecutionV1 {
    /// The one existing logical pin and its physical owner pin remain current.
    Retained(CachePinV1),
    /// A protected transition was attempted; physical settlement is separate.
    Committed {
        /// Exact protected outcome, including ambiguous recovery custody.
        outcome: CacheResidencyCommitOutcomeV1,
        /// Physical settlement, absent while the protected outcome is unresolved.
        settlement: Option<Result<CacheOwnerPinSettlementV1, CacheOwnerPinSettlementErrorV1>>,
    },
}

/// Proves that one public pin is retained by both protected and physical owners.
#[must_use = "a confirmed public pin must be reflected in its operation result"]
pub enum ConfirmedPublicCachePinV1 {
    /// The existing logical and physical pins remained current.
    Retained(CachePinV1),
    /// A protected transition was read back and its physical effect settled.
    Settled(CacheOwnerPinSettlementV1),
}

impl PublicCachePinExecutionV1 {
    /// Separates a complete pin from an outcome that still needs recovery.
    ///
    /// An applied protected transaction is insufficient when its physical
    /// handoff was skipped or failed. An unresolved result is returned intact
    /// so the caller can retain its exact recovery custody.
    ///
    /// # Errors
    ///
    /// Returns the original execution when protected readback or physical
    /// settlement has not been confirmed.
    pub fn into_confirmed(self) -> Result<ConfirmedPublicCachePinV1, Self> {
        match self {
            Self::Retained(pin) => Ok(ConfirmedPublicCachePinV1::Retained(pin)),
            Self::Committed {
                outcome: CacheResidencyCommitOutcomeV1::Applied(_),
                settlement: Some(Ok(settlement)),
            } => Ok(ConfirmedPublicCachePinV1::Settled(settlement)),
            unresolved => Err(unresolved),
        }
    }
}

/// Retains the protected and physical outcomes of one exact public pin drain.
#[must_use = "public unpin completion requires every retained partition to be drained"]
pub struct PublicCacheUnpinExecutionV1 {
    /// Exact protected outcome, including ambiguous recovery custody.
    pub outcome: CacheResidencyCommitOutcomeV1,
    /// Physical settlement, absent while the protected outcome is unresolved.
    pub settlement: Option<Result<CacheOwnerPinSettlementV1, CacheOwnerPinSettlementErrorV1>>,
}

impl PublicCacheUnpinExecutionV1 {
    /// Confirms that one partition's protected drain and physical release settled.
    ///
    /// The caller must repeat this for every retained partition pin before
    /// completing the public UnpinObject operation.
    ///
    /// # Errors
    ///
    /// Returns the original execution when protected readback or physical
    /// settlement has not been confirmed.
    pub fn into_confirmed(self) -> Result<CacheOwnerPinSettlementV1, Self> {
        match self {
            Self {
                outcome: CacheResidencyCommitOutcomeV1::Applied(_),
                settlement: Some(Ok(settlement @ CacheOwnerPinSettlementV1::Changed(_))),
            } => Ok(settlement),
            unresolved => Err(unresolved),
        }
    }
}

/// Reports failure before a public Cache pin has a complete execution result.
#[derive(Debug, thiserror::Error)]
pub enum PublicCachePinExecutionErrorV1<E: std::error::Error + 'static> {
    /// The exact View source did not prove this object's membership.
    #[error(transparent)]
    Source(#[from] CompiledCacheSourceMembershipErrorV1<E>),
    /// Source membership did not match the current local consumer and partition.
    #[error(transparent)]
    Acquisition(#[from] PublicLogicalPinAcquisitionErrorV1),
    /// Protected pin authority or its durable transition failed.
    #[error(transparent)]
    Protected(#[from] CacheResidencyProtectedJournalErrorV1),
    /// A retained logical pin lacked its exact physical counterpart.
    #[error(transparent)]
    Physical(#[from] CacheOwnerErrorV1),
}

/// Executes one source-proven public pin against both protected Cache owners.
///
/// A repeated pin does not acquire a second logical or physical pin. It may
/// return `Retained` only after checking the current physical owner manifest.
/// New and renewed protected transitions retain their exact commit outcome;
/// callers must settle or recover an unresolved outcome before public success.
/// This method does not select the partition or supply source authority: the
/// caller must do both independently and retain the source journal until the
/// protected commit-time consumer recheck completes.
///
/// # Errors
///
/// Returns an error for missing source membership, stale consumer or local
/// partition, rejected protected authority, or a missing retained physical pin.
#[allow(clippy::too_many_arguments)]
pub fn execute_public_cache_pin_v1<S: ObjectSource>(
    protected: &mut CacheResidencyProtectedOwnerV1,
    physical: &mut DormantCacheOwnerV1,
    source: &mut S,
    consumer: &RecheckedCacheConsumerV1,
    source_journal: &Journal,
    request: &DormantSandboxRequestKindV1,
    operation: OperationId,
    transaction_id: [u8; 16],
    partition: PhysicalPartitionId,
    controller_node: NodeId,
    compiler_abi: [u8; 32],
    compilation_limits: CacheCompiledSourceLimitsV1,
) -> Result<PublicCachePinExecutionV1, PublicCachePinExecutionErrorV1<S::Error>> {
    with_compiled_cache_source_membership_v1(
        consumer,
        source,
        compiler_abi,
        compilation_limits,
        |membership| {
            let acquisition = ValidatedPublicLogicalPinAcquisitionV1::new(
                consumer,
                membership,
                partition,
                controller_node,
            )?;
            let result = protected.commit_public_logical_pin_acquisition(
                transaction_id,
                &acquisition,
                operation,
                source_journal,
                request,
                |postcommit| postcommit.settle_cache_owner_pin_change(physical),
            )?;

            match result {
                PublicLogicalPinAcquisitionCommitV1::Retained(pin) => {
                    let id = CacheOwnerPinIdV1::for_cache_pin(pin.partition(), pin.id())?;
                    let presence = physical.observe_pin(id, pin.partition(), pin.object())?;
                    if presence != CacheOwnerPinPresenceV1::Present {
                        return Err(PublicCachePinExecutionErrorV1::Physical(
                            CacheOwnerErrorV1::RecoveryMismatch,
                        ));
                    }
                    Ok(PublicCachePinExecutionV1::Retained(pin))
                }
                PublicLogicalPinAcquisitionCommitV1::Committed { outcome, handoff } => {
                    Ok(PublicCachePinExecutionV1::Committed {
                        outcome,
                        settlement: handoff,
                    })
                }
            }
        },
    )?
}

/// Drains one exact retained public pin through both protected Cache owners.
///
/// The public request does not name a physical partition or pin ID. Its caller
/// must find *every* retained partition pin for the consumer and object, then
/// invoke this function for each with a distinct durable transaction identity.
/// A protected commit or physical settlement alone does not establish public
/// completion; the caller must reconcile and observe each exact effect.
///
/// # Errors
///
/// Returns an error when the pin is not the exact retained consumer obligation,
/// the consumer changed at commit time, or protected authority is unavailable.
#[allow(clippy::too_many_arguments)]
pub fn execute_public_cache_unpin_v1(
    protected: &mut CacheResidencyProtectedOwnerV1,
    physical: &mut DormantCacheOwnerV1,
    consumer: &RecheckedCacheConsumerV1,
    source_journal: &Journal,
    request: &DormantSandboxRequestKindV1,
    operation: OperationId,
    transaction_id: [u8; 16],
    pin: &CachePinV1,
) -> Result<PublicCacheUnpinExecutionV1, CacheResidencyProtectedJournalErrorV1> {
    let (outcome, settlement) = protected.commit_public_logical_pin_release(
        transaction_id,
        consumer,
        pin,
        operation,
        source_journal,
        request,
        |postcommit| postcommit.settle_cache_owner_pin_change(physical),
    )?;

    Ok(PublicCacheUnpinExecutionV1 {
        outcome,
        settlement,
    })
}
