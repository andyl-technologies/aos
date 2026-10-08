//! Retained preparation of an operation-owned Snapshot Storage authorization.
//!
//! This installed Method25 prerequisite can append T0/T1, but never sends the
//! group request. Writer exclusion, Root attestation, retention and mandatory
//! Thaw remain separate producers. An occupied attempt is not a retry permit.

use aos_sandbox::lifecycle::{
    CurrentLifecycleCoordinationV1, CurrentLifecycleOperationV1,
    LifecycleAtomicDatasetSnapshotPlanV1, LifecycleAtomicSnapshotSourceErrorV1,
    LifecycleProtectedJournalKeyV1, LifecycleProtectedJournalOwnerV1,
    LifecycleSnapshotBarrierV1,
};
use aos_sandbox::{EffectFailure, Journal, PreparedAuthorityEffectV1, ReconcilerError,
    SignedBrokerPlan, SnapshotDerivedStoragePreparationV3};
use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, RawPairedClockSample, SignatureBytes};

use crate::controller_service::ownership::ControllerOwnershipConfigurationV1;
use crate::ownership_clock::sample_ownership_clock;
use crate::controller_service::plan_signer::{ControllerBrokerPlanSignerError,
    ControllerBrokerPlanSignerV1, PreparedSnapshotPlanV3};
use crate::{BrokerSessionSecurityError, DormantAtomicStorageInventoryPredecessorV1};

use super::super::SnapshotOwnershipDonationV3;
use crate::DormantStorageLifecycleInventoryOwnerV1;

#[derive(Debug, thiserror::Error)]
enum SnapshotPostErrorV3 {
    #[error("Snapshot source observation failed: {0}")]
    Source(aos_sandbox::lifecycle::LifecycleProtectedJournalErrorV1),
    #[error("Snapshot original source/runtime cut failed: {0}")]
    Original(ReconcilerError),
    #[error("Snapshot original Session failed: {0:?}")]
    Session(EffectFailure),
    #[error("Snapshot original current cut changed")]
    Changed,
}

#[derive(Clone, Copy)]
enum FirstCauseV3 {
    MissingOwner,
    Inventory,
    Checkpoint,
    OriginalClock,
    Preparation,
    SigningPreparation,
    Key,
    UnsignedCommit,
    Completion,
    Authority,
    SignedCommit,
    PreSignClock,
    PreSignCut,
    Post(usize),
    PostSession(usize),
    PostClock(usize),
    PostCut(usize),
}

/// Owns returned originals and typed Results before later observations.
pub(in crate::controller_service) struct SnapshotDerivativeAttemptV3 {
    operation: OperationId,
    first: Option<FirstCauseV3>,
    predecessor: Option<Result<DormantAtomicStorageInventoryPredecessorV1, aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>>,
    checkpoint: Option<Result<ObjectDigest, EffectFailure>>,
    original_clock: Option<Result<RawPairedClockSample, aos_sandbox::ownership_resume::OwnershipClockObservationError>>,
    preparation: Option<Result<SnapshotDerivedStoragePreparationV3, ReconcilerError>>,
    signing: Option<Result<PreparedSnapshotPlanV3, ControllerBrokerPlanSignerError>>,
    key_error: Option<ControllerBrokerPlanSignerError>,
    unsigned_commit: Option<Result<aos_sandbox::journal::CommitResult, LifecycleAtomicSnapshotSourceErrorV1>>,
    signed_commit: Option<Result<aos_sandbox::journal::CommitResult, LifecycleAtomicSnapshotSourceErrorV1>>,
    sign_attempted: bool,
    pre_sign_clock: Option<Result<RawPairedClockSample, aos_sandbox::ownership_resume::OwnershipClockObservationError>>,
    pre_sign_cut: Option<Result<(), ReconcilerError>>,
    signature: Option<SignatureBytes>,
    completion: Option<Result<SignedBrokerPlan, ControllerBrokerPlanSignerError>>,
    authority: Option<Result<PreparedAuthorityEffectV1, ReconcilerError>>,
    post: [Option<Result<(), SnapshotPostErrorV3>>; 5],
    session_post: [Option<Result<(), BrokerSessionSecurityError>>; 5],
    post_clock: [Option<Result<RawPairedClockSample, aos_sandbox::ownership_resume::OwnershipClockObservationError>>; 5],
    post_cut: [Option<Result<(), ReconcilerError>>; 5],
}

impl SnapshotDerivativeAttemptV3 {
    pub(super) fn new(operation: OperationId) -> Self {
        Self {
            operation, first: None, predecessor: None, checkpoint: None, original_clock: None,
            preparation: None, signing: None, key_error: None,
            unsigned_commit: None, signed_commit: None, sign_attempted: false,
            pre_sign_clock: None, pre_sign_cut: None, signature: None,
            completion: None, authority: None,
            post: std::array::from_fn(|_| None),
            session_post: std::array::from_fn(|_| None),
            post_clock: std::array::from_fn(|_| None),
            post_cut: std::array::from_fn(|_| None),
        }
    }

    // No owner is taken out of the parent across fallible native or signing
    // work. The Source/Controller writers and Session are disjoint outer loans.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn advance(
        &mut self,
        donation: &SnapshotOwnershipDonationV3,
        signer: Option<&ControllerBrokerPlanSignerV1>,
        node: NodeId,
        journal: &mut Journal,
        source: &LifecycleProtectedJournalOwnerV1<'_>,
        current: &CurrentLifecycleOperationV1<'_>,
        coordination: &CurrentLifecycleCoordinationV1<'_>,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        barrier: &LifecycleSnapshotBarrierV1,
        storage: &mut DormantStorageLifecycleInventoryOwnerV1,
    ) -> Result<bool, EffectFailure> {
        if self.first.is_some() || self.predecessor.is_some() || self.sign_attempted {
            return Err(self.failure());
        }
        let (Some(ownership), Some(signer)) = (donation.get(), signer) else {
            self.first = Some(FirstCauseV3::MissingOwner);
            return Err(self.failure());
        };

        self.predecessor = Some(storage.begin_atomic_snapshot_inventory());
        let predecessor = match self.predecessor.as_ref() {
            Some(Ok(predecessor)) => predecessor,
            _ => {
                self.first = Some(FirstCauseV3::Inventory);
                return Err(self.failure());
            }
        };
        self.original_clock = Some(sample_ownership_clock());
        let clock = match self.original_clock.as_ref() {
            Some(Ok(clock)) => *clock,
            _ => {
                self.first = Some(FirstCauseV3::OriginalClock);
                return Err(self.failure());
            }
        };
        let Some(deadline) = clock.boottime_nanoseconds().checked_add(5_000_000_000) else {
            self.first = Some(FirstCauseV3::MissingOwner);
            return Err(self.failure());
        };
        self.checkpoint = Some(storage.historical_checkpoint_digest());
        let checkpoint = match self.checkpoint.as_ref() {
            Some(Ok(checkpoint)) => *checkpoint,
            _ => {
                self.first = Some(FirstCauseV3::Checkpoint);
                return Err(self.failure());
            }
        };
        self.preparation = Some(prepare_original(
            journal, node, current, coordination, barrier, predecessor,
            checkpoint, clock, deadline, ownership,
        ));
        let preparation = match self.preparation.as_mut() {
            Some(Ok(preparation)) => preparation,
            _ => {
                self.first = Some(FirstCauseV3::Preparation);
                return Err(self.failure());
            }
        };
        self.signing = Some(signer.prepare_snapshot_plan_v3(preparation));
        let signing = match self.signing.as_ref() {
            Some(Ok(signing)) => signing,
            _ => {
                self.first = Some(FirstCauseV3::SigningPreparation);
                return Err(self.failure());
            }
        };
        let unsigned = signing.preparation().map_err(|_| {
            ReconcilerError::InvalidPlan("Snapshot signing preparation is absent")
        }).and_then(|signing| preparation.prepare_unsigned_original(
            journal, signing, predecessor.outcome().canonical_packet(),
        ));
        if let Err(error) = unsigned {
            self.pre_sign_cut = Some(Err(error));
            self.first = Some(FirstCauseV3::PreSignCut);
            return Err(self.failure());
        }

        self.observe(0, journal, source, coordination_key, storage);
        if self.first.is_some() { return Err(self.failure()); }
        let Some(Ok(preparation)) = self.preparation.as_ref() else {
            return Err(self.failure());
        };
        self.unsigned_commit = Some(preparation.append_unsigned_original(journal));
        if matches!(self.unsigned_commit, Some(Err(_))) {
            self.first = Some(FirstCauseV3::UnsignedCommit);
        }
        self.observe(1, journal, source, coordination_key, storage);
        if self.first.is_some() { return Err(self.failure()); }

        // Every mutable observation, preparation and fingerprint check has
        // finished. The genuine pair is LAST; the actual raw signature parks
        // before completion, native appends or any independent postcheck.
        self.sign_attempted = true;
        let Some(Ok(signing)) = self.signing.as_ref() else {
            return Err(self.failure());
        };
        let loan = match signing.key_message_loan() {
            Ok(loan) => loan,
            Err(error) => {
                self.key_error = Some(error);
                self.first = Some(FirstCauseV3::Key);
                return Err(self.failure());
            }
        };
        self.pre_sign_clock = Some(sample_ownership_clock());
        let clock = match self.pre_sign_clock.as_ref() {
            Some(Ok(clock)) => *clock,
            _ => {
                self.first = Some(FirstCauseV3::PreSignClock);
                return Err(self.failure());
            }
        };
        let Some(Ok(preparation)) = self.preparation.as_ref() else {
            return Err(self.failure());
        };
        self.pre_sign_cut = Some(preparation.check_clock(clock));
        if matches!(self.pre_sign_cut, Some(Err(_))) {
            self.first = Some(FirstCauseV3::PreSignCut);
            return Err(self.failure());
        }
        self.signature = Some(loan.sign());

        let (Some(Ok(signing)), Some(signature)) = (self.signing.as_mut(), self.signature.as_ref()) else {
            return Err(self.failure());
        };
        self.completion = Some(signing.complete(signature, clock.wall_seconds()));
        if matches!(self.completion, Some(Err(_))) {
            self.first = Some(FirstCauseV3::Completion);
        }
        self.observe(2, journal, source, coordination_key, storage);
        if self.first.is_some() { return Err(self.failure()); }

        let (Some(Ok(preparation)), Some(Ok(signed))) =
            (self.preparation.as_mut(), self.completion.as_ref()) else {
                return Err(self.failure());
            };
        // Keep the actual completed artifact resident while the existing
        // consuming template compiler constructs its owned request.
        self.authority = Some(preparation.complete_signed_original(journal, signed.clone()));
        if matches!(self.authority, Some(Err(_))) {
            self.first = Some(FirstCauseV3::Authority);
        }
        self.observe(3, journal, source, coordination_key, storage);
        if self.first.is_some() { return Err(self.failure()); }
        let Some(Ok(preparation)) = self.preparation.as_ref() else {
            return Err(self.failure());
        };
        self.signed_commit = Some(preparation.append_signed_original(journal));
        if matches!(self.signed_commit, Some(Err(_))) {
            self.first = Some(FirstCauseV3::SignedCommit);
        }
        // Final readback is independent debt, never a reason to resend/sign.
        // The existing pre-append original cut is unchanged; no deadline renews.
        self.observe(4, journal, source, coordination_key, storage);
        Err(self.failure())
    }

    fn observe(
        &mut self,
        slot: usize,
        journal: &mut Journal,
        source: &LifecycleProtectedJournalOwnerV1<'_>,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        storage: &mut DormantStorageLifecycleInventoryOwnerV1,
    ) {
        let Some(Ok(preparation)) = self.preparation.as_ref() else { return; };
        self.post[slot] = Some(observe_original(self.operation, journal, source,
            coordination_key, storage, preparation));
        if matches!(self.post[slot], Some(Err(_))) && self.first.is_none() {
            self.first = Some(FirstCauseV3::Post(slot));
        }

        // Borrow the original terminal owner, then park its actual typed
        // currentness result before independently observing the original D.
        let Some(Ok(predecessor)) = self.predecessor.as_ref() else { return; };
        self.session_post[slot] = Some(storage.compare_atomic_snapshot_predecessor_v3(predecessor));
        if matches!(self.session_post[slot], Some(Err(_))) && self.first.is_none() {
            self.first = Some(FirstCauseV3::PostSession(slot));
        }

        // Even a native/source failure independently samples the ORIGINAL D.
        self.post_clock[slot] = Some(sample_ownership_clock());
        match self.post_clock[slot].as_ref() {
            Some(Ok(clock)) => {
                self.post_cut[slot] = Some(preparation.check_clock(*clock));
                if matches!(self.post_cut[slot], Some(Err(_))) && self.first.is_none() {
                    self.first = Some(FirstCauseV3::PostCut(slot));
                }
            }
            _ if self.first.is_none() => self.first = Some(FirstCauseV3::PostClock(slot)),
            _ => {}
        }
    }

    fn failure(&self) -> EffectFailure {
        // Formatting occurs only after actual native/signing/error custody.
        let cause: Option<&dyn std::fmt::Debug> = match self.first {
            Some(FirstCauseV3::Inventory) => self.predecessor.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Checkpoint) => self.checkpoint.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::OriginalClock) => self.original_clock.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Preparation) => self.preparation.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::SigningPreparation) => self.signing.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Key) => self.key_error.as_ref().map(|e| e as _),
            Some(FirstCauseV3::UnsignedCommit) => self.unsigned_commit.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::SignedCommit) => self.signed_commit.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Completion) => self.completion.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Authority) => self.authority.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::PreSignClock) => self.pre_sign_clock.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::PreSignCut) => self.pre_sign_cut.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::Post(slot)) => self.post[slot].as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::PostSession(slot)) => self.session_post[slot].as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::PostClock(slot)) => self.post_clock[slot].as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            Some(FirstCauseV3::PostCut(slot)) => self.post_cut[slot].as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _),
            _ => None,
        };
        EffectFailure::Permanent(match cause {
            Some(cause) => format!("retained Snapshot authorization failed: {cause:?}"),
            None => "Snapshot authorization originals remain retained; full writer/Root/retention/Thaw producer is missing".to_owned(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_original(
    journal: &mut Journal,
    node: NodeId,
    current: &CurrentLifecycleOperationV1<'_>,
    coordination: &CurrentLifecycleCoordinationV1<'_>,
    barrier: &LifecycleSnapshotBarrierV1,
    predecessor: &DormantAtomicStorageInventoryPredecessorV1,
    checkpoint: ObjectDigest,
    clock: RawPairedClockSample,
    deadline: u64,
    ownership: &ControllerOwnershipConfigurationV1,
) -> Result<SnapshotDerivedStoragePreparationV3, ReconcilerError> {
    let plan: LifecycleAtomicDatasetSnapshotPlanV1 = barrier
        .atomic_dataset_snapshot_plan(current, predecessor.inventory())
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot actual group differs"))?;
    aos_sandbox::prepare_snapshot_derived_storage_v3(
        journal, node, current, coordination, barrier, &plan, predecessor.inventory(),
        predecessor.outcome(), checkpoint, aos_sandbox::AuthorityEffectAttemptTimingV1::new(clock, deadline),
        ownership.verifier(),
    )
}

fn observe_original(
    operation: OperationId,
    journal: &mut Journal,
    source: &LifecycleProtectedJournalOwnerV1<'_>,
    coordination_key: &LifecycleProtectedJournalKeyV1,
    storage: &DormantStorageLifecycleInventoryOwnerV1,
    preparation: &SnapshotDerivedStoragePreparationV3,
) -> Result<(), SnapshotPostErrorV3> {
    let (_, current) = source.current_operation_by_id(operation)
        .map_err(SnapshotPostErrorV3::Source)?.ok_or(SnapshotPostErrorV3::Changed)?;
    let coordination = source.current_coordination(coordination_key)
        .map_err(SnapshotPostErrorV3::Source)?.ok_or(SnapshotPostErrorV3::Changed)?;
    preparation.recheck(journal, &current, &coordination)
        .map_err(SnapshotPostErrorV3::Original)?;
    let checkpoint = storage.historical_checkpoint_digest().map_err(SnapshotPostErrorV3::Session)?;
    preparation.require_checkpoint(checkpoint).map_err(SnapshotPostErrorV3::Original)?;
    Ok(())
}
