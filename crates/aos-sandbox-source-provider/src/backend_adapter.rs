//! Dormant raw-transport adapter for the protected SourceProvider backend.
//!
//! The transport sees immutable plans and returns untrusted descriptors and
//! data projections. It never receives a journal, signing key, session, effect
//! permit, or replay authority. The adapter kernel-validates descriptor claims
//! and seals them to the exact plan, while [`FixedProviderBackendSessionV1`]
//! keeps the fixed namespace-41 claim attached through completion or recovery.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    RecoveryCurrentnessQueryV1, SignedSourceProviderRequestV1, SignedStorageLiveExportRequestV1,
    SourceProviderDescriptorRole, SourceProviderProofV1, SourceResourceV1, digest_signed_request,
};

use crate::backend_verifier::{
    BackendObservationChallengeV1, ProtectedBackendVerifierV1, RawBackendAttestationV1,
    VerifiedAcquireNotAppliedV1, VerifiedBackendAcquisitionV1, VerifiedBackendReleaseV1,
    VerifiedBackendReopenV1, VerifiedReleaseStillPresentV1,
};
use crate::{
    AcquireObservationV1, AcquirePlanV1, ActiveAcquisitionSnapshotV1, BackendEvidenceClassV1,
    BackendEvidenceStateV1, BackendEvidenceV1, DurableAcquireEffectPermitV1,
    DurableProviderReplyV1, DurableReleaseEffectPermitV1, DurableReleaseTombstoneV1,
    FixedProviderOwnerV1, ObservedBackendAcquisitionV1, ObservedBackendReleaseV1,
    ProviderAdmissionDispositionV1, ProviderLedgerError, ProviderRecoveryContinuationV1,
    ProviderRecoveryObservationV1, ProviderRecoveryWorkV1, RecoveryAcquireNotAppliedV1,
    RecoveryReleaseStillPresentV1, ReleaseObservationV1, ReleasePlanV1, ReopenIdentityV1,
    ReopenObservationV1, SourceProviderBackendV1,
};

/// Reports an operational result from an authority-free backend transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderBackendTransportErrorV1 {
    /// The selected backend object is currently unavailable.
    #[error("the selected SourceProvider backend object is unavailable")]
    Unavailable,
    /// The effect outcome is indeterminate and requires durable recovery.
    #[error("the SourceProvider backend effect outcome is indeterminate")]
    Indeterminate,
    /// The transport observed facts that contradict the immutable plan.
    #[error("the SourceProvider backend observation contradicts its plan")]
    Conflict,
}

/// Carries untrusted acquisition output returned by an external transport.
///
/// Construction grants no journal, signing, effect, or completion authority.
/// The descriptor and projections are accepted only after kernel observation
/// and exact plan, catalog, proof, evidence, and reopen-identity validation.
pub struct RawBackendAcquisitionV1 {
    pub(crate) descriptor: OwnedFd,
    pub(crate) resource: SourceResourceV1,
    pub(crate) proof: SourceProviderProofV1,
    pub(crate) evidence: BackendEvidenceV1,
    pub(crate) reopen_identity: ReopenIdentityV1,
    pub(crate) attestations: Vec<RawBackendAttestationV1>,
}

impl core::fmt::Debug for RawBackendAcquisitionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RawBackendAcquisitionV1([untrusted descriptor and projections])")
    }
}

impl RawBackendAcquisitionV1 {
    /// Collects untrusted raw acquisition output for fixed-owner validation.
    #[must_use]
    pub fn new(
        descriptor: OwnedFd,
        resource: SourceResourceV1,
        proof: SourceProviderProofV1,
        evidence: BackendEvidenceV1,
        reopen_identity: ReopenIdentityV1,
        attestations: Vec<RawBackendAttestationV1>,
    ) -> Self {
        Self {
            descriptor,
            resource,
            proof,
            evidence,
            reopen_identity,
            attestations,
        }
    }
}

/// Carries untrusted signed classification that an Acquire was not applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawAcquireNotAppliedV1 {
    pub(crate) observation_generation: u64,
    pub(crate) attestations: Vec<RawBackendAttestationV1>,
}

impl RawAcquireNotAppliedV1 {
    /// Collects one generation and every class-authority absence attestation.
    #[must_use]
    pub fn new(observation_generation: u64, attestations: Vec<RawBackendAttestationV1>) -> Self {
        Self {
            observation_generation,
            attestations,
        }
    }
}

/// Classifies an untrusted acquisition readback.
#[derive(Debug)]
pub enum RawAcquireObservationV1 {
    /// No selected backend object matches the exact plan.
    NotApplied(RawAcquireNotAppliedV1),
    /// A candidate object and descriptor require owner-side validation.
    Applied(RawBackendAcquisitionV1),
    /// Backend facts contradict the immutable plan.
    Conflict,
}

/// Carries untrusted terminal release evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBackendReleaseV1 {
    pub(crate) evidence: BackendEvidenceV1,
    pub(crate) attestations: Vec<RawBackendAttestationV1>,
}

impl RawBackendReleaseV1 {
    /// Collects untrusted release evidence for fixed-owner validation.
    #[must_use]
    pub fn new(evidence: BackendEvidenceV1, attestations: Vec<RawBackendAttestationV1>) -> Self {
        Self {
            evidence,
            attestations,
        }
    }
}

/// Carries untrusted signed classification that a Release remains unapplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawReleaseStillPresentV1 {
    pub(crate) observation_generation: u64,
    pub(crate) attestations: Vec<RawBackendAttestationV1>,
}

impl RawReleaseStillPresentV1 {
    /// Collects the generation and class-authority presence attestations.
    #[must_use]
    pub fn new(observation_generation: u64, attestations: Vec<RawBackendAttestationV1>) -> Self {
        Self {
            observation_generation,
            attestations,
        }
    }
}

/// Classifies an untrusted release readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawReleaseObservationV1 {
    /// The selected backend object remains present.
    StillPresent(RawReleaseStillPresentV1),
    /// Candidate terminal evidence requires owner-side validation.
    Released(RawBackendReleaseV1),
    /// Backend facts contradict the immutable plan.
    Conflict,
}

/// Classifies an untrusted active-source reopen readback.
#[derive(Debug)]
pub enum RawReopenObservationV1 {
    /// A candidate descriptor requires kernel and owner-side validation.
    Descriptor {
        /// Owns the candidate descriptor.
        descriptor: OwnedFd,
        /// Carries the detached class-authority attestations.
        attestations: Vec<RawBackendAttestationV1>,
    },
    /// No descriptor can currently be returned.
    Unavailable,
    /// Backend facts contradict the retained active identity.
    Conflict,
}

/// Defines authority-free effect and readback transport operations.
///
/// Implementations may perform external I/O, but receive only immutable data
/// projections. They cannot mint or retain the move-only effect permit and do
/// not receive protected journal, session, signing, or reply authority. Raw
/// results must carry the exact protected attestations for their evidence
/// class: ZFS hold; Storage export plus kernel grant; publisher receipt plus
/// cache/fs-verity; or replica authority. The fixed owner verifies those
/// signatures independently, so implementing this trait never grants a way to
/// declare evidence verified.
pub trait SourceProviderBackendTransportV1 {
    /// Sends an already signed plan only to nonauthorizing Storage readback.
    ///
    /// # Errors
    ///
    /// Returns unavailable by default or when authenticated inspection fails.
    fn inspect_storage_live_export_request(
        &mut self,
        _signed_plan: &SignedStorageLiveExportRequestV1,
    ) -> Result<(), SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }

    /// Reads whether an Acquire plan has already been applied.
    ///
    /// # Errors
    ///
    /// Returns an operational transport classification when readback cannot
    /// produce a complete observation.
    fn observe_acquire(
        &mut self,
        plan: &AcquirePlanV1,
        challenge: &BackendObservationChallengeV1,
    ) -> Result<RawAcquireObservationV1, SourceProviderBackendTransportErrorV1>;

    /// Executes one Acquire plan without receiving its durable permit.
    ///
    /// # Errors
    ///
    /// Returns an operational transport classification when execution is
    /// unavailable, indeterminate, or contradicts the plan.
    fn execute_acquire(
        &mut self,
        plan: &AcquirePlanV1,
    ) -> Result<RawBackendAcquisitionV1, SourceProviderBackendTransportErrorV1>;

    /// Reopens one exact retained active source.
    ///
    /// # Errors
    ///
    /// Returns an operational transport classification when readback cannot
    /// classify the retained source.
    fn reopen_active(
        &mut self,
        acquisition: &ActiveAcquisitionSnapshotV1,
    ) -> Result<RawReopenObservationV1, SourceProviderBackendTransportErrorV1>;

    /// Reads whether a Release plan has already completed.
    ///
    /// # Errors
    ///
    /// Returns an operational transport classification when readback cannot
    /// produce a complete observation.
    fn observe_release(
        &mut self,
        plan: &ReleasePlanV1,
        challenge: &BackendObservationChallengeV1,
    ) -> Result<RawReleaseObservationV1, SourceProviderBackendTransportErrorV1>;

    /// Executes one Release plan without receiving its durable permit.
    ///
    /// # Errors
    ///
    /// Returns an operational transport classification when execution is
    /// unavailable, indeterminate, or contradicts the plan.
    fn execute_release(
        &mut self,
        plan: &ReleasePlanV1,
    ) -> Result<RawBackendReleaseV1, SourceProviderBackendTransportErrorV1>;
}

/// Adapts an authority-free transport to the sealed provider backend boundary.
///
/// Only the fixed owner constructs this adapter with its retained verifier.
/// Backend effects remain possible only when the fixed ledger also supplies a
/// move-only permit after synchronizing the exact reservation.
pub(crate) struct FixedSourceProviderBackendV1<'transport, Transport: ?Sized> {
    transport: &'transport mut Transport,
    verifier: Arc<ProtectedBackendVerifierV1>,
}

impl<'transport, Transport: SourceProviderBackendTransportV1 + ?Sized>
    FixedSourceProviderBackendV1<'transport, Transport>
{
    pub(crate) fn new(
        transport: &'transport mut Transport,
        verifier: Arc<ProtectedBackendVerifierV1>,
    ) -> Self {
        Self {
            transport,
            verifier,
        }
    }

    fn verify_acquisition(
        &self,
        plan: &AcquirePlanV1,
        raw: RawBackendAcquisitionV1,
    ) -> Result<
        (
            crate::ProviderPhysicalSourceRootV1,
            VerifiedBackendAcquisitionV1,
        ),
        ProviderLedgerError,
    > {
        let RawBackendAcquisitionV1 {
            descriptor,
            resource,
            proof,
            evidence,
            reopen_identity,
            attestations,
        } = raw;
        if evidence.state() != BackendEvidenceStateV1::Acquired
            || reopen_identity.class() != evidence.class()
            || !reopen_identity.matches_proof(&proof)
            || reopen_identity.backend_id() != plan.backend_id()
        {
            return Err(ProviderLedgerError::BackendConflict);
        }
        let physical_root = plan
            .observe_source_root(descriptor)
            .map_err(|_| ProviderLedgerError::BackendConflict)?;
        let descriptor_commitment = physical_root.descriptor_commitment();
        if evidence.class() == crate::BackendEvidenceClassV1::LocalLiveExport
            && !evidence
                .local_live_binding()
                .map_err(|_| ProviderLedgerError::BackendConflict)?
                .matches(&proof, descriptor_commitment)
        {
            return Err(ProviderLedgerError::BackendConflict);
        }
        let verified = self.verifier.verify_acquisition(
            plan,
            resource,
            proof,
            evidence,
            reopen_identity,
            attestations,
            descriptor_commitment,
        )?;
        Ok((physical_root, verified))
    }

    fn verify_release(
        &self,
        plan: &ReleasePlanV1,
        raw: RawBackendReleaseV1,
    ) -> Result<VerifiedBackendReleaseV1, ProviderLedgerError> {
        if raw.evidence.state() != BackendEvidenceStateV1::Released {
            return Err(ProviderLedgerError::BackendConflict);
        }
        self.verifier.verify_release(plan, raw)
    }

    fn seal_verified_reopen(
        acquisition: &ActiveAcquisitionSnapshotV1,
        physical: crate::ProviderPhysicalSourceRootV1,
        _verified: VerifiedBackendReopenV1,
    ) -> Result<crate::ReopenedSourceRootV1, ProviderLedgerError> {
        acquisition
            .seal_reopened_source_root(physical)
            .map_err(|_| ProviderLedgerError::BackendConflict)
    }

    fn classify_verified_acquire_absence(
        _verified: VerifiedAcquireNotAppliedV1,
    ) -> AcquireObservationV1 {
        AcquireObservationV1::NotApplied
    }

    fn classify_verified_release_presence(
        _verified: VerifiedReleaseStillPresentV1,
    ) -> ReleaseObservationV1 {
        ReleaseObservationV1::StillPresent
    }
}

impl<Transport: SourceProviderBackendTransportV1 + ?Sized> SourceProviderBackendV1
    for FixedSourceProviderBackendV1<'_, Transport>
{
    fn inspect_storage_live_export_request(
        &mut self,
        signed_plan: &SignedStorageLiveExportRequestV1,
    ) -> Result<(), ProviderLedgerError> {
        self.transport
            .inspect_storage_live_export_request(signed_plan)
            .map_err(map_transport_error)
    }

    fn observe_acquire(
        &mut self,
        plan: &AcquirePlanV1,
    ) -> Result<AcquireObservationV1, ProviderLedgerError> {
        if plan.kernel_coupled() {
            return Err(ProviderLedgerError::Unavailable);
        }
        let challenge = self.verifier.issue_acquire_absence_challenge(plan)?;
        match self
            .transport
            .observe_acquire(plan, &challenge)
            .map_err(map_transport_error)?
        {
            RawAcquireObservationV1::NotApplied(raw) => self
                .verifier
                .verify_acquire_not_applied(plan, challenge, raw)
                .map(Self::classify_verified_acquire_absence),
            RawAcquireObservationV1::Applied(raw) => {
                let (physical, verified) = self.verify_acquisition(plan, raw)?;
                plan.seal_observed_acquisition(
                    physical,
                    verified.resource,
                    verified.proof,
                    verified.evidence,
                    verified.reopen_identity,
                    plan.backend_id(),
                )
                .map(AcquireObservationV1::Applied)
                .map_err(|_| ProviderLedgerError::BackendConflict)
            }
            RawAcquireObservationV1::Conflict => Ok(AcquireObservationV1::Conflict),
        }
    }

    fn execute_acquire(
        &mut self,
        permit: DurableAcquireEffectPermitV1,
    ) -> Result<(DurableAcquireEffectPermitV1, ObservedBackendAcquisitionV1), ProviderLedgerError>
    {
        if permit.plan().kernel_coupled() {
            return Err(ProviderLedgerError::Unavailable);
        }
        let raw = self
            .transport
            .execute_acquire(permit.plan())
            .map_err(map_transport_error)?;
        let (physical, verified) = self.verify_acquisition(permit.plan(), raw)?;
        let backend_id = permit.plan().backend_id();
        permit.seal_execution(
            physical,
            verified.resource,
            verified.proof,
            verified.evidence,
            verified.reopen_identity,
            backend_id,
        )
    }

    fn reopen_active(
        &mut self,
        acquisition: &ActiveAcquisitionSnapshotV1,
    ) -> Result<ReopenObservationV1, ProviderLedgerError> {
        if acquisition.evidence().class() == BackendEvidenceClassV1::LocalLiveExport {
            return Err(ProviderLedgerError::Unavailable);
        }
        match self
            .transport
            .reopen_active(acquisition)
            .map_err(map_transport_error)?
        {
            RawReopenObservationV1::Descriptor {
                descriptor,
                attestations,
            } => {
                let physical = acquisition
                    .observe_reopened_source_root(descriptor)
                    .map_err(|_| ProviderLedgerError::BackendConflict)?;
                if acquisition.evidence().class() == BackendEvidenceClassV1::LocalLiveExport
                    && !acquisition
                        .evidence()
                        .local_live_binding()
                        .map_err(|_| ProviderLedgerError::BackendConflict)?
                        .matches_descriptor(physical.descriptor_commitment())
                {
                    return Err(ProviderLedgerError::BackendConflict);
                }
                let verified = self.verifier.verify_reopen(
                    acquisition,
                    acquisition.evidence().class(),
                    &attestations,
                    physical.descriptor_commitment(),
                )?;
                Self::seal_verified_reopen(acquisition, physical, verified)
                    .map(ReopenObservationV1::Reopened)
            }
            RawReopenObservationV1::Unavailable => Ok(ReopenObservationV1::Unavailable),
            RawReopenObservationV1::Conflict => Ok(ReopenObservationV1::Conflict),
        }
    }

    fn observe_release(
        &mut self,
        plan: &ReleasePlanV1,
    ) -> Result<ReleaseObservationV1, ProviderLedgerError> {
        if plan.evidence_class() == BackendEvidenceClassV1::LocalLiveExport {
            return Err(ProviderLedgerError::Unavailable);
        }
        let challenge = self.verifier.issue_release_presence_challenge(plan)?;
        match self
            .transport
            .observe_release(plan, &challenge)
            .map_err(map_transport_error)?
        {
            RawReleaseObservationV1::StillPresent(raw) => self
                .verifier
                .verify_release_still_present(plan, challenge, raw)
                .map(Self::classify_verified_release_presence),
            RawReleaseObservationV1::Released(raw) => {
                let verified = self.verify_release(plan, raw)?;
                plan.seal_observed_release(verified.evidence, plan.backend_id())
                    .map(ReleaseObservationV1::Released)
                    .map_err(|_| ProviderLedgerError::BackendConflict)
            }
            RawReleaseObservationV1::Conflict => Ok(ReleaseObservationV1::Conflict),
        }
    }

    fn execute_release(
        &mut self,
        permit: DurableReleaseEffectPermitV1,
    ) -> Result<(DurableReleaseEffectPermitV1, ObservedBackendReleaseV1), ProviderLedgerError> {
        if permit.plan().evidence_class() == BackendEvidenceClassV1::LocalLiveExport {
            return Err(ProviderLedgerError::Unavailable);
        }
        let raw = self
            .transport
            .execute_release(permit.plan())
            .map_err(map_transport_error)?;
        let verified = self.verify_release(permit.plan(), raw)?;
        let backend_id = permit.plan().backend_id();
        permit.seal_execution(verified.evidence, backend_id)
    }
}

fn map_transport_error(error: SourceProviderBackendTransportErrorV1) -> ProviderLedgerError {
    match error {
        SourceProviderBackendTransportErrorV1::Unavailable
        | SourceProviderBackendTransportErrorV1::Indeterminate => ProviderLedgerError::Unavailable,
        SourceProviderBackendTransportErrorV1::Conflict => ProviderLedgerError::BackendConflict,
    }
}

/// Reports a fully owner-scoped request execution result.
#[must_use = "a durable reply or recovery work item must be consumed"]
pub enum FixedProviderBackendRequestOutcomeV1 {
    /// Carries one durable response ready for fixed-owner authenticated send.
    Reply(DurableProviderReplyV1),
    /// Carries a durable Release response and its terminal tombstone.
    Released {
        /// Owns the exact response and its send authority.
        reply: DurableProviderReplyV1,
        /// Identifies the synchronized release tombstone.
        tombstone: DurableReleaseTombstoneV1,
    },
    /// Reports that exact observation-first recovery awaits a fresh request.
    RecoveryPending,
    /// Preserves a cached response alongside distinct recovery work.
    CachedRecovery {
        /// Owns the exact cached response and revalidated replay authority.
        reply: DurableProviderReplyV1,
    },
}

/// Retains exact authenticated request custody for one backend recovery lineage.
#[must_use = "backend recovery must be continued or retained by the fixed provider owner"]
pub(crate) struct FixedProviderBackendRecoveryV1 {
    work: ProviderRecoveryWorkV1,
    original_request: SignedSourceProviderRequestV1,
    descriptor_roles: Vec<SourceProviderDescriptorRole>,
    fresh_request: Option<SignedSourceProviderRequestV1>,
    fresh_request_in_flight: bool,
    successor_session_ready: bool,
    quarantined: bool,
}

impl core::fmt::Debug for FixedProviderBackendRecoveryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedProviderBackendRecoveryV1([authenticated recovery custody])")
    }
}

impl FixedProviderBackendRecoveryV1 {
    pub(crate) fn matches_signed_request(
        &self,
        signed_request: &SignedSourceProviderRequestV1,
    ) -> bool {
        &self.original_request == signed_request
            && self.signed_request_digest()
                == *aos_sandbox_source_provider_protocol::digest_signed_request(signed_request)
                    .as_bytes()
    }

    pub(crate) fn semantic_identity(
        &self,
    ) -> (
        aos_sandbox_source_provider_protocol::SourceProviderMethod,
        Option<[u8; 32]>,
    ) {
        use aos_sandbox_source_provider_protocol::SourceProviderMethod;

        match &self.work {
            ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. }
            | ProviderRecoveryWorkV1::ObserveAcquireRebind { acquisition_id, .. }
            | ProviderRecoveryWorkV1::ObservePending { acquisition_id, .. }
            | ProviderRecoveryWorkV1::ReopenActive { acquisition_id, .. } => (
                SourceProviderMethod::Acquire,
                Some(*acquisition_id.as_bytes()),
            ),
            ProviderRecoveryWorkV1::ObserveReleasing { acquisition_id, .. } => (
                SourceProviderMethod::Release,
                Some(*acquisition_id.as_bytes()),
            ),
            ProviderRecoveryWorkV1::ObserveInventoryReservation { .. } => {
                (SourceProviderMethod::Inventory, None)
            }
        }
    }

    pub(crate) fn signed_request_digest(&self) -> [u8; 32] {
        *aos_sandbox_source_provider_protocol::digest_signed_request(&self.original_request)
            .as_bytes()
    }

    pub(crate) fn has_fresh_request(&self) -> bool {
        self.fresh_request.is_some() || self.fresh_request_in_flight || self.quarantined
    }

    pub(crate) fn mark_fresh_request_in_flight(&mut self) {
        self.fresh_request_in_flight = true;
        self.successor_session_ready = false;
    }

    pub(crate) fn mark_successor_session_ready(&mut self) {
        self.successor_session_ready = true;
    }

    pub(crate) fn reject_in_flight_request(&mut self) {
        self.fresh_request = None;
        self.fresh_request_in_flight = false;
        self.successor_session_ready = false;
    }

    pub(crate) fn successor_session_ready(&self) -> bool {
        self.successor_session_ready
    }

    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
        self.fresh_request = None;
        self.fresh_request_in_flight = false;
    }
}

pub(crate) fn rehydrate_backend_recovery(
    detached: &crate::state::DetachedProviderLedgerV1,
) -> Result<Vec<FixedProviderBackendRecoveryV1>, ProviderLedgerError> {
    let recovered = detached.recovered();
    recovered
        .recovery_work
        .iter()
        // Active is durable terminal state, not an unresolved effect. Mount
        // startup owns descriptor reopen; treating every Active row as backend
        // recovery would block a valid Complete Mount row after joint restart.
        .filter(|work| !matches!(work, ProviderRecoveryWorkV1::ReopenActive { .. }))
        .map(|work| {
            let attempt_digest = match work {
                ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. }
                | ProviderRecoveryWorkV1::ObservePending { acquisition_id, .. }
                | ProviderRecoveryWorkV1::ReopenActive { acquisition_id, .. } => recovered
                    .acquisitions
                    .values()
                    .find(|record| record.acquisition_id == *acquisition_id)
                    .map(|record| record.current_attempt_digest),
                ProviderRecoveryWorkV1::ObserveAcquireRebind { attempt_digest, .. }
                | ProviderRecoveryWorkV1::ObserveInventoryReservation { attempt_digest } => {
                    Some(*attempt_digest)
                }
                ProviderRecoveryWorkV1::ObserveReleasing { acquisition_id, .. } => recovered
                    .releases
                    .values()
                    .find(|record| record.acquisition_id == *acquisition_id)
                    .map(|record| record.attempt_digest),
            }
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery work has no exact original attempt",
            ))?;
            let mut attempts = recovered
                .attempts
                .values()
                .filter(|attempt| attempt.attempt_digest == attempt_digest);
            let attempt = attempts.next().ok_or(ProviderLedgerError::Corrupt(
                "recovery work original request is absent",
            ))?;
            if attempts.next().is_some() {
                return Err(ProviderLedgerError::Corrupt(
                    "recovery work original request is aliased",
                ));
            }
            let original_request =
                SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
                    .map_err(|_| {
                        ProviderLedgerError::Corrupt("recovery original request is invalid")
                    })?;
            let expected = FixedProviderBackendRecoveryV1 {
                work: work.clone(),
                original_request,
                descriptor_roles: Vec::new(),
                fresh_request: None,
                fresh_request_in_flight: false,
                successor_session_ready: false,
                quarantined: false,
            };
            let (method, acquisition_id) = expected.semantic_identity();
            let request_identity = recovery_request_identity(&expected.original_request)?;
            if method != request_identity.0 || acquisition_id != request_identity.1 {
                return Err(ProviderLedgerError::Corrupt(
                    "recovery work differs from its original request",
                ));
            }
            Ok(expected)
        })
        .collect()
}

fn recovery_request_identity(
    request: &SignedSourceProviderRequestV1,
) -> Result<
    (
        aos_sandbox_source_provider_protocol::SourceProviderMethod,
        Option<[u8; 32]>,
    ),
    ProviderLedgerError,
> {
    use aos_sandbox_source_provider_protocol::{
        SourceProviderMethod, decode_acquire_request, decode_inventory_request,
        decode_release_request,
    };

    let acquisition_id = match request.method() {
        SourceProviderMethod::Acquire => Some(
            *decode_acquire_request(request.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("recovery Acquire request is invalid"))?
                .acquisition_id()
                .as_bytes(),
        ),
        SourceProviderMethod::Release => Some(
            *decode_release_request(request.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("recovery Release request is invalid"))?
                .acquisition_id()
                .as_bytes(),
        ),
        SourceProviderMethod::Inventory => {
            decode_inventory_request(request.subject()).map_err(|_| {
                ProviderLedgerError::Corrupt("recovery Inventory request is invalid")
            })?;
            None
        }
        SourceProviderMethod::Hello => {
            return Err(ProviderLedgerError::Corrupt("recovery request is Hello"));
        }
    };
    Ok((request.method(), acquisition_id))
}

enum PreparedFixedProviderBackendOutcomeV1 {
    Reply(DurableProviderReplyV1),
    Released {
        reply: DurableProviderReplyV1,
        tombstone: DurableReleaseTombstoneV1,
    },
    Recovery(FixedProviderBackendRecoveryV1),
    CachedRecovery {
        reply: DurableProviderReplyV1,
        recovery: FixedProviderBackendRecoveryV1,
    },
}

/// Reports progress while receiving a request from the fixed authenticated carrier.
#[must_use = "pending receive state or the exact provider outcome must be retained"]
pub enum FixedProviderReceivedRequestProgressV1 {
    /// The nonblocking authenticated carrier has no complete request yet.
    Pending,
    /// The exact received request was admitted and produced this durable result.
    Outcome(FixedProviderBackendRequestOutcomeV1),
}

impl core::fmt::Debug for FixedProviderBackendRequestOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reply(_) => formatter.write_str("FixedProviderBackendRequestOutcomeV1::Reply"),
            Self::Released { .. } => {
                formatter.write_str("FixedProviderBackendRequestOutcomeV1::Released")
            }
            Self::RecoveryPending => {
                formatter.write_str("FixedProviderBackendRequestOutcomeV1::Recovery")
            }
            Self::CachedRecovery { .. } => {
                formatter.write_str("FixedProviderBackendRequestOutcomeV1::CachedRecovery")
            }
        }
    }
}

/// Runs backend work while the fixed provider owner retains journal authority.
///
/// The session is dormant and borrows an already-created transport. It opens no
/// listener, socket, service, worker, route, or dispatch loop.
pub struct FixedProviderBackendSessionV1<'owner, Transport: ?Sized> {
    owner: &'owner mut FixedProviderOwnerV1,
    transport: &'owner mut Transport,
    current_catalog: Option<(&'owner [u8], &'owner [u8])>,
}

impl FixedProviderOwnerV1 {
    /// Borrows an authority-free transport for fixed-owner backend operations.
    #[must_use]
    pub fn backend_session<'owner, Transport: SourceProviderBackendTransportV1 + ?Sized>(
        &'owner mut self,
        transport: &'owner mut Transport,
    ) -> FixedProviderBackendSessionV1<'owner, Transport> {
        FixedProviderBackendSessionV1 {
            owner: self,
            transport,
            current_catalog: None,
        }
    }

    /// Borrows a current publication and manifest for pre-effect LocalLive inspection.
    ///
    /// The bytes are not authority until each reservation independently
    /// verifies them against live custody and the protected Provider journal.
    #[must_use]
    pub fn backend_session_with_catalog<
        'owner,
        Transport: SourceProviderBackendTransportV1 + ?Sized,
    >(
        &'owner mut self,
        transport: &'owner mut Transport,
        canonical_catalog_publication: &'owner [u8],
        canonical_manifest: &'owner [u8],
    ) -> FixedProviderBackendSessionV1<'owner, Transport> {
        FixedProviderBackendSessionV1 {
            owner: self,
            transport,
            current_catalog: Some((canonical_catalog_publication, canonical_manifest)),
        }
    }
}

impl<Transport: SourceProviderBackendTransportV1 + ?Sized>
    FixedProviderBackendSessionV1<'_, Transport>
{
    /// Admits one Acquire or Inventory packet received by the fixed live owner.
    ///
    /// The packet brand has no public constructor. Recovery and retry work
    /// retain priority; this path never accepts caller-assembled request bytes.
    ///
    /// # Errors
    ///
    /// Rejects pending recovery, stale carrier custody, failed reservation,
    /// Storage inspection, or protected completion.
    pub fn execute_authenticated_source_request(
        &mut self,
        request: crate::FixedProviderAuthenticatedSourceRequestV1,
    ) -> Result<FixedProviderBackendRequestOutcomeV1, ProviderLedgerError> {
        if !self.owner.pending_backend_recovery.is_empty()
            || self.owner.priority_mount_retry_digest.is_some()
            || self.owner.priority_mount_retry_rearm_digest.is_some()
        {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        let signed = request.into_signed();
        self.execute_request(&signed, &[])
    }

    /// Retries one cold selected-row reservation without a successor attempt.
    ///
    /// The original RootMount request and row are re-read from the protected
    /// ledger. A deterministic signed plan may reach only authenticated
    /// Storage readback; this method never observes or reissues backend work,
    /// completes an Acquire, or clears the retained recovery barrier.
    ///
    /// # Errors
    ///
    /// Returns unavailable when the old attempt, current manifest, signer,
    /// trust interval, or authenticated Storage readback cannot be proven.
    pub fn retry_selected_storage_recovery(&mut self) -> Result<bool, ProviderLedgerError> {
        let Some(recovery) = self.owner.pending_backend_recovery.first() else {
            return Ok(false);
        };
        let ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. } = &recovery.work else {
            return Ok(false);
        };
        let acquisition_id = *acquisition_id;
        let selected = self.owner.with_ledger(|ledger| {
            Ok(ledger.recovered.acquisitions.values().any(|record| {
                record.acquisition_id == acquisition_id
                    && record.normalized_intent.kernel_coupled()
                    && record.resource_id != [0; 32]
                    && record.lease_id.is_none()
            }))
        })?;
        if !selected {
            return Ok(false);
        }
        let (publication, manifest) = self
            .current_catalog
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = self.owner.with_ledger(|ledger| {
            ledger.sign_recovered_storage_export_request(acquisition_id, publication, manifest)
        })?;
        self.transport
            .inspect_storage_live_export_request(&signed)
            .map_err(map_transport_error)?;
        Ok(true)
    }

    /// Revalidates the original Applying attempt before a new-session answer.
    ///
    /// The RootMount attempt record digest in the query is opaque to Provider;
    /// RootMount must derive it from its own protected graph. Provider verifies
    /// the signed request digest, authority IDs, acquisition, selected row,
    /// and its own protected attempt through the deterministic signed plan.
    /// Only an authenticated Storage Unavailable readback yields a plan digest.
    ///
    /// # Errors
    ///
    /// Rejects any changed original attempt, catalog, signer, or readback.
    pub fn inspect_selected_storage_recovery_for_query(
        &mut self,
        query: &RecoveryCurrentnessQueryV1,
    ) -> Result<ObjectDigest, ProviderLedgerError> {
        let acquisition_id = query.acquisition_id();
        let Some(recovery) = self.owner.pending_backend_recovery.first() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        if !matches!(
            &recovery.work,
            ProviderRecoveryWorkV1::ObserveApplying { acquisition_id: pending, .. }
                if *pending == acquisition_id
        ) {
            return Err(ProviderLedgerError::Unavailable);
        }
        let (publication, manifest) = self
            .current_catalog
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = self.owner.with_ledger(|ledger| {
            ledger.sign_recovered_storage_export_request(acquisition_id, publication, manifest)
        })?;
        let plan = signed.request();
        let root = plan
            .root_acquire()
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        if query.authorities() != (signed.signer().authority_id(), root.holder_authority().0)
            || root.acquisition_id() != acquisition_id
            || query.original_signed_request_digest()
                != digest_signed_request(plan.signed_root_request())
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        self.transport
            .inspect_storage_live_export_request(&signed)
            .map_err(map_transport_error)?;
        Ok(signed.digest())
    }

    fn retain_backend_recovery(
        &mut self,
        recovery: FixedProviderBackendRecoveryV1,
    ) -> Result<(), ProviderLedgerError> {
        self.owner.pending_backend_recovery.insert(0, recovery);
        Ok(())
    }

    fn continue_backend_recovery(
        &mut self,
        mut recovery: FixedProviderBackendRecoveryV1,
    ) -> Result<FixedProviderBackendRequestOutcomeV1, ProviderLedgerError> {
        let fresh_request =
            recovery
                .fresh_request
                .take()
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "fresh authenticated recovery request is absent",
                ))?;
        if fresh_request == recovery.original_request {
            recovery.fresh_request = Some(fresh_request);
            self.owner.pending_backend_recovery.insert(0, recovery);
            return Err(ProviderLedgerError::Equivocation);
        }
        let work = recovery.work.clone();
        let (observation, continuation) = match self.observe_recovery_continuation(work.clone()) {
            Ok(value) => value,
            Err(error) => {
                recovery.fresh_request = Some(fresh_request);
                self.owner.pending_backend_recovery.insert(0, recovery);
                return Err(error);
            }
        };
        let admitted = match self.execute_recovery_request(
            continuation,
            &fresh_request,
            &recovery.descriptor_roles,
        ) {
            Ok(admitted) => admitted,
            Err(error) => {
                let restaged = self.owner.with_ledger(|ledger| {
                    ledger.restage_recovery_after_failed_continuation(&work, &fresh_request)
                });
                match restaged {
                    Ok((successor, true)) => {
                        recovery.work = successor;
                        recovery.original_request = fresh_request;
                    }
                    Ok((successor, false)) => {
                        recovery.work = successor;
                        recovery.fresh_request = Some(fresh_request);
                    }
                    Err(restage_error) => {
                        recovery.quarantine();
                        self.owner.pending_backend_recovery.insert(0, recovery);
                        return Err(restage_error);
                    }
                }
                self.owner.pending_backend_recovery.insert(0, recovery);
                return Err(error);
            }
        };
        match admitted {
            PreparedFixedProviderBackendOutcomeV1::Reply(reply) => {
                return Ok(FixedProviderBackendRequestOutcomeV1::Reply(reply));
            }
            PreparedFixedProviderBackendOutcomeV1::Released { reply, tombstone } => {
                return Ok(FixedProviderBackendRequestOutcomeV1::Released { reply, tombstone });
            }
            PreparedFixedProviderBackendOutcomeV1::CachedRecovery { reply, recovery } => {
                self.retain_backend_recovery(recovery)?;
                return Ok(FixedProviderBackendRequestOutcomeV1::CachedRecovery { reply });
            }
            PreparedFixedProviderBackendOutcomeV1::Recovery(mut authorized) => {
                if !same_recovery_semantic_identity(&authorized.work, &work) {
                    self.owner.pending_backend_recovery.insert(0, authorized);
                    return Err(ProviderLedgerError::Equivocation);
                }
                let completed = match observation {
                    ProviderRecoveryObservationV1::AcquireNotApplied(absent) => self
                        .reissue_recovered_acquire(absent)
                        .map(FixedProviderBackendRequestOutcomeV1::Reply),
                    ProviderRecoveryObservationV1::AcquireApplied => self
                        .complete_recovered_acquire_applied(work)
                        .map(FixedProviderBackendRequestOutcomeV1::Reply),
                    ProviderRecoveryObservationV1::ReleaseStillPresent(present) => {
                        self.reissue_recovered_release(present)
                            .map(|(reply, tombstone)| {
                                FixedProviderBackendRequestOutcomeV1::Released { reply, tombstone }
                            })
                    }
                    ProviderRecoveryObservationV1::ReleaseApplied => {
                        self.complete_recovered_release_applied(work)
                            .map(|(reply, tombstone)| {
                                FixedProviderBackendRequestOutcomeV1::Released { reply, tombstone }
                            })
                    }
                    ProviderRecoveryObservationV1::InventoryRequiresAuthenticatedCompletion => self
                        .resume_recovered_inventory(work)
                        .map(FixedProviderBackendRequestOutcomeV1::Reply),
                    ProviderRecoveryObservationV1::ActiveReopened
                    | ProviderRecoveryObservationV1::Unavailable => {
                        Err(ProviderLedgerError::Unavailable)
                    }
                };
                if completed.is_err() {
                    match self.owner.with_ledger(|ledger| {
                        ledger.restage_recovery_after_failed_continuation(
                            &authorized.work,
                            &authorized.original_request,
                        )
                    }) {
                        Ok((successor, _)) => {
                            authorized.work = successor;
                            authorized.fresh_request = None;
                        }
                        Err(restage_error) => {
                            authorized.quarantine();
                            self.owner.pending_backend_recovery.insert(0, authorized);
                            return Err(restage_error);
                        }
                    }
                    self.owner.pending_backend_recovery.insert(0, authorized);
                }
                completed
            }
        }
    }

    /// Authenticates, reserves, executes or reopens, and commits one request.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for request, reservation, transport,
    /// observation, currentness, completion, or recovery classification failure.
    fn execute_request(
        &mut self,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
    ) -> Result<FixedProviderBackendRequestOutcomeV1, ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        let current_catalog = self.current_catalog;
        let prepared = self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            let disposition = ledger.verify_and_admit_request_with_catalog(
                signed_request,
                descriptor_roles,
                current_catalog,
            )?;
            execute_disposition(
                ledger,
                disposition,
                &mut backend,
                signed_request,
                descriptor_roles,
                current_catalog,
            )
        })?;
        match prepared {
            PreparedFixedProviderBackendOutcomeV1::Reply(reply) => {
                Ok(FixedProviderBackendRequestOutcomeV1::Reply(reply))
            }
            PreparedFixedProviderBackendOutcomeV1::Released { reply, tombstone } => {
                Ok(FixedProviderBackendRequestOutcomeV1::Released { reply, tombstone })
            }
            PreparedFixedProviderBackendOutcomeV1::Recovery(recovery) => {
                self.retain_backend_recovery(recovery)?;
                Ok(FixedProviderBackendRequestOutcomeV1::RecoveryPending)
            }
            PreparedFixedProviderBackendOutcomeV1::CachedRecovery { reply, recovery } => {
                self.retain_backend_recovery(recovery)?;
                Ok(FixedProviderBackendRequestOutcomeV1::CachedRecovery { reply })
            }
        }
    }

    /// Receives and executes the next request from the fixed authenticated session.
    ///
    /// Unlike the internal recovery helper, this entry point does not accept
    /// caller-provided request bytes. The exact descriptor-free packet received
    /// from the Root-Mount carrier is the packet authenticated and admitted by
    /// the durable provider reducer.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for carrier, authentication, admission,
    /// backend, completion, or protected-currentness failure.
    pub fn receive_and_execute_request(
        &mut self,
    ) -> Result<FixedProviderReceivedRequestProgressV1, ProviderLedgerError> {
        let priority_mount_retry = self.owner.priority_mount_retry_digest;
        if priority_mount_retry.is_none()
            && self
                .owner
                .pending_backend_recovery
                .first()
                .is_some_and(|recovery| recovery.quarantined)
        {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        if priority_mount_retry.is_none()
            && self
                .owner
                .pending_backend_recovery
                .first()
                .is_some_and(|recovery| recovery.fresh_request.is_some())
        {
            let recovery = self.owner.pending_backend_recovery.remove(0);
            return self
                .continue_backend_recovery(recovery)
                .map(FixedProviderReceivedRequestProgressV1::Outcome);
        }
        let reopen_checkpoint = self.owner.with_ledger(|ledger| {
            let installed = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            installed
                .session
                .prepare_ingress_reopen_checkpoint()
                .map_err(ProviderLedgerError::from)
        })?;
        let packet = match self.owner.with_ledger(|ledger| {
            let installed = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            installed
                .session
                .receive_current_request_packet()
                .map_err(ProviderLedgerError::from)
        }) {
            Ok(packet) => packet,
            Err(error) => {
                // A failed successor receive did not consume an authenticated
                // recovery request. Re-arm the retained work so the fixed
                // owners can rotate again instead of wedging ingress forever.
                if let Some(recovery) = self.owner.pending_backend_recovery.first_mut() {
                    recovery.reject_in_flight_request();
                }
                if let Some(digest) = self.owner.priority_mount_retry_digest.take() {
                    self.owner.priority_mount_retry_rearm_digest = Some(digest);
                }
                self.owner.retain_failed_ingress(reopen_checkpoint)?;
                return Err(error);
            }
        };
        let Some(packet) = packet else {
            return Ok(FixedProviderReceivedRequestProgressV1::Pending);
        };
        let signed = match SignedSourceProviderRequestV1::from_canonical_bytes(&packet) {
            Ok(signed) => signed,
            Err(_) => {
                if let Some(digest) = self.owner.priority_mount_retry_digest.take() {
                    self.owner.priority_mount_retry_rearm_digest = Some(digest);
                }
                if let Some(recovery) = self.owner.pending_backend_recovery.first_mut() {
                    recovery.reject_in_flight_request();
                }
                return Err(ProviderLedgerError::Equivocation);
            }
        };
        let signed_request_digest =
            *aos_sandbox_source_provider_protocol::digest_signed_request(&signed).as_bytes();
        if priority_mount_retry == Some(signed_request_digest) {
            self.owner.priority_mount_retry_digest = None;
            return self
                .execute_request(&signed, &[])
                .map(FixedProviderReceivedRequestProgressV1::Outcome);
        }
        if let Some(digest) = priority_mount_retry {
            self.owner.priority_mount_retry_digest = None;
            self.owner.priority_mount_retry_rearm_digest = Some(digest);
            return Err(ProviderLedgerError::Equivocation);
        }
        if !self.owner.pending_backend_recovery.is_empty() {
            let mut recovery = self.owner.pending_backend_recovery.remove(0);
            if let Err(error) = self.owner.with_ledger(|ledger| {
                ledger.validate_recovery_request_candidate(&recovery.work, &signed)
            }) {
                recovery.reject_in_flight_request();
                self.owner.pending_backend_recovery.insert(0, recovery);
                return Err(error);
            }
            recovery.fresh_request_in_flight = false;
            recovery.successor_session_ready = false;
            recovery.fresh_request = Some(signed);
            return self
                .continue_backend_recovery(recovery)
                .map(FixedProviderReceivedRequestProgressV1::Outcome);
        }
        self.execute_request(&signed, &[])
            .map(FixedProviderReceivedRequestProgressV1::Outcome)
    }

    /// Observes one live Pending Acquire under the same fixed claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale progress, transport failure,
    /// contradictory observation, or lost protected currentness.
    pub fn observe_pending_acquire(
        &mut self,
        acquisition_id: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.observe_pending_acquire(acquisition_id, &mut backend)
        })
    }

    /// Observes one live Pending Release under the same fixed claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale progress, transport failure,
    /// contradictory observation, or lost protected currentness.
    pub fn observe_pending_release(
        &mut self,
        acquisition_id: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.observe_pending_release(acquisition_id, &mut backend)
        })
    }

    /// Observes exact recovered work and produces its fresh-session continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, transport failure,
    /// contradictory evidence, or incomplete durable lineage.
    pub fn observe_recovery_continuation(
        &mut self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<
        (
            ProviderRecoveryObservationV1,
            ProviderRecoveryContinuationV1,
        ),
        ProviderLedgerError,
    > {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.observe_recovery_continuation(work, &mut backend)
        })
    }

    /// Authenticates and executes a fresh request bound to recovered work.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for invalid recovery lineage, request,
    /// transport, observation, currentness, or completion.
    pub(crate) fn execute_recovery_request(
        &mut self,
        continuation: ProviderRecoveryContinuationV1,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
    ) -> Result<PreparedFixedProviderBackendOutcomeV1, ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            let disposition = ledger.verify_and_admit_recovery_request(
                continuation,
                signed_request,
                descriptor_roles,
            )?;
            execute_disposition(
                ledger,
                disposition,
                &mut backend,
                signed_request,
                descriptor_roles,
                None,
            )
        })
    }

    /// Reissues and completes one exact recovered Acquire after proven absence.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale absence, missing death or
    /// replay authority, transport failure, or completion failure.
    pub fn reissue_recovered_acquire(
        &mut self,
        absent: RecoveryAcquireNotAppliedV1,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            let permit = ledger.reissue_recovered_acquire(absent)?;
            let holder_id = permit.plan().holder_id();
            let reply = ledger.execute_acquire(permit, &mut backend)?;
            ledger.consume_recovered_execution_death(holder_id)?;
            Ok(reply)
        })
    }

    /// Reissues and completes one exact recovered Release after proven presence.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale presence, missing death or
    /// replay authority, transport failure, or completion failure.
    pub fn reissue_recovered_release(
        &mut self,
        present: RecoveryReleaseStillPresentV1,
    ) -> Result<(DurableProviderReplyV1, DurableReleaseTombstoneV1), ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            let permit = ledger.reissue_recovered_release(present)?;
            let holder_id = permit.plan().holder_id();
            let released = ledger.execute_release(permit, &mut backend)?;
            ledger.consume_recovered_execution_death(holder_id)?;
            Ok(released)
        })
    }

    /// Completes one recovered Acquire proven already applied by fresh readback.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, invalid readback,
    /// missing replay authority, or completion failure.
    pub fn complete_recovered_acquire_applied(
        &mut self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.complete_recovered_acquire_applied(work, &mut backend)
        })
    }

    /// Completes one recovered Release proven already applied by fresh readback.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, invalid readback,
    /// missing replay authority, or completion failure.
    pub fn complete_recovered_release_applied(
        &mut self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<(DurableProviderReplyV1, DurableReleaseTombstoneV1), ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.complete_recovered_release_applied(work, &mut backend)
        })
    }

    /// Resumes and completes one exact recovered Inventory reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, incomplete reopen,
    /// transport failure, missing replay authority, or completion failure.
    pub fn resume_recovered_inventory(
        &mut self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            let permit = ledger.resume_recovered_inventory(work)?;
            ledger.execute_inventory(permit, &mut backend)
        })
    }

    /// Sends one synchronized reply through the fixed authenticated session.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when reply or session currentness is
    /// lost, or the authenticated descriptor transport cannot complete.
    pub fn send_reply(&mut self, reply: DurableProviderReplyV1) -> Result<(), ProviderLedgerError> {
        self.owner.send_reply(reply)
    }

    /// Reopens the exact active SourceRoot for one completed historical Acquire.
    ///
    /// The returned outcome is not sent on the historical session. Mount must
    /// consume it through protected attempt/session recovery before it can
    /// produce a current broker response.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the replay is stale, physical
    /// SourceRoot readback is unavailable or conflicting, or fixed journal
    /// currentness is lost.
    #[doc(hidden)]
    pub fn reopen_historical_acquire(
        &mut self,
        reopen: crate::FixedProviderAcquireReopenV1,
    ) -> Result<crate::FixedProviderHistoricalOutcomeV1, ProviderLedgerError> {
        let crate::FixedProviderAcquireReopenV1 { replay, persisted } = reopen;
        let verifier = self.owner.backend_verifier();
        let transport = &mut *self.transport;
        let reply = self.owner.with_ledger(move |ledger| {
            let mut backend = FixedSourceProviderBackendV1::new(transport, verifier);
            ledger.execute_acquire_replay(replay, &mut backend)
        })?;
        Ok(crate::FixedProviderHistoricalOutcomeV1 {
            response: reply.response,
            source_root: reply.source_root,
            persisted,
        })
    }
}

fn execute_disposition(
    ledger: &mut crate::ProviderLedgerV1<'_>,
    disposition: ProviderAdmissionDispositionV1,
    backend: &mut impl SourceProviderBackendV1,
    signed_request: &SignedSourceProviderRequestV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
    current_catalog: Option<(&[u8], &[u8])>,
) -> Result<PreparedFixedProviderBackendOutcomeV1, ProviderLedgerError> {
    match disposition {
        ProviderAdmissionDispositionV1::Cached(cached) => ledger
            .materialize_cached_response(cached)
            .map(PreparedFixedProviderBackendOutcomeV1::Reply),
        ProviderAdmissionDispositionV1::CachedRecovery { cached, work } => {
            let reply = ledger.materialize_cached_response(cached)?;
            Ok(PreparedFixedProviderBackendOutcomeV1::CachedRecovery {
                reply,
                recovery: FixedProviderBackendRecoveryV1 {
                    work,
                    original_request: signed_request.clone(),
                    descriptor_roles: descriptor_roles.to_vec(),
                    fresh_request: None,
                    fresh_request_in_flight: false,
                    successor_session_ready: false,
                    quarantined: false,
                },
            })
        }
        ProviderAdmissionDispositionV1::AcquireReplay(replay) => ledger
            .execute_acquire_replay(replay, backend)
            .map(PreparedFixedProviderBackendOutcomeV1::Reply),
        ProviderAdmissionDispositionV1::AcquireRebind(permit) => ledger
            .execute_acquire_rebind(permit, backend)
            .map(PreparedFixedProviderBackendOutcomeV1::Reply),
        ProviderAdmissionDispositionV1::Recover(work) => Ok(
            PreparedFixedProviderBackendOutcomeV1::Recovery(FixedProviderBackendRecoveryV1 {
                work,
                original_request: signed_request.clone(),
                descriptor_roles: descriptor_roles.to_vec(),
                fresh_request: None,
                fresh_request_in_flight: false,
                successor_session_ready: false,
                quarantined: false,
            }),
        ),
        ProviderAdmissionDispositionV1::Acquire(permit) if permit.plan().kernel_coupled() => {
            let (publication, manifest) =
                current_catalog.ok_or(ProviderLedgerError::Unavailable)?;
            let signed =
                ledger.sign_current_storage_export_request(&permit, publication, manifest)?;
            // Storage's only current reply is descriptor-free Unavailable. An
            // inspection failure cannot promote the request to an effect.
            let _ = backend.inspect_storage_live_export_request(&signed);
            ledger
                .complete_acquire_disposition(
                    permit,
                    aos_sandbox_source_provider_protocol::SourceProviderStatus::Unavailable,
                )
                .map(PreparedFixedProviderBackendOutcomeV1::Reply)
        }
        ProviderAdmissionDispositionV1::Acquire(permit) => ledger
            .execute_acquire(permit, backend)
            .map(PreparedFixedProviderBackendOutcomeV1::Reply),
        ProviderAdmissionDispositionV1::Release(permit) => {
            let (reply, tombstone) = ledger.execute_release(permit, backend)?;
            Ok(PreparedFixedProviderBackendOutcomeV1::Released { reply, tombstone })
        }
        ProviderAdmissionDispositionV1::Inventory(permit) => ledger
            .execute_inventory(permit, backend)
            .map(PreparedFixedProviderBackendOutcomeV1::Reply),
    }
}

fn same_recovery_semantic_identity(
    left: &ProviderRecoveryWorkV1,
    right: &ProviderRecoveryWorkV1,
) -> bool {
    match (left, right) {
        (
            ProviderRecoveryWorkV1::ObserveApplying {
                acquisition_id: left,
                ..
            }
            | ProviderRecoveryWorkV1::ObserveAcquireRebind {
                acquisition_id: left,
                ..
            }
            | ProviderRecoveryWorkV1::ObservePending {
                acquisition_id: left,
                ..
            }
            | ProviderRecoveryWorkV1::ReopenActive {
                acquisition_id: left,
                ..
            },
            ProviderRecoveryWorkV1::ObserveApplying {
                acquisition_id: right,
                ..
            }
            | ProviderRecoveryWorkV1::ObserveAcquireRebind {
                acquisition_id: right,
                ..
            }
            | ProviderRecoveryWorkV1::ObservePending {
                acquisition_id: right,
                ..
            }
            | ProviderRecoveryWorkV1::ReopenActive {
                acquisition_id: right,
                ..
            },
        ) => left == right,
        (
            ProviderRecoveryWorkV1::ObserveReleasing {
                acquisition_id: left,
                ..
            },
            ProviderRecoveryWorkV1::ObserveReleasing {
                acquisition_id: right,
                ..
            },
        ) => left == right,
        (
            ProviderRecoveryWorkV1::ObserveInventoryReservation { .. },
            ProviderRecoveryWorkV1::ObserveInventoryReservation { .. },
        ) => true,
        _ => false,
    }
}
