//! Common signed-plan and ownership-lease admission.
//!
//! Audience crates supply exact canonical semantics. This module alone turns
//! those semantics plus protected trust and time into authenticated pending
//! records. Returned records are not executable authority until durably
//! committed and checked again through [`BrokerAuthority::check_before_effect`].

mod receiving;
mod public_verification;
pub use public_verification::NetworkPublicVerifierV2;

mod signed_original;
pub use signed_original::BrokerSignedAdmissionOriginalV4;

mod effect_clock;
pub use effect_clock::BrokerEffectClockComparisonV3;

mod capture_lifetime;
pub use capture_lifetime::VerifiedStorageCaptureLifetimeV3;

mod capture_stop;
pub use capture_stop::{StorageCaptureStopInspectionErrorV4,
    StorageCaptureStopInspectionOriginalV4, VerifiedStorageCaptureStopCleanupV4};

mod storage_root_launch_export;
pub use storage_root_launch_export::{
    StorageHostLaunchExportInspectionErrorV2, VerifiedStorageHostLaunchExportV2,
};

mod storage_prepare_clock;
pub use storage_prepare_clock::StoragePrepareNativeClockLoanV1;

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_core::format::decode_signature;
use aos_sandbox_core::{
    BrokerAdmissionIntersection, BrokerArgumentCommitment, BrokerAssignment, BrokerAudience,
    BrokerGrantTarget, BrokerPlanExpectation, BrokerPlanRequest, BrokerPlanTrustAnchor, BrokerVerb,
    DecodeLimits, NodeId, ObjectDigest,
    OwnershipLeaseExpectation, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, VerifiedOwnershipLease, intersect_broker_admission, negotiate_protocol,
    prepare_local_lease_record, verify_broker_plan, verify_ownership_lease,
};
use aos_sandbox_protocol::session::{
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES, MAXIMUM_BROKER_PLAN_BYTES,
    MAXIMUM_OWNERSHIP_LEASE_BYTES, ValidatedUntrustedAuthorizationArtifacts,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::record::{
    AuthorizationRecordError, BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV1,
    BrokerEffectStatusV1, BrokerLocalRecordDomain,
};

use crate::record::{
    NodeJournalMacKey, open_authorization_fence, open_effect_intent, open_local_record,
    seal_authorization_fence, seal_effect_intent, seal_local_record,
};

/// Reports a closed failure before broker effect authority can be consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerAdmissionError {
    /// Protected local authority configuration is invalid.
    #[error("invalid broker authority configuration")]
    InvalidConfiguration,
    /// Signed plan or ownership-lease verification failed.
    #[error("broker authority artifacts failed verification")]
    VerificationFailed,
    /// Request semantics, bounds, or assignment do not match signed authority.
    #[error("request is outside signed broker authority")]
    RequestMismatch,
    /// Authenticated durable state is malformed, stale, equivocal, or misplaced.
    #[error("broker authorization fence rejected admission")]
    FenceRejected,
}

/// Classifies whether an authenticated effect may still cross its first
/// physical-effect boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerEffectClockDispositionV1 {
    /// The authenticated effect remains inside its exclusive deadline.
    Fresh,
    /// The authenticated effect has reached or passed its exclusive deadline.
    Expired,
}

/// Supplies exact audience-owned facts to common authority admission.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionRequest<'a> {
    /// Receiving broker audience.
    pub audience: BrokerAudience,
    /// Independently versioned local broker protocol.
    pub protocol: ProtocolId,
    /// Exact negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// Assignment carried by the validated request.
    pub assignment: BrokerAssignment,
    /// Exact nonzero request identifier.
    pub request_id: [u8; 16],
    /// Exact received method-specific protobuf body.
    pub request_body: &'a [u8],
    /// Exact count of already-validated ancillary descriptor roles.
    pub descriptor_count: u16,
    /// Audience-specific canonical semantic verb.
    pub verb: BrokerVerb,
    /// Audience-specific canonical resource target.
    pub target: BrokerGrantTarget,
    /// Commitment to audience-specific request and catalog semantics.
    pub argument_commitment: BrokerArgumentCommitment,
    /// Exclusive request-local BOOTTIME effect deadline.
    pub request_deadline_boottime_nanoseconds: u64,
}

/// Owns protected trust, node identity, and journal authentication state.
pub struct BrokerAuthority {
    domain: BrokerDomain,
    plan_anchor: BrokerPlanTrustAnchor,
    lease_anchor: OwnershipLeaseTrustAnchor,
    node: NodeId,
    journal_mac_key: NodeJournalMacKey,
}

/// Selects an owner-specific phase, never a request-supplied eligibility flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionPhase {
    BasePlan,
    ExactGrantRotation,
    ExistingMountFuseIntent,
    ExistingHostFuseWorker,
    ExistingStorageSnapshot,
}

impl BrokerAuthority {
    /// Returns the configured local node identity as comparison DATA.
    ///
    /// The returned identity carries no admission or mutation capability.
    #[must_use]
    pub const fn node_identity_data_v2(&self) -> NodeId {
        self.node
    }

    /// Admits an operation-owned Snapshot derivative beside its unchanged base.
    ///
    /// A same-plan request retains ordinary admission. A changed plan must use
    /// the exact installed assignment and lease, with one descriptor-free grant.
    ///
    /// # Errors
    ///
    /// Rejects another purpose, a changed base assignment, expiry or local lease,
    /// or any failure in the common signature/intersection engine.
    pub fn admit_storage_snapshot(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Storage
            || request.audience != BrokerAudience::Storage
            || request.protocol != ProtocolId::StorageBroker
            || request.verb != BrokerVerb::StorageAtomicSnapshot
            || request.target != BrokerGrantTarget::Assignment
            || request.descriptor_count != 0
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts, request, current_clock, prior_fence,
            AdmissionPhase::ExistingStorageSnapshot,
        )
    }

    /// Constructs authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::InvalidConfiguration`] for sentinel
    /// node or journal-key values.
    pub fn new(
        domain: BrokerDomain,
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, BrokerAdmissionError> {
        let mut plan = Some(Ok(plan_anchor));
        let mut lease = Some(Ok(lease_anchor));
        Self::new_from_anchor_results_v1(
            domain, &mut plan, &mut lease, node, journal_key_id, journal_secret,
        )
    }

    // The selected loader keeps these actual successful anchors resident if
    // later node/MAC validation fails. Ordinary callers use the same recipe
    // with local slots and their existing semantic validation order.
    pub(crate) fn new_from_anchor_results_v1(
        domain: BrokerDomain,
        plan: &mut Option<Result<BrokerPlanTrustAnchor, aos_sandbox_core::BrokerPlanVerificationError>>,
        lease: &mut Option<Result<OwnershipLeaseTrustAnchor, aos_sandbox_core::OwnershipLeaseVerificationError>>,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, BrokerAdmissionError> {
        let journal_secret = Zeroizing::new(journal_secret);
        if node.as_bytes() == &[0; 16] {
            return Err(BrokerAdmissionError::InvalidConfiguration);
        }
        let journal_mac_key = NodeJournalMacKey::new(domain, journal_key_id, *journal_secret)
            .map_err(|_| BrokerAdmissionError::InvalidConfiguration)?;
        let (plan_anchor, lease_anchor) = match (plan.take(), lease.take()) {
            (Some(Ok(plan)), Some(Ok(lease))) => (plan, lease),
            (original_plan, original_lease) => {
                *plan = original_plan;
                *lease = original_lease;
                return Err(BrokerAdmissionError::InvalidConfiguration);
            }
        };
        Ok(Self {
            domain,
            plan_anchor,
            lease_anchor,
            node,
            journal_mac_key,
        })
    }

    /// Verifies and intersects one exact request with protected local state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError`] for any signature, context, semantic,
    /// bound, clock, lease, prior-fence, or durable-state mismatch.
    pub fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain == BrokerDomain::Nix && !is_online_nix_resolve_admission(&request) {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            prior_fence,
            if self.domain == BrokerDomain::Nix {
                // Resolve signs the exact original request commitment rather
                // than borrowing a reusable assignment-wide plan. The same
                // monotonic fence and local lease checks still reject rollback.
                AdmissionPhase::ExactGrantRotation
            } else {
                AdmissionPhase::BasePlan
            },
        )
    }

    /// Admits an exact Host execution grant while retaining the prior lease.
    ///
    /// The caller must keep the prior base-plan fence as its shared lease head;
    /// the returned exact-grant plan is only an effect-specific authorization.
    ///
    /// # Errors
    ///
    /// Rejects a non-execution verb, invalid signature, assignment, lease,
    /// semantic grant, or stale prior fence.
    pub fn admit_host_execution(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || !matches!(
                request.verb,
                BrokerVerb::HostApplyExecution | BrokerVerb::HostQueryExecution
            )
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Admits one provisional Host output reserve or read-only query grant.
    ///
    /// The signed Controller source still requires independent Host currentness
    /// and protected output-ledger checks before a reservation can commit.
    ///
    /// # Errors
    ///
    /// Rejects a wrong domain or verb, stale plan/lease, semantic mismatch,
    /// or a replaced shared Host base fence.
    pub fn admit_host_output(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || !matches!(
                request.verb,
                BrokerVerb::HostReserveExecutionOutput | BrokerVerb::HostQueryExecutionOutput
            )
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Admits a one-shot Host argument observation or historical query grant.
    ///
    /// The caller must retain the exact current Host runtime and output
    /// correlation before touching the Guest channel. Query is read-only and
    /// cannot turn a historical packet into fresh execution authority.
    ///
    /// # Errors
    ///
    /// Rejects a wrong domain or verb, stale plan/lease, semantic mismatch,
    /// or a replaced shared Host base fence.
    pub fn admit_host_argument(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || !matches!(
                request.verb,
                BrokerVerb::HostObserveExecutionArgument
                    | BrokerVerb::HostPrepareExecutionArgumentV2
                    | BrokerVerb::HostAcceptExecutionArgumentV2
                    | BrokerVerb::HostQueryExecutionArgument
                    | BrokerVerb::HostTerminalNoApply
                    | BrokerVerb::HostQueryNoApply
            )
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Admits only purpose 57 beside an existing Mount fence for the same assignment.
    ///
    /// The FUSE presentation grant has its own plan digest after native slot
    /// preparation. This exact carve-out reuses the already current local
    /// ownership lease; native Mount and other FUSE purposes remain unchanged.
    ///
    /// # Errors
    ///
    /// Rejects another domain/profile, stale assignment or ownership, invalid
    /// signatures, substituted complete intent semantics and expanded FD count.
    pub fn admit_fuse_intent(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Mount || !is_fuse_intent_admission(&request) {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        // Open location-authenticated local state, not a caller assertion that
        // a slot or previous assignment exists. The phase may rotate only the
        // exact-grant plan, never create or advance the shared assignment.
        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        self.check_current_fence(&current)?;
        require_same_fuse_assignment(Some(&current), request.assignment)?;
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExistingMountFuseIntent,
        )
    }

    /// Admits purpose 56 only on the exact already installed Host ownership cut.
    ///
    /// The worker's Resource grant rotates only its exact plan commitment.
    /// Neither a newer assignment nor a renewed local lease can authorize this
    /// preparation. The caller still owes original held Mount/session custody,
    /// role-object validation and durable Host launch escrow before PID1.
    ///
    /// # Errors
    ///
    /// Rejects another domain/profile, missing or changed location-authenticated
    /// prior state, invalid signatures, substituted semantics, or any renewal
    /// of the complete installed local ownership lease.
    pub fn admit_host_fuse_worker(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host || !is_host_fuse_worker_admission(&request) {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        self.check_current_fence(&current)?;
        require_same_fuse_assignment(Some(&current), request.assignment)?;
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExistingHostFuseWorker,
        )
    }

    /// Admits a distinct Host ATTACH grant on the shared runtime lease.
    ///
    /// # Errors
    ///
    /// Rejects the wrong domain or verb, invalid signatures, a mismatched
    /// semantic plan grant, or a stale durable lease fence.
    pub fn admit_host_attach_gate(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host || request.verb != BrokerVerb::HostInstallAttachGate {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Verifies a distinct read-only Host attach query against the shared fence.
    ///
    /// The returned records are not committed. Callers must check the effect
    /// deadline and use them only for a current read-only observation.
    ///
    /// # Errors
    ///
    /// Rejects wrong domain/verb or any signed plan, lease, semantic, or
    /// current durable-fence mismatch.
    pub fn admit_host_attach_query(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || !matches!(
                request.verb,
                BrokerVerb::HostQueryAttachGateReadiness | BrokerVerb::HostQueryAttachGateRoute
            )
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Verifies one read-only Host observation of an original Storage reserve.
    ///
    /// The exact Controller Host-audience grant may rotate away from the base
    /// plan, but its assignment and lease must remain on the protected fence.
    /// No Host or Storage output record is written by this admission.
    ///
    /// # Errors
    ///
    /// Rejects a foreign verb or target, invalid signatures, changed lease,
    /// or an inexact request commitment.
    pub fn admit_host_storage_output_readback(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || request.verb != BrokerVerb::HostObserveStorageOutput
            || request.target != BrokerGrantTarget::Assignment
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Verifies one read-only Storage capture candidate on its retained fence.
    ///
    /// The exact Controller plan may differ from the shared Storage base plan,
    /// but the assignment and lease may not move. No durable effect is
    /// committed by this verification.
    ///
    /// # Errors
    ///
    /// Rejects a wrong domain or verb, substituted signed plan, stale lease,
    /// or changed protected assignment fence.
    pub fn admit_storage_capture_candidate(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Storage
            || request.verb != BrokerVerb::StorageCaptureCandidateReadback
            || request.target != BrokerGrantTarget::Assignment
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        if current.assignment() != request.assignment {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Admits only an original logical Storage output reserve or historical query.
    ///
    /// The exact grant may rotate, but the genuine existing base assignment and
    /// lease remain unchanged. This check does not establish live Host custody.
    ///
    /// # Errors
    ///
    /// Rejects another domain, verb, target, assignment, signed grant, or lease.
    pub fn admit_storage_output(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Storage
            || !matches!(request.verb, BrokerVerb::StorageReserveExecutionOutput | BrokerVerb::StorageQueryExecutionOutput)
            || request.target != BrokerGrantTarget::Assignment
            || request.descriptor_count != 0
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        if current.assignment() != request.assignment {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )
    }

    /// Verifies the explicit physical Capture reserve on its existing assignment.
    ///
    /// This checks the independent Capture grant, rather than treating a logical
    /// output reservation as permission to create a dataset or mount. Storage
    /// still owns the current catalog, Host and durable one-shot joins.
    ///
    /// # Errors
    ///
    /// Rejects another domain, verb, target, descriptor-bearing request, changed
    /// assignment, substituted signed plan, stale lease or invalid protected fence.
    pub fn admit_storage_capture_reserve_v2(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_storage_capture_exact_v2(artifacts, request, current_clock, prior_fence,
            BrokerVerb::StorageReserveExecutionCapture)
    }

    /// Verifies only a fresh read-only Capture Query on the same existing lease.
    ///
    /// The signed query may rotate its exact plan. It cannot renew the base
    /// assignment or lease and supplies no worker, reservation or write permit.
    ///
    /// # Errors
    /// Rejects another domain, verb, target, descriptors, assignment, grant,
    /// protected fence, stale clock or changed original local lease.
    pub fn admit_storage_capture_query_v2(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_storage_capture_exact_v2(artifacts, request, current_clock, prior_fence,
            BrokerVerb::StorageQueryExecutionCapture)
    }

    fn admit_storage_capture_exact_v2(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
        expected_verb: BrokerVerb,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Storage
            || request.verb != expected_verb
            || request.target != BrokerGrantTarget::Assignment
            || request.descriptor_count != 0
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        if current.assignment() != request.assignment {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let admission = self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )?;
        if admission.fence.local_lease_record() != current.local_lease_record() {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(admission)
    }

    /// Admits only Nix population on the same installed Storage assignment.
    ///
    /// The post-Create grant may rotate its exact plan, but it borrows the
    /// original local lease without renewing its fail-stop deadline. This
    /// verification supplies no resource reservation or native writer loan.
    ///
    /// # Errors
    ///
    /// Rejects another domain, verb, target, descriptor-bearing request,
    /// missing or changed assignment fence, invalid grant, or lease renewal.
    pub fn admit_storage_nix_generation_population(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Storage
            || request.verb != BrokerVerb::StoragePopulateNixGenerationRoot
            || request.target != BrokerGrantTarget::Assignment
            || request.descriptor_count != 0
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }

        let current = self.open_fence(request.assignment.sandbox().as_bytes(), prior_fence)?;
        if current.assignment() != request.assignment {
            return Err(BrokerAdmissionError::FenceRejected);
        }

        let admission = self.admit_with_plan_rotation(
            artifacts,
            request,
            current_clock,
            Some(prior_fence),
            AdmissionPhase::ExactGrantRotation,
        )?;
        if admission.fence.local_lease_record() != current.local_lease_record() {
            // Exact-plan rotation is not permission to renew the installed
            // lease, create a new BOOTTIME cut, or extend the original attempt.
            return Err(BrokerAdmissionError::FenceRejected);
        }

        Ok(admission)
    }

    fn admit_with_plan_rotation(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
        phase: AdmissionPhase,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_with_plan_rotation_retaining_v4(
            artifacts, request, current_clock, prior_fence, phase, None,
        )
    }

    fn admit_with_plan_rotation_retaining_v4(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
        phase: AdmissionPhase,
        mut original: Option<&mut BrokerSignedAdmissionOriginalV4>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        let fuse_intent = phase == AdmissionPhase::ExistingMountFuseIntent
            && self.domain == BrokerDomain::Mount
            && is_fuse_intent_admission(&request);
        if phase == AdmissionPhase::ExistingMountFuseIntent && !fuse_intent {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let host_fuse_worker = phase == AdmissionPhase::ExistingHostFuseWorker
            && self.domain == BrokerDomain::Host
            && is_host_fuse_worker_admission(&request);
        if (phase == AdmissionPhase::ExistingHostFuseWorker && !host_fuse_worker)
            || (request.verb == BrokerVerb::HostPrepareFuseWorkerSession && !host_fuse_worker)
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        if (!supports_signed_admission(request.protocol, request.protocol_version) && !fuse_intent)
            || (request.audience.protocol() != request.protocol && !fuse_intent)
            || request.audience != self.domain.audience()
            || request.request_id == [0; 16]
            || request.request_body.is_empty()
            || request.request_deadline_boottime_nanoseconds <= current_clock.boottime_nanoseconds()
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let authorization = borrowed_artifacts(artifacts);
        let verified_plan = self.verify_signed_plan_retaining_v4(authorization, &request, current_clock, original.as_deref_mut())?;
        let request_bytes = u32::try_from(request.request_body.len())
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        let matched = verified_plan
            .match_request(BrokerPlanRequest {
                verb: request.verb,
                target: request.target,
                argument_commitment: request.argument_commitment,
                request_bytes,
                descriptor_count: request.descriptor_count,
            })
            .map_err(|cause| {
                if let Some(original) = original.as_deref_mut() { original.retain_plan_v4(cause); }
                BrokerAdmissionError::RequestMismatch
            })?;

        let verified_lease = self.verify_signed_lease_retaining_v4(
            authorization, &verified_plan, &request, current_clock, original.as_deref_mut(),
        )?;

        let sandbox = request.assignment.sandbox();
        let sandbox_key = sandbox.as_bytes();
        let prior = if self.domain == BrokerDomain::Nix {
            prior_fence
                .map(|bytes| self.open_online_nix_fence(sandbox_key, bytes))
                .transpose()?
        } else {
            prior_fence
                .map(|bytes| {
                    open_authorization_fence(
                        &self.journal_mac_key,
                        RecordNamespace::DesiredState,
                        sandbox_key,
                        bytes,
                    )
                })
                .transpose()
                .map_err(|cause| {
                    if let Some(original) = original.as_deref_mut() { original.retain_record_v4(cause); }
                    BrokerAdmissionError::FenceRejected
                })?
        };
        let snapshot_derivative = phase == AdmissionPhase::ExistingStorageSnapshot
            && prior.as_ref().is_some_and(|base| base.plan_digest() != verified_plan.plan_digest());
        if snapshot_derivative {
            let base = prior.as_ref().ok_or(BrokerAdmissionError::FenceRejected)?;
            self.check_current_fence(base)?;
            require_same_fuse_assignment(Some(base), request.assignment)?;
            if verified_plan.plan().expires_seconds() != base.plan_expires_seconds()
                || verified_plan.plan().grants().len() != 1
            {
                return Err(BrokerAdmissionError::FenceRejected);
            }
        }
        if matches!(
            phase,
            AdmissionPhase::ExistingMountFuseIntent | AdmissionPhase::ExistingHostFuseWorker
        ) {
            require_same_fuse_assignment(prior.as_ref(), request.assignment)?;
        }
        let prior_local = validate_prior_fence(
            prior.as_ref(),
            &verified_plan,
            request.assignment,
            self.node,
            phase != AdmissionPhase::BasePlan
                && (phase != AdmissionPhase::ExistingStorageSnapshot || snapshot_derivative),
        )?;
        let pending_lease = prepare_local_lease_record(prior_local, &verified_lease, current_clock)
            .map_err(|cause| {
                if let Some(original) = original.as_deref_mut() { original.retain_lease_v4(cause); }
                BrokerAdmissionError::FenceRejected
            })?;
        if matches!(
            phase,
            AdmissionPhase::ExistingMountFuseIntent | AdmissionPhase::ExistingHostFuseWorker
        ) || snapshot_derivative
        {
            if prior_local.is_none_or(|current| current != &pending_lease.record) {
                // These phases borrow the installed local lease; renewal or a
                // new BOOTTIME fence belongs to the ordinary owner path.
                return Err(BrokerAdmissionError::FenceRejected);
            }
        }
        let intersection = intersect_broker_admission(
            matched,
            &verified_lease,
            &pending_lease.record,
            current_clock,
            request.request_id,
            request.argument_commitment.digest(),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() { original.retain_lease_v4(cause); }
            BrokerAdmissionError::FenceRejected
        })?;
        let fence = BrokerAuthorizationFenceV1::new(
            request.assignment,
            self.node,
            verified_plan.plan_digest(),
            verified_plan.plan().expires_seconds(),
            verified_plan.plan().ownership_authority().clone(),
            pending_lease.record.clone(),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() { original.retain_record_v4(cause); }
            BrokerAdmissionError::FenceRejected
        })?;
        let effect_deadline =
            conservative_plan_deadline(verified_plan.plan().expires_seconds(), current_clock)?
                .min(pending_lease.record.fail_stop_boottime_nanoseconds())
                .min(request.request_deadline_boottime_nanoseconds);
        if effect_deadline <= current_clock.boottime_nanoseconds() {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let effect = BrokerEffectIntentV1::pending(
            &intersection,
            ObjectDigest::from_bytes(Sha256::digest(request.request_body).into()),
            pending_lease.record,
            *current_clock,
            request.request_deadline_boottime_nanoseconds,
            effect_deadline,
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() { original.retain_record_v4(cause); }
            BrokerAdmissionError::FenceRejected
        })?;
        Ok(VerifiedBrokerAdmission {
            fence,
            effect,
            verified_lease,
            intersection,
        })
    }

    // These two pure verification stages are shared with Storage's closed
    // inspection of an original HostLaunch. Only ordinary admission continues
    // into the local lease, durable fence and pending effect machinery.
    fn verify_signed_plan(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
    ) -> Result<aos_sandbox_core::VerifiedBrokerPlan, BrokerAdmissionError> {
        self.verify_signed_plan_retaining_v4(artifacts, request, current_clock, None)
    }

    fn verify_signed_plan_retaining_v4(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        original: Option<&mut BrokerSignedAdmissionOriginalV4>,
    ) -> Result<aos_sandbox_core::VerifiedBrokerPlan, BrokerAdmissionError> {
        self.public_verification_v2().verify_signed_plan_retaining_v4(
            artifacts, request, current_clock, original,
        )
    }

    fn verify_signed_lease(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        verified_plan: &aos_sandbox_core::VerifiedBrokerPlan,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
    ) -> Result<VerifiedOwnershipLease, BrokerAdmissionError> {
        self.verify_signed_lease_retaining_v4(artifacts, verified_plan, request, current_clock, None)
    }

    fn verify_signed_lease_retaining_v4(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        verified_plan: &aos_sandbox_core::VerifiedBrokerPlan,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        original: Option<&mut BrokerSignedAdmissionOriginalV4>,
    ) -> Result<VerifiedOwnershipLease, BrokerAdmissionError> {
        self.public_verification_v2().verify_signed_lease_retaining_v4(
            artifacts, verified_plan, request, current_clock, original,
        )
    }

    /// Authenticates and opens one exact effect-record location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn open_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV1, BrokerAdmissionError> {
        open_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates and opens one exact assignment-fence record location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for malformed,
    /// unauthenticated, or relocated state.
    pub fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, BrokerAdmissionError> {
        open_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Returns the fixed ONLINE Nix assignment-fence key as nonauthorizing DATA.
    #[must_use]
    pub fn online_nix_fence_key(sandbox_id: &[u8; 16]) -> [u8; 24] {
        let mut key = [0; 24];
        key[..8].copy_from_slice(b"AOSNXF01");
        key[8..].copy_from_slice(sandbox_id);
        key
    }

    /// Returns the fixed ONLINE Nix effect key as nonauthorizing DATA.
    #[must_use]
    pub fn online_nix_effect_key(request_id: &[u8; 16]) -> [u8; 24] {
        let mut key = [0; 24];
        key[..8].copy_from_slice(b"AOSNXE01");
        key[8..].copy_from_slice(request_id);
        key
    }

    /// Opens an ONLINE Nix fence at its exact namespace-47 location.
    ///
    /// # Errors
    /// Rejects another broker purpose, sentinel identity, unauthenticated bytes,
    /// or a fence relocated from its actual sandbox key.
    pub fn open_online_nix_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Nix || sandbox_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let fence = open_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::BrokerSessionTraffic,
            &Self::online_nix_fence_key(sandbox_id),
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if fence.assignment().sandbox().as_bytes() != sandbox_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(fence)
    }

    /// Opens an ONLINE Nix effect at its exact namespace-47 location.
    ///
    /// # Errors
    /// Rejects another broker purpose, sentinel identity, unauthenticated bytes,
    /// or an effect relocated from its original request key.
    pub fn open_online_nix_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV1, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Nix || request_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let effect = open_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::BrokerSessionTraffic,
            &Self::online_nix_effect_key(request_id),
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if effect.request_id() != request_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(effect)
    }

    /// Authenticates an assignment fence retained with one exact operation.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for a zero operation
    /// identity or malformed, unauthenticated, or relocated state.
    pub fn open_operation_fence(
        &self,
        operation_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, BrokerAdmissionError> {
        if operation_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        open_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::AuthorityPublication,
            operation_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Reads a fresh clock and validates it immediately before an effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] when the clock source
    /// fails or any signed/local expiry, boot, provenance, or drift bound fails.
    pub fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV1,
        trusted_clock: &mut F,
    ) -> Result<(), BrokerAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, BrokerAdmissionError>,
    {
        let current_clock = trusted_clock()?;
        self.validate_effect_clock(effect, &current_clock)
    }

    /// Checks that a durable fence still belongs to current protected identity.
    ///
    /// The journal MAC key must be rotated whenever the protected broker-plan
    /// trust anchor changes because the V1 fence retains the accepted plan
    /// digest but not its signing-key identity. Ownership-authority and node
    /// changes are rejected directly here even if an operator incorrectly
    /// reuses the journal key.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] when the fence names a
    /// different configured node or ownership-authority generation.
    pub fn check_current_fence(
        &self,
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<(), BrokerAdmissionError> {
        if fence.node() != self.node || fence.ownership_authority() != self.lease_anchor.authority()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }

    /// Validates a freshly sampled protected clock against a durable effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for expiry, reboot,
    /// provenance substitution, backwards time, or excessive paired-clock drift.
    pub fn validate_effect_clock(
        &self,
        effect: &BrokerEffectIntentV1,
        current_clock: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        match self.classify_effect_clock(effect, current_clock)? {
            BrokerEffectClockDispositionV1::Fresh => Ok(()),
            BrokerEffectClockDispositionV1::Expired => Err(BrokerAdmissionError::FenceRejected),
        }
    }

    /// Classifies one protected clock sample against an authenticated effect.
    ///
    /// This method distinguishes expiry only after authenticating the complete
    /// paired-clock continuity contract. Callers may use [`Self::validate_effect_clock`]
    /// when they do not need to distinguish an expired effect from another
    /// fail-closed clock rejection.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for reboot, provenance
    /// substitution, backwards time, or excessive paired-clock drift.
    pub fn classify_effect_clock(
        &self,
        effect: &BrokerEffectIntentV1,
        current_clock: &RawPairedClockSample,
    ) -> Result<BrokerEffectClockDispositionV1, BrokerAdmissionError> {
        BrokerEffectClockComparisonV3::from_effect(effect).classify(current_clock)
    }

    /// Authenticates one assignment fence for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if fence.assignment().sandbox().as_bytes() != sandbox_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox_id,
            fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Seals an ONLINE Nix fence for its fixed namespace-47 location.
    ///
    /// # Errors
    /// Rejects another broker purpose, sentinel or changed sandbox identity,
    /// or an invalid fence. The value still requires the caller's atomic
    /// RequestPrepared/fence/effect transaction and physical floor readback.
    pub fn seal_online_nix_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Nix
            || sandbox_id == &[0; 16]
            || fence.assignment().sandbox().as_bytes() != sandbox_id
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::BrokerSessionTraffic,
            &Self::online_nix_fence_key(sandbox_id),
            fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Seals an ONLINE Nix effect for its fixed namespace-47 location.
    ///
    /// # Errors
    /// Rejects another broker purpose, sentinel or changed request identity,
    /// or an invalid effect. Sealing is not a durable commit or effect permit.
    pub fn seal_online_nix_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Nix
            || request_id == &[0; 16]
            || effect.request_id() != request_id
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::BrokerSessionTraffic,
            &Self::online_nix_effect_key(request_id),
            effect,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an assignment fence for one exact operation location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for a zero operation
    /// identity or invalid state.
    pub fn seal_operation_fence(
        &self,
        operation_id: &[u8; 16],
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if operation_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::AuthorityPublication,
            operation_id,
            fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates one effect for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if effect.request_id() != request_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            effect,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an audience-specific local record at one exact journal location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid bounds or key state.
    pub fn seal_local_record(
        &self,
        namespace: RecordNamespace,
        journal_key: &[u8],
        domain: BrokerLocalRecordDomain,
        payload: &[u8],
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        seal_local_record(
            &self.journal_mac_key,
            namespace,
            journal_key,
            domain,
            payload,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an audience-specific record before returning its payload.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for tampering, relocation,
    /// a wrong application domain, or malformed framing.
    pub fn open_local_record<'a>(
        &self,
        namespace: RecordNamespace,
        journal_key: &[u8],
        domain: BrokerLocalRecordDomain,
        bytes: &'a [u8],
    ) -> Result<&'a [u8], BrokerAdmissionError> {
        open_local_record(&self.journal_mac_key, namespace, journal_key, domain, bytes)
            .map_err(|_| BrokerAdmissionError::FenceRejected)
    }
}

fn is_fuse_intent_admission(request: &AdmissionRequest<'_>) -> bool {
    request.audience == BrokerAudience::Mount
        && request.protocol == ProtocolId::MountFuseBroker
        && request.protocol_version == ProtocolVersion::new(3, 0)
        && request.verb == BrokerVerb::MountReserveFuseWorkerIntent
        && matches!(request.target, BrokerGrantTarget::Resource(_))
        && request.descriptor_count == 0
}

fn is_host_fuse_worker_admission(request: &AdmissionRequest<'_>) -> bool {
    request.audience == BrokerAudience::Host
        && request.protocol == ProtocolId::HostBroker
        && request.protocol_version == ProtocolVersion::new(1, 0)
        && request.verb == BrokerVerb::HostPrepareFuseWorkerSession
        && matches!(request.target, BrokerGrantTarget::Resource(_))
        && request.descriptor_count == 4
        && request.request_body.len() <= 4096
}

fn is_online_nix_resolve_admission(request: &AdmissionRequest<'_>) -> bool {
    request.audience == BrokerAudience::Nix
        && request.protocol == ProtocolId::NixBuildBroker
        && request.protocol_version == ProtocolVersion::new(1, 0)
        && matches!(request.verb,
            BrokerVerb::NixResolveProtectedRecipe
                | BrokerVerb::NixRealizeAuthorizedDerivation
                | BrokerVerb::NixQueryAuthorizedPathInfo)
        && matches!(request.target, BrokerGrantTarget::Resource(_))
        && request.descriptor_count == 0
        && request.request_body.len()
            <= aos_sandbox_protocol::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2
}

fn supports_signed_admission(protocol: ProtocolId, version: ProtocolVersion) -> bool {
    negotiate_protocol(protocol, version).is_ok()
        && (version.minor() >= 1
            || matches!(
                protocol,
                ProtocolId::HostBroker
                    | ProtocolId::MountBroker
                    | ProtocolId::StorageBroker
                    | ProtocolId::NetworkBroker
                    | ProtocolId::NixBuildBroker
            ))
}

/// Carries exact authenticated records that callers must commit atomically.
#[derive(Debug)]
pub struct VerifiedBrokerAdmission {
    /// Monotonic assignment/plan/lease fence.
    pub fence: BrokerAuthorizationFenceV1,
    /// Pending non-authorizing effect intent.
    pub effect: BrokerEffectIntentV1,
    /// Fresh signature-verified lease used for the committed local fence.
    pub verified_lease: VerifiedOwnershipLease,
    /// Exact signed-plan/current-lease match retained for protected effect owners.
    pub intersection: BrokerAdmissionIntersection,
}

fn borrowed_artifacts(
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) -> aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_> {
    aos_sandbox_protocol::session::AuthorizationArtifactBytes {
        broker_plan: artifacts.broker_plan(),
        broker_plan_signature: artifacts.broker_plan_signature(),
        ownership_lease: artifacts.ownership_lease(),
        ownership_lease_signature: artifacts.ownership_lease_signature(),
    }
}

const fn artifact_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 2_048,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: maximum_bytes,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

fn conservative_plan_deadline(
    plan_expires_seconds: i64,
    clock: &RawPairedClockSample,
) -> Result<u64, BrokerAdmissionError> {
    let remaining_whole_seconds = plan_expires_seconds
        .checked_sub(clock.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .ok_or(BrokerAdmissionError::FenceRejected)?;
    let duration = remaining_whole_seconds
        .checked_mul(1_000_000_000)
        .ok_or(BrokerAdmissionError::FenceRejected)?;
    clock
        .boottime_nanoseconds()
        .checked_add(duration)
        .ok_or(BrokerAdmissionError::FenceRejected)
}

fn validate_prior_fence<'a>(
    prior: Option<&'a BrokerAuthorizationFenceV1>,
    plan: &aos_sandbox_core::VerifiedBrokerPlan,
    assignment: BrokerAssignment,
    node: NodeId,
    allow_exact_plan_rotation: bool,
) -> Result<Option<&'a aos_sandbox_core::LocalLeaseRecord>, BrokerAdmissionError> {
    let Some(prior) = prior else {
        return Ok(None);
    };
    let current = prior.assignment();
    if prior.node() != node
        || (assignment.epoch() == current.epoch()
            && plan.plan().ownership_authority() != prior.ownership_authority())
        || assignment.epoch() < current.epoch()
        || (assignment.epoch() == current.epoch()
            && assignment.desired_generation() < current.desired_generation())
        || (assignment.epoch() == current.epoch()
            && assignment.incarnation() != current.incarnation())
        || (assignment.epoch() == current.epoch()
            && assignment.desired_generation() == current.desired_generation()
            && (assignment.digest() != current.digest()
                || (!allow_exact_plan_rotation && plan.plan_digest() != prior.plan_digest())))
    {
        return Err(BrokerAdmissionError::FenceRejected);
    }
    if assignment.epoch() == current.epoch() && assignment.digest() == current.digest() {
        Ok(Some(prior.local_lease_record()))
    } else {
        Ok(None)
    }
}

fn require_same_fuse_assignment(
    prior: Option<&BrokerAuthorizationFenceV1>,
    assignment: BrokerAssignment,
) -> Result<(), BrokerAdmissionError> {
    match prior {
        Some(current) if current.assignment() == assignment => Ok(()),
        _ => Err(BrokerAdmissionError::FenceRejected),
    }
}

impl BrokerDomain {
    const fn audience(self) -> BrokerAudience {
        match self {
            Self::Host => BrokerAudience::Host,
            Self::Mount => BrokerAudience::Mount,
            Self::Storage => BrokerAudience::Storage,
            Self::Network => BrokerAudience::Network,
            Self::Nix => BrokerAudience::Nix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_admission_requires_exact_host_resource_and_four_roles() {
        let original = AdmissionRequest {
            audience: BrokerAudience::Host,
            protocol: ProtocolId::HostBroker,
            protocol_version: ProtocolVersion::new(1, 0),
            assignment: BrokerAssignment::new(
                aos_sandbox_core::SandboxId::from_bytes([1; 16]),
                aos_sandbox_core::IncarnationId::from_bytes([2; 16]),
                aos_sandbox_core::AssignmentEpoch::new(1),
                aos_sandbox_core::DesiredGeneration::new(1),
                ObjectDigest::from_bytes([3; 32]),
            )
            .unwrap(),
            request_id: [4; 16],
            request_body: b"exact body",
            descriptor_count: 4,
            verb: BrokerVerb::HostPrepareFuseWorkerSession,
            target: BrokerGrantTarget::Resource(
                aos_sandbox_core::BrokerResourceHandle::from_bytes([5; 32]).unwrap(),
            ),
            argument_commitment: BrokerArgumentCommitment::for_canonical_bytes(b"exact semantics"),
            request_deadline_boottime_nanoseconds: 100,
        };

        assert!(is_host_fuse_worker_admission(&original));
        for case in 0..8 {
            let mut changed = original;
            match case {
                0 => changed.audience = BrokerAudience::Mount,
                1 => changed.protocol = ProtocolId::MountBroker,
                2 => changed.protocol_version = ProtocolVersion::new(1, 1),
                3 => changed.verb = BrokerVerb::HostObserve,
                4 => changed.target = BrokerGrantTarget::Assignment,
                5 => changed.descriptor_count = 3,
                6 => changed.descriptor_count = 5,
                7 => changed.request_body = &[1; 4097],
                _ => unreachable!(),
            }
            assert!(
                !is_host_fuse_worker_admission(&changed),
                "substitution {case}"
            );
        }
    }

    #[test]
    fn fuse_signed_admission_is_only_the_exact_purpose_fifty_seven_profile() {
        let original = AdmissionRequest {
            audience: BrokerAudience::Mount,
            protocol: ProtocolId::MountFuseBroker,
            protocol_version: ProtocolVersion::new(3, 0),
            assignment: BrokerAssignment::new(
                aos_sandbox_core::SandboxId::from_bytes([1; 16]),
                aos_sandbox_core::IncarnationId::from_bytes([2; 16]),
                aos_sandbox_core::AssignmentEpoch::new(1),
                aos_sandbox_core::DesiredGeneration::new(1),
                aos_sandbox_core::ObjectDigest::from_bytes([3; 32]),
            )
            .unwrap(),
            request_id: [4; 16],
            request_body: b"exact body",
            descriptor_count: 0,
            verb: BrokerVerb::MountReserveFuseWorkerIntent,
            target: BrokerGrantTarget::Resource(
                aos_sandbox_core::BrokerResourceHandle::from_bytes([5; 32]).unwrap(),
            ),
            argument_commitment: aos_sandbox_core::BrokerArgumentCommitment::for_canonical_bytes(
                b"exact semantics",
            ),
            request_deadline_boottime_nanoseconds: 100,
        };

        assert!(is_fuse_intent_admission(&original));
        for case in 0..7 {
            let mut changed = original;
            match case {
                0 => changed.audience = BrokerAudience::Host,
                1 => changed.protocol = ProtocolId::MountBroker,
                2 => changed.protocol_version = ProtocolVersion::new(2, 0),
                3 => changed.protocol_version = ProtocolVersion::new(3, 1),
                4 => changed.verb = BrokerVerb::MountCreate,
                5 => changed.target = BrokerGrantTarget::Assignment,
                6 => changed.descriptor_count = 1,
                _ => unreachable!(),
            }
            assert!(!is_fuse_intent_admission(&changed), "substitution {case}");
        }
    }

    #[test]
    fn all_broker_domains_admit_minor_zero_signed_requests() {
        let cases = [
            (ProtocolId::StorageBroker, ProtocolVersion::new(1, 0)),
            (ProtocolId::HostBroker, ProtocolVersion::new(1, 0)),
            (ProtocolId::MountBroker, ProtocolVersion::new(2, 0)),
            (ProtocolId::NetworkBroker, ProtocolVersion::new(1, 0)),
        ];

        for (protocol, version) in cases {
            assert_eq!(
                supports_signed_admission(protocol, version),
                true,
                "unexpected signed-admission result for {protocol:?}"
            );
        }
        assert!(!supports_signed_admission(
            ProtocolId::MountFuseBroker,
            ProtocolVersion::new(3, 0)
        ));
    }

    #[test]
    fn online_keys_keep_seed_fence_and_effect_rows_disjoint() {
        let identity = [7; 16];
        let fence = BrokerAuthority::online_nix_fence_key(&identity);
        let effect = BrokerAuthority::online_nix_effect_key(&identity);
        let mut seed = [0; 24];
        seed[..8].copy_from_slice(b"AOSNXK01");
        seed[8..].copy_from_slice(&identity);

        assert_ne!(fence, effect);
        assert_ne!(fence, seed);
        assert_ne!(effect, seed);
        assert_eq!(&fence[8..], &identity);
        assert_eq!(&effect[8..], &identity);
        assert_ne!(BrokerAuthority::online_nix_fence_key(&[8; 16]), fence);
        assert_ne!(BrokerAuthority::online_nix_effect_key(&[8; 16]), effect);
    }
}

// The canonical comparison always checks the actual pair continuity first.
// Its request-local Expired disposition is comparison DATA here: the genuine
// verified Capture lifetime owner separately enforces its original ongoing
// BOOTTIME bound and both original signed WALL ceilings before any use.
fn require_effect_paired_clock_v3(
    effect: &BrokerEffectIntentV1,
    current_clock: &RawPairedClockSample,
) -> Result<(), BrokerAdmissionError> {
    BrokerEffectClockComparisonV3::from_effect(effect)
        .classify(current_clock)
        .map(|_| ())
}
