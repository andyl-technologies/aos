//! Host adapter for shared signed-plan and ownership-lease admission.

use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV1, BrokerLocalRecordDomain,
    ProtectedBrokerAuthorityConfiguration, ProtectedBrokerPublicCredentialRole,
    ProtectedBrokerPublicCredentialSnapshot, ProtectedBrokerPublicCredentials, RecordNamespace,
    VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerGrant, BrokerPlanTrustAnchor, NodeId,
    OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;
use aos_sandbox_protocol::semantics::CanonicalHostAttachGateSemanticsV1;
use aos_sandbox_protocol::semantics::CanonicalHostExecutionArgumentSemanticsV1;
use aos_sandbox_protocol::semantics::CanonicalHostExecutionSemanticsV1;
use aos_sandbox_protocol::semantics::CanonicalHostOutputSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

use super::semantics_v1::canonical_host_semantics_v1;

type RevalidatedGuardianCredentials<'a> = [(
    ProtectedBrokerPublicCredentialRole,
    BorrowedFd<'a>,
    ProtectedBrokerPublicCredentialSnapshot,
); 6];

const HOST_EXECUTION_RECORD_DOMAIN: [u8; 16] = *b"AOSHOSTEXECV0001";
const BROKER_OUTCOME_VERIFIER_FILE: &str = "broker-outcome-verifier-v1";
const BROKER_OUTCOME_VERIFIER_BYTES: usize =
    aos_sandbox_protocol::BROKER_TERMINAL_COMMIT_VERIFIER_BYTES;

struct ProtectedTerminalVerifierV1 {
    descriptor: OwnedFd,
    verifier: aos_sandbox_protocol::BrokerTerminalCommitVerifierV1,
    metadata: TerminalVerifierMetadataV1,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalVerifierMetadataV1 {
    device: u64,
    inode: u64,
    mode: u32,
    links: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modified_seconds: u64,
    modified_nanoseconds: u32,
    changed_seconds: u64,
    changed_nanoseconds: u32,
}

/// Host-audience alias for shared admission failures.
pub type HostAdmissionError = BrokerAdmissionError;
/// Host-audience alias for protected authority configuration failures.
pub type HostAuthorityConfigError = BrokerAuthorityConfigError;
/// Exact authenticated records the host broker commits atomically.
pub(crate) type VerifiedHostAdmissionV1 = VerifiedBrokerAdmission;

/// Owns protected host-audience trust and durable authentication state.
pub struct HostAuthorityV1 {
    authority: BrokerAuthority,
    public_credentials: Option<ProtectedBrokerPublicCredentials>,
    terminal_verifier: Option<ProtectedTerminalVerifierV1>,
}

impl HostAuthorityV1 {
    /// Constructs host authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`HostAdmissionError::InvalidConfiguration`] for invalid local
    /// node or journal-key configuration.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, HostAdmissionError> {
        let authority = BrokerAuthority::new(
            BrokerDomain::Host,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )?;
        Ok(Self {
            authority,
            public_credentials: None,
            terminal_verifier: None,
        })
    }

    /// Loads host authority from a protected systemd credential directory.
    ///
    /// # Errors
    ///
    /// Returns [`HostAuthorityConfigError`] for any missing, insecure,
    /// malformed, oversized, or inconsistent credential.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, HostAuthorityConfigError> {
        let path = path.as_ref();
        let configuration = ProtectedBrokerAuthorityConfiguration::from_protected_directory(
            path,
            BrokerDomain::Host,
        )?;
        let (authority, public_credentials) = configuration.into_authority_and_public_credentials();
        let terminal_verifier = load_optional_terminal_verifier(path)?;
        Ok(Self {
            authority,
            public_credentials: Some(public_credentials),
            terminal_verifier,
        })
    }

    /// Returns the fixed protected broker-outcome verifier commitment.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the verifier credential is absent,
    /// replaced, modified, or no longer has its protected shape.
    pub(crate) fn terminal_verifier_commitment(
        &self,
    ) -> Result<[u8; 32], HostAuthorityConfigError> {
        let protected =
            self.terminal_verifier
                .as_ref()
                .ok_or(HostAuthorityConfigError::Invalid(
                    BROKER_OUTCOME_VERIFIER_FILE,
                ))?;
        revalidate_terminal_verifier(protected)?;
        Ok(protected.verifier.commitment())
    }

    /// Revalidates and borrows the protected public Guardian credentials.
    ///
    /// Authorities built directly with [`Self::new`] have no descriptor
    /// custody and return `Ok(None)`. A protected-directory authority returns
    /// all six roles and their original non-secret snapshots only while every
    /// descriptor still matches the exact bytes and metadata used to construct
    /// the authority.
    ///
    /// # Errors
    ///
    /// Returns [`HostAuthorityConfigError`] after any in-place rewrite,
    /// replacement, unlink, permission change, or descriptor read failure.
    pub(crate) fn revalidated_guardian_credentials(
        &self,
    ) -> Result<Option<RevalidatedGuardianCredentials<'_>>, HostAuthorityConfigError> {
        self.public_credentials
            .as_ref()
            .map(ProtectedBrokerPublicCredentials::revalidated_descriptor_evidence)
            .transpose()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter receives one closed host request plus protected context"
    )]
    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedRuntimeRequest,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics = canonical_host_semantics_v1(request)
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        self.authority.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version,
                assignment: request_assignment(request)?,
                request_id: *request.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: request
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies a protected-runtime execution grant against the shared fence.
    ///
    /// The returned admission is still pending. The Host broker must atomically
    /// retain its sealed fence and effect in HostState before the runtime owner
    /// may commit an execution effect.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_execution(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        semantics: CanonicalHostExecutionSemanticsV1,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_execution(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies a provisional output reserve or query against the shared Host fence.
    ///
    /// # Errors
    ///
    /// Rejects a foreign signer, verb, assignment, exact request semantic,
    /// lease, deadline, or protected base-fence mismatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_output(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        semantics: CanonicalHostOutputSemanticsV1,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_output(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies a method-37/38 Host argument grant against the shared fence.
    ///
    /// # Errors
    ///
    /// Rejects a foreign signer, verb, assignment, exact AOSCIA02 semantic,
    /// current lease, deadline, or protected base-fence mismatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_argument(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        semantics: CanonicalHostExecutionArgumentSemanticsV1,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_argument(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies one exact ATTACH plan and lease against the shared Host fence.
    ///
    /// # Errors
    ///
    /// Rejects a wrong semantic verb, signer, current assignment, lease, or
    /// protected base fence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_attach_gate(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        semantics: CanonicalHostAttachGateSemanticsV1,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_attach_gate(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies a read-only attach query's distinct plan and current lease.
    ///
    /// # Errors
    ///
    /// Rejects a stale or unauthenticated signed plan/lease or base fence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_attach_query(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        semantics: CanonicalHostAttachGateSemanticsV1,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_attach_query(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Verifies the exact read-only Host output readback grant and current lease.
    ///
    /// # Errors
    ///
    /// Rejects a changed Controller plan, assignment, request, lease, or
    /// protected Host base fence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_storage_output_readback(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        request_body: &[u8],
        grant: &BrokerGrant,
        deadline_boottime_nanoseconds: u64,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        self.authority.admit_host_storage_output_readback(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id,
                request_body,
                descriptor_count: 0,
                verb: grant.verb(),
                target: grant.target(),
                argument_commitment: grant.argument_commitment(),
                request_deadline_boottime_nanoseconds: deadline_boottime_nanoseconds,
            },
            current_clock,
            prior_fence,
        )
    }

    /// Advances the stable Host base-plan fence with a verified exact grant's lease.
    pub(crate) fn advance_base_execution_fence(
        &self,
        sandbox_id: &[u8; 16],
        prior_base: &[u8],
        admitted: &VerifiedHostAdmissionV1,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        let base = self.open_fence(sandbox_id, prior_base)?;
        if base.assignment() != admitted.fence.assignment()
            || base.node() != admitted.fence.node()
            || base.ownership_authority() != admitted.fence.ownership_authority()
        {
            return Err(HostAdmissionError::FenceRejected);
        }
        let advanced = BrokerAuthorizationFenceV1::new(
            base.assignment(),
            base.node(),
            base.plan_digest(),
            base.plan_expires_seconds(),
            base.ownership_authority().clone(),
            admitted.fence.local_lease_record().clone(),
        )
        .map_err(|_| HostAdmissionError::FenceRejected)?;
        self.seal_fence(sandbox_id, &advanced)
    }

    pub(crate) fn open_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV1, HostAdmissionError> {
        self.authority.open_effect(request_id, bytes)
    }

    /// Checks the exact signed payload-scope query against live ownership.
    ///
    /// The current assignment plan must contain this query's distinct
    /// argument commitment; an ordinary runtime-observe grant is insufficient.
    pub(crate) fn admit_payload_scope(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::payload_scope::ValidatedPayloadScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics =
            aos_sandbox_protocol::semantics::payload_scope::canonical_payload_scope_semantics_v1(
                request,
            )
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        let fence = request.fence();
        let assignment = fence
            .broker_assignment()
            .map_err(|_| HostAdmissionError::RequestMismatch)?;

        self.authority.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id: *request.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: request
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            Some(prior_fence),
        )
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, HostAdmissionError> {
        self.authority.open_fence(sandbox_id, bytes)
    }

    pub(crate) fn check_current_fence(
        &self,
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<(), HostAdmissionError> {
        self.authority.check_current_fence(fence)
    }

    /// Admits only the distinct exact-scope RootMount observation commitment.
    pub(crate) fn admit_mount_scope(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::mount_scope::ValidatedMountScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics =
            aos_sandbox_protocol::semantics::mount_scope::canonical_mount_scope_semantics_v1(
                request,
            )
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        self.admit_exact_mount_scope(
            artifacts,
            request,
            request_body,
            current_clock,
            prior_fence,
            semantics,
        )
    }

    /// Admits only the separate method-45 Host namespace-identity purpose.
    pub(crate) fn admit_mount_scope_identity(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::mount_scope::ValidatedMountScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics = aos_sandbox_protocol::semantics::mount_scope::
            canonical_mount_scope_identity_semantics_v1(request)
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        self.admit_exact_mount_scope(
            artifacts,
            request,
            request_body,
            current_clock,
            prior_fence,
            semantics,
        )
    }

    fn admit_exact_mount_scope(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::mount_scope::ValidatedMountScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
        semantics: aos_sandbox_protocol::semantics::mount_scope::CanonicalMountScopeSemanticsV1,
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let fence = request.fence();
        let assignment = fence
            .broker_assignment()
            .map_err(|_| HostAdmissionError::RequestMismatch)?;

        self.authority.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id: *request.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: request
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            Some(prior_fence),
        )
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV1,
        trusted_clock: &mut F,
    ) -> Result<(), HostAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, HostAdmissionError>,
    {
        self.authority.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &aos_sandbox_broker::BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.authority.seal_fence(sandbox_id, fence)
    }

    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV1,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.authority.seal_effect(request_id, effect)
    }

    /// Authenticates one Host execution payload at its exact request location.
    pub(crate) fn seal_execution_record(
        &self,
        request_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<Vec<u8>, HostAdmissionError> {
        if request_id == &[0; 16] || payload.is_empty() {
            return Err(HostAdmissionError::FenceRejected);
        }
        self.authority.seal_local_record(
            RecordNamespace::HostExecution,
            request_id,
            execution_record_domain()?,
            payload,
        )
    }

    /// Authenticates one exact request-keyed Host execution record.
    pub(crate) fn open_execution_record<'a>(
        &self,
        request_id: &[u8; 16],
        bytes: &'a [u8],
    ) -> Result<&'a [u8], HostAdmissionError> {
        if request_id == &[0; 16] {
            return Err(HostAdmissionError::FenceRejected);
        }
        let payload = self.authority.open_local_record(
            RecordNamespace::HostExecution,
            request_id,
            execution_record_domain()?,
            bytes,
        )?;
        if payload.is_empty() {
            return Err(HostAdmissionError::FenceRejected);
        }
        Ok(payload)
    }
}

fn execution_record_domain() -> Result<BrokerLocalRecordDomain, HostAdmissionError> {
    BrokerLocalRecordDomain::new(HOST_EXECUTION_RECORD_DOMAIN)
        .map_err(|_| HostAdmissionError::InvalidConfiguration)
}

fn request_assignment(
    request: &ValidatedRuntimeRequest,
) -> Result<BrokerAssignment, HostAdmissionError> {
    request
        .fence()
        .broker_assignment()
        .map_err(|_| HostAdmissionError::RequestMismatch)
}

fn load_optional_terminal_verifier(
    path: &Path,
) -> Result<Option<ProtectedTerminalVerifierV1>, HostAuthorityConfigError> {
    let directory = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| terminal_verifier_filesystem("directory", source))?;
    let directory_metadata =
        fstat(&directory).map_err(|source| terminal_verifier_filesystem("directory", source))?;
    if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory
        || directory_metadata.st_uid != 0
        || directory_metadata.st_mode & 0o022 != 0
    {
        return Err(HostAuthorityConfigError::Invalid("directory"));
    }
    let descriptor = match openat(
        &directory,
        BROKER_OUTCOME_VERIFIER_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => {
            return Err(terminal_verifier_filesystem(
                BROKER_OUTCOME_VERIFIER_FILE,
                source,
            ));
        }
    };
    let initial = terminal_verifier_metadata(&descriptor)?;
    let file = File::from(descriptor);
    let mut bytes = [0_u8; BROKER_OUTCOME_VERIFIER_BYTES];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|source| HostAuthorityConfigError::Filesystem {
            object: BROKER_OUTCOME_VERIFIER_FILE,
            source,
        })?;
    let mut extra = [0_u8; 1];
    if file
        .read_at(&mut extra, BROKER_OUTCOME_VERIFIER_BYTES as u64)
        .map_err(|source| HostAuthorityConfigError::Filesystem {
            object: BROKER_OUTCOME_VERIFIER_FILE,
            source,
        })?
        != 0
    {
        return Err(HostAuthorityConfigError::Invalid(
            BROKER_OUTCOME_VERIFIER_FILE,
        ));
    }
    let mut repeated_bytes = [0_u8; BROKER_OUTCOME_VERIFIER_BYTES];
    file.read_exact_at(&mut repeated_bytes, 0)
        .map_err(|source| HostAuthorityConfigError::Filesystem {
            object: BROKER_OUTCOME_VERIFIER_FILE,
            source,
        })?;
    let descriptor = OwnedFd::from(file);
    let repeated = terminal_verifier_metadata(&descriptor)?;
    if initial != repeated || bytes != repeated_bytes {
        return Err(HostAuthorityConfigError::Invalid(
            BROKER_OUTCOME_VERIFIER_FILE,
        ));
    }
    let verifier = aos_sandbox_protocol::BrokerTerminalCommitVerifierV1::decode(&bytes).ok_or(
        HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE),
    )?;
    Ok(Some(ProtectedTerminalVerifierV1 {
        descriptor,
        verifier,
        metadata: initial,
        digest: Sha256::digest(bytes).into(),
    }))
}

fn revalidate_terminal_verifier(
    protected: &ProtectedTerminalVerifierV1,
) -> Result<(), HostAuthorityConfigError> {
    if terminal_verifier_metadata(&protected.descriptor)? != protected.metadata {
        return Err(HostAuthorityConfigError::Invalid(
            BROKER_OUTCOME_VERIFIER_FILE,
        ));
    }
    let file = File::from(protected.descriptor.try_clone().map_err(|source| {
        HostAuthorityConfigError::Filesystem {
            object: BROKER_OUTCOME_VERIFIER_FILE,
            source,
        }
    })?);
    let mut bytes = [0_u8; BROKER_OUTCOME_VERIFIER_BYTES];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|source| HostAuthorityConfigError::Filesystem {
            object: BROKER_OUTCOME_VERIFIER_FILE,
            source,
        })?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if terminal_verifier_metadata(&protected.descriptor)? != protected.metadata
        || digest != protected.digest
    {
        return Err(HostAuthorityConfigError::Invalid(
            BROKER_OUTCOME_VERIFIER_FILE,
        ));
    }
    Ok(())
}

fn terminal_verifier_metadata(
    descriptor: &OwnedFd,
) -> Result<TerminalVerifierMetadataV1, HostAuthorityConfigError> {
    let metadata = fstat(descriptor)
        .map_err(|source| terminal_verifier_filesystem(BROKER_OUTCOME_VERIFIER_FILE, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o400
        || metadata.st_size != BROKER_OUTCOME_VERIFIER_BYTES as i64
    {
        return Err(HostAuthorityConfigError::Invalid(
            BROKER_OUTCOME_VERIFIER_FILE,
        ));
    }
    Ok(TerminalVerifierMetadataV1 {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        mode: metadata.st_mode,
        links: u32::try_from(metadata.st_nlink)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        size: u64::try_from(metadata.st_size)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
        modified_seconds: u64::try_from(metadata.st_mtime)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
        modified_nanoseconds: u32::try_from(metadata.st_mtime_nsec)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
        changed_seconds: u64::try_from(metadata.st_ctime)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
        changed_nanoseconds: u32::try_from(metadata.st_ctime_nsec)
            .map_err(|_| HostAuthorityConfigError::Invalid(BROKER_OUTCOME_VERIFIER_FILE))?,
    })
}

fn terminal_verifier_filesystem(
    object: &'static str,
    source: rustix::io::Errno,
) -> HostAuthorityConfigError {
    HostAuthorityConfigError::Filesystem {
        object,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        DecodeLimits, MediaType, ObjectDigest, PortableMediaType, RevocationScopeId, TrustScopeId,
        descriptor_for_bytes,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn key_reference(
        name: &str,
        generation: u64,
        usage: KeyUsage,
        key: &SigningKey,
    ) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        key: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        let bytes =
            encode_trust_policy(&TrustPolicy::new(scope, purpose, vec![key], vec![]).unwrap());
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    fn authority() -> HostAuthorityV1 {
        let plan_key = SigningKey::from_bytes(&[11; 32]);
        let lease_key = SigningKey::from_bytes(&[12; 32]);
        let plan_scope = TrustScopeId::from_bytes([13; 16]);
        let lease_scope = TrustScopeId::from_bytes([14; 16]);
        let plan_signer = key_reference(
            "host-execution-plan",
            1,
            KeyUsage::BrokerAuthorization,
            &plan_key,
        );
        let lease_signer = key_reference(
            "host-execution-lease",
            1,
            KeyUsage::OwnershipLease,
            &lease_key,
        );
        let (plan_policy, plan_descriptor) = policy(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            plan_signer.clone(),
        );
        let (lease_policy, lease_descriptor) = policy(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            lease_signer.clone(),
        );
        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_policy,
            plan_descriptor,
            plan_scope,
            plan_signer,
            plan_key.verifying_key().to_bytes(),
            RevocationScopeId::from_bytes([15; 16]),
            DecodeLimits::default(),
        )
        .unwrap();
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy,
            lease_descriptor,
            lease_scope,
            lease_signer,
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();

        HostAuthorityV1::new(
            plan_anchor,
            lease_anchor,
            NodeId::from_bytes([16; 16]),
            [17; 16],
            [18; 32],
        )
        .unwrap()
    }

    #[test]
    fn direct_authority_has_no_protected_descriptor_custody() {
        assert!(
            authority()
                .revalidated_guardian_credentials()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn execution_record_is_bound_to_host_domain_and_request_location() {
        let authority = authority();
        let request_id = [21; 16];
        let sealed = authority
            .seal_execution_record(&request_id, b"host execution")
            .unwrap();

        assert_eq!(
            authority
                .open_execution_record(&request_id, &sealed)
                .unwrap(),
            b"host execution"
        );
        assert!(authority.open_execution_record(&[22; 16], &sealed).is_err());
        assert!(
            authority
                .authority
                .open_local_record(
                    RecordNamespace::HostExecution,
                    &request_id,
                    BrokerLocalRecordDomain::new(*b"AOSHOSTEXECV0002").unwrap(),
                    &sealed,
                )
                .is_err()
        );
    }

    #[test]
    fn execution_record_rejects_tampering_and_invalid_bounds() {
        let authority = authority();
        let request_id = [23; 16];
        let mut tampered = authority
            .seal_execution_record(&request_id, b"host execution")
            .unwrap();
        let final_byte = tampered.last_mut().unwrap();
        *final_byte ^= 1;

        assert!(
            authority
                .open_execution_record(&request_id, &tampered)
                .is_err()
        );
        assert!(
            authority
                .seal_execution_record(&[0; 16], b"payload")
                .is_err()
        );
        assert!(authority.seal_execution_record(&request_id, b"").is_err());
        assert!(
            authority
                .open_execution_record(&[0; 16], &tampered)
                .is_err()
        );
        assert!(
            authority
                .seal_execution_record(&request_id, &vec![1; 2 * 1024 * 1024])
                .is_err()
        );
    }
}
