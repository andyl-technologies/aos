//! Protected dormant admission for one FUSE worker qualification.
//!
//! A broker-authored fixed record binds the complete connection authority to an
//! authenticated Mount-session outcome. New outcomes remain unusable until the
//! protected journal CAS and exact readback produce a committed advancement;
//! an exact protected replay reconstructs the same qualification without a
//! write. Nothing here opens FUSE, installs callbacks, or advertises features.
//!
//! The canonical protected companion has this fixed format:
//!
//! ```text
//! AOSFQF01 || version:u16be=1 || reserved[6]=0 || request-id[16] ||
//! method:u8 || reserved[7]=0 || signed-request-digest[32] ||
//! qualification-omitted-outcome-projection[32] || peer-binding[32] ||
//! session-binding[32] || exact qualification facts[400] || signature[64]
//! ```

use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, CanonicalBrokerResponseEnvelopeV1,
    hello_message::BrokerMethod,
};
use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerOutcomeVerificationV1, ProtectedBrokerOutcomeAdmissionGateV1,
    ProtectedBrokerOutcomeAdmissionV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerOutcomePendingAdvancementV1,
};
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, CacheDomainId, IncarnationId, Revision, SandboxId, ViewId,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::authority::feature_set_commitment;
use super::{
    AuthenticatedConnectionJoin, ConnectionAuthorityError, ConnectionLease, DirectoryHandleLimits,
    FrozenFeatureSet, FuseCapabilities, InodeTableLimits, MetadataConnection, MountPolicy,
    PreparedFuseConnection, UserNamespaceIdentity, WorkerError, WorkerLimits,
};
use crate::{PreparedPresentation, ValidatedViewProjection};

const MAGIC: [u8; 8] = *b"AOSFQF01";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 568;
const RECORD_BYTES: usize = BODY_BYTES + 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos-filesystem-fuse-qualification-v1\0";

/// Reports malformed qualification, stale protected currentness, or worker admission failure.
#[derive(Debug, thiserror::Error)]
pub enum QualificationError {
    /// Kernel boot identity or monotonic time is unavailable or regressed.
    #[error("protected FUSE kernel clock is unavailable")]
    Clock,
    /// The fixed qualification record or its signature is invalid.
    #[error("protected FUSE qualification record is invalid")]
    InvalidRecord,
    /// The qualification does not match the protected Mount outcome or connection artifacts.
    #[error("protected FUSE qualification is stale")]
    Stale,
    /// Protected outcome admission or readback failed.
    #[error("protected FUSE qualification currentness failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    /// Exact connection authority admission failed.
    #[error("FUSE connection authority failed: {0}")]
    Authority(#[from] ConnectionAuthorityError),
}

/// Owns kernel boot identity and a nondecreasing `CLOCK_BOOTTIME` floor.
///
/// Callers can request no timestamp or boot identity. The owner samples both
/// from fixed kernel interfaces and rejects cold replay from another boot.
pub struct ProtectedFuseKernelClockV1 {
    boot_id: [u8; 16],
    floor_ns: u64,
}

impl ProtectedFuseKernelClockV1 {
    /// Opens the fixed kernel clock owner without activating a worker.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationError::Clock`] when the kernel boot identity or
    /// initial `CLOCK_BOOTTIME` sample is unavailable or malformed.
    pub fn open_fixed() -> Result<Self, QualificationError> {
        let boot_id = read_kernel_boot_id()?;
        let floor_ns = sample_kernel_boottime()?;
        Ok(Self { boot_id, floor_ns })
    }

    fn sample_for_boot(&mut self, expected_boot_id: [u8; 16]) -> Result<u64, QualificationError> {
        if expected_boot_id != self.boot_id || read_kernel_boot_id()? != self.boot_id {
            return Err(QualificationError::Clock);
        }
        let now = sample_kernel_boottime()?;
        if now < self.floor_ns {
            return Err(QualificationError::Clock);
        }
        self.floor_ns = now;
        Ok(now)
    }
}

/// Opaque authority for one exact, protected, broker-qualified connection.
///
/// It has no public scalar constructor. The only creation paths are confirmed
/// protected advancement and byte-exact protected replay.
pub struct ProtectedFuseConnectionQualification {
    facts: QualificationFacts,
    record_commitment: [u8; 32],
    currentness_owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
}

/// Retains a new qualification until its protected CAS is confirmed.
#[must_use = "confirm the protected CAS before preparing a worker"]
pub struct PendingFuseConnectionQualification {
    facts: QualificationFacts,
    record_commitment: [u8; 32],
    binding: AdvancementBinding,
}

/// Classifies protected qualification admission as new progress or exact recovery.
#[must_use = "persist new progress or retain exact replay evidence"]
pub enum QualificationAdmission {
    /// The record is authenticated but cannot authorize a worker before CAS/readback.
    New {
        /// Opaque pending qualification.
        pending: PendingFuseConnectionQualification,
        /// Protected journal replacement and CAS target.
        advancement: ProtectedBrokerOutcomePendingAdvancementV1,
    },
    /// The terminal outcome was recovered byte for byte without a new write.
    ExactReplay {
        /// Recovered opaque qualification.
        qualification: ProtectedFuseConnectionQualification,
    },
}

/// Authenticates one canonical qualification against a protected Mount outcome.
///
/// `canonical_record` is a fixed 632-byte companion signed by the active broker
/// outcome key. It cross-links the qualification-omitted canonical outcome
/// projection and protected gate. Empirical qualification remains deferred.
///
/// # Errors
///
/// Returns [`QualificationError`] for malformed bytes, an inactive or weak key,
/// a non-Mount-Apply gate, a failed signature, mismatched protected bindings, or
/// protected outcome admission failure.
pub fn admit_fuse_connection_qualification(
    verification: DormantBrokerOutcomeVerificationV1,
    canonical_record: &[u8],
    outcome: &CanonicalBrokerResponseEnvelopeV1,
) -> Result<QualificationAdmission, QualificationError> {
    let (gate, context) = verification.into_parts();
    let signed = SignedQualification::decode(canonical_record)?;
    let qualification_record_commitment = qualification_record_commitment(canonical_record);
    let protected_context = context.protected_context_digest();
    if context.protocol() != BrokerSessionProtocolV1::Mount
        || gate.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY
        || gate.protected_bindings().protected_context() != protected_context
    {
        return Err(QualificationError::Stale);
    }
    let key = context
        .keys()
        .iter()
        .find(|key| {
            key.signer().usage() == BrokerSessionKeyUsageV1::BrokerOutcome
                && key.signer() == outcome.signed_artifact().signer()
                && key.is_active()
        })
        .ok_or(QualificationError::InvalidRecord)?;
    let verifying_key = VerifyingKey::from_bytes(key.public_key())
        .map_err(|_| QualificationError::InvalidRecord)?;
    if verifying_key.is_weak() {
        return Err(QualificationError::InvalidRecord);
    }
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + BODY_BYTES);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&signed.body);
    verifying_key
        .verify_strict(&message, &Signature::from_bytes(&signed.signature))
        .map_err(|_| QualificationError::InvalidRecord)?;

    let subject = outcome.signed_artifact().subject();
    if signed.request_id != gate.request_id()
        || signed.method != gate.method() as u8
        || signed.request_digest != gate.signed_request_digest()
        || signed.peer_binding != gate.peer_binding().digest()
        || signed.session_binding != gate.session_binding()
        || signed.request_id != subject.request_id()
        || signed.request_digest != subject.signed_request_digest()
        || signed.session_binding != subject.session_binding()
    {
        return Err(QualificationError::Stale);
    }

    let gate_binding = GateBinding::from_gate(&gate);
    match gate.admit_qualified_mount_outcome(
        outcome,
        qualification_record_commitment,
        signed.outcome_projection_commitment,
    )? {
        ProtectedBrokerOutcomeAdmissionV1::New { advancement } => {
            let binding = AdvancementBinding::from_pending(
                &advancement,
                gate_binding,
                qualification_record_commitment,
            )?;
            Ok(QualificationAdmission::New {
                pending: PendingFuseConnectionQualification {
                    facts: signed.facts,
                    record_commitment: qualification_record_commitment,
                    binding,
                },
                advancement,
            })
        }
        ProtectedBrokerOutcomeAdmissionV1::ExactReplay { replay } => {
            if replay.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                || replay.request_id() != signed.request_id
                || replay.signed_request_digest() != signed.request_digest
                || replay.session_binding() != signed.session_binding
                || replay.peer_binding().digest() != signed.peer_binding
                || replay.exact_packet() != outcome.encoded_bytes()
                || replay.qualification_record_commitment() != Some(qualification_record_commitment)
            {
                return Err(QualificationError::Stale);
            }
            Ok(QualificationAdmission::ExactReplay {
                qualification: ProtectedFuseConnectionQualification {
                    facts: signed.facts,
                    record_commitment: qualification_record_commitment,
                    currentness_owner: replay.into_currentness_owner(),
                },
            })
        }
    }
}

impl PendingFuseConnectionQualification {
    /// Unlocks this qualification after exact protected CAS readback.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationError::Stale`] unless `advancement` is the unique
    /// committed successor paired with this pending record.
    pub fn confirm(
        self,
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<ProtectedFuseConnectionQualification, QualificationError> {
        self.binding.validate(&advancement)?;
        Ok(ProtectedFuseConnectionQualification {
            facts: self.facts,
            record_commitment: self.record_commitment,
            currentness_owner: advancement.into_currentness_owner(),
        })
    }
}

/// Retains exact prepared authority until a borrow-scoped worker is created.
pub struct DormantFilesystemWorkerPreparation<
    'current,
    'clock,
    'projection,
    'index,
    'bytes,
    'presentation,
    'plan,
> {
    _protected_current:
        aos_sandbox_broker_session_security::ProtectedBrokerOutcomeCurrentV1<'current>,
    _kernel_clock: &'clock mut ProtectedFuseKernelClockV1,
    prepared: PreparedFuseConnection<'projection, 'index, 'bytes, 'presentation, 'plan>,
}

impl<'current, 'clock, 'projection, 'index, 'bytes, 'presentation, 'plan>
    DormantFilesystemWorkerPreparation<
        'current,
        'clock,
        'projection,
        'index,
        'bytes,
        'presentation,
        'plan,
    >
{
    /// Consumes one protected qualification into exact prepared authority.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationError`] when the protected facts disagree with the
    /// projection, presentation, closed feature registry, lease, or mount policy.
    pub fn from_protected_qualification(
        session: &'current mut DormantAuthenticatedBrokerSessionV1,
        kernel_clock: &'clock mut ProtectedFuseKernelClockV1,
        projection: &'projection ValidatedViewProjection<'index, 'bytes>,
        presentation: &'presentation PreparedPresentation<'index, 'bytes, 'plan>,
        qualification: ProtectedFuseConnectionQualification,
    ) -> Result<Self, QualificationError> {
        let ProtectedFuseConnectionQualification {
            facts,
            record_commitment,
            currentness_owner,
        } = qualification;
        let protected_current = session.revalidate_broker_outcome(currentness_owner)?;
        let mut features = Vec::new();
        features.push(projection.view().identity_presentation().clone());
        features.extend(projection.view().required_features().iter().cloned());
        features.extend(
            projection
                .profiles()
                .iter()
                .map(|profile| profile.profile().clone()),
        );
        features.sort();
        features.dedup();
        aos_sandbox_core::validate_required_features(&features)
            .map_err(|_| QualificationError::InvalidRecord)?;
        let commitment = feature_set_commitment(&features);
        if commitment != facts.feature_set_commitment {
            return Err(QualificationError::Stale);
        }
        let features = FrozenFeatureSet::from_verified_registry(features, commitment)?;
        let lease = ConnectionLease::from_authenticated(
            facts.lease_identity,
            facts.lease_valid_from_ns,
            facts.lease_expires_at_ns,
        )
        .ok_or(QualificationError::InvalidRecord)?;
        let user_namespace = UserNamespaceIdentity::from_pinned(
            facts.user_namespace_device,
            facts.user_namespace_inode,
            facts.user_namespace_generation,
            facts.presentation_plan,
        )
        .ok_or(QualificationError::InvalidRecord)?;
        let authority = AuthenticatedConnectionJoin::from_verified_observations(
            facts.attachment,
            facts.sandbox,
            facts.incarnation,
            facts.assignment_epoch,
            facts.connection_generation,
            facts.attachment_generation,
            facts.presentation_generation,
            facts.expected_view,
            lease,
            facts.lease_holder,
            facts.lease_audience,
            facts.disclosure,
            facts.policy_digest,
            user_namespace,
            MountPolicy::from_observed(
                facts.default_permissions,
                facts.allow_other,
                facts.read_only,
                facts.no_suid,
                facts.no_dev,
                facts.no_exec,
            ),
            FuseCapabilities::from_qualified(
                facts.posix_acl,
                facts.extended_attributes,
                facts.sparse_files,
                facts.passthrough,
                facts.fallback_reads,
            ),
            facts.execute_authorized,
            facts.immutable_revision_verified,
            features,
            qualified_inode_entropy(
                facts.kernel_boot_id,
                facts.trusted_inode_entropy,
                record_commitment,
            ),
        )?;
        let before_prepare = kernel_clock.sample_for_boot(facts.kernel_boot_id)?;
        if !lease.contains(before_prepare) {
            return Err(QualificationError::Authority(
                ConnectionAuthorityError::Lease,
            ));
        }
        let prepared =
            PreparedFuseConnection::prepare(projection, presentation, before_prepare, &authority)?;
        let after_prepare = kernel_clock.sample_for_boot(facts.kernel_boot_id)?;
        if !lease.contains(after_prepare) {
            return Err(QualificationError::Authority(
                ConnectionAuthorityError::Lease,
            ));
        }

        Ok(Self {
            _protected_current: protected_current,
            _kernel_clock: kernel_clock,
            prepared,
        })
    }

    /// Creates an uninitialized worker without installing a transport or reducer.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError`] when bounded worker state cannot be allocated or branded.
    pub fn metadata_connection<'prepared>(
        &'prepared self,
        inode_limits: InodeTableLimits,
        directory_limits: DirectoryHandleLimits,
        worker_limits: WorkerLimits,
    ) -> Result<MetadataConnection<'prepared, 'index, 'bytes, 'plan>, WorkerError>
    where
        'projection: 'prepared,
        'presentation: 'prepared,
    {
        MetadataConnection::from_prepared(
            &self.prepared,
            inode_limits,
            directory_limits,
            worker_limits,
        )
    }
}

struct SignedQualification {
    body: Vec<u8>,
    signature: [u8; 64],
    request_id: [u8; 16],
    method: u8,
    request_digest: [u8; 32],
    outcome_projection_commitment: [u8; 32],
    peer_binding: [u8; 32],
    session_binding: [u8; 32],
    facts: QualificationFacts,
}

struct QualificationFacts {
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    connection_generation: u64,
    attachment_generation: Revision,
    presentation_generation: u64,
    expected_view: (ViewId, Revision),
    lease_identity: [u8; 16],
    lease_valid_from_ns: u64,
    lease_expires_at_ns: u64,
    lease_holder: [u8; 32],
    lease_audience: [u8; 32],
    disclosure: CacheDomain,
    policy_digest: [u8; 32],
    user_namespace_device: u64,
    user_namespace_inode: u64,
    user_namespace_generation: u64,
    presentation_plan: [u8; 32],
    kernel_boot_id: [u8; 16],
    default_permissions: bool,
    allow_other: bool,
    read_only: bool,
    no_suid: bool,
    no_dev: bool,
    no_exec: bool,
    posix_acl: bool,
    extended_attributes: bool,
    sparse_files: bool,
    passthrough: bool,
    fallback_reads: bool,
    execute_authorized: bool,
    immutable_revision_verified: bool,
    feature_set_commitment: [u8; 32],
    trusted_inode_entropy: [u8; 32],
}

impl SignedQualification {
    fn decode(bytes: &[u8]) -> Result<Self, QualificationError> {
        if bytes.len() != RECORD_BYTES {
            return Err(QualificationError::InvalidRecord);
        }
        let (body, signature) = bytes.split_at(BODY_BYTES);
        let mut cursor = Cursor::new(body);
        if cursor.array()? != MAGIC || cursor.u16()? != VERSION || cursor.array::<6>()? != [0; 6] {
            return Err(QualificationError::InvalidRecord);
        }
        let request_id = cursor.nonzero_array()?;
        let method = cursor.u8()?;
        if method == 0 || cursor.array::<7>()? != [0; 7] {
            return Err(QualificationError::InvalidRecord);
        }
        let request_digest = cursor.nonzero_array()?;
        let outcome_projection_commitment = cursor.nonzero_array()?;
        let peer_binding = cursor.nonzero_array()?;
        let session_binding = cursor.nonzero_array()?;
        let attachment = AttachmentId::from_bytes(cursor.nonzero_array()?);
        let sandbox = SandboxId::from_bytes(cursor.nonzero_array()?);
        let incarnation = IncarnationId::from_bytes(cursor.nonzero_array()?);
        let assignment_epoch = AssignmentEpoch::new(cursor.nonzero_u64()?);
        let connection_generation = cursor.nonzero_u64()?;
        let attachment_generation = Revision::new(cursor.nonzero_u64()?);
        let presentation_generation = cursor.nonzero_u64()?;
        let expected_view = (
            ViewId::from_bytes(cursor.nonzero_array()?),
            Revision::new(cursor.nonzero_u64()?),
        );
        let lease_identity = cursor.nonzero_array()?;
        let lease_valid_from_ns = cursor.u64()?;
        let lease_expires_at_ns = cursor.nonzero_u64()?;
        let lease_holder = cursor.nonzero_array()?;
        let lease_audience = cursor.nonzero_array()?;
        let disclosure_kind = match cursor.u8()? {
            0 => CacheDomainKind::Private,
            1 => CacheDomainKind::Project,
            2 => CacheDomainKind::TrustDomain,
            3 => CacheDomainKind::Public,
            _ => return Err(QualificationError::InvalidRecord),
        };
        if cursor.array::<7>()? != [0; 7] {
            return Err(QualificationError::InvalidRecord);
        }
        let disclosure = CacheDomain::new(
            disclosure_kind,
            CacheDomainId::from_bytes(cursor.nonzero_array()?),
        );
        let policy_digest = cursor.nonzero_array()?;
        let user_namespace_device = cursor.nonzero_u64()?;
        let user_namespace_inode = cursor.nonzero_u64()?;
        let user_namespace_generation = cursor.nonzero_u64()?;
        let presentation_plan = cursor.nonzero_array()?;
        let kernel_boot_id = cursor.nonzero_array()?;
        let mount = cursor.u8()?;
        let capabilities = cursor.u8()?;
        let decisions = cursor.u8()?;
        if mount & !0x3f != 0
            || capabilities & !0x1f != 0
            || decisions & !0x03 != 0
            || cursor.array::<5>()? != [0; 5]
        {
            return Err(QualificationError::InvalidRecord);
        }
        let feature_set_commitment = cursor.nonzero_array()?;
        let trusted_inode_entropy = cursor.nonzero_array()?;
        cursor.finish()?;
        Ok(Self {
            body: body.to_vec(),
            signature: signature
                .try_into()
                .map_err(|_| QualificationError::InvalidRecord)?,
            request_id,
            method,
            request_digest,
            outcome_projection_commitment,
            peer_binding,
            session_binding,
            facts: QualificationFacts {
                attachment,
                sandbox,
                incarnation,
                assignment_epoch,
                connection_generation,
                attachment_generation,
                presentation_generation,
                expected_view,
                lease_identity,
                lease_valid_from_ns,
                lease_expires_at_ns,
                lease_holder,
                lease_audience,
                disclosure,
                policy_digest,
                user_namespace_device,
                user_namespace_inode,
                user_namespace_generation,
                presentation_plan,
                kernel_boot_id,
                default_permissions: mount & 1 != 0,
                allow_other: mount & 2 != 0,
                read_only: mount & 4 != 0,
                no_suid: mount & 8 != 0,
                no_dev: mount & 16 != 0,
                no_exec: mount & 32 != 0,
                posix_acl: capabilities & 1 != 0,
                extended_attributes: capabilities & 2 != 0,
                sparse_files: capabilities & 4 != 0,
                passthrough: capabilities & 8 != 0,
                fallback_reads: capabilities & 16 != 0,
                execute_authorized: decisions & 1 != 0,
                immutable_revision_verified: decisions & 2 != 0,
                feature_set_commitment,
                trusted_inode_entropy,
            },
        })
    }
}

struct AdvancementBinding {
    method: BrokerMethod,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    client_sequence: u64,
    session_binding: [u8; 32],
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
    expected_commitment: [u8; 32],
    replacement_head: [u8; 32],
    admission_commitment: [u8; 32],
    qualification_record_commitment: [u8; 32],
}

impl AdvancementBinding {
    fn from_pending(
        value: &ProtectedBrokerOutcomePendingAdvancementV1,
        gate: GateBinding,
        qualification_record_commitment: [u8; 32],
    ) -> Result<Self, QualificationError> {
        if value.qualification_record_commitment() != Some(qualification_record_commitment) {
            return Err(QualificationError::Stale);
        }
        let cas = value.durable_cas();
        Ok(Self {
            method: gate.method,
            request_id: gate.request_id,
            request_digest: gate.request_digest,
            client_sequence: gate.client_sequence,
            session_binding: gate.session_binding,
            expected_generation: cas.expected_generation(),
            expected_head: cas.expected_head(),
            expected_revision: cas.expected_revision(),
            expected_commitment: cas.expected_commitment(),
            replacement_head: cas.replacement_head(),
            admission_commitment: value.admission_commitment(),
            qualification_record_commitment,
        })
    }

    fn validate(
        &self,
        value: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<(), QualificationError> {
        if value.method() != self.method
            || value.request_id() != self.request_id
            || value.signed_request_digest() != self.request_digest
            || value.client_sequence() != self.client_sequence
            || value.session_binding() != self.session_binding
            || value.expected_generation() != self.expected_generation
            || value.expected_head() != self.expected_head
            || value.expected_revision() != self.expected_revision
            || value.expected_commitment() != self.expected_commitment
            || value.replacement_head() != self.replacement_head
            || value.admission_commitment() != self.admission_commitment
            || value.qualification_record_commitment() != Some(self.qualification_record_commitment)
        {
            return Err(QualificationError::Stale);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct GateBinding {
    method: BrokerMethod,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    client_sequence: u64,
    session_binding: [u8; 32],
}

impl GateBinding {
    fn from_gate(value: &ProtectedBrokerOutcomeAdmissionGateV1) -> Self {
        Self {
            method: value.method(),
            request_id: value.request_id(),
            request_digest: value.signed_request_digest(),
            client_sequence: value.client_sequence(),
            session_binding: value.session_binding(),
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QualificationError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(QualificationError::InvalidRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(QualificationError::InvalidRecord)?
            .try_into()
            .map_err(|_| QualificationError::InvalidRecord)?;
        self.offset = end;
        Ok(value)
    }

    fn nonzero_array<const N: usize>(&mut self) -> Result<[u8; N], QualificationError> {
        let value = self.array()?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(QualificationError::InvalidRecord);
        }
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, QualificationError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, QualificationError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, QualificationError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn nonzero_u64(&mut self) -> Result<u64, QualificationError> {
        let value = self.u64()?;
        if value == 0 {
            return Err(QualificationError::InvalidRecord);
        }
        Ok(value)
    }

    fn finish(self) -> Result<(), QualificationError> {
        (self.offset == self.bytes.len())
            .then_some(())
            .ok_or(QualificationError::InvalidRecord)
    }
}

fn qualification_record_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-filesystem-fuse-qualification-record-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn qualified_inode_entropy(
    kernel_boot_id: [u8; 16],
    trusted_inode_entropy: [u8; 32],
    record_commitment: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-filesystem-fuse-qualified-inode-entropy-v1\0");
    digest.update(kernel_boot_id);
    digest.update(trusted_inode_entropy);
    digest.update(record_commitment);
    digest.finalize().into()
}

fn read_kernel_boot_id() -> Result<[u8; 16], QualificationError> {
    aos_sandbox_linux::boot::KernelBootId::current()
        .map(aos_sandbox_linux::boot::KernelBootId::into_bytes)
        .map_err(|_| QualificationError::Clock)
}

fn sample_kernel_boottime() -> Result<u64, QualificationError> {
    let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(sample.tv_sec).map_err(|_| QualificationError::Clock)?;
    let nanoseconds = u64::try_from(sample.tv_nsec).map_err(|_| QualificationError::Clock)?;
    if nanoseconds >= 1_000_000_000 {
        return Err(QualificationError::Clock);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(QualificationError::Clock)
}
