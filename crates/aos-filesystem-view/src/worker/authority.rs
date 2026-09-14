//! Exact attachment and lease authority for one prospective FUSE connection.
//!
//! Construction joins portable View projection, presentation, attachment,
//! sandbox incarnation, assignment, namespace, mount policy, user namespace,
//! disclosure domain, and lease state. The resulting value is intentionally
//! opaque and cannot be reconstructed from a digest or caller-selected inode
//! hash key.

use aos_sandbox_core::model::CacheDomain;
use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, FeatureRef, IncarnationId, Revision, SandboxId, ViewId,
};
use sha2::{Digest, Sha256};

use crate::{
    DataError, DataOpenPolicy, DataPlane, DataPlaneLimits, DurableRegistrationRecord,
    DurableStateCodec, DurableStateError, DurableStateLimits, IndexContentView,
    PassthroughRegistrations, PreparedPresentation, RegistrationLimits, ValidatedViewProjection,
    WorkerLifecycle,
};

/// Holds the frozen, registry-qualified feature set of one worker executable.
pub struct FrozenFeatureSet {
    features: Vec<FeatureRef>,
    commitment: [u8; 32],
}

impl FrozenFeatureSet {
    pub(crate) fn from_verified_registry(
        features: Vec<FeatureRef>,
        commitment: [u8; 32],
    ) -> Result<Self, ConnectionAuthorityError> {
        if features.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ConnectionAuthorityError::Unsupported(
                "invalid frozen feature set",
            ));
        }
        let derived = feature_set_commitment(&features);
        if commitment == [0; 32] || commitment != derived {
            return Err(ConnectionAuthorityError::Unsupported(
                "frozen feature commitment mismatch",
            ));
        }
        Ok(Self {
            features,
            commitment: derived,
        })
    }

    fn supports(&self, feature: &FeatureRef) -> bool {
        self.features.binary_search(feature).is_ok()
    }
}

fn feature_set_commitment(features: &[FeatureRef]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-frozen-features-v1\0");
    hasher.update((features.len() as u64).to_be_bytes());
    for feature in features {
        hasher.update((feature.namespace().len() as u64).to_be_bytes());
        hasher.update(feature.namespace().as_bytes());
        hasher.update(feature.major().to_be_bytes());
        hasher.update(feature.minor().to_be_bytes());
    }
    hasher.finalize().into()
}

/// Identifies the pinned consumer user namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserNamespaceIdentity {
    /// Device number of the pinned namespace descriptor.
    device: u64,
    /// Inode number of the pinned namespace descriptor.
    inode: u64,
    /// Broker-observed namespace generation.
    generation: u64,
    /// Exact translation plan proven for this pinned namespace.
    presentation_plan: [u8; 32],
}

impl UserNamespaceIdentity {
    pub(crate) fn from_pinned(
        device: u64,
        inode: u64,
        generation: u64,
        presentation_plan: [u8; 32],
    ) -> Option<Self> {
        (device != 0 && inode != 0 && generation != 0 && presentation_plan != [0; 32]).then_some(
            Self {
                device,
                inode,
                generation,
                presentation_plan,
            },
        )
    }
}

/// Records mandatory immutable FUSE mount policy observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountPolicy {
    /// The mount enforces kernel DAC checks.
    default_permissions: bool,
    /// The connection accepts consumers other than the daemon credentials.
    allow_other: bool,
    /// The mount rejects writes.
    read_only: bool,
    /// The mount suppresses set-user/group-ID execution effects.
    no_suid: bool,
    /// The mount suppresses device-node interpretation.
    no_dev: bool,
    /// The mount rejects execution unless separately authorized.
    no_exec: bool,
}

impl MountPolicy {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_observed(
        default_permissions: bool,
        allow_other: bool,
        read_only: bool,
        no_suid: bool,
        no_dev: bool,
        no_exec: bool,
    ) -> Self {
        Self {
            default_permissions,
            allow_other,
            read_only,
            no_suid,
            no_dev,
            no_exec,
        }
    }
}

/// Records independently probed kernel and transport semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseCapabilities {
    /// Exact POSIX ACL negotiation and xattr representation passed its userns probe.
    posix_acl: bool,
    /// Extended-attribute callbacks preserve the portable xattr profile.
    extended_attributes: bool,
    /// Sparse allocation and `SEEK_HOLE` semantics are represented exactly.
    sparse_files: bool,
    /// Read-only backing-file passthrough is available.
    passthrough: bool,
    /// Bounded verified userspace reads are permitted by policy.
    fallback_reads: bool,
}

impl FuseCapabilities {
    pub(crate) const fn metadata_only() -> Self {
        Self {
            posix_acl: false,
            extended_attributes: false,
            sparse_files: false,
            passthrough: false,
            fallback_reads: false,
        }
    }

    pub(crate) const fn from_qualified(
        posix_acl: bool,
        extended_attributes: bool,
        sparse_files: bool,
        passthrough: bool,
        fallback_reads: bool,
    ) -> Self {
        Self {
            posix_acl,
            extended_attributes,
            sparse_files,
            passthrough,
            fallback_reads,
        }
    }
}

/// Binds one lease to an absolute monotonic-clock interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLease {
    /// Opaque lease identity bytes from the durable authority owner.
    identity: [u8; 16],
    /// First admitted monotonic nanosecond.
    valid_from_ns: u64,
    /// Exclusive final admitted monotonic nanosecond.
    expires_at_ns: u64,
}

impl ConnectionLease {
    pub(crate) fn from_authenticated(
        identity: [u8; 16],
        valid_from_ns: u64,
        expires_at_ns: u64,
    ) -> Option<Self> {
        (identity != [0; 16] && valid_from_ns < expires_at_ns).then_some(Self {
            identity,
            valid_from_ns,
            expires_at_ns,
        })
    }

    /// Reports whether an observation lies in the closed-open lease interval.
    #[must_use]
    pub const fn contains(self, monotonic_now_ns: u64) -> bool {
        monotonic_now_ns >= self.valid_from_ns && monotonic_now_ns < self.expires_at_ns
    }
}

/// Opaque result of joining authenticated broker, assignment, lease, and mount observations.
///
/// Only the authority-owning code in this crate can construct this value. In
/// particular, public callers cannot manufacture a connection from identity
/// scalars, digests, feature claims, or entropy bytes.
pub struct AuthenticatedConnectionJoin {
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    connection_generation: u64,
    attachment_generation: Revision,
    presentation_generation: u64,
    expected_view: (ViewId, Revision),
    lease: ConnectionLease,
    lease_holder: [u8; 32],
    lease_audience: [u8; 32],
    disclosure: CacheDomain,
    policy_digest: [u8; 32],
    user_namespace: UserNamespaceIdentity,
    mount_policy: MountPolicy,
    capabilities: FuseCapabilities,
    execute_authorized: bool,
    immutable_revision_verified: bool,
    features: FrozenFeatureSet,
    trusted_inode_entropy: [u8; 32],
}

impl AuthenticatedConnectionJoin {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_observations(
        attachment: AttachmentId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        connection_generation: u64,
        attachment_generation: Revision,
        presentation_generation: u64,
        expected_view: (ViewId, Revision),
        lease: ConnectionLease,
        lease_holder: [u8; 32],
        lease_audience: [u8; 32],
        disclosure: CacheDomain,
        policy_digest: [u8; 32],
        user_namespace: UserNamespaceIdentity,
        mount_policy: MountPolicy,
        capabilities: FuseCapabilities,
        execute_authorized: bool,
        immutable_revision_verified: bool,
        features: FrozenFeatureSet,
        trusted_inode_entropy: [u8; 32],
    ) -> Result<Self, ConnectionAuthorityError> {
        if attachment.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || connection_generation == 0
            || attachment_generation.get() == 0
            || presentation_generation == 0
            || expected_view.0.as_bytes() == &[0; 16]
            || expected_view.1.get() == 0
            || policy_digest == [0; 32]
            || lease_holder == [0; 32]
            || lease_audience == [0; 32]
        {
            return Err(ConnectionAuthorityError::InvalidIdentity);
        }
        if trusted_inode_entropy == [0; 32] {
            return Err(ConnectionAuthorityError::Entropy);
        }
        Ok(Self {
            attachment,
            sandbox,
            incarnation,
            assignment_epoch,
            connection_generation,
            attachment_generation,
            presentation_generation,
            expected_view,
            lease,
            lease_holder,
            lease_audience,
            disclosure,
            policy_digest,
            user_namespace,
            mount_policy,
            capabilities,
            execute_authorized,
            immutable_revision_verified,
            features,
            trusted_inode_entropy,
        })
    }
}

/// Reports failure to join exact connection authority.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionAuthorityError {
    /// A required identity, generation, or nonsecret commitment is zero.
    #[error("connection authority contains a sentinel identity or generation")]
    InvalidIdentity,
    /// Presentation and projection do not retain the same validated index.
    #[error("presentation and View projection index authorities differ")]
    IndexMismatch,
    /// Portable and requested View identity or disclosure bindings differ.
    #[error("View authority binding differs from its validated projection")]
    ViewMismatch,
    /// The mandatory immutable FUSE mount policy was not proven.
    #[error("mandatory immutable FUSE mount policy is absent")]
    MountPolicy,
    /// The lease is malformed or not currently live.
    #[error("FUSE connection lease is invalid or expired")]
    Lease,
    /// A portable semantic cannot be represented by the negotiated transport.
    #[error("FUSE connection cannot represent {0}")]
    Unsupported(&'static str),
    /// The trusted entropy source failed or returned the forbidden zero value.
    #[error("trusted FUSE connection entropy is unavailable")]
    Entropy,
    /// Data-plane limits could not be admitted.
    #[error("FUSE connection data-plane admission failed: {0}")]
    Data(#[from] DataError),
    /// Structural-index reauthentication failed during feature admission.
    #[error("FUSE connection feature admission failed integrity checks")]
    Integrity,
}

/// Proves the complete authority tuple for one unshared FUSE connection.
///
/// The private inode key is mixed with every binding but never exposed. This
/// value does not itself open `/dev/fuse`, register backing files, or activate
/// a worker; those effects require a broker-owned adapter.
pub struct PreparedFuseConnection<'projection, 'index, 'bytes, 'presentation, 'plan> {
    projection: &'projection ValidatedViewProjection<'index, 'bytes>,
    presentation: &'presentation PreparedPresentation<'index, 'bytes, 'plan>,
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    connection_generation: u64,
    attachment_generation: Revision,
    lease: ConnectionLease,
    disclosure: CacheDomain,
    policy_digest: [u8; 32],
    user_namespace: UserNamespaceIdentity,
    mount_policy: MountPolicy,
    capabilities: FuseCapabilities,
    execute_authorized: bool,
    immutable_revision_verified: bool,
    feature_set_commitment: [u8; 32],
    binding: [u8; 32],
    inode_key: [u8; 32],
}

impl<'projection, 'index, 'bytes, 'presentation, 'plan>
    PreparedFuseConnection<'projection, 'index, 'bytes, 'presentation, 'plan>
{
    /// Joins immutable projection and live attachment authority at one clock sample.
    ///
    /// The current metadata transport has no ACL/xattr/sparse callbacks. Even if
    /// a caller asserts those capability bits, admission rejects those semantics
    /// until a transport-specific constructor replaces this dormant source seam.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError`] for mismatched artifacts, identities,
    /// disclosure, mandatory flags, lease state, unsupported projected metadata,
    /// index corruption, or unavailable trusted entropy.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        projection: &'projection ValidatedViewProjection<'index, 'bytes>,
        presentation: &'presentation PreparedPresentation<'index, 'bytes, 'plan>,
        monotonic_now_ns: u64,
        authority: &AuthenticatedConnectionJoin,
    ) -> Result<Self, ConnectionAuthorityError> {
        if !std::ptr::eq(projection.index(), presentation.index())
            || projection.index().descriptor() != presentation.index().descriptor()
        {
            return Err(ConnectionAuthorityError::IndexMismatch);
        }
        if projection.view_identity() != authority.expected_view
            || projection.view().disclosure() != authority.disclosure
            || presentation.generation() != authority.presentation_generation
            || presentation.policy_digest() != authority.policy_digest
            || presentation.plan_digest() != authority.user_namespace.presentation_plan
        {
            return Err(ConnectionAuthorityError::ViewMismatch);
        }
        if authority.connection_generation == 0
            || authority.attachment_generation.get() == 0
            || authority.user_namespace.device == 0
            || authority.user_namespace.inode == 0
            || authority.user_namespace.generation == 0
        {
            return Err(ConnectionAuthorityError::ViewMismatch);
        }
        if !authority.mount_policy.default_permissions
            || !authority.mount_policy.allow_other
            || !authority.mount_policy.read_only
            || !authority.mount_policy.no_suid
            || !authority.mount_policy.no_dev
            || (!authority.mount_policy.no_exec
                && (!authority.execute_authorized || !authority.immutable_revision_verified))
        {
            return Err(ConnectionAuthorityError::MountPolicy);
        }
        if authority.lease.identity == [0; 16]
            || authority.lease.valid_from_ns >= authority.lease.expires_at_ns
            || !authority.lease.contains(monotonic_now_ns)
        {
            return Err(ConnectionAuthorityError::Lease);
        }

        // The installed V1 C ABI cannot preserve these observable semantics.
        // Claimed feature bits are not accepted as proof until a qualified ABI
        // constructor exists, so this scan is deliberately fail-closed.
        admit_current_transport(projection)?;
        if authority.capabilities.posix_acl
            || authority.capabilities.extended_attributes
            || authority.capabilities.sparse_files
        {
            return Err(ConnectionAuthorityError::Unsupported(
                "unqualified ACL, xattr, or sparse transport capability",
            ));
        }
        let feature_set_commitment = authority.features.commitment;
        if !authority
            .features
            .supports(projection.view().identity_presentation())
            || projection
                .view()
                .required_features()
                .iter()
                .any(|feature| !authority.features.supports(feature))
            || projection
                .profiles()
                .iter()
                .any(|profile| !authority.features.supports(profile.profile()))
        {
            return Err(ConnectionAuthorityError::Unsupported(
                "required View presentation feature",
            ));
        }

        let mut secret = authority.trusted_inode_entropy;
        let binding = authority_binding(
            projection,
            presentation,
            authority.attachment,
            authority.sandbox,
            authority.incarnation,
            authority.assignment_epoch,
            authority.connection_generation,
            authority.attachment_generation,
            authority.presentation_generation,
            authority.lease,
            authority.lease_holder,
            authority.lease_audience,
            authority.disclosure,
            authority.policy_digest,
            authority.user_namespace,
            authority.mount_policy,
            authority.capabilities,
            authority.execute_authorized,
            authority.immutable_revision_verified,
            feature_set_commitment,
        );
        let mut key_hasher = Sha256::new();
        key_hasher.update(b"aos-filesystem-inode-key-v1\0");
        key_hasher.update(secret);
        key_hasher.update(binding);
        let inode_key = key_hasher.finalize().into();
        secret.fill(0);

        Ok(Self {
            projection,
            presentation,
            attachment: authority.attachment,
            sandbox: authority.sandbox,
            incarnation: authority.incarnation,
            assignment_epoch: authority.assignment_epoch,
            connection_generation: authority.connection_generation,
            attachment_generation: authority.attachment_generation,
            lease: authority.lease,
            disclosure: authority.disclosure,
            policy_digest: authority.policy_digest,
            user_namespace: authority.user_namespace,
            mount_policy: authority.mount_policy,
            capabilities: authority.capabilities,
            execute_authorized: authority.execute_authorized,
            immutable_revision_verified: authority.immutable_revision_verified,
            feature_set_commitment,
            binding,
            inode_key,
        })
    }

    /// Returns the exact validated View projection.
    #[must_use]
    pub const fn projection(&self) -> &'projection ValidatedViewProjection<'index, 'bytes> {
        self.projection
    }

    /// Returns the exact prepared metadata presentation.
    #[must_use]
    pub const fn presentation(&self) -> &'presentation PreparedPresentation<'index, 'bytes, 'plan> {
        self.presentation
    }

    /// Returns attachment, sandbox, and incarnation identities.
    #[must_use]
    pub const fn consumer_identity(&self) -> (AttachmentId, SandboxId, IncarnationId) {
        (self.attachment, self.sandbox, self.incarnation)
    }

    /// Returns assignment, connection, and attachment generations.
    #[must_use]
    pub const fn generations(&self) -> (AssignmentEpoch, u64, Revision) {
        (
            self.assignment_epoch,
            self.connection_generation,
            self.attachment_generation,
        )
    }

    /// Returns the exact lease.
    #[must_use]
    pub const fn lease(&self) -> ConnectionLease {
        self.lease
    }

    /// Returns the exact cache-disclosure domain.
    #[must_use]
    pub const fn disclosure(&self) -> CacheDomain {
        self.disclosure
    }

    /// Returns the policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Returns the pinned user-namespace identity.
    #[must_use]
    pub const fn user_namespace(&self) -> UserNamespaceIdentity {
        self.user_namespace
    }

    /// Returns the qualified mount policy and capability profile.
    #[must_use]
    pub const fn transport_profile(&self) -> (MountPolicy, FuseCapabilities) {
        (self.mount_policy, self.capabilities)
    }

    /// Returns execute and immutable-revision proof decisions bound at admission.
    #[must_use]
    pub const fn execute_profile(&self) -> (bool, bool) {
        (self.execute_authorized, self.immutable_revision_verified)
    }

    /// Returns the closed worker feature-set commitment.
    #[must_use]
    pub const fn feature_set_commitment(&self) -> [u8; 32] {
        self.feature_set_commitment
    }

    /// Returns a non-authorizing audit commitment to every joined binding.
    #[must_use]
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Rechecks the lease before a new lookup or open is admitted.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError::Lease`] once the absolute lease is
    /// outside its valid interval. Existing handles require separate revocation.
    pub fn authorize_new_request(
        &self,
        monotonic_now_ns: u64,
    ) -> Result<(), ConnectionAuthorityError> {
        self.lease
            .contains(monotonic_now_ns)
            .then_some(())
            .ok_or(ConnectionAuthorityError::Lease)
    }

    /// Creates a data plane bound to this exact connection authority.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError::Unsupported`] when the requested
    /// disposition is absent from the qualified connection capabilities, or
    /// [`ConnectionAuthorityError::Data`] for invalid data-plane limits.
    pub fn prepare_data_plane(
        &self,
        limits: DataPlaneLimits,
        policy: DataOpenPolicy,
    ) -> Result<DataPlane, ConnectionAuthorityError> {
        let admitted = match policy {
            DataOpenPolicy::PassthroughRequired => self.capabilities.passthrough,
            DataOpenPolicy::PreferPassthrough => {
                self.capabilities.passthrough && self.capabilities.fallback_reads
            }
            DataOpenPolicy::FallbackOnly => self.capabilities.fallback_reads,
        };
        if !admitted {
            return Err(ConnectionAuthorityError::Unsupported(
                "requested data-plane disposition",
            ));
        }
        Ok(DataPlane::new(
            limits,
            policy,
            self.binding,
            self.lease.valid_from_ns,
            self.lease.expires_at_ns,
        )?)
    }

    /// Allocates durable passthrough-registration state for this connection.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError::Data`] when the registration bounds
    /// or exact preallocation cannot be admitted.
    pub fn prepare_passthrough_registrations(
        &self,
        limits: RegistrationLimits,
    ) -> Result<PassthroughRegistrations, ConnectionAuthorityError> {
        Ok(PassthroughRegistrations::new(self, limits)?)
    }

    /// Restores canonically decoded passthrough registrations for this connection.
    ///
    /// The caller remains responsible for authenticating and durably reading the
    /// journal bytes. Restoration rebinds every decoded record to this exact
    /// prepared connection and performs no backing-open or backing-close effect.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError::Data`] when a record is foreign,
    /// malformed, exceeds the supplied bounds, or exact preallocation fails.
    pub fn restore_passthrough_registrations(
        &self,
        limits: RegistrationLimits,
        records: &[DurableRegistrationRecord],
    ) -> Result<PassthroughRegistrations, ConnectionAuthorityError> {
        Ok(PassthroughRegistrations::restore(self, limits, records)?)
    }

    /// Creates the initial pure lifecycle reducer for this prepared connection.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAuthorityError::Integrity`] if the joined identities
    /// or immutable index/projection artifacts are not canonical.
    pub fn prepare_worker_lifecycle(&self) -> Result<WorkerLifecycle, ConnectionAuthorityError> {
        let (attachment, _, _) = self.consumer_identity();
        let (_, connection_generation, attachment_generation) = self.generations();
        WorkerLifecycle::new(
            attachment,
            attachment_generation,
            connection_generation,
            self.binding,
            self.projection.index().descriptor().clone(),
            self.projection.commitment(),
        )
        .map_err(|_| ConnectionAuthorityError::Integrity)
    }

    /// Creates a bounded authenticated codec for dormant durable recovery state.
    ///
    /// The codec derives its private verification key from this prepared
    /// connection. It can encode only opaque authorized values and refuses to
    /// decode bytes created for another connection.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for zero or undersized codec limits.
    pub fn durable_state_codec(
        &self,
        limits: DurableStateLimits,
    ) -> Result<DurableStateCodec, DurableStateError> {
        DurableStateCodec::new(self.binding, self.inode_key, limits)
    }

    // Reserved for the projected inode-table constructor. Keeping this private
    // prevents adapters from detaching entropy from the complete authority.
    #[allow(dead_code)]
    pub(crate) const fn inode_key(&self) -> [u8; 32] {
        self.inode_key
    }
}

fn admit_current_transport(
    projection: &ValidatedViewProjection<'_, '_>,
) -> Result<(), ConnectionAuthorityError> {
    // Capability admission inspects exactly the visible source mappings. An
    // excluded source record is not observable and grants no worker authority.
    for projected in projection.nodes() {
        let Some(node) = projection
            .source_node(projected)
            .map_err(|_| ConnectionAuthorityError::Integrity)?
        else {
            continue;
        };
        let semantics = projection
            .index()
            .record_semantics(&node)
            .map_err(|_| ConnectionAuthorityError::Integrity)?;
        if semantics.acl().is_some() {
            return Err(ConnectionAuthorityError::Unsupported("POSIX ACL"));
        }
        if !semantics.xattrs().is_empty() {
            return Err(ConnectionAuthorityError::Unsupported("extended attribute"));
        }
        if matches!(
            semantics.body(),
            crate::IndexNodeBodyView::File(file)
                if matches!(file.content(), IndexContentView::Sparse(_))
        ) {
            return Err(ConnectionAuthorityError::Unsupported(
                "sparse file topology",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn authority_binding(
    projection: &ValidatedViewProjection<'_, '_>,
    presentation: &PreparedPresentation<'_, '_, '_>,
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    connection_generation: u64,
    attachment_generation: Revision,
    presentation_generation: u64,
    lease: ConnectionLease,
    lease_holder: [u8; 32],
    lease_audience: [u8; 32],
    disclosure: CacheDomain,
    policy_digest: [u8; 32],
    user_namespace: UserNamespaceIdentity,
    mount_policy: MountPolicy,
    capabilities: FuseCapabilities,
    execute_authorized: bool,
    immutable_revision_verified: bool,
    feature_set_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-fuse-authority-v1\0");
    hasher.update(projection.commitment());
    hasher.update(presentation.cache_identity());
    hasher.update(attachment.as_bytes());
    hasher.update(sandbox.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(assignment_epoch.get().to_be_bytes());
    hasher.update(connection_generation.to_be_bytes());
    hasher.update(attachment_generation.get().to_be_bytes());
    hasher.update(presentation_generation.to_be_bytes());
    hasher.update(lease.identity);
    hasher.update(lease.valid_from_ns.to_be_bytes());
    hasher.update(lease.expires_at_ns.to_be_bytes());
    hasher.update(lease_holder);
    hasher.update(lease_audience);
    hasher.update([cache_domain_code(disclosure)]);
    hasher.update(disclosure.domain_id().as_bytes());
    hasher.update(policy_digest);
    hasher.update(user_namespace.device.to_be_bytes());
    hasher.update(user_namespace.inode.to_be_bytes());
    hasher.update(user_namespace.generation.to_be_bytes());
    hasher.update(user_namespace.presentation_plan);
    hasher.update([
        mount_policy.default_permissions as u8,
        mount_policy.allow_other as u8,
        mount_policy.read_only as u8,
        mount_policy.no_suid as u8,
        mount_policy.no_dev as u8,
        mount_policy.no_exec as u8,
        capabilities.posix_acl as u8,
        capabilities.extended_attributes as u8,
        capabilities.sparse_files as u8,
        capabilities.passthrough as u8,
        capabilities.fallback_reads as u8,
        execute_authorized as u8,
        immutable_revision_verified as u8,
    ]);
    hasher.update(feature_set_commitment);
    hasher.finalize().into()
}

const fn cache_domain_code(disclosure: CacheDomain) -> u8 {
    match disclosure.kind() {
        aos_sandbox_core::model::CacheDomainKind::Private => 0,
        aos_sandbox_core::model::CacheDomainKind::Project => 1,
        aos_sandbox_core::model::CacheDomainKind::TrustDomain => 2,
        aos_sandbox_core::model::CacheDomainKind::Public => 3,
    }
}
