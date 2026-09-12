//! SourceProvider trust, route, and session-verification inputs.
//!
//! These values are deliberately absent from SourceProvider wire messages.
//! A caller must obtain them from protected node configuration and kernel
//! observations; constructing them from peer-supplied bytes grants no
//! authority. Composite verification in [`crate::verification`] consumes the
//! complete values so later Mount code has no field-by-field comparison path.
//! [`SourceProviderSessionV1`] authenticates the mutually signed hello
//! transcript and shape-checks Mount-side provider-confinement fields. A future
//! branded kernel adapter must establish their provenance. A provider-side
//! adapter must apply the same transcript and independently establish Root
//! Mount connection-peer, record-subject, pidfd, cgroup, and capability
//! confinement before accepting requests; Stage 2A implements neither adapter.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use sha2::Digest as _;

use crate::crypto::{
    SignedSourceProviderHelloV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    digest_signed_hello, source_provider_session_binding_v1, verify_hello,
};
use crate::model::{
    SourceProviderHelloV1, SourceProviderPeerRole, SourceProviderValidationError, require_digest,
    require_generation, require_nonzero, require_proof_capabilities,
};

/// Reports invalid trust, route, or supplied session-verification inputs.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderTrustError {
    /// A supplied trust, route, or session value violates the semantic model.
    #[error("invalid SourceProvider trust, route, or session value: {0}")]
    InvalidValue(#[from] SourceProviderValidationError),
    /// A revoked or superseded key cannot authenticate new protocol work.
    #[error("SourceProvider signing key is revoked or superseded")]
    InactiveKey,
    /// The signed key reference differs from the protected trust anchor.
    #[error("SourceProvider signer differs from protected trust")]
    SignerMismatch,
    /// The configured route and trust anchor do not identify the same authority.
    #[error("SourceProvider route differs from protected trust")]
    RouteMismatch,
    /// Supplied process/session fields do not describe one fixed service process.
    #[error("SourceProvider process/session fields are not exact")]
    SessionMismatch,
    /// The protected Ed25519 key is malformed or weak.
    #[error("SourceProvider protected Ed25519 key is invalid")]
    InvalidPublicKey,
    /// A signed hello failed strict cryptographic verification.
    #[error("SourceProvider signed hello is invalid")]
    HelloSignature,
}

/// Pins one signing authority, active key, route, and exact rollback floors.
///
/// The resource floor carries identity and state digest as well as generation,
/// so an equal-generation resource cannot equivocate or substitute identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderTrustAnchorV1 {
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
    public_key: [u8; 32],
    usage: SourceProviderKeyUsageV1,
    proof_class_capabilities: u8,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    minimum_catalog_generation: u64,
    minimum_catalog_digest: ObjectDigest,
    minimum_resource_generation: u64,
    minimum_resource_id: [u8; 32],
    minimum_resource_digest: ObjectDigest,
    minimum_selection_generation: u64,
    minimum_selection_digest: ObjectDigest,
    revoked: bool,
    superseded_by_key_generation: Option<u64>,
}

impl SourceProviderTrustAnchorV1 {
    /// Constructs an exact protected trust-anchor snapshot.
    ///
    /// Construction validates shape only. The caller must load this value from
    /// protected configuration rather than peer input.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for sentinel fields, malformed or
    /// weak keys, invalid rollback-floor digests, unknown proof capabilities,
    /// or a non-advancing superseding key generation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        public_key: [u8; 32],
        usage: SourceProviderKeyUsageV1,
        proof_class_capabilities: u8,
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        minimum_catalog_generation: u64,
        minimum_catalog_digest: ObjectDigest,
        minimum_resource_generation: u64,
        minimum_resource_id: [u8; 32],
        minimum_resource_digest: ObjectDigest,
        minimum_selection_generation: u64,
        minimum_selection_digest: ObjectDigest,
        revoked: bool,
        superseded_by_key_generation: Option<u64>,
    ) -> Result<Self, SourceProviderTrustError> {
        require_nonzero("trusted authority ID", &authority_id)?;
        require_generation("trusted authority", authority_generation)?;
        require_digest("trusted authority digest", authority_digest)?;
        require_nonzero("trusted key ID", &key_id)?;
        require_generation("trusted key", key_generation)?;
        require_nonzero("trusted Ed25519 public key", &public_key)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SourceProviderTrustError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(SourceProviderTrustError::InvalidPublicKey);
        }
        if usage == SourceProviderKeyUsageV1::ProviderReceipt {
            require_proof_capabilities(proof_class_capabilities)?;
        } else if proof_class_capabilities != 0 {
            return Err(SourceProviderValidationError::InvalidCapabilities.into());
        }
        require_nonzero("trusted provider route ID", &route_id)?;
        require_generation("trusted provider route", route_generation)?;
        require_digest("trusted provider route digest", route_digest)?;
        require_generation("trusted catalog floor", minimum_catalog_generation)?;
        require_digest("trusted catalog floor digest", minimum_catalog_digest)?;
        require_generation("trusted resource floor", minimum_resource_generation)?;
        require_nonzero("trusted resource floor ID", &minimum_resource_id)?;
        require_digest("trusted resource floor digest", minimum_resource_digest)?;
        require_generation("trusted selection floor", minimum_selection_generation)?;
        require_digest("trusted selection floor digest", minimum_selection_digest)?;
        if superseded_by_key_generation.is_some_and(|generation| generation <= key_generation) {
            return Err(SourceProviderValidationError::InvalidInterval("key supersession").into());
        }
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key,
            usage,
            proof_class_capabilities,
            route_id,
            route_generation,
            route_digest,
            minimum_catalog_generation,
            minimum_catalog_digest,
            minimum_resource_generation,
            minimum_resource_id,
            minimum_resource_digest,
            minimum_selection_generation,
            minimum_selection_digest,
            revoked,
            superseded_by_key_generation,
        })
    }

    /// Returns the trusted raw Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the exact allowed signature use.
    #[must_use]
    pub const fn usage(&self) -> SourceProviderKeyUsageV1 {
        self.usage
    }

    /// Returns the allowed provider proof-class bitset.
    #[must_use]
    pub const fn proof_class_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }

    /// Checks an envelope signer against this active protected anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] when the key is inactive or any
    /// authority, key, fingerprint, or use field differs.
    pub fn verify_signer(
        &self,
        signer: &SourceProviderSigningKeyV1,
    ) -> Result<(), SourceProviderTrustError> {
        if self.revoked || self.superseded_by_key_generation.is_some() {
            return Err(SourceProviderTrustError::InactiveKey);
        }
        let public_key_digest =
            ObjectDigest::from_bytes(sha2::Sha256::digest(self.public_key).into());
        if signer.authority_id() != self.authority_id
            || signer.authority_generation() != self.authority_generation
            || signer.authority_digest() != self.authority_digest
            || signer.key_id() != self.key_id
            || signer.key_generation() != self.key_generation
            || signer.public_key_digest() != public_key_digest
            || signer.usage() != self.usage
        {
            return Err(SourceProviderTrustError::SignerMismatch);
        }
        Ok(())
    }
}

/// Models one provider-controlled resource namespace selected by route policy.
///
/// The route names the provider authority and a configured resource namespace;
/// the provider selects a concrete resource within that namespace. Its
/// `selection_generation` and `selection_digest` commit that routing decision,
/// independently of resource and catalog generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSourceProviderRouteV1 {
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    provider_authority_id: [u8; 16],
    resource_namespace_digest: ObjectDigest,
    proof_class_capabilities: u8,
    allow_recursive: bool,
    allow_kernel_coupled: bool,
    expected_uid: u32,
    expected_gid: u32,
    expected_cgroup_digest: ObjectDigest,
}

impl ProtectedSourceProviderRouteV1 {
    /// Constructs one shaped provider-route snapshot.
    ///
    /// Construction does not establish configuration provenance. The caller
    /// must obtain this value from protected route policy rather than peer input.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for sentinel route/authority data
    /// or unknown proof-class capability bits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        provider_authority_id: [u8; 16],
        resource_namespace_digest: ObjectDigest,
        proof_class_capabilities: u8,
        allow_recursive: bool,
        allow_kernel_coupled: bool,
        expected_uid: u32,
        expected_gid: u32,
        expected_cgroup_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderTrustError> {
        require_nonzero("provider route ID", &route_id)?;
        require_generation("provider route", route_generation)?;
        require_digest("provider route digest", route_digest)?;
        require_nonzero("route provider authority ID", &provider_authority_id)?;
        require_digest(
            "provider resource namespace digest",
            resource_namespace_digest,
        )?;
        require_proof_capabilities(proof_class_capabilities)?;
        require_digest("provider service cgroup digest", expected_cgroup_digest)?;
        Ok(Self {
            route_id,
            route_generation,
            route_digest,
            provider_authority_id,
            resource_namespace_digest,
            proof_class_capabilities,
            allow_recursive,
            allow_kernel_coupled,
            expected_uid,
            expected_gid,
            expected_cgroup_digest,
        })
    }

    /// Checks this route against one provider trust anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError::RouteMismatch`] for an identity,
    /// generation, digest, or capability mismatch.
    pub fn verify_trust(
        &self,
        trust: &SourceProviderTrustAnchorV1,
    ) -> Result<(), SourceProviderTrustError> {
        if self.route_id != trust.route_id
            || self.route_generation != trust.route_generation
            || self.route_digest != trust.route_digest
            || self.provider_authority_id != trust.authority_id
            || self.proof_class_capabilities & !trust.proof_class_capabilities != 0
        {
            return Err(SourceProviderTrustError::RouteMismatch);
        }
        Ok(())
    }
}

/// Models service-process identity fields supplied by a future kernel adapter.
///
/// Construction validates field shape only; it does not establish kernel
/// provenance for caller-supplied scalars.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderProcessIdentityV1 {
    uid: u32,
    gid: u32,
    tgid: u32,
    start_time_ticks: u64,
    cgroup_digest: ObjectDigest,
    pidfd_live: bool,
}

impl SourceProviderProcessIdentityV1 {
    /// Constructs one shaped process-identity value.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for a zero TGID/start time,
    /// sentinel cgroup digest, or a false pidfd-liveness claim.
    pub fn new(
        uid: u32,
        gid: u32,
        tgid: u32,
        start_time_ticks: u64,
        cgroup_digest: ObjectDigest,
        pidfd_live: bool,
    ) -> Result<Self, SourceProviderTrustError> {
        require_generation("provider TGID", u64::from(tgid))?;
        require_generation("provider start time", start_time_ticks)?;
        require_digest("provider cgroup digest", cgroup_digest)?;
        if !pidfd_live {
            return Err(SourceProviderTrustError::SessionMismatch);
        }
        Ok(Self {
            uid,
            gid,
            tgid,
            start_time_ticks,
            cgroup_digest,
            pidfd_live,
        })
    }
}

/// Binds mutually signed protocol hellos to supplied provider-confinement fields.
///
/// The signed client hello authenticates Root Mount's query authority. The
/// future provider ingress adapter must additionally retain and compare the
/// Root Mount connection-peer, record-subject, pidfd, cgroup, and capability
/// observations before it executes a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderSessionV1 {
    root_mount_hello: SignedSourceProviderHelloV1,
    provider_hello: SignedSourceProviderHelloV1,
    route: ProtectedSourceProviderRouteV1,
    provider_identity: SourceProviderProcessIdentityV1,
    binding: ObjectDigest,
}

impl SourceProviderSessionV1 {
    /// Authenticates a signed hello transcript and validates supplied confinement fields.
    ///
    /// The Linux carrier can report a privileged sender-nominated subject; it
    /// does not prove this equality. The higher layer must obtain both retained
    /// kernel observations and pass them here before composite verification.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for invalid signatures, wrong hello
    /// roles, nonce/boot/key/route/capability mismatch, mismatched supplied
    /// process fields, or route identity mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate(
        expected_client_nonce: [u8; 32],
        root_mount_hello: SignedSourceProviderHelloV1,
        provider_hello: SignedSourceProviderHelloV1,
        root_mount_trust: &SourceProviderTrustAnchorV1,
        provider_trust: &SourceProviderTrustAnchorV1,
        connection_peer: SourceProviderProcessIdentityV1,
        nominated_record_subject: SourceProviderProcessIdentityV1,
        route: &ProtectedSourceProviderRouteV1,
    ) -> Result<Self, SourceProviderTrustError> {
        verify_hello(&root_mount_hello, root_mount_trust)
            .map_err(|_| SourceProviderTrustError::HelloSignature)?;
        verify_hello(&provider_hello, provider_trust)
            .map_err(|_| SourceProviderTrustError::HelloSignature)?;
        route.verify_trust(provider_trust)?;
        let client = root_mount_hello.subject();
        let server = provider_hello.subject();
        if client.role() != SourceProviderPeerRole::RootMount
            || server.role() != SourceProviderPeerRole::Provider
            || client.nonce() != expected_client_nonce
            || client.nonce() == server.nonce()
            || client.kernel_boot_id() != server.kernel_boot_id()
            || client.expected_peer_signer() != provider_hello.signer()
            || server.expected_peer_signer() != root_mount_hello.signer()
            || server.client_hello_digest() != Some(digest_signed_hello(&root_mount_hello))
            || client.route_id() != route.route_id
            || client.route_generation() != route.route_generation
            || client.route_digest() != route.route_digest
            || server.route_id() != route.route_id
            || server.route_generation() != route.route_generation
            || server.route_digest() != route.route_digest
            || server.proof_class_capabilities() & !client.proof_class_capabilities() != 0
            || server.proof_class_capabilities() & !route.proof_class_capabilities != 0
            || server.proof_class_capabilities() & !provider_trust.proof_class_capabilities != 0
            || (server.supports_recursive()
                && (!client.supports_recursive() || !route.allow_recursive))
            || (server.supports_kernel_coupled()
                && (!client.supports_kernel_coupled() || !route.allow_kernel_coupled))
            || connection_peer != nominated_record_subject
            || connection_peer.uid != route.expected_uid
            || connection_peer.gid != route.expected_gid
            || connection_peer.cgroup_digest != route.expected_cgroup_digest
            || !connection_peer.pidfd_live
        {
            return Err(SourceProviderTrustError::SessionMismatch);
        }
        let binding = source_provider_session_binding_v1(&root_mount_hello, &provider_hello);
        Ok(Self {
            root_mount_hello,
            provider_hello,
            route: route.clone(),
            provider_identity: connection_peer,
            binding,
        })
    }

    /// Returns the Root Mount process introduction.
    #[must_use]
    pub const fn root_mount_hello(&self) -> &SourceProviderHelloV1 {
        self.root_mount_hello.subject()
    }

    /// Returns the provider process introduction.
    #[must_use]
    pub const fn provider_hello(&self) -> &SourceProviderHelloV1 {
        self.provider_hello.subject()
    }

    /// Returns the complete signed client hello.
    #[must_use]
    pub const fn signed_root_mount_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.root_mount_hello
    }

    /// Returns the complete signed server hello.
    #[must_use]
    pub const fn signed_provider_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.provider_hello
    }

    /// Returns the digest binding both complete signed hello envelopes.
    #[must_use]
    pub const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    /// Returns the supplied provider-process confinement fields.
    #[must_use]
    pub const fn provider_identity(&self) -> &SourceProviderProcessIdentityV1 {
        &self.provider_identity
    }

    pub(crate) const fn route(&self) -> &ProtectedSourceProviderRouteV1 {
        &self.route
    }
}

impl SourceProviderTrustAnchorV1 {
    pub(crate) const fn minimum_catalog_generation(&self) -> u64 {
        self.minimum_catalog_generation
    }

    pub(crate) const fn minimum_resource_generation(&self) -> u64 {
        self.minimum_resource_generation
    }

    pub(crate) const fn minimum_resource_id(&self) -> [u8; 32] {
        self.minimum_resource_id
    }

    pub(crate) const fn minimum_resource_digest(&self) -> ObjectDigest {
        self.minimum_resource_digest
    }

    pub(crate) const fn minimum_selection_generation(&self) -> u64 {
        self.minimum_selection_generation
    }

    pub(crate) const fn minimum_catalog_digest(&self) -> ObjectDigest {
        self.minimum_catalog_digest
    }

    pub(crate) const fn minimum_selection_digest(&self) -> ObjectDigest {
        self.minimum_selection_digest
    }
}

impl ProtectedSourceProviderRouteV1 {
    pub(crate) const fn proof_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }

    pub(crate) const fn allows_recursive(&self) -> bool {
        self.allow_recursive
    }

    pub(crate) const fn allows_kernel_coupled(&self) -> bool {
        self.allow_kernel_coupled
    }

    pub(crate) const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }
}
