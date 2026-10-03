//! SourceProvider trust, route, and session-verification inputs.
//!
//! These values are deliberately absent from SourceProvider wire messages.
//! A caller must obtain them from protected node configuration and kernel
//! observations; constructing them from peer-supplied bytes grants no
//! authority. Composite verification in [`crate::verification`] consumes the
//! complete values so later Mount code has no field-by-field comparison path.
//! [`SourceProviderSessionV1`] authenticates the mutually signed hello
//! transcript and shape-checks Mount-side provider-confinement fields.
//! [`SourceProviderIngressSessionV1`] applies the same transcript checks to a
//! shaped Root Mount peer policy. Future branded kernel adapters must establish
//! the provenance and continuing liveness of every supplied process value.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SignedSourceProviderHelloV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    digest_signed_hello, encode_signer, source_provider_session_binding_v1, verify_hello,
};
use crate::model::{
    SourceProviderAuthorityV1, SourceProviderHelloV1, SourceProviderPeerRole,
    SourceProviderValidationError, SourceResourceV1, require_digest, require_generation,
    require_nonzero, require_proof_capabilities,
};

const TRUST_SET_DOMAIN: &[u8] = b"aos-source-provider-trust-set-v1\0";
const SIGNER_SET_DOMAIN: &[u8] = b"aos-source-provider-signer-set-v1\0";
const CATALOG_FLOOR_DOMAIN: &[u8] = b"aos-source-provider-catalog-floor-v1\0";
const SELECTION_FLOOR_DOMAIN: &[u8] = b"aos-source-provider-selection-floor-v1\0";

/// Maximum authority generations retained in one protected trust snapshot.
pub const MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS: usize = 16;
/// Maximum signing-key generations retained in one protected trust snapshot.
pub const MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS: usize = 64;
/// Maximum acquisition-scoped selection floors accepted with one inventory.
pub const MAXIMUM_SOURCE_SELECTION_FLOORS: usize = crate::model::MAXIMUM_INVENTORY_ENTRIES;

/// Reports invalid trust, route, or supplied session-verification inputs.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderTrustError {
    /// A supplied trust, route, or session value violates the semantic model.
    #[error("invalid SourceProvider trust, route, or session value: {0}")]
    InvalidValue(#[from] SourceProviderValidationError),
    /// A revoked or superseded key cannot authenticate new protocol work.
    #[error("SourceProvider signing key is revoked or superseded")]
    InactiveKey,
    /// The signed key reference differs from the protected trust snapshot.
    #[error("SourceProvider signer differs from protected trust")]
    SignerMismatch,
    /// The configured route and current selector do not identify the same authority.
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
    /// A protected trust set is not canonical or its digest differs.
    #[error("SourceProvider protected trust set is not canonical")]
    TrustSetNotCanonical,
    /// A historical signer cannot be resolved at its issuance time.
    #[error("SourceProvider historical signer is not trusted for this artifact")]
    HistoricalSigner,
}

/// Describes whether an authority generation is usable or revoked.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderAuthorityTrustStateV1 {
    /// The authority generation is trusted during its validity interval.
    Trusted = 1,
    /// The authority generation is explicitly revoked.
    Revoked = 2,
}

/// Retains one authority generation and its validity interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderAuthorityTrustV1 {
    authority: SourceProviderAuthorityV1,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    state: SourceProviderAuthorityTrustStateV1,
}

impl SourceProviderAuthorityTrustV1 {
    /// Constructs one bounded authority-trust record.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] when the validity interval is not
    /// nonnegative and nonempty.
    pub fn new(
        authority: SourceProviderAuthorityV1,
        valid_from_seconds: i64,
        valid_until_seconds: i64,
        state: SourceProviderAuthorityTrustStateV1,
    ) -> Result<Self, SourceProviderTrustError> {
        if valid_from_seconds < 0 || valid_from_seconds >= valid_until_seconds {
            return Err(SourceProviderValidationError::InvalidInterval("authority trust").into());
        }
        Ok(Self {
            authority,
            valid_from_seconds,
            valid_until_seconds,
            state,
        })
    }

    /// Returns the trusted authority generation.
    #[must_use]
    pub const fn authority(&self) -> &SourceProviderAuthorityV1 {
        &self.authority
    }

    /// Returns the inclusive validity start in Unix seconds.
    #[must_use]
    pub const fn valid_from_seconds(&self) -> i64 {
        self.valid_from_seconds
    }

    /// Returns the exclusive validity end in Unix seconds.
    #[must_use]
    pub const fn valid_until_seconds(&self) -> i64 {
        self.valid_until_seconds
    }

    /// Returns the authority trust state.
    #[must_use]
    pub const fn state(&self) -> SourceProviderAuthorityTrustStateV1 {
        self.state
    }
}

/// Describes currentness of one signing-key generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderKeyTrustStateV1 {
    /// The key may authenticate newly issued artifacts.
    Eligible = 1,
    /// The key may authenticate historical artifacts but not new work.
    Superseded = 2,
    /// The key is revoked, including for historical verification.
    Revoked = 3,
}

/// Retains one exact raw Ed25519 key and its currentness state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderKeyTrustV1 {
    signer: SourceProviderSigningKeyV1,
    public_key: [u8; 32],
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    state: SourceProviderKeyTrustStateV1,
    superseded_by_key_generation: u64,
}

impl SourceProviderKeyTrustV1 {
    /// Constructs one exact key-trust record.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for an invalid public key,
    /// fingerprint, interval, or supersession tuple.
    pub fn new(
        signer: SourceProviderSigningKeyV1,
        public_key: [u8; 32],
        valid_from_seconds: i64,
        valid_until_seconds: i64,
        state: SourceProviderKeyTrustStateV1,
        superseded_by_key_generation: u64,
    ) -> Result<Self, SourceProviderTrustError> {
        require_nonzero("trusted Ed25519 public key", &public_key)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SourceProviderTrustError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(SourceProviderTrustError::InvalidPublicKey);
        }
        if ObjectDigest::from_bytes(Sha256::digest(public_key).into()) != signer.public_key_digest()
        {
            return Err(SourceProviderTrustError::SignerMismatch);
        }
        if valid_from_seconds < 0 || valid_from_seconds >= valid_until_seconds {
            return Err(SourceProviderValidationError::InvalidInterval("key trust").into());
        }
        let supersession_is_valid = match state {
            SourceProviderKeyTrustStateV1::Superseded => {
                superseded_by_key_generation > signer.key_generation()
            }
            SourceProviderKeyTrustStateV1::Eligible | SourceProviderKeyTrustStateV1::Revoked => {
                superseded_by_key_generation == 0
            }
        };
        if !supersession_is_valid {
            return Err(SourceProviderValidationError::InvalidInterval("key supersession").into());
        }
        Ok(Self {
            signer,
            public_key,
            valid_from_seconds,
            valid_until_seconds,
            state,
            superseded_by_key_generation,
        })
    }

    /// Returns the exact stable signer reference.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Returns the exact raw Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the inclusive validity start in Unix seconds.
    #[must_use]
    pub const fn valid_from_seconds(&self) -> i64 {
        self.valid_from_seconds
    }

    /// Returns the exclusive validity end in Unix seconds.
    #[must_use]
    pub const fn valid_until_seconds(&self) -> i64 {
        self.valid_until_seconds
    }

    /// Returns the key trust state.
    #[must_use]
    pub const fn state(&self) -> SourceProviderKeyTrustStateV1 {
        self.state
    }

    /// Returns the replacing key generation, or zero when absent.
    #[must_use]
    pub const fn superseded_by_key_generation(&self) -> u64 {
        self.superseded_by_key_generation
    }
}

/// Retains one canonical protected authority and signing-key snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderTrustSetV1 {
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    authorities: Vec<SourceProviderAuthorityTrustV1>,
    keys: Vec<SourceProviderKeyTrustV1>,
}

impl SourceProviderTrustSetV1 {
    /// Constructs a canonical bounded trust set and checks its expected digest.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for sentinel snapshot fields,
    /// empty, oversized, unordered, unresolved, or conflicting records, or a
    /// digest mismatch.
    pub fn new(
        trust_generation: u64,
        expected_trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
        authorities: Vec<SourceProviderAuthorityTrustV1>,
        keys: Vec<SourceProviderKeyTrustV1>,
    ) -> Result<Self, SourceProviderTrustError> {
        require_generation("SourceProvider trust", trust_generation)?;
        require_digest(
            "SourceProvider expected trust digest",
            expected_trust_digest,
        )?;
        require_generation("SourceProvider revocation", revocation_generation)?;
        require_digest("SourceProvider revocation digest", revocation_digest)?;
        if authorities.is_empty()
            || authorities.len() > MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS
            || keys.is_empty()
            || keys.len() > MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS
            || !authorities
                .windows(2)
                .all(|pair| authority_order(&pair[0]) < authority_order(&pair[1]))
            || !keys
                .windows(2)
                .all(|pair| key_order(&pair[0]) < key_order(&pair[1]))
        {
            return Err(SourceProviderTrustError::TrustSetNotCanonical);
        }
        for key in &keys {
            if !authorities.iter().any(|authority| {
                authority.authority.authority_id() == key.signer.authority_id()
                    && authority.authority.authority_generation()
                        == key.signer.authority_generation()
                    && authority.authority.authority_digest() == key.signer.authority_digest()
            }) {
                return Err(SourceProviderTrustError::TrustSetNotCanonical);
            }
        }
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].iter().any(|prior| {
                prior.public_key == key.public_key
                    || prior.signer.public_key_digest() == key.signer.public_key_digest()
                    || (prior.signer.authority_id() == key.signer.authority_id()
                        && prior.signer.key_id() == key.signer.key_id()
                        && prior.signer.usage() != key.signer.usage())
            }) {
                return Err(SourceProviderTrustError::TrustSetNotCanonical);
            }
        }
        let trust_digest = compute_trust_digest(
            trust_generation,
            revocation_generation,
            revocation_digest,
            &authorities,
            &keys,
        );
        if !digest_equal(trust_digest, expected_trust_digest) {
            return Err(SourceProviderTrustError::TrustSetNotCanonical);
        }
        Ok(Self {
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            authorities,
            keys,
        })
    }

    /// Returns the protected trust-set generation.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the canonical trust-set digest.
    #[must_use]
    pub const fn trust_digest(&self) -> ObjectDigest {
        self.trust_digest
    }

    /// Returns the protected revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the protected revocation digest.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    /// Returns the canonical authority-trust records.
    #[must_use]
    pub fn authorities(&self) -> &[SourceProviderAuthorityTrustV1] {
        &self.authorities
    }

    /// Returns the canonical key-trust records.
    #[must_use]
    pub fn keys(&self) -> &[SourceProviderKeyTrustV1] {
        &self.keys
    }

    fn authority(
        &self,
        authority: &SourceProviderAuthorityV1,
    ) -> Option<&SourceProviderAuthorityTrustV1> {
        self.authorities
            .iter()
            .find(|entry| entry.authority == *authority)
    }

    fn key(&self, signer: &SourceProviderSigningKeyV1) -> Option<&SourceProviderKeyTrustV1> {
        self.keys.iter().find(|entry| entry.signer == *signer)
    }

    pub(crate) fn resolve_current(
        &self,
        current: &SourceProviderCurrentAuthorityV1,
        signer: &SourceProviderSigningKeyV1,
        now_seconds: i64,
    ) -> Result<&[u8; 32], SourceProviderTrustError> {
        current.validate_at(now_seconds)?;
        if current.trust_generation != self.trust_generation
            || current.trust_digest != self.trust_digest
            || current.revocation_generation != self.revocation_generation
            || current.revocation_digest != self.revocation_digest
            || (signer != &current.hello_signer && signer != &current.traffic_signer)
        {
            return Err(SourceProviderTrustError::SignerMismatch);
        }
        let key = self
            .key(signer)
            .ok_or(SourceProviderTrustError::SignerMismatch)?;
        if key.state != SourceProviderKeyTrustStateV1::Eligible
            || now_seconds < key.valid_from_seconds
            || now_seconds >= key.valid_until_seconds
        {
            return Err(SourceProviderTrustError::InactiveKey);
        }
        Ok(&key.public_key)
    }

    pub(crate) fn resolve_historical_outcome(
        &self,
        signer: &SourceProviderSigningKeyV1,
        issued_seconds: i64,
        floor: &SourceSelectionFloorV1,
    ) -> Result<&[u8; 32], SourceProviderTrustError> {
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer != &floor.outcome_signer
            || self.trust_generation < floor.trust_generation
            || (self.trust_generation == floor.trust_generation
                && self.trust_digest != floor.trust_digest)
            || self.revocation_generation < floor.revocation_generation
            || (self.revocation_generation == floor.revocation_generation
                && self.revocation_digest != floor.revocation_digest)
        {
            return Err(SourceProviderTrustError::HistoricalSigner);
        }
        let authority = self
            .authorities
            .iter()
            .find(|entry| {
                entry.authority.authority_id() == signer.authority_id()
                    && entry.authority.authority_generation() == signer.authority_generation()
                    && entry.authority.authority_digest() == signer.authority_digest()
            })
            .ok_or(SourceProviderTrustError::HistoricalSigner)?;
        let key = self
            .key(signer)
            .ok_or(SourceProviderTrustError::HistoricalSigner)?;
        if authority.state == SourceProviderAuthorityTrustStateV1::Revoked
            || key.state == SourceProviderKeyTrustStateV1::Revoked
            || issued_seconds < authority.valid_from_seconds
            || issued_seconds >= authority.valid_until_seconds
            || issued_seconds < key.valid_from_seconds
            || issued_seconds >= key.valid_until_seconds
        {
            return Err(SourceProviderTrustError::HistoricalSigner);
        }
        Ok(&key.public_key)
    }

    pub(crate) fn validate_selection_floor(
        &self,
        floor: &SourceSelectionFloorV1,
    ) -> Result<(), SourceProviderTrustError> {
        if self.trust_generation < floor.trust_generation
            || (self.trust_generation == floor.trust_generation
                && self.trust_digest != floor.trust_digest)
            || self.revocation_generation < floor.revocation_generation
            || (self.revocation_generation == floor.revocation_generation
                && self.revocation_digest != floor.revocation_digest)
        {
            return Err(SourceProviderTrustError::HistoricalSigner);
        }
        let signer = floor.outcome_signer();
        let authority = self
            .authorities
            .iter()
            .find(|entry| {
                entry.authority.authority_id() == signer.authority_id()
                    && entry.authority.authority_generation() == signer.authority_generation()
                    && entry.authority.authority_digest() == signer.authority_digest()
            })
            .ok_or(SourceProviderTrustError::HistoricalSigner)?;
        let key = self
            .key(signer)
            .ok_or(SourceProviderTrustError::HistoricalSigner)?;
        if authority.state == SourceProviderAuthorityTrustStateV1::Revoked
            || key.state == SourceProviderKeyTrustStateV1::Revoked
        {
            return Err(SourceProviderTrustError::HistoricalSigner);
        }
        Ok(())
    }
}

/// Computes the canonical digest expected by [`SourceProviderTrustSetV1::new`].
///
/// This pure digest does not establish protected provenance or current trust.
#[must_use]
pub fn source_provider_trust_set_digest_v1(
    trust_generation: u64,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    authorities: &[SourceProviderAuthorityTrustV1],
    keys: &[SourceProviderKeyTrustV1],
) -> ObjectDigest {
    compute_trust_digest(
        trust_generation,
        revocation_generation,
        revocation_digest,
        authorities,
        keys,
    )
}

fn authority_order(value: &SourceProviderAuthorityTrustV1) -> ([u8; 16], u64) {
    (
        value.authority.authority_id(),
        value.authority.authority_generation(),
    )
}

fn key_order(value: &SourceProviderKeyTrustV1) -> ([u8; 16], u64, u8, [u8; 16], u64) {
    (
        value.signer.authority_id(),
        value.signer.authority_generation(),
        value.signer.usage() as u8,
        value.signer.key_id(),
        value.signer.key_generation(),
    )
}

fn compute_trust_digest(
    trust_generation: u64,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    authorities: &[SourceProviderAuthorityTrustV1],
    keys: &[SourceProviderKeyTrustV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(TRUST_SET_DOMAIN);
    hasher.update(trust_generation.to_be_bytes());
    hasher.update(revocation_generation.to_be_bytes());
    hasher.update(revocation_digest.as_bytes());
    hasher.update((authorities.len() as u32).to_be_bytes());
    for value in authorities {
        hasher.update(value.authority.authority_id());
        hasher.update(value.authority.authority_generation().to_be_bytes());
        hasher.update(value.authority.authority_digest().as_bytes());
        hasher.update(value.valid_from_seconds.to_be_bytes());
        hasher.update(value.valid_until_seconds.to_be_bytes());
        hasher.update([value.state as u8]);
        hasher.update([0; 7]);
    }
    hasher.update((keys.len() as u32).to_be_bytes());
    for value in keys {
        let mut signer = Vec::with_capacity(120);
        encode_signer(&mut signer, &value.signer);
        hasher.update(&signer);
        hasher.update(value.public_key);
        hasher.update(value.valid_from_seconds.to_be_bytes());
        hasher.update(value.valid_until_seconds.to_be_bytes());
        hasher.update([value.state as u8]);
        hasher.update([0; 7]);
        hasher.update(value.superseded_by_key_generation.to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn digest_equal(left: ObjectDigest, right: ObjectDigest) -> bool {
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0, |different, (left, right)| different | (*left ^ *right))
        == 0
}

/// Pins one currently eligible role-specific authority and its two keys.
///
/// Construction validates shape and consistency with supplied protected
/// values. It does not establish that either input came from protected storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderCurrentAuthorityV1 {
    role: SourceProviderPeerRole,
    authority: SourceProviderAuthorityV1,
    hello_signer: SourceProviderSigningKeyV1,
    traffic_signer: SourceProviderSigningKeyV1,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    proof_class_capabilities: u8,
}

impl SourceProviderCurrentAuthorityV1 {
    /// Constructs one current role selector from an exact trust snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] when the authority or either key is
    /// absent, inactive, mismatched, not role-separated, or has no common
    /// validity interval, or when the route snapshot disagrees.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: SourceProviderPeerRole,
        authority: SourceProviderAuthorityV1,
        hello_signer: SourceProviderSigningKeyV1,
        traffic_signer: SourceProviderSigningKeyV1,
        proof_class_capabilities: u8,
        route: &ProtectedSourceProviderRouteV1,
        trust_set: &SourceProviderTrustSetV1,
    ) -> Result<Self, SourceProviderTrustError> {
        require_proof_capabilities(proof_class_capabilities)?;
        let expected_usages = match role {
            SourceProviderPeerRole::RootMount => (
                SourceProviderKeyUsageV1::RootMountHello,
                SourceProviderKeyUsageV1::RootMountRecord,
            ),
            SourceProviderPeerRole::Provider => (
                SourceProviderKeyUsageV1::ProviderHello,
                SourceProviderKeyUsageV1::ProviderOutcome,
            ),
        };
        if hello_signer.usage() != expected_usages.0
            || traffic_signer.usage() != expected_usages.1
            || hello_signer.key_id() == traffic_signer.key_id()
            || hello_signer.public_key_digest() == traffic_signer.public_key_digest()
            || !signer_matches_authority(&hello_signer, &authority)
            || !signer_matches_authority(&traffic_signer, &authority)
            || route.route_id == [0; 16]
            || route.route_generation == 0
            || route.route_digest == ObjectDigest::from_bytes([0; 32])
            || (role == SourceProviderPeerRole::Provider
                && route.provider_authority_id != authority.authority_id())
            || proof_class_capabilities & !route.proof_class_capabilities != 0
        {
            return Err(SourceProviderTrustError::RouteMismatch);
        }
        let authority_trust = trust_set
            .authority(&authority)
            .ok_or(SourceProviderTrustError::SignerMismatch)?;
        let hello_key = trust_set
            .key(&hello_signer)
            .ok_or(SourceProviderTrustError::SignerMismatch)?;
        let traffic_key = trust_set
            .key(&traffic_signer)
            .ok_or(SourceProviderTrustError::SignerMismatch)?;
        if authority_trust.state != SourceProviderAuthorityTrustStateV1::Trusted
            || hello_key.state != SourceProviderKeyTrustStateV1::Eligible
            || traffic_key.state != SourceProviderKeyTrustStateV1::Eligible
            || hello_key.public_key == traffic_key.public_key
        {
            return Err(SourceProviderTrustError::InactiveKey);
        }
        let valid_from_seconds = authority_trust
            .valid_from_seconds
            .max(hello_key.valid_from_seconds)
            .max(traffic_key.valid_from_seconds);
        let valid_until_seconds = authority_trust
            .valid_until_seconds
            .min(hello_key.valid_until_seconds)
            .min(traffic_key.valid_until_seconds);
        if valid_from_seconds >= valid_until_seconds {
            return Err(SourceProviderValidationError::InvalidInterval("current authority").into());
        }
        Ok(Self {
            role,
            authority,
            hello_signer,
            traffic_signer,
            trust_generation: trust_set.trust_generation,
            trust_digest: trust_set.trust_digest,
            revocation_generation: trust_set.revocation_generation,
            revocation_digest: trust_set.revocation_digest,
            valid_from_seconds,
            valid_until_seconds,
            route_id: route.route_id,
            route_generation: route.route_generation,
            route_digest: route.route_digest,
            proof_class_capabilities,
        })
    }

    /// Checks whether this current selector is valid at an exact Unix time.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError::InactiveKey`] outside the retained
    /// half-open validity interval.
    pub fn validate_at(&self, now_seconds: i64) -> Result<(), SourceProviderTrustError> {
        if now_seconds < self.valid_from_seconds || now_seconds >= self.valid_until_seconds {
            Err(SourceProviderTrustError::InactiveKey)
        } else {
            Ok(())
        }
    }

    /// Returns the selected stable authority generation.
    #[must_use]
    pub const fn authority(&self) -> &SourceProviderAuthorityV1 {
        &self.authority
    }

    /// Returns the current hello signer.
    #[must_use]
    pub const fn hello_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.hello_signer
    }

    /// Returns the current traffic signer.
    #[must_use]
    pub const fn traffic_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.traffic_signer
    }

    /// Returns the selected endpoint role.
    #[must_use]
    pub const fn role(&self) -> SourceProviderPeerRole {
        self.role
    }

    /// Returns the protected trust generation.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the protected trust digest.
    #[must_use]
    pub const fn trust_digest(&self) -> ObjectDigest {
        self.trust_digest
    }

    /// Returns the protected revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the protected revocation digest.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    pub(crate) const fn valid_until_seconds(&self) -> i64 {
        self.valid_until_seconds
    }

    pub(crate) const fn proof_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }
}

/// Commits the minimum acceptable provider catalog head for one route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCatalogFloorV1 {
    provider_authority_id: [u8; 16],
    resource_namespace_digest: ObjectDigest,
    minimum_catalog_generation: u64,
    minimum_catalog_digest: ObjectDigest,
}

impl ProviderCatalogFloorV1 {
    /// Constructs one provider-catalog rollback floor.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for a sentinel scope, generation,
    /// or digest.
    pub fn new(
        provider_authority_id: [u8; 16],
        resource_namespace_digest: ObjectDigest,
        minimum_catalog_generation: u64,
        minimum_catalog_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderTrustError> {
        require_nonzero(
            "catalog-floor provider authority ID",
            &provider_authority_id,
        )?;
        require_digest(
            "catalog-floor resource namespace",
            resource_namespace_digest,
        )?;
        require_generation("catalog floor", minimum_catalog_generation)?;
        require_digest("catalog-floor digest", minimum_catalog_digest)?;
        Ok(Self {
            provider_authority_id,
            resource_namespace_digest,
            minimum_catalog_generation,
            minimum_catalog_digest,
        })
    }

    /// Returns the exact canonical 88-byte floor encoding.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; 88] {
        let mut bytes = [0; 88];
        bytes[..16].copy_from_slice(&self.provider_authority_id);
        bytes[16..48].copy_from_slice(self.resource_namespace_digest.as_bytes());
        bytes[48..56].copy_from_slice(&self.minimum_catalog_generation.to_be_bytes());
        bytes[56..88].copy_from_slice(self.minimum_catalog_digest.as_bytes());
        bytes
    }

    /// Returns the domain-separated canonical floor digest.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        domain_digest(CATALOG_FLOOR_DOMAIN, &self.to_canonical_bytes())
    }

    /// Returns the stable provider authority ID scoped by this floor.
    #[must_use]
    pub const fn provider_authority_id(&self) -> [u8; 16] {
        self.provider_authority_id
    }
    /// Returns the resource namespace scoped by this floor.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }
    /// Returns the minimum catalog generation.
    #[must_use]
    pub const fn minimum_catalog_generation(&self) -> u64 {
        self.minimum_catalog_generation
    }
    /// Returns the exact digest required at the minimum generation.
    #[must_use]
    pub const fn minimum_catalog_digest(&self) -> ObjectDigest {
        self.minimum_catalog_digest
    }
}

/// Retains the exact outcome selected for one stable acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSelectionFloorV1 {
    acquisition_id: ObjectDigest,
    provider_authority_id: [u8; 16],
    route_id: [u8; 16],
    resource: SourceResourceV1,
    outcome_signer: SourceProviderSigningKeyV1,
    lease_id: [u8; 16],
    signed_lease_digest: ObjectDigest,
    proof_class: u8,
    proof_digest: ObjectDigest,
    resource_commitment: ObjectDigest,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
}

impl SourceSelectionFloorV1 {
    /// Constructs one acquisition-scoped exact replay floor.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for sentinel fields, a non-outcome
    /// signer, or an unknown proof class.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        acquisition_id: ObjectDigest,
        provider_authority_id: [u8; 16],
        route_id: [u8; 16],
        resource: SourceResourceV1,
        outcome_signer: SourceProviderSigningKeyV1,
        lease_id: [u8; 16],
        signed_lease_digest: ObjectDigest,
        proof_class: u8,
        proof_digest: ObjectDigest,
        resource_commitment: ObjectDigest,
        trust_generation: u64,
        trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderTrustError> {
        require_digest("selection-floor acquisition ID", acquisition_id)?;
        require_nonzero(
            "selection-floor provider authority ID",
            &provider_authority_id,
        )?;
        require_nonzero("selection-floor route ID", &route_id)?;
        require_nonzero("selection-floor lease ID", &lease_id)?;
        require_digest("selection-floor signed lease", signed_lease_digest)?;
        if outcome_signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || outcome_signer.authority_id() != provider_authority_id
            || !(1..=4).contains(&proof_class)
        {
            return Err(SourceProviderValidationError::InvalidCapabilities.into());
        }
        require_digest("selection-floor proof", proof_digest)?;
        require_digest("selection-floor resource commitment", resource_commitment)?;
        require_generation("selection-floor trust", trust_generation)?;
        require_digest("selection-floor trust digest", trust_digest)?;
        require_generation("selection-floor revocation", revocation_generation)?;
        require_digest("selection-floor revocation digest", revocation_digest)?;
        Ok(Self {
            acquisition_id,
            provider_authority_id,
            route_id,
            resource,
            outcome_signer,
            lease_id,
            signed_lease_digest,
            proof_class,
            proof_digest,
            resource_commitment,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
        })
    }

    /// Returns the stable acquisition ID scoped by this floor.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the exact floor resource.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the pinned provider outcome signer.
    #[must_use]
    pub const fn outcome_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.outcome_signer
    }

    /// Returns the stable provider authority ID.
    #[must_use]
    pub const fn provider_authority_id(&self) -> [u8; 16] {
        self.provider_authority_id
    }
    /// Returns the protected route ID.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }
    /// Returns the exact provider lease ID.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }
    /// Returns the digest of the exact signed lease envelope.
    #[must_use]
    pub const fn signed_lease_digest(&self) -> ObjectDigest {
        self.signed_lease_digest
    }
    /// Returns the closed proof-class code.
    #[must_use]
    pub const fn proof_class(&self) -> u8 {
        self.proof_class
    }
    /// Returns the exact proof digest.
    #[must_use]
    pub const fn proof_digest(&self) -> ObjectDigest {
        self.proof_digest
    }
    /// Returns the exact resource/proof commitment.
    #[must_use]
    pub const fn resource_commitment(&self) -> ObjectDigest {
        self.resource_commitment
    }

    /// Returns the trust generation that authenticated the selection.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the trust digest that authenticated the selection.
    #[must_use]
    pub const fn trust_digest(&self) -> ObjectDigest {
        self.trust_digest
    }

    /// Returns the revocation generation that authenticated the selection.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the revocation digest that authenticated the selection.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    /// Returns the exact canonical 568-byte floor encoding.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; 568] {
        let mut bytes = Vec::with_capacity(568);
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(&self.provider_authority_id);
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(self.resource.resource_namespace_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.catalog_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.catalog_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.resource_id());
        bytes.extend_from_slice(&self.resource.resource_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.resource_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.selection_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.selection_digest().as_bytes());
        encode_signer(&mut bytes, &self.outcome_signer);
        bytes.extend_from_slice(&self.lease_id);
        bytes.extend_from_slice(self.signed_lease_digest.as_bytes());
        bytes.push(self.proof_class);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(self.proof_digest.as_bytes());
        bytes.extend_from_slice(self.resource_commitment.as_bytes());
        bytes.extend_from_slice(&self.trust_generation.to_be_bytes());
        bytes.extend_from_slice(self.trust_digest.as_bytes());
        bytes.extend_from_slice(&self.revocation_generation.to_be_bytes());
        bytes.extend_from_slice(self.revocation_digest.as_bytes());
        let mut canonical = [0; 568];
        canonical.copy_from_slice(&bytes);
        canonical
    }

    /// Returns the domain-separated canonical selection-floor digest.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        domain_digest(SELECTION_FLOOR_DOMAIN, &self.to_canonical_bytes())
    }
}

/// Commits the four exact signer references in protocol order.
#[must_use]
pub fn source_provider_signer_set_commitment_v1(
    root_mount_hello: &SourceProviderSigningKeyV1,
    root_mount_record: &SourceProviderSigningKeyV1,
    provider_hello: &SourceProviderSigningKeyV1,
    provider_outcome: &SourceProviderSigningKeyV1,
) -> ObjectDigest {
    let mut bytes = Vec::with_capacity(480);
    for signer in [
        root_mount_hello,
        root_mount_record,
        provider_hello,
        provider_outcome,
    ] {
        encode_signer(&mut bytes, signer);
    }
    domain_digest(SIGNER_SET_DOMAIN, &bytes)
}

fn signer_matches_authority(
    signer: &SourceProviderSigningKeyV1,
    authority: &SourceProviderAuthorityV1,
) -> bool {
    signer.authority_id() == authority.authority_id()
        && signer.authority_generation() == authority.authority_generation()
        && signer.authority_digest() == authority.authority_digest()
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
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
    /// Returns the protected route ID.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }

    /// Returns the protected route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.route_generation
    }

    /// Returns the protected route-state digest.
    #[must_use]
    pub const fn route_digest(&self) -> ObjectDigest {
        self.route_digest
    }

    /// Returns the protected provider authority ID.
    #[must_use]
    pub const fn provider_authority_id(&self) -> [u8; 16] {
        self.provider_authority_id
    }

    /// Returns the protected resource-namespace digest.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

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

    /// Checks this route against one current authority selector.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError::RouteMismatch`] for an identity,
    /// generation, digest, or capability mismatch.
    pub fn verify_current_authority(
        &self,
        current: &SourceProviderCurrentAuthorityV1,
    ) -> Result<(), SourceProviderTrustError> {
        if self.route_id != current.route_id
            || self.route_generation != current.route_generation
            || self.route_digest != current.route_digest
            || (current.role == SourceProviderPeerRole::Provider
                && self.provider_authority_id != current.authority.authority_id())
            || self.proof_class_capabilities & !current.proof_class_capabilities != 0
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

    pub(crate) const fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) const fn gid(&self) -> u32 {
        self.gid
    }

    pub(crate) const fn tgid(&self) -> u32 {
        self.tgid
    }

    pub(crate) const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    pub(crate) const fn cgroup_digest(&self) -> ObjectDigest {
        self.cgroup_digest
    }

    pub(crate) const fn pidfd_live(&self) -> bool {
        self.pidfd_live
    }
}

/// Supplies the protected Root Mount peer policy for provider ingress.
///
/// Construction validates shape only and does not establish policy provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRootMountPeerV1 {
    authority_id: [u8; 16],
    expected_uid: u32,
    expected_gid: u32,
    expected_cgroup_digest: ObjectDigest,
}

impl ProtectedRootMountPeerV1 {
    /// Constructs one shaped Root Mount peer-policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for a sentinel authority or cgroup
    /// digest.
    pub fn new(
        authority_id: [u8; 16],
        expected_uid: u32,
        expected_gid: u32,
        expected_cgroup_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderTrustError> {
        require_nonzero("Root Mount peer authority ID", &authority_id)?;
        require_digest("Root Mount peer cgroup digest", expected_cgroup_digest)?;
        Ok(Self {
            authority_id,
            expected_uid,
            expected_gid,
            expected_cgroup_digest,
        })
    }
}

#[derive(Clone, Copy)]
struct AuthenticatedTranscript {
    binding: ObjectDigest,
    signer_set_commitment: ObjectDigest,
}

#[allow(clippy::too_many_arguments)]
fn authenticate_transcript(
    expected_client_nonce: [u8; 32],
    now_seconds: i64,
    root_mount_hello: &SignedSourceProviderHelloV1,
    provider_hello: &SignedSourceProviderHelloV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
) -> Result<AuthenticatedTranscript, SourceProviderTrustError> {
    let root_hello_key =
        trust_set.resolve_current(root_current, root_mount_hello.signer(), now_seconds)?;
    let provider_hello_key =
        trust_set.resolve_current(provider_current, provider_hello.signer(), now_seconds)?;
    verify_hello(root_mount_hello, root_hello_key)
        .map_err(|_| SourceProviderTrustError::HelloSignature)?;
    verify_hello(provider_hello, provider_hello_key)
        .map_err(|_| SourceProviderTrustError::HelloSignature)?;
    route.verify_current_authority(root_current)?;
    route.verify_current_authority(provider_current)?;

    let client = root_mount_hello.subject();
    let server = provider_hello.subject();
    let root_traffic_key =
        trust_set.resolve_current(root_current, client.traffic_signer(), now_seconds)?;
    let provider_traffic_key =
        trust_set.resolve_current(provider_current, server.traffic_signer(), now_seconds)?;
    let key_ids = [
        root_mount_hello.signer().key_id(),
        client.traffic_signer().key_id(),
        provider_hello.signer().key_id(),
        server.traffic_signer().key_id(),
    ];
    let public_keys = [
        *root_hello_key,
        *root_traffic_key,
        *provider_hello_key,
        *provider_traffic_key,
    ];
    if client.role() != SourceProviderPeerRole::RootMount
        || server.role() != SourceProviderPeerRole::Provider
        || root_current.role != SourceProviderPeerRole::RootMount
        || provider_current.role != SourceProviderPeerRole::Provider
        || root_current.authority.authority_id() == provider_current.authority.authority_id()
        || client.nonce() != expected_client_nonce
        || client.nonce() == server.nonce()
        || client.kernel_boot_id() != server.kernel_boot_id()
        || root_mount_hello.signer() != root_current.hello_signer()
        || provider_hello.signer() != provider_current.hello_signer()
        || client.traffic_signer() != root_current.traffic_signer()
        || server.traffic_signer() != provider_current.traffic_signer()
        || client.expected_peer_traffic_signer() != provider_current.traffic_signer()
        || server.expected_peer_traffic_signer() != root_current.traffic_signer()
        || has_duplicate(&key_ids)
        || has_duplicate(&public_keys)
        || server.client_hello_digest() != Some(digest_signed_hello(root_mount_hello))
        || client.route_id() != route.route_id
        || client.route_generation() != route.route_generation
        || client.route_digest() != route.route_digest
        || server.route_id() != route.route_id
        || server.route_generation() != route.route_generation
        || server.route_digest() != route.route_digest
        || client.proof_class_capabilities() & !root_current.proof_class_capabilities != 0
        || server.proof_class_capabilities() & !client.proof_class_capabilities() != 0
        || server.proof_class_capabilities() & !route.proof_class_capabilities != 0
        || server.proof_class_capabilities() & !provider_current.proof_class_capabilities != 0
        || (server.supports_recursive() && (!client.supports_recursive() || !route.allow_recursive))
        || (server.supports_kernel_coupled()
            && (!client.supports_kernel_coupled() || !route.allow_kernel_coupled))
    {
        return Err(SourceProviderTrustError::SessionMismatch);
    }

    Ok(AuthenticatedTranscript {
        binding: source_provider_session_binding_v1(root_mount_hello, provider_hello),
        signer_set_commitment: source_provider_signer_set_commitment_v1(
            root_mount_hello.signer(),
            client.traffic_signer(),
            provider_hello.signer(),
            server.traffic_signer(),
        ),
    })
}

/// Binds the provider-side view of a Root Mount peer to one signed transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderIngressSessionV1 {
    root_mount_hello: SignedSourceProviderHelloV1,
    provider_hello: SignedSourceProviderHelloV1,
    route: ProtectedSourceProviderRouteV1,
    root_mount_identity: SourceProviderProcessIdentityV1,
    binding: ObjectDigest,
    signer_set_commitment: ObjectDigest,
}

impl SourceProviderIngressSessionV1 {
    /// Authenticates a provider-side transcript and supplied Root Mount confinement.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderTrustError`] for any transcript, trust, route,
    /// currentness, process, or protected peer-policy mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate(
        expected_client_nonce: [u8; 32],
        now_seconds: i64,
        root_mount_hello: SignedSourceProviderHelloV1,
        provider_hello: SignedSourceProviderHelloV1,
        trust_set: &SourceProviderTrustSetV1,
        root_current: &SourceProviderCurrentAuthorityV1,
        provider_current: &SourceProviderCurrentAuthorityV1,
        root_connection_peer: SourceProviderProcessIdentityV1,
        root_nominated_record_subject: SourceProviderProcessIdentityV1,
        root_peer_policy: &ProtectedRootMountPeerV1,
        route: &ProtectedSourceProviderRouteV1,
    ) -> Result<Self, SourceProviderTrustError> {
        let transcript = authenticate_transcript(
            expected_client_nonce,
            now_seconds,
            &root_mount_hello,
            &provider_hello,
            trust_set,
            root_current,
            provider_current,
            route,
        )?;
        if root_connection_peer != root_nominated_record_subject
            || !root_connection_peer.pidfd_live
            || root_connection_peer.uid != root_peer_policy.expected_uid
            || root_connection_peer.gid != root_peer_policy.expected_gid
            || root_connection_peer.cgroup_digest != root_peer_policy.expected_cgroup_digest
            || root_peer_policy.authority_id != root_current.authority.authority_id()
        {
            return Err(SourceProviderTrustError::SessionMismatch);
        }
        Ok(Self {
            root_mount_hello,
            provider_hello,
            route: route.clone(),
            root_mount_identity: root_connection_peer,
            binding: transcript.binding,
            signer_set_commitment: transcript.signer_set_commitment,
        })
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    /// Returns the signed Root Mount process-instance claim.
    #[must_use]
    pub const fn root_mount_process_instance(&self) -> [u8; 16] {
        self.root_mount_hello.subject().process_instance()
    }

    /// Returns the signed provider process-instance claim.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_hello.subject().process_instance()
    }

    pub(crate) const fn root_mount_identity(&self) -> &SourceProviderProcessIdentityV1 {
        &self.root_mount_identity
    }

    pub(crate) const fn root_mount_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.root_mount_hello
    }

    pub(crate) const fn provider_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.provider_hello
    }

    pub(crate) const fn route(&self) -> &ProtectedSourceProviderRouteV1 {
        &self.route
    }

    pub(crate) const fn signer_set_commitment(&self) -> ObjectDigest {
        self.signer_set_commitment
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
    signer_set_commitment: ObjectDigest,
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
        now_seconds: i64,
        root_mount_hello: SignedSourceProviderHelloV1,
        provider_hello: SignedSourceProviderHelloV1,
        trust_set: &SourceProviderTrustSetV1,
        root_current: &SourceProviderCurrentAuthorityV1,
        provider_current: &SourceProviderCurrentAuthorityV1,
        connection_peer: SourceProviderProcessIdentityV1,
        nominated_record_subject: SourceProviderProcessIdentityV1,
        route: &ProtectedSourceProviderRouteV1,
    ) -> Result<Self, SourceProviderTrustError> {
        let transcript = authenticate_transcript(
            expected_client_nonce,
            now_seconds,
            &root_mount_hello,
            &provider_hello,
            trust_set,
            root_current,
            provider_current,
            route,
        )?;
        if connection_peer != nominated_record_subject
            || connection_peer.uid != route.expected_uid
            || connection_peer.gid != route.expected_gid
            || connection_peer.cgroup_digest != route.expected_cgroup_digest
            || !connection_peer.pidfd_live
        {
            return Err(SourceProviderTrustError::SessionMismatch);
        }
        Ok(Self {
            root_mount_hello,
            provider_hello,
            route: route.clone(),
            provider_identity: connection_peer,
            binding: transcript.binding,
            signer_set_commitment: transcript.signer_set_commitment,
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

    /// Returns the ordered four-key signer-set commitment.
    #[must_use]
    pub const fn signer_set_commitment(&self) -> ObjectDigest {
        self.signer_set_commitment
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

fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
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
}
