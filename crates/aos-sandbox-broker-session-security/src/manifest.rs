//! Compatibility API for the sole lower pure AOSBSC01 manifest codec.
//!
//! The protocol crate owns all byte parsing, shape and cryptographic key checks.
//! This facade preserves Security's public types and redacted error contract;
//! neither layer turns decoded manifest data into protected endpoint authority.

use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
    ProtectedBrokerSessionVerificationContextV1,
};
use aos_sandbox_broker_session_protocol::manifest::{
    BROKER_SESSION_MANIFEST_BYTES, BrokerSessionManifestErrorV1,
    BrokerSessionManifestKeyPinV1, BrokerSessionManifestV1,
};

use crate::BrokerSessionSecurityError;

#[cfg(test)]
use aos_sandbox_broker_session_protocol::BrokerSessionKeyUsageV1;

pub use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1 as BrokerSessionSecurityAudienceV1,
    BrokerSessionManifestBindingV1,
};

/// Exact byte length of the unchanged AOSBSC01 manifest.
pub const BROKER_SESSION_SECURITY_MANIFEST_BYTES: usize = BROKER_SESSION_MANIFEST_BYTES;

const KEY_COUNT: usize = 4;

fn security_error(error: BrokerSessionManifestErrorV1) -> BrokerSessionSecurityError {
    BrokerSessionSecurityError::manifest(error.field)
}

/// Retains one shape-checked role pin through the existing Security API.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerSessionSecurityKeyPinV1(BrokerSessionManifestKeyPinV1);

impl core::fmt::Debug for BrokerSessionSecurityKeyPinV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionSecurityKeyPinV1([redacted])")
    }
}

impl BrokerSessionSecurityKeyPinV1 {
    /// Constructs one pure role pin without conferring protected provenance.
    ///
    /// # Errors
    /// Preserves the existing redacted key-pin rejection for invalid keys,
    /// fingerprints, generation floors and supersession generations.
    pub fn new(
        signer: BrokerSessionSignerReferenceV1,
        public_key: [u8; 32],
        minimum_authority_generation: u64,
        minimum_key_generation: u64,
        revoked: bool,
        superseded_by_key_generation: Option<u64>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        BrokerSessionManifestKeyPinV1::new(
            signer,
            public_key,
            minimum_authority_generation,
            minimum_key_generation,
            revoked,
            superseded_by_key_generation,
        )
        .map(Self)
        .map_err(security_error)
    }

    /// Returns the exact pinned signer reference.
    #[must_use]
    pub const fn signer(&self) -> &BrokerSessionSignerReferenceV1 {
        self.0.signer()
    }

    /// Returns the exact raw public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        self.0.public_key()
    }

    /// Returns the minimum admitted authority generation.
    #[must_use]
    pub const fn minimum_authority_generation(&self) -> u64 {
        self.0.minimum_authority_generation()
    }

    /// Returns the minimum admitted key generation.
    #[must_use]
    pub const fn minimum_key_generation(&self) -> u64 {
        self.0.minimum_key_generation()
    }

    /// Reports whether the pure pin is revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.0.is_revoked()
    }

    /// Returns the advancing superseding key generation, if present.
    #[must_use]
    pub const fn superseded_by_key_generation(&self) -> Option<u64> {
        self.0.superseded_by_key_generation()
    }

    /// Reports whether the pure pin admits new work.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.0.is_active()
    }
}

/// Preserves the existing Security API for the sole lower canonical codec.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerSessionSecurityManifestV1 {
    inner: BrokerSessionManifestV1,
    keys: [BrokerSessionSecurityKeyPinV1; KEY_COUNT],
}

impl core::fmt::Debug for BrokerSessionSecurityManifestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionSecurityManifestV1([redacted])")
    }
}

impl BrokerSessionSecurityManifestV1 {
    /// Constructs the existing shape-only manifest without granting authority.
    ///
    /// # Errors
    /// Preserves all existing redacted field failures from the lower codec.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: BrokerSessionProtocolV1,
        audience: BrokerSessionSecurityAudienceV1,
        major: u16,
        minor: u16,
        domain_id: [u8; 16],
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: [u8; 32],
        trust_generation: u64,
        trust_digest: [u8; 32],
        revocation_generation: u64,
        revocation_digest: [u8; 32],
        node_id: [u8; 16],
        keys: [BrokerSessionSecurityKeyPinV1; KEY_COUNT],
    ) -> Result<Self, BrokerSessionSecurityError> {
        let inner = BrokerSessionManifestV1::new(
            protocol, audience, major, minor, domain_id, route_id,
            route_generation, route_digest, trust_generation, trust_digest,
            revocation_generation, revocation_digest, node_id,
            keys.each_ref().map(|key| key.0.clone()),
        )
        .map_err(security_error)?;
        Ok(Self { inner, keys })
    }

    /// Decodes the unchanged exact canonical 920-byte manifest.
    ///
    /// # Errors
    /// Preserves every original length, magic, offset, reserved-byte, key,
    /// audience, version, ordering, sentinel and currentness-shape error class.
    pub fn decode(input: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        let inner = BrokerSessionManifestV1::decode(input).map_err(security_error)?;
        let keys = inner.key_pins().each_ref().map(|key| {
            BrokerSessionSecurityKeyPinV1(key.clone())
        });
        Ok(Self { inner, keys })
    }

    /// Encodes the same exact canonical manifest bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; BROKER_SESSION_SECURITY_MANIFEST_BYTES] {
        self.inner.encode()
    }

    /// Returns the unchanged purpose-separated exact manifest binding.
    #[must_use]
    pub fn binding(&self) -> BrokerSessionManifestBindingV1 {
        self.inner.binding()
    }

    /// Returns the unchanged broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.inner.protocol()
    }

    /// Returns the unchanged closed audience.
    #[must_use]
    pub const fn audience(&self) -> BrokerSessionSecurityAudienceV1 {
        self.inner.audience()
    }

    /// Returns the unchanged exact protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> (u16, u16) {
        self.inner.protocol_version()
    }

    /// Returns the unchanged broker domain identity.
    #[must_use]
    pub const fn domain_id(&self) -> [u8; 16] {
        self.inner.domain_id()
    }

    /// Returns the unchanged broker route identity.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.inner.route_id()
    }

    /// Returns the unchanged route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.inner.route_generation()
    }

    /// Returns the unchanged route digest.
    #[must_use]
    pub const fn route_digest(&self) -> [u8; 32] {
        self.inner.route_digest()
    }

    /// Returns the unchanged trust generation.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.inner.trust_generation()
    }

    /// Returns the unchanged trust digest.
    #[must_use]
    pub const fn trust_digest(&self) -> [u8; 32] {
        self.inner.trust_digest()
    }

    /// Returns the unchanged revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.inner.revocation_generation()
    }

    /// Returns the unchanged revocation digest.
    #[must_use]
    pub const fn revocation_digest(&self) -> [u8; 32] {
        self.inner.revocation_digest()
    }

    /// Returns the unchanged node identity.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.inner.node_id()
    }

    /// Returns the four original API role pins in the unchanged order.
    #[must_use]
    pub const fn key_pins(&self) -> &[BrokerSessionSecurityKeyPinV1; KEY_COUNT] {
        &self.keys
    }

    pub(crate) fn require_all_active(&self) -> Result<(), BrokerSessionSecurityError> {
        self.inner.require_all_active().map_err(security_error)
    }

    pub(crate) fn verification_context(
        &self,
        boot_id: [u8; 16],
        client_process: [u8; 16],
        broker_process: [u8; 16],
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.inner.verification_context(boot_id, client_process, broker_process)
            .map_err(security_error)
    }
}

#[cfg(test)]
const fn key_usages() -> [BrokerSessionKeyUsageV1; KEY_COUNT] {
    [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ]
}

#[cfg(test)]
mod tests;
