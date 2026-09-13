//! Fixed protected Broker Session Authentication manifest.
//!
//! The format is exactly 920 bytes and has no extensions or trailing bytes:
//!
//! ```text
//! AOSBSC01 || version:u16be=1 || protocol:u8 || audience:u8 ||
//! major:u16be || minor:u16be || domain-id[16] || route-id[16] ||
//! route-generation:u64be || route-digest[32] || trust-generation:u64be ||
//! trust-digest[32] || revocation-generation:u64be ||
//! revocation-digest[32] || node-id[16] ||
//! four * (signer-reference[120] || raw-public-key[32] ||
//!         minimum-authority-generation:u64be ||
//!         minimum-key-generation:u64be || revoked:u8 ||
//!         superseded-present:u8 || reserved[6]=0 ||
//!         superseding-key-generation:u64be)
//! ```
//!
//! The four pins are ordered ClientHello, BrokerHello, ClientRecord, then
//! BrokerOutcome. Decoding establishes only canonical shape and cryptographic
//! self-consistency; it does not establish protected provenance or authority.

use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_SIGNER_REFERENCE_BYTES, BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
    BrokerSessionSignerReferenceV1, ProtectedBrokerSessionKeyV1,
    supported_broker_session_version_v1,
};
use sha2::{Digest as _, Sha256};

use crate::BrokerSessionSecurityError;

/// Exact byte length of an `AOSBSC01` manifest.
pub const BROKER_SESSION_SECURITY_MANIFEST_BYTES: usize = 920;
const MANIFEST_MAGIC: &[u8; 8] = b"AOSBSC01";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_PREFIX_BYTES: usize = 184;
const KEY_PIN_BYTES: usize = 184;
const KEY_COUNT: usize = 4;
const MANIFEST_BINDING_DOMAIN: &[u8] = b"aos-sandbox-broker-session-manifest-v1\0";

const _: () = assert!(
    MANIFEST_PREFIX_BYTES + (KEY_COUNT * KEY_PIN_BYTES) == BROKER_SESSION_SECURITY_MANIFEST_BYTES
);
const _: () = assert!(BROKER_SESSION_SIGNER_REFERENCE_BYTES == 120);

/// Identifies the exact protobuf audience admitted by a protected manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrokerSessionSecurityAudienceV1 {
    /// The node controller audience used by every broker protocol.
    NodeController,
    /// The root-mount audience used only by the Host broker protocol.
    RootMount,
}

impl BrokerSessionSecurityAudienceV1 {
    const fn code(self) -> u8 {
        match self {
            Self::NodeController => 1,
            Self::RootMount => 5,
        }
    }

    const fn decode(code: u8) -> Result<Self, BrokerSessionSecurityError> {
        match code {
            1 => Ok(Self::NodeController),
            5 => Ok(Self::RootMount),
            _ => Err(BrokerSessionSecurityError::manifest("audience")),
        }
    }
}

/// Holds a manifest-binding digest without conferring authority.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BrokerSessionManifestBindingV1([u8; 32]);

impl BrokerSessionManifestBindingV1 {
    /// Returns the exact manifest-binding digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for BrokerSessionManifestBindingV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionManifestBindingV1([redacted])")
    }
}

/// Pins one signing role and its manifest currentness state.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerSessionSecurityKeyPinV1 {
    signer: BrokerSessionSignerReferenceV1,
    public_key: [u8; 32],
    minimum_authority_generation: u64,
    minimum_key_generation: u64,
    revoked: bool,
    superseded_by_key_generation: Option<u64>,
}

impl core::fmt::Debug for BrokerSessionSecurityKeyPinV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionSecurityKeyPinV1([redacted])")
    }
}

impl BrokerSessionSecurityKeyPinV1 {
    /// Constructs one cryptographically self-consistent manifest key pin.
    ///
    /// Construction validates shape only and grants no authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for a malformed or weak key,
    /// fingerprint mismatch, invalid generation floor, or non-advancing
    /// supersession generation.
    pub fn new(
        signer: BrokerSessionSignerReferenceV1,
        public_key: [u8; 32],
        minimum_authority_generation: u64,
        minimum_key_generation: u64,
        revoked: bool,
        superseded_by_key_generation: Option<u64>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        ProtectedBrokerSessionKeyV1::new(
            signer.clone(),
            public_key,
            minimum_authority_generation,
            minimum_key_generation,
            revoked,
            superseded_by_key_generation,
        )
        .map_err(|_| BrokerSessionSecurityError::manifest("key pin"))?;

        Ok(Self {
            signer,
            public_key,
            minimum_authority_generation,
            minimum_key_generation,
            revoked,
            superseded_by_key_generation,
        })
    }

    /// Returns the exact pinned signer reference.
    #[must_use]
    pub const fn signer(&self) -> &BrokerSessionSignerReferenceV1 {
        &self.signer
    }

    /// Returns the exact raw Ed25519 verification key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the minimum admitted authority generation.
    #[must_use]
    pub const fn minimum_authority_generation(&self) -> u64 {
        self.minimum_authority_generation
    }

    /// Returns the minimum admitted key generation.
    #[must_use]
    pub const fn minimum_key_generation(&self) -> u64 {
        self.minimum_key_generation
    }

    /// Reports whether protected revocation state rejects the key.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns the advancing generation that superseded this key, if any.
    #[must_use]
    pub const fn superseded_by_key_generation(&self) -> Option<u64> {
        self.superseded_by_key_generation
    }

    /// Reports whether the pin admits new session work.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.revoked && self.superseded_by_key_generation.is_none()
    }

    fn encode_into(&self, output: &mut [u8]) {
        encode_signer_reference(&self.signer, &mut output[..120]);
        output[120..152].copy_from_slice(&self.public_key);
        output[152..160].copy_from_slice(&self.minimum_authority_generation.to_be_bytes());
        output[160..168].copy_from_slice(&self.minimum_key_generation.to_be_bytes());
        output[168] = u8::from(self.revoked);
        output[169] = u8::from(self.superseded_by_key_generation.is_some());
        output[170..176].fill(0);
        output[176..184].copy_from_slice(
            &self
                .superseded_by_key_generation
                .unwrap_or_default()
                .to_be_bytes(),
        );
    }

    fn decode(
        input: &[u8],
        expected_usage: BrokerSessionKeyUsageV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if input.len() != KEY_PIN_BYTES || input[170..176].iter().any(|byte| *byte != 0) {
            return Err(BrokerSessionSecurityError::manifest("key pin encoding"));
        }
        let revoked = decode_boolean(input[168], "revoked")?;
        let superseded_present = decode_boolean(input[169], "superseded presence")?;
        let superseding_generation = read_u64(input, 176)?;
        let superseded_by_key_generation = match (superseded_present, superseding_generation) {
            (false, 0) => None,
            (true, generation) if generation != 0 => Some(generation),
            _ => return Err(BrokerSessionSecurityError::manifest("supersession")),
        };
        let signer = decode_signer_reference(&input[..120])?;
        if signer.usage() != expected_usage {
            return Err(BrokerSessionSecurityError::manifest("key pin order"));
        }

        Self::new(
            signer,
            read_array(input, 120)?,
            read_u64(input, 152)?,
            read_u64(input, 160)?,
            revoked,
            superseded_by_key_generation,
        )
    }
}

/// Models one exact, non-authorizing `AOSBSC01` security manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerSessionSecurityManifestV1 {
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
}

impl core::fmt::Debug for BrokerSessionSecurityManifestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionSecurityManifestV1([redacted])")
    }
}

impl BrokerSessionSecurityManifestV1 {
    /// Constructs one shape-checked security manifest without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for sentinel routing fields, a
    /// wrong protocol version or audience, misordered key roles, or repeated
    /// signer references, stable key IDs, or physical public keys.
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
        if (major, minor) != supported_broker_session_version_v1(protocol) {
            return Err(BrokerSessionSecurityError::manifest("protocol version"));
        }
        if audience == BrokerSessionSecurityAudienceV1::RootMount
            && protocol != BrokerSessionProtocolV1::Host
        {
            return Err(BrokerSessionSecurityError::manifest("protocol audience"));
        }
        require_nonzero("domain ID", &domain_id)?;
        require_nonzero("route ID", &route_id)?;
        require_nonzero_scalar("route generation", route_generation)?;
        require_nonzero("route digest", &route_digest)?;
        require_nonzero_scalar("trust generation", trust_generation)?;
        require_nonzero("trust digest", &trust_digest)?;
        require_nonzero_scalar("revocation generation", revocation_generation)?;
        require_nonzero("revocation digest", &revocation_digest)?;
        require_nonzero("node ID", &node_id)?;

        let expected_usages = key_usages();
        if keys
            .iter()
            .zip(expected_usages)
            .any(|(key, usage)| key.signer().usage() != usage)
        {
            return Err(BrokerSessionSecurityError::manifest("key pin order"));
        }
        for left in 0..keys.len() {
            for right in left + 1..keys.len() {
                if keys[left].signer() == keys[right].signer()
                    || keys[left].signer().key_id() == keys[right].signer().key_id()
                    || keys[left].public_key() == keys[right].public_key()
                {
                    return Err(BrokerSessionSecurityError::manifest("key pin distinctness"));
                }
            }
        }

        Ok(Self {
            protocol,
            audience,
            major,
            minor,
            domain_id,
            route_id,
            route_generation,
            route_digest,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            node_id,
            keys,
        })
    }

    /// Decodes one exact canonical 920-byte manifest.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for every wrong length, magic,
    /// version, closed code, reserved byte, sentinel, inconsistent key, or
    /// noncanonical currentness value.
    pub fn decode(input: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        if input.len() != BROKER_SESSION_SECURITY_MANIFEST_BYTES {
            return Err(BrokerSessionSecurityError::manifest("length"));
        }
        if &input[..8] != MANIFEST_MAGIC {
            return Err(BrokerSessionSecurityError::manifest("magic"));
        }
        if read_u16(input, 8)? != MANIFEST_VERSION {
            return Err(BrokerSessionSecurityError::manifest("version"));
        }
        let protocol = decode_protocol(input[10])?;
        let audience = BrokerSessionSecurityAudienceV1::decode(input[11])?;
        let keys = [
            BrokerSessionSecurityKeyPinV1::decode(
                &input[184..368],
                BrokerSessionKeyUsageV1::ClientHello,
            )?,
            BrokerSessionSecurityKeyPinV1::decode(
                &input[368..552],
                BrokerSessionKeyUsageV1::BrokerHello,
            )?,
            BrokerSessionSecurityKeyPinV1::decode(
                &input[552..736],
                BrokerSessionKeyUsageV1::ClientRecord,
            )?,
            BrokerSessionSecurityKeyPinV1::decode(
                &input[736..920],
                BrokerSessionKeyUsageV1::BrokerOutcome,
            )?,
        ];

        Self::new(
            protocol,
            audience,
            read_u16(input, 12)?,
            read_u16(input, 14)?,
            read_array(input, 16)?,
            read_array(input, 32)?,
            read_u64(input, 48)?,
            read_array(input, 56)?,
            read_u64(input, 88)?,
            read_array(input, 96)?,
            read_u64(input, 128)?,
            read_array(input, 136)?,
            read_array(input, 168)?,
            keys,
        )
    }

    /// Encodes the exact canonical 920-byte manifest.
    #[must_use]
    pub fn encode(&self) -> [u8; BROKER_SESSION_SECURITY_MANIFEST_BYTES] {
        let mut output = [0_u8; BROKER_SESSION_SECURITY_MANIFEST_BYTES];
        output[..8].copy_from_slice(MANIFEST_MAGIC);
        output[8..10].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
        output[10] = protocol_code(self.protocol);
        output[11] = self.audience.code();
        output[12..14].copy_from_slice(&self.major.to_be_bytes());
        output[14..16].copy_from_slice(&self.minor.to_be_bytes());
        output[16..32].copy_from_slice(&self.domain_id);
        output[32..48].copy_from_slice(&self.route_id);
        output[48..56].copy_from_slice(&self.route_generation.to_be_bytes());
        output[56..88].copy_from_slice(&self.route_digest);
        output[88..96].copy_from_slice(&self.trust_generation.to_be_bytes());
        output[96..128].copy_from_slice(&self.trust_digest);
        output[128..136].copy_from_slice(&self.revocation_generation.to_be_bytes());
        output[136..168].copy_from_slice(&self.revocation_digest);
        output[168..184].copy_from_slice(&self.node_id);
        for (index, key) in self.keys.iter().enumerate() {
            let start = MANIFEST_PREFIX_BYTES + (index * KEY_PIN_BYTES);
            key.encode_into(&mut output[start..start + KEY_PIN_BYTES]);
        }
        output
    }

    /// Computes the independently domain-separated binding of the exact manifest.
    #[must_use]
    pub fn binding(&self) -> BrokerSessionManifestBindingV1 {
        let exact = self.encode();
        let mut digest = Sha256::new();
        digest.update(MANIFEST_BINDING_DOMAIN);
        digest.update((BROKER_SESSION_SECURITY_MANIFEST_BYTES as u32).to_be_bytes());
        digest.update(exact);
        BrokerSessionManifestBindingV1(digest.finalize().into())
    }

    /// Returns the manifest broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the exact protobuf audience represented by the manifest.
    #[must_use]
    pub const fn audience(&self) -> BrokerSessionSecurityAudienceV1 {
        self.audience
    }

    /// Returns the exact protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> (u16, u16) {
        (self.major, self.minor)
    }

    /// Returns the pinned broker domain identifier.
    #[must_use]
    pub const fn domain_id(&self) -> [u8; 16] {
        self.domain_id
    }

    /// Returns the pinned broker route identifier.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }

    /// Returns the route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.route_generation
    }

    /// Returns the route-state digest.
    #[must_use]
    pub const fn route_digest(&self) -> [u8; 32] {
        self.route_digest
    }

    /// Returns the trust generation.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the trust-state digest.
    #[must_use]
    pub const fn trust_digest(&self) -> [u8; 32] {
        self.trust_digest
    }

    /// Returns the revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the revocation-state digest.
    #[must_use]
    pub const fn revocation_digest(&self) -> [u8; 32] {
        self.revocation_digest
    }

    /// Returns the pinned node identifier.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }

    /// Returns the four ordered role pins.
    #[must_use]
    pub const fn key_pins(&self) -> &[BrokerSessionSecurityKeyPinV1; KEY_COUNT] {
        &self.keys
    }

    pub(crate) fn require_all_active(&self) -> Result<(), BrokerSessionSecurityError> {
        if self
            .keys
            .iter()
            .all(BrokerSessionSecurityKeyPinV1::is_active)
        {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::manifest("inactive key pin"))
        }
    }
}

const fn key_usages() -> [BrokerSessionKeyUsageV1; KEY_COUNT] {
    [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ]
}

const fn protocol_code(protocol: BrokerSessionProtocolV1) -> u8 {
    match protocol {
        BrokerSessionProtocolV1::Host => 1,
        BrokerSessionProtocolV1::Storage => 2,
        BrokerSessionProtocolV1::Mount => 3,
        BrokerSessionProtocolV1::Network => 4,
    }
}

const fn decode_protocol(code: u8) -> Result<BrokerSessionProtocolV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionProtocolV1::Host),
        2 => Ok(BrokerSessionProtocolV1::Storage),
        3 => Ok(BrokerSessionProtocolV1::Mount),
        4 => Ok(BrokerSessionProtocolV1::Network),
        _ => Err(BrokerSessionSecurityError::manifest("protocol")),
    }
}

fn encode_signer_reference(signer: &BrokerSessionSignerReferenceV1, output: &mut [u8]) {
    output[..16].copy_from_slice(&signer.authority_id());
    output[16..24].copy_from_slice(&signer.authority_generation().to_be_bytes());
    output[24..56].copy_from_slice(&signer.authority_digest());
    output[56..72].copy_from_slice(&signer.key_id());
    output[72..80].copy_from_slice(&signer.key_generation().to_be_bytes());
    output[80..112].copy_from_slice(&signer.public_key_digest());
    output[112] = usage_code(signer.usage());
    output[113..120].fill(0);
}

fn decode_signer_reference(
    input: &[u8],
) -> Result<BrokerSessionSignerReferenceV1, BrokerSessionSecurityError> {
    if input.len() != BROKER_SESSION_SIGNER_REFERENCE_BYTES
        || input[113..120].iter().any(|byte| *byte != 0)
    {
        return Err(BrokerSessionSecurityError::manifest(
            "signer reference encoding",
        ));
    }
    BrokerSessionSignerReferenceV1::new(
        read_array(input, 0)?,
        read_u64(input, 16)?,
        read_array(input, 24)?,
        read_array(input, 56)?,
        read_u64(input, 72)?,
        read_array(input, 80)?,
        decode_usage(input[112])?,
    )
    .map_err(|_| BrokerSessionSecurityError::manifest("signer reference"))
}

const fn usage_code(usage: BrokerSessionKeyUsageV1) -> u8 {
    match usage {
        BrokerSessionKeyUsageV1::ClientHello => 1,
        BrokerSessionKeyUsageV1::BrokerHello => 2,
        BrokerSessionKeyUsageV1::ClientRecord => 3,
        BrokerSessionKeyUsageV1::BrokerOutcome => 4,
    }
}

const fn decode_usage(code: u8) -> Result<BrokerSessionKeyUsageV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionKeyUsageV1::ClientHello),
        2 => Ok(BrokerSessionKeyUsageV1::BrokerHello),
        3 => Ok(BrokerSessionKeyUsageV1::ClientRecord),
        4 => Ok(BrokerSessionKeyUsageV1::BrokerOutcome),
        _ => Err(BrokerSessionSecurityError::manifest("key usage")),
    }
}

const fn decode_boolean(
    value: u8,
    field: &'static str,
) -> Result<bool, BrokerSessionSecurityError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BrokerSessionSecurityError::manifest(field)),
    }
}

fn require_nonzero<const N: usize>(
    field: &'static str,
    value: &[u8; N],
) -> Result<(), BrokerSessionSecurityError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(BrokerSessionSecurityError::manifest(field))
    } else {
        Ok(())
    }
}

const fn require_nonzero_scalar(
    field: &'static str,
    value: u64,
) -> Result<(), BrokerSessionSecurityError> {
    if value == 0 {
        Err(BrokerSessionSecurityError::manifest(field))
    } else {
        Ok(())
    }
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    input
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| BrokerSessionSecurityError::manifest("length"))
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, BrokerSessionSecurityError> {
    Ok(u16::from_be_bytes(read_array(input, offset)?))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, BrokerSessionSecurityError> {
    Ok(u64::from_be_bytes(read_array(input, offset)?))
}

#[cfg(test)]
mod tests;
