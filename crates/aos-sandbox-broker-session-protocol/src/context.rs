//! Caller-supplied protected-context shapes for signature verification.
//!
//! Values in this module pin the route, domain, protocol, audience, execution
//! instances, and all four physical keys. Constructors validate only shape and
//! cryptographic consistency. They explicitly do not prove that a value was
//! loaded from protected storage, observed from the kernel, is fresh/current,
//! or carries authority. Peer-supplied bytes must never select these values.
//!
//! The protected-context digest uses this fixed canonical preimage:
//!
//! ```text
//! domain || domain-id[16] || route-id[16] || route-generation:u64be ||
//! route-digest[32] || trust-generation:u64be || trust-digest[32] ||
//! revocation-generation:u64be || revocation-digest[32] || node-id[16] ||
//! boot-id[16] || protocol:u8 || major:u16be || minor:u16be || audience:u8 ||
//! client-process[16] || broker-process[16] || signer-set-digest[32] ||
//! four * (signer-reference[120] || raw-key[32] ||
//!         minimum-authority-generation:u64be || minimum-key-generation:u64be ||
//!         revoked:u8 || superseded-present:u8 || superseding-generation:u64be)
//! ```

use aos_proto::aos::sandbox::local::v1::Audience;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::model::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
    BrokerSessionValidationError, audience_code, audience_from_code, require_nonzero,
};

const PROTECTED_CONTEXT_DOMAIN: &[u8] = b"aos-sandbox-broker-session-protected-context-v1\0";
const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSBSC01";
const CHECKPOINT_BYTES: usize = 8 + 2 + 222 + 4 * 178;

/// Pins one caller-selected signer reference, physical key, and currentness floors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedBrokerSessionKeyV1 {
    signer: BrokerSessionSignerReferenceV1,
    public_key: [u8; 32],
    minimum_authority_generation: u64,
    minimum_key_generation: u64,
    revoked: bool,
    superseded_by_key_generation: Option<u64>,
}

impl ProtectedBrokerSessionKeyV1 {
    /// Constructs one shape-checked, caller-supplied verification-key pin.
    ///
    /// This function does not establish protected provenance or authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for a malformed/weak key,
    /// fingerprint mismatch, zero floors, or a non-advancing supersession.
    pub fn new(
        signer: BrokerSessionSignerReferenceV1,
        public_key: [u8; 32],
        minimum_authority_generation: u64,
        minimum_key_generation: u64,
        revoked: bool,
        superseded_by_key_generation: Option<u64>,
    ) -> Result<Self, BrokerSessionValidationError> {
        require_nonzero("protected raw public key", &public_key)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| BrokerSessionValidationError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(BrokerSessionValidationError::InvalidPublicKey);
        }
        if <[u8; 32]>::from(Sha256::digest(public_key)) != signer.public_key_digest() {
            return Err(BrokerSessionValidationError::PublicKeyMismatch);
        }
        if minimum_authority_generation == 0 || minimum_key_generation == 0 {
            return Err(BrokerSessionValidationError::ZeroScalar(
                "currentness floor",
            ));
        }
        if signer.authority_generation() < minimum_authority_generation
            || signer.key_generation() < minimum_key_generation
            || superseded_by_key_generation
                .is_some_and(|generation| generation <= signer.key_generation())
        {
            return Err(BrokerSessionValidationError::InvalidClosedValue(
                "currentness floor",
            ));
        }
        Ok(Self {
            signer,
            public_key,
            minimum_authority_generation,
            minimum_key_generation,
            revoked,
            superseded_by_key_generation,
        })
    }

    /// Returns the exact locally pinned signer reference.
    #[must_use]
    pub const fn signer(&self) -> &BrokerSessionSignerReferenceV1 {
        &self.signer
    }

    /// Returns the exact locally pinned raw Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Reports whether caller-supplied currentness state permits new work.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.revoked && self.superseded_by_key_generation.is_none()
    }

    pub(crate) fn matches_active(
        &self,
        received: &BrokerSessionSignerReferenceV1,
    ) -> Result<(), BrokerSessionValidationError> {
        if !self.is_active() {
            return Err(BrokerSessionValidationError::InvalidClosedValue(
                "inactive signing key",
            ));
        }
        if received != &self.signer
            || received.authority_generation() < self.minimum_authority_generation
            || received.key_generation() < self.minimum_key_generation
        {
            return Err(BrokerSessionValidationError::InvalidClosedValue(
                "signer reference",
            ));
        }
        Ok(())
    }
}

/// Pins the complete local shape required to verify one broker session.
///
/// All values are supplied by the caller. This type neither loads protected
/// state nor establishes its provenance, freshness, currentness, process
/// identity, route ownership, or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedBrokerSessionVerificationContextV1 {
    domain_id: [u8; 16],
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: [u8; 32],
    trust_generation: u64,
    trust_digest: [u8; 32],
    revocation_generation: u64,
    revocation_digest: [u8; 32],
    node_id: [u8; 16],
    boot_id: [u8; 16],
    protocol: BrokerSessionProtocolV1,
    protocol_major: u16,
    protocol_minor: u16,
    audience: Audience,
    client_process: [u8; 16],
    broker_process: [u8; 16],
    keys: [ProtectedBrokerSessionKeyV1; 4],
}

impl ProtectedBrokerSessionVerificationContextV1 {
    /// Encodes the exact protected context as a canonical historical witness.
    ///
    /// These bytes have no authority unless a protected owner binds them to
    /// the original signed hello pair and first-request journal transaction.
    #[must_use]
    pub fn checkpoint_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CHECKPOINT_BYTES);
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.domain_id);
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(&self.route_generation.to_be_bytes());
        bytes.extend_from_slice(&self.route_digest);
        bytes.extend_from_slice(&self.trust_generation.to_be_bytes());
        bytes.extend_from_slice(&self.trust_digest);
        bytes.extend_from_slice(&self.revocation_generation.to_be_bytes());
        bytes.extend_from_slice(&self.revocation_digest);
        bytes.extend_from_slice(&self.node_id);
        bytes.extend_from_slice(&self.boot_id);
        bytes.push(self.protocol.code());
        bytes.extend_from_slice(&self.protocol_major.to_be_bytes());
        bytes.extend_from_slice(&self.protocol_minor.to_be_bytes());
        bytes.push(context_audience_code(self.audience));
        bytes.extend_from_slice(&self.client_process);
        bytes.extend_from_slice(&self.broker_process);
        for key in &self.keys {
            key.signer.encode_into(&mut bytes);
            bytes.extend_from_slice(&key.public_key);
            bytes.extend_from_slice(&key.minimum_authority_generation.to_be_bytes());
            bytes.extend_from_slice(&key.minimum_key_generation.to_be_bytes());
            bytes.push(u8::from(key.revoked));
            bytes.push(u8::from(key.superseded_by_key_generation.is_some()));
            bytes.extend_from_slice(
                &key.superseded_by_key_generation
                    .unwrap_or_default()
                    .to_be_bytes(),
            );
        }
        bytes
    }

    /// Decodes a canonical historical context without granting live authority.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or shape-invalid bytes.
    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, BrokerSessionValidationError> {
        if bytes.len() != CHECKPOINT_BYTES {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        let mut input = bytes;
        if checkpoint_field::<8>(&mut input)? != *CHECKPOINT_MAGIC
            || checkpoint_field::<2>(&mut input)? != 1_u16.to_be_bytes()
        {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        let domain_id = checkpoint_field(&mut input)?;
        let route_id = checkpoint_field(&mut input)?;
        let route_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let route_digest = checkpoint_field(&mut input)?;
        let trust_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let trust_digest = checkpoint_field(&mut input)?;
        let revocation_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let revocation_digest = checkpoint_field(&mut input)?;
        let node_id = checkpoint_field(&mut input)?;
        let boot_id = checkpoint_field(&mut input)?;
        let protocol = BrokerSessionProtocolV1::from_code(checkpoint_field::<1>(&mut input)?[0])?;
        let major = u16::from_be_bytes(checkpoint_field(&mut input)?);
        let minor = u16::from_be_bytes(checkpoint_field(&mut input)?);
        let audience = audience_from_code(checkpoint_field::<1>(&mut input)?[0])?;
        let client_process = checkpoint_field(&mut input)?;
        let broker_process = checkpoint_field(&mut input)?;
        let mut keys = Vec::with_capacity(4);
        for _ in 0..4 {
            let signer =
                BrokerSessionSignerReferenceV1::decode(checkpoint_slice(&mut input, 120)?)?;
            let public_key = checkpoint_field(&mut input)?;
            let minimum_authority_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            let minimum_key_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            let revoked = checkpoint_field::<1>(&mut input)?[0];
            let superseded = checkpoint_field::<1>(&mut input)?[0];
            let generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            if revoked > 1 || superseded > 1 || (superseded == 0 && generation != 0) {
                return Err(BrokerSessionValidationError::InvalidEncoding);
            }
            keys.push(ProtectedBrokerSessionKeyV1::new(
                signer,
                public_key,
                minimum_authority_generation,
                minimum_key_generation,
                revoked == 1,
                (superseded == 1).then_some(generation),
            )?);
        }
        let keys = keys
            .try_into()
            .map_err(|_| BrokerSessionValidationError::InvalidEncoding)?;
        let context = Self::new(
            domain_id,
            route_id,
            route_generation,
            route_digest,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            node_id,
            boot_id,
            protocol,
            major,
            minor,
            audience,
            client_process,
            broker_process,
            keys,
        )?;
        if !input.is_empty() || context.checkpoint_bytes() != bytes {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        Ok(context)
    }

    /// Constructs one complete shape-only verification context.
    ///
    /// The caller must source this value from protected configuration and
    /// independently establish process/kernel facts. Construction itself does
    /// neither and grants no authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionValidationError`] for sentinels, an unknown
    /// audience, wrong key-use order, malformed currentness state, or any
    /// repeated signer reference, stable key ID, or physical raw public key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: [u8; 16],
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: [u8; 32],
        trust_generation: u64,
        trust_digest: [u8; 32],
        revocation_generation: u64,
        revocation_digest: [u8; 32],
        node_id: [u8; 16],
        boot_id: [u8; 16],
        protocol: BrokerSessionProtocolV1,
        protocol_major: u16,
        protocol_minor: u16,
        audience: Audience,
        client_process: [u8; 16],
        broker_process: [u8; 16],
        keys: [ProtectedBrokerSessionKeyV1; 4],
    ) -> Result<Self, BrokerSessionValidationError> {
        require_nonzero("broker domain ID", &domain_id)?;
        require_nonzero("broker route ID", &route_id)?;
        require_generation(route_generation)?;
        require_nonzero("broker route digest", &route_digest)?;
        require_generation(trust_generation)?;
        require_nonzero("broker trust digest", &trust_digest)?;
        require_generation(revocation_generation)?;
        require_nonzero("broker revocation digest", &revocation_digest)?;
        require_nonzero("node ID", &node_id)?;
        require_nonzero("boot ID", &boot_id)?;
        require_generation(u64::from(protocol_major))?;
        audience_code(audience)?;
        require_nonzero("client process ID", &client_process)?;
        require_nonzero("broker process ID", &broker_process)?;
        if client_process == broker_process {
            return Err(BrokerSessionValidationError::SignersNotDistinct);
        }
        let uses = [
            BrokerSessionKeyUsageV1::ClientHello,
            BrokerSessionKeyUsageV1::BrokerHello,
            BrokerSessionKeyUsageV1::ClientRecord,
            BrokerSessionKeyUsageV1::BrokerOutcome,
        ];
        if keys
            .iter()
            .zip(uses)
            .any(|(key, usage)| key.signer().usage() != usage)
        {
            return Err(BrokerSessionValidationError::InvalidClosedValue(
                "key role/currentness",
            ));
        }
        for left in 0..keys.len() {
            for right in left + 1..keys.len() {
                if keys[left].signer() == keys[right].signer()
                    || keys[left].signer().key_id() == keys[right].signer().key_id()
                    || keys[left].public_key() == keys[right].public_key()
                {
                    return Err(BrokerSessionValidationError::SignersNotDistinct);
                }
            }
        }
        Ok(Self {
            domain_id,
            route_id,
            route_generation,
            route_digest,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            node_id,
            boot_id,
            protocol,
            protocol_major,
            protocol_minor,
            audience,
            client_process,
            broker_process,
            keys,
        })
    }

    /// Returns the pinned node identity.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }
    /// Returns the pinned kernel boot identity.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }
    /// Returns the pinned broker protocol code.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.protocol
    }
    /// Returns the pinned protocol major.
    #[must_use]
    pub const fn protocol_major(&self) -> u16 {
        self.protocol_major
    }
    /// Returns the pinned protocol minor.
    #[must_use]
    pub const fn protocol_minor(&self) -> u16 {
        self.protocol_minor
    }
    /// Returns the pinned client audience.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }
    /// Returns the pinned client execution identity.
    #[must_use]
    pub const fn client_process(&self) -> [u8; 16] {
        self.client_process
    }
    /// Returns the pinned broker execution identity.
    #[must_use]
    pub const fn broker_process(&self) -> [u8; 16] {
        self.broker_process
    }
    /// Returns the four ordered, locally pinned role keys.
    #[must_use]
    pub const fn keys(&self) -> &[ProtectedBrokerSessionKeyV1; 4] {
        &self.keys
    }

    /// Returns the locally selected broker-domain ID.
    #[must_use]
    pub const fn domain_id(&self) -> [u8; 16] {
        self.domain_id
    }

    /// Returns the locally selected route ID, generation, and digest.
    #[must_use]
    pub const fn route(&self) -> ([u8; 16], u64, [u8; 32]) {
        (self.route_id, self.route_generation, self.route_digest)
    }

    /// Returns the caller-supplied trust generation and digest.
    #[must_use]
    pub const fn trust_state(&self) -> (u64, [u8; 32]) {
        (self.trust_generation, self.trust_digest)
    }

    /// Returns the caller-supplied revocation generation and digest.
    #[must_use]
    pub const fn revocation_state(&self) -> (u64, [u8; 32]) {
        (self.revocation_generation, self.revocation_digest)
    }

    /// Computes the exact digest committed by both signed hello subjects.
    ///
    /// The digest binds every fixed route, trust, revocation, execution, key,
    /// and currentness component. It does not prove where those values came
    /// from or that a caller persisted them.
    #[must_use]
    pub fn protected_context_digest(&self) -> [u8; 32] {
        let signers = self.keys.each_ref().map(|key| key.signer.clone());
        let signer_set = crate::artifact::signer_set_digest_v1(&signers);
        let mut hasher = Sha256::new();
        hasher.update(PROTECTED_CONTEXT_DOMAIN);
        hasher.update(self.domain_id);
        hasher.update(self.route_id);
        hasher.update(self.route_generation.to_be_bytes());
        hasher.update(self.route_digest);
        hasher.update(self.trust_generation.to_be_bytes());
        hasher.update(self.trust_digest);
        hasher.update(self.revocation_generation.to_be_bytes());
        hasher.update(self.revocation_digest);
        hasher.update(self.node_id);
        hasher.update(self.boot_id);
        hasher.update([self.protocol.code()]);
        hasher.update(self.protocol_major.to_be_bytes());
        hasher.update(self.protocol_minor.to_be_bytes());
        hasher.update([context_audience_code(self.audience)]);
        hasher.update(self.client_process);
        hasher.update(self.broker_process);
        hasher.update(signer_set);
        for key in &self.keys {
            let mut signer = Vec::with_capacity(120);
            key.signer.encode_into(&mut signer);
            hasher.update(signer);
            hasher.update(key.public_key);
            hasher.update(key.minimum_authority_generation.to_be_bytes());
            hasher.update(key.minimum_key_generation.to_be_bytes());
            hasher.update([u8::from(key.revoked)]);
            hasher.update([u8::from(key.superseded_by_key_generation.is_some())]);
            hasher.update(
                key.superseded_by_key_generation
                    .unwrap_or_default()
                    .to_be_bytes(),
            );
        }
        hasher.finalize().into()
    }

    pub(crate) fn require_all_active(&self) -> Result<(), BrokerSessionValidationError> {
        for key in &self.keys {
            key.matches_active(&key.signer)?;
        }
        Ok(())
    }

    pub(crate) fn key(&self, usage: BrokerSessionKeyUsageV1) -> &ProtectedBrokerSessionKeyV1 {
        &self.keys[usage.index()]
    }
}

const fn context_audience_code(audience: Audience) -> u8 {
    match audience {
        Audience::AUDIENCE_NODE_CONTROLLER => 1,
        Audience::AUDIENCE_ASSIGNMENT_GUARDIAN => 2,
        Audience::AUDIENCE_MOUNT_WORKER => 3,
        Audience::AUDIENCE_GUEST_AGENT => 4,
        Audience::AUDIENCE_ROOT_MOUNT => 5,
        Audience::AUDIENCE_STORAGE_BROKER => 6,
        Audience::AUDIENCE_UNSPECIFIED => 0,
    }
}

fn require_generation(value: u64) -> Result<(), BrokerSessionValidationError> {
    if value == 0 {
        Err(BrokerSessionValidationError::ZeroScalar("generation"))
    } else {
        Ok(())
    }
}

fn checkpoint_slice<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], BrokerSessionValidationError> {
    let (field, rest) = input
        .split_at_checked(length)
        .ok_or(BrokerSessionValidationError::InvalidEncoding)?;
    *input = rest;
    Ok(field)
}

fn checkpoint_field<const N: usize>(
    input: &mut &[u8],
) -> Result<[u8; N], BrokerSessionValidationError> {
    checkpoint_slice(input, N)?
        .try_into()
        .map_err(|_| BrokerSessionValidationError::InvalidEncoding)
}
