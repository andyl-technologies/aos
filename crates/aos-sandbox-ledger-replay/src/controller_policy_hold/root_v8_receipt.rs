//! Owns the exact historical AOSPC88A Root ACK DATA codec.
//!
//! This checksum record carries no current Root authority, verified signature,
//! held decision, writer or release grant. Native owners retain every such join.

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSPC88A";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0";
/// Bounds the existing canonical historical Root ACK record.
pub const ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1: usize = 332;

/// Preserves the original pure ACK codec's stale-data refusal.
#[derive(Debug, thiserror::Error)]
#[error("stale Root V8 effect acknowledgment")]
pub struct RootV8EffectAckDataErrorV1;

/// Retains one exact no-Apply Root receipt before Root releases its writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8EffectAckV1 {
    /// Commits the proposed policy binding.
    pub binding: ObjectDigest,
    /// Names the policy handoff epoch.
    pub epoch: u64,
    /// Names the associated public Create operation.
    pub operation: OperationId,
    /// Names the associated sandbox.
    pub sandbox: SandboxId,
    /// Names the accepted Create generation.
    pub accepted_generation: u64,
    /// Names the no-Apply effect transaction.
    pub effect_transaction: [u8; 16],
    /// Commits the signed terminal record.
    pub terminal: ObjectDigest,
    /// Commits the consumed AOSPCP02 proof.
    pub proof: ObjectDigest,
    /// Commits the complete Cache quota.
    pub quota: ObjectDigest,
    /// Commits the Controller AOSQ8K01 acknowledgment.
    pub controller_ack: ObjectDigest,
    /// Commits the signed Controller receipt packet.
    pub receipt: ObjectDigest,
    /// Names the pinned Controller signer generation.
    pub signer_generation: u64,
    /// Names the authenticated Controller UID.
    pub controller_uid: u32,
    /// Retains the Root challenge nonce.
    pub nonce: [u8; 16],
}

impl RootV8EffectAckV1 {
    /// Returns the held binding.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the Root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the accepted Create generation.
    #[must_use]
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Returns the reserved no-Apply effect transaction.
    #[must_use]
    pub const fn effect_transaction(self) -> [u8; 16] {
        self.effect_transaction
    }

    /// Returns the exact signed terminal digest.
    #[must_use]
    pub const fn terminal(self) -> ObjectDigest {
        self.terminal
    }

    /// Returns the consumed AOSPCP02 digest.
    #[must_use]
    pub const fn proof(self) -> ObjectDigest {
        self.proof
    }

    /// Returns the complete Cache quota digest.
    #[must_use]
    pub const fn quota(self) -> ObjectDigest {
        self.quota
    }

    /// Returns the protected AOSQ8K01 digest.
    #[must_use]
    pub const fn controller_ack(self) -> ObjectDigest {
        self.controller_ack
    }

    /// Returns the signed packet digest.
    #[must_use]
    pub const fn receipt(self) -> ObjectDigest {
        self.receipt
    }

    /// Returns the pinned Controller signer generation.
    #[must_use]
    pub const fn signer_generation(self) -> u64 {
        self.signer_generation
    }

    /// Returns the authenticated Controller UID.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the spent Root nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Encodes canonical bytes for authenticated transport.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields.
    pub fn record_bytes(
        self,
    ) -> Result<[u8; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1], RootV8EffectAckDataErrorV1> {
        self.encode()
    }

    /// Decodes canonical historical bytes without asserting current custody.
    ///
    /// # Errors
    ///
    /// Rejects changed or noncanonical bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootV8EffectAckDataErrorV1> {
        Self::decode(bytes)
    }

    /// Encodes the checksummed AOSPC88A Root ACK record.
    ///
    /// # Errors
    ///
    /// Rejects zero identity, generation, transaction, evidence, UID or nonce fields.
    pub fn encode(
        self,
    ) -> Result<[u8; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1], RootV8EffectAckDataErrorV1> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.terminal.as_bytes() == &[0; 32]
            || self.proof.as_bytes() == &[0; 32]
            || self.quota.as_bytes() == &[0; 32]
            || self.controller_ack.as_bytes() == &[0; 32]
            || self.receipt.as_bytes() == &[0; 32]
            || self.signer_generation == 0
            || self.controller_uid == 0
            || self.nonce == [0; 16]
        {
            return Err(RootV8EffectAckDataErrorV1);
        }
        let mut bytes = [0; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..72].copy_from_slice(self.operation.as_bytes());
        bytes[72..88].copy_from_slice(self.sandbox.as_bytes());
        bytes[88..96].copy_from_slice(&self.accepted_generation.to_be_bytes());
        bytes[96..112].copy_from_slice(&self.effect_transaction);
        bytes[112..144].copy_from_slice(self.terminal.as_bytes());
        bytes[144..176].copy_from_slice(self.proof.as_bytes());
        bytes[176..208].copy_from_slice(self.quota.as_bytes());
        bytes[208..240].copy_from_slice(self.controller_ack.as_bytes());
        bytes[240..272].copy_from_slice(self.receipt.as_bytes());
        bytes[272..280].copy_from_slice(&self.signer_generation.to_be_bytes());
        bytes[280..284].copy_from_slice(&self.controller_uid.to_be_bytes());
        bytes[284..300].copy_from_slice(&self.nonce);
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..300])
            .finalize();
        bytes[300..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes the checksummed AOSPC88A Root ACK record.
    ///
    /// # Errors
    ///
    /// Rejects wrong width, magic, version or reserved bytes, zero required fields
    /// or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, RootV8EffectAckDataErrorV1> {
        if bytes.len() != ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1
            || bytes[..8] != MAGIC[..]
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(RootV8EffectAckDataErrorV1);
        }
        let record = Self {
            binding: ObjectDigest::from_bytes(take::<32>(bytes, 16)?),
            epoch: u64::from_be_bytes(take::<8>(bytes, 48)?),
            operation: OperationId::from_bytes(take::<16>(bytes, 56)?),
            sandbox: SandboxId::from_bytes(take::<16>(bytes, 72)?),
            accepted_generation: u64::from_be_bytes(take::<8>(bytes, 88)?),
            effect_transaction: take::<16>(bytes, 96)?,
            terminal: ObjectDigest::from_bytes(take::<32>(bytes, 112)?),
            proof: ObjectDigest::from_bytes(take::<32>(bytes, 144)?),
            quota: ObjectDigest::from_bytes(take::<32>(bytes, 176)?),
            controller_ack: ObjectDigest::from_bytes(take::<32>(bytes, 208)?),
            receipt: ObjectDigest::from_bytes(take::<32>(bytes, 240)?),
            signer_generation: u64::from_be_bytes(take::<8>(bytes, 272)?),
            controller_uid: u32::from_be_bytes(take::<4>(bytes, 280)?),
            nonce: take::<16>(bytes, 284)?,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(RootV8EffectAckDataErrorV1);
        }
        Ok(record)
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], RootV8EffectAckDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(RootV8EffectAckDataErrorV1)
}
