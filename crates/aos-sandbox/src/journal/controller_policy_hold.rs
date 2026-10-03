//! Controller-wide durable custody for one closed policy-binding proposal.
//!
//! ```text
//! AOSCTH01 | version=1 | phase=held|released | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! SHA-256[32]
//! AOSQ8A01 | version=1 | state=terminal-prepared | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! exact-Root-terminal-digest[32] | SHA-256[32]
//! AOSQ8K01 | version=1 | state=acknowledged-no-Apply | reserved[5]=0 |
//! AOSQ8A01[184] | accepted-generation[8] | effect-transaction[16] |
//! consumed-AOSPCP02-digest[32] | Cache-quota-digest[32] | SHA-256[32]
//! AOSQ8R01 | version=1 | reserved[6]=0 | AOSPC88A[332] | SHA-256[32]
//! AOSCTA01 | version=1 | state=acknowledged-no-Apply | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! accepted-generation[8] | effect-transaction[16] | Root-proof-digest[32] |
//! SHA-256[32]
//! ```
//!
//! The hold freezes ordinary Controller mutations across crash and reopen.
//! Only exact private no-Apply acknowledgment and release transitions can
//! write while held. Neither freezes other owners nor authorizes public Create,
//! policy publication, or Apply. The AOSQ8F01 and AOSQ8S01 rows have private
//! codecs in `v8_pre_release_floor` and `v8_settlement`.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::policy_compiler::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};

use super::{
    CachePolicyHoldV1, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
    SourceDomainPolicyHoldV1,
};

mod v8_pre_release_floor;
mod v8_settlement;

pub(crate) use v8_pre_release_floor::ControllerPolicyV8PreReleaseFloorV1;
use v8_pre_release_floor::{
    KEY as V8_FLOOR_KEY, RECORD_BYTES as V8_FLOOR_RECORD_BYTES,
    TRANSACTION_DOMAIN as V8_FLOOR_TRANSACTION_DOMAIN,
};
pub(crate) use v8_settlement::{
    ControllerPolicyV8ReleaseEvidenceV1, ControllerPolicyV8SettlementV1,
};

const KEY: &[u8] = b"\0aos-controller-policy-hold-v1\0";
const MAGIC: &[u8; 8] = b"AOSCTH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold-transaction.v1\0";
const RECORD_BYTES: usize = 152;
const ACK_KEY: &[u8] = b"\0aos-controller-policy-effect-ack-v1\0";
const ACK_MAGIC: &[u8; 8] = b"AOSCTA01";
const ACK_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-effect-ack.v1\0";
const ACK_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-effect-ack-transaction.v1\0";
const ACK_RECORD_BYTES: usize = 208;
const V8_ATTEMPT_KEY: &[u8] = b"\0aos-controller-policy-v8-attempt-v1\0";
const V8_ATTEMPT_MAGIC: &[u8; 8] = b"AOSQ8A01";
const V8_ATTEMPT_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-attempt.v1\0";
const V8_ATTEMPT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-attempt-transaction.v1\0";
const V8_ATTEMPT_RECORD_BYTES: usize = 184;
const V8_ACK_KEY: &[u8] = b"\0aos-controller-policy-v8-effect-ack-v1\0";
const V8_ACK_MAGIC: &[u8; 8] = b"AOSQ8K01";
const V8_ACK_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-effect-ack.v1\0";
const V8_ACK_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-effect-ack-transaction.v1\0";
const V8_ACK_RECORD_BYTES: usize = 16 + V8_ATTEMPT_RECORD_BYTES + 8 + 16 + 32 + 32 + 32;
const V8_ROOT_RECEIPT_KEY: &[u8] = b"\0aos-controller-policy-v8-root-receipt-v1\0";
const V8_ROOT_RECEIPT_MAGIC: &[u8; 8] = b"AOSQ8R01";
const V8_ROOT_RECEIPT_CHECKSUM_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-root-receipt.v1\0";
const V8_ROOT_RECEIPT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-root-receipt-transaction.v1\0";
const V8_ROOT_RECEIPT_RECORD_BYTES: usize = 16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1 + 32;
const V8_SETTLEMENT_KEY: &[u8] = b"\0aos-controller-policy-v8-settlement-v1\0";
const V8_SETTLEMENT_MAGIC: &[u8; 8] = b"AOSQ8S01";
const V8_SETTLEMENT_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-settlement.v1\0";
const V8_SETTLEMENT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-settlement-transaction.v1\0";
const V8_SETTLEMENT_RECORD_BYTES: usize = 312;

/// Retains the exact V8 terminal digest before sending it to held Root.
///
/// This row is crash-replay custody only. It neither proves Root committed
/// nor grants owner release, publication, Create, or Apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8AttemptV1 {
    hold: ControllerPolicyHoldV1,
    terminal: ObjectDigest,
}

impl ControllerPolicyV8AttemptV1 {
    /// Constructs an exact terminal attempt under a retained Controller hold.
    ///
    /// # Errors
    ///
    /// Rejects released custody or an absent terminal digest.
    pub fn new(hold: ControllerPolicyHoldV1, terminal: ObjectDigest) -> Result<Self, JournalError> {
        let attempt = Self { hold, terminal };
        attempt.validate()?;
        Ok(attempt)
    }

    /// Returns the held Create and proposed Root binding.
    #[must_use]
    pub const fn hold(self) -> ControllerPolicyHoldV1 {
        self.hold
    }

    /// Returns the exact Controller-predicted AOSSFT01 digest.
    #[must_use]
    pub const fn terminal(self) -> ObjectDigest {
        self.terminal
    }

    fn validate(self) -> Result<(), JournalError> {
        self.hold.validate()?;
        if !self.hold.held || self.terminal.as_bytes() == &[0; 32] {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; V8_ATTEMPT_RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0; V8_ATTEMPT_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_ATTEMPT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..32].copy_from_slice(self.hold.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.hold.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.hold.source.as_bytes());
        bytes[80..112].copy_from_slice(self.hold.binding.as_bytes());
        bytes[112..120].copy_from_slice(&self.hold.epoch.to_be_bytes());
        bytes[120..152].copy_from_slice(self.terminal.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_ATTEMPT_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..152])
            .finalize();
        bytes[152..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != V8_ATTEMPT_RECORD_BYTES
            || bytes.get(..8) != Some(V8_ATTEMPT_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let attempt = Self::new(
            ControllerPolicyHoldV1::new(
                OperationId::from_bytes(take_attempt::<16>(bytes, 16)?),
                SandboxId::from_bytes(take_attempt::<16>(bytes, 32)?),
                ObjectDigest::from_bytes(take_attempt::<32>(bytes, 48)?),
                ObjectDigest::from_bytes(take_attempt::<32>(bytes, 80)?),
                u64::from_be_bytes(take_attempt::<8>(bytes, 112)?),
            )?,
            ObjectDigest::from_bytes(take_attempt::<32>(bytes, 120)?),
        )?;
        if attempt.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(attempt)
    }
}

fn take_attempt<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    bytes[offset..offset + N]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)
}

/// Retains an exact V8 Root-held CAS observation without authorizing Apply.
///
/// The prepared terminal, accepted Create, consumed AOSPCP02, and complete
/// Cache quota envelope stay bound under Controller custody. This record is
/// not an ordered-release grant; Root must separately acknowledge it under a
/// qualified live all-owner barrier before any owner can be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8EffectAckV1 {
    attempt: ControllerPolicyV8AttemptV1,
    accepted_generation: u64,
    effect_transaction: [u8; 16],
    root_proof: ObjectDigest,
    cache_quota: ObjectDigest,
}

impl ControllerPolicyV8EffectAckV1 {
    /// Constructs a no-Apply ACK for one exact protected V8 attempt.
    ///
    /// # Errors
    ///
    /// Rejects released custody or absent generation, transaction, proof, or quota.
    pub fn new(
        attempt: ControllerPolicyV8AttemptV1,
        accepted_generation: u64,
        effect_transaction: [u8; 16],
        root_proof: ObjectDigest,
        cache_quota: ObjectDigest,
    ) -> Result<Self, JournalError> {
        let ack = Self {
            attempt,
            accepted_generation,
            effect_transaction,
            root_proof,
            cache_quota,
        };
        ack.validate()?;
        Ok(ack)
    }

    /// Returns the pre-send attempt and held Create identity.
    #[must_use]
    pub const fn attempt(self) -> ControllerPolicyV8AttemptV1 {
        self.attempt
    }

    /// Returns the accepted Create generation.
    #[must_use]
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Returns the exact reserved effect transaction identity.
    #[must_use]
    pub const fn effect_transaction(self) -> [u8; 16] {
        self.effect_transaction
    }

    /// Returns the digest of Root's consumed AOSPCP02 proof.
    #[must_use]
    pub const fn root_proof(self) -> ObjectDigest {
        self.root_proof
    }

    /// Returns the complete Cache quota envelope retained by Root.
    #[must_use]
    pub const fn cache_quota(self) -> ObjectDigest {
        self.cache_quota
    }

    /// Returns the digest a future versioned Root ACK must bind.
    ///
    /// # Errors
    ///
    /// Rejects malformed protected ACK fields.
    pub fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    /// Encodes the canonical protected ACK for Controller-only signing.
    ///
    /// # Errors
    ///
    /// Rejects invalid ACK fields.
    pub fn record_bytes(self) -> Result<[u8; 320], JournalError> {
        self.encode()
    }

    /// Decodes a canonical ACK without asserting current Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed or noncanonical record bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, JournalError> {
        Self::decode(bytes)
    }

    fn validate(self) -> Result<(), JournalError> {
        self.attempt.validate()?;
        if self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.root_proof.as_bytes() == &[0; 32]
            || self.cache_quota.as_bytes() == &[0; 32]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; V8_ACK_RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0; V8_ACK_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_ACK_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..200].copy_from_slice(&self.attempt.encode()?);
        bytes[200..208].copy_from_slice(&self.accepted_generation.to_be_bytes());
        bytes[208..224].copy_from_slice(&self.effect_transaction);
        bytes[224..256].copy_from_slice(self.root_proof.as_bytes());
        bytes[256..288].copy_from_slice(self.cache_quota.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_ACK_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..288])
            .finalize();
        bytes[288..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != V8_ACK_RECORD_BYTES
            || bytes.get(..8) != Some(V8_ACK_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let ack = Self::new(
            ControllerPolicyV8AttemptV1::decode(&bytes[16..200])?,
            u64::from_be_bytes(take_attempt::<8>(bytes, 200)?),
            take_attempt::<16>(bytes, 208)?,
            ObjectDigest::from_bytes(take_attempt::<32>(bytes, 224)?),
            ObjectDigest::from_bytes(take_attempt::<32>(bytes, 256)?),
        )?;
        if ack.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(ack)
    }
}

/// Records that Controller durably received one exact qualified Root decision.
///
/// This is an effect handoff acknowledgment, not an Apply-capable effect. The
/// Controller remains frozen until a separately authenticated Root ACK and
/// ordered all-owner release are implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyEffectAckV1 {
    hold: ControllerPolicyHoldV1,
    accepted_generation: u64,
    effect_transaction: [u8; 16],
    root_proof: ObjectDigest,
}

impl ControllerPolicyEffectAckV1 {
    /// Constructs an exact no-Apply acknowledgment for a held Create.
    ///
    /// # Errors
    ///
    /// Rejects released custody, a zero generation or transaction, or an
    /// absent Root signer-proof commitment.
    pub fn new(
        hold: ControllerPolicyHoldV1,
        accepted_generation: u64,
        effect_transaction: [u8; 16],
        root_proof: ObjectDigest,
    ) -> Result<Self, JournalError> {
        let ack = Self {
            hold,
            accepted_generation,
            effect_transaction,
            root_proof,
        };
        ack.validate()?;
        Ok(ack)
    }

    /// Returns the exact held Controller claim.
    #[must_use]
    pub const fn hold(self) -> ControllerPolicyHoldV1 {
        self.hold
    }

    /// Returns the accepted public Create generation.
    #[must_use]
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Returns the Root-bound effect transaction identity.
    #[must_use]
    pub const fn effect_transaction(self) -> [u8; 16] {
        self.effect_transaction
    }

    /// Returns the digest of Root's canonical qualified signer-proof record.
    #[must_use]
    pub const fn root_proof(self) -> ObjectDigest {
        self.root_proof
    }

    /// Returns the digest of the exact canonical durable ACK record.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or released acknowledgment.
    pub fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    fn validate(self) -> Result<(), JournalError> {
        self.hold.validate()?;
        if !self.hold.held
            || self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.root_proof.as_bytes() == &[0; 32]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; ACK_RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0; ACK_RECORD_BYTES];
        bytes[..8].copy_from_slice(ACK_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..32].copy_from_slice(self.hold.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.hold.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.hold.source.as_bytes());
        bytes[80..112].copy_from_slice(self.hold.binding.as_bytes());
        bytes[112..120].copy_from_slice(&self.hold.epoch.to_be_bytes());
        bytes[120..128].copy_from_slice(&self.accepted_generation.to_be_bytes());
        bytes[128..144].copy_from_slice(&self.effect_transaction);
        bytes[144..176].copy_from_slice(self.root_proof.as_bytes());
        let checksum = Sha256::new()
            .chain_update(ACK_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..176])
            .finalize();
        bytes[176..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != ACK_RECORD_BYTES
            || bytes.get(..8) != Some(ACK_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let ack = Self {
            hold: ControllerPolicyHoldV1::new(
                OperationId::from_bytes(
                    bytes[16..32]
                        .try_into()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ),
                SandboxId::from_bytes(
                    bytes[32..48]
                        .try_into()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ),
                ObjectDigest::from_bytes(
                    bytes[48..80]
                        .try_into()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ),
                ObjectDigest::from_bytes(
                    bytes[80..112]
                        .try_into()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ),
                u64::from_be_bytes(
                    bytes[112..120]
                        .try_into()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ),
            )?,
            accepted_generation: u64::from_be_bytes(
                bytes[120..128]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            effect_transaction: bytes[128..144]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            root_proof: ObjectDigest::from_bytes(
                bytes[144..176]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
        };
        if ack.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(ack)
    }
}

/// Identifies one exact, nonauthorizing Controller policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyHoldV1 {
    operation: OperationId,
    sandbox: SandboxId,
    source: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl ControllerPolicyHoldV1 {
    /// Constructs the exact hold to persist before root Q04 submission.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers, commitments, or epoch.
    pub fn new(
        operation: OperationId,
        sandbox: SandboxId,
        source: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            operation,
            sandbox,
            source,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the accepted Create operation fixed by this hold.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the accepted Create sandbox fixed by this hold.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the query-time Controller source commitment.
    #[must_use]
    pub const fn source(self) -> ObjectDigest {
        self.source
    }

    /// Returns the root binding digest fixed before submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether the Controller writer remains frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of this exact held or released Controller row.
    ///
    /// # Errors
    ///
    /// Rejects malformed local hold fields.
    pub(crate) fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.source.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.source.as_bytes());
        bytes[80..112].copy_from_slice(self.binding.as_bytes());
        bytes[112..120].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let hold = Self {
            operation: OperationId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            sandbox: SandboxId::from_bytes(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[112..120]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(hold)
    }
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
    let mut hold = None;
    let mut ack = None;
    let mut attempt = None;
    let mut v8_ack = None;
    let mut v8_root_receipt = None;
    let mut v8_floor = None;
    let mut v8_settlement = None;
    for ((_, key), value) in state
        .range((RecordNamespace::ControllerPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::ControllerPolicyHold)
    {
        match key.as_slice() {
            KEY if hold.is_none() => hold = Some(ControllerPolicyHoldV1::decode(value)?),
            ACK_KEY if ack.is_none() => ack = Some(ControllerPolicyEffectAckV1::decode(value)?),
            V8_ATTEMPT_KEY if attempt.is_none() => {
                attempt = Some(ControllerPolicyV8AttemptV1::decode(value)?)
            }
            V8_ACK_KEY if v8_ack.is_none() => {
                v8_ack = Some(ControllerPolicyV8EffectAckV1::decode(value)?)
            }
            V8_ROOT_RECEIPT_KEY if v8_root_receipt.is_none() => {
                v8_root_receipt = Some(decode_v8_root_receipt(value)?)
            }
            V8_FLOOR_KEY if v8_floor.is_none() => {
                v8_floor = Some(ControllerPolicyV8PreReleaseFloorV1::decode(value)?)
            }
            V8_SETTLEMENT_KEY if v8_settlement.is_none() => {
                v8_settlement = Some(ControllerPolicyV8SettlementV1::decode(value)?)
            }
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    if ack.is_some_and(|ack| hold != Some(ack.hold)) {
        return Err(JournalError::ProtectedBoundary);
    }
    if attempt.is_some_and(|attempt| {
        hold.map(|current| ControllerPolicyHoldV1 {
            held: true,
            ..current
        }) != Some(attempt.hold)
            || ack.is_some()
            || !attempt.hold.is_held()
    }) {
        return Err(JournalError::ProtectedBoundary);
    }
    if v8_ack.is_some_and(|ack| attempt != Some(ack.attempt)) {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some(receipt) = v8_root_receipt {
        let ack = v8_ack.ok_or(JournalError::ProtectedBoundary)?;
        if !v8_root_receipt_matches_ack(receipt, ack)? {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if let Some(floor) = v8_floor {
        let controller = hold.ok_or(JournalError::ProtectedBoundary)?;
        let receipt = v8_root_receipt.ok_or(JournalError::ProtectedBoundary)?;
        if ack.is_some() || !floor.matches_chain(controller, receipt)? {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if let Some(settlement) = v8_settlement {
        let released = hold.ok_or(JournalError::ProtectedBoundary)?;
        let floor = v8_floor.ok_or(JournalError::ProtectedBoundary)?;
        let expected = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt.ok_or(JournalError::ProtectedBoundary)?,
            v8_ack.ok_or(JournalError::ProtectedBoundary)?,
            v8_root_receipt.ok_or(JournalError::ProtectedBoundary)?,
            settlement.root_release_marker,
            settlement.cache_released,
            settlement.source_released,
        )?;
        if ack.is_some()
            || settlement != expected
            || settlement.root_release_marker != floor.root_release_marker
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if hold.is_some_and(|hold| !hold.is_held()) && attempt.is_some() && v8_settlement.is_none() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(hold)
}

pub(crate) fn v8_root_receipt_matches_ack(
    receipt: RootV8EffectAckV1,
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<bool, JournalError> {
    let hold = ack.attempt().hold();
    Ok(receipt.binding() == hold.binding()
        && receipt.epoch() == hold.epoch()
        && receipt.operation() == hold.operation()
        && receipt.sandbox() == hold.sandbox()
        && receipt.accepted_generation() == ack.accepted_generation()
        && receipt.effect_transaction() == ack.effect_transaction()
        && receipt.terminal() == ack.attempt().terminal()
        && receipt.proof() == ack.root_proof()
        && receipt.quota() == ack.cache_quota()
        && receipt.controller_ack() == ack.record_digest()?)
}

fn encode_v8_root_receipt(
    receipt: RootV8EffectAckV1,
) -> Result<[u8; V8_ROOT_RECEIPT_RECORD_BYTES], JournalError> {
    let mut bytes = [0; V8_ROOT_RECEIPT_RECORD_BYTES];
    bytes[..8].copy_from_slice(V8_ROOT_RECEIPT_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1].copy_from_slice(
        &receipt
            .record_bytes()
            .map_err(|_| JournalError::ProtectedBoundary)?,
    );
    let checksum = Sha256::new()
        .chain_update(V8_ROOT_RECEIPT_CHECKSUM_DOMAIN)
        .chain_update(&bytes[..V8_ROOT_RECEIPT_RECORD_BYTES - 32])
        .finalize();
    bytes[V8_ROOT_RECEIPT_RECORD_BYTES - 32..].copy_from_slice(&checksum);
    Ok(bytes)
}

/// Returns the digest of Controller's canonical retained Root ACK receipt.
///
/// # Errors
///
/// Rejects a Root ACK that cannot be encoded as an exact Controller receipt.
pub(crate) fn controller_v8_root_receipt_record_digest_v1(
    receipt: RootV8EffectAckV1,
) -> Result<ObjectDigest, JournalError> {
    Ok(ObjectDigest::from_bytes(
        Sha256::digest(encode_v8_root_receipt(receipt)?).into(),
    ))
}

fn validate_held_owner_cut(
    controller: ControllerPolicyHoldV1,
    cache: CachePolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
) -> Result<(), JournalError> {
    if !controller.is_held()
        || !cache.is_held()
        || cache.binding() != controller.binding()
        || cache.epoch() != controller.epoch()
        || !source.is_held()
        || source.operation() != controller.operation()
        || source.sandbox() != controller.sandbox()
        || source.controller_source() != controller.source()
        || source.binding() != controller.binding()
        || source.epoch() != controller.epoch()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn decode_v8_root_receipt(bytes: &[u8]) -> Result<RootV8EffectAckV1, JournalError> {
    if bytes.len() != V8_ROOT_RECEIPT_RECORD_BYTES
        || bytes.get(..8) != Some(V8_ROOT_RECEIPT_MAGIC.as_slice())
        || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || bytes[10..16] != [0; 6]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let receipt =
        RootV8EffectAckV1::from_record_bytes(&bytes[16..16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1])
            .map_err(|_| JournalError::ProtectedBoundary)?;
    if encode_v8_root_receipt(receipt)?.as_slice() != bytes {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(receipt)
}

fn current_ack(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyEffectAckV1>, JournalError> {
    current(state)?;
    state
        .get(&(RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()))
        .map(|bytes| ControllerPolicyEffectAckV1::decode(bytes))
        .transpose()
}

fn current_v8_attempt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8AttemptV1>, JournalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ATTEMPT_KEY.to_vec(),
        ))
        .map(|bytes| ControllerPolicyV8AttemptV1::decode(bytes))
        .transpose()
}

fn current_v8_ack(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8EffectAckV1>, JournalError> {
    current(state)?;
    state
        .get(&(RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()))
        .map(|bytes| ControllerPolicyV8EffectAckV1::decode(bytes))
        .transpose()
}

fn current_v8_root_receipt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RootV8EffectAckV1>, JournalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ))
        .map(|bytes| decode_v8_root_receipt(bytes))
        .transpose()
}

fn current_v8_floor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8PreReleaseFloorV1>, JournalError> {
    current(state)?;
    state
        .get(&(RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()))
        .map(|bytes| ControllerPolicyV8PreReleaseFloorV1::decode(bytes))
        .transpose()
}

fn current_v8_settlement(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8SettlementV1>, JournalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_SETTLEMENT_KEY.to_vec(),
        ))
        .map(|bytes| ControllerPolicyV8SettlementV1::decode(bytes))
        .transpose()
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
        || current_v8_attempt(state)?.is_some()
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::ControllerPolicyHold)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
        || current_v8_attempt(state)?.is_some()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn single_record_transaction(
    domain: &[u8],
    key: &[u8],
    bytes: &[u8],
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            key.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn transaction(hold: ControllerPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(TRANSACTION_DOMAIN, KEY, &hold.encode()?)
}

fn ack_transaction(ack: ControllerPolicyEffectAckV1) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(ACK_TRANSACTION_DOMAIN, ACK_KEY, &ack.encode()?)
}

fn v8_attempt_transaction(
    attempt: ControllerPolicyV8AttemptV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(
        V8_ATTEMPT_TRANSACTION_DOMAIN,
        V8_ATTEMPT_KEY,
        &attempt.encode()?,
    )
}

fn v8_ack_transaction(
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(V8_ACK_TRANSACTION_DOMAIN, V8_ACK_KEY, &ack.encode()?)
}

fn v8_root_receipt_transaction(
    receipt: RootV8EffectAckV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(
        V8_ROOT_RECEIPT_TRANSACTION_DOMAIN,
        V8_ROOT_RECEIPT_KEY,
        &encode_v8_root_receipt(receipt)?,
    )
}

fn v8_root_receipt_capacity_transaction(
    hold: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    // Preflight only: the real receipt has this exact key and encoded length.
    // No synthetic Root row is committed or exposed as authority.
    let digest = Sha256::new()
        .chain_update(V8_ROOT_RECEIPT_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold.encode()?)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
            vec![0; V8_ROOT_RECEIPT_RECORD_BYTES],
        )],
    )
}

fn v8_floor_transaction(
    floor: ControllerPolicyV8PreReleaseFloorV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(V8_FLOOR_TRANSACTION_DOMAIN, V8_FLOOR_KEY, &floor.encode()?)
}

fn v8_floor_capacity_transaction(
    hold: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_FLOOR_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold.encode()?)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_FLOOR_KEY.to_vec(),
            vec![0; V8_FLOOR_RECORD_BYTES],
        )],
    )
}

fn v8_settlement_transaction(
    released: ControllerPolicyHoldV1,
    settlement: ControllerPolicyV8SettlementV1,
) -> Result<JournalTransaction, JournalError> {
    let hold_bytes = released.encode()?;
    let settlement_bytes = settlement.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(hold_bytes)
        .chain_update(settlement_bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
                settlement_bytes.to_vec(),
            ),
        ],
    )
}

fn v8_settlement_capacity_transaction(
    held: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let released = ControllerPolicyHoldV1 {
        held: false,
        ..held
    };
    let hold_bytes = released.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold_bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
                vec![0; V8_SETTLEMENT_RECORD_BYTES],
            ),
        ],
    )
}

fn ensure_controller(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    if journal
        .protected
        .as_ref()
        .map(|location| location.name.as_str())
        != Some("controller.journal")
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Durably freezes the protected Controller journal before root Q04 submission.
    ///
    /// A lost root reply leaves this hold intact across process death. The
    /// caller must not release it on successful terminal-ACK write alone.
    ///
    /// # Errors
    ///
    /// Rejects an unprotected journal, existing held or malformed custody,
    /// invalid fields, or a failed durable write/readback.
    pub fn acquire_controller_policy_hold_v1(
        &mut self,
        hold: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        if !hold.is_held()
            || current(&self.state)?.is_some_and(ControllerPolicyHoldV1::is_held)
            || current_ack(&self.state)?.is_some()
            || current_v8_attempt(&self.state)?.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(hold)?;
        let ack = ack_transaction(ControllerPolicyEffectAckV1::new(
            hold,
            1,
            [1; 16],
            ObjectDigest::from_bytes([1; 32]),
        )?)?;
        let attempt = v8_attempt_transaction(ControllerPolicyV8AttemptV1::new(
            hold,
            ObjectDigest::from_bytes([1; 32]),
        )?)?;
        let v8_ack = v8_ack_transaction(ControllerPolicyV8EffectAckV1::new(
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([1; 32]))?,
            1,
            [1; 16],
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([1; 32]),
        )?)?;
        let v8_root_receipt = v8_root_receipt_capacity_transaction(hold)?;
        let v8_floor = v8_floor_capacity_transaction(hold)?;
        let release = transaction(ControllerPolicyHoldV1 {
            held: false,
            ..hold
        })?;
        let v8_settlement = v8_settlement_capacity_transaction(hold)?;
        // The V1 and V8 continuations are alternatives. Reserve each complete
        // path without charging either path for the other's records.
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), ack, release],
            None,
            false,
            true,
        )?;
        self.preflight_transactions_with_capacity_scope(
            &[
                acquire.clone(),
                attempt,
                v8_ack,
                v8_root_receipt,
                v8_floor,
                v8_settlement,
            ],
            None,
            false,
            true,
        )?;
        self.commit_with_capacity_scope(&acquire, None, false, true, false, false, false)?;
        if current(&self.state)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact Controller custody state under its protected writer.
    ///
    /// This observation does not attest the root owner's state.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or malformed custody.
    pub fn controller_policy_hold_v1(
        &self,
    ) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
        ensure_controller(self)?;
        current(&self.state)
    }

    /// Reads the durable no-Apply Controller acknowledgment under its writer.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or malformed Controller custody.
    pub fn controller_policy_effect_ack_v1(
        &self,
    ) -> Result<Option<ControllerPolicyEffectAckV1>, JournalError> {
        ensure_controller(self)?;
        current_ack(&self.state)
    }

    /// Reads the exact protected V8 pre-send attempt under Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects unprotected, malformed, or mixed hold state.
    pub fn controller_policy_v8_attempt_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8AttemptV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_attempt(&self.state)
    }

    /// Retains the exact V8 terminal digest before sending it to Root.
    ///
    /// An ambiguous append is recovered by reopening this same protected
    /// Controller journal. Identical replay is idempotent; a second terminal
    /// attempt is forbidden while the first remains unresolved.
    ///
    /// # Errors
    ///
    /// Rejects a stale hold, prior ACK or different attempt, unsafe journal,
    /// exhausted reserved capacity, or failed durable readback.
    pub fn record_controller_policy_v8_attempt_v1(
        &mut self,
        attempt: ControllerPolicyV8AttemptV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        attempt.validate()?;
        if current(&self.state)? != Some(attempt.hold) || current_ack(&self.state)?.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_attempt(&self.state)? {
            Some(prior) if prior == attempt => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_with_capacity_scope(
            &v8_attempt_transaction(attempt)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current_v8_attempt(&self.state)? != Some(attempt) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact historical V8 no-Apply effect acknowledgment.
    ///
    /// This protected local replay does not reauthenticate Root or Cache and
    /// cannot be used as a release or effect capability on its own.
    ///
    /// # Errors
    ///
    /// Rejects unprotected, malformed, or mixed Controller custody.
    pub fn controller_policy_v8_effect_ack_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8EffectAckV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_ack(&self.state)
    }

    /// Durably advances one exact V8 attempt to a no-Apply effect ACK.
    ///
    /// The caller must first join Root's authenticated AOSPCP02 replay to the
    /// still-held Controller, Source, and protected/physical Cache writer cut.
    /// An identical cold replay is idempotent; this does not permit release.
    ///
    /// # Errors
    ///
    /// Rejects a changed attempt, released hold, mixed V1 acknowledgment,
    /// conflicting replay, or failed protected commit/readback.
    pub fn acknowledge_controller_policy_v8_effect_v1(
        &mut self,
        ack: ControllerPolicyV8EffectAckV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        ack.validate()?;
        if current(&self.state)? != Some(ack.attempt.hold)
            || current_v8_attempt(&self.state)? != Some(ack.attempt)
            || current_ack(&self.state)?.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_ack(&self.state)? {
            Some(prior) if prior == ack => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_with_capacity_scope(
            &v8_ack_transaction(ack)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current_v8_ack(&self.state)? != Some(ack) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact historical Root V8 ACK retained under Controller custody.
    ///
    /// This receipt grants no release, public Create, or Apply authority.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or inconsistent Controller custody.
    pub fn controller_policy_v8_root_receipt_v1(
        &self,
    ) -> Result<Option<RootV8EffectAckV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_root_receipt(&self.state)
    }

    /// Retains one authenticated historical Root V8 ACK under the held writer.
    ///
    /// The caller must authenticate Root and join the exact Source and Cache
    /// cut first. Identical cold replay is idempotent; this grants no release.
    ///
    /// # Errors
    ///
    /// Rejects changed Create, attempt, ACK, or Root receipt, or a failed
    /// protected commit and readback.
    pub fn record_controller_policy_v8_root_receipt_v1(
        &mut self,
        receipt: RootV8EffectAckV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        let ack = current_v8_ack(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        if current(&self.state)? != Some(ack.attempt().hold())
            || !v8_root_receipt_matches_ack(receipt, ack)?
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_root_receipt(&self.state)? {
            Some(prior) if prior == receipt => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_with_capacity_scope(
            &v8_root_receipt_transaction(receipt)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current_v8_root_receipt(&self.state)? != Some(receipt) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Records the held Cache and Source cut after Root has durably released.
    ///
    /// A future caller must supply `root_release_marker` only from a peer-checked
    /// R8X Released proof while Controller, Source, and Cache writers remain
    /// held. This floor authorizes no owner release, successor, Create, or Apply.
    /// It persists through the later Controller S row for exact cold recovery.
    ///
    /// # Errors
    ///
    /// Rejects a changed V8 chain, held owner identity, Root marker, or prior
    /// floor, or a failed durable commit and typed readback.
    #[allow(dead_code)]
    pub(crate) fn record_controller_policy_v8_pre_release_floor_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        root_release_marker: ObjectDigest,
        cache_held: CachePolicyHoldV1,
        source_held: SourceDomainPolicyHoldV1,
    ) -> Result<ControllerPolicyV8PreReleaseFloorV1, JournalError> {
        ensure_controller(self)?;
        let attempt = current_v8_attempt(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        let ack = current_v8_ack(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        if current(&self.state)? != Some(expected)
            || !expected.is_held()
            || attempt.hold() != expected
            || ack.attempt() != attempt
            || !v8_root_receipt_matches_ack(receipt, ack)?
            || current_v8_root_receipt(&self.state)? != Some(receipt)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            expected,
            receipt,
            root_release_marker,
            cache_held,
            source_held,
        )?;
        match current_v8_floor(&self.state)? {
            Some(prior) if prior == floor => return Ok(floor),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }

        self.commit_with_capacity_scope(
            &v8_floor_transaction(floor)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current(&self.state)? != Some(expected) || current_v8_floor(&self.state)? != Some(floor)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(floor)
    }

    /// Reads the exact pre-release floor under the protected Controller writer.
    ///
    /// # Errors
    ///
    /// Rejects foreign or malformed Controller custody.
    #[allow(dead_code)]
    pub(crate) fn controller_policy_v8_pre_release_floor_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8PreReleaseFloorV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_floor(&self.state)
    }

    /// Atomically retires Controller V8 custody with exact owner-release evidence.
    ///
    /// The caller must obtain the Root marker digest from a peer-checked R8X
    /// Released proof and Cache/Source rows from their retained writers. This
    /// inert local primitive does not authenticate those owners itself or grant
    /// Root successor, public Create, or Apply. The retained V8 attempt keeps
    /// ordinary Controller mutations fenced after local release.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete or changed V8 chain, owner evidence, Controller
    /// hold, or failed atomic commit and typed readback. Exact cold replay is
    /// idempotent; a different release proof fails closed.
    #[allow(dead_code)]
    pub(crate) fn retire_controller_policy_v8_hold_with_settlement_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        evidence: ControllerPolicyV8ReleaseEvidenceV1,
    ) -> Result<ControllerPolicyV8SettlementV1, JournalError> {
        ensure_controller(self)?;
        evidence.validate_for(expected)?;
        if !expected.is_held() || current_ack(&self.state)?.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let attempt = current_v8_attempt(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        let ack = current_v8_ack(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        if attempt.hold() != expected
            || ack.attempt() != attempt
            || !v8_root_receipt_matches_ack(receipt, ack)?
            || current_v8_root_receipt(&self.state)? != Some(receipt)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let floor = current_v8_floor(&self.state)?.ok_or(JournalError::ProtectedBoundary)?;
        if floor.root_release_marker != evidence.root_release_marker
            || floor.cache_held != evidence.cache_held.record_digest()?
            || floor.source_held != evidence.source_held.record_digest()?
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest()?,
            evidence.source_released.record_digest()?,
        )?;
        match current(&self.state)? {
            Some(prior) if prior == released => {
                if current_v8_settlement(&self.state)? == Some(settlement) {
                    return Ok(settlement);
                }
                return Err(JournalError::ProtectedBoundary);
            }
            Some(prior) if prior == expected && current_v8_settlement(&self.state)?.is_none() => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        self.commit_with_capacity_scope(
            &v8_settlement_transaction(released, settlement)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current(&self.state)? != Some(released)
            || current_v8_root_receipt(&self.state)? != Some(receipt)
            || current_v8_settlement(&self.state)? != Some(settlement)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(settlement)
    }

    /// Reads the canonical local V8 settlement row under Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects a foreign or malformed protected Controller journal.
    #[allow(dead_code)]
    pub(crate) fn controller_policy_v8_settlement_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8SettlementV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_settlement(&self.state)
    }

    /// Durably acknowledges one qualified Root decision while Controller stays held.
    ///
    /// The caller must retain the all-owner cut through authenticated Root
    /// replay and this write. A replay of the identical acknowledgment is
    /// accepted; a changed generation, transaction, or proof fails closed.
    /// This method never issues Apply or releases the hold.
    ///
    /// # Errors
    ///
    /// Rejects stale or malformed claims, conflicting prior acknowledgment,
    /// exhausted journal capacity, or failed durable write/readback.
    pub fn acknowledge_controller_policy_effect_v1(
        &mut self,
        ack: ControllerPolicyEffectAckV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        ack.validate()?;
        if current(&self.state)? != Some(ack.hold) || current_v8_attempt(&self.state)?.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_ack(&self.state)? {
            Some(prior) if prior == ack => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_with_capacity_scope(
            &ack_transaction(ack)?,
            None,
            false,
            true,
            false,
            false,
            false,
        )?;
        if current_ack(&self.state)? != Some(ack) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn release_controller_policy_hold_after_root_readback_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        // A qualified effect ACK needs the later Root ACK and ordered release;
        // this older inert path has no evidence of either.
        if !expected.held
            || current(&self.state)? != Some(expected)
            || current_ack(&self.state)?.is_some()
            || current_v8_attempt(&self.state)?.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let transaction = transaction(released)?;
        self.commit_with_capacity_scope(&transaction, None, false, true, false, false, false)?;
        if current(&self.state)? != Some(released) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use super::*;
    use crate::journal::JournalLimits;
    use aos_sandbox_core::ProjectId;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-controller-policy-hold-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protected directory mode");
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).expect("directory metadata").uid();
            Journal::open_protected_at_uid(
                &self.0,
                "controller.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("protected Controller reopen")
            .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hold() -> ControllerPolicyHoldV1 {
        ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            7,
        )
        .expect("valid hold")
    }

    fn ordinary_transaction() -> JournalTransaction {
        JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction")
    }

    fn acknowledgement(hold: ControllerPolicyHoldV1) -> ControllerPolicyEffectAckV1 {
        ControllerPolicyEffectAckV1::new(hold, 11, [12; 16], ObjectDigest::from_bytes([13; 32]))
            .expect("canonical no-Apply acknowledgment")
    }

    fn v8_root_receipt(ack: ControllerPolicyV8EffectAckV1) -> RootV8EffectAckV1 {
        let hold = ack.attempt().hold();
        let mut bytes = [0; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSPC88A");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(hold.binding().as_bytes());
        bytes[48..56].copy_from_slice(&hold.epoch().to_be_bytes());
        bytes[56..72].copy_from_slice(hold.operation().as_bytes());
        bytes[72..88].copy_from_slice(hold.sandbox().as_bytes());
        bytes[88..96].copy_from_slice(&ack.accepted_generation().to_be_bytes());
        bytes[96..112].copy_from_slice(&ack.effect_transaction());
        bytes[112..144].copy_from_slice(ack.attempt().terminal().as_bytes());
        bytes[144..176].copy_from_slice(ack.root_proof().as_bytes());
        bytes[176..208].copy_from_slice(ack.cache_quota().as_bytes());
        bytes[208..240].copy_from_slice(ack.record_digest().unwrap().as_bytes());
        bytes[240..272].fill(21);
        bytes[272..280].copy_from_slice(&4_u64.to_be_bytes());
        bytes[280..284].copy_from_slice(&1234_u32.to_be_bytes());
        bytes[284..300].fill(22);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0")
            .chain_update(&bytes[..300])
            .finalize();
        bytes[300..].copy_from_slice(&checksum);
        RootV8EffectAckV1::from_record_bytes(&bytes).unwrap()
    }

    fn v8_release_evidence(
        controller: ControllerPolicyHoldV1,
    ) -> ControllerPolicyV8ReleaseEvidenceV1 {
        let cache_directory = tempfile::tempdir().unwrap();
        fs::set_permissions(cache_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cache_uid = fs::metadata(cache_directory.path()).unwrap().uid();
        Journal::initialize_cache_policy_hold_at(cache_directory.path(), cache_uid).unwrap();
        let cache_held = CachePolicyHoldV1::new(
            ProjectId::from_bytes([41; 16]),
            ObjectDigest::from_bytes([42; 32]),
            ObjectDigest::from_bytes([43; 32]),
            controller.binding(),
            controller.epoch(),
        )
        .unwrap();
        Journal::acquire_cache_policy_hold_at(cache_directory.path(), cache_uid, cache_held)
            .unwrap();
        let (mut cache_writer, _) = Journal::open_protected_at_uid(
            cache_directory.path(),
            crate::journal::CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            cache_uid,
        )
        .unwrap();
        cache_writer
            .release_v8_held_cache_policy_hold_for_writer(cache_held)
            .unwrap();
        let (cache_held, cache_released) = cache_writer
            .v8_pending_cache_policy_release_for_writer()
            .unwrap();

        let source_directory = tempfile::tempdir().unwrap();
        fs::set_permissions(source_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source_uid = fs::metadata(source_directory.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_directory.path(),
            "source-domains-v1.journal",
            JournalLimits::default(),
            source_uid,
        )
        .unwrap();
        let source_held = SourceDomainPolicyHoldV1::new(
            controller.operation(),
            controller.sandbox(),
            controller.source(),
            ObjectDigest::from_bytes([44; 32]),
            controller.binding(),
            controller.epoch(),
        )
        .unwrap();
        source
            .acquire_source_domain_policy_hold_v1(source_held)
            .unwrap();
        let source_held = source.source_domain_policy_hold_v1().unwrap().unwrap();
        source
            .retire_source_domain_policy_hold_v8(source_held)
            .unwrap();
        let (source_held, source_released) =
            source.source_domain_policy_v8_release_pair_v1().unwrap();

        ControllerPolicyV8ReleaseEvidenceV1::new(
            controller,
            ObjectDigest::from_bytes([45; 32]),
            cache_held,
            cache_released,
            source_held,
            source_released,
        )
        .unwrap()
    }

    fn record_v8_floor(
        controller: &mut Journal,
        hold: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        evidence: ControllerPolicyV8ReleaseEvidenceV1,
    ) -> ControllerPolicyV8PreReleaseFloorV1 {
        controller
            .record_controller_policy_v8_pre_release_floor_v1(
                hold,
                receipt,
                evidence.root_release_marker,
                evidence.cache_held,
                evidence.source_held,
            )
            .unwrap()
    }

    #[test]
    fn qualified_ack_survives_crash_and_rejects_stale_generation_or_proof() {
        let directory = TestDirectory::new();
        let expected = hold();
        let ack = acknowledgement(expected);
        let mut controller = directory.open();

        assert!(
            controller
                .acknowledge_controller_policy_effect_v1(ack)
                .is_err()
        );
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        controller
            .acknowledge_controller_policy_effect_v1(ack)
            .unwrap();
        assert_eq!(controller.records(RecordNamespace::Effect).count(), 0);
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_effect_ack_v1().unwrap(),
            Some(ack)
        );
        reopened
            .acknowledge_controller_policy_effect_v1(ack)
            .unwrap();
        assert!(
            reopened
                .acknowledge_controller_policy_effect_v1(
                    ControllerPolicyEffectAckV1::new(
                        expected,
                        12,
                        ack.effect_transaction(),
                        ack.root_proof()
                    )
                    .unwrap()
                )
                .is_err()
        );
        assert!(
            reopened
                .acknowledge_controller_policy_effect_v1(
                    ControllerPolicyEffectAckV1::new(
                        expected,
                        11,
                        ack.effect_transaction(),
                        ObjectDigest::from_bytes([14; 32])
                    )
                    .unwrap()
                )
                .is_err()
        );
        assert!(
            reopened
                .acknowledge_controller_policy_effect_v1(
                    ControllerPolicyEffectAckV1::new(expected, 11, [15; 16], ack.root_proof())
                        .unwrap()
                )
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        assert_eq!(reopened.records(RecordNamespace::Effect).count(), 0);
        assert_eq!(
            reopened.controller_policy_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
        assert_eq!(
            reopened.controller_policy_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(expected)
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        assert!(
            reopened
                .acquire_controller_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn released_hold_with_ack_is_not_valid_cold_state() {
        let expected = hold();
        let ack = acknowledgement(expected);
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            released.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()),
            ack.encode().unwrap().to_vec(),
        );

        assert!(current(&state).is_err());
        assert!(current_ack(&state).is_err());
    }

    #[test]
    fn v8_terminal_attempt_is_durable_exact_and_fences_release() {
        let directory = TestDirectory::new();
        let expected = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(expected, ObjectDigest::from_bytes([28; 32]))
                .expect("canonical V8 attempt");
        let changed =
            ControllerPolicyV8AttemptV1::new(expected, ObjectDigest::from_bytes([29; 32]))
                .expect("different terminal");
        let mut controller = directory.open();
        assert!(
            controller
                .record_controller_policy_v8_attempt_v1(attempt)
                .is_err()
        );
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .record_controller_policy_v8_attempt_v1(changed)
                .is_err()
        );
        assert!(
            controller
                .acknowledge_controller_policy_effect_v1(acknowledgement(expected))
                .is_err()
        );
        assert!(
            controller
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_attempt_v1().unwrap(),
            Some(attempt)
        );
        reopened
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            reopened
                .record_controller_policy_v8_attempt_v1(changed)
                .is_err()
        );
        assert_eq!(reopened.records(RecordNamespace::Effect).count(), 0);

        let mut encoded = attempt.encode().unwrap();
        encoded[120] ^= 1;
        assert!(ControllerPolicyV8AttemptV1::decode(&encoded).is_err());
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..expected
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "released hold cannot replay with attempt"
        );
    }

    #[test]
    fn v8_effect_ack_replays_exact_attempt_and_cannot_release() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt = ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32]))
            .expect("V8 attempt");
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .expect("V8 no-Apply ACK");
        assert!(
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ObjectDigest::from_bytes([0; 32]),
                ack.cache_quota(),
            )
            .is_err()
        );
        assert!(
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ack.root_proof(),
                ObjectDigest::from_bytes([0; 32]),
            )
            .is_err()
        );
        let mut controller = directory.open();
        assert!(
            controller
                .acknowledge_controller_policy_v8_effect_v1(ack)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        assert!(
            controller
                .acknowledge_controller_policy_v8_effect_v1(ack)
                .is_err()
        );
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        assert_eq!(
            controller.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert_ne!(ack.record_digest().unwrap().as_bytes(), &[0; 32]);
        assert!(
            controller
                .acknowledge_controller_policy_effect_v1(acknowledgement(hold))
                .is_err()
        );
        assert!(
            controller
                .release_controller_policy_hold_after_root_readback_v1(hold)
                .is_err()
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        for changed in [
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                14,
                [14; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [17; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ObjectDigest::from_bytes([18; 32]),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ack.root_proof(),
                ObjectDigest::from_bytes([19; 32]),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([20; 32])).unwrap(),
                13,
                [14; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
        ] {
            assert!(
                reopened
                    .acknowledge_controller_policy_v8_effect_v1(changed)
                    .is_err()
            );
        }
        reopened
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();

        let mut malformed = ack.encode().unwrap();
        malformed[224] ^= 1;
        assert!(ControllerPolicyV8EffectAckV1::decode(&malformed).is_err());
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            hold.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()),
            ack.encode().unwrap().to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "ACK without attempt is not recoverable"
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        assert_eq!(current_v8_ack(&state).unwrap(), Some(ack));
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([20; 32]))
                .unwrap()
                .encode()
                .unwrap()
                .to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "substituted attempt fails cold replay"
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()),
            acknowledgement(hold).encode().unwrap().to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "mixed V1 and V8 ACKs fail cold replay"
        );
        state.remove(&(RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()));
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..hold
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "released hold plus ACK fails cold replay"
        );
    }

    #[test]
    fn v8_root_receipt_replays_exactly_and_keeps_controller_frozen() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        let mut controller = directory.open();
        assert!(
            controller
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert_eq!(
            controller.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        reopened
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        let mut changed = receipt.record_bytes().unwrap();
        changed[240] ^= 1;
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0")
            .chain_update(&changed[..300])
            .finalize();
        changed[300..].copy_from_slice(&checksum);
        let changed = RootV8EffectAckV1::from_record_bytes(&changed).unwrap();
        assert!(
            reopened
                .record_controller_policy_v8_root_receipt_v1(changed)
                .is_err()
        );
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(hold)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        assert_eq!(reopened.records(RecordNamespace::Effect).count(), 0);

        let mut encoded = encode_v8_root_receipt(receipt).unwrap();
        encoded[16] ^= 1;
        assert!(decode_v8_root_receipt(&encoded).is_err());
        let mut state = reopened.state.clone();
        state.remove(&(RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()));
        assert!(current(&state).is_err(), "receipt requires the exact ACK");

        let mut state = reopened.state.clone();
        let changed_ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            ack.accepted_generation() + 1,
            ack.effect_transaction(),
            ack.root_proof(),
            ack.cache_quota(),
        )
        .unwrap();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()),
            changed_ack.encode().unwrap().to_vec(),
        );
        assert!(current(&state).is_err(), "changed Create fails cold replay");

        let mut state = reopened.state.clone();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..hold
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        assert!(current(&state).is_err(), "released V8 requires settlement");
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        let evidence = v8_release_evidence(hold);
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            hold,
            receipt,
            evidence.root_release_marker,
            evidence.cache_held,
            evidence.source_held,
        )
        .unwrap();
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest().unwrap(),
            evidence.source_released.record_digest().unwrap(),
        )
        .unwrap();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()),
            floor.encode().unwrap().to_vec(),
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
            ),
            settlement.encode().unwrap().to_vec(),
        );
        assert_eq!(
            current(&state).unwrap(),
            Some(released),
            "the complete V8 chain and settlement admit exact released replay"
        );
        state.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ));
        assert!(current(&state).is_err(), "release requires Root receipt");
    }

    #[test]
    fn v8_settlement_requires_complete_chain_and_replays_exactly() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        let evidence = v8_release_evidence(hold);
        let mut controller = directory.open();

        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err(),
            "settlement requires a durable pre-release floor"
        );
        let floor = record_v8_floor(&mut controller, hold, receipt, evidence);
        assert_eq!(
            controller
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor)
        );
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor,
            "exact pre-release floor replay is idempotent"
        );
        assert_eq!(
            floor.cache_held_digest(),
            evidence.cache_held.record_digest().unwrap()
        );
        assert_eq!(
            floor.source_held_digest(),
            evidence.source_held.record_digest().unwrap()
        );
        assert_eq!(
            floor.root_release_marker_digest(),
            evidence.root_release_marker
        );
        assert_ne!(floor.record_digest().unwrap().as_bytes(), &[0; 32]);
        assert_eq!(
            ControllerPolicyV8PreReleaseFloorV1::from_record_bytes(&floor.record_bytes().unwrap())
                .unwrap(),
            floor
        );

        let changed_cache = CachePolicyHoldV1::new(
            ProjectId::from_bytes([47; 16]),
            evidence.cache_held.partition(),
            evidence.cache_held.cache_head(),
            hold.binding(),
            hold.epoch(),
        )
        .unwrap();
        let changed_source = SourceDomainPolicyHoldV1::new(
            hold.operation(),
            hold.sandbox(),
            hold.source(),
            ObjectDigest::from_bytes([48; 32]),
            hold.binding(),
            hold.epoch(),
        )
        .unwrap();
        for (marker, cache, source) in [
            (
                ObjectDigest::from_bytes([46; 32]),
                evidence.cache_held,
                evidence.source_held,
            ),
            (
                evidence.root_release_marker,
                changed_cache,
                evidence.source_held,
            ),
            (
                evidence.root_release_marker,
                evidence.cache_held,
                changed_source,
            ),
        ] {
            assert!(
                controller
                    .record_controller_policy_v8_pre_release_floor_v1(
                        hold, receipt, marker, cache, source,
                    )
                    .is_err(),
                "changed held or Root evidence cannot replace the floor"
            );
        }
        drop(controller);

        let mut controller = directory.open();
        assert_eq!(
            controller
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor),
            "the exact floor survives cold replay while all writers remain held"
        );
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor
        );

        let changed_hold = ControllerPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([29; 32]),
            ..hold
        };
        let changed_ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            14,
            ack.effect_transaction(),
            ack.root_proof(),
            ack.cache_quota(),
        )
        .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    changed_hold,
                    receipt,
                    evidence,
                )
                .is_err()
        );
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    hold,
                    v8_root_receipt(changed_ack),
                    evidence,
                )
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), Some(hold));

        let settlement = controller
            .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
            .unwrap();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        assert_eq!(
            controller.controller_policy_hold_v1().unwrap(),
            Some(released)
        );
        assert_eq!(
            controller.controller_policy_v8_settlement_v1().unwrap(),
            Some(settlement)
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        assert!(require_no_compaction(&controller.state).is_err());
        assert_eq!(controller.records(RecordNamespace::Effect).count(), 0);
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(released)
        );
        assert_eq!(
            reopened.controller_policy_v8_attempt_v1().unwrap(),
            Some(attempt)
        );
        assert_eq!(
            reopened.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert_eq!(
            reopened.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        assert_eq!(
            reopened
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor)
        );
        assert_eq!(
            reopened.controller_policy_v8_settlement_v1().unwrap(),
            Some(settlement)
        );
        assert_eq!(
            ControllerPolicyV8SettlementV1::from_record_bytes(&settlement.record_bytes().unwrap())
                .unwrap(),
            settlement
        );
        assert_eq!(
            settlement.root_receipt_digest(),
            controller_v8_root_receipt_record_digest_v1(receipt).unwrap()
        );
        assert_eq!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .unwrap(),
            settlement
        );
        assert_ne!(settlement.record_digest().unwrap().as_bytes(), &[0; 32]);

        let settled_state = reopened.state.clone();
        let mut torn = settled_state.clone();
        torn.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_SETTLEMENT_KEY.to_vec(),
        ));
        assert!(current(&torn).is_err(), "release without S fails closed");
        let mut torn = settled_state.clone();
        torn.remove(&(RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()));
        assert!(current(&torn).is_err(), "S without floor fails closed");
        let mut torn = settled_state.clone();
        torn.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ));
        assert!(current(&torn).is_err(), "floor without R01 fails closed");
        let mut torn = settled_state.clone();
        torn.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            hold.encode().unwrap().to_vec(),
        );
        assert!(current(&torn).is_err(), "S without release fails closed");

        for offset in [16, 48, 56, 88, 120, 152, 184, 216, 248] {
            let mut changed = settlement.encode().unwrap();
            changed[offset] ^= 1;
            let checksum = Sha256::new()
                .chain_update(V8_SETTLEMENT_CHECKSUM_DOMAIN)
                .chain_update(&changed[..280])
                .finalize();
            changed[280..].copy_from_slice(&checksum);
            reopened.state.insert(
                (
                    RecordNamespace::ControllerPolicyHold,
                    V8_SETTLEMENT_KEY.to_vec(),
                ),
                changed.to_vec(),
            );
            assert!(
                reopened
                    .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                    .is_err(),
                "changed settlement field at {offset} accepted"
            );
            reopened.state = settled_state.clone();
        }
        for offset in [16, 48, 56, 88, 120, 152] {
            let mut changed = floor.record_bytes().unwrap();
            changed[offset] ^= 1;
            let checksum = Sha256::new()
                .chain_update(v8_pre_release_floor::CHECKSUM_DOMAIN)
                .chain_update(&changed[..184])
                .finalize();
            changed[184..].copy_from_slice(&checksum);
            reopened.state.insert(
                (RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()),
                changed.to_vec(),
            );
            assert!(
                reopened
                    .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                    .is_err(),
                "changed floor field at {offset} accepted"
            );
            reopened.state = settled_state.clone();
        }
        let mut changed = floor.record_bytes().unwrap();
        changed[184] ^= 1;
        assert!(ControllerPolicyV8PreReleaseFloorV1::decode(&changed).is_err());
        let mut changed = settlement.encode().unwrap();
        changed[280] ^= 1;
        assert!(ControllerPolicyV8SettlementV1::decode(&changed).is_err());

        let changed_root = ControllerPolicyV8ReleaseEvidenceV1 {
            root_release_marker: ObjectDigest::from_bytes([46; 32]),
            ..evidence
        };
        assert!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, changed_root,)
                .is_err()
        );
        assert!(reopened.acquire_controller_policy_hold_v1(hold).is_err());
        assert!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    changed_hold,
                    receipt,
                    evidence,
                )
                .is_err()
        );
        assert!(
            reopened
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
    }

    #[test]
    fn v8_release_evidence_requires_matching_typed_owner_rows() {
        let controller = hold();
        let evidence = v8_release_evidence(controller);
        let wrong_cache = ControllerPolicyV8ReleaseEvidenceV1 {
            cache_held: CachePolicyHoldV1::new(
                ProjectId::from_bytes([47; 16]),
                evidence.cache_held.partition(),
                evidence.cache_held.cache_head(),
                controller.binding(),
                controller.epoch(),
            )
            .unwrap(),
            ..evidence
        };
        assert!(wrong_cache.validate_for(controller).is_err());

        let wrong_source = ControllerPolicyV8ReleaseEvidenceV1 {
            source_held: SourceDomainPolicyHoldV1::new(
                controller.operation(),
                controller.sandbox(),
                controller.source(),
                ObjectDigest::from_bytes([48; 32]),
                controller.binding(),
                controller.epoch(),
            )
            .unwrap(),
            ..evidence
        };
        assert!(wrong_source.validate_for(controller).is_err());

        for invalid in [
            ControllerPolicyV8ReleaseEvidenceV1 {
                root_release_marker: ObjectDigest::from_bytes([0; 32]),
                ..evidence
            },
            ControllerPolicyV8ReleaseEvidenceV1 {
                cache_released: evidence.cache_held,
                ..evidence
            },
            ControllerPolicyV8ReleaseEvidenceV1 {
                source_released: evidence.source_held,
                ..evidence
            },
        ] {
            assert!(invalid.validate_for(controller).is_err());
        }
    }

    #[test]
    fn acknowledgment_format_rejects_corruption_and_released_claim() {
        let ack = acknowledgement(hold());
        let mut encoded = ack.encode().unwrap();
        assert_eq!(ControllerPolicyEffectAckV1::decode(&encoded).unwrap(), ack);
        encoded[120] ^= 1;
        assert!(ControllerPolicyEffectAckV1::decode(&encoded).is_err());
        encoded = ack.encode().unwrap();
        encoded[10] = 2;
        assert!(ControllerPolicyEffectAckV1::decode(&encoded).is_err());
        assert!(
            ControllerPolicyEffectAckV1::new(
                ControllerPolicyHoldV1 {
                    held: false,
                    ..hold()
                },
                11,
                [12; 16],
                ObjectDigest::from_bytes([13; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn lost_root_reply_freezes_controller_after_crash_and_reopen() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        assert!(
            controller
                .acquire_controller_policy_hold_v1(released)
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
        controller
            .acquire_controller_policy_hold_v1(expected)
            .expect("durable hold before root submit");
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(expected)
        );
        assert!(matches!(
            reopened.commit(&ordinary_transaction()),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.preflight_transactions(&[ordinary_transaction()]),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            reopened
                .acquire_controller_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn exact_cold_release_restores_writes_but_wrong_binding_does_not() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        drop(controller);

        let mut reopened = directory.open();
        let wrong_binding = ControllerPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([5; 32]),
            ..expected
        };
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(wrong_binding)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        reopened
            .release_controller_policy_hold_after_root_readback_v1(expected)
            .expect("exact root-released evidence is checked by caller");
        assert!(
            !reopened
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        reopened
            .commit(&ordinary_transaction())
            .expect("writes restored");
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn format_rejects_noncanonical_or_corrupt_custody() {
        let expected = hold();
        let mut bytes = expected.encode().unwrap();
        assert_eq!(ControllerPolicyHoldV1::decode(&bytes).unwrap(), expected);
        bytes[11] = 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
        bytes = expected.encode().unwrap();
        bytes[119] ^= 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
    }

    #[test]
    fn acquisition_reserves_capacity_for_v8_receipt_and_atomic_settlement() {
        for maximum_transactions in [1, 5] {
            let directory = TestDirectory::new();
            let uid = fs::metadata(&directory.0).unwrap().uid();
            let limits = JournalLimits {
                maximum_transactions,
                ..JournalLimits::default()
            };
            let (mut controller, _) =
                Journal::open_protected_at_uid(&directory.0, "controller.journal", limits, uid)
                    .expect("protected Controller");

            assert!(
                controller
                    .acquire_controller_policy_hold_v1(hold())
                    .is_err()
            );
            assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
        }

        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_root_receipt_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(
                &v8_root_receipt_transaction(receipt).unwrap()
            )
            .unwrap(),
        );
        let evidence = v8_release_evidence(hold);
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            hold,
            receipt,
            evidence.root_release_marker,
            evidence.cache_held,
            evidence.source_held,
        )
        .unwrap();
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_floor_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(&v8_floor_transaction(floor).unwrap())
                .unwrap(),
        );
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest().unwrap(),
            evidence.source_released.record_digest().unwrap(),
        )
        .unwrap();
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_settlement_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(
                &v8_settlement_transaction(released, settlement).unwrap()
            )
            .unwrap(),
        );

        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 6,
            ..JournalLimits::default()
        };
        let (mut controller, _) =
            Journal::open_protected_at_uid(&directory.0, "controller.journal", limits, uid)
                .expect("protected Controller");
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor
        );
        assert_eq!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .unwrap(),
            settlement
        );
        assert_eq!(
            controller.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
    }
}
