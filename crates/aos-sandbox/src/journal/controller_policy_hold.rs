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
//! AOSCTA01 | version=1 | state=acknowledged-no-Apply | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! accepted-generation[8] | effect-transaction[16] | Root-proof-digest[32] |
//! SHA-256[32]
//! ```
//!
//! The hold freezes ordinary Controller mutations across crash and reopen.
//! Only exact private no-Apply acknowledgment and release transitions can
//! write while held. Neither freezes other owners nor authorizes public Create,
//! policy publication, or Apply.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

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
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    if ack.is_some_and(|ack| hold != Some(ack.hold)) {
        return Err(JournalError::ProtectedBoundary);
    }
    if attempt.is_some_and(|attempt| {
        hold != Some(attempt.hold) || ack.is_some() || !attempt.hold.is_held()
    }) {
        return Err(JournalError::ProtectedBoundary);
    }
    if v8_ack.is_some_and(|ack| attempt != Some(ack.attempt)) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(hold)
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

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
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
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn transaction(hold: ControllerPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
    let bytes = hold.encode()?;
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn ack_transaction(ack: ControllerPolicyEffectAckV1) -> Result<JournalTransaction, JournalError> {
    let bytes = ack.encode()?;
    let digest = Sha256::new()
        .chain_update(ACK_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            ACK_KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn v8_attempt_transaction(
    attempt: ControllerPolicyV8AttemptV1,
) -> Result<JournalTransaction, JournalError> {
    let bytes = attempt.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_ATTEMPT_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_ATTEMPT_KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn v8_ack_transaction(
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<JournalTransaction, JournalError> {
    let bytes = ack.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_ACK_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_ACK_KEY.to_vec(),
            bytes.to_vec(),
        )],
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
        let release = transaction(ControllerPolicyHoldV1 {
            held: false,
            ..hold
        })?;
        // All later Controller commits are fenced, so this reserves the
        // bounded journal room for one effect ACK and exact cold release.
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), ack, attempt, v8_ack, release],
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
    /// Rejects unprotected, malformed, released, or mixed hold state.
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

    /// Reads the exact, still-held V8 no-Apply effect acknowledgment.
    ///
    /// This protected local replay does not reauthenticate Root or Cache and
    /// cannot be used as a release or effect capability on its own.
    ///
    /// # Errors
    ///
    /// Rejects unprotected, malformed, mixed, or released Controller custody.
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
    fn acquisition_reserves_capacity_for_exact_cold_release() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 1,
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
}
