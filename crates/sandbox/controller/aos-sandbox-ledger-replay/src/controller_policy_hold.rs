//! Owns canonical Controller policy-hold and V8/Q04 historical DATA.
//!
//! Native Controller/Root/Source/Cache writer custody and every typed exception
//! remain with their actual owners. No decoded row or historical phase grants
//! currentness, funding, signing, mutation, publication or release authority.
//!
//! ```text
//! AOSCTH01 held/released | AOSQ8A01 attempt | AOSQ8K01 no-Apply ACK |
//! AOSQ8R01 Root receipt | AOSQ8F01 owner floor | AOSQ8S01 settlement
//! ```

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_model::{ObjectDigest, OperationId, RecordNamespace, SandboxId};
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Owns the original historical Root ACK codec without native Root authority.
pub mod root_v8_receipt;
/// Owns the original held-owner evidence floor DATA codec.
pub mod v8_pre_release_floor;
/// Owns the original released-owner evidence and settlement DATA codec.
pub mod v8_settlement;
#[cfg(target_os = "linux")]
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    Q04CutIdentityV1, Q04PhaseOwnerV1, Q04PhaseRecordV1, Q04TransactionOwnerV1,
};
use root_v8_receipt::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};
pub use v8_pre_release_floor::ControllerPolicyV8PreReleaseFloorV1;
use v8_pre_release_floor::KEY as V8_FLOOR_KEY;
pub use v8_settlement::{ControllerPolicyV8ReleaseEvidenceV1, ControllerPolicyV8SettlementV1};
/// Names the existing Controller Q04 cut key as historical DATA.
pub const CONTROLLER_IDENTITY_KEY: &[u8] = b"\0aos-controller-q04-cut-v1\0";
/// Names the existing Controller Q04 phase prefix as historical DATA.
pub const CONTROLLER_PHASE_PREFIX: &[u8] = b"\0aos-controller-q04-phase-v1\0";

/// Names the canonical row key.
#[doc(hidden)]
pub const KEY: &[u8] = b"\0aos-controller-policy-hold-v1\0";
/// Identifies the canonical record format.
#[doc(hidden)]
pub const MAGIC: &[u8; 8] = b"AOSCTH01";
/// Separates the record checksum from other formats.
#[doc(hidden)]
pub const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold.v1\0";
/// Separates native transaction hashes for this row.
#[doc(hidden)]
pub const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold-transaction.v1\0";
/// Bounds the complete checksummed record.
#[doc(hidden)]
pub const RECORD_BYTES: usize = 152;
// Presence of the retired profile fails closed at the current namespace scan.
/// Names the retired ACK row rejected during current-state scans.
#[doc(hidden)]
pub const ACK_KEY: &[u8] = b"\0aos-controller-policy-effect-ack-v1\0";
/// Names the terminal attempt row key.
#[doc(hidden)]
pub const V8_ATTEMPT_KEY: &[u8] = b"\0aos-controller-policy-v8-attempt-v1\0";
/// Identifies the terminal attempt record format.
#[doc(hidden)]
pub const V8_ATTEMPT_MAGIC: &[u8; 8] = b"AOSQ8A01";
/// Separates terminal attempt record checksums.
#[doc(hidden)]
pub const V8_ATTEMPT_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-attempt.v1\0";
/// Separates native terminal attempt transaction hashes.
#[doc(hidden)]
pub const V8_ATTEMPT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-attempt-transaction.v1\0";
/// Bounds the complete terminal attempt record.
#[doc(hidden)]
pub const V8_ATTEMPT_RECORD_BYTES: usize = 184;
/// Names the Controller ACK row key.
#[doc(hidden)]
pub const V8_ACK_KEY: &[u8] = b"\0aos-controller-policy-v8-effect-ack-v1\0";
/// Identifies the Controller ACK record format.
#[doc(hidden)]
pub const V8_ACK_MAGIC: &[u8; 8] = b"AOSQ8K01";
/// Separates Controller ACK record checksums.
#[doc(hidden)]
pub const V8_ACK_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-effect-ack.v1\0";
/// Separates native Controller ACK transaction hashes.
#[doc(hidden)]
pub const V8_ACK_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-effect-ack-transaction.v1\0";
/// Bounds the complete Controller ACK record.
#[doc(hidden)]
pub const V8_ACK_RECORD_BYTES: usize = 16 + V8_ATTEMPT_RECORD_BYTES + 8 + 16 + 32 + 32 + 32;
/// Names the Root receipt wrapper row key.
#[doc(hidden)]
pub const V8_ROOT_RECEIPT_KEY: &[u8] = b"\0aos-controller-policy-v8-root-receipt-v1\0";
/// Identifies the Root receipt wrapper record format.
#[doc(hidden)]
pub const V8_ROOT_RECEIPT_MAGIC: &[u8; 8] = b"AOSQ8R01";
/// Separates Root receipt wrapper record checksums.
#[doc(hidden)]
pub const V8_ROOT_RECEIPT_CHECKSUM_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-root-receipt.v1\0";
/// Separates native Root receipt wrapper transaction hashes.
#[doc(hidden)]
pub const V8_ROOT_RECEIPT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-root-receipt-transaction.v1\0";
/// Bounds the complete Root receipt wrapper record.
#[doc(hidden)]
pub const V8_ROOT_RECEIPT_RECORD_BYTES: usize = 16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1 + 32;
/// Names the settlement row key.
#[doc(hidden)]
pub const V8_SETTLEMENT_KEY: &[u8] = b"\0aos-controller-policy-v8-settlement-v1\0";
/// Identifies the settlement record format.
#[doc(hidden)]
pub const V8_SETTLEMENT_MAGIC: &[u8; 8] = b"AOSQ8S01";
/// Separates settlement record checksums.
#[doc(hidden)]
pub const V8_SETTLEMENT_CHECKSUM_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-settlement.v1\0";
/// Separates native settlement transaction hashes.
#[doc(hidden)]
pub const V8_SETTLEMENT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-settlement-transaction.v1\0";
/// Bounds the complete settlement record.
#[doc(hidden)]
pub const V8_SETTLEMENT_RECORD_BYTES: usize = 312;

/// Retains the exact V8 terminal digest before sending it to held Root.
///
/// This row is crash-replay custody only. It neither proves Root committed
/// nor grants owner release, publication, Create, or Apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8AttemptV1 {
    /// Records the associated Controller hold.
    pub hold: ControllerPolicyHoldV1,
    /// Commits the proposed AOSSFT01 terminal record.
    pub terminal: ObjectDigest,
}

impl ControllerPolicyV8AttemptV1 {
    /// Constructs an exact terminal attempt under a retained Controller hold.
    ///
    /// # Errors
    ///
    /// Rejects released custody or an absent terminal digest.
    pub fn new(
        hold: ControllerPolicyHoldV1,
        terminal: ObjectDigest,
    ) -> Result<Self, MechanicalError> {
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

    /// Checks the held attempt and its terminal digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed hold fields, a released hold or a zero terminal digest.
    pub fn validate(self) -> Result<(), MechanicalError> {
        self.hold.validate()?;
        if !self.hold.held || self.terminal.as_bytes() == &[0; 32] {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Encodes the AOSQ8A01 terminal attempt.
    ///
    /// # Errors
    ///
    /// Rejects an invalid held attempt or zero terminal digest.
    pub fn encode(self) -> Result<[u8; V8_ATTEMPT_RECORD_BYTES], MechanicalError> {
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

    /// Decodes an AOSQ8A01 terminal attempt.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, invalid held fields or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != V8_ATTEMPT_RECORD_BYTES
            || bytes.get(..8) != Some(V8_ATTEMPT_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
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
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(attempt)
    }
}

fn take_attempt<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], MechanicalError> {
    bytes[offset..offset + N]
        .try_into()
        .map_err(|_| MechanicalError::ProtectedBoundary)
}

/// Retains an exact V8 Root-held CAS observation without authorizing Apply.
///
/// The prepared terminal, accepted Create, consumed AOSPCP02, and complete
/// Cache quota envelope stay bound under Controller custody. This record is
/// not an ordered-release grant; Root must separately acknowledge it under a
/// qualified live all-owner barrier before any owner can be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8EffectAckV1 {
    /// Records the terminal attempt acknowledged by Controller.
    pub attempt: ControllerPolicyV8AttemptV1,
    /// Names the accepted Create generation.
    pub accepted_generation: u64,
    /// Names the no-Apply effect transaction.
    pub effect_transaction: [u8; 16],
    /// Commits the consumed AOSPCP02 proof.
    pub root_proof: ObjectDigest,
    /// Commits the complete Cache quota.
    pub cache_quota: ObjectDigest,
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
    ) -> Result<Self, MechanicalError> {
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
    pub fn record_digest(self) -> Result<ObjectDigest, MechanicalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    /// Encodes the canonical protected ACK for Controller-only signing.
    ///
    /// # Errors
    ///
    /// Rejects invalid ACK fields.
    pub fn record_bytes(self) -> Result<[u8; 320], MechanicalError> {
        self.encode()
    }

    /// Decodes a canonical ACK without asserting current Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed or noncanonical record bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, MechanicalError> {
        Self::decode(bytes)
    }

    /// Checks the acknowledged attempt and Controller evidence fields.
    ///
    /// # Errors
    ///
    /// Rejects an invalid attempt or zero generation, transaction, proof or quota.
    pub fn validate(self) -> Result<(), MechanicalError> {
        self.attempt.validate()?;
        if self.accepted_generation == 0
            || self.effect_transaction == [0; 16]
            || self.root_proof.as_bytes() == &[0; 32]
            || self.cache_quota.as_bytes() == &[0; 32]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Encodes the AOSQ8K01 no-Apply acknowledgment.
    ///
    /// # Errors
    ///
    /// Rejects invalid attempt or acknowledgment fields.
    pub fn encode(self) -> Result<[u8; V8_ACK_RECORD_BYTES], MechanicalError> {
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

    /// Decodes an AOSQ8K01 no-Apply acknowledgment.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, invalid attempt or ACK fields, or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != V8_ACK_RECORD_BYTES
            || bytes.get(..8) != Some(V8_ACK_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let ack = Self::new(
            ControllerPolicyV8AttemptV1::decode(&bytes[16..200])?,
            u64::from_be_bytes(take_attempt::<8>(bytes, 200)?),
            take_attempt::<16>(bytes, 208)?,
            ObjectDigest::from_bytes(take_attempt::<32>(bytes, 224)?),
            ObjectDigest::from_bytes(take_attempt::<32>(bytes, 256)?),
        )?;
        if ack.encode()?.as_slice() != bytes {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(ack)
    }
}

/// Identifies one exact, nonauthorizing Controller policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyHoldV1 {
    /// Names the associated public Create operation.
    pub operation: OperationId,
    /// Names the associated sandbox.
    pub sandbox: SandboxId,
    /// Commits the Controller-selected Create source.
    pub source: ObjectDigest,
    /// Commits the proposed policy binding.
    pub binding: ObjectDigest,
    /// Names the policy handoff epoch.
    pub epoch: u64,
    /// Distinguishes the held row from its released form.
    pub held: bool,
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
    ) -> Result<Self, MechanicalError> {
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

    /// Reports whether this historical hold row is held.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of this exact held or released Controller row.
    ///
    /// # Errors
    ///
    /// Rejects malformed local hold fields.
    pub fn record_digest(self) -> Result<ObjectDigest, MechanicalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    // Canonical comparison DATA only. A digest does not observe retirement or
    // permit a transition; the Q04 native/owner engines establish that cut.
    #[cfg(target_os = "linux")]
    /// Returns the digest of the matching released Q04 hold row.
    ///
    /// # Errors
    ///
    /// Rejects zero operation, sandbox, source, binding or epoch fields.
    pub fn q04_released_record_digest(self) -> Result<ObjectDigest, MechanicalError> {
        Self {
            held: false,
            ..self
        }
        .record_digest()
    }

    /// Checks the hold identity fields.
    ///
    /// # Errors
    ///
    /// Rejects zero operation, sandbox, source, binding or epoch fields.
    pub fn validate(self) -> Result<(), MechanicalError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.source.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Encodes the held or released AOSCTH01 row.
    ///
    /// # Errors
    ///
    /// Rejects zero identity fields or epoch.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], MechanicalError> {
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

    /// Decodes a held or released AOSCTH01 row.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, invalid identity fields or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let hold = Self {
            operation: OperationId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            sandbox: SandboxId::from_bytes(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[112..120]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(hold)
    }
}

/// Returns the hold after validating its complete stored history.
///
/// # Errors
///
/// Rejects malformed rows, unknown keys or inconsistent V8/Q04 history.
pub fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyHoldV1>, MechanicalError> {
    current_readback(state).map(|readback| readback.hold)
}

/// Retains the complete canonical current hold and optional historical Q04 fold.
pub struct ControllerHoldReadbackV1 {
    /// Records the associated Controller hold.
    pub hold: Option<ControllerPolicyHoldV1>,
    #[cfg(target_os = "linux")]
    /// Retains the validated Q04 identity and ordered phases, when present.
    pub q04: Option<ControllerQ04HistoryV1>,
}

/// Validates the complete hold namespace and folds its V8 or Q04 history.
///
/// # Errors
///
/// Rejects unknown or retired rows, mixed V8/Q04 history, broken receipt chains,
/// missing settlement or inconsistent hold and phase records.
pub fn current_readback(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<ControllerHoldReadbackV1, MechanicalError> {
    let mut hold = None;
    let mut attempt = None;
    let mut v8_ack = None;
    let mut v8_root_receipt = None;
    let mut v8_floor = None;
    let mut v8_settlement = None;
    #[cfg(target_os = "linux")]
    let mut q04 = false;
    for ((_, key), value) in state
        .range((RecordNamespace::ControllerPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::ControllerPolicyHold)
    {
        match key.as_slice() {
            KEY if hold.is_none() => hold = Some(ControllerPolicyHoldV1::decode(value)?),
            ACK_KEY => return Err(MechanicalError::ProtectedBoundary),
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
            #[cfg(target_os = "linux")]
            key if key == CONTROLLER_IDENTITY_KEY || key.starts_with(CONTROLLER_PHASE_PREFIX)
                || key == aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY => {
                q04 = true;
            }
            _ => return Err(MechanicalError::ProtectedBoundary),
        }
    }
    if attempt.is_some_and(|attempt| {
        hold.map(|current| ControllerPolicyHoldV1 {
            held: true,
            ..current
        }) != Some(attempt.hold)
            || !attempt.hold.is_held()
    }) {
        return Err(MechanicalError::ProtectedBoundary);
    }
    if v8_ack.is_some_and(|ack| attempt != Some(ack.attempt)) {
        return Err(MechanicalError::ProtectedBoundary);
    }
    if let Some(receipt) = v8_root_receipt {
        let ack = v8_ack.ok_or(MechanicalError::ProtectedBoundary)?;
        if !v8_root_receipt_matches_ack(receipt, ack)? {
            return Err(MechanicalError::ProtectedBoundary);
        }
    }
    if let Some(floor) = v8_floor {
        let controller = hold.ok_or(MechanicalError::ProtectedBoundary)?;
        let receipt = v8_root_receipt.ok_or(MechanicalError::ProtectedBoundary)?;
        if !floor.matches_chain(controller, receipt)? {
            return Err(MechanicalError::ProtectedBoundary);
        }
    }
    if let Some(settlement) = v8_settlement {
        let released = hold.ok_or(MechanicalError::ProtectedBoundary)?;
        let floor = v8_floor.ok_or(MechanicalError::ProtectedBoundary)?;
        let expected = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt.ok_or(MechanicalError::ProtectedBoundary)?,
            v8_ack.ok_or(MechanicalError::ProtectedBoundary)?,
            v8_root_receipt.ok_or(MechanicalError::ProtectedBoundary)?,
            settlement.root_release_marker,
            settlement.cache_released,
            settlement.source_released,
        )?;
        if settlement != expected || settlement.root_release_marker != floor.root_release_marker {
            return Err(MechanicalError::ProtectedBoundary);
        }
    }
    if hold.is_some_and(|hold| !hold.is_held()) && attempt.is_some() && v8_settlement.is_none() {
        return Err(MechanicalError::ProtectedBoundary);
    }
    #[cfg(target_os = "linux")]
    let q04 = if q04 {
        if attempt.is_some()
            || v8_ack.is_some()
            || v8_root_receipt.is_some()
            || v8_floor.is_some()
            || v8_settlement.is_some()
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Some(q04_history(
            state,
            hold.ok_or(MechanicalError::ProtectedBoundary)?,
        )?)
    } else {
        None
    };
    Ok(ControllerHoldReadbackV1 {
        hold,
        #[cfg(target_os = "linux")]
        q04,
    })
}

/// Retains the exact validated historical Q04 identity and ordered phases.
///
/// Native membership and the complete Create ledger remain independently
/// checked by the actual replay and transition owners.
#[cfg(target_os = "linux")]
pub struct ControllerQ04HistoryV1 {
    /// Retains the exact validated original Q04 historical identity.
    pub identity: Q04CutIdentityV1,
    /// Retains the exact validated original Q04 historical phase sequence.
    pub phases: Vec<Q04PhaseRecordV1>,
}

#[cfg(target_os = "linux")]
/// Reports whether stored Q04 cut, phase or input-origin keys are present.
pub fn has_q04_history(state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>) -> bool {
    state
        .range((RecordNamespace::ControllerPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::ControllerPolicyHold)
        .any(|((_, key), _)| {
            key == CONTROLLER_IDENTITY_KEY || key.starts_with(CONTROLLER_PHASE_PREFIX)
                || key == aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY
        })
}

// Old private hold transitions are not a Q04 waiver. Check this even when
// they select the existing policy-hold transition flag; only the new named
// closed action may later cross this purpose boundary.
#[cfg(target_os = "linux")]
/// Rejects ordinary mutations involving Q04 history or records.
///
/// # Errors
///
/// Rejects retained Q04 history, proposed cut/phase/input-origin rows, or
/// Q04 Effect records.
pub fn require_q04_ordinary_boundary(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), MechanicalError> {
    if has_q04_history(state)
        || transaction.records().iter().any(|record| {
            (record.namespace() == RecordNamespace::ControllerPolicyHold
                && (record.key() == CONTROLLER_IDENTITY_KEY
                    || record.key() == aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY
                    || record.key().starts_with(CONTROLLER_PHASE_PREFIX)))
                || (record.namespace() == RecordNamespace::Effect
                    && record.value().is_some_and(|bytes| bytes.first() == Some(&6)))
        })
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Validates the Q04 identity, ordered phases and hold transition.
///
/// # Errors
///
/// Rejects missing or malformed identity/input history, broken phase succession,
/// wrong transaction IDs or inconsistent held/released row digests.
pub fn q04_history(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    hold: ControllerPolicyHoldV1,
) -> Result<ControllerQ04HistoryV1, MechanicalError> {
    let identity = state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            CONTROLLER_IDENTITY_KEY.to_vec(),
        ))
        .ok_or(MechanicalError::ProtectedBoundary)?;
    let identity =
        Q04CutIdentityV1::decode(identity).map_err(|_| MechanicalError::ProtectedBoundary)?;
    let origin = state.get(&(
        RecordNamespace::ControllerPolicyHold,
        aos_sandbox_protocol::domain_ledger::resource_bank::CONTROLLER_INPUT_ORIGIN_KEY.to_vec(),
    ));
    aos_sandbox_protocol::domain_ledger::resource_bank::require_input_history(
        state,
        &identity,
        origin.map(Vec::as_slice),
    )
    .map_err(|_| MechanicalError::ProtectedBoundary)?;
    if hold.operation() != identity.operation()
        || hold.sandbox() != identity.sandbox()
        || hold.binding() != identity.binding()
        || hold.epoch() != identity.epoch()
    {
        return Err(MechanicalError::ProtectedBoundary);
    }

    let mut phases = Vec::<Q04PhaseRecordV1>::new();
    for ((_, key), bytes) in state
        .range((RecordNamespace::ControllerPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::ControllerPolicyHold)
    {
        if !key.starts_with(CONTROLLER_PHASE_PREFIX) {
            continue;
        }
        if key.len() != CONTROLLER_PHASE_PREFIX.len() + 1 {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let phase = Q04PhaseRecordV1::decode(Q04PhaseOwnerV1::Controller, bytes, &identity)
            .map_err(|_| MechanicalError::ProtectedBoundary)?;
        let expected =
            u8::try_from(phases.len() + 1).map_err(|_| MechanicalError::ProtectedBoundary)?;
        if phase.phase() != expected
            || key[CONTROLLER_PHASE_PREFIX.len()] != expected
            || phase.bytes()[512..544] != *identity.before_controller_rows().as_bytes()
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let predecessor = if let Some(prior) = phases.last() {
            phase
                .require_successor(prior)
                .map_err(|_| MechanicalError::ProtectedBoundary)?;
            prior.digest()
        } else {
            identity.before_controller_rows()
        };
        if phase.native_transaction_id()
            != Q04TransactionOwnerV1::Controller
                .transaction_id(&identity, expected, predecessor)
                .map_err(|_| MechanicalError::ProtectedBoundary)?
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        phases.push(phase);
    }

    let first = phases.first().ok_or(MechanicalError::ProtectedBoundary)?;
    let last = phases.last().ok_or(MechanicalError::ProtectedBoundary)?;
    let held = ControllerPolicyHoldV1 { held: true, ..hold }.record_digest()?;
    let released = ControllerPolicyHoldV1 {
        held: false,
        ..hold
    }
    .record_digest()?;
    if first.bytes()[288..320] != *held.as_bytes()
        || hold.is_held() != (last.phase() < 5)
        || (last.phase() >= 5 && last.bytes()[320..352] != *released.as_bytes())
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(ControllerQ04HistoryV1 { identity, phases })
}

/// Compares a Root receipt with its acknowledged Controller attempt.
///
/// # Errors
///
/// Returns an error if the compared Controller acknowledgment cannot be encoded.
pub fn v8_root_receipt_matches_ack(
    receipt: RootV8EffectAckV1,
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<bool, MechanicalError> {
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

/// Encodes the Controller wrapper around an AOSPC88A Root receipt.
///
/// # Errors
///
/// Rejects invalid fields in the embedded Root ACK.
pub fn encode_v8_root_receipt(
    receipt: RootV8EffectAckV1,
) -> Result<[u8; V8_ROOT_RECEIPT_RECORD_BYTES], MechanicalError> {
    let mut bytes = [0; V8_ROOT_RECEIPT_RECORD_BYTES];
    bytes[..8].copy_from_slice(V8_ROOT_RECEIPT_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1].copy_from_slice(
        &receipt
            .record_bytes()
            .map_err(|_| MechanicalError::ProtectedBoundary)?,
    );
    let checksum = Sha256::new()
        .chain_update(V8_ROOT_RECEIPT_CHECKSUM_DOMAIN)
        .chain_update(&bytes[..V8_ROOT_RECEIPT_RECORD_BYTES - 32])
        .finalize();
    bytes[V8_ROOT_RECEIPT_RECORD_BYTES - 32..].copy_from_slice(&checksum);
    Ok(bytes)
}

/// Hashes the canonical Controller-wrapped Root receipt.
///
/// # Errors
///
/// Rejects invalid fields in the embedded Root ACK.
pub fn controller_v8_root_receipt_record_digest_v1(
    receipt: RootV8EffectAckV1,
) -> Result<ObjectDigest, MechanicalError> {
    Ok(ObjectDigest::from_bytes(
        Sha256::digest(encode_v8_root_receipt(receipt)?).into(),
    ))
}

/// Checks that held Controller, Cache and Source rows name the same cut.
///
/// # Errors
///
/// Rejects released rows or differing binding, epoch or Source identity fields.
pub fn validate_held_owner_cut(
    controller: ControllerPolicyHoldV1,
    cache: CachePolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
) -> Result<(), MechanicalError> {
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
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}

/// Decodes the Controller-wrapped AOSPC88A Root receipt.
///
/// # Errors
///
/// Rejects wrong wrapper or ACK framing, invalid fields or a checksum mismatch.
pub fn decode_v8_root_receipt(bytes: &[u8]) -> Result<RootV8EffectAckV1, MechanicalError> {
    if bytes.len() != V8_ROOT_RECEIPT_RECORD_BYTES
        || bytes.get(..8) != Some(V8_ROOT_RECEIPT_MAGIC.as_slice())
        || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || bytes[10..16] != [0; 6]
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    let receipt =
        RootV8EffectAckV1::from_record_bytes(&bytes[16..16 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1])
            .map_err(|_| MechanicalError::ProtectedBoundary)?;
    if encode_v8_root_receipt(receipt)?.as_slice() != bytes {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(receipt)
}

/// Returns the terminal attempt after validating the hold namespace.
///
/// # Errors
///
/// Rejects malformed or inconsistent stored hold, V8 or Q04 history.
pub fn current_v8_attempt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8AttemptV1>, MechanicalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ATTEMPT_KEY.to_vec(),
        ))
        .map(|bytes| ControllerPolicyV8AttemptV1::decode(bytes))
        .transpose()
}

/// Returns the Controller ACK after validating the hold namespace.
///
/// # Errors
///
/// Rejects malformed or inconsistent stored hold, V8 or Q04 history.
pub fn current_v8_ack(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8EffectAckV1>, MechanicalError> {
    current(state)?;
    state
        .get(&(RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()))
        .map(|bytes| ControllerPolicyV8EffectAckV1::decode(bytes))
        .transpose()
}

/// Returns the Root receipt after validating the hold namespace.
///
/// # Errors
///
/// Rejects malformed or inconsistent stored hold, V8 or Q04 history.
pub fn current_v8_root_receipt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RootV8EffectAckV1>, MechanicalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ))
        .map(|bytes| decode_v8_root_receipt(bytes))
        .transpose()
}

/// Returns the owner evidence floor after validating the hold namespace.
///
/// # Errors
///
/// Rejects malformed or inconsistent stored hold, V8 or Q04 history.
pub fn current_v8_floor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8PreReleaseFloorV1>, MechanicalError> {
    current(state)?;
    state
        .get(&(RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()))
        .map(|bytes| ControllerPolicyV8PreReleaseFloorV1::decode(bytes))
        .transpose()
}

/// Returns the settlement after validating the hold namespace.
///
/// # Errors
///
/// Rejects malformed or inconsistent stored hold, V8 or Q04 history.
pub fn current_v8_settlement(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8SettlementV1>, MechanicalError> {
    current(state)?;
    state
        .get(&(
            RecordNamespace::ControllerPolicyHold,
            V8_SETTLEMENT_KEY.to_vec(),
        ))
        .map(|bytes| ControllerPolicyV8SettlementV1::decode(bytes))
        .transpose()
}

/// Checks whether ordinary mutation is outside retained policy custody.
///
/// # Errors
///
/// Rejects invalid hold history, a held row, a retained V8 attempt or Q04 history,
/// or any proposed Controller policy-hold record.
pub fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), MechanicalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
        || current_v8_attempt(state)?.is_some()
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::ControllerPolicyHold)
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    #[cfg(target_os = "linux")]
    if has_q04_history(state) {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}

/// Checks whether compaction is outside retained policy custody.
///
/// # Errors
///
/// Rejects invalid hold history, a held row, a retained V8 attempt or Q04 history.
pub fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), MechanicalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
        || current_v8_attempt(state)?.is_some()
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    #[cfg(target_os = "linux")]
    if has_q04_history(state) {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}
