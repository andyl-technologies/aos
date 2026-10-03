//! Finite, descriptor-free native recovery query and historical state claims.
//!
//! ```text
//! Q144 = recovery_session[32] | nonce[32] | sequence:u64be | mode:u8 |
//!        target:u8 | reserved[6] | original_prepared_digest[32] | parent_query[32]
//! K = version1 | Root_phase | runtime | cold_custody | reserved[3] |
//!     diagnostic_sequence:u64be | Root_witnesses[418] | lengths[3] | R | hot_archive | S
//! V/Z = version1 | phase | runtime | row_class | child_status | flags:u16be=0 |
//!       diagnostic_sequence:u64be | digests[5] | witness_length:u16be |
//!       reserved[6] | witness | lengths[4] | R | own_assertion | hot_terminal | child
//! ```
//!
//! A current signature reports owning-journal metadata. It cannot recreate an
//! old hot guard, descriptor, clock bracket, nonce or signing generation.

use aos_sandbox_core::ObjectDigest;

use super::assertion::{
    NativeHeldDispositionV1, NativeHeldSettlementV1, ProviderNativeSettlementAssertionV1,
    RootNativeDispositionAssertionV1, RootNativeObservationV1, StorageNativeSettlementAssertionV1,
};
use super::codec::{Reader, invalid, nonzero, put_length};
use super::frame::SignedNativeHeldControlV1;
use super::witness::{
    NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1, ROOT_NATIVE_WITNESS_FAMILIES_V1,
    decode_records, encode_records,
};
use super::{NativeHeldControlKindV1, NativeHeldOwnerV1, NativeHeldSectionTagV1, Result};

/// Bounds Root's complete historical assertion including its optional hot archive.
pub const MAXIMUM_ROOT_NATIVE_RECOVERY_ASSERTION_BYTES_V1: usize = 4_370;
/// Bounds Source's state with the one permitted exact Storage child.
pub const MAXIMUM_PROVIDER_NATIVE_RECOVERY_STATE_BYTES_V1: usize = 6_145;
/// Bounds Storage's state; Storage never carries another recovery child.
pub const MAXIMUM_STORAGE_NATIVE_RECOVERY_STATE_BYTES_V1: usize = 2_334;

/// Reports runtime availability separately from the retained durable phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldRuntimeStatusV1 {
    /// The actual owner reports healthy metadata, not production readiness.
    Healthy = 0,
    /// Only exact original recovery is available before general dispatch.
    RecoveryOnly = 1,
    /// The original operation retains a genuine cleanup obligation.
    CleanupRequired = 2,
}

impl NativeHeldRuntimeStatusV1 {
    pub(super) fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::RecoveryOnly),
            2 => Ok(Self::CleanupRequired),
            _ => Err(invalid("runtime status")),
        }
    }
}

/// Selects one closed metadata operation, never an effect retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldRecoveryModeV1 {
    /// Observes a validated prefix without any durable append.
    Observe = 1,
    /// Resolves an already committed irreversible Root disposition.
    SettleRecordedDisposition = 2,
    /// Proves Root terminal recording to resolve the retained signer-pin wait.
    RecordRootTerminal = 3,
}

impl NativeHeldRecoveryModeV1 {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Observe),
            2 => Ok(Self::SettleRecordedDisposition),
            3 => Ok(Self::RecordRootTerminal),
            _ => Err(invalid("recovery mode")),
        }
    }
}

/// Fixes Root-only metadata versus an actual retained native Requested child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldRecoveryTargetV1 {
    /// Retains Root's unchanged five-known-field scope.
    RootScope = 1,
    /// Uses an actual Source Requested full original scope.
    NativeScope = 2,
}

/// Correlates a current metadata query without renewing original authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeldRecoveryQueryV1 {
    /// Correlates the ephemeral current Root recovery association.
    pub recovery_session: ObjectDigest,
    /// Carries the one query's nonzero correlation nonce, not an effect challenge.
    pub nonce: [u8; 32],
    /// Uses the current recovery association's own sequence, not Acquire's counter.
    pub sequence: u64,
    /// Selects Observe, already-recorded settlement, or terminal pin acknowledgement.
    pub mode: NativeHeldRecoveryModeV1,
    /// Fixes Root-only versus actual native child context.
    pub target: NativeHeldRecoveryTargetV1,
    /// Commits the unchanged original signed RootPrepared, if it actually exists.
    pub original_prepared: ObjectDigest,
    /// Commits the entire signed Root9 in Storage11/12; zero only Root9/Source10.
    pub parent_root_query: ObjectDigest,
}

impl NativeHeldRecoveryQueryV1 {
    /// Encodes exact144-byte correlation without issuing a fresh authority nonce.
    ///
    /// # Errors
    ///
    /// Rejects sentinel current session, nonce or recovery sequence.
    pub fn to_canonical_bytes(&self) -> Result<[u8; 144]> {
        if !nonzero(self.recovery_session) || self.nonce == [0; 32] || self.sequence == 0 {
            return Err(invalid("recovery correlation"));
        }
        let mut bytes = [0; 144];
        bytes[..32].copy_from_slice(self.recovery_session.as_bytes());
        bytes[32..64].copy_from_slice(&self.nonce);
        bytes[64..72].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[72] = self.mode as u8;
        bytes[73] = self.target as u8;
        bytes[80..112].copy_from_slice(self.original_prepared.as_bytes());
        bytes[112..144].copy_from_slice(self.parent_root_query.as_bytes());
        Ok(bytes)
    }

    /// Decodes correlation claims without creating ordinary session mutation authority.
    ///
    /// # Errors
    ///
    /// Rejects wrong width, reserved fields, modes/targets or sentinel correlation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 144 {
            return Err(invalid("recovery query width"));
        }
        let mut reader = Reader::new(bytes);
        let recovery_session = reader.digest()?;
        let nonce = reader.array()?;
        let sequence = reader.u64()?;
        let mode = NativeHeldRecoveryModeV1::from_byte(reader.u8()?)?;
        let target = match reader.u8()? {
            1 => NativeHeldRecoveryTargetV1::RootScope,
            2 => NativeHeldRecoveryTargetV1::NativeScope,
            _ => return Err(invalid("recovery target")),
        };
        reader.zeros(6)?;
        let value = Self {
            recovery_session,
            nonce,
            sequence,
            mode,
            target,
            original_prepared: reader.digest()?,
            parent_root_query: reader.digest()?,
        };
        reader.finish()?;
        value.to_canonical_bytes()?;
        Ok(value)
    }

    /// Checks the exact query target, parent and mode implied by its control kind.
    ///
    /// # Errors
    ///
    /// Rejects hot kinds, child terminal ACKs or an incorrect parent/target profile.
    pub fn validate_for_kind(&self, kind: NativeHeldControlKindV1) -> Result<()> {
        self.to_canonical_bytes()?;
        match kind {
            NativeHeldControlKindV1::RootRecoveryQuery
            | NativeHeldControlKindV1::ProviderRecoveryState => {
                if self.target != NativeHeldRecoveryTargetV1::RootScope
                    || nonzero(self.parent_root_query)
                {
                    return Err(invalid("Root recovery query profile"));
                }
            }
            NativeHeldControlKindV1::ProviderStorageRecoveryQuery
            | NativeHeldControlKindV1::StorageRecoveryState => {
                if self.target != NativeHeldRecoveryTargetV1::NativeScope
                    || !nonzero(self.parent_root_query)
                    || !nonzero(self.original_prepared)
                    || self.mode == NativeHeldRecoveryModeV1::RecordRootTerminal
                {
                    return Err(invalid("Storage recovery query profile"));
                }
            }
            _ => return Err(invalid("recovery kind")),
        }
        Ok(())
    }
}

/// Reports no cold live-custody state; restart cannot recapture the original FD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldColdCustodyV1 {
    /// The actual owner cannot prove all descriptor copies absent.
    Unknown = 0,
    /// This cold owner has no original live descriptor token.
    Unavailable = 1,
}

/// Reports exact Root durable metadata without recreating a hot acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeRecoveryAssertionV1 {
    /// Retains the actual Root native durable phase, independent of runtime status.
    pub phase: u8,
    /// Reports this owner runtime's metadata availability.
    pub runtime_status: NativeHeldRuntimeStatusV1,
    /// Cannot claim live custody after restart.
    pub cold_custody: NativeHeldColdCustodyV1,
    /// Reports a diagnostic namespace40 sequence, not a protected snapshot.
    pub diagnostic_sequence: u64,
    /// Retains session/attempt/acquisition/head witnesses in their fixed order.
    pub records: [NativeHeldByteWitnessV1; 4],
    /// Retains committed unsigned R only at actual irreversible disposition phases.
    pub disposition: Option<RootNativeDispositionAssertionV1>,
    /// Optionally retains the exact original hot4/8; absence does not erase R.
    pub hot_archive: Option<Vec<u8>>,
    /// Retains complete stable IDs only after actual Root terminal recording.
    pub settlement: Option<NativeHeldSettlementV1>,
}

impl RootNativeRecoveryAssertionV1 {
    /// Encodes a bounded Root owning-journal claim, never its protected token.
    ///
    /// # Errors
    ///
    /// Rejects phase/presence, stable identity, archive or fixed-family mismatches.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.encode_at_depth(0)
    }

    /// Decodes canonical historical Root data without establishing currentness.
    ///
    /// # Errors
    ///
    /// Rejects oversize/truncated/noncanonical claims or any phase/archive mismatch.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_at_depth(bytes, 0)
    }

    pub(super) fn encode_at_depth(&self, depth: usize) -> Result<Vec<u8>> {
        self.validate_at_depth(depth)?;
        let mut bytes = vec![
            0,
            1,
            self.phase,
            self.runtime_status as u8,
            self.cold_custody as u8,
            0,
            0,
            0,
        ];
        bytes.extend_from_slice(&self.diagnostic_sequence.to_be_bytes());
        encode_records(&mut bytes, &self.records, &ROOT_NATIVE_WITNESS_FAMILIES_V1)?;
        let disposition = self
            .disposition
            .as_ref()
            .map(RootNativeDispositionAssertionV1::to_canonical_bytes)
            .transpose()?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let archive = self.hot_archive.as_deref().unwrap_or_default();
        let settlement = self
            .settlement
            .as_ref()
            .map(NativeHeldSettlementV1::to_canonical_bytes)
            .transpose()?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        for field in [&disposition[..], archive, &settlement[..]] {
            put_length(&mut bytes, field)?;
        }
        bytes.extend_from_slice(&disposition);
        bytes.extend_from_slice(archive);
        bytes.extend_from_slice(&settlement);
        if bytes.len() > MAXIMUM_ROOT_NATIVE_RECOVERY_ASSERTION_BYTES_V1 {
            return Err(super::NativeHeldCompletionErrorV1::LimitExceeded(
                "Root recovery assertion",
            ));
        }
        Ok(bytes)
    }

    pub(super) fn decode_at_depth(bytes: &[u8], depth: usize) -> Result<Self> {
        if bytes.len() > MAXIMUM_ROOT_NATIVE_RECOVERY_ASSERTION_BYTES_V1 {
            return Err(super::NativeHeldCompletionErrorV1::LimitExceeded(
                "Root recovery assertion",
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.u16()? != 1 {
            return Err(invalid("Root recovery version"));
        }
        let phase = reader.u8()?;
        let runtime_status = NativeHeldRuntimeStatusV1::from_byte(reader.u8()?)?;
        let cold_custody = match reader.u8()? {
            0 => NativeHeldColdCustodyV1::Unknown,
            1 => NativeHeldColdCustodyV1::Unavailable,
            _ => return Err(invalid("cold custody")),
        };
        reader.zeros(3)?;
        let diagnostic_sequence = reader.u64()?;
        let records = decode_records(&mut reader, ROOT_NATIVE_WITNESS_FAMILIES_V1)?;
        let lengths = [
            reader.u32()? as usize,
            reader.u32()? as usize,
            reader.u32()? as usize,
        ];
        let disposition = optional_root_assertion(reader.bytes(lengths[0])?)?;
        let hot_archive = optional_bytes(reader.bytes(lengths[1])?);
        let settlement_bytes = reader.bytes(lengths[2])?;
        let settlement = if settlement_bytes.is_empty() {
            None
        } else {
            Some(NativeHeldSettlementV1::from_canonical_bytes(
                settlement_bytes,
            )?)
        };
        reader.finish()?;
        let value = Self {
            phase,
            runtime_status,
            cold_custody,
            diagnostic_sequence,
            records,
            disposition,
            hot_archive,
            settlement,
        };
        if value.encode_at_depth(depth)? != bytes {
            return Err(invalid("Root recovery canonical bytes"));
        }
        Ok(value)
    }

    pub(super) fn validate_at_depth(&self, depth: usize) -> Result<()> {
        let class = match self.phase {
            0..=3 => None,
            4..=7 => Some(NativeHeldDispositionV1::Accepted),
            10..=13 => Some(NativeHeldDispositionV1::Closed),
            _ => return Err(invalid("Root durable phase")),
        };
        if self.disposition.as_ref().map(|value| value.disposition) != class
            || self.settlement.is_some() != matches!(self.phase, 6 | 7 | 12 | 13)
        {
            return Err(invalid("Root phase field presence"));
        }
        let mut witnesses = Vec::new();
        encode_records(
            &mut witnesses,
            &self.records,
            &ROOT_NATIVE_WITNESS_FAMILIES_V1,
        )?;
        if let Some(disposition) = &self.disposition {
            disposition.to_canonical_bytes()?;
            if disposition.records != self.records {
                return Err(invalid("Root assertion witnesses"));
            }
            if let Some(settlement) = &self.settlement {
                settlement.validate_for_kind(NativeHeldControlKindV1::RootTerminalRecorded)?;
                if settlement.disposition != disposition.disposition
                    || settlement.root_disposition != disposition.digest()?
                {
                    return Err(invalid("Root terminal identity"));
                }
            }
        }
        if let Some(archive) = &self.hot_archive {
            let control = SignedNativeHeldControlV1::decode_at_depth(archive, depth + 1)?;
            if !matches!(
                control.kind(),
                NativeHeldControlKindV1::RootAccepted | NativeHeldControlKindV1::RootClosed
            ) {
                return Err(invalid("Root hot archive kind"));
            }
            let archived = RootNativeDispositionAssertionV1::from_canonical_bytes(
                control
                    .section(NativeHeldSectionTagV1::RootDispositionAssertion)
                    .ok_or_else(|| invalid("Root archive R"))?,
            )?;
            if self.disposition.as_ref() != Some(&archived) {
                return Err(invalid("Root archive disposition identity"));
            }
        }
        Ok(())
    }
}

/// Distinguishes actual rows without converting unknown lookup into absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldRecoveryRowClassV1 {
    /// The owner reports a validated point-in-time absence, not permanent exclusion.
    Absent = 0,
    /// An actual Requested/native issuance row exists in this owner.
    Native = 1,
    /// Source has an actual Applying acquisition but no Requested row.
    ApplyingWithoutRequested = 2,
}

/// Fixes the exact presence of Source's optional verified Storage child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldRecoveryChildStatusV1 {
    /// No Storage query occurred; child bytes must be empty.
    NotQueried = 0,
    /// The exact matching signed Storage12 is present, not an arbitrary old archive.
    VerifiedState = 1,
    /// An actual eligible lookup failed; this is not an absence proof.
    Unreachable = 2,
}

/// Owns only the common mechanical fields of concrete Source/Storage metadata.
///
/// The enclosing typed wrapper fixes the owner. Owner reducers independently
/// establish actual row presence, signature provenance and the exact byte cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldRecoveryFieldsV1 {
    /// Retains the actual owner-specific durable phase; status never overwrites it.
    pub phase: u8,
    /// Reports availability separately from irreversible state.
    pub runtime_status: NativeHeldRuntimeStatusV1,
    /// Distinguishes native row, actual absence and Source-only Applying.
    pub row_class: NativeHeldRecoveryRowClassV1,
    /// Fixes whether exact Storage child bytes exist.
    pub child_status: NativeHeldRecoveryChildStatusV1,
    /// Reports the owner's diagnostic sequence, not a journal snapshot digest.
    pub diagnostic_sequence: u64,
    /// Uses the exact original signed native request digest only for actual rows.
    pub native_request: ObjectDigest,
    /// Uses the existing original unsigned acceptance digest, never a new issuance.
    pub acceptance: ObjectDigest,
    /// Uses the committed stable unsigned Root disposition ID, if it exists.
    pub root_disposition: ObjectDigest,
    /// Uses the committed stable unsigned Storage settlement ID, if it exists.
    pub storage_settlement: ObjectDigest,
    /// Uses the committed stable unsigned Provider settlement ID, if it exists.
    pub provider_settlement: ObjectDigest,
    /// Carries only the actual owner-specific native/acquisition/issuance witness.
    pub witness: Option<NativeHeldByteWitnessV1>,
    /// Retains original irreversible R; no recovery signature replaces its ID.
    pub disposition: Option<RootNativeDispositionAssertionV1>,
    /// Holds the exact concrete owner's stable unsigned488/336 assertion or empty.
    pub own_assertion: Vec<u8>,
    /// Optionally retains original hot6/7; missing hot signature does not erase IDs.
    pub hot_terminal: Option<Vec<u8>>,
    /// Holds the exact joined Storage12 only for Source VerifiedState.
    pub child: Option<Vec<u8>>,
}

/// Carries concrete Source metadata without giving Root a new Storage trust role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderNativeRecoveryStateV1 {
    /// Retains Source's fixed-format nonauthorizing metadata fields.
    pub fields: NativeHeldRecoveryFieldsV1,
}

/// Carries concrete Storage metadata, always with zero descriptors and no child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeRecoveryStateV1 {
    /// Retains Storage's fixed-format nonauthorizing metadata fields.
    pub fields: NativeHeldRecoveryFieldsV1,
}

impl ProviderNativeRecoveryStateV1 {
    /// Encodes Source metadata under its exact phase/family/presence rules.
    ///
    /// # Errors
    ///
    /// Rejects malformed Source state, unbounded child or substituted assertions.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.fields.encode_at_depth(NativeHeldOwnerV1::Provider, 0)
    }

    /// Decodes Source metadata without resolving original owner authority.
    ///
    /// # Errors
    ///
    /// Rejects canonical/phase/presence/family or finite child-nesting violations.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_at_depth(bytes, 0)
    }

    pub(super) fn decode_at_depth(bytes: &[u8], depth: usize) -> Result<Self> {
        Ok(Self {
            fields: NativeHeldRecoveryFieldsV1::decode_at_depth(
                NativeHeldOwnerV1::Provider,
                bytes,
                depth,
            )?,
        })
    }
}

impl StorageNativeRecoveryStateV1 {
    /// Encodes Storage metadata without creating an interest or retiring one.
    ///
    /// # Errors
    ///
    /// Rejects wrong row/phase/family, child bytes or inconsistent stable IDs.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.fields.encode_at_depth(NativeHeldOwnerV1::Storage, 0)
    }

    /// Decodes Storage metadata without renewing receipt, acceptance or FD custody.
    ///
    /// # Errors
    ///
    /// Rejects canonical/phase/presence/family or archive-nesting violations.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_at_depth(bytes, 0)
    }

    pub(super) fn decode_at_depth(bytes: &[u8], depth: usize) -> Result<Self> {
        Ok(Self {
            fields: NativeHeldRecoveryFieldsV1::decode_at_depth(
                NativeHeldOwnerV1::Storage,
                bytes,
                depth,
            )?,
        })
    }
}

impl NativeHeldRecoveryFieldsV1 {
    fn encode_at_depth(&self, owner: NativeHeldOwnerV1, depth: usize) -> Result<Vec<u8>> {
        self.validate_at_depth(owner, depth)?;
        let mut bytes = vec![
            0,
            1,
            self.phase,
            self.runtime_status as u8,
            self.row_class as u8,
            self.child_status as u8,
            0,
            0,
        ];
        bytes.extend_from_slice(&self.diagnostic_sequence.to_be_bytes());
        for digest in [
            self.native_request,
            self.acceptance,
            self.root_disposition,
            self.storage_settlement,
            self.provider_settlement,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        let witness = self
            .witness
            .as_ref()
            .map(NativeHeldByteWitnessV1::to_canonical_bytes)
            .unwrap_or_default();
        bytes.extend_from_slice(&(witness.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&witness);
        let disposition = self
            .disposition
            .as_ref()
            .map(RootNativeDispositionAssertionV1::to_canonical_bytes)
            .transpose()?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let hot_terminal = self.hot_terminal.as_deref().unwrap_or_default();
        let child = self.child.as_deref().unwrap_or_default();
        for field in [
            &disposition[..],
            &self.own_assertion[..],
            hot_terminal,
            child,
        ] {
            put_length(&mut bytes, field)?;
        }
        for field in [
            &disposition[..],
            &self.own_assertion[..],
            hot_terminal,
            child,
        ] {
            bytes.extend_from_slice(field);
        }
        if bytes.len() > state_maximum(owner)? {
            return Err(super::NativeHeldCompletionErrorV1::LimitExceeded(
                "owner recovery state",
            ));
        }
        Ok(bytes)
    }

    fn decode_at_depth(owner: NativeHeldOwnerV1, bytes: &[u8], depth: usize) -> Result<Self> {
        if bytes.len() > state_maximum(owner)? {
            return Err(super::NativeHeldCompletionErrorV1::LimitExceeded(
                "owner recovery state",
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.u16()? != 1 {
            return Err(invalid("owner recovery version"));
        }
        let phase = reader.u8()?;
        let runtime_status = NativeHeldRuntimeStatusV1::from_byte(reader.u8()?)?;
        let row_class = match reader.u8()? {
            0 => NativeHeldRecoveryRowClassV1::Absent,
            1 => NativeHeldRecoveryRowClassV1::Native,
            2 => NativeHeldRecoveryRowClassV1::ApplyingWithoutRequested,
            _ => return Err(invalid("recovery row class")),
        };
        let child_status = match reader.u8()? {
            0 => NativeHeldRecoveryChildStatusV1::NotQueried,
            1 => NativeHeldRecoveryChildStatusV1::VerifiedState,
            2 => NativeHeldRecoveryChildStatusV1::Unreachable,
            _ => return Err(invalid("recovery child status")),
        };
        reader.zeros(2)?;
        let diagnostic_sequence = reader.u64()?;
        let native_request = reader.digest()?;
        let acceptance = reader.digest()?;
        let root_disposition = reader.digest()?;
        let storage_settlement = reader.digest()?;
        let provider_settlement = reader.digest()?;
        let witness_length = usize::from(reader.u16()?);
        reader.zeros(6)?;
        let witness_bytes = reader.bytes(witness_length)?;
        let family = match (owner, row_class) {
            (_, NativeHeldRecoveryRowClassV1::Absent) => None,
            (NativeHeldOwnerV1::Provider, NativeHeldRecoveryRowClassV1::Native) => {
                Some(NativeHeldRecordFamilyV1::ProviderNative)
            }
            (
                NativeHeldOwnerV1::Provider,
                NativeHeldRecoveryRowClassV1::ApplyingWithoutRequested,
            ) => Some(NativeHeldRecordFamilyV1::ProviderAcquisition),
            (NativeHeldOwnerV1::Storage, NativeHeldRecoveryRowClassV1::Native) => {
                Some(NativeHeldRecordFamilyV1::StorageIssuance)
            }
            _ => return Err(invalid("owner recovery row class")),
        };
        let witness = match family {
            Some(family) => Some(NativeHeldByteWitnessV1::from_canonical_bytes(
                family,
                witness_bytes,
            )?),
            None if witness_bytes.is_empty() => None,
            None => return Err(invalid("absent witness")),
        };
        let lengths = [
            reader.u32()? as usize,
            reader.u32()? as usize,
            reader.u32()? as usize,
            reader.u32()? as usize,
        ];
        let disposition = optional_root_assertion(reader.bytes(lengths[0])?)?;
        let own_assertion = reader.bytes(lengths[1])?.to_vec();
        let hot_terminal = optional_bytes(reader.bytes(lengths[2])?);
        let child = optional_bytes(reader.bytes(lengths[3])?);
        reader.finish()?;
        let value = Self {
            phase,
            runtime_status,
            row_class,
            child_status,
            diagnostic_sequence,
            native_request,
            acceptance,
            root_disposition,
            storage_settlement,
            provider_settlement,
            witness,
            disposition,
            own_assertion,
            hot_terminal,
            child,
        };
        if value.encode_at_depth(owner, depth)? != bytes {
            return Err(invalid("owner recovery canonical bytes"));
        }
        Ok(value)
    }

    fn validate_at_depth(&self, owner: NativeHeldOwnerV1, depth: usize) -> Result<()> {
        let digests = [
            self.native_request,
            self.acceptance,
            self.root_disposition,
            self.storage_settlement,
            self.provider_settlement,
        ];
        if self.row_class != NativeHeldRecoveryRowClassV1::Native {
            let expected_family = match self.row_class {
                NativeHeldRecoveryRowClassV1::Absent => None,
                NativeHeldRecoveryRowClassV1::ApplyingWithoutRequested
                    if owner == NativeHeldOwnerV1::Provider =>
                {
                    Some(NativeHeldRecordFamilyV1::ProviderAcquisition)
                }
                _ => return Err(invalid("non-native recovery owner")),
            };
            if self.phase != 0
                || digests.iter().any(|value| nonzero(*value))
                || self.witness.as_ref().map(NativeHeldByteWitnessV1::family) != expected_family
                || self.disposition.is_some()
                || !self.own_assertion.is_empty()
                || self.hot_terminal.is_some()
                || self.child.is_some()
                || self.child_status != NativeHeldRecoveryChildStatusV1::NotQueried
            {
                return Err(invalid("absent/Applying field presence"));
            }
            if self
                .witness
                .as_ref()
                .is_some_and(|value| !nonzero(value.digest()))
            {
                return Err(invalid("Applying absence witness"));
            }
            return Ok(());
        }

        let family = match owner {
            NativeHeldOwnerV1::Provider => NativeHeldRecordFamilyV1::ProviderNative,
            NativeHeldOwnerV1::Storage => NativeHeldRecordFamilyV1::StorageIssuance,
            _ => return Err(invalid("recovery state owner")),
        };
        if !nonzero(self.native_request)
            || self
                .witness
                .as_ref()
                .is_none_or(|value| value.family() != family || !nonzero(value.digest()))
        {
            return Err(invalid("actual native row witness"));
        }
        if (owner == NativeHeldOwnerV1::Provider && self.phase > 10)
            || (owner == NativeHeldOwnerV1::Storage && self.phase > 5)
        {
            return Err(invalid("native durable phase"));
        }
        if owner == NativeHeldOwnerV1::Storage {
            if !nonzero(self.acceptance)
                || nonzero(self.provider_settlement)
                || self.child.is_some()
                || self.child_status != NativeHeldRecoveryChildStatusV1::NotQueried
            {
                return Err(invalid("Storage recovery fields"));
            }
        } else {
            // Cold Closed may skip StoragePrepared and stay unresolved at7.
            // It cannot fill a missing acceptance merely by advancing R's suffix.
            let acceptance_required = matches!(self.phase, 2..=6 | 8..=10)
                || (self.phase == 7
                    && self.disposition.as_ref().is_some_and(|value| {
                        value.disposition == NativeHeldDispositionV1::Accepted
                    }));
            if (acceptance_required && !nonzero(self.acceptance))
                || (self.phase < 2 && nonzero(self.acceptance))
            {
                return Err(invalid("Source retained acceptance"));
            }
            if (self.child_status == NativeHeldRecoveryChildStatusV1::VerifiedState)
                != self.child.is_some()
            {
                return Err(invalid("Source child presence"));
            }
        }
        let root_phase = if owner == NativeHeldOwnerV1::Provider {
            7
        } else {
            3
        };
        if nonzero(self.root_disposition) != self.disposition.is_some()
            || self.disposition.is_some() != (self.phase >= root_phase)
        {
            return Err(invalid("Root disposition phase presence"));
        }
        if let Some(disposition) = &self.disposition {
            if disposition.digest()? != self.root_disposition {
                return Err(invalid("stable Root disposition ID"));
            }
        }
        if owner == NativeHeldOwnerV1::Provider {
            if nonzero(self.storage_settlement) != (self.phase >= 8) {
                return Err(invalid("Source Store settlement phase"));
            }
            if nonzero(self.provider_settlement) != !self.own_assertion.is_empty()
                || (self.phase < 8 && !self.own_assertion.is_empty())
                || (self.phase >= 9 && self.own_assertion.is_empty())
            {
                return Err(invalid("Provider assertion phase presence"));
            }
            if !self.own_assertion.is_empty() {
                let own =
                    ProviderNativeSettlementAssertionV1::from_canonical_bytes(&self.own_assertion)?;
                if own.digest()? != self.provider_settlement
                    || own.root_disposition != self.root_disposition
                    || own.storage_settlement != self.storage_settlement
                    || self.disposition.as_ref().is_none_or(|value| {
                        value.disposition != own.disposition
                            || (value.observation == RootNativeObservationV1::ProviderHeldObserved
                                && value.source_artifact != own.source_artifact)
                    })
                {
                    return Err(invalid("Provider assertion identities"));
                }
            }
        } else {
            if nonzero(self.storage_settlement) != !self.own_assertion.is_empty()
                || (self.phase < 3 && !self.own_assertion.is_empty())
                || (self.phase >= 4 && self.own_assertion.is_empty())
            {
                return Err(invalid("Storage assertion phase presence"));
            }
            if !self.own_assertion.is_empty() {
                let own =
                    StorageNativeSettlementAssertionV1::from_canonical_bytes(&self.own_assertion)?;
                if own.digest()? != self.storage_settlement
                    || own.root_disposition != self.root_disposition
                    || own.acceptance.digest() != self.acceptance
                    || self.disposition.as_ref().is_none_or(|value| {
                        value.disposition != own.disposition
                            || (value.disposition == NativeHeldDispositionV1::Accepted
                                && value.descriptor_commitment
                                    != own.acceptance.descriptor_commitment())
                    })
                {
                    return Err(invalid("Storage assertion identities"));
                }
            }
        }
        if let Some(archive) = &self.hot_terminal {
            let stored_phase = if owner == NativeHeldOwnerV1::Provider {
                9
            } else {
                4
            };
            if self.phase < stored_phase {
                return Err(invalid("hot terminal before signature storage"));
            }
            let control = SignedNativeHeldControlV1::decode_at_depth(archive, depth + 1)?;
            let expected = if owner == NativeHeldOwnerV1::Provider {
                NativeHeldControlKindV1::ProviderSettled
            } else {
                NativeHeldControlKindV1::StorageSettled
            };
            if control.kind() != expected {
                return Err(invalid("original hot terminal kind"));
            }
            let settlement = NativeHeldSettlementV1::from_canonical_bytes(
                control
                    .section(NativeHeldSectionTagV1::Settlement)
                    .ok_or_else(|| invalid("terminal settlement"))?,
            )?;
            if settlement.root_disposition != self.root_disposition
                || settlement.storage_settlement != self.storage_settlement
                || settlement.provider_settlement != self.provider_settlement
                || self
                    .disposition
                    .as_ref()
                    .is_none_or(|value| value.disposition != settlement.disposition)
            {
                return Err(invalid("terminal stable identities"));
            }
        }
        if let Some(child) = &self.child {
            let control = SignedNativeHeldControlV1::decode_at_depth(child, depth + 1)?;
            if control.kind() != NativeHeldControlKindV1::StorageRecoveryState {
                return Err(invalid("Storage child kind"));
            }
        }
        Ok(())
    }
}

fn state_maximum(owner: NativeHeldOwnerV1) -> Result<usize> {
    match owner {
        NativeHeldOwnerV1::Provider => Ok(MAXIMUM_PROVIDER_NATIVE_RECOVERY_STATE_BYTES_V1),
        NativeHeldOwnerV1::Storage => Ok(MAXIMUM_STORAGE_NATIVE_RECOVERY_STATE_BYTES_V1),
        _ => Err(invalid("recovery state owner")),
    }
}

fn optional_root_assertion(bytes: &[u8]) -> Result<Option<RootNativeDispositionAssertionV1>> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            RootNativeDispositionAssertionV1::from_canonical_bytes(bytes)?,
        ))
    }
}

fn optional_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    (!bytes.is_empty()).then(|| bytes.to_vec())
}
