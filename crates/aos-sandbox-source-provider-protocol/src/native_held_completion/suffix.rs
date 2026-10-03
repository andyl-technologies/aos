//! Bounded append-once native archive and prepared-control data.
//!
//! ```text
//! AOSNHS01 | version:u16be=1 | owner:u8 | phase:u8 | flags:u16be=0 |
//! reserved:u16be=0 | flight[32] | prepared_length:u32be | count:u16be |
//! reserved:u16be=0 | exact_prepared | (kind:u8 | reserved[3] | length:u32be | signed)*
//! ```
//!
//! This module checks mechanical closed slots and phase shapes only. Actual
//! Root, Source and Storage reducers validate their own old/new canonical
//! records, allowed writes and before-image witnesses. No suffix is a writer
//! lease, currentness token, dispatch permit or successful-send acknowledgement.

use aos_sandbox_core::ObjectDigest;

use super::codec::{Reader, invalid, nonzero, put_length};
use super::frame::{PreparedNativeHeldControlV1, SignedNativeHeldControlV1};
use super::recovery::{NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1};
use super::{
    MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, MAXIMUM_NATIVE_HELD_PREPARED_BYTES_V1,
    MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1, MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1,
    NativeHeldCompletionErrorV1, NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner,
    NativeHeldSectionTagV1 as Tag, Result,
};

const MAGIC: &[u8; 8] = b"AOSNHS01";

/// Retains exact closed format claims for one owner's native journal suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldCompletionSuffixV1 {
    owner: Owner,
    phase: u8,
    flight: ObjectDigest,
    prepared: Option<PreparedNativeHeldControlV1>,
    controls: Vec<SignedNativeHeldControlV1>,
}

impl NativeHeldCompletionSuffixV1 {
    /// Validates one closed archive shape, not an owner transition proposal.
    ///
    /// # Errors
    ///
    /// Rejects unsupported phases, repeated slots, wrong preparation or scope joins.
    pub fn new(
        owner: Owner,
        phase: u8,
        flight: ObjectDigest,
        prepared: Option<PreparedNativeHeldControlV1>,
        controls: Vec<SignedNativeHeldControlV1>,
    ) -> Result<Self> {
        let value = Self {
            owner,
            phase,
            flight,
            prepared,
            controls,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the independently fixed record owner, not transferable custody.
    #[must_use]
    pub const fn owner(&self) -> Owner {
        self.owner
    }

    /// Returns the durable phase; RecoveryOnly never overwrites it.
    #[must_use]
    pub const fn phase(&self) -> u8 {
        self.phase
    }

    /// Returns the immutable original flight correlation.
    #[must_use]
    pub const fn flight(&self) -> ObjectDigest {
        self.flight
    }

    /// Returns the exact unescaped prepared frame, if the prefix has one.
    #[must_use]
    pub const fn prepared(&self) -> Option<&PreparedNativeHeldControlV1> {
        self.prepared.as_ref()
    }

    /// Returns retained controls in actual first durable insertion order.
    #[must_use]
    pub fn controls(&self) -> &[SignedNativeHeldControlV1] {
        &self.controls
    }

    /// Finds a retained kind without inventing a missing signature archive.
    #[must_use]
    pub fn control(&self, kind: Kind) -> Option<&SignedNativeHeldControlV1> {
        self.controls.iter().find(|control| control.kind() == kind)
    }

    /// Encodes the bounded suffix; it cannot grant an owning-journal append scope.
    ///
    /// # Errors
    ///
    /// Rejects the same closed slot/prefix invariants as construction.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let prepared = self
            .prepared
            .as_ref()
            .map(PreparedNativeHeldControlV1::to_canonical_bytes)
            .unwrap_or_default();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[self.owner as u8, self.phase]);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(self.flight.as_bytes());
        put_length(&mut bytes, &prepared)?;
        bytes.extend_from_slice(&(self.controls.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&prepared);
        for control in &self.controls {
            let encoded = control.to_canonical_bytes();
            bytes.push(control.kind() as u8);
            bytes.extend_from_slice(&[0; 3]);
            put_length(&mut bytes, &encoded)?;
            bytes.extend_from_slice(&encoded);
        }
        if bytes.len() > MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1 {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded("native suffix"));
        }
        Ok(bytes)
    }

    /// Decodes bounded archive data before any actual owner graph admission.
    ///
    /// # Errors
    ///
    /// Rejects oversize allocation, malformed headers/lengths or any closed-slot violation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1 {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded("native suffix"));
        }
        let mut reader = Reader::new(bytes);
        reader.header(MAGIC)?;
        let owner = Owner::from_byte(reader.u8()?)?;
        let phase = reader.u8()?;
        reader.zeros(4)?;
        let flight = reader.digest()?;
        let prepared_length = reader.u32()? as usize;
        let count = usize::from(reader.u16()?);
        reader.zeros(2)?;
        if prepared_length > MAXIMUM_NATIVE_HELD_PREPARED_BYTES_V1
            || count > MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1
        {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "suffix preparation or archive count",
            ));
        }
        let prepared = if prepared_length == 0 {
            None
        } else {
            Some(PreparedNativeHeldControlV1::from_canonical_bytes(
                reader.bytes(prepared_length)?,
            )?)
        };
        let mut controls = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = Kind::from_byte(reader.u8()?)?;
            reader.zeros(3)?;
            let length = reader.u32()? as usize;
            if length > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1 {
                return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                    "retained control",
                ));
            }
            let control = SignedNativeHeldControlV1::from_canonical_bytes(reader.bytes(length)?)?;
            if control.kind() != kind {
                return Err(invalid("retained kind/header mismatch"));
            }
            controls.push(control);
        }
        reader.finish()?;
        let value = Self::new(owner, phase, flight, prepared, controls)?;
        if value.to_canonical_bytes()? != bytes {
            return Err(invalid("suffix canonical bytes"));
        }
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if !nonzero(self.flight) {
            return Err(invalid("suffix flight"));
        }
        if self.controls.len() > MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1 {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "retained controls",
            ));
        }
        let mut slots = Vec::with_capacity(self.controls.len());
        for control in &self.controls {
            if control.scope().flight != self.flight {
                return Err(invalid("archive original flight"));
            }
            let slot = retained_slot(self.owner, control)?;
            if slots.contains(&slot) {
                return Err(invalid("repeated append-once slot"));
            }
            slots.push(slot);
        }
        if let Some(prepared) = &self.prepared {
            if prepared.kind().sender() != self.owner
                || prepared.scope().flight != self.flight
                || self
                    .controls
                    .iter()
                    .any(|control| control.kind() == prepared.kind())
            {
                return Err(invalid("prepared owner/flight/stored successor"));
            }
            validate_prepared_phase(self.owner, self.phase, prepared.kind())?;
        }
        match self.owner {
            Owner::Root => self.validate_root_slots()?,
            Owner::Provider => self.validate_provider_slots()?,
            Owner::Storage => self.validate_storage_slots()?,
        }
        // Scalar flight equality is not enough to join different original fields.
        if let Some(original) = self.control(Kind::RootPrepared) {
            for control in &self.controls {
                if control.scope().is_root_only() {
                    if control.scope() != original.scope() {
                        return Err(invalid("archive Root-only scope"));
                    }
                } else {
                    control.scope().require_root_prefix(original.scope())?;
                }
            }
            if let Some(prepared) = &self.prepared {
                if prepared.scope().is_root_only() {
                    if prepared.scope() != original.scope() {
                        return Err(invalid("prepared original Root scope"));
                    }
                } else {
                    prepared.scope().require_root_prefix(original.scope())?;
                }
            }
        }
        let full_scope = self
            .controls
            .iter()
            .map(SignedNativeHeldControlV1::scope)
            .chain(self.prepared.iter().map(PreparedNativeHeldControlV1::scope))
            .find(|scope| !scope.is_root_only());
        if let Some(original) = full_scope {
            if self
                .controls
                .iter()
                .map(SignedNativeHeldControlV1::scope)
                .chain(self.prepared.iter().map(PreparedNativeHeldControlV1::scope))
                .any(|scope| !scope.is_root_only() && scope != original)
            {
                return Err(invalid("immutable full native archive scope"));
            }
        }
        self.validate_hot_signer_references()?;
        Ok(())
    }

    fn validate_hot_signer_references(&self) -> Result<()> {
        let anchor = match self.owner {
            Owner::Root => self.control(Kind::RootPrepared),
            Owner::Provider => self.control(Kind::ProviderHeld),
            Owner::Storage => self.control(Kind::StorageHeld),
        };
        if let Some(anchor) = anchor {
            for control in &self.controls {
                if control.kind().sender() == self.owner
                    && !control.kind().is_recovery()
                    && control.prepared().signer() != anchor.prepared().signer()
                {
                    return Err(invalid("original hot signer reference changed"));
                }
            }
            if let Some(prepared) = &self.prepared {
                if !prepared.kind().is_recovery() && prepared.signer() != anchor.prepared().signer()
                {
                    return Err(invalid("original prepared signer reference changed"));
                }
            }
        }
        Ok(())
    }

    fn validate_root_slots(&self) -> Result<()> {
        if !matches!(self.phase, 0..=7 | 10..=13) {
            return Err(invalid("Root suffix phase"));
        }
        let original = self.control(Kind::RootPrepared);
        if self.phase == 0 {
            if !self.controls.is_empty()
                || self
                    .prepared
                    .as_ref()
                    .is_none_or(|control| control.kind() != Kind::RootPrepared)
            {
                return Err(invalid("Root initial unsigned preparation"));
            }
        } else if self.phase != 10 && original.is_none() {
            return Err(invalid("Root missing original signed preparation"));
        }
        if matches!(self.phase, 2..=7) && self.control(Kind::ProviderHeld).is_none() {
            return Err(invalid("Root missing original held offer"));
        }
        if self.phase == 5 && self.control(Kind::RootAccepted).is_none() {
            return Err(invalid("Root missing stored Accepted"));
        }
        if self.phase == 11 && self.control(Kind::RootClosed).is_none() {
            return Err(invalid("Root missing stored Closed"));
        }
        if self.control(Kind::RootAccepted).is_some() && self.control(Kind::RootClosed).is_some() {
            return Err(invalid("both irreversible Root dispositions"));
        }
        if self.control(Kind::ProviderSettled).is_some()
            && self.control(Kind::ProviderRecoveryState).is_some()
        {
            return Err(invalid("both Root terminal carriers"));
        }
        if self.control(Kind::RootTerminalRecorded).is_some()
            && self.control(Kind::RootRecoveryQuery).is_some()
        {
            return Err(invalid("both Root ACK alternatives"));
        }
        if self.control(Kind::RootAccepted).is_some() && self.phase < 5 {
            return Err(invalid("Root AcceptedStored phase"));
        }
        if self.control(Kind::RootClosed).is_some() && self.phase < 11 {
            return Err(invalid("Root ClosedStored phase"));
        }
        if self.phase >= 10 && self.control(Kind::RootAccepted).is_some() {
            return Err(invalid("Accepted cannot become Closed"));
        }
        if matches!(self.phase, 0..=7) && self.control(Kind::RootClosed).is_some() {
            return Err(invalid("Closed cannot become Accepted"));
        }
        let terminal = self.control(Kind::ProviderSettled).is_some()
            || self.control(Kind::ProviderRecoveryState).is_some();
        if terminal != matches!(self.phase, 6 | 7 | 12 | 13) {
            return Err(invalid("Root terminal carrier phase"));
        }
        let ack = self.control(Kind::RootTerminalRecorded).is_some()
            || self.control(Kind::RootRecoveryQuery).is_some();
        if ack != matches!(self.phase, 7 | 13) {
            return Err(invalid("Root terminal ACK phase"));
        }
        Ok(())
    }

    fn validate_provider_slots(&self) -> Result<()> {
        if self.phase > 10 || self.control(Kind::RootPrepared).is_none() {
            return Err(invalid("Source Requested original preparation"));
        }
        if self.control(Kind::RootAccepted).is_some() && self.control(Kind::RootClosed).is_some() {
            return Err(invalid("both Source Root dispositions"));
        }
        if self.control(Kind::RootTerminalRecorded).is_some()
            && self.controls.iter().any(|control| {
                control.kind() == Kind::RootRecoveryQuery
                    && recovery_mode(control).ok()
                        == Some(NativeHeldRecoveryModeV1::RecordRootTerminal)
            })
        {
            return Err(invalid("both Source terminal ACK alternatives"));
        }
        for control in &self.controls {
            let earliest = match control.kind() {
                Kind::RootPrepared => 0,
                Kind::StorageHeld => 2,
                Kind::ProviderHeld => 6,
                Kind::RootAccepted
                | Kind::RootClosed
                | Kind::ProviderRelay
                | Kind::RootRecoveryQuery
                | Kind::ProviderStorageRecoveryQuery => 7,
                Kind::StorageSettled | Kind::StorageRecoveryState => 8,
                Kind::ProviderSettled | Kind::ProviderRecoveryState => 9,
                Kind::RootTerminalRecorded => 10,
            };
            // The terminal Root9 occupies its own last slot, not the first Settle9.
            let earliest = if control.kind() == Kind::RootRecoveryQuery
                && recovery_mode(control)? == NativeHeldRecoveryModeV1::RecordRootTerminal
            {
                10
            } else {
                earliest
            };
            if self.phase < earliest {
                return Err(invalid("Source archive phase"));
            }
        }
        if self.phase == 10
            && self.control(Kind::RootTerminalRecorded).is_none()
            && !self.controls.iter().any(|control| {
                control.kind() == Kind::RootRecoveryQuery
                    && recovery_mode(control).ok()
                        == Some(NativeHeldRecoveryModeV1::RecordRootTerminal)
            })
        {
            return Err(invalid("Source terminal readback proof"));
        }
        Ok(())
    }

    fn validate_storage_slots(&self) -> Result<()> {
        if self.phase > 5 || self.control(Kind::RootPrepared).is_none() {
            return Err(invalid("Storage original acceptance prefix"));
        }
        if self.control(Kind::StorageHeld).is_some() && self.phase < 2 {
            return Err(invalid("Storage HeldStored phase"));
        }
        if self.control(Kind::ProviderRelay).is_some() && self.phase < 3 {
            return Err(invalid("Storage Root disposition phase"));
        }
        if (self.control(Kind::StorageSettled).is_some()
            || self.control(Kind::StorageRecoveryState).is_some())
            != (self.phase >= 4)
        {
            return Err(invalid("Storage terminal carrier phase"));
        }
        if self.control(Kind::ProviderStorageRecoveryQuery).is_some() && self.phase < 3 {
            return Err(invalid("Storage first recovery proof phase"));
        }
        if self.control(Kind::StorageRecoveryState).is_some()
            && self.control(Kind::ProviderStorageRecoveryQuery).is_none()
        {
            return Err(invalid("Storage12 missing exact11"));
        }
        if self.phase == 4
            && self.control(Kind::StorageSettled).is_some()
            && self.control(Kind::StorageRecoveryState).is_some()
            && self.prepared.is_some()
        {
            return Err(invalid("already-settled metadata exception preparation"));
        }
        // The actual Storage reducer alone permits R4's atomic first11+12 append:
        // old settled4/normal6/empty slots -> same4/exact two new archives.
        Ok(())
    }
}

fn recovery_mode(control: &SignedNativeHeldControlV1) -> Result<NativeHeldRecoveryModeV1> {
    Ok(NativeHeldRecoveryQueryV1::from_canonical_bytes(
        control
            .section(Tag::RecoveryQuery)
            .ok_or_else(|| invalid("retained recovery query"))?,
    )?
    .mode)
}

fn retained_slot(owner: Owner, control: &SignedNativeHeldControlV1) -> Result<u8> {
    let kind = control.kind();
    match owner {
        Owner::Root => match kind {
            Kind::RootPrepared => Ok(1),
            Kind::ProviderHeld => Ok(2),
            Kind::RootAccepted | Kind::RootClosed => Ok(3),
            Kind::ProviderSettled => Ok(4),
            Kind::ProviderRecoveryState
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(4)
            }
            Kind::RootTerminalRecorded => Ok(5),
            Kind::RootRecoveryQuery
                if recovery_mode(control)? == NativeHeldRecoveryModeV1::RecordRootTerminal =>
            {
                Ok(5)
            }
            _ => Err(invalid("Root retained kind/mode")),
        },
        Owner::Provider => match kind {
            Kind::RootPrepared => Ok(1),
            Kind::StorageHeld => Ok(2),
            Kind::ProviderHeld => Ok(3),
            Kind::RootAccepted | Kind::RootClosed => Ok(4),
            Kind::ProviderRelay => Ok(5),
            Kind::StorageSettled => Ok(6),
            Kind::ProviderSettled => Ok(7),
            Kind::RootRecoveryQuery
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(8)
            }
            Kind::ProviderStorageRecoveryQuery
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(9)
            }
            Kind::StorageRecoveryState
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(10)
            }
            Kind::ProviderRecoveryState
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(11)
            }
            Kind::RootTerminalRecorded => Ok(12),
            Kind::RootRecoveryQuery
                if recovery_mode(control)? == NativeHeldRecoveryModeV1::RecordRootTerminal =>
            {
                Ok(12)
            }
            _ => Err(invalid("Source retained kind/mode")),
        },
        Owner::Storage => match kind {
            Kind::RootPrepared => Ok(1),
            Kind::StorageHeld => Ok(2),
            Kind::ProviderRelay => Ok(3),
            Kind::StorageSettled => Ok(4),
            Kind::ProviderStorageRecoveryQuery
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(5)
            }
            Kind::StorageRecoveryState
                if recovery_mode(control)?
                    == NativeHeldRecoveryModeV1::SettleRecordedDisposition =>
            {
                Ok(6)
            }
            _ => Err(invalid("Storage retained kind/mode")),
        },
    }
}

fn validate_prepared_phase(owner: Owner, phase: u8, kind: Kind) -> Result<()> {
    let legal = match owner {
        Owner::Root => matches!(
            (phase, kind),
            (0, Kind::RootPrepared)
                | (4, Kind::RootAccepted)
                | (10, Kind::RootClosed)
                | (6 | 12, Kind::RootTerminalRecorded)
        ),
        Owner::Provider => matches!(
            (phase, kind),
            (5, Kind::ProviderHeld)
                | (7, Kind::ProviderRelay)
                | (8, Kind::ProviderSettled)
                | (7..=9, Kind::ProviderStorageRecoveryQuery)
                | (8 | 9, Kind::ProviderRecoveryState)
        ),
        Owner::Storage => matches!(
            (phase, kind),
            (1, Kind::StorageHeld) | (3, Kind::StorageSettled | Kind::StorageRecoveryState)
        ),
    };
    if !legal {
        return Err(invalid("prepared exact owner checkpoint"));
    }
    Ok(())
}
