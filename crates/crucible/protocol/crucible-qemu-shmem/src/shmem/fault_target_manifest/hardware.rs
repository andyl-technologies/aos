//! Hardware-error capability vocabulary, rows, and manifests.

use super::*;

/// Guest-visible hardware-error record family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorRecordKindV1 {
    /// x86 machine-check architecture record.
    X86MachineCheck = 1,
    /// AArch64 RAS exception record.
    Aarch64Ras = 2,
    /// Platform memory ECC record.
    MemoryEcc = 3,
}

impl FaultHardwareErrorRecordKindV1 {
    /// Decodes one registered record-family tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::X86MachineCheck),
            2 => Ok(Self::Aarch64Ras),
            3 => Ok(Self::MemoryEcc),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Severity or delivery class of one hardware-error row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorClassV1 {
    /// Corrected record without uncorrectable delivery.
    Corrected = 1,
    /// Recoverable uncorrectable error.
    Recoverable = 2,
    /// Fatal uncorrectable error linked to lifecycle handling.
    Fatal = 3,
    /// Synchronous AArch64 external abort.
    Synchronous = 4,
    /// Asynchronous AArch64 SError.
    Asynchronous = 5,
}

impl FaultHardwareErrorClassV1 {
    /// Decodes one registered error-class tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Corrected),
            2 => Ok(Self::Recoverable),
            3 => Ok(Self::Fatal),
            4 => Ok(Self::Synchronous),
            5 => Ok(Self::Asynchronous),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Real guest-visible mechanism used to publish a hardware error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorMechanismV1 {
    /// x86 MCA banks and machine-check delivery.
    X86Mca = 1,
    /// ACPI APEI GHES memory error record.
    AcpiGhes = 2,
    /// AArch64 RAS synchronous abort or SError.
    Aarch64Ras = 3,
}

impl FaultHardwareErrorMechanismV1 {
    /// Decodes one registered delivery-mechanism tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::X86Mca),
            2 => Ok(Self::AcpiGhes),
            3 => Ok(Self::Aarch64Ras),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Publishes a guest-visible telemetry record without exception delivery.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY: u16 = 1 << 0;
/// Delivers a corrected-error interrupt when the realized mechanism supports it.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT: u16 = 1 << 1;
/// Delivers the complete architecture exception described by the command.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION: u16 = 1 << 2;
/// Every hardware-error visibility bit understood by codec version 1.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK: u16 = (1 << 3) - 1;
/// Every x86 CPL or AArch64 exception level represented by a manifest row.
pub const FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK: u16 = (1 << 4) - 1;

/// One immutable architecture or platform hardware-error capability row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultHardwareErrorCapabilityRowV1 {
    /// Stable row identity.
    pub id: String,
    /// Stable architecture bank or platform record identity.
    pub bank: String,
    /// Stable memory-channel identity.
    pub channel: String,
    /// Stable memory-rank identity.
    pub rank: String,
    /// Exact firmware or table prerequisite.
    pub firmware: String,
    /// Exact resulting QEMU and guest-visible state contract.
    pub state: String,
    /// Typed record family.
    pub record_kind: FaultHardwareErrorRecordKindV1,
    /// Error severity or AArch64 delivery class.
    pub error_class: FaultHardwareErrorClassV1,
    /// Real publication and delivery mechanism.
    pub mechanism: FaultHardwareErrorMechanismV1,
    /// Permitted telemetry, interrupt, and exception visibility modes.
    pub visibility_mask: u16,
    /// First numeric architecture bank or platform record.
    pub bank_number: u32,
    /// Number of consecutive banks or records in this row.
    pub bank_count: u32,
    /// Required architecture vector or exception class.
    pub vector: u32,
    /// Status bits that every request must set.
    pub status_required: u64,
    /// Complete mask of status bits a request may set.
    pub status_allowed: u64,
    /// Syndrome bits that every request must set.
    pub syndrome_required: u64,
    /// Complete mask of syndrome bits a request may set.
    pub syndrome_allowed: u64,
    /// Fault-model phases at which the row can apply.
    pub model_phase_mask: u64,
    /// x86 CPL or AArch64 EL bit set admitted by this row.
    pub privilege_mask: u16,
    /// Identifies a corrected rather than uncorrectable record.
    pub corrected: bool,
    /// Allows architecture masking to defer delivery.
    pub maskable: bool,
    /// Confirms that resulting architecture/platform state participates in VMState.
    pub vmstate: bool,
}

impl FaultHardwareErrorCapabilityRowV1 {
    fn validate(&self, architecture: FaultCapabilityScope) -> Result<(), FaultAbiError> {
        let identities = [
            self.id.as_str(),
            self.bank.as_str(),
            self.channel.as_str(),
            self.rank.as_str(),
            self.firmware.as_str(),
            self.state.as_str(),
        ];
        let x86 = architecture == FaultCapabilityScope::X86_64;
        let arm = architecture == FaultCapabilityScope::Aarch64;
        let mechanism_matches = match self.mechanism {
            FaultHardwareErrorMechanismV1::X86Mca => x86,
            FaultHardwareErrorMechanismV1::AcpiGhes | FaultHardwareErrorMechanismV1::Aarch64Ras => {
                arm
            }
        };
        let record_matches = match self.record_kind {
            FaultHardwareErrorRecordKindV1::X86MachineCheck => {
                x86 && self.mechanism == FaultHardwareErrorMechanismV1::X86Mca
            }
            FaultHardwareErrorRecordKindV1::Aarch64Ras => {
                arm && self.mechanism == FaultHardwareErrorMechanismV1::Aarch64Ras
            }
            FaultHardwareErrorRecordKindV1::MemoryEcc => matches!(
                self.mechanism,
                FaultHardwareErrorMechanismV1::X86Mca | FaultHardwareErrorMechanismV1::AcpiGhes
            ),
        };
        let class_matches = match self.mechanism {
            FaultHardwareErrorMechanismV1::X86Mca => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Corrected
                    | FaultHardwareErrorClassV1::Recoverable
                    | FaultHardwareErrorClassV1::Fatal
            ),
            FaultHardwareErrorMechanismV1::AcpiGhes => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Corrected | FaultHardwareErrorClassV1::Recoverable
            ),
            FaultHardwareErrorMechanismV1::Aarch64Ras => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Synchronous
                    | FaultHardwareErrorClassV1::Asynchronous
                    | FaultHardwareErrorClassV1::Fatal
            ),
        };
        let visibility_valid = self.visibility_mask != 0
            && self.visibility_mask & !FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK == 0
            && if self.corrected {
                self.visibility_mask
                    & (FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
                        | FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT)
                    != 0
                    && self.visibility_mask & FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION == 0
            } else {
                self.visibility_mask == FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
            };
        if identities
            .iter()
            .any(|identity| !valid_hardware_identity(identity))
            || identities
                .iter()
                .any(|identity| identity.len() > HARD_FAULT_TARGET_NAME_BYTES)
            || !mechanism_matches
            || !record_matches
            || !class_matches
            || self.bank_count == 0
            || self.bank_number.checked_add(self.bank_count).is_none()
            || self.status_required & !self.status_allowed != 0
            || self.syndrome_required & !self.syndrome_allowed != 0
            || self.model_phase_mask == 0
            || self.model_phase_mask & !FAULT_MODEL_PHASES_V1_MASK != 0
            || self.privilege_mask == 0
            || self.privilege_mask & !FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK != 0
            || !visibility_valid
            || self.corrected != (self.error_class == FaultHardwareErrorClassV1::Corrected)
            || (x86 && self.vector != 18)
            || (arm && self.vector != if self.maskable { 47 } else { 3 })
            || (self.maskable && self.mechanism != FaultHardwareErrorMechanismV1::Aarch64Ras)
            || (self.error_class == FaultHardwareErrorClassV1::Asynchronous && !self.maskable)
            || (self.error_class == FaultHardwareErrorClassV1::Synchronous && self.maskable)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    fn encode(
        &self,
        architecture: FaultCapabilityScope,
        output: &mut Vec<u8>,
    ) -> Result<(), FaultAbiError> {
        self.validate(architecture)?;
        let identities = [
            self.id.as_str(),
            self.bank.as_str(),
            self.channel.as_str(),
            self.rank.as_str(),
            self.firmware.as_str(),
            self.state.as_str(),
        ];
        let lengths = identities
            .iter()
            .map(|identity| {
                u16::try_from(identity.len()).map_err(|_| FaultAbiError::CapabilityInvariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let identity_bytes = identities.iter().try_fold(0_usize, |total, identity| {
            total
                .checked_add(identity.len())
                .ok_or(FaultAbiError::CapabilityInvariant)
        })?;
        let row_len = FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES
            .checked_add(identity_bytes)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&(self.record_kind as u16).to_le_bytes());
        output.extend_from_slice(&(self.error_class as u16).to_le_bytes());
        output.extend_from_slice(&(self.mechanism as u16).to_le_bytes());
        output.extend_from_slice(&self.visibility_mask.to_le_bytes());
        output.extend_from_slice(&self.bank_number.to_le_bytes());
        output.extend_from_slice(&self.bank_count.to_le_bytes());
        output.extend_from_slice(&self.vector.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&self.status_required.to_le_bytes());
        output.extend_from_slice(&self.status_allowed.to_le_bytes());
        output.extend_from_slice(&self.syndrome_required.to_le_bytes());
        output.extend_from_slice(&self.syndrome_allowed.to_le_bytes());
        output.extend_from_slice(&self.model_phase_mask.to_le_bytes());
        output.extend_from_slice(&self.privilege_mask.to_le_bytes());
        output.push(u8::from(self.corrected));
        output.push(u8::from(self.maskable));
        output.push(u8::from(self.vmstate));
        output.push(0);
        for length in lengths {
            output.extend_from_slice(&length.to_le_bytes());
        }
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(row_len)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?
                .to_le_bytes(),
        );
        for identity in identities {
            output.extend_from_slice(identity.as_bytes());
        }
        Ok(())
    }
}

/// Exact hardware-error manifest for one realized QEMU machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultHardwareErrorCapabilityManifestV1 {
    /// Architecture scope of every row.
    pub architecture: FaultCapabilityScope,
    /// Canonically ordered hardware-error rows.
    pub rows: Vec<FaultHardwareErrorCapabilityRowV1>,
}

impl FaultHardwareErrorCapabilityManifestV1 {
    fn validate_completeness(&self) -> Result<(), FaultAbiError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let has = |id: &str| self.rows.iter().any(|row| row.id == id);
        let required: &[&str] = match self.architecture {
            FaultCapabilityScope::X86_64 => &[
                "x86.machine-check.corrected",
                "x86.machine-check.recoverable",
                "x86.machine-check.fatal",
            ],
            FaultCapabilityScope::Aarch64 => &[
                "aarch64.ras.synchronous",
                "aarch64.ras.synchronous-fatal",
                "aarch64.ras.asynchronous",
                "aarch64.ras.asynchronous-fatal",
            ],
            _ => return Err(FaultAbiError::CapabilityInvariant),
        };
        if required.iter().any(|id| !has(id)) {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let has_corrected_memory = has("memory.ecc.corrected");
        let has_uncorrectable_memory = has("memory.ecc.uncorrectable");
        if has_corrected_memory != has_uncorrectable_memory {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    /// Encodes a canonical self-authenticating hardware-error manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for invalid rows, architecture, ordering,
    /// masks, identities, or payload size.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.rows.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        self.validate_completeness()?;
        let mut body = Vec::new();
        for row in &self.rows {
            row.encode(self.architecture, &mut body)?;
        }
        let maximum_body_bytes = usize::try_from(crate::HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_| FaultAbiError::PayloadLimit)?
            .checked_sub(FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if body.len() > maximum_body_bytes {
            return Err(FaultAbiError::PayloadLimit);
        }
        let mut output =
            Vec::with_capacity(FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1.to_le_bytes());
        output.extend_from_slice(&(self.architecture as u16).to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(self.rows.len())
                .map_err(|_| FaultAbiError::CapabilityInvariant)?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| FaultAbiError::PayloadLimit)?
                .to_le_bytes(),
        );
        output.extend_from_slice(blake3::hash(&body).as_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes and authenticates a canonical hardware-error manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, digest, fields,
    /// identities, ordering, or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16_at(bytes, 8)? != FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1 || u32_at(bytes, 12)? != 0
        {
            return Err(FaultAbiError::Version);
        }
        let architecture = FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?;
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count > HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        if bytes.len()
            != FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES
                .checked_add(body_len)
                .ok_or(FaultAbiError::PayloadLimit)?
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let mut offset = 0;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES];
            if u32_at(header, 20)? != 0 || header[69] != 0 || u16_at(header, 82)? != 0 {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let corrected = bool_at(header, 66)?;
            let maskable = bool_at(header, 67)?;
            let vmstate = bool_at(header, 68)?;
            let lengths = [70, 72, 74, 76, 78, 80]
                .into_iter()
                .map(|field| u16_at(header, field).map(usize::from))
                .collect::<Result<Vec<_>, _>>()?;
            let row_len = usize::try_from(u32_at(header, 84)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let calculated = lengths
                .iter()
                .try_fold(FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES, |total, length| {
                    total.checked_add(*length)
                });
            if calculated != Some(row_len) || body.len().saturating_sub(offset) < row_len {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES;
            let id = take_text(body, &mut cursor, lengths[0])?;
            let bank = take_text(body, &mut cursor, lengths[1])?;
            let channel = take_text(body, &mut cursor, lengths[2])?;
            let rank = take_text(body, &mut cursor, lengths[3])?;
            let firmware = take_text(body, &mut cursor, lengths[4])?;
            let state = take_text(body, &mut cursor, lengths[5])?;
            let row = FaultHardwareErrorCapabilityRowV1 {
                id,
                bank,
                channel,
                rank,
                firmware,
                state,
                record_kind: FaultHardwareErrorRecordKindV1::from_u16(u16_at(header, 0)?)?,
                error_class: FaultHardwareErrorClassV1::from_u16(u16_at(header, 2)?)?,
                mechanism: FaultHardwareErrorMechanismV1::from_u16(u16_at(header, 4)?)?,
                visibility_mask: u16_at(header, 6)?,
                bank_number: u32_at(header, 8)?,
                bank_count: u32_at(header, 12)?,
                vector: u32_at(header, 16)?,
                status_required: u64_at(header, 24)?,
                status_allowed: u64_at(header, 32)?,
                syndrome_required: u64_at(header, 40)?,
                syndrome_allowed: u64_at(header, 48)?,
                model_phase_mask: u64_at(header, 56)?,
                privilege_mask: u16_at(header, 64)?,
                corrected,
                maskable,
                vmstate,
            };
            row.validate(architecture)?;
            rows.push(row);
            offset += row_len;
        }
        if offset != body.len() {
            return Err(FaultAbiError::HeaderLength);
        }
        let manifest = Self { architecture, rows };
        if manifest.encode()?.as_slice() != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(manifest)
    }
}
