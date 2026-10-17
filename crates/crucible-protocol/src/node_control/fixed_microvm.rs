//! Original fixed-microvm source preparation and bounded dispatch policy.
//!
//! This record preserves the original administrative, phase and construction
//! companions. Native enrollment separately measures actual device objects and
//! initial firmware bytes. Neither matching this pin nor selecting its effect
//! edition creates a root seal, closes input, grants effects or supplies Ready.
//! Firmware is writable guest memory after its original loading measurement.
//!
//! ```text
//! CNMICR01 | administration_length:u32be | administration_bytes
//! root_policy_digest[32] | firmware_sha256[32]
//! firmware_length:u64be | ram_length:u64be | seed:u64be
//! maximum_microstep:u64be | maximum_service_span:u64be
//! mapping:u32be=2 | maximum_callbacks:u32be
//!
//! Early native pin320: eight digests, five u64le, six u32le.
//! Native policy328: version:u32le=1 | size:u32le=328 | exact early pin320.
//! ```

use crucible_node_contract::U64;

use super::codec::Cursor;
use super::{NODE_CONTROL_MAX_BODY_BYTES, NativeAdministrativePreparation, NativeCommandError};

const MAGIC: &[u8; 8] = b"CNMICR01";
const SUFFIX_BYTES: usize = 112;
const MAXIMUM_MICROSTEP: u64 = 1_000_000;
const MAXIMUM_SERVICE_SPAN: u64 = 10_000_000;

/// Sizes the source-owned original fixed-microvm launch pin.
pub const NATIVE_FIXED_MICROVM_EARLY_PIN_BYTES: usize = 320;

/// Sizes the separately versioned native policy, including its closed prefix.
pub const NATIVE_FIXED_MICROVM_POLICY_BYTES: usize = 328;

/// Identifies the separately selected controller required for effect admission.
///
/// A controller of this edition must still independently authenticate source
/// root enrollment, retained input epoch and each original finite effect cut.
pub const NATIVE_FIXED_MICROVM_CONTROLLER_EDITION: u32 = 7;

/// Pins CPU service before device timers at each physical reaction instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeFixedMicrovmMapping {
    /// Orders instruction service at microstep zero and original device timers at one.
    ///
    /// Same-time callback successors follow their actual parent microstep.
    /// Native list and FIFO order break ties within the selected original cut.
    InstructionThenTimers = 2,
}

/// Preserves the complete original preparation for a closed native microvm subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeFixedMicrovmPreparation {
    /// Preserves original Realize, construction, phase and actual reader commitments.
    pub administration: NativeAdministrativePreparation,
    /// Commits to the separately installed native root and ordering policy.
    pub policy_digest: [u8; 32],
    /// Measures actual initial loaded firmware bytes with SHA-256.
    ///
    /// This is an initial measurement, not an immutability claim. Native
    /// enrollment must verify writable firmware RAM and its ISA alias mappings.
    pub firmware_sha256: [u8; 32],
    /// Bounds the actual firmware image extent before construction.
    pub firmware_length: U64,
    /// Pins actual configured guest RAM, distinct from firmware RAM and aliases.
    pub ram_length: U64,
    /// Pins the actual native deterministic guest entropy stream seed.
    pub seed: U64,
    /// Bounds the exclusive same-time microstep range.
    pub maximum_microstep: U64,
    /// Bounds the number of instruction services in one native admitted span.
    pub maximum_service_span: U64,
    /// Selects the source-defined timer and instruction tie rule.
    pub mapping: NativeFixedMicrovmMapping,
    /// Bounds callbacks in one finite original source-selected effect cut.
    pub maximum_callbacks: u32,
}

impl NativeFixedMicrovmPreparation {
    /// Validates bounded local preparation without accepting any claimed source facts.
    ///
    /// # Errors
    /// Rejects malformed companions, absent digests, invalid firmware/RAM bounds,
    /// zero/excessive finite service, callback and microstep allowances, or a
    /// microstep ceiling contradicting the original phase companion.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.administration.validate()?;
        if self.policy_digest == [0; 32]
            || self.firmware_sha256 == [0; 32]
            || !(64 * 1024..=16 * 1024 * 1024).contains(&self.firmware_length.get())
            || !(16 * 1024 * 1024..=3 * 1024 * 1024 * 1024).contains(&self.ram_length.get())
            || !(1..=MAXIMUM_MICROSTEP).contains(&self.maximum_microstep.get())
            || self.maximum_microstep != self.administration.phase.maximum_microstep
            || !(1..=MAXIMUM_SERVICE_SPAN).contains(&self.maximum_service_span.get())
            || !(1..=64).contains(&self.maximum_callbacks)
        {
            return Err(NativeCommandError::Invalid(
                "invalid fixed microvm preparation",
            ));
        }
        Ok(())
    }

    /// Encodes every original companion and policy field in a closed bounded format.
    ///
    /// # Errors
    /// Rejects invalid preparation or inadequate bounded allocation/framing credit.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let administration = self.administration.encode()?;
        let length = 12usize
            .checked_add(administration.len())
            .and_then(|length| length.checked_add(SUFFIX_BYTES))
            .filter(|length| *length <= NODE_CONTROL_MAX_BODY_BYTES)
            .ok_or(NativeCommandError::ResourceLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(administration.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&administration);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.firmware_sha256);
        for value in [
            self.firmware_length,
            self.ram_length,
            self.seed,
            self.maximum_microstep,
            self.maximum_service_span,
        ] {
            bytes.extend_from_slice(&value.get().to_be_bytes());
        }
        bytes.extend_from_slice(&(self.mapping as u32).to_be_bytes());
        bytes.extend_from_slice(&self.maximum_callbacks.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only complete closed records without enrolling a native device or endpoint.
    ///
    /// # Errors
    /// Rejects oversized, truncated, trailing or malformed bytes and unknown mappings.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(NativeCommandError::Invalid(
                "invalid fixed microvm preparation tag",
            ));
        }
        let length = cursor.u32()? as usize;
        let administration = NativeAdministrativePreparation::decode(cursor.take(length)?)?;
        let policy_digest = cursor.array()?;
        let firmware_sha256 = cursor.array()?;
        let firmware_length = U64::new(cursor.u64()?);
        let ram_length = U64::new(cursor.u64()?);
        let seed = U64::new(cursor.u64()?);
        let maximum_microstep = U64::new(cursor.u64()?);
        let maximum_service_span = U64::new(cursor.u64()?);
        let mapping = match cursor.u32()? {
            2 => NativeFixedMicrovmMapping::InstructionThenTimers,
            _ => return Err(NativeCommandError::Invalid("unknown fixed microvm mapping")),
        };
        let maximum_callbacks = cursor.u32()?;
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Invalid(
                "trailing fixed microvm preparation bytes",
            ));
        }
        let preparation = Self {
            administration,
            policy_digest,
            firmware_sha256,
            firmware_length,
            ram_length,
            seed,
            maximum_microstep,
            maximum_service_span,
            mapping,
            maximum_callbacks,
        };
        preparation.validate()?;
        Ok(preparation)
    }

    /// Computes the commitment to the unchanged original preparation and finite policy.
    ///
    /// # Errors
    /// Rejects invalid or oversized preparation. A digest grants no native custody.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.qemu-native-fixed-microvm-preparation.v1\0");
        hash.update(&self.encode()?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Encodes the exact native early pin before any source-owned construction.
    ///
    /// # Errors
    /// Rejects invalid or oversized companions, never accepting late source enrollment.
    pub fn early_pin(
        &self,
    ) -> Result<[u8; NATIVE_FIXED_MICROVM_EARLY_PIN_BYTES], NativeCommandError> {
        self.validate()?;
        let phase = &self.administration.phase;
        let mut bytes = [0; NATIVE_FIXED_MICROVM_EARLY_PIN_BYTES];
        let digests = [
            phase.initialization.preparation.scope.identity_digest()?,
            self.identity_digest()?,
            phase.initialization.realize_request_digest,
            self.policy_digest,
            phase.initialization.identity_digest()?,
            phase.identity_digest()?,
            self.administration.identity_digest()?,
            self.firmware_sha256,
        ];
        for (destination, digest) in bytes[..256].as_chunks_mut::<32>().0.iter_mut().zip(digests) {
            destination.copy_from_slice(&digest);
        }
        let integers = [
            self.firmware_length,
            self.ram_length,
            self.seed,
            self.maximum_microstep,
            self.maximum_service_span,
        ];
        for (destination, value) in bytes[256..296]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(integers)
        {
            destination.copy_from_slice(&value.get().to_le_bytes());
        }
        let selectors = [
            self.mapping as u32,
            NATIVE_FIXED_MICROVM_CONTROLLER_EDITION,
            1,
            1,
            self.maximum_callbacks,
            0,
        ];
        for (destination, value) in bytes[296..]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(selectors)
        {
            destination.copy_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Encodes the native policy prefix and exact early-pin fields without native layout.
    ///
    /// # Errors
    /// Rejects invalid original preparation. The bytes confer no root or effect authority.
    pub fn native_policy(
        &self,
    ) -> Result<[u8; NATIVE_FIXED_MICROVM_POLICY_BYTES], NativeCommandError> {
        let mut bytes = [0; NATIVE_FIXED_MICROVM_POLICY_BYTES];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(NATIVE_FIXED_MICROVM_POLICY_BYTES as u32).to_le_bytes());
        bytes[8..].copy_from_slice(&self.early_pin()?);
        Ok(bytes)
    }

    /// Formats the original early pin using canonical lowercase hexadecimal.
    ///
    /// # Errors
    /// Rejects invalid preparation or bounded argument allocation failure.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::new();
        value
            .try_reserve_exact(643)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        value.push_str("v1:");
        for byte in self.early_pin()? {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(value)
    }
}

#[cfg(test)]
#[path = "fixed_microvm_tests.rs"]
mod tests;
