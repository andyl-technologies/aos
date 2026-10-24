//! Original source pins for one observed administrative reader role.
//!
//! This optional record embeds the complete original phase preparation. Its
//! digest binds the actual inherited descriptor slot and socket identity before
//! native construction. The source independently verifies the endpoint and the
//! self-registering thread; reproducing these portable bytes grants no authority.
//! The role leaves other native roots unknown and conveys no readiness, input
//! closure, execution permission or capture qualification.
//!
//! ```text
//! CNPADM01, phase_length:u32be, original phase bytes, role_policy_digest[32],
//! descriptor_slot:i32be, socket_device:u64be, socket_inode:u64be
//!
//! Early native pin (160 bytes): scope[32], role_commitment[32], Realize[32],
//! policy[32], kind:u32le=1, count:u32le=1, descriptor_slot:i32le,
//! reserved:u32le=0, socket_device:u64le, socket_inode:u64le
//! ```

use super::{NativeCommandError, NativePhasePreparation};

const MAGIC: &[u8; 8] = b"CNPADM01";
const MAXIMUM_PREPARATION_BYTES: usize = 4096;

/// Binds an original phase preparation to one observed native reader endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAdministrativePreparation {
    /// Preserves the complete original Realize and phase policy commitments.
    pub phase: NativePhasePreparation,
    /// Identifies the installed administrative role policy, distinct from phase policy.
    pub policy_digest: [u8; 32],
    /// Names the actual inherited socket slot in the child process.
    pub descriptor_slot: i32,
    /// Preserves the original endpoint's actual filesystem device identity.
    pub socket_device: u64,
    /// Preserves the original endpoint's actual inode identity.
    pub socket_inode: u64,
}

#[cfg(test)]
#[path = "administrative_preparation_tests.rs"]
mod tests;

impl NativeAdministrativePreparation {
    /// Validates bounded original launch material without authenticating a source.
    ///
    /// # Errors
    /// Rejects invalid phase preparation, zero policy/socket identities or a slot
    /// overlapping standard input, output or error.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.phase.encode()?;
        if self.policy_digest == [0; 32]
            || self.descriptor_slot < 3
            || self.socket_device == 0
            || self.socket_inode == 0
        {
            return Err(NativeCommandError::Invalid(
                "invalid administrative endpoint pin",
            ));
        }
        Ok(())
    }

    /// Encodes the complete original preparation in a bounded closed byte format.
    ///
    /// # Errors
    /// Rejects malformed preparation or an encoded extent above the framing bound.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let phase = self.phase.encode()?;
        let length = 64usize
            .checked_add(phase.len())
            .filter(|length| *length <= MAXIMUM_PREPARATION_BYTES)
            .ok_or(NativeCommandError::ResourceLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(phase.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&phase);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.descriptor_slot.to_be_bytes());
        bytes.extend_from_slice(&self.socket_device.to_be_bytes());
        bytes.extend_from_slice(&self.socket_inode.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes one bounded original record without adopting its claimed endpoint.
    ///
    /// # Errors
    /// Rejects bad tags, truncated/trailing bytes, oversized or invalid preparation.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > MAXIMUM_PREPARATION_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        if bytes.len() < 64 || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(NativeCommandError::Invalid(
                "invalid administrative preparation",
            ));
        }
        let phase_length = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| NativeCommandError::Invalid("invalid phase extent"))?,
        ) as usize;
        let phase_end = 12usize
            .checked_add(phase_length)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if phase_end.checked_add(52) != Some(bytes.len()) {
            return Err(NativeCommandError::Invalid(
                "invalid administrative preparation extent",
            ));
        }
        let suffix = &bytes[phase_end..];
        let value = Self {
            phase: NativePhasePreparation::decode(&bytes[12..phase_end])?,
            policy_digest: suffix[..32]
                .try_into()
                .map_err(|_| NativeCommandError::Invalid("invalid policy digest"))?,
            descriptor_slot: i32::from_be_bytes(
                suffix[32..36]
                    .try_into()
                    .map_err(|_| NativeCommandError::Invalid("invalid descriptor slot"))?,
            ),
            socket_device: u64::from_be_bytes(
                suffix[36..44]
                    .try_into()
                    .map_err(|_| NativeCommandError::Invalid("invalid socket device"))?,
            ),
            socket_inode: u64::from_be_bytes(
                suffix[44..52]
                    .try_into()
                    .map_err(|_| NativeCommandError::Invalid("invalid socket inode"))?,
            ),
        };
        value.validate()?;
        Ok(value)
    }

    /// Computes an original role commitment without providing a registration seal.
    ///
    /// # Errors
    /// Rejects malformed or oversized original preparation.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    /// Encodes the exact source-owned early pin, preserving process-local slot identity.
    ///
    /// # Errors
    /// Rejects malformed or oversized original preparation.
    pub fn early_pin(&self) -> Result<[u8; 160], NativeCommandError> {
        let mut bytes = [0; 160];
        bytes[..32].copy_from_slice(
            &self
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?,
        );
        bytes[32..64].copy_from_slice(&self.identity_digest()?);
        bytes[64..96].copy_from_slice(&self.phase.initialization.realize_request_digest);
        bytes[96..128].copy_from_slice(&self.policy_digest);
        bytes[128..132].copy_from_slice(&1u32.to_le_bytes());
        bytes[132..136].copy_from_slice(&1u32.to_le_bytes());
        bytes[136..140].copy_from_slice(&self.descriptor_slot.to_le_bytes());
        bytes[144..152].copy_from_slice(&self.socket_device.to_le_bytes());
        bytes[152..160].copy_from_slice(&self.socket_inode.to_le_bytes());
        Ok(bytes)
    }

    /// Formats the separately selected source early argument with canonical lowercase hex.
    ///
    /// # Errors
    /// Rejects malformed preparation or failure to reserve bounded argument bytes.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let pin = self.early_pin()?;
        let mut value = String::new();
        value
            .try_reserve_exact(323)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        value.push_str("v1:");
        for byte in pin {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(value)
    }
}

#[cfg(test)]
pub(super) fn test_preparation() -> NativeAdministrativePreparation {
    NativeAdministrativePreparation {
        phase: super::phase::test_preparation(),
        policy_digest: [7; 32],
        descriptor_slot: 23,
        socket_device: 9,
        socket_inode: 31,
    }
}
