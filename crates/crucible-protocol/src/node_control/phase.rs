//! Original native phase policy pinned before realization or execution.
//!
//! These records correlate the original accepted Realize request, complete
//! owner preparation and installed mapping policy. Matching their digests does
//! not establish live custody, grant execution or qualify a native stop.
//!
//! ```text
//! preparation: initialization_bytes:u32 | exact_v5_initialization[initialization_bytes]
//!              policy_digest[32]
//!              mapping:u32=1 | maximum_microstep:u64
//! native policy: version:u32=1 | bytes:u32=152 | mapping:u32=1 | reserved:u32=0
//!                maximum_microstep:u64 | prepared_scope[32]
//!                phase_preparation[32] | realize_digest[32] | policy_digest[32]
//! early pin: v1: + lowercase_hex(scope[32] | phase_preparation[32]
//!            | realize[32] | policy[32] | mapping:LEu32 | maximum_microstep:LEu64)
//! ```
//!
//! Preparation and policy integers are big endian. The distinct early launch
//! pin follows the native source's fixed little-endian argument layout.

use std::fmt::Write;

use crucible_node_contract::{Position, U64};

use super::{NativeCommandError, NativeInitializationPreparation, codec::Cursor};

/// Bounds the closed mapping's finite same-time microstep allowance.
pub const NATIVE_PHASE_MAX_MICROSTEP: u64 = 1_000_000;

/// Sizes the separately versioned fixed native phase-policy observation.
pub const NATIVE_PHASE_POLICY_BYTES: usize = 152;

/// Sizes the launch pin that precedes native subsystem construction.
pub const NATIVE_PHASE_EARLY_PIN_BYTES: usize = 140;

/// Selects a closed source-defined mapping without claiming CPU timing fidelity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativePhaseMapping {
    /// Locates authentic instruction-born timer arms at reaction, microstep zero.
    InstructionReaction = 1,
}

impl NativePhaseMapping {
    fn decode(value: u32) -> Result<Self, NativeCommandError> {
        match value {
            1 => Ok(Self::InstructionReaction),
            _ => Err(NativeCommandError::Invalid(
                "unsupported native phase mapping",
            )),
        }
    }
}

/// Binds a fresh original Realize request to its complete native phase policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhasePreparation {
    /// Preserves the original construction preparation and accepted Realize identity.
    ///
    /// The complete companion owns the original scope, operation identity,
    /// request digest and distinct construction policy. Phase preparation does
    /// not supply a second scope or a replacement realization request.
    pub initialization: NativeInitializationPreparation,
    /// Commits to the independently installed source-defined mapping policy.
    pub policy_digest: [u8; 32],
    /// Selects the closed source mapping pinned before subsystem construction.
    pub mapping: NativePhaseMapping,
    /// Bounds the exclusive same-time microstep count, admitting only `microstep < maximum`.
    ///
    /// A count of one admits microstep zero. The count never authorizes a
    /// callback or permits an unbounded same-time settlement loop.
    pub maximum_microstep: U64,
}

impl NativePhasePreparation {
    /// Validates a fresh preparation without issuing native execution authority.
    ///
    /// # Errors
    /// Rejects an invalid owner preparation, noninitial cut, missing commitments
    /// or a zero or excessive finite microstep allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.initialization.validate()?;
        if self.policy_digest == [0; 32] {
            return Err(NativeCommandError::Invalid(
                "invalid original native phase preparation",
            ));
        }
        validate_microstep_allowance(self.maximum_microstep)
    }

    /// Computes the commitment to every original preparation and policy field.
    ///
    /// Equality only correlates bytes; the native launcher must independently
    /// authenticate the original accepted request and inactive native custody.
    ///
    /// # Errors
    /// Rejects invalid preparation data or an unrepresentable bounded encoding.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let bytes = self.encode()?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.qemu-native-phase-preparation.v1\0");
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }

    /// Encodes preparation while preserving the original construction bytes.
    ///
    /// # Errors
    /// Rejects invalid local data or a body beyond the public frame allowance.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let original = self.initialization.encode()?;
        let mut bytes = Vec::with_capacity(original.len() + 48);
        bytes.extend_from_slice(&(original.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&original);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&(self.mapping as u32).to_be_bytes());
        bytes.extend_from_slice(&self.maximum_microstep.get().to_be_bytes());
        if bytes.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Decodes closed preparation bytes without adopting native owner custody.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, open mappings, oversized fields,
    /// an invalid construction companion or any invalid phase preparation.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        let original_length = cursor.u32()? as usize;
        if original_length > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let initialization =
            NativeInitializationPreparation::decode(cursor.take(original_length)?)?;
        let value = Self {
            initialization,
            policy_digest: cursor.array()?,
            mapping: NativePhaseMapping::decode(cursor.u32()?)?,
            maximum_microstep: U64::new(cursor.u64()?),
        };
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Invalid(
                "trailing native phase preparation",
            ));
        }
        value.validate()?;
        Ok(value)
    }

    /// Formats the fixed early pin before native subsystem construction.
    ///
    /// The argument is `v1:` followed by exactly 280 lowercase hexadecimal
    /// characters. Supplying it does not qualify phase or native ownership.
    ///
    /// # Errors
    /// Rejects invalid original preparation or an unrepresentable commitment.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        let policy = self.policy()?;
        let mut bytes = [0; NATIVE_PHASE_EARLY_PIN_BYTES];
        for (offset, digest) in [
            (0, &policy.prepared_scope_hash),
            (32, &policy.phase_preparation_commitment),
            (64, &policy.realize_request_digest),
            (96, &policy.policy_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest);
        }
        bytes[128..132].copy_from_slice(&(self.mapping as u32).to_le_bytes());
        bytes[132..140].copy_from_slice(&self.maximum_microstep.get().to_le_bytes());

        let mut argument = String::with_capacity(3 + NATIVE_PHASE_EARLY_PIN_BYTES * 2);
        argument.push_str("v1:");
        for byte in bytes {
            write!(&mut argument, "{byte:02x}")
                .map_err(|_| NativeCommandError::Invalid("phase pin formatting"))?;
        }
        Ok(argument)
    }

    /// Constructs the corresponding bounded native policy data for comparison.
    ///
    /// # Errors
    /// Rejects an invalid or unrepresentable original preparation.
    pub fn policy(&self) -> Result<NativePhasePolicy, NativeCommandError> {
        self.validate()?;
        Ok(NativePhasePolicy {
            mapping: self.mapping,
            maximum_microstep: self.maximum_microstep,
            prepared_scope_hash: self.initialization.preparation.scope.identity_digest()?,
            phase_preparation_commitment: self.identity_digest()?,
            realize_request_digest: self.initialization.realize_request_digest,
            policy_digest: self.policy_digest,
        })
    }
}

/// Preserves fixed native policy facts without issuing execution or readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhasePolicy {
    /// Selects the original closed source-defined mapping.
    pub mapping: NativePhaseMapping,
    /// Bounds the exclusive same-time microstep count in this native incarnation.
    pub maximum_microstep: U64,
    /// Binds the complete prepared native owner scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds the original preparation, Realize identity and installed policy.
    pub phase_preparation_commitment: [u8; 32],
    /// Binds the originally accepted complete Realize request bytes.
    pub realize_request_digest: [u8; 32],
    /// Binds the originally installed source mapping policy.
    pub policy_digest: [u8; 32],
}

impl NativePhasePolicy {
    /// Validates fixed policy fields without authenticating their native source.
    ///
    /// # Errors
    /// Rejects missing commitments or a zero or excessive microstep allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if [
            self.prepared_scope_hash,
            self.phase_preparation_commitment,
            self.realize_request_digest,
            self.policy_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(NativeCommandError::Conflict);
        }
        validate_microstep_allowance(self.maximum_microstep)
    }

    /// Compares every field against the original independently retained preparation.
    ///
    /// # Errors
    /// Rejects invalid policy data or any original scope, request or policy change.
    pub fn validate_against(
        &self,
        preparation: &NativePhasePreparation,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        if self != &preparation.policy()? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Checks a complete finite position against the declared native allowance.
    ///
    /// This pure check grants no execution permission and does not establish
    /// that the native engine can stop at the supplied microstep or phase.
    ///
    /// # Errors
    /// Rejects invalid policy, unrepresentable signed native time or a microstep
    /// at or above the exclusive declared count.
    pub fn validate_position(&self, position: Position) -> Result<(), NativeCommandError> {
        self.validate()?;
        if position.time_ps.get() > i64::MAX as u64 || position.microstep >= self.maximum_microstep
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }

    /// Checks an ordered finite same-time range without authorizing native settlement.
    ///
    /// Both endpoints retain their complete original microstep and phase. A
    /// valid range neither attests a current native cursor nor promises that
    /// the native engine can realize the requested exclusive stop.
    ///
    /// # Errors
    /// Rejects invalid endpoints, a reversed or empty range, or a range that
    /// would advance physical time rather than settle the same instant.
    pub fn validate_same_time_range(
        &self,
        start: Position,
        limit: Position,
    ) -> Result<(), NativeCommandError> {
        self.validate_position(start)?;
        self.validate_position(limit)?;
        if start >= limit || start.time_ps != limit.time_ps {
            return Err(NativeCommandError::Invalid(
                "invalid finite native phase range",
            ));
        }
        Ok(())
    }

    /// Encodes exactly the fixed 152-byte big-endian native policy record.
    ///
    /// # Errors
    /// Rejects any record that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; NATIVE_PHASE_POLICY_BYTES], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; NATIVE_PHASE_POLICY_BYTES];
        for (offset, value) in [
            (0, 1),
            (4, NATIVE_PHASE_POLICY_BYTES as u32),
            (8, self.mapping as u32),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes[16..24].copy_from_slice(&self.maximum_microstep.get().to_be_bytes());
        for (offset, digest) in [
            (24, &self.prepared_scope_hash),
            (56, &self.phase_preparation_commitment),
            (88, &self.realize_request_digest),
            (120, &self.policy_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest);
        }
        Ok(bytes)
    }

    /// Decodes a closed fixed policy record without asserting native ownership.
    ///
    /// # Errors
    /// Rejects unsupported formats or mapping, open reserved fields, malformed
    /// lengths, missing commitments or invalid microstep allowances.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != NATIVE_PHASE_POLICY_BYTES {
            return Err(NativeCommandError::Invalid("native phase policy length"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != NATIVE_PHASE_POLICY_BYTES as u32 {
            return Err(NativeCommandError::Invalid("native phase policy format"));
        }
        let mapping = NativePhaseMapping::decode(cursor.u32()?)?;
        if cursor.u32()? != 0 {
            return Err(NativeCommandError::Invalid(
                "native phase policy reserved field",
            ));
        }
        let value = Self {
            mapping,
            maximum_microstep: U64::new(cursor.u64()?),
            prepared_scope_hash: cursor.array()?,
            phase_preparation_commitment: cursor.array()?,
            realize_request_digest: cursor.array()?,
            policy_digest: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn validate_microstep_allowance(maximum: U64) -> Result<(), NativeCommandError> {
    if maximum.get() == 0 || maximum.get() > NATIVE_PHASE_MAX_MICROSTEP {
        return Err(NativeCommandError::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
#[path = "phase_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn test_preparation() -> NativePhasePreparation {
    tests::original()
}
