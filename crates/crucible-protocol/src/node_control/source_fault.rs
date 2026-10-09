//! Fixed, pointer-free diagnostics for the first original native source fault.
//!
//! These bytes report unknown birth and effects. They establish neither native
//! containment nor physical stop, payload lifetime, no-effects, or custody ACK.
//! The host must retain the original diagnostic and obtain actual containment
//! independently. Scope and command digests require trusted original comparison.
//!
//! ```text
//! version:u32=1 | bytes:u32=112 | code:u32 | flags:u32=7
//! fault_id:u64 | command_sequence:u64 | ingress_id:u64
//! cpu_index:u32 | ingress_kind:u32 | prepared_scope_hash[32] | command_digest[32]
//! ```
//!
//! All scalar fields use big endian. The negotiated edition-two frame supplies
//! its own kind and length; this payload has no native ABI layout or pointers.

use crucible_node_contract::U64;

use super::{NativeCommandError, codec::Cursor};

/// Bounds the complete source-fault payload, including its fixed format prefix.
pub const SOURCE_FAULT_BYTES: usize = 112;

/// Preserves raw facts about one immutable original native source fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFaultFacts {
    /// Records capacity/identity exhaustion (1) or unexpected unmediated source (3).
    pub code: u32,
    /// Records first diagnostic retained, unknown birth and unknown effects bits.
    pub flags: u32,
    /// Identifies the original retained fault; it must be positive.
    pub fault_id: U64,
    /// Names the original command, or zero for initial preparation.
    pub command_sequence: U64,
    /// Preserves a diagnostic identity, or zero when no ingress was reserved.
    ///
    /// This field never names an admitted semantic input or proves its lifetime.
    pub ingress_id: U64,
    /// Names the actual CPU slot, or UINT32_MAX for a global system reset.
    pub cpu_index: u32,
    /// Records CPU work, IRQ set/clear, CPU reset/resume, Arm line, system reset or x86 INIT.
    pub ingress_kind: u32,
    /// Copies the original prepared-scope digest, requiring trusted comparison.
    pub prepared_scope_hash: [u8; 32],
    /// Copies the original command digest, or zero at initial preparation.
    pub command_digest: [u8; 32],
}

impl SourceFaultFacts {
    /// Validates the closed diagnostic fields without granting native authority.
    ///
    /// The retained, unknown-birth and unknown-effects flags must all remain set.
    /// A different nonzero scope is still merely data for trusted comparison.
    ///
    /// # Errors
    /// Rejects unknown codes, flags or ingress kinds, absent original identities,
    /// an invalid global CPU sentinel, or inconsistent initial-command fields.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if !matches!(self.code, 1 | 3)
            || self.flags != 7
            || self.fault_id.get() == 0
            || !(1..=8).contains(&self.ingress_kind)
            || (self.cpu_index == u32::MAX) != (self.ingress_kind == 7)
            || (self.ingress_kind != 7 && self.cpu_index >= 1024)
            || self.prepared_scope_hash == [0; 32]
            || (self.command_sequence.get() == 0) != (self.command_digest == [0; 32])
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes the exact fixed payload without inferring fault containment.
    ///
    /// # Errors
    /// Rejects any diagnostic that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; SOURCE_FAULT_BYTES], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; SOURCE_FAULT_BYTES];
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&(SOURCE_FAULT_BYTES as u32).to_be_bytes());
        bytes[8..12].copy_from_slice(&self.code.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.flags.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.fault_id.get().to_be_bytes());
        bytes[24..32].copy_from_slice(&self.command_sequence.get().to_be_bytes());
        bytes[32..40].copy_from_slice(&self.ingress_id.get().to_be_bytes());
        bytes[40..44].copy_from_slice(&self.cpu_index.to_be_bytes());
        bytes[44..48].copy_from_slice(&self.ingress_kind.to_be_bytes());
        bytes[48..80].copy_from_slice(&self.prepared_scope_hash);
        bytes[80..112].copy_from_slice(&self.command_digest);
        Ok(bytes)
    }

    /// Decodes exactly one bounded original diagnostic without granting authority.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, unsupported format prefixes and every
    /// field inconsistency rejected by [`Self::validate`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != SOURCE_FAULT_BYTES {
            return Err(NativeCommandError::Invalid("source fault payload length"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != SOURCE_FAULT_BYTES as u32 {
            return Err(NativeCommandError::Invalid("source fault format prefix"));
        }
        let facts = Self {
            code: cursor.u32()?,
            flags: cursor.u32()?,
            fault_id: U64::new(cursor.u64()?),
            command_sequence: U64::new(cursor.u64()?),
            ingress_id: U64::new(cursor.u64()?),
            cpu_index: cursor.u32()?,
            ingress_kind: cursor.u32()?,
            prepared_scope_hash: cursor.array()?,
            command_digest: cursor.array()?,
        };
        facts.validate()?;
        Ok(facts)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn original() -> SourceFaultFacts {
        SourceFaultFacts {
            code: 1,
            flags: 7,
            fault_id: U64::new(1),
            command_sequence: U64::new(9),
            ingress_id: U64::new(18),
            cpu_index: 0,
            ingress_kind: 1,
            prepared_scope_hash: [0x12; 32],
            command_digest: [0x34; 32],
        }
    }

    #[test]
    fn diagnostic_requires_pinned_edition_two_and_preserves_fixed_payload() {
        use crate::node_control::{
            NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame,
            encode_frame_for_edition,
        };
        let frame = NativeFrame::SourceFault(Box::new(original()));
        let bytes = encode_frame_for_edition(NativeControlEdition::OwnedCustody, &frame).unwrap();

        assert_eq!(&bytes[8..16], &[0, 2, 0, 13, 0, 0, 0, 112]);
        assert_eq!(&bytes[16..], original().encode().unwrap());
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::OwnedCustody, &bytes).unwrap(),
            frame
        );
        assert!(encode_frame(&frame).is_err());
        assert!(decode_frame_for_edition(NativeControlEdition::Original, &bytes).is_err());
        for length in 0..bytes.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::OwnedCustody, &bytes[..length])
                    .is_err()
            );
        }
        let mut oversized = bytes;
        oversized.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::OwnedCustody, &oversized).is_err());
    }

    #[test]
    fn exact_big_endian_payload_preserves_original_facts() {
        let facts = original();
        let bytes = facts.encode().unwrap();

        assert_eq!(
            &bytes[..16],
            &[0, 0, 0, 1, 0, 0, 0, 112, 0, 0, 0, 1, 0, 0, 0, 7]
        );
        assert_eq!(&bytes[16..24], &1u64.to_be_bytes());
        assert_eq!(&bytes[24..32], &9u64.to_be_bytes());
        assert_eq!(&bytes[32..40], &18u64.to_be_bytes());
        assert_eq!(&bytes[48..80], &[0x12; 32]);
        assert_eq!(SourceFaultFacts::decode(&bytes).unwrap(), facts);
    }

    #[test]
    fn rejects_every_truncation_trailing_byte_and_wrong_prefix() {
        let original = original().encode().unwrap();
        for length in 0..SOURCE_FAULT_BYTES {
            assert!(SourceFaultFacts::decode(&original[..length]).is_err());
        }
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(SourceFaultFacts::decode(&trailing).is_err());
        for offset in [3, 7] {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(SourceFaultFacts::decode(&changed).is_err());
        }
    }

    #[test]
    fn closed_codes_flags_and_ingress_kinds_refuse_unknown_values() {
        for code in [0, 2, 4, u32::MAX] {
            let mut changed = original();
            changed.code = code;
            assert!(changed.encode().is_err());
        }
        for flags in [0, 1, 3, 6, 8, u32::MAX] {
            let mut changed = original();
            changed.flags = flags;
            assert!(changed.encode().is_err());
        }
        for kind in [0, 9, u32::MAX] {
            let mut changed = original();
            changed.ingress_kind = kind;
            assert!(changed.encode().is_err());
        }
        for kind in 1..=8 {
            let mut accepted = original();
            accepted.ingress_kind = kind;
            if kind == 7 {
                accepted.cpu_index = u32::MAX;
            }
            accepted.code = 3;
            assert_eq!(
                SourceFaultFacts::decode(&accepted.encode().unwrap()).unwrap(),
                accepted
            );
        }
    }

    #[test]
    fn absent_original_identity_or_initial_command_mismatch_is_rejected() {
        let mut changed = original();
        changed.fault_id = U64::new(0);
        assert!(changed.encode().is_err());
        changed = original();
        changed.ingress_id = U64::new(0);
        assert_eq!(
            SourceFaultFacts::decode(&changed.encode().unwrap()).unwrap(),
            changed
        );
        changed = original();
        changed.prepared_scope_hash = [0; 32];
        assert!(changed.encode().is_err());
        changed = original();
        changed.command_sequence = U64::new(0);
        assert!(changed.encode().is_err());
        changed = original();
        changed.command_digest = [0; 32];
        assert!(changed.encode().is_err());

        changed.command_sequence = U64::new(0);
        assert_eq!(
            SourceFaultFacts::decode(&changed.encode().unwrap()).unwrap(),
            changed
        );
    }

    #[test]
    fn global_and_scoped_cpu_slots_require_exact_ingress_kind() {
        let mut changed = original();
        changed.cpu_index = u32::MAX;
        assert!(changed.encode().is_err());

        changed.ingress_kind = 7;
        assert_eq!(
            SourceFaultFacts::decode(&changed.encode().unwrap()).unwrap(),
            changed
        );
    }

    #[test]
    fn cpu_slots_are_bounded_without_proving_actual_roster_membership() {
        let mut changed = original();
        changed.cpu_index = 1023;
        assert!(changed.encode().is_ok());

        changed.cpu_index = 1024;
        assert!(changed.encode().is_err());
        changed.cpu_index = 0;
        changed.ingress_kind = 7;
        assert!(changed.encode().is_err());
    }

    #[test]
    fn foreign_nonzero_scope_remains_raw_data_for_trusted_comparison() {
        let mut changed = original();
        changed.prepared_scope_hash = [0x56; 32];
        changed.command_sequence = U64::new(10);
        changed.command_digest = [0x78; 32];
        let decoded = SourceFaultFacts::decode(&changed.encode().unwrap()).unwrap();

        assert_eq!(decoded, changed);
        assert_ne!(decoded, original());
        assert_eq!(decoded.flags, 7);
    }
}
