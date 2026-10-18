//! Names the nonrecursive proof body emitted by an actual installed Commit.
//!
//! This body precedes the Commit response's completed-pair evidence. It keeps
//! the captured logical inventory hash separate from the fresh physical hold.

use super::*;

/// Retains the exact captured state and current held target without a response cycle.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeRestoredCommitHold {
    /// Selects the nonrecursive held-Commit branch of the restored proof family.
    pub schema: String,
    /// Reports the original current native process.
    pub native_pid: U64,
    /// Names the actual fresh target world.
    pub target_world: crucible_node_contract::HashRef,
    /// Names the actual fresh owning node.
    pub target_owner: Id,
    /// Names its complete fresh owner binding.
    pub target_owner_binding: crucible_node_contract::HashRef,
    /// Names the actual fresh activation.
    pub target_activation: Id,
    /// Retains the actual fresh world generation.
    pub target_generation: U64,
    /// Names the exact source-signed native snapshot.
    pub captured_owner_state: ContentRef,
    /// Names its separately verified pending Control body.
    pub captured_control: ContentRef,
    /// Names the complete settled Capture/after/confirmation journal.
    pub captured_journal: ContentRef,
    /// Names the exact sealed historical mapping installed on this connection.
    pub mapping: ContentRef,
    /// Names the complete actual assigned Commit including its proof.
    pub restore_commit: ContentRef,
    /// Binds the actual private verified Commit context.
    pub context_digest: Bytes,
    /// Retains the captured local model cursor unchanged.
    pub local_cursor: Position,
    /// Hashes its complete literal producer or reactive inventory.
    pub inventory_hash: crucible_node_contract::HashRef,
    /// Reports the separately installed fresh physical hold.
    pub physical_gate_held: bool,
}

impl PacketNativeRestoredCommitHold {
    /// Checks this closed proof body's bounded data without issuing a held token.
    ///
    /// # Errors
    /// Refuses another grammar, invalid references or scope identifiers, absent
    /// process/generation, a changed digest width or an open physical gate.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-restored-commit-held/12"
            || self.native_pid.get() == 0
            || self.context_digest.as_slice().len() != 32
            || !self.physical_gate_held
        {
            return Err(ProviderError::Correlation(
                "restored Commit held proof grammar",
            ));
        }
        self.target_world.validate()?;
        self.target_owner.validate()?;
        self.target_owner_binding.validate()?;
        self.target_activation.validate()?;
        self.local_cursor.validate()?;
        self.inventory_hash.validate()?;
        for reference in [
            &self.captured_owner_state,
            &self.captured_control,
            &self.captured_journal,
            &self.mapping,
            &self.restore_commit,
        ] {
            reference.validate()?;
        }
        crate::connection::serialized_credit(
            self,
            maximum_complete_restore_held_evidence_bytes()?,
        )?;
        Ok(())
    }
}

#[derive(Serialize)]
struct HoldView<'a, H: ?Sized, C: ?Sized, I: ?Sized, P: ?Sized, B: ?Sized, N> {
    schema: &'a str,
    native_pid: N,
    target_world: &'a H,
    target_owner: &'a I,
    target_owner_binding: &'a H,
    target_activation: &'a I,
    target_generation: N,
    captured_owner_state: &'a C,
    captured_control: &'a C,
    captured_journal: &'a C,
    mapping: &'a C,
    restore_commit: &'a C,
    context_digest: &'a B,
    local_cursor: &'a P,
    inventory_hash: &'a H,
    physical_gate_held: bool,
}

impl Serialize for PacketNativeRestoredCommitHold {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // An added owner field must be represented explicitly in this shared
        // view; the actual producer and bound cannot silently diverge.
        let Self {
            schema,
            native_pid,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation,
            captured_owner_state,
            captured_control,
            captured_journal,
            mapping,
            restore_commit,
            context_digest,
            local_cursor,
            inventory_hash,
            physical_gate_held,
        } = self;
        HoldView {
            schema,
            native_pid: *native_pid,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation: *target_generation,
            captured_owner_state,
            captured_control,
            captured_journal,
            mapping,
            restore_commit,
            context_digest,
            local_cursor,
            inventory_hash,
            physical_gate_held: *physical_gate_held,
        }
        .serialize(serializer)
    }
}

/// Counts the closed held-proof maximum using the actual producer's field view.
///
/// The bound includes every 128-byte identifier, all maximum U64 counters,
/// 128-byte hash domains at their worst six-byte ASCII escaping, maximum full
/// ContentRefs with doubled quote media bytes, the 32-byte digest's exact
/// unpadded base64 width and the complete coordinate. It constructs no ID or
/// JSON value, custom U64 formatter string or selected protocol credit. The
/// maximum decimal spelling is borrowed statically through the same field view.
///
/// # Errors
/// Reports serialization/count overflow; it does not admit an input lease.
pub fn maximum_complete_restore_held_evidence_bytes() -> Result<usize, ProviderError> {
    maximum_held_encoded_bytes_data("18446744073709551615")
}

fn maximum_held_encoded_bytes_data<N: Serialize + Copy>(
    maximum: N,
) -> Result<usize, ProviderError> {
    let domains = [0u8; 128];
    let identifiers = [b'x'; 128];
    let media = [b'"'; 128];
    let hexadecimal = [b'0'; 64];
    let digest = [b'x'; 43];
    let hash = MaximumHeldHash {
        algorithm: "blake3-256",
        domain: bound_ascii(&domains)?,
        digest: bound_ascii(&hexadecimal)?,
    };
    let content = MaximumHeldContent {
        hash: MaximumHeldHash {
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: bound_ascii(&hexadecimal)?,
        },
        length: maximum,
        media_type: bound_ascii(&media)?,
    };
    let coordinate = MaximumHeldCoordinate {
        time_ps: maximum,
        microstep: maximum,
        phase: 3,
    };
    crate::connection::serialized_credit(
        &HoldView {
            schema: "source-owned.packet-restored-commit-held/12",
            native_pid: maximum,
            target_world: &hash,
            target_owner: bound_ascii(&identifiers)?,
            target_owner_binding: &hash,
            target_activation: bound_ascii(&identifiers)?,
            target_generation: maximum,
            captured_owner_state: &content,
            captured_control: &content,
            captured_journal: &content,
            mapping: &content,
            restore_commit: &content,
            context_digest: bound_ascii(&digest)?,
            local_cursor: &coordinate,
            inventory_hash: &hash,
            physical_gate_held: true,
        },
        65_536,
    )
}

fn bound_ascii(bytes: &[u8]) -> Result<&str, ProviderError> {
    std::str::from_utf8(bytes).map_err(|_| ProviderError::Frame("closed held proof bound ASCII"))
}

#[derive(Serialize)]
struct MaximumHeldHash<'a> {
    algorithm: &'static str,
    domain: &'a str,
    digest: &'a str,
}
#[derive(Serialize)]
struct MaximumHeldContent<'a, N> {
    hash: MaximumHeldHash<'a>,
    length: N,
    media_type: &'a str,
}
#[derive(Serialize)]
struct MaximumHeldCoordinate<N> {
    time_ps: N,
    microstep: N,
    phase: u16,
}

/// Names actual fixed maximum-Hold counter views without decimal allocation.
///
/// The maximum decimal spelling is borrowed static data. Compiler and recursive
/// serde frames and allocator physical overhead remain separate.
pub fn maximum_complete_restore_held_evidence_counter_scratch_data() -> usize {
    use std::mem::size_of;
    3 * size_of::<[u8; 128]>()
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 43]>()
        + size_of::<&'static str>()
        + size_of::<MaximumHeldHash<'static>>()
        + size_of::<MaximumHeldContent<'static, &'static str>>()
        + size_of::<MaximumHeldCoordinate<&'static str>>()
        + size_of::<
            HoldView<
                'static,
                MaximumHeldHash<'static>,
                MaximumHeldContent<'static, &'static str>,
                str,
                MaximumHeldCoordinate<&'static str>,
                str,
                &'static str,
            >,
        >()
        + crate::connection::original_serialized_credit_counter_scratch_data()
}

#[cfg(test)]
mod maximum_counter_tests {
    use super::*;

    #[test]
    fn borrowed_maximum_decimal_preserves_the_original_u64_serialized_bound()
    -> Result<(), ProviderError> {
        assert_eq!(
            maximum_complete_restore_held_evidence_bytes()?,
            maximum_held_encoded_bytes_data(U64::new(u64::MAX))?
        );
        assert!(maximum_complete_restore_held_evidence_bytes()? > 0);
        Ok(())
    }
}
