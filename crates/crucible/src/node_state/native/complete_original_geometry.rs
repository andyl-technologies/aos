//! Admits source-selected complete capture geometry before administrative effects.
//!
//! These data rows convey no capture permission. Only the installed factory can
//! provide the selected codec plan, and core admission still requires the actual
//! unchanged runtime, owner roster and private capture ticket. Hard ceilings are
//! not selected buffer capacities.

use super::{AdmittedGraph, NativeCaptureLimits, StateError, StateLimits, refused};
use crucible_node_contract::Id;

/// Describes the selected complete native/host capture plan without authority.
#[derive(Debug)]
pub struct CompleteOriginalCaptureGeometry {
    /// Lists exactly four rows in the admitted capture-owner order.
    pub owners: Vec<CompleteOriginalOwnerCaptureGeometry>,
}

/// Bounds one actual source-selected snapshot, settlement and protocol closure.
///
/// The source codec accounts for its complete raw and encoded prefix, cached
/// replies, transport banks and temporary copies. Returning this data cannot
/// enroll a source or manufacture a native capture result.
#[derive(Debug, PartialEq, Eq)]
pub struct CompleteOriginalOwnerCaptureGeometry {
    /// Names the actual admitted capture owner.
    pub owner: Id,
    /// Names every actual participant in canonical order.
    pub participants: Vec<Id>,
    /// Bounds each snapshot, journal and original prefix object.
    pub maximum_record_bytes: usize,
    /// Counts all distinct typed snapshot, journal and evidence roles.
    pub maximum_objects: usize,
    /// Bounds the complete retained closure and preallocated source banks.
    pub maximum_retained_bytes: usize,
    /// Counts all source-owned dependency edges in the returned closure.
    pub maximum_dependency_edges: usize,
    /// Bounds additional simultaneous encoding, decoding and copy extents.
    pub maximum_transient_bytes: usize,
}

/// Carries one native capsule's readonly complete-capture allocation facts.
///
/// This result has no constructor restriction because it grants no authority.
/// Core independently binds its actual same-node invocation and selected key;
/// decoded or copied rows cannot issue a runtime-owned preflight seal.
#[derive(Debug)]
pub struct CompleteOriginalOwnerCapturePreflight {
    /// Binds the source-selected implementation, profile and exact native format.
    pub key: crate::node_contract::NativeStateKey,
    /// Bounds actual selected banks and complete snapshot/settlement peak.
    pub geometry: CompleteOriginalOwnerCaptureGeometry,
}

impl CompleteOriginalCaptureGeometry {
    /// Checks complete finite geometry against the original declared owner roster.
    ///
    /// This validates data only. It issues no ticket, seals no factory selection
    /// and confers no capture, restoration or readiness permission.
    ///
    /// # Errors
    /// Refuses a different roster, malformed bounds, arithmetic overflow or
    /// aggregate object, edge, retained-byte or simultaneous-peak excess.
    pub fn validate(
        &self,
        graph: &AdmittedGraph,
        native: NativeCaptureLimits,
        state: StateLimits,
        remaining_edges: usize,
    ) -> Result<(), StateError> {
        let roster = &graph.ownership_policy().capture_owners;
        if roster.len() != 4 || self.owners.len() != roster.len() {
            return Err(refused(
                "complete capture geometry requires the actual four owners",
            ));
        }

        let mut objects = 0usize;
        let mut bytes = 0usize;
        let mut edges = 0usize;
        let mut transient = 0usize;
        for (row, original) in self.owners.iter().zip(roster) {
            let participants = graph.node_ids().filter(|node| {
                graph.binding(node).is_some_and(|binding| {
                    binding.compatibility.capture_owner.id == original.owner_id
                })
            });
            if row.owner != original.owner_id
                || !row.participants.iter().eq(participants)
                || row.participants.len() != 1
                || row.maximum_record_bytes == 0
                || row.maximum_record_bytes > native.maximum_record_bytes
                || row.maximum_objects < 2
                || row.maximum_retained_bytes < row.maximum_record_bytes
            {
                return Err(refused(
                    "complete capture geometry changed selected owner or record bounds",
                ));
            }

            objects = objects
                .checked_add(row.maximum_objects)
                .ok_or_else(|| refused("complete capture geometry object overflow"))?;
            bytes = bytes
                .checked_add(row.maximum_retained_bytes)
                .ok_or_else(|| refused("complete capture geometry byte overflow"))?;
            edges = edges
                .checked_add(row.maximum_dependency_edges)
                .ok_or_else(|| refused("complete capture geometry edge overflow"))?;
            transient = transient
                .checked_add(row.maximum_transient_bytes)
                .ok_or_else(|| refused("complete capture geometry transient overflow"))?;
        }

        let peak = bytes
            .checked_add(transient)
            .ok_or_else(|| refused("complete capture geometry peak overflow"))?;
        if objects > native.maximum_objects
            || bytes > native.maximum_total_record_bytes
            || peak > native.maximum_total_record_bytes
            || peak > state.maximum_total_content_bytes
            || edges > remaining_edges
        {
            return Err(refused(
                "complete source-selected capture geometry exceeds whole-world credit",
            ));
        }
        Ok(())
    }
}

impl crate::node_contract::NodeRuntime {
    pub(crate) fn capture_selected_json_decode_storage(
        bytes: &[u8],
        typed_slot: usize,
        typed_map_node: usize,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        super::core_decode_credit::preflight_selected(bytes, typed_slot, typed_map_node, maximum)?
            .total()
    }

    /// Separates raw decoder work from later adjacent String-key clones.
    ///
    /// Both terms come from the same actual lexical preflight. The second term
    /// independently covers two decoded strings without assuming equality with
    /// an already retained typed projection; it is never a record-byte factor.
    ///
    /// # Errors
    /// Refuses unsupported layout, malformed raw framing, arithmetic overflow
    /// or a decoder/string projection beyond the caller's finite ceiling.
    pub(crate) fn capture_selected_json_decode_and_string_clone_storage_data(
        bytes: &[u8],
        typed_slot: usize,
        typed_map_node: usize,
        maximum: usize,
    ) -> Result<(usize, usize), crate::node_contract::RuntimeError> {
        let data = super::core_decode_credit::preflight_selected(
            bytes,
            typed_slot,
            typed_map_node,
            maximum,
        )?;
        let strings = data
            .parser_strings
            .checked_mul(2)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
        Ok((data.total()?, strings))
    }

    pub(crate) fn capture_host_decode_storage(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        super::core_decode_credit::preflight(bytes, maximum)?.total()
    }

    /// Quotes the distinct Host17 decoder without constructing historical state.
    pub(crate) fn capture_restored_host17_decode_storage_data(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        super::core_decode_credit::preflight_restored_host17(bytes, maximum)?.total()
    }

    pub(crate) fn capture_host_dependency_count(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        // Each core ContentRef has one literal "hash" key. Counting every
        // such key, including an unrelated same-spelled dynamic key, is a
        // conservative edge ceiling. This fixed scanner creates no DOM and
        // accepts no dependency identity or source permission.
        let mut cursor = 0;
        let mut count = 0usize;
        while cursor < bytes.len() {
            if bytes[cursor] != b'"' {
                cursor += 1;
                continue;
            }
            cursor += 1;
            let start = cursor;
            let mut escaped = false;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                if bytes[cursor] == b'\\' {
                    escaped = true;
                    cursor += 1;
                }
                cursor += 1;
            }
            if cursor >= bytes.len() {
                return Err(RuntimeError::InvalidReceipt);
            }
            let hash = !escaped && &bytes[start..cursor] == b"hash";
            cursor += 1;
            let mut next = cursor;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if hash && bytes.get(next) == Some(&b':') {
                count = count
                    .checked_add(1)
                    .filter(|count| *count <= maximum)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod host_edge_count_controls {
    use crate::node_contract::{NodeRuntime, RuntimeError};

    #[test]
    fn borrowed_edge_ceiling_ignores_string_values_and_counts_every_key() {
        let bytes =
            br#"{"hash":{"digest":"hash"},"nested":[{"hash":{}},{"hash":{}}],"text":"\"hash\":"}"#;
        assert_eq!(NodeRuntime::capture_host_dependency_count(bytes, 3), Ok(3));
        assert_eq!(
            NodeRuntime::capture_host_dependency_count(bytes, 2),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(
            NodeRuntime::capture_host_dependency_count(br#"{"hash":"unterminated"#, 8),
            Err(RuntimeError::InvalidReceipt)
        );
    }
}

impl crate::node_contract::NodeRuntime {
    pub(crate) fn capture_selected_json_counter_scratch_data() -> usize {
        super::core_decode_credit::scanner_storage()
    }
}

impl crate::node_contract::NodeRuntime {
    /// Separates the existing selected raw decoder's actual typed and temporary pools.
    pub(crate) fn capture_selected_json_decode_axes_data(
        bytes: &[u8],
        typed_slot: usize,
        typed_map_node: usize,
        maximum: usize,
    ) -> Result<(usize, usize, usize), crate::node_contract::RuntimeError> {
        let data = super::core_decode_credit::preflight_selected(
            bytes,
            typed_slot,
            typed_map_node,
            maximum,
        )?;
        // A Value-to-typed move can retain the parser's original String capacity.
        // Include that complete pool with the typed upper bound. The temporary
        // row repeats strings conservatively rather than granting a move refund.
        Ok((
            data.typed_containers
                .checked_add(data.parser_strings)
                .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?,
            data.parser_strings
                .checked_add(data.value_containers)
                .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?,
            data.canonical_temporaries,
        ))
    }

    pub(crate) fn capture_selected_json_decode_counter_scratch_data() -> usize {
        super::core_decode_credit::scanner_storage() + std::mem::size_of::<[usize; 3]>()
    }
}
