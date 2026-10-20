//! Dominant byte geometry beside the sole complete publication codecs.

use super::*;
use std::mem::size_of;
use aos_sandbox_core::format::{assignment_capture::CanonicalAssignmentDecodeCaptureV1, authorization_capture};
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1;

/// Bounds complete current/prepared/draft decoding from an actual row extent.
///
/// The old readers allocate their announced template vector only after the
/// fixed 256 ceiling, and each role vector after the fixed 16 ceiling. Those
/// real format limits are included even for truncated later fields. Core
/// canonical prevalidation precedes variable assignment/authorization vectors.
/// This is BYTE DATA, not parsing, currentness or publication permission.
/// `None` reports checked arithmetic overflow.
#[must_use]
pub fn decoding_receiving_bytes_v1(encoded_bytes: usize) -> Option<usize> {
    let (assignment, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
        encoded_bytes, DecodeLimits::default(),
    )?;
    let (authorization, _) = authorization_capture::authorization_artifact_plan_set_dynamic_footprint_v1(encoded_bytes, MAXIMUM_TEMPLATES)?;
    let assignment = assignment.checked_add(CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?)?;
    let role_backing = 16usize.checked_mul(size_of::<i32>().checked_add(size_of::<BrokerDescriptorRole>())?)?;
    let templates = MAXIMUM_TEMPLATES.checked_mul(
        size_of::<RecoveredBrokerDispatchTemplateV1>().checked_add(role_backing)?,
    )?.checked_mul(3)?;
    let plans = conservative_btree_node_bytes_v1::<u8, (Vec<u8>, Vec<u8>)>(4)?;
    let draft_plans = conservative_btree_node_bytes_v1::<BrokerAudience, (ObjectDigest, Vec<u8>)>(4)?;
    let fixed = size_of::<PublicationHistoryV1>()
        .checked_add(size_of::<RecoveredPublicationArtifactsV1>())?
        .checked_add(size_of::<DecodedPublicationCurrentV1>())?
        .checked_add(size_of::<AuthorityPublicationDraftV1>())?
        .checked_add(size_of::<OwnershipLease>())?
        .checked_add(size_of::<OwnershipTransactionReceiptV1>())?
        .checked_mul(3)?;
    // Outer prepared parse, structural revalidation and reconstructed draft
    // hold three actual assignment planes; signed plan/lease/signature/receipt
    // current decodes and construction/move planes coexist beside them.
    assignment.checked_mul(3)?.checked_add(usize::try_from(authorization).ok()?.checked_mul(3)?)?
        .checked_add(encoded_bytes.checked_mul(3)?)?
        .checked_add(templates)?.checked_add(plans)?.checked_add(draft_plans)?.checked_add(fixed)
}

/// Bounds named assignment/source/feature rows in the three decode planes.
///
/// Every materialized named row consumes at least one byte of its actual
/// encoded input. Three complete assignment/artifact reconstructions can
/// coexist in the same publication decoder, as in its byte supplier above.
/// This counts semantic rows only; no Result, Option, field or carrier fee is
/// included. Empty input has no such rows. `None` reports overflow.
#[must_use]
pub fn assignment_decoding_namespace_entries_v1(encoded_bytes: usize) -> Option<usize> {
    encoded_bytes.checked_mul(3)
}

/// Bounds the same decoder's named rows and its two audience-plan indices.
///
/// Template, role, feature, source and grant rows share the disjoint encoded
/// extent bound above. The actual `plans` and reconstructed `draft_plans`
/// indices each contain at most the four canonical broker audiences and no
/// more entries than encoded bytes. Their entries are separate real maps;
/// Rust controls and collection headers add no namespace entries.
/// `None` reports checked overflow.
#[must_use]
pub fn decoding_receiving_namespace_entries_v1(encoded_bytes: usize) -> Option<usize> {
    assignment_decoding_namespace_entries_v1(encoded_bytes)?
        .checked_add(encoded_bytes.min(4).checked_mul(2)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_namespace_has_no_control_or_map_header_fee() {
        assert_eq!(decoding_receiving_namespace_entries_v1(0), Some(0));
        assert_eq!(assignment_decoding_namespace_entries_v1(0), Some(0));
        assert!(decoding_receiving_bytes_v1(0).unwrap() > 0);
    }

    #[test]
    fn namespace_geometry_refuses_overflow_before_decoder_entry() {
        assert!(decoding_receiving_namespace_entries_v1(usize::MAX).is_none());
        assert!(assignment_decoding_namespace_entries_v1(usize::MAX).is_none());
    }

    #[test]
    fn truncated_later_template_fields_still_pay_announced_vector_capacity() {
        let bound = decoding_receiving_bytes_v1(32).unwrap();
        let templates = MAXIMUM_TEMPLATES * size_of::<RecoveredBrokerDispatchTemplateV1>();

        assert!(bound >= templates);
        assert!(decoding_receiving_bytes_v1(usize::MAX).is_none());
    }
}
