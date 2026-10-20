//! Bounds the existing consuming Environment reader on its actual held rows.
//!
//! This passive byte requirement creates no record, currentness, owner, payer
//! or decoder admission. The genuine execution18 scope checks it before any
//! Environment candidate, history, activation or specification model grows.

use std::mem::size_of;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use crate::ResourceReservationErrorV1;
use super::*;

/// Bounds consuming replay and model peaks from the same held Source rows.
///
/// # Errors
/// Refuses unrepresentable checked geometry without decoding or native IO.
pub(crate) fn execution_source_receiving_demand_v1(
    view: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    use aos_sandbox_core::{ObjectDigest, ObjectDescriptor, RelativePath, PathName, SandboxId, Revision};
    let invalid = || ResourceReservationErrorV1::Conflict;
    let mut bytes = 0usize;
    let mut rows = 0usize;
    for (_, key, value) in view.all_records() {
        if !key.starts_with(<crate::environment::protected_journal::EnvironmentProtectedJournalSchemaV1
            as aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1>::KEY_PREFIX) {
            continue;
        }
        bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len())).ok_or_else(invalid)?;
        rows = rows.checked_add(1).ok_or_else(invalid)?;
    }
    // These are dominant byte peaks over the actual held prefix, not new
    // Option/scalar MetadataEntries. The existing consuming canonical engines
    // and physical memory backstop remain authoritative. Namespace/index
    // entries already resident in Source are never charged a second time.
    let generations = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
        (SandboxId, Revision), (EnvironmentGenerationManifestV1, EnvironmentManifestDigestV1),
    >(bytes).ok_or_else(invalid)?;
    let latest = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
        SandboxId, (EnvironmentGenerationManifestV1, EnvironmentManifestDigestV1),
    >(bytes).ok_or_else(invalid)?;
    let floors = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<SandboxId, Revision>(bytes)
        .ok_or_else(invalid)?;
    // Every ordinary CBOR element owns a distinct encoded head. The fixed
    // activation records preflight every count before allocating. Charge the
    // largest actual vector cell per byte, adjusted for those sole fixed-wire
    // strides; separately charge model roots/maps rather than treating every
    // scalar byte as a whole manifest or activation allocation.
    let ratio = |width: usize, stride: usize| width.checked_add(stride.checked_sub(1)?)?.checked_div(stride);
    let input_atom = [size_of::<ObjectDescriptor>(), size_of::<RelativePath>(),
        size_of::<PathName>(), size_of::<aos_sandbox_core::model::EnvironmentEntry>(),
        size_of::<aos_sandbox_core::FeatureRef>(),
        ratio(size_of::<EnvironmentInputCommitmentV1>(), 4).ok_or_else(invalid)?,
        ratio(size_of::<EnvironmentGenerationLeaseV1>(), super::activation_format::LEASE_BYTES).ok_or_else(invalid)?,
        ratio(size_of::<EnvironmentGcRootAcknowledgementV1>(), 64).ok_or_else(invalid)?,
        ratio(size_of::<EnvironmentSelectorV1>(), super::activation_format::SELECTOR_BYTES).ok_or_else(invalid)?]
        .into_iter().max().ok_or_else(invalid)?;
    let root_width = size_of::<EnvironmentGenerationManifestV1>()
        .checked_add(size_of::<EnvironmentActivationTransactionV1>())
        .and_then(|n| n.checked_add(size_of::<EnvironmentExecutionSourceV1>()))
        .and_then(|n| n.checked_add(size_of::<NixBuildStateV1>()))
        .and_then(|n| n.checked_add(size_of::<NixBuildRequestV1>())).ok_or_else(invalid)?;
    let headers = (bytes / 64).checked_add(rows)
        .and_then(|count| count.checked_mul(root_width)).ok_or_else(invalid)?;
    let limits = aos_sandbox_core::DecodeLimits::default();
    // The sole generation decoder caps announced capacities by the actual
    // inner CBOR extent, which cannot exceed these same held row bytes.
    // A failed CBOR collection may reserve its announced capacity before the
    // missing body is detected. Only the currently decoded collection can
    // have capacity without its elements' encoded bytes: preceding successful
    // collections and every cloned model are charged by the byte planes below.
    let announced_atom = [size_of::<ObjectDescriptor>(),
        size_of::<aos_sandbox_core::model::EnvironmentEntry>(),
        size_of::<RelativePath>(), size_of::<aos_sandbox_core::FeatureRef>(),
        size_of::<PathName>()].into_iter().max().ok_or_else(invalid)?;
    let announced = limits.maximum_collection_items.min(bytes).checked_mul(announced_atom)
        .ok_or_else(invalid)?;
    // Each retained-old selector encodes40 bytes and clones a complete
    // manifest plus closure. Desired/current/observed add three per record.
    // Until actual typed selection has completed, every held byte can belong
    // to the shared activation/checkpoint framing and every row can select a
    // generation. This is amplification DATA, not parser admission.
    let selectors = (bytes / super::activation_format::SELECTOR_BYTES).checked_add(rows.checked_mul(3).ok_or_else(invalid)?)
        .and_then(|n| n.checked_add(1)).ok_or_else(invalid)?;
    // A successful nested checkpoint item consumes at least one held byte.
    // Using bytes, rather than outer rows, also covers checkpoint-expanded
    // map/header cardinality without parsing a second time or narrowing grammar.
    // Two byte planes cover collection growth/strings and their live canonical
    // encoding; selector resolution can clone the whole manifest/closure.
    let plane = bytes.checked_mul(input_atom)
        .and_then(|n| n.checked_mul(selectors))
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(headers))
        .and_then(|n| n.checked_add(generations.checked_add(latest)?.checked_add(floors)?))
        .and_then(|n| n.checked_add(bytes.checked_mul(size_of::<ObjectDigest>())?))
        .ok_or_else(invalid)?;
    // These named consuming phases conservatively coexist with the held owner:
    // its Source history, initial recovery, schema replay, authenticated-history
    // reconstruction, current-activation candidates, selected execution source,
    // specification source/preview and canonical encode/compare scratch.
    let models = [plane, plane, plane, plane, plane, plane, plane, plane]
        .into_iter().try_fold(announced, |total, reached| total.checked_add(reached))
        .and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, models))
}
