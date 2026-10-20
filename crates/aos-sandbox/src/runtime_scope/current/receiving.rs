//! Prices the complete current-runtime reader graph on the held resident rows.
//!
//! This visits borrowed DATA only. It performs no parser entry, allocation, IO,
//! currentness check or selection, and cannot issue a scope or financial loan.

use std::collections::BTreeMap;
use std::mem::size_of;
use aos_sandbox_core::{DecodeLimits, ResourceDimension as D, ResourceVector};
use aos_sandbox_core::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use aos_sandbox_protocol::domain_ledger::{
    runtime_authority_history::{RuntimeAuthorityBindingV1, RuntimeAuthorityPendingV1, RuntimeAuthorityHeadV1},
    ownership_gate::{OwnershipGatePlanV1, OwnershipGateStatusV1},
    effect_history::effect_decoding_receiving_bytes_v1,
};
use crate::{Journal, RecordNamespace};
use super::CurrentRuntimeScopePolicy;

pub(in crate::runtime_scope) fn acquisition_receiving_demand_v1(
    journal: &Journal, policy: &CurrentRuntimeScopePolicy,
) -> Option<ResourceVector> {
    let mut runtime_rows = 0_usize;
    let mut runtime_bytes = 0_usize;
    let mut publication_peak = 0_usize;
    let mut gate_peak = 0_usize;
    let mut effect_peak = 0_usize;
    let mut artifact_extent = 0_usize;

    for (namespace, _, value) in journal.all_records() {
        match namespace {
            RecordNamespace::RuntimeAuthority => {
                runtime_rows = runtime_rows.checked_add(1)?;
                let (backing, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(value.len(), DecodeLimits::default())?;
                let construction = CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?;
                // Input holder binding, the scan's resident row and current
                // acquisition binding can coexist across the nested reader.
                let row = backing.checked_add(construction)?.checked_add(value.len().checked_mul(3)?)?;
                runtime_bytes = runtime_bytes.checked_add(row.checked_mul(3)?)?;
            }
            RecordNamespace::AuthorityPublication => {
                let bytes = aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(value.len())?;
                publication_peak = publication_peak.max(bytes);
                artifact_extent = artifact_extent.max(value.len());
            }
            RecordNamespace::OwnershipGate => {
                // The exact reader holds the parsed claim/draft while its
                // durable publication crosslink parses current/prepared rows.
                gate_peak = gate_peak.max(gate_receiving_bytes_v2(value.len())?);
                artifact_extent = artifact_extent.max(value.len());
            }
            RecordNamespace::Effect => {
                // A hostile Runtime crosslink can reference any Effect grammar
                // before its later exact Host/Stop relation refuses. Preserve
                // every existing public/Controller/FUSE/Nix/Q04 decoder branch.
                effect_peak = effect_peak.max(effect_decoding_receiving_bytes_v1(value.len())?);
            }
            _ => {}
        }
    }

    let maps = nodes::<[u8;16], RuntimeAuthorityPendingV1>(runtime_rows)?
        .checked_add(nodes::<[u8;16], RuntimeAuthorityHeadV1>(runtime_rows)?)?
        .checked_add(nodes::<[u8;16], BTreeMap<u64, RuntimeAuthorityBindingV1>>(runtime_rows)?)?
        .checked_add(nodes::<u64, RuntimeAuthorityBindingV1>(runtime_rows)?)?;
    let ownership = policy.ownership_verifier.response_receiving_dynamic_bytes_v2(artifact_extent)?;
    let plan = policy.broker_anchor.verification_receiving_bytes_v1(artifact_extent)?;
    // Existing outer selection, nested durable crosslink and current/permanent
    // comparison may hold three complete publications beside the Runtime map.
    let bytes = runtime_bytes.checked_add(maps)?
        .checked_add(publication_peak.checked_mul(3)?)?
        .checked_add(gate_peak)?.checked_add(effect_peak)?
        .checked_add(ownership)?.checked_add(plan)?
        // Original guarded residency is retained before freshness attenuation.
        // Price its actual construction and destination; this adds no namespace.
        .checked_add(size_of::<super::capture_lifetime::AssignmentCaptureBoundsV2>().checked_mul(2)?)?;
    // Each Runtime row enters at most one pending/head/inner-binding index,
    // plus one outer sandbox-group entry. The two publication plan indexes
    // each contain at most four audience entries. These are actual map rows;
    // decoder fields, JSON trees and Vecs remain byte representation only.
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::MetadataEntries, u64::try_from(runtime_rows.checked_mul(2)?.checked_add(if publication_peak > 0 || gate_peak > 0 { 8 } else { 0 })?).ok()?))
}

/// Shares the actual gate/claim decoder peak with the retained lifetime reader.
pub(super) fn gate_receiving_bytes_v2(bytes: usize) -> Option<usize> {
    let draft = aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(bytes)?;
    let fixed = size_of::<OwnershipGatePlanV1>()
        .checked_add(size_of::<OwnershipGateStatusV1>())?.checked_mul(3)?;
    draft.checked_add(bytes.checked_mul(3)?)?.checked_add(fixed)
}
