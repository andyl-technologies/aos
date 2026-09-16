//! Full recovered-object-graph validation for `AOSMSA02`.
//!
//! Local shape checks are followed by exact reference, lineage, sequence,
//! projection, and global-history checks. Recovery therefore accepts only a
//! state reachable through an all-old or all-new bounded transaction graph.

use std::collections::{BTreeMap, BTreeSet};

use crate::semantics::project_final_mount_create_semantics_v1;
use crate::{
    MountSourcePhysicalProofV1, SourceRealizationBindingV1,
    decode_historical_acquire_mount_source_request, mount_source_acquisition_id_v1,
    mount_source_acquisition_request_digest_v1, mount_source_physical_proof_digest_v1,
    mount_source_proof_class_from_provider_v1, mount_source_realization_handle_v1,
};
use aos_proto::aos::sandbox::local::v1::ReleaseMountSourceAcquisitionRequest;
use aos_sandbox_core::{BrokerArgumentCommitment, ObjectDigest};
use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, NormalizedAcquisitionIntentV2, SignedSourceExportLeaseV1,
    SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1,
    SignedSourceReleaseReceiptV1, SourceProviderAuthorityV1, SourceProviderDescriptorRole,
    SourceProviderKeyUsageV1, SourceProviderSigningKeyV1, SourceRootObservationV1,
    SourceSelectionFloorV1, SourceUseV1, decode_acquire_request, decode_inventory_request,
    decode_release_request, digest_acquire_request, digest_inventory, digest_inventory_request,
    digest_logical_binding_bytes, digest_provider_proof, digest_release_request,
    digest_signed_export_lease, prospective_mount_apply_template_digest_v1,
    provider_resource_commitment_v1, source_acquisition_id_v2,
    source_root_descriptor_commitment_v1, verify_inventory, verify_provider_receipt,
    verify_provider_receipt_and_lease, verify_release_receipt,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::checkpoint::{signer_matches, validate_attempt_checkpoint, validate_session_checkpoint};
use super::format::{
    MAXIMUM_LINEAGE_ATTEMPTS, MAXIMUM_SOURCE_ACQUISITIONS, MAXIMUM_SOURCE_HOLDER_SEQUENCES,
    MAXIMUM_SOURCE_PROVIDER_ATTEMPTS, MAXIMUM_SOURCE_PROVIDER_HEADS,
    MAXIMUM_SOURCE_PROVIDER_SESSIONS, MutationTagV2, attempt_id, death_digest, execution_digest,
    intent_digest, inventory_correlation_set_v2, manager_custody_evidence_digest_v2,
    manager_custody_loss_evidence_digest_v2, record_digest, request_id, session_id, state_error,
    transaction_id, validate_inventory_correlation_set_v2,
};
use super::history::{attempt_is_terminal, validate_global_history};
use super::model::*;
use super::projection::{
    inventory_correlation_for_row_v2, inventory_entry_matches_evidence, project_row, project_scope,
    projection_from_entries, reconciliation_conflict, reproduce_reconciliation,
};
use super::{MountSourceAcquisitionStateError, Result, SourceAcquisitionTableV2};

mod artifact;
mod common;
mod inventory;
mod lineage;
mod predecessor;
mod recovery;
mod row;
mod session;

use artifact::*;
use common::*;
use inventory::*;
use lineage::*;
use predecessor::*;
use recovery::*;
use row::*;
use session::*;

/// Validates every record and cross-record edge in one materialized snapshot.
///
/// # Errors
///
/// Returns an error for an invalid record, missing or aliased reference,
/// unreachable transition graph, broken cryptographic correlation, capacity
/// violation, or conflicting global history.
pub fn validate_recovered_table(table: &SourceAcquisitionTableV2) -> Result<()> {
    if table.acquisitions.len() > MAXIMUM_SOURCE_ACQUISITIONS
        || table.holder_sequences.len() > MAXIMUM_SOURCE_HOLDER_SEQUENCES
        || table.provider_heads.len() > MAXIMUM_SOURCE_PROVIDER_HEADS
        || table.provider_sessions.len() > MAXIMUM_SOURCE_PROVIDER_SESSIONS
        || table.provider_attempts.len() > MAXIMUM_SOURCE_PROVIDER_ATTEMPTS
    {
        return Err(state_error("AOSMSA02 table exceeds a fixed record bound"));
    }

    for sequence in table.holder_sequences.values() {
        validate_holder_sequence(sequence)?;
    }
    for session in table.provider_sessions.values() {
        validate_session(session)?;
    }
    for attempt in table.provider_attempts.values() {
        validate_attempt(attempt, table)?;
    }
    for row in table.acquisitions.values() {
        validate_row(row, table)?;
    }
    for head in table.provider_heads.values() {
        validate_head(head, table)?;
    }

    validate_global_history(
        &table.acquisitions,
        &table.provider_sessions,
        &table.provider_attempts,
    )?;
    validate_holder_sequence_graph(table)?;
    validate_lineages(table)?;
    validate_sequence_and_reservation_graph(table)?;
    validate_recovery_graph(table)?;
    validate_resolution_causality(table)?;
    validate_session_reachability(table)?;
    Ok(())
}
