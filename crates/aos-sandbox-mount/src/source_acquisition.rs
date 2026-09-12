//! Durable Mount source-provider acquisition attempts and replay fences.
//!
//! Namespace 40 stores two exact `AOSMSA01` record kinds: acquisition rows
//! keyed by Mount-minted acquisition ID and provider heads keyed by stable
//! holder/provider authority. Provider heads own direction-local sequence CAS
//! and signed-inventory rollback floors. A durable observation ordinal orders
//! those floors against Release admission; none of these values is inferred by
//! scanning lifecycle rows.
//!
//! ```text
//! acquisition key = "aos.mount.source-acquisition.v1\0" || acquisition-id[32]
//! provider head key = "aos.mount.source-provider-head.v1\0" ||
//!                     holder-authority-id[16] || provider-authority-id[16]
//! ```
//!
//! This module deliberately exposes no provider router, socket, descriptor
//! observation constructor, or manager-custody adapter. A complete provider
//! response may be checkpointed with atomic sequence advancement while the row
//! remains `PendingQuery`; descriptor use begins only after that durable CAS.
//! `DescriptorCustodied` remains unusable until an authoritative PID 1 positive
//! query advances it to `Active`. Production wiring remains closed.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceResponse, InventoryMountSourceAcquisitionsResponse,
    ReleaseMountSourceAcquisitionRequest, ReleaseMountSourceAcquisitionResponse,
};
use aos_sandbox::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_protocol::{
    MountSourcePhysicalProofV1, MountSourceProviderHistoryV1,
    ValidatedReleaseMountSourceAcquisitionRequest, decode_historical_acquire_mount_source_request,
    mount_source_acquisition_id_v1, mount_source_acquisition_request_digest_v1,
    mount_source_physical_proof_digest_v1, mount_source_proof_class_from_provider_v1,
    mount_source_provider_history_is_valid_v1, mount_source_realization_handle_v1,
};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceResponseV1, InventoryLeaseStateV1, InventorySourceResponseV1,
    ReleaseSourceResponseV1, SignedSourceExportLeaseV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderDescriptorRole, SourceProviderKeyUsageV1,
    SourceProviderMethod, SourceProviderStatus, SourceRootObservationV1,
    VerifiedSourceAcquisitionV1, VerifiedSourceInventoryV1, VerifiedSourceProviderDispositionV1,
    VerifiedSourceReleaseV1, decode_acquire_request, decode_inventory_request,
    decode_release_request, digest_acquire_request, digest_inventory, digest_inventory_request,
    digest_logical_binding_bytes, digest_provider_proof, digest_release_request,
    digest_signed_export_lease, empty_descriptor_set_commitment_v1,
    prospective_mount_apply_template_digest_v1, provider_resource_commitment_v1,
    response_result_digest_v1, source_root_descriptor_commitment_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{MountError, Result};

mod checkpoint;
mod history;
mod inventory;
mod lifecycle;
mod model;
mod release_authority;
mod reservation;
#[cfg(test)]
mod tests;
mod validation;
mod wire;

use checkpoint::{
    checkpoint_request_identity, checkpoint_sequences_are_paired,
    validate_checkpoint_provider_signer, validate_checkpoint_provider_signer_against_head,
};
use inventory::{
    inventory_floor_proves_terminal_release, reconcile_current_inventory, reconcile_inventory,
};
pub use model::*;
use model::{StoredEnvelopeV1, StoredRecordV1};
use release_authority::validate_mount_release_request;
use reservation::{reserve_query, validate_pending_query, validate_release_query};
use validation::{
    acquire_checkpoint, derive_acquisition_evidence, inventory_checkpoint, release_checkpoint,
    same_acquire_identity, same_stable_inventory, validate_head_for_provider_context,
    validate_head_identity, validate_recovered_table, validate_sequence_advance,
    validate_sequence_numbers,
};
use wire::source_acquisition_record;

const SCHEMA: &str = "AOSMSA01";
const FORMAT_VERSION: u16 = 1;
const ACQUISITION_KEY_PREFIX: &[u8] = b"aos.mount.source-acquisition.v1\0";
const PROVIDER_HEAD_KEY_PREFIX: &[u8] = b"aos.mount.source-provider-head.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquisition-record.v1\0";
const ACQUISITION_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-acquisition-transaction.v1\0";
const PROVIDER_HEAD_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-provider-head-transaction.v1\0";
const PROVIDER_HEAD_CAPACITY_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-provider-head-capacity.v1\0";
const MAXIMUM_VALUE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_SIGNED_PROVIDER_BYTES: usize = 1024 * 1024;
const MAXIMUM_DISPOSITION_HISTORY: usize = 64;

/// Maximum retained acquisition rows in one Mount journal.
pub const MAXIMUM_SOURCE_ACQUISITIONS: usize = 1_024;
/// Maximum stable holder/provider sequence and inventory heads.
pub const MAXIMUM_SOURCE_PROVIDER_HEADS: usize = 256;

/// Materializes and validates all namespace-40 acquisition and provider-head state.
#[derive(Debug)]
pub struct SourceAcquisitionTableV1 {
    acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV1>,
}

/// Encodes one canonical Acquire response from the current durable row.
///
/// # Errors
///
/// Returns an error when the row fails recovery validation.
pub fn encode_acquire_response(row: &SourceAcquisitionRowV1) -> Result<Vec<u8>> {
    Ok(AcquireMountSourceResponse {
        record: Some(source_acquisition_record(row)?).into(),
        ..Default::default()
    }
    .encode_to_vec())
}

/// Encodes one canonical Release response from the current durable row.
///
/// # Errors
///
/// Returns an error when the row fails recovery validation.
pub fn encode_release_response(row: &SourceAcquisitionRowV1) -> Result<Vec<u8>> {
    Ok(ReleaseMountSourceAcquisitionResponse {
        record: Some(source_acquisition_record(row)?).into(),
        ..Default::default()
    }
    .encode_to_vec())
}

impl SourceAcquisitionTableV1 {
    /// Reconstructs every exact `AOSMSA01` record from namespace 40.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported, noncanonical, corrupt, aliased, or
    /// over-limit rows, invalid phase shapes, and invalid provider heads.
    pub fn recover(journal: &Journal) -> Result<Self> {
        let mut acquisitions = BTreeMap::new();
        let mut provider_heads = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::MountSourceAcquisition) {
            match decode_value(value)? {
                StoredRecordV1::Acquisition { row } => {
                    if key != acquisition_key(row.acquisition_id)
                        || acquisitions.insert(row.acquisition_id, row).is_some()
                    {
                        return Err(state_error("source acquisition key aliases another row"));
                    }
                }
                StoredRecordV1::ProviderHead { head } => {
                    let identity = (head.holder_authority_id, head.provider_authority_id);
                    if key != provider_head_key(identity.0, identity.1)
                        || provider_heads.insert(identity, head).is_some()
                    {
                        return Err(state_error("source provider head key aliases another row"));
                    }
                }
            }
        }
        if acquisitions.len() > MAXIMUM_SOURCE_ACQUISITIONS
            || provider_heads.len() > MAXIMUM_SOURCE_PROVIDER_HEADS
        {
            return Err(state_error(
                "source acquisition state exceeds its fixed count bound",
            ));
        }
        validate_recovered_table(&acquisitions, &provider_heads)?;
        Ok(Self {
            acquisitions,
            provider_heads,
        })
    }

    /// Returns acquisition rows in canonical acquisition-ID order.
    pub fn rows(&self) -> impl Iterator<Item = &SourceAcquisitionRowV1> {
        self.acquisitions.values()
    }

    /// Returns one exact acquisition row.
    #[must_use]
    pub fn get(&self, acquisition_id: &[u8; 32]) -> Option<&SourceAcquisitionRowV1> {
        self.acquisitions.get(acquisition_id)
    }

    /// Returns one exact durable provider head.
    #[must_use]
    pub fn provider_head(
        &self,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Option<&SourceProviderHeadV1> {
        self.provider_heads
            .get(&(holder_authority_id, provider_authority_id))
    }

    /// Encodes one canonical bounded source-acquisition inventory response.
    ///
    /// The returned snapshot is kernel-nominated broker output, not proof of
    /// the syscall writer. Controller currentness remains gated on authenticated
    /// broker sessions and deployment confinement.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinel snapshot identities, an empty journal
    /// sequence, an invalid retained row, or an encoded response over the
    /// global protocol maximum. The outer session envelope applies the
    /// negotiated and request-specific response ceilings.
    pub fn encode_inventory_response(
        &self,
        kernel_boot_id: [u8; 16],
        journal_sequence: u64,
        broker_instance_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        if kernel_boot_id == [0; 16] || journal_sequence == 0 || broker_instance_id == [0; 16] {
            return Err(state_error(
                "source acquisition inventory header is invalid",
            ));
        }
        let acquisitions = self
            .acquisitions
            .values()
            .map(source_acquisition_record)
            .collect::<Result<Vec<_>>>()?;
        let bytes = InventoryMountSourceAcquisitionsResponse {
            kernel_boot_id: kernel_boot_id.to_vec(),
            journal_sequence,
            acquisitions,
            broker_instance_id: broker_instance_id.to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition inventory exceeds the response ceiling",
            ));
        }
        Ok(bytes)
    }

    /// Replaces one authenticated provider session without resetting stable floors.
    ///
    /// Fresh hello nonces, a kernel reboot, route replacement, or provider
    /// rekey may reset direction-local counters only after every PendingQuery
    /// attempt under the old session was durably resolved or faulted. Inventory
    /// and catalog evidence survive unchanged. A faulted attempt requires a new
    /// controller operation and therefore a new acquisition ID; authenticated
    /// query history is never rewritten into a replacement session.
    /// Construction of the scalar context is shape-only; production callers
    /// must obtain it from the protected trust/session adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when the authority pair changes, the replacement does
    /// not change session authority, counters do not restart at one, a stable
    /// floor changes, or the journal commit fails.
    pub fn replace_provider_session(
        &mut self,
        journal: &mut Journal,
        session: &AuthenticatedProviderSessionV1,
    ) -> Result<()> {
        let provider = session.provider;
        let mut next = session.head.clone();
        let identity = (provider.holder_authority_id, provider.provider_authority_id);
        let current = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider head is absent"))?;
        let has_old_session_attempt = self.acquisitions.values().any(|row| {
            row.provider.holder_authority_id == provider.holder_authority_id
                && row.provider.provider_authority_id == provider.provider_authority_id
                && row.phase == SourceAcquisitionPhaseV1::PendingQuery
        });
        if current.pending_query.is_some()
            || has_old_session_attempt
            || next.next_request_sequence != 1
            || next.next_response_sequence != 1
            || next.inventory_generation != current.inventory_generation
            || next.inventory_digest != current.inventory_digest
            || next.signed_inventory_digest != current.signed_inventory_digest
            || next.signed_inventory != current.signed_inventory
            || next.catalog_generation != current.catalog_generation
            || next.catalog_digest != current.catalog_digest
            || next.inventory_observation_ordinal != current.inventory_observation_ordinal
            || next.has_untracked_inventory_residuals != current.has_untracked_inventory_residuals
            || next.has_inventory_authority_conflicts != current.has_inventory_authority_conflicts
            || next.last_inventory_checkpoint.is_some()
            || next.pending_query.is_some()
            || !provider_session_replacement_is_monotonic(current, &next)
            || current.session_binding == next.session_binding
                && current.kernel_boot_id == next.kernel_boot_id
                && current.route_id == next.route_id
                && current.route_generation == next.route_generation
                && current.route_digest == next.route_digest
                && current.provider_key_generation == next.provider_key_generation
        {
            return Err(state_error(
                "source provider session replacement is not exact",
            ));
        }
        next.last_inventory_checkpoint = None;
        validate_head_for_provider_context(&next, provider)?;
        next.validate()?;
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, next.clone());
        validate_recovered_table(&self.acquisitions, &tentative_heads)?;

        let transaction = JournalTransaction::new(
            provider_head_transaction_id(&next),
            vec![put_provider_head(&next)?],
        )?;
        journal.commit(&transaction)?;
        self.provider_heads.insert(identity, next);
        Ok(())
    }

    /// Commits a first PendingQuery row and its existing or new provider head.
    ///
    /// Exact replay performs no logical write. Reuse of either operation ID or
    /// acquisition ID with changed bytes fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid shape, capacity, replay equivocation,
    /// provider-head mismatch, or journal failure.
    pub fn admit_pending(
        &mut self,
        journal: &mut Journal,
        mut row: SourceAcquisitionRowV1,
        session: &AuthenticatedProviderSessionV1,
    ) -> Result<bool> {
        let head = &session.head;
        row.record_digest = acquisition_record_digest(&row)?;
        row.validate()?;
        head.validate()?;
        if row.revision != 1
            || row.phase != SourceAcquisitionPhaseV1::PendingQuery
            || row.acquire_checkpoint.is_some()
            || !row.acquire_history.is_empty()
            || row.evidence.is_some()
            || row.descriptor_custody_digest.is_some()
            || row.positive_custody_digest.is_some()
            || row.consumed_source_pin_record_digest.is_some()
            || row.consumed_create_effect_record_digest.is_some()
            || row.consumed_create_operation_record_digest.is_some()
            || row.release.is_some()
            || row.mount_release_request.is_some()
            || row.release_authority.is_some()
            || row.release_provider.is_some()
            || row.release_inventory_observation_floor.is_some()
            || row.provider_release_request.is_some()
            || row.provider_release_request_digest.is_some()
            || row.initial_provider_release_request.is_some()
            || row.initial_provider_release_request_digest.is_some()
            || row.release_checkpoint.is_some()
            || !row.release_history.is_empty()
            || row.release_generation.is_some()
            || row.provider_inventory_digest.is_some()
            || row.provider_inventory_observation_ordinal.is_some()
            || row.negative_custody_digest.is_some()
            || row.faulted_from.is_some()
            || row.fault_digest.is_some()
            || row.retained_faulted_from.is_some()
            || row.retained_fault_digest.is_some()
        {
            return Err(state_error(
                "source acquisition admission is not a pristine PendingQuery",
            ));
        }
        if session.provider != row.provider {
            return Err(state_error(
                "authenticated provider session differs from acquisition context",
            ));
        }
        validate_head_for_provider_context(head, row.provider)?;
        if let Some(existing) = self.acquisitions.get(&row.acquisition_id) {
            if same_acquire_identity(existing, &row) {
                return Ok(false);
            }
            return Err(state_error("source acquisition ID equivocated"));
        }
        if operation_id_is_used(&self.acquisitions, row.acquire.operation_id) {
            return Err(state_error("source acquisition operation ID equivocated"));
        }
        if self.acquisitions.len() >= MAXIMUM_SOURCE_ACQUISITIONS {
            return Err(state_error("source acquisition capacity exhausted"));
        }
        let head_identity = (head.holder_authority_id, head.provider_authority_id);
        let current_head = match self.provider_heads.get(&head_identity) {
            Some(existing) if existing != head => {
                return Err(state_error(
                    "source provider head changed outside sequence CAS",
                ));
            }
            None if self.provider_heads.len() >= MAXIMUM_SOURCE_PROVIDER_HEADS => {
                return Err(state_error("source provider head capacity exhausted"));
            }
            None if !pristine_provider_head(head) => {
                return Err(state_error("initial source provider head is not pristine"));
            }
            Some(existing) => existing,
            None => head,
        };
        let reserved_head = reserve_query(
            current_head,
            ProviderQueryOwnerV1::Acquire {
                acquisition_id: row.acquisition_id,
            },
            &row.provider_acquire_request,
        )?;
        let mut tentative = self.acquisitions.clone();
        tentative.insert(row.acquisition_id, row.clone());
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(head_identity, reserved_head.clone());
        validate_recovered_table(&tentative, &tentative_heads)?;

        let records = vec![put_acquisition(&row)?, put_provider_head(&reserved_head)?];
        let transaction = JournalTransaction::new(
            transaction_id(row.acquisition_id, row.revision),
            records.clone(),
        )?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(row.acquisition_id, row);
        self.provider_heads.insert(head_identity, reserved_head);
        Ok(true)
    }

    /// Atomically advances one row and its shared provider sequence head.
    ///
    /// This is the sole path for consuming a newly verified provider status.
    /// The checkpoint sequences must equal the current head, and the next head
    /// must advance each by exactly one. Exact response redelivery against the
    /// already-recorded checkpoint is a no-write replay.
    ///
    /// # Errors
    ///
    /// Returns an error for sequence gaps/replay/equivocation, phase or record
    /// mismatch, provider-head mismatch, or journal failure.
    pub fn record_provider_disposition(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        signed_request: &SignedSourceProviderRequestV1,
        response: &AcquireSourceResponseV1,
        verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
        branded_observation: Option<&BrandedSourceRootObservationV1>,
        next_head: SourceProviderHeadV1,
    ) -> Result<bool> {
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        let checkpoint = acquire_checkpoint(signed_request, response, verified)?;
        let evidence = derive_acquisition_evidence(current, verified, branded_observation)?;
        if current.acquire_history.contains(&checkpoint) && evidence.is_none() {
            return Ok(false);
        }
        if let Some(existing) = &current.acquire_checkpoint {
            if existing == &checkpoint && current.evidence == evidence {
                return Ok(false);
            }
            return Err(state_error(
                "provider Acquire response equivocated after sequence CAS",
            ));
        }
        if current.phase != SourceAcquisitionPhaseV1::PendingQuery {
            return Err(state_error(
                "provider Acquire disposition requires PendingQuery",
            ));
        }
        let head_identity = (
            current.provider.holder_authority_id,
            current.provider.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&head_identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        validate_sequence_advance(
            current_head,
            &checkpoint,
            &next_head,
            ProviderQueryOwnerV1::Acquire { acquisition_id },
        )?;
        if checkpoint.status == ProviderStatusV1::Complete && evidence.is_none()
            || checkpoint.status != ProviderStatusV1::Complete && evidence.is_some()
        {
            return Err(state_error("provider Acquire result shape is invalid"));
        }
        if checkpoint.signed_request != current.provider_acquire_request
            || checkpoint.signed_request_digest != current.provider_acquire_request_digest
        {
            return Err(state_error(
                "provider Acquire request differs from durable query",
            ));
        }
        next_head.validate()?;
        let mut next = current.clone();
        next.revision = next_revision(next.revision)?;
        next.acquire_checkpoint = Some(checkpoint);
        next.evidence = evidence;
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;
        let mut tentative = self.acquisitions.clone();
        tentative.insert(acquisition_id, next.clone());
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(head_identity, next_head.clone());
        validate_recovered_table(&tentative, &tentative_heads)?;

        let records = vec![put_acquisition(&next)?, put_provider_head(&next_head)?];
        let transaction =
            JournalTransaction::new(transaction_id(acquisition_id, next.revision), records)?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        self.provider_heads.insert(head_identity, next_head);
        Ok(true)
    }

    /// Atomically records a monotonic signed provider inventory floor.
    ///
    /// The supplied verified inventory is cryptographic evidence only. The
    /// current durable head supplies rollback/currentness authority. Equal
    /// generation with unchanged stable content is a fresh observation and
    /// advances the durable observation ordinal. Exact checkpoint redelivery
    /// produces no write; lower or changed equal-generation evidence fails.
    ///
    /// # Errors
    ///
    /// Returns an error for scope mismatch, rollback/equivocation, sequence
    /// mismatch, malformed head state, or journal failure.
    pub fn record_inventory_floor(
        &mut self,
        journal: &mut Journal,
        holder_authority_id: [u8; 16],
        signed_request: &SignedSourceProviderRequestV1,
        response: &InventorySourceResponseV1,
        verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
        next_head: SourceProviderHeadV1,
    ) -> Result<bool> {
        let mut checkpoint = inventory_checkpoint(signed_request, response, verified)?;
        let verified_inventory = verified
            .result()
            .ok_or_else(|| state_error("provider inventory result is not Complete"))?;
        let signed_inventory_bytes = verified_inventory.signed_inventory().to_canonical_bytes();
        let inventory = verified_inventory.signed_inventory().subject();
        let provider_authority_id = inventory.provider().authority_id();
        let identity = (holder_authority_id, provider_authority_id);
        let current = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider head is absent"))?;
        if inventory.holder_authority_id() != holder_authority_id
            || response.signed_inventory() != Some(signed_inventory_bytes.as_slice())
        {
            return Err(state_error("provider inventory scope or bytes differ"));
        }
        let inventory_digest = *digest_inventory(inventory).as_bytes();
        let signed_digest: [u8; 32] = Sha256::digest(&signed_inventory_bytes).into();
        // The provider head retains the complete inventory bytes once. Its
        // checkpoint retains the linked result digest and signed status.
        checkpoint.signed_result.clear();
        match current.inventory_generation {
            Some(generation) if inventory.inventory_generation() < generation => {
                return Err(state_error("provider inventory generation rolled back"));
            }
            Some(generation) if inventory.inventory_generation() == generation => {
                if current.inventory_digest == Some(inventory_digest)
                    && current.signed_inventory_digest == Some(signed_digest)
                    && current.signed_inventory == signed_inventory_bytes
                    && current.catalog_generation == Some(inventory.catalog_generation())
                    && current.catalog_digest == Some(*inventory.catalog_digest().as_bytes())
                    && current.last_inventory_checkpoint.as_ref() == Some(&checkpoint)
                {
                    return Ok(false);
                }
                let previous = SignedSourceProviderInventoryV1::from_canonical_bytes(
                    &current.signed_inventory,
                )
                .map_err(|error| state_error(error.to_string()))?;
                if !same_stable_inventory(previous.subject(), inventory) {
                    return Err(state_error(
                        "equal-generation provider inventory equivocated",
                    ));
                }
            }
            _ => {}
        }
        if current.catalog_generation.is_some_and(|generation| {
            inventory.catalog_generation() < generation
                || inventory.catalog_generation() == generation
                    && current.catalog_digest != Some(*inventory.catalog_digest().as_bytes())
        }) {
            return Err(state_error(
                "provider inventory catalog rolled back or equivocated",
            ));
        }
        let reconciliation = reconcile_inventory(
            &self.acquisitions,
            holder_authority_id,
            provider_authority_id,
            inventory,
        )?;
        let mut next_head = next_head;
        next_head.last_inventory_checkpoint = Some(checkpoint.clone());
        if next_head.holder_authority_id != holder_authority_id
            || next_head.provider_authority_id != provider_authority_id
            || next_head.inventory_generation != Some(inventory.inventory_generation())
            || next_head.inventory_digest != Some(inventory_digest)
            || next_head.signed_inventory_digest != Some(signed_digest)
            || next_head.signed_inventory != signed_inventory_bytes
            || next_head.catalog_generation != Some(inventory.catalog_generation())
            || next_head.catalog_digest != Some(*inventory.catalog_digest().as_bytes())
            || next_head.inventory_observation_ordinal
                != next_inventory_observation_ordinal(current.inventory_observation_ordinal)?
            || next_head.last_inventory_checkpoint.as_ref() != Some(&checkpoint)
            || next_head.has_untracked_inventory_residuals != reconciliation.has_untracked_residuals
            || next_head.has_inventory_authority_conflicts != reconciliation.has_authority_conflicts
        {
            return Err(state_error("next provider inventory head is not exact"));
        }
        validate_head_identity(current, &next_head)?;
        validate_sequence_numbers(
            current,
            &checkpoint,
            &next_head,
            ProviderQueryOwnerV1::Inventory,
        )?;
        next_head.validate()?;
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, next_head.clone());
        validate_recovered_table(&self.acquisitions, &tentative_heads)?;
        let transaction = JournalTransaction::new(
            provider_head_transaction_id(&next_head),
            vec![put_provider_head(&next_head)?],
        )?;
        journal.commit(&transaction)?;
        self.provider_heads.insert(identity, next_head);
        Ok(true)
    }

    /// Consumes a signed noncomplete provider Inventory disposition without changing its floor.
    ///
    /// Pending, Rejected, and Unavailable statuses advance both authenticated
    /// direction sequences and retain their exact bytes. They do not establish
    /// inventory currentness or reconcile any acquisition row.
    ///
    /// # Errors
    ///
    /// Returns an error for a Complete result, scope mismatch, response
    /// equivocation, sequence replay/gap, floor mutation, or journal failure.
    #[allow(clippy::too_many_arguments)]
    pub fn record_noncomplete_inventory_disposition(
        &mut self,
        journal: &mut Journal,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
        signed_request: &SignedSourceProviderRequestV1,
        response: &InventorySourceResponseV1,
        verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
        next_head: SourceProviderHeadV1,
    ) -> Result<bool> {
        if verified.result().is_some() {
            return Err(state_error(
                "Complete provider inventory must advance the durable floor",
            ));
        }
        let checkpoint = inventory_checkpoint(signed_request, response, verified)?;
        let identity = (holder_authority_id, provider_authority_id);
        let current = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider head is absent"))?;
        if current.last_inventory_checkpoint.as_ref() == Some(&checkpoint) {
            return Ok(false);
        }
        validate_head_identity(current, &next_head)?;
        validate_sequence_numbers(
            current,
            &checkpoint,
            &next_head,
            ProviderQueryOwnerV1::Inventory,
        )?;
        if next_head.inventory_generation != current.inventory_generation
            || next_head.inventory_digest != current.inventory_digest
            || next_head.signed_inventory_digest != current.signed_inventory_digest
            || next_head.signed_inventory != current.signed_inventory
            || next_head.catalog_generation != current.catalog_generation
            || next_head.catalog_digest != current.catalog_digest
            || next_head.inventory_observation_ordinal != current.inventory_observation_ordinal
            || next_head.last_inventory_checkpoint.as_ref() != Some(&checkpoint)
            || next_head.has_untracked_inventory_residuals
                != current.has_untracked_inventory_residuals
            || next_head.has_inventory_authority_conflicts
                != current.has_inventory_authority_conflicts
        {
            return Err(state_error(
                "noncomplete provider inventory disposition changed stable state",
            ));
        }
        next_head.validate()?;
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, next_head.clone());
        validate_recovered_table(&self.acquisitions, &tentative_heads)?;
        let transaction = JournalTransaction::new(
            provider_head_transaction_id(&next_head),
            vec![put_provider_head(&next_head)?],
        )?;
        journal.commit(&transaction)?;
        self.provider_heads.insert(identity, next_head);
        Ok(true)
    }

    /// Durably enters `Releasing` before any provider Release I/O.
    ///
    /// Exact replay returns the current lifecycle row without a logical write,
    /// including after later disposition or terminal commits. Cleanup may begin
    /// from any phase that already retains a verified provider lease. The row
    /// freezes the current Inventory observation ordinal before Release I/O.
    ///
    /// # Errors
    ///
    /// Returns an error for request-ID equivocation, a stale initial CAS,
    /// missing lease evidence, an ineligible phase, invalid signed request
    /// bytes, or journal failure.
    pub fn begin_release(
        &mut self,
        journal: &mut Journal,
        mount_release_request: Vec<u8>,
        request: &ValidatedReleaseMountSourceAcquisitionRequest,
        provider_release_request: Vec<u8>,
        session: &AuthenticatedProviderSessionV1,
    ) -> Result<bool> {
        let acquisition_id = *request.acquisition_id().as_bytes();
        let release = SourceAcquisitionOperationV1 {
            operation_id: *request.header().request_id(),
            request_digest: *request.request_digest().as_bytes(),
        };
        let provider_release_request_digest: [u8; 32] =
            Sha256::digest(&provider_release_request).into();
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        if let Some(existing) = current.release {
            if existing == release
                && current.mount_release_request.as_ref() == Some(&mount_release_request)
                && current.initial_provider_release_request.as_ref()
                    == Some(&provider_release_request)
                && current.initial_provider_release_request_digest
                    == Some(provider_release_request_digest)
            {
                return Ok(false);
            }
            return Err(state_error(
                "source acquisition Release request equivocated",
            ));
        }
        if mount_source_acquisition_request_digest_v1(&mount_release_request)
            != request.request_digest()
            || request.expected_revision() != current.revision
            || request.expected_record_digest().as_bytes() != &current.record_digest
        {
            return Err(state_error(
                "source acquisition Release compare-and-swap failed",
            ));
        }
        let release_authority = release_authority(request);
        if !release_authority_dominates(current.assignment, release_authority) {
            return Err(state_error(
                "source acquisition Release fence does not dominate Acquire",
            ));
        }
        if operation_id_is_used(&self.acquisitions, release.operation_id) {
            return Err(state_error(
                "source acquisition Release operation ID is already used",
            ));
        }
        if !valid_operation(release)
            || !valid_signed_request(&provider_release_request, provider_release_request_digest)
            || current.evidence.is_none()
            || !matches!(
                current.phase,
                SourceAcquisitionPhaseV1::PendingQuery
                    | SourceAcquisitionPhaseV1::DescriptorCustodied
                    | SourceAcquisitionPhaseV1::Active
                    | SourceAcquisitionPhaseV1::Consumed
                    | SourceAcquisitionPhaseV1::Faulted
            )
        {
            return Err(state_error(
                "source acquisition is not eligible for cleanup",
            ));
        }
        let head_identity = (
            current.provider.holder_authority_id,
            current.provider.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&head_identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        if session.head != *current_head
            || session.provider.holder_authority_id != current.provider.holder_authority_id
            || session.provider.provider_authority_id != current.provider.provider_authority_id
        {
            return Err(state_error(
                "source provider Release session is not the authenticated current head",
            ));
        }
        validate_release_query(current, session.provider, &provider_release_request)?;
        let reserved_head = reserve_query(
            current_head,
            ProviderQueryOwnerV1::Release { acquisition_id },
            &provider_release_request,
        )?;

        let mut next = current.clone();
        next.revision = next_revision(next.revision)?;
        next.phase = SourceAcquisitionPhaseV1::Releasing;
        next.release = Some(release);
        next.mount_release_request = Some(mount_release_request);
        next.release_authority = Some(release_authority);
        next.release_provider = Some(session.provider);
        next.release_inventory_observation_floor = Some(current_head.inventory_observation_ordinal);
        next.provider_release_request = Some(provider_release_request);
        next.provider_release_request_digest = Some(provider_release_request_digest);
        next.initial_provider_release_request = next.provider_release_request.clone();
        next.initial_provider_release_request_digest = next.provider_release_request_digest;
        next.release_checkpoint = None;
        next.release_history.clear();
        next.release_generation = None;
        next.negative_custody_digest = None;
        if current.phase == SourceAcquisitionPhaseV1::Faulted {
            next.retained_faulted_from = current.faulted_from;
            next.retained_fault_digest = current.fault_digest;
        }
        next.faulted_from = None;
        next.fault_digest = None;
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;
        let mut tentative = self.acquisitions.clone();
        tentative.insert(acquisition_id, next.clone());
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(head_identity, reserved_head.clone());
        validate_recovered_table(&tentative, &tentative_heads)?;

        let transaction = JournalTransaction::new(
            transaction_id(acquisition_id, next.revision),
            vec![put_acquisition(&next)?, put_provider_head(&reserved_head)?],
        )?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        self.provider_heads.insert(head_identity, reserved_head);
        Ok(true)
    }

    /// Atomically records one verified provider Release disposition and advances its shared head.
    ///
    /// The row remains `Releasing`; a separate transition may reach `Released`
    /// only after authoritative manager-negative custody evidence is available.
    /// Exact redelivery of the already-consumed signed response performs no write.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent or non-Releasing row, request or response
    /// equivocation, sequence replay/gap, nonterminal result shape, a release
    /// generation mismatch, or journal failure.
    pub fn record_release_disposition(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        signed_request: &SignedSourceProviderRequestV1,
        response: &ReleaseSourceResponseV1,
        verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceReleaseV1>,
        next_head: SourceProviderHeadV1,
    ) -> Result<bool> {
        let checkpoint = release_checkpoint(signed_request, response, verified)?;
        let release_generation = verified
            .result()
            .map(VerifiedSourceReleaseV1::release_generation);
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        if current.release_history.contains(&checkpoint) && release_generation.is_none() {
            return Ok(false);
        }
        if let Some(existing) = &current.release_checkpoint {
            if existing == &checkpoint && current.release_generation == release_generation {
                return Ok(false);
            }
            return Err(state_error(
                "provider Release response equivocated after sequence CAS",
            ));
        }
        if current.phase != SourceAcquisitionPhaseV1::Releasing {
            return Err(state_error(
                "provider Release disposition requires Releasing",
            ));
        }
        let release_request = current
            .provider_release_request
            .as_ref()
            .ok_or_else(|| state_error("durable provider Release request is absent"))?;
        let release_request_digest = current
            .provider_release_request_digest
            .ok_or_else(|| state_error("durable provider Release request digest is absent"))?;
        if checkpoint.signed_request != *release_request
            || checkpoint.signed_request_digest != release_request_digest
        {
            return Err(state_error(
                "provider Release request differs from durable query",
            ));
        }
        if (checkpoint.status == ProviderStatusV1::Complete) != release_generation.is_some()
            || release_generation == Some(0)
            || verified.result().is_some_and(|release| {
                current.evidence.as_ref().is_none_or(|evidence| {
                    release.lease_digest().as_bytes() != &evidence.signed_lease_digest
                })
            })
        {
            return Err(state_error("provider Release result shape is invalid"));
        }
        let head_identity = (
            current.provider.holder_authority_id,
            current.provider.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&head_identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        validate_sequence_advance(
            current_head,
            &checkpoint,
            &next_head,
            ProviderQueryOwnerV1::Release { acquisition_id },
        )?;
        next_head.validate()?;

        let mut next = current.clone();
        next.revision = next_revision(next.revision)?;
        next.release_checkpoint = Some(checkpoint);
        next.release_generation = release_generation;
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;

        let records = vec![put_acquisition(&next)?, put_provider_head(&next_head)?];
        let transaction =
            JournalTransaction::new(transaction_id(acquisition_id, next.revision), records)?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        self.provider_heads.insert(head_identity, next_head);
        Ok(true)
    }
}

fn acquisition_record_digest(row: &SourceAcquisitionRowV1) -> Result<[u8; 32]> {
    let mut body = row.clone();
    body.record_digest = [0; 32];
    let bytes = serde_json::to_vec(&body).map_err(|error| state_error(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(RECORD_DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn put_acquisition(row: &SourceAcquisitionRowV1) -> Result<JournalRecord> {
    row.validate()?;
    encode_record(
        acquisition_key(row.acquisition_id),
        StoredRecordV1::Acquisition { row: row.clone() },
    )
}

fn put_provider_head(head: &SourceProviderHeadV1) -> Result<JournalRecord> {
    head.validate()?;
    encode_record(
        provider_head_key(head.holder_authority_id, head.provider_authority_id),
        StoredRecordV1::ProviderHead { head: head.clone() },
    )
}

fn encode_record(key: Vec<u8>, record: StoredRecordV1) -> Result<JournalRecord> {
    let bytes = serde_json::to_vec(&StoredEnvelopeV1 {
        schema: SCHEMA.to_owned(),
        version: FORMAT_VERSION,
        record,
    })
    .map_err(|error| state_error(error.to_string()))?;
    if bytes.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error(
            "source acquisition record exceeds its fixed byte bound",
        ));
    }
    Ok(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        key,
        bytes,
    ))
}

fn decode_value(bytes: &[u8]) -> Result<StoredRecordV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error("source acquisition record length is invalid"));
    }
    let stored: StoredEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|error| state_error(error.to_string()))?;
    if stored.schema != SCHEMA || stored.version != FORMAT_VERSION {
        return Err(state_error(
            "source acquisition schema or version is unsupported",
        ));
    }
    match &stored.record {
        StoredRecordV1::Acquisition { row } => row.validate()?,
        StoredRecordV1::ProviderHead { head } => head.validate()?,
    }
    if serde_json::to_vec(&stored).map_err(|error| state_error(error.to_string()))? != bytes {
        return Err(state_error(
            "source acquisition record is not canonical JSON",
        ));
    }
    Ok(stored.record)
}

fn acquisition_key(acquisition_id: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ACQUISITION_KEY_PREFIX.len() + 32);
    key.extend_from_slice(ACQUISITION_KEY_PREFIX);
    key.extend_from_slice(&acquisition_id);
    key
}

fn provider_head_key(holder: [u8; 16], provider: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PROVIDER_HEAD_KEY_PREFIX.len() + 32);
    key.extend_from_slice(PROVIDER_HEAD_KEY_PREFIX);
    key.extend_from_slice(&holder);
    key.extend_from_slice(&provider);
    key
}

fn transaction_id(acquisition_id: [u8; 32], revision: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(ACQUISITION_TRANSACTION_DOMAIN);
    digest.update(acquisition_id);
    digest.update(revision.to_be_bytes());
    truncate_digest(digest.finalize().into())
}

fn provider_head_transaction_id(head: &SourceProviderHeadV1) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(PROVIDER_HEAD_TRANSACTION_DOMAIN);
    digest.update(head.holder_authority_id);
    digest.update(head.provider_authority_id);
    digest.update(head.session_binding);
    digest.update(head.next_request_sequence.to_be_bytes());
    digest.update(head.next_response_sequence.to_be_bytes());
    truncate_digest(digest.finalize().into())
}

fn provider_head_capacity_transaction_id(head: &SourceProviderHeadV1) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(PROVIDER_HEAD_CAPACITY_TRANSACTION_DOMAIN);
    digest.update(head.holder_authority_id);
    digest.update(head.provider_authority_id);
    digest.update(head.session_binding);
    digest.update(head.next_request_sequence.to_be_bytes());
    digest.update(head.next_response_sequence.to_be_bytes());
    truncate_digest(digest.finalize().into())
}

fn preflight_inventory_completion_capacity(
    journal: &Journal,
    reservation: &JournalTransaction,
    head: &SourceProviderHeadV1,
) -> Result<()> {
    let maximum_head = JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        provider_head_key(head.holder_authority_id, head.provider_authority_id),
        vec![0; MAXIMUM_VALUE_BYTES],
    );
    let completion = JournalTransaction::new(
        provider_head_capacity_transaction_id(head),
        vec![maximum_head],
    )?;
    journal.preflight_transactions(&[reservation.clone(), completion])?;
    Ok(())
}

fn truncate_digest(digest: [u8; 32]) -> [u8; 16] {
    let mut value = [0; 16];
    value.copy_from_slice(&digest[..16]);
    value
}

fn next_revision(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| state_error("source acquisition generation overflowed"))
}

fn next_inventory_observation_ordinal(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| state_error("provider Inventory observation ordinal overflowed"))
}

fn nonzero_digest(value: [u8; 32]) -> bool {
    value != [0; 32]
}

fn valid_operation(value: SourceAcquisitionOperationV1) -> bool {
    value.operation_id != [0; 16] && value.request_digest != [0; 32]
}

fn valid_assignment(value: SourceAcquisitionAssignmentV1) -> bool {
    value.sandbox_id != [0; 16]
        && value.incarnation_id != [0; 16]
        && value.assignment_epoch != 0
        && value.desired_generation != 0
        && value.assignment_digest != [0; 32]
        && value.namespace_generation != 0
}

fn valid_provider_context(value: SourceProviderContextSnapshotV1) -> bool {
    value.holder_authority_id != [0; 16]
        && value.holder_generation != 0
        && value.holder_authority_digest != [0; 32]
        && value.node_id != [0; 16]
        && value.kernel_boot_id != [0; 16]
        && value.revocation_digest != [0; 32]
        && value.provider_route_id != [0; 16]
        && value.provider_route_generation != 0
        && value.provider_route_digest != [0; 32]
        && value.provider_authority_id != [0; 16]
        && value.provider_authority_generation != 0
        && value.provider_authority_digest != [0; 32]
        && value.provider_key_id != [0; 16]
        && value.provider_key_generation != 0
        && value.provider_public_key_digest != [0; 32]
        && value.resource_namespace_digest != [0; 32]
        && value.session_binding != [0; 32]
}

fn pristine_provider_head(head: &SourceProviderHeadV1) -> bool {
    head.next_request_sequence == 1
        && head.next_response_sequence == 1
        && head.inventory_observation_ordinal == 0
        && head.pending_query.is_none()
        && head.inventory_generation.is_none()
        && head.inventory_digest.is_none()
        && head.signed_inventory_digest.is_none()
        && head.signed_inventory.is_empty()
        && head.catalog_generation.is_none()
        && head.catalog_digest.is_none()
        && head.last_inventory_checkpoint.is_none()
        && !head.has_untracked_inventory_residuals
        && !head.has_inventory_authority_conflicts
}

fn provider_session_replacement_is_monotonic(
    current: &SourceProviderHeadV1,
    next: &SourceProviderHeadV1,
) -> bool {
    next.holder_generation >= current.holder_generation
        && (next.holder_generation != current.holder_generation
            || next.holder_authority_digest == current.holder_authority_digest)
        && next.provider_authority_generation >= current.provider_authority_generation
        && (next.provider_authority_generation != current.provider_authority_generation
            || next.provider_authority_digest == current.provider_authority_digest)
        && next.route_id == current.route_id
        && next.resource_namespace_digest == current.resource_namespace_digest
        && next.route_generation >= current.route_generation
        && (next.route_generation != current.route_generation
            || next.route_digest == current.route_digest)
        && next.provider_key_generation >= current.provider_key_generation
        && (next.provider_key_generation != current.provider_key_generation
            || next.provider_key_id == current.provider_key_id
                && next.provider_public_key_digest == current.provider_public_key_digest)
}

fn valid_evidence(value: &SourceAcquisitionEvidenceV1) -> bool {
    value.provider_resource_id != [0; 32]
        && value.provider_resource_generation != 0
        && value.provider_resource_digest != [0; 32]
        && value.provider_catalog_generation != 0
        && value.provider_catalog_digest != [0; 32]
        && value.provider_selection_generation != 0
        && value.provider_selection_digest != [0; 32]
        && value.provider_proof_digest != [0; 32]
        && value.lease_id != [0; 16]
        && value.signed_lease_digest != [0; 32]
        && value.lease_expires_seconds > value.lease_issued_seconds
        && value.source_realization_handle != [0; 32]
        && value.source_physical_proof_digest != [0; 32]
        && value.source_kernel_boot_id != [0; 16]
        && value.source_device != 0
        && value.source_inode != 0
        && value.source_unique_mount_id != 0
        && value.descriptor_commitment != [0; 32]
}

fn operation_id_is_used(
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    operation_id: [u8; 16],
) -> bool {
    rows.values()
        .any(|row| operation_id_matches_row(row.acquire.operation_id, row.release, operation_id))
}

fn release_authority(
    request: &ValidatedReleaseMountSourceAcquisitionRequest,
) -> SourceAcquisitionReleaseAuthorityV1 {
    SourceAcquisitionReleaseAuthorityV1 {
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
        expected_revision: request.expected_revision(),
        expected_record_digest: *request.expected_record_digest().as_bytes(),
    }
}

fn release_authority_dominates(
    acquire: SourceAcquisitionAssignmentV1,
    release: SourceAcquisitionReleaseAuthorityV1,
) -> bool {
    release.sandbox_id == acquire.sandbox_id
        && release.incarnation_id == acquire.incarnation_id
        && (release.assignment_epoch > acquire.assignment_epoch
            || release.assignment_epoch == acquire.assignment_epoch
                && (release.desired_generation > acquire.desired_generation
                    || release.desired_generation == acquire.desired_generation
                        && release.assignment_digest == acquire.assignment_digest))
}

fn operation_id_matches_row(
    acquire_operation_id: [u8; 16],
    release: Option<SourceAcquisitionOperationV1>,
    candidate: [u8; 16],
) -> bool {
    acquire_operation_id == candidate
        || match release {
            Some(release) => release.operation_id == candidate,
            None => false,
        }
}

fn validate_provider_acquire_query(row: &SourceAcquisitionRowV1) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&row.provider_acquire_request)
        .map_err(|error| state_error(error.to_string()))?;
    if signed.method() != SourceProviderMethod::Acquire {
        return Err(state_error("durable provider query is not Acquire"));
    }
    let query =
        decode_acquire_request(signed.subject()).map_err(|error| state_error(error.to_string()))?;
    let mount = decode_historical_acquire_mount_source_request(&row.mount_acquire_request)
        .map_err(|error| state_error(error.to_string()))?;
    let recursive = prospective_template_recursive(&row.prospective_mount_template)?;
    if mount.header().request_id() != &row.acquire.operation_id
        || mount.fence().sandbox_id() != &row.assignment.sandbox_id
        || mount.fence().incarnation_id() != &row.assignment.incarnation_id
        || mount.fence().assignment_epoch() != row.assignment.assignment_epoch
        || mount.fence().desired_generation() != row.assignment.desired_generation
        || mount.fence().assignment_digest() != &row.assignment.assignment_digest
        || mount.prospective_mount_template() != row.prospective_mount_template
        || mount.prospective_mount_template_digest().as_bytes()
            != &row.prospective_mount_template_digest
        || mount.source_binding().canonical_bytes() != row.source_binding
        || mount.source_binding().digest().as_bytes() != &row.source_binding_digest
        || prospective_template_u64_field(&row.prospective_mount_template, 12)?
            != row.assignment.namespace_generation
        || mount.requested_lease_seconds() != query.requested_lease_seconds()
        || mount.requested_maximum_submounts() != query.requested_maximum_submounts()
        || mount.kernel_coupled() != query.kernel_coupled()
        || query.acquisition_id().as_bytes() != &row.acquisition_id
        || query.prospective_apply_template() != row.prospective_mount_template
        || query.prospective_apply_template_digest().as_bytes()
            != &row.prospective_mount_template_digest
        || query.binding() != row.source_binding
        || query.binding_digest().as_bytes() != &row.source_binding_digest
        || query.node_id() != row.provider.node_id
        || query.boot_id() != row.provider.kernel_boot_id
        || query.holder_authority_id() != row.provider.holder_authority_id
        || query.holder_generation() != row.provider.holder_generation
        || query.holder_authority_digest().as_bytes() != &row.provider.holder_authority_digest
        || query.session_binding().as_bytes() != &row.provider.session_binding
        || query.revocation_digest().as_bytes() != &row.provider.revocation_digest
        || query.requested_lease_seconds() != mount.requested_lease_seconds()
        || query.requested_maximum_submounts() != mount.requested_maximum_submounts()
        || query.kernel_coupled() != mount.kernel_coupled()
        || query.recursive() != recursive
    {
        return Err(state_error(
            "durable provider Acquire query does not reproduce Mount authority",
        ));
    }
    Ok(())
}

fn prospective_template_recursive(bytes: &[u8]) -> Result<bool> {
    let mut cursor = 0usize;
    for expected_tag in 1_u8..=15 {
        if bytes.get(cursor).copied() != Some(expected_tag) {
            return Err(state_error("prospective Mount template tags are not exact"));
        }
        let length_bytes = bytes
            .get(cursor + 1..cursor + 5)
            .ok_or_else(|| state_error("prospective Mount template is truncated"))?;
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes.try_into().map_err(
                |_| state_error("prospective Mount template length is invalid"),
            )?))
            .map_err(|_| state_error("prospective Mount template length overflowed"))?;
        cursor = cursor
            .checked_add(5)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| state_error("prospective Mount template length overflowed"))?;
        if expected_tag == 15 {
            let attributes = bytes
                .get(cursor - length..cursor)
                .ok_or_else(|| state_error("prospective Mount attributes are truncated"))?;
            return attributes
                .get(5)
                .copied()
                .map(|recursive| recursive == 1)
                .ok_or_else(|| state_error("prospective Mount attributes are absent"));
        }
    }
    Err(state_error("prospective Mount attributes are absent"))
}

fn prospective_template_u64_field(bytes: &[u8], requested_tag: u8) -> Result<u64> {
    let mut cursor = 0usize;
    for expected_tag in 1_u8..=27 {
        if bytes.get(cursor).copied() != Some(expected_tag) {
            return Err(state_error("prospective Mount template tags are not exact"));
        }
        let length_bytes = bytes
            .get(cursor + 1..cursor + 5)
            .ok_or_else(|| state_error("prospective Mount template is truncated"))?;
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes.try_into().map_err(
                |_| state_error("prospective Mount template length is invalid"),
            )?))
            .map_err(|_| state_error("prospective Mount template length overflowed"))?;
        let value_start = cursor
            .checked_add(5)
            .ok_or_else(|| state_error("prospective Mount template length overflowed"))?;
        let value_end = value_start
            .checked_add(length)
            .ok_or_else(|| state_error("prospective Mount template length overflowed"))?;
        let value = bytes
            .get(value_start..value_end)
            .ok_or_else(|| state_error("prospective Mount template is truncated"))?;
        if expected_tag == requested_tag {
            return value
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| state_error("prospective Mount generation is malformed"));
        }
        cursor = value_end;
    }
    Err(state_error("prospective Mount generation is absent"))
}

fn valid_signed_request(bytes: &[u8], digest: [u8; 32]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= MAXIMUM_SIGNED_PROVIDER_BYTES
        && digest != [0; 32]
        && Sha256::digest(bytes).as_slice() == digest
}

fn valid_optional_signed_request(bytes: Option<&[u8]>, digest: Option<[u8; 32]>) -> bool {
    bytes
        .zip(digest)
        .is_some_and(|(bytes, digest)| valid_signed_request(bytes, digest))
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}
