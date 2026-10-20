//! Authenticates exact restoration input custody before a separate keyed commit.
//!
//! Two distinct SDK-assigned Begin/PrepareRestore originals share one transaction.
//! Prepare authorizes only precharged banks for the exact signed references.
//! Commit consumes that same lease after full hashes and typed decoding succeed.
//! Generic Blob limits, chunk semantics and scenario Admit remain unchanged.
//!
//! ```text
//! prepare/12 + proof -> exact input banks; baseline Blob chunks fill them
//! commit/12 + proof -> same one-shot lease installation; completed receipt
//! ```

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::{
    PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE,
    PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
    PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,
    PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
    PacketCompleteRestoreTransferPhase,
};

use super::*;
use crate::envelope::Envelope;

mod assigned;
pub(crate) use assigned::authenticate_fresh_prepare_shape;
mod contract;
mod crypto;
mod owner_state;
pub use assigned::{
    complete_restore_fresh_prepare_assigned_request_digest,
    complete_restore_fresh_prepare_assigned_response_digest,
    complete_restore_fresh_prepare_digest_counter_scratch_data,
    complete_restore_transfer_assigned_request_digest,
    complete_restore_transfer_assigned_response_digest, complete_restore_transfer_original_digest,
};
pub use contract::{
    PacketCompleteRestoreTransferSchema, complete_restore_transfer_contract,
    complete_restore_transfer_schema,
};
pub use crypto::*;
pub use owner_state::{
    PacketCompleteRestoreModelOutputPopulationData, PacketCompleteRestoreOwnerProjection,
    PacketCompleteRestoreOwnerStateData, PacketCompleteRestoreOwnerValidationStorage,
    PacketCompleteRestoreSelectedOwnerInputs, authenticate_complete_restore_owner_state_data,
    complete_restore_invocation_owner_construction_storage_data,
    complete_restore_owner_validation_storage_data,
    complete_restore_selected_model_output_population_counter_scratch_data,
    complete_restore_selected_model_output_population_data,
    complete_restore_selected_owner_construction_counter_scratch_data,
    complete_restore_selected_owner_construction_storage_data,
};
pub(crate) use owner_state::{
    selected_issuer_decode_counter_scratch_data, selected_issuer_decode_storage_data,
    selected_native_dto_decode_storage_data, selected_value_decode_storage_data,
};

/// Binds a separately source-admitted finite native reconstruction plan.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreInputAllocation {
    /// Bounds the simultaneous raw inputs, typed owners, lookup and scratch total.
    pub maximum_known_requested_bytes: U64,
    /// Bounds complete native encoded input.
    pub maximum_input_bytes: U64,
    /// Bounds native JSON traversal work.
    pub maximum_nodes: U64,
    /// Bounds native grammar nesting, at most 64.
    pub maximum_depth: U64,
    /// Bounds recorded String and Vec backing.
    pub maximum_owned_backing_bytes: U64,
    /// Bounds all native initialized tree entries.
    pub maximum_tree_entries: U64,
    /// Bounds independent restore capacity and alias rows, not capture banks.
    pub maximum_metadata_rows: U64,
    /// Bounds independent reconstructed native literal banks.
    pub maximum_literal_backing_bytes: U64,
    /// Bounds historical content transfer entries.
    pub maximum_content_transfers: U64,
    /// Bounds historical verified content object entries.
    pub maximum_content_objects: U64,
    /// Bounds historical independent byte alias groups.
    pub maximum_content_groups: U64,
    /// Bounds historical content byte backing.
    pub maximum_content_bytes: U64,
    /// Bounds historical content key and reference backing.
    pub maximum_content_metadata_bytes: U64,
    /// Bounds the separately reconstructed model and Control data.
    pub maximum_model_bytes: U64,
}

/// Binds exact inputs before any larger Blob is accepted.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestorePrepareRequest {
    /// Names the exact prepare grammar.
    pub schema: String,
    /// Binds the complete signed archive and fresh target.
    pub restoration: PacketCompleteRestoreRequest,
    /// Binds the host body named by the canonical mapping; it remains host-side.
    pub host_protocol: ContentRef,
    /// Names the complete native historical body to receive.
    pub native_protocol: ContentRef,
    /// Names the exact pending Control/model body to receive.
    pub native_control: ContentRef,
    /// Names the exact unchanged-cut anchor to receive.
    pub native_anchor: ContentRef,
    /// Names the one transaction shared by distinct prepare and commit requests.
    pub transaction_id: Id,
    /// Names its positive original source-born lease generation.
    pub generation: U64,
    /// Binds separate source-authenticated native restore memory and work limits.
    pub allocation: PacketCompleteRestoreInputAllocation,
}

/// Binds the actual peer and full request without requiring unreceived bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestorePrepareContext {
    /// Names the exact prepare context.
    pub schema: String,
    /// Names the exact keyed construction.
    pub algorithm: String,
    /// Binds the actual original source birth.
    pub source_birth: Bytes,
    /// Binds both actual kernel and measured executable roles.
    pub kernel_binding: Bytes,
    /// Binds the full selected policy/backend tuple.
    pub policy_binding: Bytes,
    /// Binds the actual host registration.
    pub host_registration: Bytes,
    /// Binds the actual native registration.
    pub native_registration: Bytes,
    /// Binds the full literal original Hello request.
    pub hello_request: Bytes,
    /// Binds the full literal original Hello response.
    pub hello_response: Bytes,
    /// Binds the exact assigned prepare envelope with only its proof removed.
    pub assigned_prepare: Bytes,
    /// Binds the entire canonical prepare extension.
    pub prepare_request: Bytes,
    /// Binds exact full input references, lengths, allocation, nonce and generation.
    pub input_roster: Bytes,
}

/// Carries inert MAC data for one exact phase.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreTransferProof {
    /// Names the exact phase proof grammar.
    pub schema: String,
    /// Names the exact keyed construction.
    pub algorithm: String,
    /// Hashes the complete canonical phase context.
    pub context_digest: Bytes,
    /// Contains the 32-byte phase-specific keyed output.
    pub mac: Bytes,
}

/// Retains an actual input lease without certifying installation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestorePrepareReceipt {
    /// Names the prepare receipt grammar.
    pub schema: String,
    /// Names the exact keyed construction.
    pub algorithm: String,
    /// Hashes the canonical prepare extension.
    pub prepare_digest: Bytes,
    /// Hashes its complete phase context.
    pub context_digest: Bytes,
    /// Binds all exact input references and allocation limits.
    pub input_roster: Bytes,
    /// Names the actual one-shot native lease, 32 bytes.
    pub transfer_token: Bytes,
    /// Retains the source-born lease generation.
    pub generation: U64,
    /// Retains the actual assigned native response sequence.
    pub native_sequence: U64,
    /// Hashes the actual response with only this receipt removed.
    pub assigned_response: Bytes,
    /// Contains the separately domain-separated prepare receipt MAC.
    pub mac: Bytes,
}

/// Commits the same prepared lease after exact body verification.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreCommitRequest {
    /// Names the exact commit grammar.
    pub schema: String,
    /// Retains the complete original prepare data unchanged.
    pub prepare: PacketCompleteRestorePrepareRequest,
    /// Retains the actual completed Capture envelope authenticated by the journal.
    pub capture_terminal: Envelope,
    /// Names the actual original prepare request.
    pub prepare_request_id: Id,
    /// Retains its actual assigned controller sequence.
    pub prepare_request_sequence: U64,
    /// Hashes its full actual envelope including its proof.
    pub prepare_request_digest: Bytes,
    /// Retains the actual native prepare response sequence.
    pub prepare_response_sequence: U64,
    /// Hashes its full actual envelope including its receipt.
    pub prepare_response_digest: Bytes,
    /// Binds the exact prepared native lease.
    pub transfer_token: Bytes,
}

/// Binds full mapping bytes and exact original prepared custody.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreCommitContext {
    /// Names the exact commit context.
    pub schema: String,
    /// Names the exact keyed construction.
    pub algorithm: String,
    /// Retains all twelve full restoration bindings after receipt of inputs.
    pub restoration: PacketCompleteRestoreContext,
    /// Hashes the canonical commit extension.
    pub commit_request: Bytes,
    /// Hashes the full original prepare including proof.
    pub prepare_request: Bytes,
    /// Hashes the full original prepare response including receipt.
    pub prepare_response: Bytes,
    /// Binds the actual prepared native lease.
    pub transfer_token: Bytes,
    /// Binds all exact full-reference inputs and allocation limits.
    pub input_roster: Bytes,
}

/// Retains only a completed same-lease installation receipt.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreCommitReceipt {
    /// Names the exact commit receipt grammar.
    pub schema: String,
    /// Names the exact keyed construction.
    pub algorithm: String,
    /// Hashes the entire canonical commit request.
    pub commit_digest: Bytes,
    /// Hashes the complete commit context.
    pub context_digest: Bytes,
    /// Names the exact consumed mapping.
    pub installed_mapping: ContentRef,
    /// Binds the same original prepared native lease.
    pub transfer_token: Bytes,
    /// Retains the actual assigned native response sequence.
    pub native_sequence: U64,
    /// Hashes that actual response with only this receipt removed.
    pub assigned_response: Bytes,
    /// Contains the separately domain-separated commit receipt MAC.
    pub mac: Bytes,
}

impl PacketCompleteRestoreInputAllocation {
    /// Checks finite selected limits without admitting any allocation.
    ///
    /// # Errors
    /// Refuses zero or excessive limits and an inconsistent aggregate byte bound.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        const MAXIMUM: u64 = 512 * 1024 * 1024;
        let total = self.maximum_known_requested_bytes.get();
        if total == 0
            || total > MAXIMUM
            || self.maximum_depth.get() == 0
            || self.maximum_depth.get() > 64
            || self.maximum_metadata_rows.get() == 0
            || self.maximum_metadata_rows.get() > 131072
        {
            return Err(ProviderError::ResourceExhausted(
                "restore transfer allocation limits",
            ));
        }
        for limit in [
            self.maximum_input_bytes,
            self.maximum_owned_backing_bytes,
            self.maximum_literal_backing_bytes,
            self.maximum_content_bytes,
            self.maximum_content_metadata_bytes,
            self.maximum_model_bytes,
        ] {
            if limit.get() == 0 || limit.get() > total {
                return Err(ProviderError::ResourceExhausted(
                    "restore transfer byte limit",
                ));
            }
        }
        for limit in [
            self.maximum_nodes,
            self.maximum_tree_entries,
            self.maximum_content_transfers,
            self.maximum_content_objects,
            self.maximum_content_groups,
        ] {
            if limit.get() == 0 || limit.get() > MAXIMUM {
                return Err(ProviderError::ResourceExhausted(
                    "restore transfer work limit",
                ));
            }
        }
        Ok(())
    }
}

impl PacketCompleteRestorePrepareRequest {
    /// Checks the exact finite prepare grammar without issuing an input lease.
    ///
    /// # Errors
    /// Refuses invalid restoration data, references, allocation bounds or extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION || self.generation.get() == 0 {
            return Err(ProviderError::Correlation("restore prepare grammar"));
        }
        self.restoration.validate_data()?;
        self.transaction_id.validate()?;
        self.allocation.validate_data()?;
        for reference in [
            &self.host_protocol,
            &self.native_protocol,
            &self.native_control,
            &self.native_anchor,
        ] {
            reference.validate()?;
        }
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
        Ok(())
    }

    /// Hashes the exact full references and independently selected allocation plan.
    ///
    /// The input lease must independently retain and authenticate this entire
    /// request. This digest grants no permission to allocate or accept a Blob.
    ///
    /// # Errors
    /// Refuses invalid data or canonical encoding failure.
    pub fn input_roster_digest_data(&self) -> Result<Bytes, ProviderError> {
        self.validate_data()?;
        let roster = (
            "source-owned.packet-complete-restore-input-roster/12",
            &self.host_protocol,
            &self.native_protocol,
            &self.native_control,
            &self.native_anchor,
            &self.restoration.owner_state,
            &self.restoration.journal,
            &self.restoration.mapping,
            &self.restoration.nonce,
            &self.transaction_id,
            self.generation,
            &self.allocation,
        );
        Ok(digest(&bounded_canonical(
            &roster,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?))
    }
}

impl PacketCompleteRestorePrepareContext {
    /// Checks every fixed-width binding in the independently derived context.
    ///
    /// # Errors
    /// Refuses another grammar, algorithm, digest width or canonical extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-complete-restore-prepare-context/12"
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(ProviderError::Correlation(
                "restore prepare context grammar",
            ));
        }
        digest_lengths(&[
            &self.source_birth,
            &self.kernel_binding,
            &self.policy_binding,
            &self.host_registration,
            &self.native_registration,
            &self.hello_request,
            &self.hello_response,
            &self.assigned_prepare,
            &self.prepare_request,
            &self.input_roster,
        ])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
        Ok(())
    }

    /// Checks the request and input roster projections, without requiring bodies.
    ///
    /// # Errors
    /// Refuses changed request data or any changed full input reference or plan.
    pub fn authenticate_request_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        request.validate_data()?;
        same_digest(
            &self.prepare_request,
            &digest(&bounded_canonical(
                request,
                MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
            )?),
        )?;
        same_digest(&self.input_roster, &request.input_roster_digest_data()?)
    }
}

impl PacketCompleteRestoreCommitRequest {
    /// Checks the original prepare identity and same-lease commit grammar.
    ///
    /// # Errors
    /// Refuses invalid prepare data, missing assigned sequences or digest widths.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION
            || self.prepare_request_sequence.get() == 0
            || self.prepare_response_sequence.get() == 0
        {
            return Err(ProviderError::Correlation("restore commit grammar"));
        }
        self.prepare.validate_data()?;
        self.capture_terminal.validate()?;
        self.prepare_request_id.validate()?;
        digest_lengths(&[
            &self.prepare_request_digest,
            &self.prepare_response_digest,
            &self.transfer_token,
        ])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
        Ok(())
    }
}

impl PacketCompleteRestoreCommitContext {
    /// Checks the complete post-transport context grammar and digest widths.
    ///
    /// # Errors
    /// Refuses another grammar, invalid inner bindings or excessive extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-complete-restore-commit-context/12"
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(ProviderError::Correlation("restore commit context grammar"));
        }
        self.restoration.validate_data()?;
        digest_lengths(&[
            &self.commit_request,
            &self.prepare_request,
            &self.prepare_response,
            &self.transfer_token,
            &self.input_roster,
        ])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
        Ok(())
    }

    /// Checks exact mapping bytes and the entire retained original prepare chain.
    ///
    /// The issuer additionally compares both full original envelopes, their
    /// actual assigned sequences and its private one-shot lease owner.
    ///
    /// # Errors
    /// Refuses changed archive, target, mapping, lease, request or prepare chain.
    pub fn authenticate_request_data(
        &self,
        request: &PacketCompleteRestoreCommitRequest,
        canonical_mapping: &[u8],
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        request.validate_data()?;
        self.restoration
            .authenticate_request_bindings_data(&request.prepare.restoration, canonical_mapping)?;
        same_digest(
            &self.commit_request,
            &digest(&bounded_canonical(
                request,
                MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
            )?),
        )?;
        for (actual, expected) in [
            (&self.prepare_request, &request.prepare_request_digest),
            (&self.prepare_response, &request.prepare_response_digest),
            (&self.transfer_token, &request.transfer_token),
        ] {
            same_digest(actual, expected)?;
        }
        same_digest(
            &self.input_roster,
            &request.prepare.input_roster_digest_data()?,
        )
    }
}

impl PacketCompleteRestoreTransferProof {
    /// Checks a proof under one exact, separately registered phase grammar.
    ///
    /// # Errors
    /// Refuses a foreign phase, algorithm, truncated digest or excessive extent.
    pub fn validate_data(
        &self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<(), ProviderError> {
        if self.schema != phase.proof_extension()
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(ProviderError::Correlation("restore transfer proof grammar"));
        }
        digest_lengths(&[&self.context_digest, &self.mac])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
        Ok(())
    }
}

impl PacketCompleteRestorePrepareReceipt {
    /// Checks an input-lease receipt without certifying installation.
    ///
    /// # Errors
    /// Refuses a foreign grammar, zero sequence or generation, or invalid digest.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || self.generation.get() == 0
            || self.native_sequence.get() == 0
        {
            return Err(ProviderError::Correlation(
                "restore prepare receipt grammar",
            ));
        }
        digest_lengths(&[
            &self.prepare_digest,
            &self.context_digest,
            &self.input_roster,
            &self.transfer_token,
            &self.assigned_response,
            &self.mac,
        ])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
        Ok(())
    }
}

impl PacketCompleteRestoreCommitReceipt {
    /// Checks completed receipt data without issuing installation authority.
    ///
    /// # Errors
    /// Refuses invalid grammar, sequence, mapping reference or digest widths.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || self.native_sequence.get() == 0
        {
            return Err(ProviderError::Correlation("restore commit receipt grammar"));
        }
        self.installed_mapping.validate()?;
        digest_lengths(&[
            &self.commit_digest,
            &self.context_digest,
            &self.transfer_token,
            &self.assigned_response,
            &self.mac,
        ])?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
        Ok(())
    }
}

fn digest_lengths(values: &[&Bytes]) -> Result<(), ProviderError> {
    if values.iter().any(|value| value.as_slice().len() != 32) {
        return Err(ProviderError::Correlation("restore transfer digest length"));
    }
    Ok(())
}

fn same_digest(actual: &Bytes, expected: &Bytes) -> Result<(), ProviderError> {
    let expected: [u8; 32] = expected
        .as_slice()
        .try_into()
        .map_err(|_| ProviderError::Correlation("restore transfer expected digest length"))?;
    if blake3::Hash::from_bytes(expected) != *actual.as_slice() {
        return Err(ProviderError::Correlation(
            "restore transfer digest correspondence",
        ));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed protocol data controls panic on fixture failures.
#[allow(clippy::unwrap_used)]
mod tests;

pub(crate) use contract::complete_restore_transfer_contract_storage_data;

pub(crate) use owner_state::{
    authenticate_selected_owner_state_data, selected_owner_counter_scratch_data,
    selected_owner_validation_storage_data,
};
