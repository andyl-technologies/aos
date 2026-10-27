//! Lends the genuine once-Admit frontier and sole fresh query without copies.
//!
//! The native token owns its original incoming Admit. The endpoint already owns
//! its actual response-only sent record. Physical adjacency in their SAME bank
//! and the sole current query guard exclude intervening control originals.
//! Canonical correspondence permits role hashing directly from immutable banks;
//! neither decoded labels nor equal hashes construct a completed native owner.

use super::*;
use crate::connection::{ExchangeRecord, OriginalSentFrameView};
use crate::reference_packet::service::fresh_restore_allocation::{
    PacketNative5FreshRestoreAllocationSelection, PacketNativeFreshRestoreOriginalRole as Role,
};
use crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose;
use std::cell::Ref;

pub(crate) struct OriginalNativeFreshFrontierData<'a> {
    actor: &'a crate::protocol_snapshot::ProtocolCaptureOwner,
    authority: &'a ConnectionAuthority,
    query: Ref<'a, [u8]>,
    admit: Ref<'a, [u8]>,
    response: OriginalSentFrameView<'a>,
}

impl OriginalNativeFreshFrontierData<'_> {
    fn ensure_current(&self) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()
    }

    pub(crate) fn authenticate_current_data(&self) -> Result<(), ProviderError> {
        self.ensure_current()
    }

    fn hash(&self, role: Role, bytes: &[u8]) -> Result<[u8; 32], ProviderError> {
        self.ensure_current()?;
        let result = role.verified_canonical_body_digest(bytes);
        self.ensure_current()?;
        Ok(result)
    }

    /// Compares the query owner with this purpose's immutable private source bank.
    ///
    /// The private startup scope supplies its SAME authenticated canonical bank
    /// and typed source value. The result is data correspondence, not a grant.
    pub(crate) fn authenticate_owner_binding_data(
        &self,
        source: &serde_json::Value,
        canonical_source: &[u8],
        query: &Envelope,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        authenticate_source_owner_binding_data(source, canonical_source, query)?;
        self.ensure_current()
    }

    pub(crate) fn assigned_query_digest_data(&self) -> Result<[u8; 32], ProviderError> {
        self.hash(Role::Query, &self.query)
    }

    pub(crate) fn completed_admit_request_digest_data(&self) -> Result<[u8; 32], ProviderError> {
        self.hash(Role::AdmitRequest, &self.admit)
    }

    pub(crate) fn completed_admit_response_digest_data(&self) -> Result<[u8; 32], ProviderError> {
        self.hash(Role::AdmitResponse, self.response.canonical_body())
    }

    pub(crate) fn admission_id_data(&self) -> Result<&str, ProviderError> {
        self.ensure_current()?;
        self.response
            .original()
            .body
            .get("result")
            .and_then(serde_json::Value::as_object)
            .and_then(|result| result.get("admission_id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(refused)
    }
}

impl OriginalNativeAckConnectionIdentity {
    /// Authenticates the real adjacent completed Admit and sole fresh query.
    ///
    /// This returns only immutable data loans. Actual fresh purpose/private
    /// nonce, baseline/publication grants and closed Control currency remain
    /// conjuncts of the private native caller.
    ///
    /// # Errors
    /// Refuses another actor/selection, malformed or unfinished sent records,
    /// noncanonical originals, intervening frames, stale scopes or a bank loan.
    pub(crate) fn original_fresh_completed_admit_data<'a, S: ProviderStream>(
        &'a self,
        connection: &'a Connection<S>,
        admit_original: &Envelope,
        query: &Envelope,
        first_response: u64,
        record: &'a ExchangeRecord,
    ) -> Result<OriginalNativeFreshFrontierData<'a>, ProviderError> {
        self.authenticate_current(connection)?;
        if self.policy.fresh_restore_allocation_selection()
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || record.originals().len() != 1
            || record.sent() != 1
            || !record.acknowledgements().is_empty()
            || admit_original.method != Method::Admit
            || admit_original.message != MessageKind::Request
            || admit_original.sequence.get().checked_add(1) != Some(query.sequence.get())
        {
            return Err(refused());
        }
        self.policy.authenticate_original_report_query_header_data(
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            query,
        )?;
        let response = record.original_sent_frame(connection, 0)?;
        admit_original.matches_response(response.original())?;
        authenticate_response_data(response.original())?;
        if response.original().sequence.get().checked_add(1) != Some(first_response) {
            return Err(refused());
        }
        let response_slot = self.literal_index.checked_add(1).ok_or_else(refused)?;
        let query_slot = response_slot.checked_add(1).ok_or_else(refused)?;
        if connection.reader.original_slot() != Some(query_slot) {
            return Err(refused());
        }
        let bank = self.frames.try_borrow().map_err(|_| refused())?;
        if bank.frames().count() != query_slot.checked_add(1).ok_or_else(refused)?
            || !std::ptr::eq(
                bank.frame(response_slot).ok_or_else(refused)?.bytes,
                response.literal().bytes,
            )
        {
            return Err(refused());
        }
        let request = bank.frame(self.literal_index).ok_or_else(refused)?;
        authenticate_request_literal_data(admit_original, request.bytes)?;
        authenticate_binding_result_data(admit_original, &request.bytes[4..], response.original())?;
        let admit = Ref::filter_map(bank, |bank| {
            bank.frame(self.literal_index)
                .and_then(|frame| frame.bytes.get(4..))
        })
        .map_err(|_| refused())?;
        let query = connection.original_report_query_body_data(query, first_response)?;
        self.authenticate_current(connection)?;
        Ok(OriginalNativeFreshFrontierData {
            actor: self.actor.as_ref(),
            authority: &connection.authority,
            query,
            admit,
            response,
        })
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Names the real immutable loan, bank views and role-hashing workspace.
    pub(crate) const fn original_fresh_frontier_counter_scratch_data() -> usize {
        crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
            + std::mem::size_of::<OriginalNativeFreshFrontierData<'static>>()
            + 4 * std::mem::size_of::<Ref<'static, OriginalFrameReservation>>()
            + std::mem::size_of::<OriginalSentFrameView<'static>>()
            + 2 * std::mem::size_of::<blake3::Hasher>()
            + 3 * std::mem::size_of::<blake3::Hash>()
            + std::mem::size_of::<[[u8; 32]; 3]>()
            // Hash::to_hex is the pinned64-byte ArrayString plus its length.
            + std::mem::size_of::<[u8;64]>()
            + std::mem::size_of::<usize>()
            + std::mem::size_of::<[u8; 4]>()
            + 5 * std::mem::size_of::<usize>()
    }
}

fn authenticate_request_literal_data(
    original: &Envelope,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    let header: [u8; 4] = bytes
        .get(..4)
        .ok_or_else(refused)?
        .try_into()
        .map_err(|_| refused())?;
    if usize::try_from(u32::from_be_bytes(header)).ok() != bytes.len().checked_sub(4) {
        return Err(refused());
    }
    crate::protocol_snapshot::owned11::correspondence::envelope(original, &bytes[4..])
}

/// Compares the actual accepted identity with the already verified Admit bytes.
///
/// The original native verifier authenticated these complete bindings against
/// its installed launch before issuing the token. Full canonical correspondence
/// precedes this call, so slicing the one-element array yields exactly the same
/// complete binding. NodeBinding::identity delegates specifically to its
/// compatibility child; authority and wrapper extensions remain inside the full
/// Admit role commitment but are excluded from durable compatibility identity.
fn authenticate_binding_result_data(
    admit: &Envelope,
    canonical_body: &[u8],
    response: &Envelope,
) -> Result<(), ProviderError> {
    if admit
        .body
        .get("bindings")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|bindings| bindings.len() != 1)
    {
        return Err(refused());
    }
    let body = super::super::restore_held_proof::borrowed_field(canonical_body, "body")?;
    let bindings = super::super::restore_held_proof::borrowed_field(body, "bindings")?;
    let payload = bindings
        .strip_prefix(b"[")
        .and_then(|b| b.strip_suffix(b"]"))
        .filter(|b| !b.is_empty())
        .ok_or_else(refused)?;
    let payload = super::super::restore_held_proof::borrowed_field(payload, "compatibility")?;
    let domain = "cnp.node-binding.v1";
    let domain_length = u32::try_from(domain.len()).map_err(|_| refused())?;
    let payload_length = u64::try_from(payload.len()).map_err(|_| refused())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&domain_length.to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&payload_length.to_be_bytes());
    hasher.update(payload);
    let digest = hasher.finalize().to_hex();
    let actual = response
        .body
        .get("result")
        .and_then(|v| v.get("accepted_binding_hashes"))
        .and_then(serde_json::Value::as_array)
        .and_then(|hashes| hashes.first())
        .ok_or_else(refused)?;
    super::super::complete_restore_projection::hash(actual, Some(domain))?;
    if actual.get("digest").and_then(serde_json::Value::as_str) != Some(digest.as_str()) {
        return Err(refused());
    }
    Ok(())
}

/// Hashes the complete owner object from a canonical private source bank.
///
/// Boot construction compared the full source selection with its actual launch,
/// then canonicalized this immutable source value once. The startup scope checks
/// that SAME bank's origin and saved digest before and after this call. Unlike
/// NodeBinding compatibility, OwnerBinding identity includes every object field.
fn authenticate_source_owner_binding_data(
    source: &serde_json::Value,
    canonical_source: &[u8],
    query: &Envelope,
) -> Result<(), ProviderError> {
    let owners = source
        .get("selection")
        .and_then(|value| value.get("realization"))
        .and_then(|value| value.get("owner_bindings"))
        .and_then(serde_json::Value::as_array)
        .filter(|owners| owners.len() == 1)
        .ok_or_else(refused)?;
    if !owners[0].is_object() {
        return Err(refused());
    }
    let selection =
        super::super::restore_held_proof::borrowed_field(canonical_source, "selection")?;
    let realization = super::super::restore_held_proof::borrowed_field(selection, "realization")?;
    let owners = super::super::restore_held_proof::borrowed_field(realization, "owner_bindings")?;
    let owner = owners
        .strip_prefix(b"[")
        .and_then(|bytes| bytes.strip_suffix(b"]"))
        .filter(|bytes| bytes.starts_with(b"{") && bytes.ends_with(b"}"))
        .ok_or_else(refused)?;
    let domain = "cnp.owner-binding.v1";
    let domain_length = u32::try_from(domain.len()).map_err(|_| refused())?;
    let owner_length = u64::try_from(owner.len()).map_err(|_| refused())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&domain_length.to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&owner_length.to_be_bytes());
    hasher.update(owner);
    let digest = hasher.finalize().to_hex();
    let actual = query.body.get("binding_hash").ok_or_else(refused)?;
    super::super::complete_restore_projection::hash(actual, Some(domain))?;
    if actual.get("digest").and_then(serde_json::Value::as_str) != Some(digest.as_str()) {
        return Err(refused());
    }
    Ok(())
}

fn authenticate_response_data(original: &Envelope) -> Result<(), ProviderError> {
    let body = &original.body;
    let result = body
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(refused)?;
    let admission = result
        .get("admission_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(refused)?;
    super::super::complete_restore_projection::identifier(admission)?;
    let hashes = result
        .get("accepted_binding_hashes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(refused)?;
    if original.protocol != "CNP/1"
        || original.message != MessageKind::Response
        || original.method != Method::Admit
        || !original.extensions.is_empty()
        || body.len() != 4
        || body.get("status").and_then(serde_json::Value::as_str) != Some("completed")
        || body
            .get("operation_state")
            .and_then(serde_json::Value::as_str)
            != Some("completed")
        || body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|v| !v.is_empty())
        || result.len() != 2
        || hashes.len() != 1
    {
        return Err(refused());
    }
    super::super::complete_restore_projection::hash(&hashes[0], Some("cnp.node-binding.v1"))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native fresh completed Admit frontier differs")
}

#[cfg(test)]
#[path = "native_fresh_frontier_tests.rs"]
mod tests;
