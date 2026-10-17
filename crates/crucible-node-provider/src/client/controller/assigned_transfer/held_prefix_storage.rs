//! Quotes the selected incoming Commit object and Host cache/ACK phases as DATA.
//!
//! The selected publisher validates every successful incoming prefix literal
//! against the same original bank before accepting this closed shape. One full
//! negotiated raw/error receive remains independently charged. Current Source,
//! assigned Prepare/Commit DTOs and native reconstruction require separate rows.

use super::*;
use crate::client::session::restore_transfer_prefix::HeldPrefix;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalSerializationStorageProjection as Projection,
        original_serialization_counter_scratch_data,
    },
};
use std::mem::{align_of, size_of};

#[derive(serde::Serialize)]
struct Reference {
    hash: Hash,
    length: &'static str,
    media_type: &'static str,
}

#[derive(serde::Serialize)]
struct Hash {
    algorithm: &'static str,
    digest: &'static str,
    domain: &'static str,
}

impl CnpController {
    /// Returns the selected Commit-prefix retained, transient and fixed DATA axes.
    ///
    /// These terms price one real native held object, all its independent Host
    /// original/cache/ACK views, and one full raw/error receive. They grant no
    /// publication or restoration authority and do not include the Source or
    /// assigned Prepare/Commit construction owners.
    ///
    /// # Errors
    /// Refuses a foreign/revoked codec, another selection, exhausted actual
    /// content/journal/literal windows, impossible wire shape or arithmetic.
    pub fn original_selected_restore_held_prefix_storage_data(
        &self,
    ) -> Result<(usize, usize, usize), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session.authenticate_native5_source_codec()?;
        if self.original_native5_complete_restore_selection()?
            != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_native5_fresh_restore_allocation_selection()?
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13) {
            return Err(refused());
        }
        let maximum = crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_bytes()?;
        let chunk = usize::try_from(self.authority().limits().blob_chunk_bytes.get())
            .map_err(|_| credit())?
            .min(4096);
        let frame = self.maximum_frame()?;
        if chunk == 0 || frame > 65_536 {
            return Err(credit());
        }
        let chunks = maximum.div_ceil(chunk);
        let requests = add(chunks, 2)?;
        self.custody.content().preflight_capacity(1, maximum)?;
        let reference = Reference {
            hash: Hash {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: "0000000000000000000000000000000000000000000000000000000000000000",
            },
            length: "18446744073709551615",
            media_type: "application/json",
        };
        let (content, content_work) = self
            .custody
            .content()
            .selected_restore_held_content_storage_data(maximum)?;
        let raw = crate::connection::original_host_initial_raw_receive_storage_data(frame)?;
        let mut retained = add(
            content,
            self.custody
                .fresh_query_cache_requested_layout_data(requests)?,
        )?;
        // A refused raw owner can coexist with all previously accepted prefix
        // caches; it is never replaced by the small successful literal shape.
        retained = add(retained, raw)?;
        let mut transient = add(raw, content_work)?;
        let mut literals = 0;
        for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
            let count = if method == Method::BlobChunk {
                chunks
            } else {
                1
            };
            let request = super::super::restore_upload::storage::held_prefix_frame(
                self, &reference, method, false, chunk,
            )?;
            let response = super::super::restore_upload::storage::held_prefix_frame(
                self, &reference, method, true, chunk,
            )?;
            if request.maximum_encoded_bytes > frame || response.maximum_encoded_bytes > frame {
                return Err(credit());
            }
            let request_work = add(
                request.requested_total()?,
                closed_ordered_collect_storage(method, false)?,
            )?;
            let response_work = add(
                response.requested_total()?,
                closed_ordered_collect_storage(method, true)?,
            )?;
            // ClientOriginal retains one request and one ACK. The same raw
            // literal bank additionally retains each canonical framed body.
            retained = add(
                retained,
                mul(
                    count,
                    sum(&[
                        request.retained_value_backing_bytes,
                        response.retained_value_backing_bytes,
                        // Cache key and separate actual request-hash strings.
                        growth(128)?,
                        growth(64)?,
                        growth("cnp.request.v1".len())?,
                        growth("blake3-256".len())?,
                    ])?,
                )?,
            )?;
            literals = add(
                literals,
                mul(
                    count,
                    sum(&[
                        request.maximum_encoded_bytes,
                        response.maximum_encoded_bytes,
                        8,
                    ])?,
                )?,
            )?;
            // Sum the distinct called operations rather than refunding work
            // across iterations: identity/envelope-size/correlation/request
            // clones; ACK DTO->Value/object clone, size/cache/send phases.
            transient = add(
                transient,
                mul(
                    count,
                    sum(&[
                        request_work,                             // request identity canonical hash
                        request_work,                             // envelope_bytes Value+canonical
                        request.dom_and_canonical_scratch_bytes, // temporary/pending raw request view
                        request.dom_and_canonical_scratch_bytes, // ClientOriginal request clone
                        response_work,                           // ACK object serialization
                        response.dom_and_canonical_scratch_bytes, // object() map clone
                        response_work,                           // ACK envelope_bytes
                        response.dom_and_canonical_scratch_bytes, // cached ACK clone
                        response_work,                           // actual send serialization
                        size_of::<BlobBeginResult>()
                            + size_of::<BlobChunkResult>()
                            + size_of::<BlobFinishResult>(),
                        size_of::<Envelope>()
                            + size_of::<RequestBody>()
                            + size_of::<ResponseBody>(),
                        growth(128)?, // receive_transfer ID clone
                        growth(20)?,  // real U64 custom formatter
                    ])?,
                )?,
            )?;
        }
        // A single pending correlation tree can retain its root after the ACK.
        retained = add(
            retained,
            tree_storage_data(
                1,
                1,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
        )?;
        let frontier = self.original_native5_storage_facts()?;
        if !frontier.all_io_complete
            || add(frontier.incoming_frames, requests)? > frontier.maximum_frames_per_direction
            || add(frontier.outgoing_frames, requests)? > frontier.maximum_frames_per_direction
            || add(
                add(frontier.incoming_frames, frontier.outgoing_frames)?,
                mul(requests, 2)?,
            )? > frontier.descriptor_capacity
            || add(frontier.retained_bytes, literals)? > frontier.maximum_history_bytes
            || add(frontier.retained_bytes, literals)? > frontier.byte_capacity
        {
            return Err(credit());
        }
        self.preflight_source_reply(0, requests, literals, 1, maximum)?;
        // Literal bytes occupy existing precharged banks: they constrain those
        // banks here and are not a new allocation charged again as retained.
        Ok((
            retained,
            transient,
            Self::original_selected_restore_held_prefix_counter_scratch_data(),
        ))
    }

    /// Returns explicit fixed views for the selected Host prefix counter and guard.
    pub fn original_selected_restore_held_prefix_counter_scratch_data() -> usize {
        crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_counter_scratch_data()
            + size_of::<HeldPrefix>() + size_of::<Option<HeldPrefix>>() + size_of::<Option<&mut HeldPrefix>>()
            + size_of::<Reference>() + size_of::<Hash>() + size_of::<Projection>()
            // The concrete serializer callback borrows the same fixed reference.
            + size_of::<&Reference>()
            + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData, ProviderError>>()
            + 2 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>()
            + original_serialization_counter_scratch_data()
            + super::super::restore_upload::storage::counter_scratch_data()
            + crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
            + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
            + size_of::<std::cell::Ref<'static, crate::transport::original_frames::OriginalFrameReservation>>()
            + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
            + size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>()
            + size_of::<Result<(), ProviderError>>() + size_of::<Result<(usize,usize), ProviderError>>()
            + size_of::<Result<(usize,usize,usize), ProviderError>>()
            + size_of::<(&Envelope, &RequestBody, &ResponseBody, &Id, &ContentRef)>()
            + size_of::<std::num::ParseIntError>() + size_of::<std::str::Bytes<'static>>()
            + size_of::<[u8;4]>() + size_of::<[u8;64]>()
            + size_of::<std::array::IntoIter<Method,3>>() + size_of::<[usize;14]>()
            + size_of::<std::array::IntoIter<usize,14>>()
            + size_of::<std::array::IntoIter<usize,6>>()
            + size_of::<(usize,usize,usize)>()
            + size_of::<[&str;4]>() + size_of::<[&str;3]>() + size_of::<[&str;2]>()
            + size_of::<&[&str]>() + size_of::<std::slice::Iter<'static,&'static str>>()
            + size_of::<Option<&'static serde_json::Map<String,Value>>>()
            + size_of::<Option<&'static str>>() + size_of::<Result<u64,ProviderError>>()
            + size_of::<[usize;6]>()
            // Pinned small-map stable-sort workspace: every closed object has
            // at most13 entries, below the heap-sort threshold.
            + size_of::<[std::mem::MaybeUninit<(Vec<u16>,(&'static str,&'static Value))>;
                4096 / size_of::<(Vec<u16>,(&'static str,&'static Value))>()]>()
            + 5 * size_of::<(Vec<(Vec<u16>,(&'static str,&'static Value))>,
                std::collections::BTreeMap<Vec<u16>,(&'static str,&'static Value)>)>()
            + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>() + 20
    }
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(credit)
}

fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(credit)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |a, b| add(a, *b))
}

fn growth(n: usize) -> Result<usize, ProviderError> {
    add(mul(n, 4)?, 8)
}

// canonical.rs collects the UTF16-key/borrowed-entry tuples before building its
// BTree. The generic projection already counts keys and tree nodes; these are
// the additional concrete FromIterator Vec owners for this closed grammar.
fn closed_ordered_collect_storage(method: Method, response: bool) -> Result<usize, ProviderError> {
    let widths: [usize; 6] = match (method, response) {
        (Method::BlobBegin, false) => [13, 3, 3, 3, 0, 0],
        (Method::BlobChunk, false) => [13, 4, 0, 0, 0, 0],
        (Method::BlobFinish, false) => [13, 2, 0, 0, 0, 0],
        (Method::BlobBegin, true) => [13, 4, 3, 0, 0, 0],
        (Method::BlobChunk, true) => [13, 4, 2, 0, 0, 0],
        (Method::BlobFinish, true) => [13, 4, 2, 3, 3, 0],
        _ => return Err(refused()),
    };
    widths.into_iter().try_fold(0, |total, n| {
        add(
            total,
            mul(
                if n == 0 { 0 } else { n.max(4) },
                size_of::<(Vec<u16>, (&str, &Value))>(),
            )?,
        )
    })
}
