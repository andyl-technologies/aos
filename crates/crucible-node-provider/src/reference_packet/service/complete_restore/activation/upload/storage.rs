//! Quotes distinct native and SDK upload owners before the first Prepare.
//!
//! Successful frames use their actual closed shape and fixed chunk width. One
//! independent full malformed/error receive remains alongside all successful
//! partials. Numeric rows are inert until the real issuer and native grant each
//! authenticate their own original owners and separately admit every axis.

use super::*;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::original_json_value_storage_extent_data,
};
use std::mem::{align_of, size_of};
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct UploadStorage {
    pub(in super::super) maximum_bytes: usize,
    pub(in super::super) chunk: usize,
    pub(in super::super) frame: usize,
    pub(in super::super) requests: usize,
    pub(in super::super) journal: usize,
    pub(in super::super) retained: usize,
    pub(in super::super) transient: usize,
    pub(in super::super) scratch: usize,
    pub(in super::super) native: PacketRestorationActivationAllocationRow,
}

pub(in super::super) fn quote(
    maximum_bytes: usize,
    chunk: usize,
    frame: usize,
) -> Result<UploadStorage, ProviderError> {
    if maximum_bytes == 0
        || maximum_bytes > 131_072
        || chunk == 0
        || chunk > 4096
        || frame == 0
        || frame > 65_536
    {
        return Err(invalid());
    }
    let chunks = maximum_bytes.div_ceil(chunk);
    let requests = add(chunks, 2)?;
    if requests > 4096 {
        return Err(invalid());
    }
    let raw = original_json_value_storage_extent_data(frame)?;
    let scratch = add(counter_scratch_data(),
        crate::reference_packet::service::ack_emitter::native_boot::original_native_restoration_upload_counter_scratch_data())?;
    let mut retained = sum(&[
        // SDK/connection originals retain planned IDs and actual typed/raw
        // requests/responses independently. Equal banks are not deduplicated.
        crate::client::CnpController::original_installed_restoration_upload_owner_header_bytes_data(requests)?,
        mul(requests, size_of::<crate::client::ClientOriginal>())?,
        tree_storage_data(1, requests, size_of::<Id>() + size_of::<crate::client::ClientOriginal>(), align_of::<crate::client::ClientOriginal>())?,
        mul(maximum_bytes, 4)?,
        // Independent SDK immutable cache and native Control map. Count the
        // larger real entry layout twice, including roots and cloned refs.
        mul(tree_storage_data(1, 1,
            (size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>() )
                .max(size_of::<ContentRef>() + size_of::<Vec<u8>>()),
            align_of::<ContentRef>().max(align_of::<Rc<Vec<u8>>>()),
        )?, 2)?,
        // Full cloned reference strings (bounded media/algorithm/domain/digest)
        // plus the SDK digest key and actual Rc<Vec<u8>> allocation view.
        mul(128 + 128 + 128 + 64, 2)?,
        64 + size_of::<Vec<u8>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(1, align_of::<Vec<u8>>())?,
        raw.canonical_pass_requested_bytes()?,
    ])?;
    let mut transient = sum(&[raw.canonical_pass_requested_bytes()?, scratch])?;
    let mut journal = 0;
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let count = if method == Method::BlobChunk {
            chunks
        } else {
            1
        };
        let request = projection::frame(method, false, chunk, usize::MAX)?;
        let response = projection::frame(method, true, chunk, usize::MAX)?;
        if request.maximum_encoded_bytes > frame || response.maximum_encoded_bytes > frame {
            return Err(ProviderError::ResourceExhausted(
                "selected activation upload frame",
            ));
        }
        retained = add(
            retained,
            mul(
                count,
                sum(&[
                    mul(request.dom_and_canonical_scratch_bytes, 3)?,
                    mul(response.dom_and_canonical_scratch_bytes, 4)?,
                    size_of::<crate::connection::ReceivedFrame>(),
                    size_of::<crate::bodies::ResponseBody>(),
                    // Original key, actual plan/request IDs and transfer ID strings.
                    4 * (2 * 128 + 4),
                ])?,
            )?,
        )?;
        transient = add(
            transient,
            mul(
                count,
                sum(&[
                    mul(request.requested_total()?, 3)?,
                    mul(response.requested_total()?, 3)?,
                    mul(chunk, 2)?,
                    chunk.div_ceil(3).checked_mul(4).ok_or_else(invalid)?,
                ])?,
            )?,
        )?;
        journal = add(
            journal,
            mul(count, add(request.maximum_encoded_bytes, frame)?)?,
        )?;
    }
    // Native keeps its own real request history, immutable transfer buffers and
    // decoded response/ACK/index views. These full independent bounds are added
    // to the host row; they are never that host row reassigned as native credit.
    let native_retained = sum(&[
        retained,
        crate::reference_packet::service::ack_emitter::native_boot::original_native_restoration_upload_attempt_backing_data()?,
        // The native ordinal retains a separately reserved Vec<Id> of actual
        // seen originals. Its element bank is not its String backing/header.
        mul(requests, size_of::<Id>())?,
        mul(requests, 2 * 128 + 4)?,
    ])?;
    let native = PacketRestorationActivationAllocationRow {
        retained_requested_bytes: u64_data(native_retained)?,
        maximum_simultaneous_transient_bytes: u64_data(transient)?,
        declared_counter_scratch_bytes: u64_data(scratch)?,
    };
    native.requested_bytes_data()?;
    Ok(UploadStorage {
        maximum_bytes,
        chunk,
        frame,
        requests,
        journal,
        retained,
        transient,
        scratch,
        native,
    })
}

/// Recounts this real upload's exact full reference and finite loop before reserve.
pub(crate) fn original_native_restoration_activation_upload_required_storage_data(
    request: &PacketRestorationActivationUploadRequest,
) -> Result<PacketRestorationActivationAllocationRow, ProviderError> {
    request.validate_data()?;
    let data = quote(
        usize::try_from(request.content_ref_data().length.get()).map_err(|_| invalid())?,
        usize::try_from(request.chunk_bytes.get()).map_err(|_| invalid())?,
        usize::try_from(request.maximum_frame_bytes.get()).map_err(|_| invalid())?,
    )?;
    Ok(data.native)
}

pub(super) fn counter_scratch_data() -> usize {
    crate::client::CnpController::original_installed_restoration_upload_counter_scratch_data()
        + size_of::<UploadStorage>() + size_of::<Result<UploadStorage, ProviderError>>()
        + 2 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection>()
        + size_of::<PacketRestorationActivationUploadRequest>()
        + size_of::<PacketRestorationActivationUploadArtifact>()
        + size_of::<PacketRestorationActivationUploadContext>()
        + size_of::<Result<PacketRestorationActivationUploadArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationUploadRequest, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationAllocationRow, ProviderError>>()
        + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Option<u64>>() + size_of::<Result<usize, ProviderError>>()
        + size_of::<crypto::ProofView<'static>>()
        + size_of::<[usize; 6]>() + size_of::<[&str; 13]>()
        + size_of::<std::array::IntoIter<Method, 3>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(invalid)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(invalid)
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |total, term| add(total, *term))
}
fn u64_data(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| invalid())
}
