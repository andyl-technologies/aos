//! Shares the original receipt parser and context checks with retained owners.
//!
//! The existing receipt wire form remains exact; this module adds no variant:
//!
//! ```text
//! AOSOTR1\0 | version:u16be | protocol:u16be | major:u16be | minor:u16be
//! action:u8 | reserved:7 | key-length:u16be | key-id | generation:u64be
//! public-key-sha256:32 | request-id:16 | claim-digest:32
//! lease-size:u64be | lease-digest:32
//! ```

use super::*;

#[derive(Default)]
pub(crate) struct ReceiptDecodeWorkV1 {
    key_id: Option<StableKeyId>,
    authority: Option<KeyReference>,
    lease_descriptor: Option<ObjectDescriptor>,
    canonical: Option<Vec<u8>>,
}

pub(crate) fn decode_receipt_engine(bytes: &[u8], capture: Option<&mut ReceiptDecodeWorkV1>)
    -> Result<OwnershipTransactionReceiptV1, OwnershipReceiptError> {
    let mut work = aos_sandbox_model::retained::CaptureValueV1::new(ReceiptDecodeWorkV1::default(), capture);
    decode_receipt(bytes, &mut work)
}

fn decode_receipt(bytes: &[u8], work: &mut ReceiptDecodeWorkV1)
    -> Result<OwnershipTransactionReceiptV1, OwnershipReceiptError> {
    if bytes.len() > MAXIMUM_RECEIPT_BYTES || bytes.len() < RECEIPT_FIXED_BYTES + 1 {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    let mut reader = BoundedReader::new(bytes, receipt_read_error);
    if reader.array::<8>()? != *RECEIPT_MAGIC
        || u16::from_be_bytes(reader.array::<2>()?) != RECEIPT_VERSION
        || u16::from_be_bytes(reader.array::<2>()?) != RECEIPT_PROTOCOL_CODE
        || u16::from_be_bytes(reader.array::<2>()?) != RECEIPT_PROTOCOL_MAJOR
    {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    if u16::from_be_bytes(reader.array::<2>()?) != RECEIPT_PROTOCOL_MINOR {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    let action = OwnershipClaimAction::from_code(reader.array::<1>()?[0])
        .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
    if reader.array::<7>()? != [0; 7] {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    let key_id_length = usize::from(u16::from_be_bytes(reader.array::<2>()?));
    if key_id_length == 0 || key_id_length > 255 {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    let key_id = std::str::from_utf8(reader.bytes(key_id_length)?)
        .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
    // The exact nonempty<=255 UTF-8 slice above guarantees StableKeyId's
    // only syntax conditions; its original constructor still runs.
    work.key_id = Some(StableKeyId::new(key_id.to_owned())
        .map_err(|_| OwnershipReceiptError::InvalidEncoding)?);
    let generation = u64::from_be_bytes(reader.array::<8>()?);
    let fingerprint = ObjectDigest::from_bytes(reader.array::<32>()?);
    work.authority = Some(KeyReference::new(
        work.key_id.take().ok_or(OwnershipReceiptError::InvalidEncoding)?,
        generation, fingerprint, KeyUsage::OwnershipLease));
    let authority = work.authority.as_ref().ok_or(OwnershipReceiptError::InvalidEncoding)?;
    let request_id = reader.array::<16>()?;
    let claim_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    let lease_size = u64::from_be_bytes(reader.array::<8>()?);
    let lease_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    if !reader.is_empty()
        || authority.generation() == 0
        || authority.public_key_sha256().as_bytes() == &[0; 32]
        || request_id == [0; 16]
        || claim_digest.as_bytes() == &[0; 32]
        || lease_size == 0
        || lease_digest.as_bytes() == &[0; 32]
    {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    work.lease_descriptor = Some(ObjectDescriptor::new(
        MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
            .map_err(|_| OwnershipReceiptError::InvalidEncoding)?,
        lease_digest,
        lease_size,
    ));
    let lease_descriptor = work.lease_descriptor.as_ref().ok_or(OwnershipReceiptError::InvalidEncoding)?;
    work.canonical = Some(encode_receipt(
        authority, action, request_id, claim_digest, lease_descriptor,
    ));
    if work.canonical.as_deref() != Some(bytes) {
        return Err(OwnershipReceiptError::InvalidEncoding);
    }
    Ok(OwnershipTransactionReceiptV1 {
        authority: work.authority.take().ok_or(OwnershipReceiptError::InvalidEncoding)?,
        action, request_id, claim_digest,
        lease_descriptor: work.lease_descriptor.take().ok_or(OwnershipReceiptError::InvalidEncoding)?,
        canonical_bytes: work.canonical.take().ok_or(OwnershipReceiptError::InvalidEncoding)?,
    })
}

#[derive(Default)]
pub(crate) struct ReceiptContextWorkV1 {
    pub(super) media: Option<MediaType>,
    pub(super) descriptor: Option<ObjectDescriptor>,
}

pub(crate) fn verify_context_engine(
    receipt: &OwnershipTransactionReceiptV1, authority: &KeyReference,
    claim: &OwnershipClaimV1, canonical_lease: &[u8],
    capture: Option<&mut ReceiptContextWorkV1>,
) -> Result<(), OwnershipReceiptError> {
    let mut work = aos_sandbox_model::retained::CaptureValueV1::new(ReceiptContextWorkV1::default(), capture);
    work.media = Some(MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
        .map_err(|_| OwnershipReceiptError::InvalidEncoding)?);
    // Preserve the original short circuit: the descriptor is computed only
    // after all preceding identity/claim comparisons have passed.
    if &receipt.authority != authority
        || receipt.action != claim.action()
        || receipt.request_id != *claim.request_id()
        || receipt.claim_digest != claim.digest()
    {
        return Err(OwnershipReceiptError::ContextMismatch);
    }
    work.descriptor = Some(descriptor_for_bytes(
        work.media.take().ok_or(OwnershipReceiptError::InvalidEncoding)?, canonical_lease));
    if Some(&receipt.lease_descriptor) != work.descriptor.as_ref() {
        return Err(OwnershipReceiptError::ContextMismatch);
    }
    Ok(())
}


#[cfg(test)]
impl ReceiptDecodeWorkV1 {
    pub(super) fn retained_authority(&self) -> Option<&KeyReference> { self.authority.as_ref() }
}
