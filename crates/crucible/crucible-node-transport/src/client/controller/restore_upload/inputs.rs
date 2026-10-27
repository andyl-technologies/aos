//! Borrows the actual completed pair and its six full role references as DATA.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, PacketNative5FreshRestoreAllocationSelection,
};
use crucible_node_format::HashRef;

pub(super) struct PrepareInputs<'a> {
    pub(super) original: &'a Envelope,
    pub(super) response: &'a Envelope,
    pub(super) request_id: &'a Id,
    pub(super) token: &'a str,
    pub(super) references: [Reference<'a>; 6],
}

#[derive(Clone, Copy)]
enum ReferenceValue<'a> {
    Original(&'a Value),
    Typed(&'a ContentRef),
    Mapping { maximum_length: usize },
    ArchiveBound { maximum_length: usize },
}

#[derive(Clone, Copy)]
pub(super) struct Reference<'a> {
    value: ReferenceValue<'a>,
    algorithm: &'a str,
    domain: &'a str,
    digest: &'a str,
    media: &'a str,
    pub(super) length: usize,
}

impl<'a> PrepareInputs<'a> {
    pub(super) fn borrow(
        controller: &'a CnpController,
        emitter: &OriginalCanonicalRestoreInputEmitter,
    ) -> Result<Self, ProviderError> {
        emitter.authenticate_original(controller)?;
        if controller.original_native5_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || controller.original_complete_restore.is_some()
            || controller.original_complete_restore_commit.is_some()
        {
            return Err(refused());
        }
        Self::borrow_original_prepare(controller)
    }

    // The original publication and pre-Commit entry checks remain above.
    // The separate completed-Commit inspector validates that actual paired
    // owner before borrowing this exact unchanged Prepare/reference grammar.
    pub(super) fn borrow_original_prepare(
        controller: &'a CnpController,
    ) -> Result<Self, ProviderError> {
        let state = controller
            .original_complete_restore_prepare
            .as_ref()
            .ok_or_else(refused)?;
        state.validate_owned_snapshot()?;
        let original = &state.original;
        let response = state.response.as_ref().ok_or_else(refused)?;
        let selected = original
            .extensions
            .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
        let request = match if selected {
            if controller.original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            {
                return Err(refused());
            }
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(original)?
        } else {
            CompleteRestoreTransferProjection::from_envelope(original)?
        } {
            CompleteRestoreTransferProjection::Request {
                phase: PacketCompleteRestoreTransferPhase::Prepare,
                request,
                ..
            } => request,
            _ => return Err(refused()),
        };
        let receipt = match CompleteRestoreTransferProjection::from_envelope(response)? {
            CompleteRestoreTransferProjection::Receipt {
                phase: PacketCompleteRestoreTransferPhase::Prepare,
                receipt,
            } => receipt,
            _ => return Err(refused()),
        };
        original.matches_response(response)?;
        let result = response
            .body
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        if response.body.get("status").and_then(Value::as_str) != Some("completed")
            || response.body.get("operation_state").and_then(Value::as_str) != Some("completed")
            || result.get("transaction_id") != request.get("transaction_id")
            || receipt.get("generation") != request.get("generation")
            || decimal(receipt.get("native_sequence").ok_or_else(refused)?)?
                != response.sequence.get()
        {
            return Err(refused());
        }
        let restoration = request
            .get("restoration")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        Ok(Self {
            original,
            response,
            request_id: original.request_id.0.as_ref().ok_or_else(refused)?,
            token: receipt
                .get("transfer_token")
                .and_then(Value::as_str)
                .ok_or_else(refused)?,
            references: [
                Reference::borrow(request.get("native_protocol").ok_or_else(refused)?)?,
                Reference::borrow(request.get("native_control").ok_or_else(refused)?)?,
                Reference::borrow(request.get("native_anchor").ok_or_else(refused)?)?,
                Reference::borrow(restoration.get("owner_state").ok_or_else(refused)?)?,
                Reference::borrow(restoration.get("journal").ok_or_else(refused)?)?,
                Reference::borrow(restoration.get("mapping").ok_or_else(refused)?)?,
            ],
        })
    }

    pub(super) fn verify_bodies(&self, bodies: &[&[u8]; 6]) -> Result<(), ProviderError> {
        for (reference, bytes) in self.references.iter().zip(bodies) {
            if reference.length != bytes.len()
                || blob_digest(bytes)?.to_hex().as_str() != reference.digest
            {
                return Err(refused());
            }
        }
        Ok(())
    }

    pub(super) fn prefix(&self) -> blake3::Hash {
        blake3::hash(self.request_id.as_str().as_bytes())
    }
}

impl<'a> Reference<'a> {
    pub(super) fn typed(value: &'a ContentRef) -> Result<Self, ProviderError> {
        let length = usize::try_from(value.length.get()).map_err(|_| credit())?;
        if value.hash.algorithm != "blake3-256"
            || value.hash.domain != "cnp.blob.v1"
            || value.hash.digest.len() != 64
            || !value
                .hash
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || value.media_type.is_empty()
            || value.media_type.len() > 128
            || !value.media_type.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || length == 0
        {
            return Err(refused());
        }
        Ok(Self {
            value: ReferenceValue::Typed(value),
            algorithm: &value.hash.algorithm,
            domain: &value.hash.domain,
            digest: &value.hash.digest,
            media: &value.media_type,
            length,
        })
    }

    pub(super) fn archive_bound(maximum_length: usize) -> Result<Self, ProviderError> {
        if maximum_length == 0 {
            return Err(credit());
        }
        Ok(Self {
            value: ReferenceValue::ArchiveBound { maximum_length },
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: "",
            media: "",
            length: maximum_length,
        })
    }

    pub(super) fn mapping(maximum_length: usize) -> Result<Self, ProviderError> {
        if maximum_length == 0 || maximum_length > 64 * 1024 {
            return Err(credit());
        }
        Ok(Self {
            value: ReferenceValue::Mapping { maximum_length },
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: "",
            media: "application/json",
            length: maximum_length,
        })
    }

    pub(super) fn project(
        &self,
        p: &mut crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection,
    ) -> Result<(), ProviderError> {
        match self.value {
            ReferenceValue::Original(value) => p.add_value(value),
            ReferenceValue::Typed(value) => p.add_value(value),
            ReferenceValue::Mapping { maximum_length }
            | ReferenceValue::ArchiveBound { maximum_length } => {
                p.add_object()?;
                p.add_field("hash")?;
                p.add_object()?;
                p.add_field("algorithm")?;
                p.add_string(self.algorithm)?;
                p.add_field("domain")?;
                p.add_string(self.domain)?;
                p.add_field("digest")?;
                p.add_unescaped_ascii_extent(64)?;
                p.add_field("length")?;
                // This is the actual closed decimal formatter width of the
                // future mapping bank's previously counted canonical extent.
                p.add_value(&U64::new(maximum_length as u64))?;
                p.add_field("media_type")?;
                if matches!(self.value, ReferenceValue::ArchiveBound { .. }) {
                    p.add_string_extent(128)
                } else {
                    p.add_string(self.media)
                }
            }
        }
    }

    pub(super) fn cloned_reference_storage_data(&self) -> Result<usize, ProviderError> {
        // Each future full-reference clone owns its initialized fields and
        // ordered object nodes; source spare capacity is not cloned. The same
        // closed projection covers typed inputs and completed raw references.
        let mut projection = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(usize::MAX)?;
        self.project(&mut projection)?;
        projection.finish(usize::MAX)?.requested_total()
    }

    pub(super) fn borrow(value: &'a Value) -> Result<Self, ProviderError> {
        let map = value.as_object().ok_or_else(refused)?;
        let hash = map
            .get("hash")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let algorithm = hash
            .get("algorithm")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let domain = hash
            .get("domain")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let digest = hash
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let media = map
            .get("media_type")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let length = usize::try_from(decimal(map.get("length").ok_or_else(refused)?)?)
            .map_err(|_| credit())?;
        if map.len() != 3
            || hash.len() != 3
            || algorithm != "blake3-256"
            || domain != "cnp.blob.v1"
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || media.is_empty()
            || media.len() > 128
            || !media.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || length == 0
        {
            return Err(refused());
        }
        Ok(Self {
            value: ReferenceValue::Original(value),
            algorithm,
            domain,
            digest,
            media,
            length,
        })
    }

    pub(super) fn identity(&self) -> blake3::Hash {
        let mut h = blake3::Hasher::new();
        for field in [self.algorithm, self.domain, self.digest, self.media] {
            h.update(&(field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
        h.update(&(self.length as u64).to_le_bytes());
        h.finalize()
    }

    pub(super) fn matches(&self, reference: &ContentRef) -> bool {
        reference.hash.algorithm == self.algorithm
            && reference.hash.domain == self.domain
            && reference.hash.digest == self.digest
            && reference.media_type == self.media
            && reference.length.get() == self.length as u64
    }

    pub(super) fn owned(&self) -> ContentRef {
        ContentRef {
            hash: HashRef {
                algorithm: self.algorithm.to_owned(),
                domain: self.domain.to_owned(),
                digest: self.digest.to_owned(),
            },
            length: U64::new(self.length as u64),
            media_type: self.media.to_owned(),
        }
    }
}

pub(super) fn decimal(value: &Value) -> Result<u64, ProviderError> {
    let text = value.as_str().ok_or_else(refused)?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(refused());
    }
    text.parse().map_err(|_| refused())
}

pub(super) fn reference_identity(reference: &ContentRef) -> blake3::Hash {
    let mut hash = blake3::Hasher::new();
    for field in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(&reference.length.get().to_le_bytes());
    hash.finalize()
}

// Match canonical::hash's normative streaming framing without cloning a full
// ContentRef or constructing a framed payload/owned hexadecimal String.
fn blob_digest(payload: &[u8]) -> Result<blake3::Hash, ProviderError> {
    const DOMAIN: &[u8] = b"cnp.blob.v1";
    let domain_length = u32::try_from(DOMAIN.len())
        .map_err(|_| credit())?
        .to_be_bytes();
    let payload_length = u64::try_from(payload.len())
        .map_err(|_| credit())?
        .to_be_bytes();
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&domain_length);
    hash.update(DOMAIN);
    hash.update(&payload_length);
    hash.update(payload);
    Ok(hash.finalize())
}
