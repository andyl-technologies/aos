//! Bounded complete historical Output publication chunks.
//!
//! The existing publication codec validates the reconstructed bytes;
//! chunk checksums alone do not publish or activate authority.
//!
//! ```text
//! AOSCSP01 | version:u16be | index:u8 | count:u8 | execution:16 | Create:16 |
//! existing-publication-digest:32 | full-length:u32be | chunk-length:u32be |
//! exact payload | domain-sha256:32
//! ```

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use crate::publication::MAXIMUM_PUBLICATION_BYTES;

use super::authority::HistoricalStorageOutputRetentionErrorV1;

const DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-publication-chunk.v1\0";
const PREFIX_BYTES: usize = 84;
/// Bounds each publication payload without changing its framing allowance.
pub(super) const MAXIMUM_CHUNK_BYTES: usize = 8_388_608;

/// Owns the exact encoded chunk and its record key until the batch consumes them.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct HistoricalOutputPublicationChunkV1 {
    bytes: Vec<u8>,
    key: Vec<u8>,
}

/// Borrows canonical historical chunk bytes after the sole framing validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoricalOutputPublicationChunkViewV1<'bytes> {
    bytes: &'bytes [u8],
    /// Records the historical execution identity checked by cold reconstruction.
    pub(super) execution: ExecutionId,
    /// Records the historical Create identity checked by cold reconstruction.
    pub(super) create_operation: OperationId,
    /// Commits the complete publication, not just this chunk's payload.
    pub(super) publication_digest: ObjectDigest,
    /// Selects the zero-based slot in the closed one/two-chunk sequence.
    pub(super) index: u8,
    /// Records the exact count derived from the complete publication length.
    pub(super) count: u8,
    /// Bounds the single reconstructed complete publication allocation.
    pub(super) full_length: usize,
}

impl HistoricalOutputPublicationChunkV1 {
    /// Encodes complete publication chunks and validates without copying them.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversize publication or invalid canonical chunk fields.
    pub(super) fn from_publication(
        execution: ExecutionId,
        create_operation: OperationId,
        publication_digest: ObjectDigest,
        full_publication: &[u8],
    ) -> Result<Vec<Self>, HistoricalStorageOutputRetentionErrorV1> {
        let length = full_publication.len();
        if length == 0 || length > MAXIMUM_PUBLICATION_BYTES {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        let count = u8::try_from(length.div_ceil(MAXIMUM_CHUNK_BYTES))
            .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
        let full_length = u32::try_from(length)
            .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
        let mut chunks = Vec::with_capacity(usize::from(count));
        for (index, payload) in full_publication.chunks(MAXIMUM_CHUNK_BYTES).enumerate() {
            let index = u8::try_from(index)
                .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
            let payload_length = u32::try_from(payload.len())
                .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
            let mut bytes = Vec::with_capacity(PREFIX_BYTES + payload.len() + 32);
            bytes.extend_from_slice(b"AOSCSP01");
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&[index, count]);
            bytes.extend_from_slice(execution.as_bytes());
            bytes.extend_from_slice(create_operation.as_bytes());
            bytes.extend_from_slice(publication_digest.as_bytes());
            bytes.extend_from_slice(&full_length.to_be_bytes());
            bytes.extend_from_slice(&payload_length.to_be_bytes());
            bytes.extend_from_slice(payload);
            let checksum = chunk_digest(&bytes);
            bytes.extend_from_slice(&checksum);
            let view = HistoricalOutputPublicationChunkViewV1::decode(&bytes)?;
            let key = view.key();
            chunks.push(Self { bytes, key });
        }
        Ok(chunks)
    }

    /// Moves every original encoded byte into its immutable Journal record.
    pub(super) fn into_record_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.key, self.bytes)
    }
}

impl<'bytes> HistoricalOutputPublicationChunkViewV1<'bytes> {
    /// Borrows a chunk only after every canonical framing and digest check.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, identities, count/index/length or checksum.
    pub(super) fn decode(
        bytes: &'bytes [u8],
    ) -> Result<Self, HistoricalStorageOutputRetentionErrorV1> {
        if bytes.len() < PREFIX_BYTES + 33
            || bytes.len() > PREFIX_BYTES + MAXIMUM_CHUNK_BYTES + 32
            || bytes.get(..8) != Some(b"AOSCSP01".as_slice())
            || bytes[8..10] != 1_u16.to_be_bytes()
        {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        let index = bytes[10];
        let count = bytes[11];
        let execution = ExecutionId::from_bytes(array(&bytes[12..28])?);
        let create_operation = OperationId::from_bytes(array(&bytes[28..44])?);
        let publication_digest = ObjectDigest::from_bytes(array(&bytes[44..76])?);
        let full_length = usize::try_from(u32::from_be_bytes(array(&bytes[76..80])?))
            .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
        let payload_length = usize::try_from(u32::from_be_bytes(array(&bytes[80..84])?))
            .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
        if execution.as_bytes() == &[0; 16]
            || create_operation.as_bytes() == &[0; 16]
            || publication_digest.as_bytes() == &[0; 32]
            || full_length == 0
            || full_length > MAXIMUM_PUBLICATION_BYTES
            || !matches!(count, 1 | 2)
            || index >= count
            || usize::from(count) != full_length.div_ceil(MAXIMUM_CHUNK_BYTES)
        {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        let offset = usize::from(index) * MAXIMUM_CHUNK_BYTES;
        let expected_length = full_length.checked_sub(offset)
            .ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?
            .min(MAXIMUM_CHUNK_BYTES);
        if payload_length != expected_length
            || payload_length == 0
            || bytes.len() != PREFIX_BYTES + payload_length + 32
            || chunk_digest(&bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
        {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        Ok(Self {
            bytes,
            execution,
            create_operation,
            publication_digest,
            index,
            count,
            full_length,
        })
    }

    /// Borrows the exact nonempty payload of this already-validated view.
    pub(super) fn payload(&self) -> &[u8] {
        &self.bytes[PREFIX_BYTES..self.bytes.len() - 32]
    }

    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(18);
        key.extend_from_slice(&[b'p', self.index]);
        key.extend_from_slice(self.execution.as_bytes());
        key
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], HistoricalStorageOutputRetentionErrorV1> {
    bytes.try_into().map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)
}

fn chunk_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_chunk_retains_payload_and_refuses_changed_identity_or_digest() {
        let chunks = HistoricalOutputPublicationChunkV1::from_publication(
            ExecutionId::from_bytes([1; 16]), OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]), b"historical publication DATA",
        ).unwrap();

        assert_eq!(chunks.len(), 1);
        let view = HistoricalOutputPublicationChunkViewV1::decode(&chunks[0].bytes).unwrap();
        assert_eq!(view.payload(), b"historical publication DATA");
        assert_eq!(view.bytes.as_ptr(), chunks[0].bytes.as_ptr());

        let mut changed = chunks[0].bytes.clone();
        changed[12] ^= 1;
        assert!(HistoricalOutputPublicationChunkViewV1::decode(&changed).is_err());
        changed.pop();
        assert!(HistoricalOutputPublicationChunkViewV1::decode(&changed).is_err());
    }

    #[test]
    fn chunk_count_and_final_payload_match_full_length_exactly() {
        let publication = vec![7; MAXIMUM_CHUNK_BYTES + 1];
        let chunks = HistoricalOutputPublicationChunkV1::from_publication(
            ExecutionId::from_bytes([1; 16]), OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]), &publication,
        ).unwrap();

        assert_eq!(chunks.len(), 2);
        let first = HistoricalOutputPublicationChunkViewV1::decode(&chunks[0].bytes).unwrap();
        let second = HistoricalOutputPublicationChunkViewV1::decode(&chunks[1].bytes).unwrap();
        assert_eq!(first.payload().len(), MAXIMUM_CHUNK_BYTES);
        assert_eq!(second.payload(), &[7]);
        assert_eq!(second.count, 2);
        assert_eq!(second.index, 1);

        assert!(HistoricalOutputPublicationChunkV1::from_publication(
            ExecutionId::from_bytes([1; 16]), OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]), &[],
        ).is_err());
    }

    #[test]
    fn encoded_original_chunk_bytes_move_into_record_parts_without_a_copy() {
        let mut chunks = HistoricalOutputPublicationChunkV1::from_publication(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            b"unchanged original bytes",
        ).unwrap();
        let chunk = chunks.pop().unwrap();
        let bytes_pointer = chunk.bytes.as_ptr();
        let key_pointer = chunk.key.as_ptr();

        let (key, bytes) = chunk.into_record_parts();

        assert_eq!(bytes.as_ptr(), bytes_pointer);
        assert_eq!(key.as_ptr(), key_pointer);
        assert_eq!(&key[..2], &[b'p', 0]);
        assert_eq!(&key[2..], &[1; 16]);
        let view = HistoricalOutputPublicationChunkViewV1::decode(&bytes).unwrap();
        assert_eq!(view.payload(), b"unchanged original bytes");
    }

    #[test]
    fn shared_publication_ceiling_and_boundary_framing_remain_exact() {
        assert_eq!(MAXIMUM_PUBLICATION_BYTES, 16_776_972);
        let lengths = [
            MAXIMUM_CHUNK_BYTES,
            MAXIMUM_CHUNK_BYTES + 1,
            MAXIMUM_PUBLICATION_BYTES,
        ];
        for length in lengths {
            let publication = vec![5; length];
            let chunks = HistoricalOutputPublicationChunkV1::from_publication(
                ExecutionId::from_bytes([1; 16]),
                OperationId::from_bytes([2; 16]),
                ObjectDigest::from_bytes([3; 32]),
                &publication,
            ).unwrap();

            assert_eq!(chunks.len(), length.div_ceil(MAXIMUM_CHUNK_BYTES));
            for (index, chunk) in chunks.iter().enumerate() {
                let view = HistoricalOutputPublicationChunkViewV1::decode(&chunk.bytes).unwrap();
                let offset = index * MAXIMUM_CHUNK_BYTES;
                let end = (offset + MAXIMUM_CHUNK_BYTES).min(length);

                assert_eq!(&chunk.bytes[..10], b"AOSCSP01\0\x01");
                assert_eq!(&chunk.bytes[12..28], &[1; 16]);
                assert_eq!(&chunk.bytes[28..44], &[2; 16]);
                assert_eq!(&chunk.bytes[44..76], &[3; 32]);
                assert_eq!(&chunk.bytes[76..80], &u32::try_from(length).unwrap().to_be_bytes());
                assert_eq!(view.payload(), &publication[offset..end]);
                assert_eq!(view.full_length, length);
                assert_eq!(usize::from(view.index), index);
            }
        }
    }

    #[test]
    fn resealed_invalid_shape_and_zero_identity_fields_are_still_refused() {
        let chunks = HistoricalOutputPublicationChunkV1::from_publication(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            b"DATA",
        ).unwrap();
        let original = &chunks[0].bytes;
        let fields: [(usize, &[u8]); 8] = [
            (8, &2_u16.to_be_bytes()),
            (10, &[1]),
            (11, &[2]),
            (12, &[0; 16]),
            (28, &[0; 16]),
            (44, &[0; 32]),
            (76, &5_u32.to_be_bytes()),
            (80, &5_u32.to_be_bytes()),
        ];
        for (offset, replacement) in fields {
            let mut changed = original.clone();
            changed[offset..offset + replacement.len()].copy_from_slice(replacement);
            let end = changed.len() - 32;
            let checksum = chunk_digest(&changed[..end]);
            changed[end..].copy_from_slice(&checksum);

            assert!(
                HistoricalOutputPublicationChunkViewV1::decode(&changed).is_err(),
                "accepted invalid field at {offset}",
            );
        }
    }
}
