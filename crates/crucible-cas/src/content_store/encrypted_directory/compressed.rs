//! Streaming compression helpers for authenticated encrypted directory leaves.
//!
//! This module owns the bounded Zstandard-to-AES writer and the keyed physical
//! header authenticator. The parent module retains the shared key-generation,
//! directory-publication, decryption, inventory, and plaintext-authentication
//! contracts.

use super::*;

const COMPRESSION_LEVEL: i32 = 3;
const COMPRESSED_HEADER_AUTHENTICATOR_DOMAIN: &[u8] =
    b"crucible.content-store.compressed-encrypted-header-authenticator.v1";

pub(super) fn compress_and_encrypt_source(
    id: ContentId,
    source: &BlobHandle,
    header: EncryptedObjectHeader,
    key: &[u8; 32],
    output: &mut File,
) -> Result<u64, StoreError> {
    let writer = EncryptingChunkWriter::new(output, id, header, key)?;
    let mut encoder =
        zstd::stream::write::Encoder::new(writer, COMPRESSION_LEVEL).map_err(|source| {
            StoreError::StreamIo {
                operation: "open-compressed-encrypted-object-encoder",
                source,
            }
        })?;
    encoder
        .window_log(MAXIMUM_DECOMPRESSION_WINDOW_LOG)
        .and_then(|()| encoder.include_checksum(true))
        .map_err(|source| StoreError::StreamIo {
            operation: "configure-compressed-encrypted-object-encoder",
            source,
        })?;
    let logical_length = copy_source(id, source, &mut encoder)?;
    let writer = encoder.finish().map_err(|source| StoreError::StreamIo {
        operation: "finish-compressed-encrypted-object-encoder",
        source,
    })?;
    let payload_length = writer.finish()?;
    if maximum_compressed_length(logical_length)
        .is_none_or(|maximum| payload_length == 0 || payload_length > maximum)
    {
        return Err(StoreError::Corrupt { id });
    }
    Ok(payload_length)
}

struct EncryptingChunkWriter<'a> {
    output: &'a mut File,
    id: ContentId,
    header: EncryptedObjectHeader,
    key: &'a [u8; 32],
    cipher: Aes256Gcm,
    chunk_index: u32,
    payload_length: u64,
    pending: Zeroizing<Vec<u8>>,
}

impl<'a> EncryptingChunkWriter<'a> {
    fn new(
        output: &'a mut File,
        id: ContentId,
        header: EncryptedObjectHeader,
        key: &'a [u8; 32],
    ) -> Result<Self, StoreError> {
        let aes_key = derived_aes_key(key);
        let cipher =
            Aes256Gcm::new_from_slice(&*aes_key).map_err(|_| StoreError::InvalidComposition {
                reason: "encrypted store AES-256 key construction failed",
            })?;
        Ok(Self {
            output,
            id,
            header,
            key,
            cipher,
            chunk_index: 0,
            payload_length: 0,
            pending: Zeroizing::new(Vec::with_capacity(ENCRYPTED_CHUNK_BYTES as usize)),
        })
    }

    fn write_chunk(&mut self, last: bool) -> std::io::Result<()> {
        let plaintext_length = self.pending.len() as u64;
        let nonce = chunk_nonce(self.key, self.id, self.chunk_index, self.header);
        let aad = chunk_aad(
            self.id,
            self.header,
            self.chunk_index,
            last,
            plaintext_length,
        )
        .map_err(|_| invalid_encrypted_data())?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &self.pending,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid_encrypted_data())?;
        self.output.write_all(&ciphertext)?;
        self.payload_length = self
            .payload_length
            .checked_add(plaintext_length)
            .ok_or_else(invalid_encrypted_data)?;
        self.pending.clear();
        if !last {
            self.chunk_index = self
                .chunk_index
                .checked_add(1)
                .ok_or_else(invalid_encrypted_data)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<u64, StoreError> {
        self.write_chunk(true)
            .map_err(|source| StoreError::StreamIo {
                operation: "write-compressed-encrypted-object-chunk",
                source,
            })?;
        Ok(self.payload_length)
    }
}

impl Write for EncryptingChunkWriter<'_> {
    fn write(&mut self, mut input: &[u8]) -> std::io::Result<usize> {
        let original_length = input.len();
        while !input.is_empty() {
            if self.pending.len() == ENCRYPTED_CHUNK_BYTES as usize {
                self.write_chunk(false)?;
            }
            let available = ENCRYPTED_CHUNK_BYTES as usize - self.pending.len();
            let copied = available.min(input.len());
            self.pending.extend_from_slice(&input[..copied]);
            input = &input[copied..];
        }
        Ok(original_length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

pub(super) fn maximum_compressed_length(logical_length: u64) -> Option<u64> {
    let logical_length = usize::try_from(logical_length).ok()?;
    u64::try_from(zstd::zstd_safe::compress_bound(logical_length)).ok()
}

pub(super) fn compressed_header_authenticator(
    key: &[u8; 32],
    id: ContentId,
    header: EncryptedObjectHeader,
) -> [u8; 32] {
    let encoded_id = id.encode();
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(COMPRESSED_HEADER_AUTHENTICATOR_DOMAIN);
    hasher.update(&(encoded_id.len() as u64).to_be_bytes());
    hasher.update(encoded_id.as_bytes());
    hasher.update(&header.logical_length.to_be_bytes());
    hasher.update(&header.payload_length.to_be_bytes());
    hasher.update(&(ENCRYPTED_CHUNK_BYTES as u32).to_be_bytes());
    hasher.update(&header.key_id_binding);
    *hasher.finalize().as_bytes()
}
