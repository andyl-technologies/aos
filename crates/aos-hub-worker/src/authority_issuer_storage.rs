//! Bounded string records and atomic chunks for actual authority DO storage.
//!
//! Small legacy version-one authority entries remain unchanged. Large records
//! use a closed version-two manifest and exact UTF-8 chunks in one transaction;
//! missing/corrupt chunks are errors, never an absent authority or fresh issuer.
//!
//! ```json
//! {"version":2,"chunks":2,"bytes":70000,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Storage, Transaction};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNKS: usize = 16;
const MAX_BYTES: usize = aos_hub_core::storage_authority::lease::control::MAX_ISSUER_CONTROL_BYTES;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    chunks: usize,
    bytes: usize,
    digest: String,
}

/// Reads a bounded record while the caller holds its addressed DO gate.
///
/// # Errors
/// Returns an error for unavailable storage, malformed manifests or missing,
/// oversized, reordered or changed chunks; corruption never creates absence.
pub(crate) async fn read(storage: &Storage, key: &str) -> Result<Option<String>> {
    read_with(
        key,
        |key| async move { Ok(storage.get::<String>(&key).await?) },
    )
    .await
}

/// Reloads a complete record inside the actual transaction snapshot.
///
/// # Errors
/// Returns an error for unavailable storage or corrupt bounded records.
pub(crate) async fn read_transaction(
    transaction: &Transaction,
    key: &str,
) -> Result<Option<String>> {
    read_with(key, |key| async move {
        Ok(read_optional_transaction(transaction, &key).await?)
    })
    .await
}

/// Reads an optional string within the actual transaction snapshot.
///
/// The SDK's single-key transaction getter errors on absence even when its
/// requested Rust type is `Option`. The map API preserves absence explicitly.
///
/// # Errors
/// Returns an error for failed I/O or a present value that is not a string.
pub(crate) async fn read_optional_transaction(
    transaction: &Transaction,
    key: &str,
) -> worker::Result<Option<String>> {
    let values = transaction.get_multiple(vec![key]).await?;
    let value = values.get(&wasm_bindgen::JsValue::from_str(key));
    if value.is_undefined() {
        Ok(None)
    } else {
        serde_wasm_bindgen::from_value(value)
            .map(Some)
            .map_err(error)
    }
}

async fn read_with<Read, ReadFuture>(key: &str, mut read: Read) -> Result<Option<String>>
where
    Read: FnMut(String) -> ReadFuture,
    ReadFuture: std::future::Future<Output = Result<Option<String>>>,
{
    let Some(raw) = read(key.to_owned()).await? else {
        return Ok(None);
    };
    ensure!(
        raw.len() <= 128 * 1024,
        "authority record header exceeds bound"
    );
    let Some(manifest) = manifest(&raw)? else {
        return Ok(Some(raw));
    };
    let mut encoded = String::with_capacity(manifest.bytes);
    for index in 0..manifest.chunks {
        let chunk = read(chunk_key(key, index))
            .await?
            .ok_or_else(|| anyhow::anyhow!("authority chunk missing"))?;
        ensure!(
            !chunk.is_empty()
                && chunk.len() <= CHUNK_BYTES
                && encoded.len() + chunk.len() <= manifest.bytes,
            "authority chunk exceeds bound"
        );
        encoded.push_str(&chunk);
    }
    ensure!(
        encoded.len() == manifest.bytes
            && hex::encode(Sha256::digest(encoded.as_bytes())) == manifest.digest,
        "authority chunk commitment differs"
    );
    Ok(Some(encoded))
}

/// Writes bounded chunks, replacement manifest and private obsolete deletions.
///
/// The caller commits this transaction with its exact CAS and semantic receipt.
///
/// # Errors
/// Returns an error for excessive input, corrupt prior manifests or failed I/O.
pub(crate) async fn write(
    transaction: &Transaction,
    key: &str,
    encoded: &str,
) -> worker::Result<()> {
    if encoded.len() > MAX_BYTES {
        return Err(error("authority record exceeds bound"));
    }
    let prior = read_optional_transaction(transaction, key).await?;
    let prior_chunks = prior
        .as_deref()
        .map(manifest)
        .transpose()
        .map_err(error)?
        .flatten()
        .map_or(0, |manifest| manifest.chunks);
    let mut offset = 0;
    let mut index = 0;
    if encoded.len() > CHUNK_BYTES {
        while offset < encoded.len() {
            let mut end = (offset + CHUNK_BYTES).min(encoded.len());
            while !encoded.is_char_boundary(end) {
                end -= 1;
            }
            transaction
                .put(&chunk_key(key, index), &encoded[offset..end])
                .await?;
            index += 1;
            offset = end;
        }
        if index > MAX_CHUNKS {
            return Err(error("authority chunk count exceeds bound"));
        }
    }
    // These are private serialization chunks, not provider receipts or unknown
    // effects. Their deletion shares the replacement manifest transaction.
    for obsolete in index..prior_chunks {
        transaction.delete(&chunk_key(key, obsolete)).await?;
    }
    if index == 0 {
        transaction.put(key, encoded).await?;
    } else {
        let manifest = Manifest {
            version: 2,
            chunks: index,
            bytes: encoded.len(),
            digest: hex::encode(Sha256::digest(encoded.as_bytes())),
        };
        transaction
            .put(key, serde_json::to_string(&manifest).map_err(error)?)
            .await?;
    }
    Ok(())
}

fn manifest(raw: &str) -> Result<Option<Manifest>> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    if value.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
        return Ok(None);
    }
    let manifest: Manifest = serde_json::from_str(raw)?;
    ensure!(
        manifest.chunks > 1
            && manifest.chunks <= MAX_CHUNKS
            && manifest.bytes > CHUNK_BYTES
            && manifest.bytes <= MAX_BYTES
            && manifest.chunks >= manifest.bytes.div_ceil(CHUNK_BYTES)
            && manifest.chunks <= manifest.bytes.div_ceil(CHUNK_BYTES - 3)
            && manifest.digest.len() == 64
            && manifest
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "authority manifest corrupt"
    );
    Ok(Some(manifest))
}

fn chunk_key(key: &str, index: usize) -> String {
    format!(
        "authority-record-chunk/{}/{index}",
        hex::encode(Sha256::digest(key.as_bytes()))
    )
}
fn error(value: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(value.to_string())
}
