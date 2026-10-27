//! Content-addressed blob I/O for campaign findings evidence.
//!
//! An evidence store is a [`crucible_engine::LocalDagStore`] that holds every captured
//! canonical campaign request and response as its own blob. Evidence records
//! name an exchange by the content addresses of both blobs:
//!
//! ```text
//! <request blake3 hex> <response blake3 hex>
//! ```
//!
//! Every read is bounded before allocation and verifies the blob's identity,
//! so a record hash commits to every byte reachable from it. Reads also refuse
//! a symlinked object or prefix directory: a finding bundle's `evidence/`
//! directory must not resolve outside the bundle.

use std::io::Read;

use super::*;

/// Largest canonical request or response blob read from an evidence store.
pub(super) const MAX_CAMPAIGN_EXCHANGE_BLOB_BYTES: usize =
    crucible_campaign::MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES;

/// Content addresses of one captured canonical request and its response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CampaignExchangeRef {
    pub(super) request: crucible_engine::ContentHash,
    pub(super) response: crucible_engine::ContentHash,
}

impl CampaignExchangeRef {
    /// Stores both canonical messages and returns their content addresses.
    pub(super) fn put(
        store: &crucible_engine::LocalDagStore,
        request: &[u8],
        response: &[u8],
    ) -> Result<Self, CliError> {
        Ok(Self {
            request: put_evidence_blob(store, request)?,
            response: put_evidence_blob(store, response)?,
        })
    }

    /// Renders the exchange as `<request hex> <response hex>`.
    pub(super) fn encode(self) -> String {
        format!("{} {}", self.request.to_hex(), self.response.to_hex())
    }

    /// Parses one canonical exchange field value.
    pub(super) fn parse(field: &str, value: &str) -> Result<Self, CliError> {
        let (request, response) = value
            .split_once(' ')
            .ok_or_else(|| artifact_error(format!("evidence exchange `{field}` is malformed")))?;
        Ok(Self {
            request: parse_evidence_hash(field, request)?,
            response: parse_evidence_hash(field, response)?,
        })
    }

    /// Reads the request blob under the campaign message bound.
    pub(super) fn read_request(self, store: &crucible_engine::LocalDagStore) -> Result<Vec<u8>, CliError> {
        read_evidence_blob(
            store,
            self.request,
            MAX_CAMPAIGN_EXCHANGE_BLOB_BYTES,
            "campaign request",
        )
    }
}

/// Parses one lowercase BLAKE3 content address from an evidence record.
pub(super) fn parse_evidence_hash(
    field: &str,
    value: &str,
) -> Result<crucible_engine::ContentHash, CliError> {
    // The shared parser accepts only 64 lowercase hexadecimal characters, so
    // every accepted spelling is the canonical one the encoder writes.
    crucible_engine::ContentAddressedBlobRef::parse("campaign evidence hash", &format!("blake3:{value}"))
        .map(crucible_engine::ContentAddressedBlobRef::hash)
        .map_err(|_| artifact_error(format!("evidence field `{field}` has an invalid hash")))
}

/// Stores one evidence blob and returns its content address.
pub(super) fn put_evidence_blob(
    store: &crucible_engine::LocalDagStore,
    bytes: &[u8],
) -> Result<crucible_engine::ContentHash, CliError> {
    store.put(bytes).map_err(CliError::Store)
}

/// Reads one evidence blob, bounded by `maximum_bytes`, and verifies its identity.
///
/// A missing blob, a symlinked object or prefix directory, an oversized
/// object, or bytes that do not hash to `key` fail closed.
pub(super) fn read_evidence_blob(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
    maximum_bytes: usize,
    kind: &str,
) -> Result<Vec<u8>, CliError> {
    let path = store.object_path(&key);
    let missing = || {
        artifact_error(format!(
            "campaign findings evidence is missing {kind} {}",
            key.to_hex()
        ))
    };

    if let Some(prefix) = path.parent() {
        match fs::symlink_metadata(prefix) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(artifact_error(format!(
                    "campaign findings evidence prefix for {kind} is not a directory"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(missing()),
            Err(error) => return Err(CliError::Io(error)),
        }
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(missing()),
        Err(error) => return Err(CliError::Io(error)),
    };
    let maximum = u64::try_from(maximum_bytes)
        .map_err(|_| artifact_error("campaign findings evidence bound exceeds u64"))?;
    if !metadata.file_type().is_file() {
        return Err(artifact_error(format!(
            "campaign findings evidence {kind} is not a regular file"
        )));
    }
    if metadata.len() > maximum {
        return Err(artifact_error(format!(
            "campaign findings evidence {kind} exceeds {maximum_bytes} bytes"
        )));
    }

    // The length check above is advisory; `take` enforces the bound even if
    // the file grows between the metadata read and this one.
    let mut bytes = Vec::new();
    fs::File::open(&path)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(artifact_error(format!(
            "campaign findings evidence {kind} exceeds {maximum_bytes} bytes"
        )));
    }
    if crucible_engine::ContentHash::from_bytes(&bytes) != key {
        return Err(artifact_error(format!(
            "campaign findings evidence {kind} {} does not match its content address",
            key.to_hex()
        )));
    }
    Ok(bytes)
}

/// Flushes every file and directory of a newly written evidence store.
///
/// [`crucible_engine::LocalDagStore`] writes without syncing. A finding bundle is
/// installed by rename, so its evidence must be durable before the rename.
pub(crate) fn sync_evidence_store(root: &Path) -> Result<(), CliError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                fs::File::open(entry.path())?.sync_all()?;
            }
        }
        fs::File::open(&directory)?.sync_all()?;
    }
    Ok(())
}
