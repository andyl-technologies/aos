//! Observes bounded retained issuer replies under an independently selected pin.
//!
//! This fixture checks historical signature and original correlation using the
//! shared issuer codec. It performs no network request, signs no data, supplies
//! no new current clock and grants no provider or publication permission. The
//! external collector must join actual Worker checks and process/transport pins.
//!
//! The input is an owner-private JSON file containing `version`, `issuerKeyId`,
//! `issuerPublicKey` and up to 4,096 `pairs`. Each pair names exact private request
//! and reply files plus their SHA-256 and byte counts and the original owner nonce.
//!
//! ```json
//! {
//!   "version": 1,
//!   "issuerKeyId": "selected-issuer",
//!   "issuerPublicKey": "<64 lowercase hexadecimal characters>",
//!   "pairs": [{
//!     "ownerNonce": "<64 lowercase hexadecimal characters>",
//!     "requestFile": "/private/request.body",
//!     "requestSha256": "<64 lowercase hexadecimal characters>",
//!     "requestBytes": 1024,
//!     "replyFile": "/private/reply.body",
//!     "replySha256": "<64 lowercase hexadecimal characters>",
//!     "replyBytes": 2048
//!   }]
//! }
//! ```
//!
//! These illustrative values establish neither private file custody nor issuer
//! trust; the selected files and externally pinned key are validated at execution.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::control::{
    verify_issuer_reply, IssuerOperation, IssuerRequest, MAX_ISSUER_CONTROL_BYTES,
};
use aos_hub_core::storage_authority::lease::{EpochLeasePayload, EpochLeaseVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_PAIRS: usize = 4_096;
const MAX_AGGREGATE: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    version: u8,
    issuer_key_id: String,
    issuer_public_key: String,
    pairs: Vec<Pair>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pair {
    owner_nonce: String,
    request_file: PathBuf,
    request_sha256: String,
    request_bytes: usize,
    reply_file: PathBuf,
    reply_sha256: String,
    reply_bytes: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observed {
    owner_nonce: String,
    request_sha256: String,
    request_bytes: usize,
    reply_sha256: String,
    reply_bytes: usize,
    cohort_digest: String,
    lease_digest: String,
    lease_sequence: i64,
    issued_at: i64,
    not_after: i64,
    attestation_valid_until: i64,
    scope: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedTokenProjection {
    payload: EpochLeasePayload,
    #[serde(rename = "signature")]
    _signature: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn private_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "expected an absolute private reference");
    let parent = path.parent().context("missing private parent")?;
    ensure!(
        std::fs::canonicalize(parent)? == parent,
        "private parent changed"
    );
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        parent_metadata.is_dir() && parent_metadata.mode() & 0o077 == 0,
        "private parent permissions differ"
    );
    ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "private reference is not a regular file"
    );
    let mut source = File::open(path)?;
    let before = source.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == parent_metadata.uid()
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1
            && before.len() <= u64::try_from(maximum)?,
        "private file custody or size differs"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut source)
        .take(u64::try_from(maximum)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = source.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    let identity = |value: &std::fs::Metadata| {
        (
            value.dev(),
            value.ino(),
            value.len(),
            value.mtime(),
            value.mtime_nsec(),
            value.ctime(),
            value.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() == usize::try_from(before.len())?
            && identity(&before) == identity(&after)
            && identity(&before) == identity(&current)
            && current.is_file(),
        "private bytes changed during observation"
    );
    Ok(bytes)
}

fn observe(selection: Selection) -> Result<Vec<Observed>> {
    ensure!(
        selection.version == 1 && !selection.pairs.is_empty() && selection.pairs.len() <= MAX_PAIRS,
        "observation geometry differs"
    );
    let public: [u8; 32] = hex::decode(selection.issuer_public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public issuer pin length differs"))?;
    let verifier = EpochLeaseVerifier::from_bytes(selection.issuer_key_id, &public)?;
    let mut nonces = BTreeSet::new();
    let mut aggregate = 0usize;
    let mut results = Vec::with_capacity(selection.pairs.len());
    for pair in selection.pairs {
        ensure!(
            nonces.insert(pair.owner_nonce.clone()),
            "duplicate issuer owner original"
        );
        for size in [pair.request_bytes, pair.reply_bytes] {
            ensure!(
                size > 0 && size <= MAX_ISSUER_CONTROL_BYTES,
                "issuer body exceeds wire bound"
            );
            aggregate = aggregate
                .checked_add(size)
                .context("aggregate observation overflow")?;
            ensure!(
                aggregate <= MAX_AGGREGATE,
                "aggregate observation bound exceeded"
            );
        }
        let request_bytes = private_bytes(&pair.request_file, MAX_ISSUER_CONTROL_BYTES)?;
        let reply_bytes = private_bytes(&pair.reply_file, MAX_ISSUER_CONTROL_BYTES)?;
        ensure!(
            request_bytes.len() == pair.request_bytes
                && digest(&request_bytes) == pair.request_sha256
                && reply_bytes.len() == pair.reply_bytes
                && digest(&reply_bytes) == pair.reply_sha256,
            "observed files differ from actual captured transport"
        );
        let request = IssuerRequest::decode(&request_bytes)?;
        ensure!(
            request.nonce == pair.owner_nonce,
            "captured owner nonce differs"
        );
        ensure!(
            matches!(request.operation, IssuerOperation::Issue { .. }),
            "only actual lease issuance is observed"
        );
        let reply = verify_issuer_reply(&verifier, &request, &reply_bytes)?;
        let token = reply
            .lease
            .as_ref()
            .context("observed reply has no positive lease")?;
        // The shared reply verifier already authenticated this exact inner
        // token and correlated its complete payload with the original. Parsing
        // it here only selects public fields for historical observation.
        let payload = serde_json::from_str::<AuthenticatedTokenProjection>(token)?.payload;
        results.push(Observed {
            owner_nonce: request.nonce,
            request_sha256: pair.request_sha256,
            request_bytes: pair.request_bytes,
            reply_sha256: pair.reply_sha256,
            reply_bytes: pair.reply_bytes,
            cohort_digest: digest(&serde_json::to_vec(&payload.cohort)?),
            lease_digest: digest(token.as_bytes()),
            lease_sequence: payload.lease_sequence.get(),
            issued_at: payload.issued_at.get(),
            not_after: payload.not_after.get(),
            attestation_valid_until: payload.cohort.attestation_valid_until.get(),
            scope: "historical signature/original evidence; no current permission or clock qualification",
        });
    }
    Ok(results)
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 2,
        "expected private selection and new private output"
    );
    let selection_bytes = private_bytes(Path::new(&arguments[0]), 1024 * 1024)?;
    let result = observe(serde_json::from_slice(&selection_bytes)?)?;
    let output_path = Path::new(&arguments[1]);
    ensure!(output_path.is_absolute(), "output must be absolute");
    let parent = output_path.parent().context("output parent is absent")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o077 == 0
            && std::fs::canonicalize(parent)? == parent,
        "output parent is not private"
    );
    let output = serde_json::to_vec(&result)?;
    ensure!(
        output.len() <= 4 * 1024 * 1024,
        "observation output exceeded bound"
    );
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output_path)?;
    target.write_all(&output)?;
    target.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    fn private_root() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aos-lease-observation-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn exact_private_bytes_refuse_size_mode_and_symlink_substitutions() {
        let root = private_root();
        let path = root.join("body");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        output.write_all(b"actual retained fixture bytes").unwrap();
        output.sync_all().unwrap();
        assert_eq!(
            private_bytes(&path, 128).unwrap(),
            b"actual retained fixture bytes"
        );
        assert!(private_bytes(&path, 4).is_err());

        let link = root.join("link");
        symlink(&path, &link).unwrap();
        assert!(private_bytes(&link, 128).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_bytes(&path, 128).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_and_excessive_pair_inventories_refuse_before_file_access() {
        let selection = Selection {
            version: 1,
            issuer_key_id: "fixture".into(),
            issuer_public_key: "not-a-key".into(),
            pairs: vec![],
        };
        assert!(observe(selection)
            .unwrap_err()
            .to_string()
            .contains("geometry"));
        let pairs = (0..=MAX_PAIRS)
            .map(|index| Pair {
                owner_nonce: format!("{index:064x}"),
                request_file: PathBuf::from("/missing/request"),
                request_sha256: "1".repeat(64),
                request_bytes: 1,
                reply_file: PathBuf::from("/missing/reply"),
                reply_sha256: "2".repeat(64),
                reply_bytes: 1,
            })
            .collect();
        let selection = Selection {
            version: 1,
            issuer_key_id: "fixture".into(),
            issuer_public_key: "not-a-key".into(),
            pairs,
        };
        assert!(observe(selection)
            .unwrap_err()
            .to_string()
            .contains("geometry"));
    }

    #[test]
    fn projection_shapes_refuse_unknown_fields_without_permission_output() {
        let bytes = br#"{"version":1,"issuerKeyId":"fixture","issuerPublicKey":"fixture","pairs":[],"accepted":true}"#;
        assert!(serde_json::from_slice::<Selection>(bytes).is_err());
    }
}
