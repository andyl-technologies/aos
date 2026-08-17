//! HTTP client for the L3 network memo tier (RFC-0007 doc 29 §5.5, MEMO-2).
//!
//! Speaks a deliberately dumb content-addressed record protocol against the
//! `AOS_NIX_MEMO_NET` endpoint:
//!
//! ```text
//! GET {endpoint}/v1/root/{key-hex}   -> 200 + root-record bundle bytes
//!                                       404 = no such record (a miss)
//! PUT {endpoint}/v1/root/{key-hex}   <- root-record bundle bytes (rw mode only)
//! GET {endpoint}/v1/compiled-body/{key-hex} -> 200 + compiled-body bundle
//! PUT {endpoint}/v1/compiled-body/{key-hex} <- compiled-body bundle (rw only)
//! ```
//!
//! `key-hex` is the lowercase hex of the 32-byte root-cutoff key, and the
//! body is the self-validating [`RootRecordBundle`] wire format. The endpoint
//! is never trusted: fetched bytes are fully content-validated by the bundle
//! codec, and the caller additionally revalidates the record's impure-input
//! slice against the local world before use. Every network failure — refused
//! connections, timeouts, bad statuses, malformed bundles — degrades to a
//! cache miss and latches a **process-wide backoff** that disables further
//! network probes for this process, so an unreachable endpoint costs one
//! timeout per process, not one per instantiation. Nothing on this path can
//! fail an evaluation.

use std::fmt::Write as _;
use std::io::Read as _;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::cache::{
    PersistFileArtifactKey, PersistFileBlobHash, PersistRootRecordKey, RootRecordBundle,
};
use crate::eval::MemoNetOptions;

const COMPILED_BODY_BUNDLE_MAGIC: [u8; 16] = *b"AOS-NIX-JITBNDL\0";
const COMPILED_BODY_BUNDLE_VERSION: u32 = 1;
const COMPILED_BODY_BUNDLE_HEADER_LEN: usize = 92;
const MAX_COMPILED_BODY_RECORD_BYTES: usize = 32 * 1024 * 1024;
const MAX_COMPILED_BODY_BUNDLE_BYTES: u64 =
    (COMPILED_BODY_BUNDLE_HEADER_LEN + MAX_COMPILED_BODY_RECORD_BYTES) as u64;

/// Process-wide backoff latch: set after any transport-level failure.
static NET_BACKOFF: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static NET_TEST_LOCK: Mutex<()> = Mutex::new(());

/// The outcome of one network record fetch.
pub(super) enum NetFetchOutcome {
    /// The endpoint returned a bundle that passed full content validation.
    Hit(RootRecordBundle),
    /// The endpoint answered "no such record".
    Miss,
    /// Transport or validation failed; the record is treated as a miss.
    Error,
}

/// The outcome of one compiled-body network fetch.
pub(crate) enum CompiledBodyFetchOutcome {
    /// The endpoint returned a bundle whose key and content hash validated.
    Hit(Vec<u8>),
    /// The endpoint answered "no such record".
    Miss,
    /// Transport, bounds, key, or content validation failed.
    Error,
}

/// Fetches and content-validates a root-record bundle for `key`.
///
/// Returns [`NetFetchOutcome::Error`] (and latches the process-wide backoff
/// for transport failures) instead of ever propagating a failure.
pub(super) fn fetch_root_record_bundle(
    net: &MemoNetOptions,
    key: PersistRootRecordKey,
) -> NetFetchOutcome {
    if NET_BACKOFF.load(Ordering::Relaxed) {
        return NetFetchOutcome::Error;
    }
    let url = record_url(net, key);
    let client = match client(net) {
        Some(client) => client,
        None => return NetFetchOutcome::Error,
    };
    let response = match client.get(&url).send() {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "network memo fetch failed; backing off for this process"
            );
            NET_BACKOFF.store(true, Ordering::Relaxed);
            return NetFetchOutcome::Error;
        }
    };
    if response.status().as_u16() == 404 {
        return NetFetchOutcome::Miss;
    }
    if !response.status().is_success() {
        tracing::debug!(
            target: "aos_nix::cache",
            url,
            status = response.status().as_u16(),
            "network memo fetch returned a non-success status"
        );
        return NetFetchOutcome::Error;
    }
    let bytes = match response.bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "network memo fetch body read failed; backing off for this process"
            );
            NET_BACKOFF.store(true, Ordering::Relaxed);
            return NetFetchOutcome::Error;
        }
    };
    match RootRecordBundle::decode(&bytes) {
        Ok(bundle) => NetFetchOutcome::Hit(bundle),
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "network memo record failed content validation; rejecting it"
            );
            NetFetchOutcome::Error
        }
    }
}

/// Publishes a root-record bundle for `key` (rw mode; best-effort).
///
/// Returns whether the endpoint acknowledged the record. Failures are logged
/// at debug level and latch the process-wide backoff for transport errors.
pub(super) fn publish_root_record_bundle(
    net: &MemoNetOptions,
    key: PersistRootRecordKey,
    bundle: &RootRecordBundle,
) -> bool {
    if NET_BACKOFF.load(Ordering::Relaxed) {
        return false;
    }
    let bytes = match bundle.encode() {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "network memo bundle encode failed"
            );
            return false;
        }
    };
    let url = record_url(net, key);
    let Some(client) = client(net) else {
        return false;
    };
    match client.put(&url).body(bytes).send() {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                status = response.status().as_u16(),
                "network memo publish returned a non-success status"
            );
            false
        }
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "network memo publish failed; backing off for this process"
            );
            NET_BACKOFF.store(true, Ordering::Relaxed);
            false
        }
    }
}

/// Fetches and content-validates a compiled-body record for `key`.
///
/// The returned bytes have passed the network envelope's expected-key,
/// bounded-length, and independent payload-hash checks. The compiled-body
/// cache must still validate the record schema and semantic identity and run
/// the CLIF decoder/verifier before using them.
pub(crate) fn fetch_compiled_body_record(
    net: &MemoNetOptions,
    key: PersistFileArtifactKey,
) -> CompiledBodyFetchOutcome {
    if NET_BACKOFF.load(Ordering::Relaxed) {
        return CompiledBodyFetchOutcome::Error;
    }
    let url = compiled_body_url(net, key);
    let client = match client(net) {
        Some(client) => client,
        None => return CompiledBodyFetchOutcome::Error,
    };
    let response = match client.get(&url).send() {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "compiled-body network fetch failed; backing off for this process"
            );
            NET_BACKOFF.store(true, Ordering::Relaxed);
            return CompiledBodyFetchOutcome::Error;
        }
    };
    if response.status().as_u16() == 404 {
        return CompiledBodyFetchOutcome::Miss;
    }
    if !response.status().is_success() {
        tracing::debug!(
            target: "aos_nix::cache",
            url,
            status = response.status().as_u16(),
            "compiled-body network fetch returned a non-success status"
        );
        return CompiledBodyFetchOutcome::Error;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_COMPILED_BODY_BUNDLE_BYTES)
    {
        tracing::debug!(
            target: "aos_nix::cache",
            url,
            "compiled-body network bundle exceeds the size limit"
        );
        return CompiledBodyFetchOutcome::Error;
    }
    let mut bytes = Vec::new();
    let mut reader = response.take(MAX_COMPILED_BODY_BUNDLE_BYTES.saturating_add(1));
    if let Err(error) = reader.read_to_end(&mut bytes) {
        tracing::debug!(
            target: "aos_nix::cache",
            url,
            error = %error,
            "compiled-body network body read failed; backing off for this process"
        );
        NET_BACKOFF.store(true, Ordering::Relaxed);
        return CompiledBodyFetchOutcome::Error;
    }
    if bytes.len() as u64 > MAX_COMPILED_BODY_BUNDLE_BYTES {
        tracing::debug!(
            target: "aos_nix::cache",
            url,
            "chunked compiled-body network bundle exceeds the size limit"
        );
        return CompiledBodyFetchOutcome::Error;
    }
    match decode_compiled_body_bundle(&bytes, key) {
        Ok(record) => CompiledBodyFetchOutcome::Hit(record),
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                ?error,
                "compiled-body network bundle failed validation"
            );
            CompiledBodyFetchOutcome::Error
        }
    }
}

/// Publishes a self-validating compiled-body bundle for `key` (best-effort).
///
/// Returns whether the endpoint acknowledged the record. The caller owns the
/// `rw` policy gate; transport failures latch the shared network backoff.
pub(crate) fn publish_compiled_body_record(
    net: &MemoNetOptions,
    key: PersistFileArtifactKey,
    record: &[u8],
) -> bool {
    if NET_BACKOFF.load(Ordering::Relaxed) {
        return false;
    }
    let Some(bytes) = encode_compiled_body_bundle(key, record) else {
        tracing::debug!(
            target: "aos_nix::cache",
            "compiled-body record exceeds the network bundle size limit"
        );
        return false;
    };
    let url = compiled_body_url(net, key);
    let Some(client) = client(net) else {
        return false;
    };
    match client.put(&url).body(bytes).send() {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                status = response.status().as_u16(),
                "compiled-body network publish returned a non-success status"
            );
            false
        }
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                url,
                error = %error,
                "compiled-body network publish failed; backing off for this process"
            );
            NET_BACKOFF.store(true, Ordering::Relaxed);
            false
        }
    }
}

/// Clears the process-wide backoff latch (tests only).
#[cfg(test)]
pub(super) fn reset_backoff_for_tests() {
    NET_BACKOFF.store(false, Ordering::Relaxed);
}

/// Serializes network tests around the process-wide transport backoff latch.
#[cfg(test)]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = NET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_backoff_for_tests();
    guard
}

/// Builds the content-addressed record URL for `key`.
fn record_url(net: &MemoNetOptions, key: PersistRootRecordKey) -> String {
    let mut hex = String::with_capacity(64);
    for byte in key.hash().as_bytes() {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    format!("{}/v1/root/{hex}", net.endpoint.trim_end_matches('/'))
}

fn compiled_body_url(net: &MemoNetOptions, key: PersistFileArtifactKey) -> String {
    format!(
        "{}/v1/compiled-body/{}",
        net.endpoint.trim_end_matches('/'),
        key.hash().to_hex()
    )
}

fn encode_compiled_body_bundle(key: PersistFileArtifactKey, record: &[u8]) -> Option<Vec<u8>> {
    if record.len() > MAX_COMPILED_BODY_RECORD_BYTES {
        return None;
    }
    let record_len = u64::try_from(record.len()).ok()?;
    let record_hash = PersistFileBlobHash::for_payload(record);
    let mut bytes =
        Vec::with_capacity(COMPILED_BODY_BUNDLE_HEADER_LEN.saturating_add(record.len()));
    bytes.extend_from_slice(&COMPILED_BODY_BUNDLE_MAGIC);
    bytes.extend_from_slice(&COMPILED_BODY_BUNDLE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&key.hash().as_bytes());
    bytes.extend_from_slice(&record_hash.as_durable_hash().as_bytes());
    bytes.extend_from_slice(&record_len.to_le_bytes());
    bytes.extend_from_slice(record);
    Some(bytes)
}

fn decode_compiled_body_bundle(
    bytes: &[u8],
    expected_key: PersistFileArtifactKey,
) -> Result<Vec<u8>, CompiledBodyBundleError> {
    if bytes.len() > MAX_COMPILED_BODY_BUNDLE_BYTES as usize {
        return Err(CompiledBodyBundleError::Oversized);
    }
    let header = bytes
        .get(..COMPILED_BODY_BUNDLE_HEADER_LEN)
        .ok_or(CompiledBodyBundleError::Truncated)?;
    if header.get(..16) != Some(COMPILED_BODY_BUNDLE_MAGIC.as_slice()) {
        return Err(CompiledBodyBundleError::BadMagic);
    }
    let version = u32::from_le_bytes(
        header
            .get(16..20)
            .ok_or(CompiledBodyBundleError::Truncated)?
            .try_into()
            .map_err(|_| CompiledBodyBundleError::Truncated)?,
    );
    if version != COMPILED_BODY_BUNDLE_VERSION {
        return Err(CompiledBodyBundleError::UnsupportedVersion);
    }
    if header.get(20..52) != Some(expected_key.hash().as_bytes().as_slice()) {
        return Err(CompiledBodyBundleError::WrongKey);
    }
    let declared_hash = header
        .get(52..84)
        .ok_or(CompiledBodyBundleError::Truncated)?;
    let record_len = u64::from_le_bytes(
        header
            .get(84..92)
            .ok_or(CompiledBodyBundleError::Truncated)?
            .try_into()
            .map_err(|_| CompiledBodyBundleError::Truncated)?,
    );
    let record = bytes
        .get(COMPILED_BODY_BUNDLE_HEADER_LEN..)
        .ok_or(CompiledBodyBundleError::Truncated)?;
    if record_len > MAX_COMPILED_BODY_RECORD_BYTES as u64
        || u64::try_from(record.len()).ok() != Some(record_len)
    {
        return Err(CompiledBodyBundleError::InvalidLength);
    }
    let actual_hash = PersistFileBlobHash::for_payload(record)
        .as_durable_hash()
        .as_bytes();
    if declared_hash != actual_hash.as_slice() {
        return Err(CompiledBodyBundleError::ContentHashMismatch);
    }
    Ok(record.to_vec())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompiledBodyBundleError {
    Truncated,
    Oversized,
    BadMagic,
    UnsupportedVersion,
    WrongKey,
    InvalidLength,
    ContentHashMismatch,
}

/// Builds a blocking client with the configured request timeout.
fn client(net: &MemoNetOptions) -> Option<reqwest::blocking::Client> {
    match reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(net.timeout_ms))
        .connect_timeout(Duration::from_millis(net.timeout_ms))
        .build()
    {
        Ok(client) => Some(client),
        Err(error) => {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "network memo client construction failed"
            );
            None
        }
    }
}
