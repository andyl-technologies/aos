//! HTTP client for the L3 network memo tier (RFC-0007 doc 29 §5.5, MEMO-2).
//!
//! Speaks a deliberately dumb content-addressed record protocol against the
//! `AOS_NIX_MEMO_NET` endpoint:
//!
//! ```text
//! GET {endpoint}/v1/root/{key-hex}   -> 200 + root-record bundle bytes
//!                                       404 = no such record (a miss)
//! PUT {endpoint}/v1/root/{key-hex}   <- root-record bundle bytes (rw mode only)
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::cache::{PersistRootRecordKey, RootRecordBundle};
use crate::eval::MemoNetOptions;

/// Process-wide backoff latch: set after any transport-level failure.
static NET_BACKOFF: AtomicBool = AtomicBool::new(false);

/// The outcome of one network record fetch.
pub(super) enum NetFetchOutcome {
    /// The endpoint returned a bundle that passed full content validation.
    Hit(RootRecordBundle),
    /// The endpoint answered "no such record".
    Miss,
    /// Transport or validation failed; the record is treated as a miss.
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

/// Clears the process-wide backoff latch (tests only).
#[cfg(test)]
pub(super) fn reset_backoff_for_tests() {
    NET_BACKOFF.store(false, Ordering::Relaxed);
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
