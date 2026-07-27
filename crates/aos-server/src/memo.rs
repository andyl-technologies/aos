//! L3 network memo tier: content-addressed root-record and compiled-body bundles.
//!
//! This is the server side of the RFC-0007 doc 29 §5.5 network memo tier that
//! the evaluator's `memo_net` client speaks to. The wire protocol is a
//! deliberately dumb content-addressed store:
//!
//! ```text
//! GET /v1/root/{key-hex}            -> 200 + root-record bundle   | 404 miss
//! PUT /v1/root/{key-hex}            <- root-record bundle          (writable only)
//! GET /v1/compiled-body/{key-hex}   -> 200 + compiled-body bundle | 404 miss
//! PUT /v1/compiled-body/{key-hex}   <- compiled-body bundle        (writable only)
//! ```
//!
//! `key-hex` is the 64-character lowercase hex of a 32-byte content key. Bundles
//! are stored opaquely — the server is a **validation catalog, never an
//! authority** (RFC-0006's principle applied to eval caching): it never decodes
//! or trusts a bundle, because the fetching evaluator re-hashes the bundle to
//! its key and revalidates the record's impure-input slice against the local
//! world before use. A poisoned or stale store therefore causes misses and
//! wasted fetches, never wrong output.
//!
//! Reads are always open. Writes are gated by [`MemoConfig::writable`]: a public
//! read mirror leaves it `false` and rejects `PUT`, while a trusted CI/builder
//! publisher sets it `true`.
//!
//! Bundles live under `{aos_root}/memo/{root,compiled-body}/{key-hex}`.

use std::io;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::routes::AppState;

/// The largest memo bundle the endpoint will store or serve.
///
/// Comfortably above a full root closure bundle or a compiled-body bundle;
/// larger uploads are rejected rather than trusted.
pub const MAX_MEMO_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Which content-addressed bundle namespace a request targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoKind {
    /// A durable root-instantiation record bundle (`/v1/root/...`).
    RootRecord,
    /// A tier-2 compiled-body bundle (`/v1/compiled-body/...`).
    CompiledBody,
}

impl MemoKind {
    /// Returns the on-disk subdirectory name for this namespace.
    const fn dir_name(self) -> &'static str {
        match self {
            Self::RootRecord => "root",
            Self::CompiledBody => "compiled-body",
        }
    }
}

/// The outcome of a memo bundle fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoFetch {
    /// The bundle was found; its opaque bytes are attached.
    Found(Vec<u8>),
    /// No bundle is stored for the key (a miss).
    NotFound,
    /// The key was not a well-formed 64-character lowercase-hex digest.
    BadKey,
}

/// The outcome of a memo bundle publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoPublish {
    /// The bundle was stored (or an identical one already existed).
    Stored,
    /// The store is a read-only mirror; the write was refused.
    ReadOnly,
    /// The key was not a well-formed 64-character lowercase-hex digest.
    BadKey,
    /// The body was empty or exceeded [`MAX_MEMO_BUNDLE_BYTES`].
    BadBody,
    /// The bundle could not be written to disk.
    IoError,
}

/// A filesystem-backed content-addressed memo bundle store.
///
/// Bundles are files named by their 64-hex key under a per-namespace directory;
/// writes are atomic (temp file plus rename) so a concurrent fetch never
/// observes a partial bundle.
#[derive(Clone, Debug)]
pub struct MemoStore {
    root: PathBuf,
    writable: bool,
}

impl MemoStore {
    /// Creates a memo store rooted at `root`, accepting writes iff `writable`.
    pub fn new(root: impl Into<PathBuf>, writable: bool) -> Self {
        Self {
            root: root.into(),
            writable,
        }
    }

    /// Returns whether this store accepts `PUT` publishes.
    pub const fn writable(&self) -> bool {
        self.writable
    }

    /// Returns the bundle path for a validated key, or `None` for a bad key.
    fn bundle_path(&self, kind: MemoKind, key_hex: &str) -> Option<PathBuf> {
        if !is_valid_key_hex(key_hex) {
            return None;
        }
        Some(self.root.join(kind.dir_name()).join(key_hex))
    }

    /// Fetches the opaque bundle bytes stored for `key_hex`.
    ///
    /// Returns [`MemoFetch::BadKey`] for a malformed key, [`MemoFetch::NotFound`]
    /// when nothing is stored, and [`MemoFetch::Found`] otherwise. A read error
    /// on an existing file is treated as a miss so a corrupt file never fails a
    /// request (the fetcher revalidates content regardless).
    pub fn fetch(&self, kind: MemoKind, key_hex: &str) -> MemoFetch {
        let Some(path) = self.bundle_path(kind, key_hex) else {
            return MemoFetch::BadKey;
        };
        match std::fs::read(&path) {
            Ok(bytes) => MemoFetch::Found(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => MemoFetch::NotFound,
            Err(error) => {
                tracing::debug!(
                    target: "aos_server::memo",
                    path = %path.display(),
                    error = %error,
                    "memo bundle read failed; treating it as a miss"
                );
                MemoFetch::NotFound
            }
        }
    }

    /// Stores `bytes` as the bundle for `key_hex`.
    ///
    /// Refuses the write with [`MemoPublish::ReadOnly`] on a non-writable store,
    /// [`MemoPublish::BadKey`] for a malformed key, and [`MemoPublish::BadBody`]
    /// for an empty or oversized body. The bundle content is not decoded — the
    /// store is content-addressed and the fetcher validates on read.
    pub fn publish(&self, kind: MemoKind, key_hex: &str, bytes: &[u8]) -> MemoPublish {
        if !self.writable {
            return MemoPublish::ReadOnly;
        }
        let Some(path) = self.bundle_path(kind, key_hex) else {
            return MemoPublish::BadKey;
        };
        if bytes.is_empty() || bytes.len() > MAX_MEMO_BUNDLE_BYTES {
            return MemoPublish::BadBody;
        }
        match write_atomic(&path, bytes) {
            Ok(()) => MemoPublish::Stored,
            Err(error) => {
                tracing::warn!(
                    target: "aos_server::memo",
                    path = %path.display(),
                    error = %error,
                    "memo bundle write failed"
                );
                MemoPublish::IoError
            }
        }
    }
}

/// Returns whether `key` is a 64-character lowercase-hex digest.
///
/// This is both a format check and the path-safety gate: a valid key has no
/// separators, `..`, or non-hex bytes, so it can never escape its namespace
/// directory.
fn is_valid_key_hex(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Writes `bytes` to `path` atomically: create parents, write a temp sibling,
/// then rename it over the destination.
fn write_atomic(path: &FsPath, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl IntoResponse for MemoFetch {
    fn into_response(self) -> Response {
        match self {
            Self::Found(bytes) => (StatusCode::OK, bytes).into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "no such record").into_response(),
            Self::BadKey => (StatusCode::BAD_REQUEST, "invalid record key").into_response(),
        }
    }
}

impl IntoResponse for MemoPublish {
    fn into_response(self) -> Response {
        match self {
            Self::Stored => StatusCode::OK.into_response(),
            Self::ReadOnly => (StatusCode::FORBIDDEN, "memo endpoint is read-only").into_response(),
            Self::BadKey => (StatusCode::BAD_REQUEST, "invalid record key").into_response(),
            Self::BadBody => (StatusCode::BAD_REQUEST, "invalid record body").into_response(),
            Self::IoError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "record store failed").into_response()
            }
        }
    }
}

/// `GET /v1/root/{key}` — serve a root-record bundle.
pub async fn root_record_get(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Response {
    state.memo.fetch(MemoKind::RootRecord, &key).into_response()
}

/// `PUT /v1/root/{key}` — publish a root-record bundle (writable stores only).
pub async fn root_record_put(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    state
        .memo
        .publish(MemoKind::RootRecord, &key, &body)
        .into_response()
}

/// `GET /v1/compiled-body/{key}` — serve a compiled-body bundle.
pub async fn compiled_body_get(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Response {
    state
        .memo
        .fetch(MemoKind::CompiledBody, &key)
        .into_response()
}

/// `PUT /v1/compiled-body/{key}` — publish a compiled-body bundle (writable only).
pub async fn compiled_body_put(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    state
        .memo
        .publish(MemoKind::CompiledBody, &key, &body)
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: &str) -> String {
        fill.repeat(64 / fill.len())
    }

    #[test]
    fn valid_key_hex_accepts_64_lowercase_hex_only() {
        assert!(is_valid_key_hex(&key("a")));
        assert!(is_valid_key_hex(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_key_hex(&key("A")), "uppercase is rejected");
        assert!(!is_valid_key_hex(&key("g")), "non-hex is rejected");
        assert!(!is_valid_key_hex("abcd"), "short is rejected");
        assert!(!is_valid_key_hex(&"a".repeat(65)), "long is rejected");
        assert!(
            !is_valid_key_hex("../../etc/passwd"),
            "traversal is rejected"
        );
    }

    #[test]
    fn writable_store_round_trips_and_isolates_namespaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = MemoStore::new(dir.path(), true);
        let k = key("a");

        assert_eq!(store.fetch(MemoKind::RootRecord, &k), MemoFetch::NotFound);
        assert_eq!(
            store.publish(MemoKind::RootRecord, &k, b"root-bundle-bytes"),
            MemoPublish::Stored
        );
        assert_eq!(
            store.fetch(MemoKind::RootRecord, &k),
            MemoFetch::Found(b"root-bundle-bytes".to_vec())
        );
        // The same key in the compiled-body namespace is independent.
        assert_eq!(store.fetch(MemoKind::CompiledBody, &k), MemoFetch::NotFound);
        assert_eq!(
            store.publish(MemoKind::CompiledBody, &k, b"body-bundle-bytes"),
            MemoPublish::Stored
        );
        assert_eq!(
            store.fetch(MemoKind::CompiledBody, &k),
            MemoFetch::Found(b"body-bundle-bytes".to_vec())
        );
    }

    #[test]
    fn read_only_store_refuses_writes_but_still_serves() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Seed a bundle through a writable handle, then reopen read-only.
        let seeded = MemoStore::new(dir.path(), true);
        let k = key("b");
        assert_eq!(
            seeded.publish(MemoKind::RootRecord, &k, b"seed"),
            MemoPublish::Stored
        );

        let mirror = MemoStore::new(dir.path(), false);
        assert!(!mirror.writable());
        assert_eq!(
            mirror.publish(MemoKind::RootRecord, &k, b"nope"),
            MemoPublish::ReadOnly
        );
        // The read-only refusal must not have overwritten the seeded bytes.
        assert_eq!(
            mirror.fetch(MemoKind::RootRecord, &k),
            MemoFetch::Found(b"seed".to_vec())
        );
    }

    #[test]
    fn bad_keys_and_bodies_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = MemoStore::new(dir.path(), true);
        assert_eq!(
            store.fetch(MemoKind::RootRecord, "short"),
            MemoFetch::BadKey
        );
        assert_eq!(
            store.publish(MemoKind::RootRecord, "short", b"x"),
            MemoPublish::BadKey
        );
        assert_eq!(
            store.publish(MemoKind::RootRecord, &key("a"), b""),
            MemoPublish::BadBody
        );
        assert_eq!(
            store.publish(
                MemoKind::RootRecord,
                &key("a"),
                &vec![0u8; MAX_MEMO_BUNDLE_BYTES + 1]
            ),
            MemoPublish::BadBody
        );
    }
}
