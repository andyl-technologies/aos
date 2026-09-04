//! The surface-write port: how the shared service mutates a registry's bytes.
//!
//! This is the write sibling of [`crate::fetch`]. The read port
//! ([`SurfaceFetch`](crate::fetch::SurfaceFetch)) lets the facade and the git
//! walk *read* a registry's wire surface from whatever store backs the
//! deployment; this port lets the shared console *write* to it — the
//! git-backed configuration change-request flow commits a draft to
//! `refs/hub/changes/<id>` and writes the loose blob/tree/commit objects it
//! references.
//!
//! - [`SurfaceWrite`] — atomically write or delete one surface path. This is
//!   the RFC's "Blobs" port, write side: the loose-object and ref writes the
//!   git-backed change-request flow performs go through it.
//! - [`SurfaceWriteProvider`] — resolve the [`SurfaceWrite`] for a given
//!   registry. The native hub returns a filesystem writer rooted at the
//!   registry's binding; the Worker returns an R2-backed writer scoped
//!   to the registry's prefix.
//!
//! Both carry the same target-conditional bound as the rest of the core ports
//! ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker (whose R2 futures are `?Send`).
//!
//! # Path semantics
//!
//! Every `path` is a **logical, registry-relative surface path** — the same
//! space the read port uses (`objects/ab/cdef…`, `refs/hub/changes/<id>`),
//! never a host filesystem path or an R2 key. The implementation owns the
//! mapping to its store and is responsible for path safety: the native writer
//! rejects `..`/absolute components lexically and then symlink-canonicalizes the
//! parent and requires it to stay under the storage root (the same containment
//! the read port enforces), and the R2 writer maps through the flat key space
//! where traversal is not expressible.

use anyhow::Result;
use md5::{Digest as _, Md5};

use crate::backend::BackendBounds;
use crate::db::{BindingWriteRevisionRecord, SurfacePlacementRecord};

/// One multipart-upload part's identity: its 1-based `part_number` and the
/// backend's entity tag.
///
/// `etag` is the value the backend returns for an uploaded part and requires
/// back at completion. S3/R2 return their native opaque ETag; local disk
/// returns a SHA-256 tag and verifies it before assembly. The hub and client
/// carry the value through the wire protocol and echo the full ordered set
/// back at [`complete`](SurfaceWrite::complete_multipart).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartTag {
    /// 1-based, contiguous part index.
    pub part_number: u32,
    /// Backend-returned part identity.
    pub etag: String,
}

/// Immutable backend identity required by a physical deletion request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDeletePrecondition {
    /// Exact entity tag, when supplied by the inventory backend.
    pub etag: Option<String>,
    /// Exact content hash, when supplied by inventory.
    pub content_hash: Option<String>,
    /// Exact object size, when supplied by inventory.
    pub size: Option<i64>,
}

/// Immutable physical address and topology fence for one provider operation.
///
/// Durable cleanup claims construct this value from their reviewed snapshot;
/// adapters must use [`Self::placement_prefix`] directly and must never select
/// a current writer. A binding row may be reopened only when its id and
/// resource version still match this fence. Plan and Apply validate the current
/// conditional-delete capability, while the durable claim revalidates this
/// frozen snapshot and its retained credential hold. The adapter therefore
/// resolves the exact frozen credential without consulting a capability or
/// credential head that may legitimately advance after Apply. The frozen
/// capability identity remains part of durable audit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenSurfaceAccess {
    /// Registry whose physical object is being inspected or deleted.
    pub registry_id: i64,
    /// Frozen placement database id.
    pub placement_id: i64,
    /// Frozen placement display name for bounded diagnostics.
    pub placement_name: String,
    /// Frozen binding-relative placement prefix.
    pub placement_prefix: String,
    /// Frozen placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Frozen placement writer-critical topology version.
    pub placement_write_spec_version: i64,
    /// Frozen ready/complete observation version.
    pub placement_observation_version: i64,
    /// Frozen storage binding id.
    pub binding_id: i64,
    /// Frozen binding optimistic-concurrency version.
    pub binding_resource_version: i64,
    /// Frozen immutable binding-write revision.
    pub binding_write_revision: i64,
    /// Exact delete credential purpose, absent for credential-free local IO.
    pub delete_credential_purpose: Option<String>,
    /// Exact delete credential generation, absent for credential-free local IO.
    pub delete_credential_generation: Option<i64>,
    /// Fingerprint of the positively observed conditional-delete capability.
    pub delete_capability_fingerprint: String,
    /// Minimum capability observation resource version frozen for audit.
    pub delete_capability_resource_version: i64,
}

impl FrozenSurfaceAccess {
    /// Validates the common frozen-address fence.
    ///
    /// # Errors
    ///
    /// Returns an error for missing identities, invalid versions, an unsafe
    /// prefix, or a half-populated delete credential pair.
    pub fn validate(&self) -> Result<()> {
        if self.registry_id <= 0
            || self.placement_id <= 0
            || self.placement_name.is_empty()
            || self.placement_name.len() > 255
            || self.placement_resource_version <= 0
            || self.placement_write_spec_version <= 0
            || self.placement_observation_version <= 0
            || self.binding_id <= 0
            || self.binding_resource_version <= 0
            || self.binding_write_revision <= 0
            || self.delete_capability_fingerprint.is_empty()
            || self.delete_capability_fingerprint.len() > 255
            || self.delete_capability_resource_version <= 0
            || self.delete_credential_purpose.is_some()
                != self.delete_credential_generation.is_some()
            || self
                .delete_credential_generation
                .is_some_and(|generation| generation <= 0)
        {
            anyhow::bail!("frozen surface access fence is invalid");
        }
        if self.placement_prefix.len() > 512
            || self.placement_prefix != self.placement_prefix.trim_matches('/')
            || self.placement_prefix != self.placement_prefix.trim()
            || self.placement_prefix.contains("//")
            || self
                .placement_prefix
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            || self.placement_prefix.chars().any(char::is_control)
        {
            anyhow::bail!("frozen surface access prefix is invalid");
        }
        Ok(())
    }
}

/// Verified result of an identity-checked backend deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceDeleteOutcome {
    /// The backend returned the deleted object's independently observed identity.
    Deleted {
        /// Entity tag accepted by the backend.
        etag: Option<String>,
        /// Hash accepted by the backend.
        content_hash: Option<String>,
        /// Size accepted by the backend.
        size: Option<i64>,
    },
    /// An HTTP backend acknowledged an atomic delete guarded by this ETag.
    ///
    /// S3-compatible DELETE responses do not return object hash or size. A 2xx
    /// response instead proves that the submitted strong `If-Match` condition
    /// was accepted. Callers must bind this ETag to separately verified
    /// inventory hash and size, and must require an observed valid conditional-
    /// delete capability for the exact backend revision.
    ConditionalDeleteAcknowledged {
        /// Canonical strong ETag submitted in the successful condition.
        etag: String,
    },
    /// The object was already absent.
    NotFound,
    /// A live object no longer matched the reviewed inventory identity.
    PreconditionFailed {
        /// Sanitized backend explanation.
        detail: String,
    },
}

/// Durable-cleanup significance of a multipart abort attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipartAbortOutcome {
    /// The backend confirmed that the staged upload was aborted.
    Aborted,
    /// The backend confirmed that no staged upload exists.
    Absent,
    /// The backend cannot distinguish an absent upload from one already completed.
    PossiblyCompleted,
}

/// Formats an inventory ETag as one strong HTTP `If-Match` entity tag.
///
/// # Errors
///
/// Returns an error for an empty, weak, quoted-malformed, or control-bearing
/// value.
pub fn strong_if_match_etag(etag: &str) -> Result<String> {
    let etag = etag.trim();
    if etag.is_empty() || etag.starts_with("W/") {
        anyhow::bail!("inventory ETag is not a strong HTTP entity tag");
    }
    if etag.starts_with('"') || etag.ends_with('"') {
        if etag.len() < 2 || !etag.starts_with('"') || !etag.ends_with('"') {
            anyhow::bail!("inventory ETag has malformed quotes");
        }
        if etag[1..etag.len() - 1]
            .bytes()
            .any(|byte| byte < 0x21 || byte == b'"' || byte == b'\\' || byte == 0x7f)
        {
            anyhow::bail!("inventory ETag contains an invalid entity-tag byte");
        }
        return Ok(etag.to_string());
    }
    if etag
        .bytes()
        .any(|byte| byte < 0x21 || byte == b'"' || byte == b'\\' || byte == 0x7f)
    {
        anyhow::bail!("inventory ETag contains an invalid entity-tag byte");
    }
    Ok(format!("\"{etag}\""))
}

/// Derives an MD5-style final multipart identity from provider part tags.
///
/// R2 and conventional S3 configurations use the MD5 of the ordered binary
/// part MD5 values plus the part count. Tags that do not have that shape return
/// `None`; callers must then rely on backend-specific durable completion
/// evidence rather than guessing.
///
/// # Errors
///
/// Returns an error when the manifest is empty, duplicated, or non-contiguous.
pub fn md5_multipart_etag(parts: &[PartTag]) -> Result<Option<String>> {
    if parts.is_empty() {
        anyhow::bail!("multipart completion manifest is empty");
    }
    let mut ordered = parts.to_vec();
    ordered.sort_by_key(|part| part.part_number);
    if ordered
        .iter()
        .enumerate()
        .any(|(index, part)| part.part_number as usize != index + 1)
    {
        anyhow::bail!("multipart completion manifest is not contiguous");
    }

    let mut part_digests = Vec::with_capacity(ordered.len() * 16);
    for part in &ordered {
        let normalized = strong_if_match_etag(&part.etag)?;
        let inner = &normalized[1..normalized.len() - 1];
        if inner.len() != 32 || !inner.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let digest = hex::decode(inner)?;
        part_digests.extend_from_slice(&digest);
    }
    Ok(Some(format!(
        "\"{}-{}\"",
        hex::encode(Md5::digest(&part_digests)),
        ordered.len()
    )))
}

/// Write access to a registry surface by relative path (the "Blobs" write
/// port).
///
/// The git-backed configuration change-request flow writes its loose objects
/// and draft ref through this port, so the same write logic is single-source
/// across the native hub and the Cloudflare Worker.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceWrite: BackendBounds {
    /// Reports the exact multipart protocol version implemented by this backend.
    ///
    /// Callers must check this capability before creating a durable ticket or
    /// mutating backend state. Version 1 is the durable
    /// create/part/complete/abort contract; the default is fail-closed.
    fn multipart_protocol_version(&self) -> Option<u32> {
        None
    }

    /// Reports the maximum lifetime of an incomplete provider multipart upload.
    ///
    /// Durable cache admission uses this guarantee to bound provider state
    /// whose opaque creation response is lost before its id reaches the
    /// database. Backends without an enforced lifecycle return `None` and are
    /// not eligible for that upload path.
    fn abandoned_multipart_lifetime_secs(&self) -> Option<u64> {
        None
    }

    /// Predicts the provider's final strong multipart identity when its
    /// contract defines that identity entirely from the accepted part tags.
    ///
    /// The default is deliberately unknown. In particular, generic S3 ETags
    /// vary with encryption and checksum configuration and must not be inferred
    /// merely because individual part tags resemble MD5 values.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider-specific part manifest is malformed.
    fn expected_multipart_etag(&self, parts: &[PartTag]) -> Result<Option<String>> {
        let _ = parts;
        Ok(None)
    }

    /// Atomically write `bytes` to the surface at the logical `path`.
    ///
    /// The write MUST be atomic with respect to a concurrent reader: a reader
    /// fetching `path` while this runs sees either the old contents (or
    /// absence) or the complete new contents, never a half-written object. The
    /// native filesystem implementation achieves this with a temp-file write
    /// followed by a rename; an object store whose puts are atomic per-object
    /// (R2) needs no temp step.
    ///
    /// `path` is a logical, registry-relative surface path (`objects/ab/cd…`,
    /// `refs/hub/changes/<id>`); the implementation maps it to its store and is
    /// responsible for rejecting any path that would escape the registry's
    /// space.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry has no writable storage root, when
    /// `path` is rejected as unsafe (traversal/symlink escape), or on any IO or
    /// transport failure.
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()>;

    /// Idempotently delete the surface object at the logical `path`.
    ///
    /// Deleting an absent path is **not** an error: the call returns `Ok(())`
    /// so a retry or a redundant cleanup is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry has no writable storage root, when
    /// `path` is rejected as unsafe, or on any IO or transport failure other
    /// than the object being absent.
    async fn delete(&self, path: &str) -> Result<()>;

    /// Deletes only the exact backend object captured by inventory.
    ///
    /// Implementations must provide an atomic backend precondition or return
    /// an error without deleting. Absence is a verified idempotent success.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot enforce the supplied identity,
    /// the path is unsafe, or the transport fails.
    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        let _ = (path, expected);
        anyhow::bail!("this backend does not support identity-checked deletion")
    }

    /// Begin a multipart upload targeting the logical `path`, returning the
    /// backend's opaque upload id.
    ///
    /// The id, paired with `path`, reconstructs the in-progress upload on every
    /// later [`upload_part`](Self::upload_part) /
    /// [`complete_multipart`](Self::complete_multipart) / [`abort_multipart`](Self::abort_multipart)
    /// call. This is what lets a *stateless* host drive a multipart upload: the
    /// Cloudflare Worker handles each request in a fresh isolate and holds no
    /// cross-request state, so the backend (R2/S3 upload id, or a hub-minted id
    /// for local disk) owns the in-flight assembly and the protocol carries the
    /// id. Large objects therefore upload as several sub-cap parts, one per
    /// request, with memory bounded to a single part.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, the store
    /// is not writable, `path` is unsafe, or on a transport failure.
    async fn create_multipart(&self, path: &str) -> Result<String> {
        let _ = path;
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Upload one part (`part_number`, 1-based and contiguous) of the
    /// in-progress upload `upload_id` for `path`, returning its [`PartTag`].
    ///
    /// Every part except the last MUST meet the backend's minimum part size
    /// (R2/S3: 5 MiB). The caller streams one sub-cap part per request, so peak
    /// memory is one part regardless of the final object size.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, the
    /// `upload_id` is unknown/expired, the part violates the size minimum, or on
    /// a transport failure.
    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        let _ = (path, upload_id, part_number, bytes);
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Finalize the upload `upload_id` for `path`, assembling `parts` (which the
    /// implementation orders by `part_number`) into the object — atomically with
    /// respect to a concurrent reader, the same guarantee as [`write`](Self::write).
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, a part is
    /// missing or out of order, an `etag` does not match, or on a transport
    /// failure.
    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        let _ = (path, upload_id, parts);
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Abort the upload `upload_id` for `path`, freeing any backend-held state.
    ///
    /// The result distinguishes a confirmed abort/absence from a possibly
    /// completed upload so callers never discard uncertain landed-byte evidence.
    ///
    /// # Errors
    ///
    /// Returns an error only on a transport failure the backend deems fatal.
    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<MultipartAbortOutcome> {
        let _ = (path, upload_id);
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Removes backend-local completion evidence after the durable write ticket
    /// has settled successfully.
    ///
    /// Remote object stores need no action. Local filesystems use this callback
    /// to remove the ambiguity marker only after the database commit proves the
    /// completion is durably accounted for.
    ///
    /// # Errors
    ///
    /// Returns an error when settlement evidence cannot be cleaned up.
    async fn settle_multipart(&self, path: &str, upload_id: &str) -> Result<()> {
        let _ = (path, upload_id);
        Ok(())
    }
}

/// Resolves the [`SurfaceWrite`] for one explicit physical placement.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceWriteProvider: BackendBounds {
    /// Builds a writer rooted at one explicit physical placement.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement's binding cannot be resolved, lacks
    /// validated write capability, or is unsupported by this runtime.
    async fn placement_writer(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>>;

    /// Builds a writer from an immutable binding revision frozen by durable work.
    ///
    /// Unlike [`Self::placement_writer`], this resolver must not consult the
    /// placement's current desired state or write authority. It is used only
    /// to finish or clean up work which already wrote bytes through `revision`.
    /// Implementations must verify that the placement and revision share the
    /// same binding and resolve the revision's exact credential generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the frozen physical identity disappeared, does
    /// not match, or cannot be addressed by this runtime.
    async fn placement_writer_at_revision(
        &self,
        placement: &SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>>;

    /// Builds a conditional deleter for one explicit physical placement.
    ///
    /// Delete capability is independent of logical write authority: GC must
    /// delete reviewed replicas and shards that are intentionally not the
    /// surface's current write target. Implementations must still reject a
    /// backend that cannot enforce [`SurfaceDeletePrecondition`] atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when credentials cannot be resolved or the backend
    /// cannot perform identity-checked deletion.
    async fn placement_deleter(
        &self,
        placement: &SurfacePlacementRecord,
        expected_binding_resource_version: i64,
        delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>>;

    /// Builds a conditional deleter from one immutable durable-work fence.
    ///
    /// Implementations may reopen the frozen binding/revision/capability, but
    /// must not inspect or select current write authority. They must address
    /// exactly [`FrozenSurfaceAccess::placement_prefix`] and fail closed when
    /// any retained version or capability no longer matches.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or stale fence, unavailable exact
    /// credentials, or a backend without atomic conditional deletion.
    async fn frozen_placement_deleter(
        &self,
        access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let _ = access;
        anyhow::bail!("this provider does not support frozen conditional deletion")
    }
}

#[cfg(test)]
mod tests {
    use super::{md5_multipart_etag, strong_if_match_etag, FrozenSurfaceAccess, PartTag};

    fn frozen_access() -> FrozenSurfaceAccess {
        FrozenSurfaceAccess {
            registry_id: 1,
            placement_id: 2,
            placement_name: "primary".into(),
            placement_prefix: "registry/objects".into(),
            placement_resource_version: 3,
            placement_write_spec_version: 4,
            placement_observation_version: 5,
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            delete_credential_purpose: Some("delete".into()),
            delete_credential_generation: Some(9),
            delete_capability_fingerprint: "conditional-delete-v1".into(),
            delete_capability_resource_version: 10,
        }
    }

    #[test]
    fn frozen_surface_access_rejects_unsafe_or_partial_addresses() {
        assert!(frozen_access().validate().is_ok());

        let mut unsafe_prefix = frozen_access();
        unsafe_prefix.placement_prefix = "../other-placement".into();
        assert!(unsafe_prefix.validate().is_err());

        let mut partial_credential = frozen_access();
        partial_credential.delete_credential_generation = None;
        assert!(partial_credential.validate().is_err());
    }

    #[test]
    fn exact_delete_etags_are_strong_and_canonical() {
        assert_eq!(strong_if_match_etag("abc").unwrap(), "\"abc\"");
        assert_eq!(strong_if_match_etag("\"abc\"").unwrap(), "\"abc\"");
        assert!(strong_if_match_etag("W/\"abc\"").is_err());
        assert!(strong_if_match_etag("\"abc").is_err());
        assert!(strong_if_match_etag("\"a\\b\"").is_err());
        assert!(strong_if_match_etag("\"a\"b\"").is_err());
        assert!(strong_if_match_etag("").is_err());
    }

    #[test]
    fn conventional_part_tags_predict_the_completed_identity() {
        let parts = [
            PartTag {
                part_number: 2,
                etag: "\"7d793037a0760186574b0282f2f435e7\"".into(),
            },
            PartTag {
                part_number: 1,
                etag: "5d41402abc4b2a76b9719d911017c592".into(),
            },
        ];
        assert_eq!(
            md5_multipart_etag(&parts).unwrap().as_deref(),
            Some("\"065947336a2f2a95ba8899f3675c3be6-2\"")
        );
    }

    #[test]
    fn opaque_part_tags_do_not_invent_a_completed_identity() {
        let parts = [PartTag {
            part_number: 1,
            etag: "provider-opaque-tag".into(),
        }];
        assert_eq!(md5_multipart_etag(&parts).unwrap(), None);
    }
}
