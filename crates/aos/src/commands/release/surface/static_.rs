//! Static-origin surfaces written directly through `aos_cache` backends.
//!
//! A static surface is a directory tree on a filesystem, S3 bucket, or SFTP
//! host, served by an ordinary origin and read back anonymously (HTTPS or
//! `file://`). No Hub RPC is involved. The coordinator therefore performs the
//! protocol a Hub would:
//!
//! - identity: `<readback>/.aos-surface` must equal the planned identity before
//!   and after every mutation (it is provisioned out of band, never written
//!   here);
//! - compare-and-swap: the registry default commit read from `HEAD` and
//!   `info/refs` must equal the plan's base before a release is uploaded;
//! - ordering: immutable objects first, then mutable pointers, then
//!   `info/refs`, and `HEAD` last, so readers never see a pointer to an absent
//!   object;
//! - receipts: publication and channel receipts signed locally by the plan's
//!   `surface-receipt` role, published immutably at
//!   `publication-receipts/<bundle digest>.json`;
//! - channels: see `static_channel`.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_cache::backend::{
    CacheBackend, ConditionalOutcome, Expectation, IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL,
};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedSurface, ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release::receipt::{
    ChannelReceipt, PUBLICATION_RECEIPT, PublicationReceipt, RECEIPT_SIGNATURE_DOMAIN,
    SIGNED_RECEIPT, SignedReceiptEnvelope, verify_signed_receipt_with_key,
};
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    SigningRequest,
};
use aos_remote::hub_types::RegistryPublicationObjectInput;
use async_trait::async_trait;
use serde::Serialize;
use url::Url;

use super::readback;
use super::{
    ChannelAdvance, ChannelExpectation, PublicationRequest, PublishedSurface, SignedReceipt,
    SurfaceClient, SurfaceObject, SurfaceSigners, TimestampPublication, TimestampReceipt,
};
use crate::commands::hub::publication::inventory::{
    PinnedPublication, publication_default_commit, publication_from_root,
    snapshot_publication_object,
};

/// Largest registry control object read for compare-and-swap.
const MAX_REFS_BYTES: usize = 4 * 1024 * 1024;

/// Largest receipt or TUF pointer read back from a static surface.
const MAX_POINTER_BYTES: usize = 1024 * 1024;

/// Path of the only mutable TUF pointer.
const TIMESTAMP_PATH: &str = "tuf/timestamp.json";

/// One static origin named by the plan.
pub(super) struct StaticSurface {
    pub(super) planned: PlannedSurface,
    pub(super) registry: String,
    pub(super) backend: Box<dyn CacheBackend>,
    pub(super) public: reqwest::Client,
    pub(super) readback: Url,
    pub(super) signers: Option<SurfaceSigners>,
}

impl StaticSurface {
    /// Connects the upload backend selected by the origin scheme.
    pub(super) async fn connect(
        planned: PlannedSurface,
        registry: &str,
        auth: &aos_cache::backend::AuthOptions,
        signers: Option<SurfaceSigners>,
    ) -> Result<Self> {
        if planned.kind != SurfaceKind::Static {
            bail!("static surface client requires a static planned surface");
        }
        if !["file://", "s3://", "sftp://"]
            .iter()
            .any(|scheme| planned.origin.starts_with(scheme))
        {
            bail!(
                "static origin {} is read-only; uploads require file://, s3://, or sftp://",
                planned.origin
            );
        }
        let backend = aos_cache::backend::from_url(&planned.origin, auth).await?;
        let readback = readback::base_url(planned.readback())?;
        Ok(Self {
            planned,
            registry: registry.to_owned(),
            backend,
            public: readback::public_client()?,
            readback,
            signers,
        })
    }

    fn signers(&self) -> Result<&SurfaceSigners> {
        self.signers
            .as_ref()
            .context("static surface operation requires the surface-receipt signer")
    }

    /// HTTP read-back also verifies byte ranges; `file://` read-back cannot.
    fn ranges(&self) -> bool {
        self.readback.scheme() != "file"
    }

    /// Reads the default commit currently served, or `None` for an empty surface.
    async fn served_default_commit(&self) -> Result<Option<String>> {
        let Some(head) = readback::fetch_small(&self.public, &self.readback, "HEAD", 4096).await?
        else {
            return Ok(None);
        };
        let refs = readback::fetch_small(&self.public, &self.readback, "info/refs", MAX_REFS_BYTES)
            .await?
            .context("static surface serves HEAD without info/refs")?;
        publication_default_commit(&head, &refs).map(Some)
    }

    /// Uploads pinned objects in reader-safe order.
    ///
    /// Immutable objects already present with identical identity evidence are
    /// skipped; everything else, including every pointer, is written.
    async fn upload(
        &self,
        pinned: &PinnedPublication,
        selected: &[&RegistryPublicationObjectInput],
        printer: &Printer,
    ) -> Result<()> {
        let mut ordered = selected.to_vec();
        ordered.sort_by_key(|object| (upload_rank(object), object.path.clone()));
        let total = ordered.len();
        for (index, object) in ordered.into_iter().enumerate() {
            let immutable = object.kind != "mutable_pointer";
            if immutable && self.holds_identical(object).await? {
                continue;
            }
            let snapshot = named_snapshot(pinned, object)?;
            self.backend
                .put_static_file(
                    &object.path,
                    snapshot.path(),
                    Some(&object.media_type),
                    Some(if immutable {
                        IMMUTABLE_CACHE_CONTROL
                    } else {
                        MUTABLE_CACHE_CONTROL
                    }),
                    None,
                    Some(&object.sha256),
                )
                .await
                .with_context(|| format!("uploading static surface object {}", object.path))?;
            if (index + 1) % 1000 == 0 {
                printer.info(&format!(
                    "Uploaded {}/{total} static surface objects",
                    index + 1
                ));
            }
        }
        Ok(())
    }

    async fn holds_identical(&self, object: &RegistryPublicationObjectInput) -> Result<bool> {
        let identity = self.backend.static_file_identity(&object.path).await?;
        Ok(identity.is_some_and(|identity| {
            i64::try_from(identity.byte_size).ok() == Some(object.byte_size)
                && identity.sha256 == object.sha256
        }))
    }

    /// Signs a receipt payload with the `surface-receipt` role.
    pub(super) async fn sign_receipt<T: Serialize>(
        &self,
        plan: &ReleasePlan,
        manifest_digest: Sha256Digest,
        artifact_kind: &str,
        receipt: &T,
    ) -> Result<SignedReceipt> {
        let signers = self.signers()?;
        let key = &signers.receipt;
        require_planned_key(plan, SignerRole::SurfaceReceipt, &key.key.key_id)?;
        let payload = canonical::to_vec(receipt)?;
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
        let nonce = fresh_nonce();
        let request = SigningRequest {
            schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
            request_id: format!("{artifact_kind}-{}", &nonce[..24]),
            nonce,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest: Sha256Digest::of_bytes(canonical::to_vec(plan)?),
            manifest_digest: Some(manifest_digest),
            role: SignerRole::SurfaceReceipt,
            key_id: key.key.key_id.clone(),
            provider_revision: key.provider_revision.clone(),
            algorithm: SignatureAlgorithm::Ed25519Payload,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: artifact_kind.to_owned(),
            },
            payload_digest: Sha256Digest::of_bytes(digest.as_bytes()),
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let response = signers
            .signer
            .sign_ed25519_payload(
                &request,
                digest.as_bytes(),
                &key.key,
                &key.verification_identity,
            )
            .await?;
        let envelope = SignedReceiptEnvelope {
            schema_version: SIGNED_RECEIPT.to_owned(),
            key_id: key.key.key_id.clone(),
            payload: serde_json::to_value(receipt)?,
            signature_base64: response.signature_base64,
        };
        let bytes = canonical::to_vec(&envelope)?;
        let trusted =
            std::collections::BTreeMap::from([(key.key.key_id.clone(), key.key.public_key)]);
        let (_, verified): (String, serde_json::Value) =
            verify_signed_receipt_with_key(&bytes, &trusted)?;
        if verified != serde_json::to_value(receipt)? {
            bail!("surface-receipt signer changed the receipt payload");
        }
        Ok(SignedReceipt::new(bytes))
    }

    /// Writes a small object only when absent; returns existing bytes otherwise.
    pub(super) async fn put_once(&self, path: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let source = temporary_file(bytes)?;
        match self
            .backend
            .put_static_file_conditional(
                path,
                source.path(),
                Some(aos_package::registry::surface_keymap::content_type(path)),
                Some(IMMUTABLE_CACHE_CONTROL),
                Expectation::Absent,
            )
            .await?
        {
            ConditionalOutcome::Written(_) => Ok(None),
            ConditionalOutcome::PreconditionFailed { .. } => self
                .backend
                .get_static_object(path, MAX_POINTER_BYTES)
                .await?
                .map(|(existing, _)| Some(existing))
                .context("static object vanished after a failed exclusive write"),
        }
    }

    /// Reads back one small object and requires its exact bytes.
    pub(super) async fn read_back_bytes(&self, path: &str, bytes: &[u8]) -> Result<()> {
        readback::read_back_objects(
            &self.public,
            &self.readback,
            &[object_for(path, bytes, false)],
            self.ranges(),
        )
        .await
    }
}

#[async_trait(?Send)]
impl SurfaceClient for StaticSurface {
    fn surface(&self) -> &PlannedSurface {
        &self.planned
    }

    async fn verify_identity(&self) -> Result<()> {
        readback::verify_static_identity(&self.public, &self.readback, &self.planned.identity).await
    }

    async fn publish_surface(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface> {
        // Compare-and-swap on the registry base: another publication since
        // planning changes the served default commit and fails closed here.
        match self.served_default_commit().await? {
            Some(commit) if commit == base_commit => {}
            Some(commit) => bail!(
                "static surface default commit {commit} differs from the planned base {base_commit}"
            ),
            None => bail!("static surface has no registry base; run step bootstrap first"),
        }
        let pinned = publication_from_root(root, &self.registry)?;
        if pinned.request.default_commit != base_commit {
            bail!("release publication does not preserve the approved registry base");
        }
        let selected: Vec<_> = pinned.request.objects.iter().collect();
        self.upload(&pinned, &selected, printer).await?;
        published(&pinned, None)
    }

    async fn read_back(&self, objects: &[SurfaceObject]) -> Result<()> {
        readback::read_back_objects(&self.public, &self.readback, objects, self.ranges()).await
    }

    async fn receipt(&self, request: &PublicationRequest<'_>) -> Result<SignedReceipt> {
        let predecessor = match (self.planned.role, &request.promotion) {
            (SurfaceRole::Staging, None) => None,
            (SurfaceRole::Production, Some(promotion)) => Some(promotion.staging_receipt.digest),
            (SurfaceRole::Staging, Some(_)) => {
                bail!("staging publication cannot claim a predecessor publication")
            }
            (SurfaceRole::Production, None) => {
                bail!("production publication requires its staging receipt")
            }
        };
        let path = receipt_path(request.bundle_digest);
        let receipt = PublicationReceipt {
            schema_version: PUBLICATION_RECEIPT.to_owned(),
            destination: request.destination.name.clone(),
            surface_role: self.planned.role,
            surface_kind: SurfaceKind::Static,
            surface_identity: self.planned.identity.clone(),
            registry: request.plan.registry.clone(),
            release_id: request.plan.release_id.clone(),
            manifest_digest: request.manifest_digest,
            bundle_digest: request.bundle_digest,
            operation_id: request.publication.operation_id.clone(),
            predecessor_receipt_digest: predecessor,
            committed_at: now_utc(),
        };
        receipt.validate_for(request.plan)?;
        let signed = self
            .sign_receipt(
                request.plan,
                request.manifest_digest,
                "publication-receipt",
                &receipt,
            )
            .await?;

        // A retried publication finds the receipt its earlier attempt
        // committed; it keeps that receipt only if it binds the same
        // publication, so the surface serves exactly one receipt per bundle.
        let signed = match self.put_once(&path, &signed.bytes).await? {
            None => signed,
            Some(existing) => {
                let existing = SignedReceipt::new(existing);
                let parsed: PublicationReceipt = super::receipt_payload(&existing.bytes)?;
                if parsed.bundle_digest != receipt.bundle_digest
                    || parsed.operation_id != receipt.operation_id
                    || parsed.surface_identity != receipt.surface_identity
                    || parsed.predecessor_receipt_digest != receipt.predecessor_receipt_digest
                {
                    bail!("static surface already serves a different receipt for this bundle");
                }
                existing
            }
        };
        self.read_back_bytes(&path, &signed.bytes).await?;
        Ok(signed)
    }

    async fn published_receipt(&self, bundle_digest: Sha256Digest) -> Result<SignedReceipt> {
        readback::fetch_small(
            &self.public,
            &self.readback,
            &receipt_path(bundle_digest),
            MAX_POINTER_BYTES,
        )
        .await?
        .map(SignedReceipt::new)
        .context("static surface serves no publication receipt for this bundle")
    }

    async fn current_generation(&self, channel: &str, _known: &[ChannelReceipt]) -> Result<u64> {
        Ok(self
            .read_generation(channel)
            .await?
            .map_or(0, |(record, _)| record.generation))
    }

    async fn advance_ring(&self, request: &ChannelAdvance<'_>) -> Result<SignedReceipt> {
        self.advance(request).await
    }

    async fn read_back_channel(&self, expected: &ChannelExpectation<'_>) -> Result<()> {
        self.read_back_partitions(expected).await
    }

    async fn bootstrap(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface> {
        if self.served_default_commit().await?.is_some() {
            bail!("registry bootstrap destination already contains a publication");
        }
        let pinned = publication_from_root(root, &self.registry)?;
        if pinned.request.default_commit != base_commit {
            bail!("bootstrap surface does not match the approved empty base");
        }
        let selected: Vec<_> = pinned.request.objects.iter().collect();
        self.upload(&pinned, &selected, printer).await?;
        published(&pinned, None)
    }

    async fn publish_timestamp(
        &self,
        root: &Path,
        request: &TimestampPublication<'_>,
        printer: &Printer,
    ) -> Result<TimestampReceipt> {
        let pinned = publication_from_root(root, &self.registry)?;
        let tuf: Vec<_> = pinned
            .request
            .objects
            .iter()
            .filter(|object| object.path.starts_with("tuf/"))
            .collect();
        let timestamp = tuf
            .iter()
            .find(|object| object.path == TIMESTAMP_PATH)
            .context("composed surface lacks tuf/timestamp.json")?;
        if timestamp.sha256 != Sha256Digest::of_bytes(request.timestamp_bytes).hex() {
            bail!("composed timestamp differs from the signed timestamp");
        }

        // Replace the pointer only over the exact predecessor version.
        let expectation = match self
            .backend
            .get_static_object(TIMESTAMP_PATH, MAX_POINTER_BYTES)
            .await?
        {
            Some((bytes, version)) => {
                let current = timestamp_version(&bytes)?;
                if current.checked_add(1) != Some(request.timestamp_version) {
                    bail!(
                        "static surface timestamp is version {current}; expected {}",
                        request.timestamp_version.saturating_sub(1)
                    );
                }
                Expectation::Version(version)
            }
            None if request.timestamp_version == 1 => Expectation::Absent,
            None => bail!("static surface has no timestamp to renew"),
        };
        let immutable: Vec<_> = tuf
            .iter()
            .copied()
            .filter(|object| object.path != TIMESTAMP_PATH)
            .collect();
        self.upload(&pinned, &immutable, printer).await?;
        let snapshot = named_snapshot(&pinned, timestamp)?;
        match self
            .backend
            .put_static_file_conditional(
                TIMESTAMP_PATH,
                snapshot.path(),
                Some("application/json"),
                Some(MUTABLE_CACHE_CONTROL),
                expectation,
            )
            .await?
        {
            ConditionalOutcome::Written(_) => {}
            ConditionalOutcome::PreconditionFailed { .. } => {
                bail!("another writer replaced the static timestamp; nothing was published")
            }
        }
        let objects = tuf
            .iter()
            .map(|object| SurfaceObject::from_input(object))
            .collect::<Result<Vec<_>>>()?;
        self.read_back(&objects).await?;
        Ok(TimestampReceipt {
            operation_id: format!("timestamp-{}", request.timestamp_version),
            objects,
        })
    }
}

/// Upload rank: immutable payloads, then pointers, then `info/refs`, then `HEAD`.
fn upload_rank(object: &RegistryPublicationObjectInput) -> u8 {
    match object.path.as_str() {
        "HEAD" => 3,
        "info/refs" => 2,
        _ if object.kind == "mutable_pointer" => 1,
        _ => 0,
    }
}

/// Converts a pinned static publication into the surface-neutral view.
fn published(pinned: &PinnedPublication, parent: Option<String>) -> Result<PublishedSurface> {
    Ok(PublishedSurface {
        operation_id: format!("static-{}", pinned.request.generation),
        objects: pinned
            .request
            .objects
            .iter()
            .map(SurfaceObject::from_input)
            .collect::<Result<Vec<_>>>()?,
        default_commit: pinned.request.default_commit.clone(),
        parent,
    })
}

/// Copies one pinned object into a named private snapshot for upload.
fn named_snapshot(
    pinned: &PinnedPublication,
    object: &RegistryPublicationObjectInput,
) -> Result<tempfile::NamedTempFile> {
    let mut source = snapshot_publication_object(&pinned.root, object)?;
    let mut named = tempfile::NamedTempFile::new()?;
    std::io::copy(&mut source, named.as_file_mut())?;
    named.as_file_mut().flush()?;
    Ok(named)
}

/// Writes exact bytes to a private temporary file.
pub(super) fn temporary_file(bytes: &[u8]) -> Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(bytes)?;
    file.as_file_mut().flush()?;
    Ok(file)
}

/// Describes exact bytes as a surface object for read-back.
pub(super) fn object_for(path: &str, bytes: &[u8], mutable: bool) -> SurfaceObject {
    SurfaceObject {
        path: path.to_owned(),
        sha256: Sha256Digest::of_bytes(bytes).hex(),
        byte_size: bytes.len() as u64,
        mutable,
        media_type: aos_package::registry::surface_keymap::content_type(path).to_owned(),
    }
}

/// Public path of a bundle's publication receipt on a static surface.
fn receipt_path(bundle_digest: Sha256Digest) -> String {
    format!("publication-receipts/{}.json", bundle_digest.hex())
}

/// Reads the version of a signed timestamp envelope.
fn timestamp_version(bytes: &[u8]) -> Result<u64> {
    let envelope: aos_release::tuf::TufEnvelopeV1<aos_release::tuf::TimestampMetadataV1> =
        canonical::from_slice(bytes, "served TUF timestamp")?;
    Ok(envelope.signed.version)
}

/// Requires `key_id` to belong to the plan's policy for `role`.
pub(super) fn require_planned_key(
    plan: &ReleasePlan,
    role: SignerRole,
    key_id: &str,
) -> Result<()> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == role)
        .with_context(|| format!("release plan lacks a {role:?} signer policy"))?;
    if !requirement.key_ids.iter().any(|id| id == key_id) {
        bail!("configured {role:?} key {key_id} is outside the frozen plan");
    }
    Ok(())
}

/// Returns a fresh 32-byte lowercase hexadecimal signer nonce.
pub(super) fn fresh_nonce() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// Returns the current time as RFC 3339 UTC with second precision.
pub(super) fn now_utc() -> String {
    crate::commands::release::journal::now_utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(path: &str, kind: &str) -> RegistryPublicationObjectInput {
        RegistryPublicationObjectInput {
            path: path.into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    #[test]
    fn uploads_order_payloads_before_pointers_and_head_last() {
        let mut objects = vec![
            input("HEAD", "mutable_pointer"),
            input("info/refs", "mutable_pointer"),
            input("objects/info/packs", "mutable_pointer"),
            input("nar/a.nar.zst", "immutable"),
            input("tuf/1.root.json", "immutable"),
        ];
        objects.sort_by_key(|object| (upload_rank(object), object.path.clone()));
        let order: Vec<_> = objects.iter().map(|object| object.path.as_str()).collect();
        assert_eq!(
            order,
            [
                "nar/a.nar.zst",
                "tuf/1.root.json",
                "objects/info/packs",
                "info/refs",
                "HEAD"
            ]
        );
    }

    #[test]
    fn receipts_live_under_the_bundle_digest() {
        let digest = Sha256Digest::of_bytes("bundle");
        assert_eq!(
            receipt_path(digest),
            format!("publication-receipts/{}.json", digest.hex())
        );
        assert!(aos_package::registry::surface_keymap::is_machine_path(
            &receipt_path(digest)
        ));
        assert!(!aos_package::registry::surface_keymap::is_mutable_path(
            &receipt_path(digest)
        ));
    }

    #[tokio::test]
    async fn https_origins_are_read_only() {
        let planned = PlannedSurface {
            role: SurfaceRole::Production,
            kind: SurfaceKind::Static,
            origin: "https://cdn.example/registry".into(),
            readback_origin: None,
            identity: "cdn-1".into(),
        };
        let result = StaticSurface::connect(
            planned,
            "andyl/testing",
            &aos_cache::backend::AuthOptions::default(),
            None,
        )
        .await;
        assert!(result.is_err());
    }
}
