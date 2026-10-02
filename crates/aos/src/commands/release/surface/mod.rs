//! Publication surfaces behind one client interface.
//!
//! A surface is one publication endpoint of the plan: an AOS Hub deployment
//! reached through its RPC publication protocol, or a static origin
//! (filesystem, S3, SFTP) written directly and read back anonymously. Release
//! commands speak only [`SurfaceClient`]; [`surface_client`] selects the
//! implementation from the frozen [`PlannedSurface`] so the Hub is never an
//! unintended requirement.
//!
//! - [`readback`] reads objects back through the public route and checks
//!   surface identity.
//! - [`project`] maps a captured bundle into the machine surface layout.
//! - `hub` implements the client over the Hub publication RPCs.
//! - `static_` implements it over `aos_cache` static-origin backends, with
//!   locally signed receipts and compare-and-swap channel generations.
//!
//! Receipts cross this boundary as exact signed bytes ([`SignedReceipt`]).
//! Both surface kinds issue the same receipt shapes; [`verify_publication_receipt`]
//! and [`verify_channel_receipt`] verify them against the plan, additionally
//! binding static receipts to the plan's `surface-receipt` role.

mod hub;
pub(super) mod project;
pub(super) mod readback;
mod static_;
mod static_channel;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedDestination, PlannedSurface, ReleasePlan, SurfaceKind};
use aos_release::receipt::{ChannelReceipt, PublicationReceipt, verify_signed_receipt_with_key};
use aos_release::signing::{SignerRole, TrustedEd25519Key};
use async_trait::async_trait;

use super::capture;
use super::signer::ExternalSigner;

/// One object of a published surface, as read back and receipted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SurfaceObject {
    /// Surface-relative path.
    pub(super) path: String,
    /// Lowercase hexadecimal SHA-256 of the exact bytes.
    pub(super) sha256: String,
    /// Exact byte length.
    pub(super) byte_size: u64,
    /// Whether the object is a replaceable pointer.
    pub(super) mutable: bool,
    /// Served media type.
    pub(super) media_type: String,
}

impl SurfaceObject {
    /// Converts one inventoried publication input.
    fn from_input(input: &aos_remote::hub_types::RegistryPublicationObjectInput) -> Result<Self> {
        Ok(Self {
            path: input.path.clone(),
            sha256: input.sha256.clone(),
            byte_size: u64::try_from(input.byte_size)
                .context("publication object has a negative size")?,
            mutable: input.kind == "mutable_pointer",
            media_type: input.media_type.clone(),
        })
    }
}

/// A committed surface publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublishedSurface {
    /// Surface-side publication operation id.
    pub(super) operation_id: String,
    /// Every committed object.
    pub(super) objects: Vec<SurfaceObject>,
    /// Registry default-branch commit after the publication.
    pub(super) default_commit: String,
    /// Compare-and-swap parent publication, when the surface records one.
    pub(super) parent: Option<String>,
}

/// An uploaded immutable candidate and its shared lifecycle record.
pub(super) struct StagedSurface {
    pub(super) publication: PublishedSurface,
    pub(super) record: aos_registry_surface::staging::StageRecord,
}

/// Exact signed receipt bytes and their digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SignedReceipt {
    /// Canonical signed envelope bytes, retained verbatim.
    pub(super) bytes: Vec<u8>,
    /// SHA-256 of `bytes`; the identity journals and later receipts bind.
    pub(super) digest: Sha256Digest,
}

impl SignedReceipt {
    /// Wraps exact envelope bytes.
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::of_bytes(&bytes);
        Self { bytes, digest }
    }

    /// Reads exact envelope bytes from a file.
    pub(super) fn read(path: &Path, label: &str) -> Result<Self> {
        Ok(Self::new(capture::control_file(path, label)?))
    }
}

/// Credentials presented to one surface.
#[derive(Clone, Debug, Default)]
pub(super) struct SurfaceCredentials {
    /// Short-lived Hub access token.
    pub(super) token: Option<String>,
    /// Static-origin transport credentials.
    pub(super) auth: aos_cache::backend::AuthOptions,
}

/// One Ed25519 signer key with its pinned provider identity.
pub(super) struct PayloadSigningKey {
    /// Trusted public key.
    pub(super) key: TrustedEd25519Key,
    /// Provider verification identity.
    pub(super) verification_identity: String,
    /// Provider revision frozen in the plan's role policy.
    pub(super) provider_revision: String,
}

/// One SSHSIG signer key with its trust line and pinned provider identity.
pub(super) struct GitSigningKey {
    /// Registry-role key id.
    pub(super) key_id: String,
    /// Exact registry trust line, `registry:Ed25519:<base64>`.
    pub(super) trust_line: String,
    /// Provider verification identity.
    pub(super) verification_identity: String,
    /// Provider revision frozen in the plan's role policy.
    pub(super) provider_revision: String,
}

/// External signing used by static surfaces.
///
/// Hub surfaces sign their own receipts and channel objects and ignore this.
pub(super) struct SurfaceSigners {
    /// Deployment-configured signer executable.
    pub(super) signer: ExternalSigner,
    /// `surface-receipt` role key for publication and channel receipts.
    pub(super) receipt: PayloadSigningKey,
    /// `registry` role key for channel partition tags.
    pub(super) registry: Option<GitSigningKey>,
}

/// Production continuity evidence imported with a publication.
pub(super) struct Promotion<'a> {
    /// Exact staging publication receipt.
    pub(super) staging_receipt: &'a SignedReceipt,
    /// Canonical staging-phase qualification receipt payload.
    pub(super) qualification_payload: &'a [u8],
    /// Signed staging-phase qualification envelope.
    pub(super) signed_qualification: &'a [u8],
}

/// Inputs of one publication receipt.
pub(super) struct PublicationRequest<'a> {
    /// Frozen plan.
    pub(super) plan: &'a ReleasePlan,
    /// Destination being published.
    pub(super) destination: &'a PlannedDestination,
    /// Closed bundle identity.
    pub(super) bundle_digest: Sha256Digest,
    /// Final manifest identity.
    pub(super) manifest_digest: Sha256Digest,
    /// Committed publication being receipted.
    pub(super) publication: &'a PublishedSurface,
    /// Production continuity evidence; `None` for staging.
    pub(super) promotion: Option<Promotion<'a>>,
}

/// Inputs of one compare-and-swap channel ring advance.
pub(super) struct ChannelAdvance<'a> {
    /// Frozen plan.
    pub(super) plan: &'a ReleasePlan,
    /// Destination whose channel advances.
    pub(super) destination: &'a PlannedDestination,
    /// One-based ring.
    pub(super) ring: u16,
    /// Inclusive first partition of the ring.
    pub(super) first_partition: u16,
    /// Inclusive last partition of the ring.
    pub(super) last_partition: u16,
    /// Expected current channel generation.
    pub(super) prior_generation: u64,
    /// Final manifest identity.
    pub(super) manifest_digest: Sha256Digest,
    /// This surface's publication receipt.
    pub(super) publication_receipt: &'a SignedReceipt,
    /// Registry release tag object the partitions select (static only).
    pub(super) release_tag_object: Option<&'a str>,
}

/// Public state a channel range must show after an advance.
pub(super) struct ChannelExpectation<'a> {
    /// Full channel name.
    pub(super) channel: &'a str,
    /// Inclusive first partition.
    pub(super) first_partition: u16,
    /// Inclusive last partition.
    pub(super) last_partition: u16,
    /// Release identity the Hub reports for each partition.
    pub(super) release_id: &'a str,
    /// Release tag object each static partition tag must target.
    pub(super) release_tag_object: Option<&'a str>,
}

/// Inputs of one TUF timestamp publication.
pub(super) struct TimestampPublication<'a> {
    /// Frozen plan.
    pub(super) plan: &'a ReleasePlan,
    /// Exact signed snapshot bytes.
    pub(super) snapshot_bytes: &'a [u8],
    /// Snapshot metadata version.
    pub(super) snapshot_version: u64,
    /// Exact signed timestamp bytes.
    pub(super) timestamp_bytes: &'a [u8],
    /// New timestamp metadata version.
    pub(super) timestamp_version: u64,
}

/// Timestamp publication result.
pub(super) struct TimestampReceipt {
    /// Surface-side operation that committed the timestamp.
    pub(super) operation_id: String,
    /// Objects written or confirmed by the operation, already read back.
    pub(super) objects: Vec<SurfaceObject>,
}

/// One publication surface of a release plan.
///
/// Futures are not required to be `Send`: release commands drive one surface
/// at a time on the command's own task, and the Hub publication primitives
/// they reuse hold non-`Send` state across awaits.
#[async_trait(?Send)]
pub(super) trait SurfaceClient {
    /// Returns the frozen surface this client writes.
    fn surface(&self) -> &PlannedSurface;

    /// Requires the live surface to present the planned identity.
    async fn verify_identity(&self) -> Result<()>;

    /// Uploads and commits a surface tree whose registry base is `base_commit`.
    async fn publish_surface(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface>;

    /// Uploads and verifies an exact common stage without exposing mutable pointers.
    async fn stage_surface(
        &self,
        root: &Path,
        revision: &aos_registry_surface::staging::StageRevision,
        printer: &Printer,
    ) -> Result<StagedSurface>;

    /// Finalizes an exact candidate after rechecking its withheld pointer preconditions.
    async fn finalize_stage(
        &self,
        root: &Path,
        revision: &aos_registry_surface::staging::StageRevision,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface>;

    /// Reads every object back anonymously and verifies its identity.
    async fn read_back(&self, objects: &[SurfaceObject]) -> Result<()>;

    /// Obtains the signed receipt for a committed publication.
    async fn receipt(&self, request: &PublicationRequest<'_>) -> Result<SignedReceipt>;

    /// Fetches the surface's existing publication receipt for a bundle anonymously.
    async fn published_receipt(&self, bundle_digest: Sha256Digest) -> Result<SignedReceipt>;

    /// Returns the channel's current generation.
    ///
    /// Hub surfaces expose no generation read; they derive it from `known`
    /// receipts (the largest `new_generation`, else zero).
    async fn current_generation(&self, channel: &str, known: &[ChannelReceipt]) -> Result<u64>;

    /// Advances one ring by compare-and-swap and returns its signed receipt.
    async fn advance_ring(&self, request: &ChannelAdvance<'_>) -> Result<SignedReceipt>;

    /// Reads a channel range back anonymously.
    async fn read_back_channel(&self, expected: &ChannelExpectation<'_>) -> Result<()>;

    /// Installs the first registry base on an empty surface.
    async fn bootstrap(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface>;

    /// Replaces the TUF timestamp pointer by compare-and-swap.
    async fn publish_timestamp(
        &self,
        root: &Path,
        request: &TimestampPublication<'_>,
        printer: &Printer,
    ) -> Result<TimestampReceipt>;
}

/// Selects the client for a planned surface.
///
/// Static surfaces that must sign receipts require `signers`; Hub surfaces
/// ignore them.
///
/// # Errors
/// Returns an error for an invalid surface or an unsupported static origin.
pub(super) async fn surface_client(
    planned: &PlannedSurface,
    registry: &str,
    credentials: SurfaceCredentials,
    signers: Option<SurfaceSigners>,
) -> Result<Box<dyn SurfaceClient>> {
    planned.validate()?;
    match planned.kind {
        SurfaceKind::Hub => Ok(Box::new(hub::HubSurface::new(
            planned.clone(),
            registry,
            credentials.token,
        )?)),
        SurfaceKind::Static => Ok(Box::new(
            static_::StaticSurface::connect(planned.clone(), registry, &credentials.auth, signers)
                .await?,
        )),
    }
}

/// Returns where a credential reference points: `$CREDENTIALS_DIRECTORY/<name>`
/// for a bare name, or the absolute path itself.
///
/// # Errors
/// Returns an error for a relative path, a name with separators, or a bare
/// name without `$CREDENTIALS_DIRECTORY`.
pub(super) fn credential_location(reference: &str) -> Result<PathBuf> {
    let path = Path::new(reference);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if reference.is_empty() || reference.contains('/') || reference == "." || reference == ".." {
        bail!("credential must be a systemd credential name or an absolute path: {reference}");
    }
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("credential {reference} requires $CREDENTIALS_DIRECTORY"))?;
    Ok(PathBuf::from(directory).join(reference))
}

/// Reads a credential by name or absolute path and trims surrounding whitespace.
///
/// # Errors
/// Returns an error for an invalid reference, an unreadable or linked file,
/// non-UTF-8 content, or an empty credential.
pub(super) fn resolve_credential(reference: &str) -> Result<String> {
    let path = credential_location(reference)?;
    let bytes = capture::control_file(&path, "credential")?;
    let value = std::str::from_utf8(&bytes)
        .with_context(|| format!("credential {reference} is not UTF-8"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        bail!("credential {reference} is empty");
    }
    Ok(value)
}

/// Verifies a publication receipt from either surface kind.
///
/// Hub receipts are signed by the Hub deployment's receipt key; static
/// receipts must be signed by a key of the plan's `surface-receipt` role.
/// Either way the receipt must name a planned destination and the plan's
/// surface for `destination`'s role. The receipt may name another destination
/// on the same surface: a surface serves one publication per release.
///
/// # Errors
/// Returns an error for an untrusted or malformed receipt, a role or surface
/// mismatch, or a static receipt signed outside the planned role.
pub(super) fn verify_publication_receipt(
    plan: &ReleasePlan,
    destination: &PlannedDestination,
    receipt: &SignedReceipt,
    keys: &BTreeMap<String, [u8; 32]>,
) -> Result<PublicationReceipt> {
    let surface = plan.surface(destination.surface)?;
    let (key_id, verified): (String, PublicationReceipt) =
        verify_signed_receipt_with_key(&receipt.bytes, keys)?;
    if surface.kind == SurfaceKind::Static {
        require_role_key(plan, SignerRole::SurfaceReceipt, &key_id)?;
    }
    verified.validate_for(plan)?;
    if verified.surface_role != destination.surface {
        bail!("publication receipt belongs to another surface role");
    }
    Ok(verified)
}

/// Verifies a channel receipt from either surface kind for one ring.
///
/// `ring`, when given, must be the ring the receipt names.
///
/// # Errors
/// Returns an error for an untrusted or malformed receipt, a static receipt
/// signed outside the planned role, a different ring, a surface mismatch, or
/// a partition range other than the ring's.
pub(super) fn verify_channel_receipt(
    plan: &ReleasePlan,
    destination: &PlannedDestination,
    ring: Option<u16>,
    receipt: &SignedReceipt,
    keys: &BTreeMap<String, [u8; 32]>,
) -> Result<ChannelReceipt> {
    let surface = plan.surface(destination.surface)?;
    let (key_id, verified): (String, ChannelReceipt) =
        verify_signed_receipt_with_key(&receipt.bytes, keys)?;
    if surface.kind == SurfaceKind::Static {
        require_role_key(plan, SignerRole::SurfaceReceipt, &key_id)?;
    }
    if ring.is_some_and(|ring| ring != verified.ring) {
        bail!("channel receipt names a different ring");
    }
    verified.validate_for(destination)?;
    if verified.surface_kind != surface.kind || verified.surface_identity != surface.identity {
        bail!("channel receipt belongs to a different surface");
    }
    Ok(verified)
}

/// Requires `key_id` to belong to the plan's policy for `role`.
fn require_role_key(plan: &ReleasePlan, role: SignerRole, key_id: &str) -> Result<()> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == role)
        .with_context(|| format!("release plan lacks a {role:?} signer policy"))?;
    if !requirement.key_ids.iter().any(|id| id == key_id) {
        bail!("receipt signer {key_id} is outside the planned {role:?} policy");
    }
    Ok(())
}

/// Decodes a signed envelope's payload without verifying its signature.
///
/// Callers use this only to compare an already-trusted or about-to-be-verified
/// receipt's fields; authorization always goes through the verifying helpers.
///
/// # Errors
/// Returns an error for a malformed envelope or payload.
pub(super) fn receipt_payload<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let envelope: aos_release::receipt::SignedReceiptEnvelope =
        aos_release::canonical::from_slice(bytes, "signed receipt")?;
    serde_json::from_value(envelope.payload).context("decoding signed receipt payload")
}

/// Builds the key map accepted by receipt verification from `KEY_ID=PATH` specs.
///
/// # Errors
/// Returns an error for a malformed, duplicate, or unreadable key.
pub(super) fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(super::verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_resolve_by_name_or_absolute_path() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let absolute = directory.path().join("token");
        std::fs::write(&absolute, b"  secret-token\n")?;
        assert_eq!(
            resolve_credential(absolute.to_str().context("utf-8 path")?)?,
            "secret-token"
        );
        assert!(credential_location("relative/path").is_err());
        assert!(credential_location("..").is_err());

        std::fs::write(directory.path().join("empty"), b"\n")?;
        assert!(
            resolve_credential(
                directory
                    .path()
                    .join("empty")
                    .to_str()
                    .context("utf-8 path")?
            )
            .is_err()
        );
        Ok(())
    }
}
