//! Independently verified TUF additions to a closed release publication.
//!
//! The manifest closes artifact bytes; TUF authorizes that manifest outside
//! its closure. This module admits only the exact current metadata chain and
//! public manifest target, without admitting arbitrary extra surface files.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::tuf::{
    DelegatedTargetsMetadataV1, ImmutableTufSetV1, RootMetadataV1, SnapshotMetadataV1,
    TargetsMetadataV1, TimestampMetadataV1, TufEnvelopeV1, TufReleaseExpectation, TufRole,
    TufRootTrust, verify_immutable_set, verify_timestamp,
};
use aos_release::verify::CapturedFile;
use serde::de::DeserializeOwned;

use crate::cli::ReleaseStageArgs;

use super::{capture, tuf, verify};

/// Holds the composed source and exact independently verified additions.
pub(super) struct PublicationMetadata {
    /// Complete composed surface, including the original closed bundle.
    pub(super) surface: PathBuf,
    /// Immutable role metadata, freshness pointer, and public manifest target.
    pub(super) files: Vec<CapturedFile>,
}

/// Captures and verifies the selected surface's complete TUF chain.
///
/// # Errors
///
/// Returns an error for malformed metadata, changed role policy, invalid or
/// expired signatures, untrusted roots, or a different public manifest.
pub(super) fn capture_metadata(
    args: &ReleaseStageArgs,
    plan: &ReleasePlanV1,
    manifest: &[u8],
) -> Result<Option<PublicationMetadata>> {
    let Some(surface) = &args.publication_surface else {
        return Ok(None);
    };
    let mut files = Vec::new();
    let timestamp: TufEnvelopeV1<TimestampMetadataV1> =
        read_envelope(surface, "timestamp.json", &mut files)?;
    let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
        read_envelope(surface, &timestamp.signed.snapshot.path, &mut files)?;
    let role = TufRole::for_release(plan.release_class);
    let root_path = metadata_path(&snapshot.signed, ".root.json")?;
    let targets_path = metadata_path(&snapshot.signed, ".targets.json")?;
    let delegated_path = metadata_path(&snapshot.signed, &format!(".{}.json", role.as_str()))?;
    let root: TufEnvelopeV1<RootMetadataV1> = read_envelope(surface, root_path, &mut files)?;
    let targets: TufEnvelopeV1<TargetsMetadataV1> =
        read_envelope(surface, targets_path, &mut files)?;
    let delegated: TufEnvelopeV1<DelegatedTargetsMetadataV1> =
        read_envelope(surface, delegated_path, &mut files)?;
    let set = ImmutableTufSetV1 {
        root,
        targets,
        delegated,
        snapshot,
    };
    for role in [
        TufRole::Root,
        TufRole::Targets,
        role,
        TufRole::Snapshot,
        TufRole::Timestamp,
    ] {
        tuf::require_policy_match(&set.root.signed, plan, role)?;
    }
    let trusted = verify::load_trusted_keys(&args.trusted_root_keys)?;
    let now = std::time::SystemTime::now();
    verify_immutable_set(
        &set,
        &TufRootTrust {
            keys: &trusted,
            threshold: args.trusted_root_threshold,
        },
        None,
        now,
        &TufReleaseExpectation {
            registry: &plan.registry,
            release_id: &plan.release_id,
            release_class: plan.release_class,
            manifest_digest: Sha256Digest::of_bytes(manifest),
        },
    )?;
    verify_timestamp(&timestamp, &set.root.signed, &set.snapshot, None, now)?;

    let public_manifest = format!(
        "releases/{}/{}/release-manifest.json",
        role.as_str(),
        plan.version
    );
    let bytes = capture::control_file(&surface.join(&public_manifest), "public release manifest")?;
    if bytes != manifest {
        bail!("composed surface has a different public release manifest");
    }
    files.push(file_identity(public_manifest, &bytes)?);
    Ok(Some(PublicationMetadata {
        surface: surface.clone(),
        files,
    }))
}

fn metadata_path<'a>(snapshot: &'a SnapshotMetadataV1, suffix: &str) -> Result<&'a str> {
    let mut matching = snapshot
        .metadata
        .iter()
        .filter(|entry| entry.path.ends_with(suffix));
    let path = matching
        .next()
        .context("TUF snapshot lacks a required metadata role")?;
    if matching.next().is_some() {
        bail!("TUF snapshot repeats a metadata role");
    }
    Ok(&path.path)
}

fn read_envelope<T: DeserializeOwned>(
    surface: &Path,
    filename: &str,
    files: &mut Vec<CapturedFile>,
) -> Result<TufEnvelopeV1<T>> {
    BundlePath::parse(filename.to_owned())?;
    if filename.contains('/') {
        bail!("TUF metadata description must name one file");
    }
    let relative = format!("tuf/{filename}");
    let bytes = capture::control_file(&surface.join(&relative), "publication TUF metadata")?;
    canonical::require_canonical(&bytes, "publication TUF metadata")?;
    let envelope = canonical::from_slice(&bytes, "publication TUF metadata")?;
    files.push(file_identity(relative, &bytes)?);
    Ok(envelope)
}

fn file_identity(path: String, bytes: &[u8]) -> Result<CapturedFile> {
    Ok(CapturedFile {
        path: BundlePath::parse(path)?,
        size_bytes: u64::try_from(bytes.len())?,
        sha256: Sha256Digest::of_bytes(bytes),
    })
}
