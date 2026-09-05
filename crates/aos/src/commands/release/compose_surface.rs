//! Atomic composition of registry, release-target, and TUF publication bytes.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::plan::ReleasePlanV1;
use aos_release::tuf::{
    ImmutableTufSetV1, TufEnvelopeV1, TufReleaseExpectation, TufRootTrust, verify_immutable_set,
    verify_timestamp,
};

use crate::cli::ReleaseComposeSurfaceArgs;

use super::{capture, verify};

pub(super) fn run(args: &ReleaseComposeSurfaceArgs, printer: &Printer) -> Result<()> {
    if args.output.exists() {
        bail!(
            "composed release surface already exists: {}",
            args.output.display()
        );
    }
    let plan_bytes = read_canonical_bytes(&args.plan, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let captured = capture::bundle(&args.bundle)?;
    if captured.plan_bytes != plan_bytes {
        bail!("release bundle plan differs from the surface plan");
    }
    let manifest_keys = verify::load_trusted_keys(&args.manifest_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &manifest_keys,
    )?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    if manifest.payload.release_id != plan.release_id {
        bail!("release manifest identity differs from the surface plan");
    }

    let (root, root_bytes) = read_envelope(&args.root, "TUF root")?;
    let previous_root = args
        .previous_root
        .as_ref()
        .map(|path| read_envelope(path, "previous TUF root").map(|value| value.0))
        .transpose()?;
    let (targets, targets_bytes) = read_envelope(&args.targets, "TUF targets")?;
    let (delegated, delegated_bytes) = read_envelope(&args.delegated, "delegated TUF targets")?;
    let (snapshot, snapshot_bytes) = read_envelope(&args.snapshot, "TUF snapshot")?;
    let (timestamp, timestamp_bytes) = read_envelope(&args.timestamp, "TUF timestamp")?;
    let set = ImmutableTufSetV1 {
        root,
        targets,
        delegated,
        snapshot,
    };
    let now = parse_utc(&args.now)?;
    let root_keys = verify::load_trusted_keys(&args.trusted_root_keys)?;
    let root_trust = TufRootTrust {
        keys: &root_keys,
        threshold: args.trusted_root_threshold,
    };
    let manifest_envelope_digest = Sha256Digest::of_bytes(&captured.manifest_bytes);
    verify_immutable_set(
        &set,
        &root_trust,
        previous_root.as_ref(),
        now,
        &TufReleaseExpectation {
            registry: &plan.registry,
            release_id: &plan.release_id,
            release_class: plan.release_class,
            manifest_digest: manifest_envelope_digest,
        },
    )?;
    verify_timestamp(
        &timestamp,
        &set.root.signed,
        &set.snapshot,
        (args.previous_timestamp_version > 0).then_some(args.previous_timestamp_version),
        now,
    )?;
    if timestamp.signed.version
        != args
            .previous_timestamp_version
            .checked_add(1)
            .context("timestamp version overflowed")?
    {
        bail!("composed timestamp version must increase by exactly one");
    }

    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-surface-")
        .tempdir_in(parent)?;
    let surface = temporary.path().join("surface");
    capture::copy_surface_tree(&args.base_surface, &surface)?;

    install_immutable(
        &surface.join(format!(
            "releases/{}/{}/release-manifest.json",
            set.delegated.signed.role.as_str(),
            plan.version
        )),
        &captured.manifest_bytes,
    )?;
    // The record is installed only as the delegated role authorized it: the
    // exact bytes named by the target entry, at the entry's path. A record
    // supplied without an entry, or an entry without a record, fails closed.
    let authorized_record = set
        .delegated
        .signed
        .targets
        .iter()
        .find(|target| target.release_id == plan.release_id)
        .and_then(|target| target.record.as_ref());
    match (authorized_record, args.release_record.as_deref()) {
        (None, None) => {}
        (Some(entry), Some(path)) => {
            let bytes = read_canonical_bytes(path, "release record")?;
            if Sha256Digest::of_bytes(&bytes) != entry.digest
                || bytes.len() as u64 != entry.length
                || entry.path != aos_release::record::record_path(plan.release_class, &plan.version)
            {
                bail!("release record does not match its delegated TUF target");
            }
            install_immutable(&surface.join(&entry.path), &bytes)?;
        }
        (Some(_), None) => {
            bail!("delegated TUF targets authorize a release record that was not supplied")
        }
        (None, Some(_)) => bail!("release record supplied without a delegated TUF target entry"),
    }
    let tuf = surface.join("tuf");
    fs::create_dir_all(&tuf)?;
    for (name, bytes) in [
        (format!("{}.root.json", set.root.signed.version), root_bytes),
        (
            format!("{}.targets.json", set.targets.signed.version),
            targets_bytes,
        ),
        (
            format!(
                "{}.{}.json",
                set.delegated.signed.version,
                set.delegated.signed.role.as_str()
            ),
            delegated_bytes,
        ),
        (
            format!("{}.snapshot.json", set.snapshot.signed.version),
            snapshot_bytes,
        ),
    ] {
        install_immutable(&tuf.join(name), &bytes)?;
    }
    install_mutable(&tuf.join("timestamp.json"), &timestamp_bytes)?;
    sync_directories(&surface)?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &surface,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.compose-surface-result/v1",
        "release_id": summary.release_id,
        "manifest_envelope_digest": manifest_envelope_digest,
        "snapshot_version": set.snapshot.signed.version,
        "timestamp_version": timestamp.signed.version,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Composed release {} with TUF snapshot {} and timestamp {} at {}",
        plan.release_id,
        set.snapshot.signed.version,
        timestamp.signed.version,
        args.output.display()
    ));
    Ok(())
}

fn read_canonical_bytes(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    Ok(bytes)
}

fn read_envelope<T>(path: &Path, label: &str) -> Result<(TufEnvelopeV1<T>, Vec<u8>)>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = read_canonical_bytes(path, label)?;
    let envelope = canonical::from_slice(&bytes, label)?;
    Ok((envelope, bytes))
}

fn parse_utc(value: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("surface verification time must be RFC 3339 UTC");
    }
    humantime::parse_rfc3339(value).context("parsing surface verification time")
}

fn install_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        if capture::control_file(path, "existing immutable surface object")? == bytes {
            return Ok(());
        }
        bail!("immutable surface object collision at {}", path.display());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn install_mutable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directories(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_dir() {
            sync_directories(&entry.path())?;
        } else if !metadata.is_file() {
            bail!("composed surface contains a non-regular object");
        }
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_install_allows_only_identical_existing_bytes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("object");
        install_immutable(&path, b"exact")?;
        install_immutable(&path, b"exact")?;
        assert!(install_immutable(&path, b"different").is_err());
        Ok(())
    }

    #[test]
    fn mutable_install_replaces_only_inside_private_composition() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("timestamp.json");
        install_mutable(&path, b"old")?;
        install_mutable(&path, b"new")?;
        assert_eq!(fs::read(path)?, b"new");
        Ok(())
    }
}
