//! Assembly of renderer-produced systemd artifacts into the boot unit tree.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::model::{STATIC_MANIFEST_SCHEMA, StaticUnitManifest, StaticUnitManifestEntry};

const MANIFEST_PATH: &str = "share/aos/systemd-unit-manifest.json";
const UNIT_ROOT: &str = "lib/systemd/system";

pub(crate) fn run() -> Result<()> {
    let base = PathBuf::from(env::var("baseUnits").context("base unit tree is not set")?);
    let roots_path =
        env::var("providerArtifactsPath").context("provider artifact list path is not set")?;
    let output = PathBuf::from(env::var("out").context("assembly output is not set")?);
    let roots: Vec<PathBuf> =
        serde_json::from_slice(&fs::read(roots_path).context("reading provider artifact list")?)
            .context("decoding provider artifact list")?;

    fs::create_dir_all(&output).context("creating assembled systemd unit root")?;
    copy_tree(&base, &output)?;
    remove_copied_platform_marker(&output)?;

    let mut claimed = collect_paths(&output)?;
    for root in roots {
        install_artifact(&root, &output, &mut claimed)?;
    }
    Ok(())
}

fn remove_copied_platform_marker(output: &Path) -> Result<()> {
    // The derivation fixup writes its own platform marker. A copied Nix store
    // marker is read-only and cannot be overwritten in place.
    let marker = output.join("nix-support/aos-target-platform");
    match fs::remove_file(&marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("removing copied target platform marker"),
    }
}

fn install_artifact(root: &Path, output: &Path, claimed: &mut BTreeSet<PathBuf>) -> Result<()> {
    let bytes = fs::read(root.join(MANIFEST_PATH))
        .with_context(|| format!("reading systemd manifest from {}", root.display()))?;
    let manifest: StaticUnitManifest =
        serde_json::from_slice(&bytes).context("decoding systemd unit manifest")?;
    if manifest.schema != STATIC_MANIFEST_SCHEMA {
        bail!("systemd artifact uses an unsupported manifest schema");
    }
    crate::render::validate_unit_name(&manifest.primary.unit_name)?;
    if manifest
        .primary
        .logical_instance
        .as_ref()
        .is_some_and(String::is_empty)
    {
        bail!("systemd artifact manifest has an empty logical instance");
    }

    let mut previous = None;
    for entry in &manifest.entries {
        let relative = checked_unit_path(manifest_path(entry))?;
        if previous.as_ref().is_some_and(|path| path >= &relative) {
            bail!("systemd manifest entries are not unique and canonically ordered");
        }
        previous = Some(relative.clone());

        let destination = relative
            .strip_prefix(UNIT_ROOT)
            .context("systemd manifest entry lies outside the unit root")?;
        let destination = output.join(destination);
        reject_collision(&destination, output, claimed)?;
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("systemd artifact entry has no parent"))?;
        fs::create_dir_all(parent).context("creating assembled unit directory")?;

        let source = root.join(&relative);
        match entry {
            StaticUnitManifestEntry::File { content, .. } => {
                let source_bytes = fs::read(&source)
                    .with_context(|| format!("reading rendered unit {}", source.display()))?;
                if aos_contract::Sha256Digest::of_bytes(&source_bytes) != *content {
                    bail!("rendered systemd unit does not match its manifest digest");
                }
                fs::write(&destination, source_bytes)
                    .context("installing rendered systemd unit")?;
            }
            StaticUnitManifestEntry::Symlink { target, .. } => {
                let actual = fs::read_link(&source)
                    .with_context(|| format!("reading rendered link {}", source.display()))?;
                if actual != Path::new(target) {
                    bail!("rendered systemd link does not match its manifest target");
                }
                symlink(target, &destination).context("installing rendered systemd link")?;
            }
        }
        claimed.insert(destination);
    }
    Ok(())
}

fn checked_unit_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.starts_with(UNIT_ROOT)
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path == Path::new(UNIT_ROOT)
    {
        bail!("systemd manifest contains an unsafe unit path");
    }
    Ok(path)
}

fn reject_collision(path: &Path, output: &Path, claimed: &BTreeSet<PathBuf>) -> Result<()> {
    if claimed.iter().any(|existing| {
        existing == path
            || existing.starts_with(path)
            || (path.starts_with(existing) && existing != output)
    }) {
        bail!("provider-rendered systemd path collides with another unit entry");
    }
    Ok(())
}

fn collect_paths(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    collect_paths_at(root, &mut paths)?;
    Ok(paths)
}

fn collect_paths_at(path: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry.context("reading systemd unit tree entry")?;
        let entry_path = entry.path();
        if entry
            .file_type()
            .context("reading systemd entry type")?
            .is_dir()
        {
            collect_paths_at(&entry_path, paths)?;
        } else {
            paths.insert(entry_path);
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry.context("reading base systemd entry")?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .context("reading base systemd entry type")?;
        if file_type.is_dir() {
            fs::create_dir(&destination_path).context("creating base systemd directory")?;
            copy_tree(&source_path, &destination_path)?;
        } else if file_type.is_symlink() {
            symlink(fs::read_link(&source_path)?, &destination_path)
                .context("copying base systemd symlink")?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).context("copying base systemd unit")?;
        } else {
            bail!("base systemd tree contains an unsupported entry type");
        }
    }
    Ok(())
}

fn manifest_path(entry: &StaticUnitManifestEntry) -> &str {
    match entry {
        StaticUnitManifestEntry::File { path, .. }
        | StaticUnitManifestEntry::Symlink { path, .. } => path,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{MANIFEST_PATH, install_artifact, remove_copied_platform_marker};
    use crate::model::{
        STATIC_MANIFEST_SCHEMA, StaticPrimaryUnit, StaticUnitManifest, StaticUnitManifestEntry,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aos-systemd-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn rendered_artifact() -> std::path::PathBuf {
        let root = temporary_directory("artifact");
        let unit_path = root.join("lib/systemd/system/example.service");
        fs::create_dir_all(unit_path.parent().expect("unit has a parent"))
            .expect("unit directory is created");
        let bytes = b"[Service]\nExecStart=/bin/true\n";
        fs::write(&unit_path, bytes).expect("unit is written");
        let link_path = root.join("lib/systemd/system/multi-user.target.wants/example.service");
        fs::create_dir_all(link_path.parent().expect("link has a parent"))
            .expect("link directory is created");
        symlink("../example.service", &link_path).expect("link is created");

        let manifest = StaticUnitManifest {
            schema: STATIC_MANIFEST_SCHEMA.to_string(),
            primary: StaticPrimaryUnit {
                unit_name: "example.service".to_string(),
                logical_instance: None,
            },
            entries: vec![
                StaticUnitManifestEntry::File {
                    path: "lib/systemd/system/example.service".to_string(),
                    content: aos_contract::Sha256Digest::of_bytes(bytes),
                },
                StaticUnitManifestEntry::Symlink {
                    path: "lib/systemd/system/multi-user.target.wants/example.service".to_string(),
                    target: "../example.service".to_string(),
                },
            ],
        };
        let manifest_path = root.join(MANIFEST_PATH);
        fs::create_dir_all(manifest_path.parent().expect("manifest has a parent"))
            .expect("manifest directory is created");
        fs::write(
            manifest_path,
            aos_contract::canonical::to_vec(&manifest).expect("manifest is canonical"),
        )
        .expect("manifest is written");
        root
    }

    #[test]
    fn manifest_bytes_and_targets_are_the_only_installed_filename_authority() {
        let artifact = rendered_artifact();
        let output = temporary_directory("assembled");
        fs::create_dir(&output).expect("output is created");

        install_artifact(&artifact, &output, &mut BTreeSet::new())
            .expect("valid artifact is installed");

        assert_eq!(
            fs::read(output.join("example.service")).expect("unit is installed"),
            b"[Service]\nExecStart=/bin/true\n"
        );
        assert_eq!(
            fs::read_link(output.join("multi-user.target.wants/example.service"))
                .expect("activation link is installed"),
            std::path::Path::new("../example.service")
        );

        fs::remove_dir_all(artifact).expect("artifact is removable");
        fs::remove_dir_all(output).expect("output is removable");
    }

    #[test]
    fn manifest_tampering_and_existing_path_collisions_fail_closed() {
        let tampered_artifact = rendered_artifact();
        fs::write(
            tampered_artifact.join("lib/systemd/system/example.service"),
            "changed",
        )
        .expect("unit is changed");
        let output = temporary_directory("collision");
        fs::create_dir(&output).expect("output is created");
        assert!(install_artifact(&tampered_artifact, &output, &mut BTreeSet::new()).is_err());
        fs::remove_dir_all(tampered_artifact).expect("tampered artifact is removable");

        let artifact = rendered_artifact();
        fs::write(output.join("example.service"), "base").expect("base unit is written");
        let mut claimed = BTreeSet::new();
        claimed.insert(output.join("example.service"));
        assert!(install_artifact(&artifact, &output, &mut claimed).is_err());

        fs::remove_dir_all(artifact).expect("artifact is removable");
        fs::remove_dir_all(output).expect("output is removable");
    }

    #[test]
    fn copied_platform_marker_is_removed_before_derivation_fixup() {
        let output = temporary_directory("platform-marker");
        let support = output.join("nix-support");
        fs::create_dir_all(&support).expect("support directory is created");

        let marker = support.join("aos-target-platform");
        fs::write(&marker, "x86_64-linux\n").expect("marker is written");
        let mut permissions = fs::metadata(&marker)
            .expect("marker metadata is read")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&marker, permissions).expect("marker is made read-only");

        remove_copied_platform_marker(&output).expect("copied marker is removed");
        fs::write(&marker, "aarch64-linux\n").expect("fixup can write its own marker");
        assert_eq!(
            fs::read_to_string(&marker).expect("new marker is readable"),
            "aarch64-linux\n"
        );

        fs::remove_dir_all(output).expect("output is removable");
    }
}
