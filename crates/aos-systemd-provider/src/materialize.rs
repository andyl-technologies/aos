//! Secure, idempotent publication of packaged units and provider drop-ins.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_ability_model::{ResourceId, RevisionId};
use tempfile::NamedTempFile;

use crate::model::RevisionReceipt;
use crate::render::{DROP_IN_FILE, RenderedUnit};

const RECEIPT_SCHEMA: &str = "aos.systemd.packaged-unit-revision/v1";

pub(crate) struct UnitPaths {
    pub(crate) unit: PathBuf,
    pub(crate) drop_in: PathBuf,
    pub(crate) receipt: PathBuf,
}

pub(crate) fn paths_for(root: &Path, unit_name: &str, revision: RevisionId) -> UnitPaths {
    UnitPaths {
        unit: root.join("systemd/system").join(unit_name),
        drop_in: root
            .join("systemd/system")
            .join(format!("{unit_name}.d"))
            .join(DROP_IN_FILE),
        receipt: root
            .join("aos/ability-revisions")
            .join(unit_name)
            .join("sha256")
            .join(revision.0.hex()),
    }
}

pub(crate) fn materialize(
    root: &Path,
    unit_name: &str,
    revision: RevisionId,
    resource: &ResourceId,
    rendered: &RenderedUnit,
) -> Result<UnitPaths> {
    let paths = paths_for(root, unit_name, revision);
    let systemd_root = root.join("systemd/system");
    ensure_directory(&systemd_root)?;
    publish_symlink(&paths.unit, &rendered.source)?;

    let drop_in_directory = paths
        .drop_in
        .parent()
        .ok_or_else(|| anyhow::anyhow!("drop-in path has no parent"))?;
    ensure_directory(drop_in_directory)?;
    publish_file(&paths.drop_in, &rendered.drop_in)?;

    let receipt_directory = paths
        .receipt
        .parent()
        .ok_or_else(|| anyhow::anyhow!("receipt path has no parent"))?;
    ensure_directory(receipt_directory)?;
    let bytes = receipt_bytes(resource, unit_name, revision)?;
    publish_file(&paths.receipt, &bytes)?;

    Ok(paths)
}

pub(crate) fn matches(
    paths: &UnitPaths,
    rendered: &RenderedUnit,
    resource: &ResourceId,
    unit_name: &str,
    revision: RevisionId,
) -> Result<bool> {
    let link_matches = match fs::read_link(&paths.unit) {
        Ok(target) => target == rendered.source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("reading packaged-unit link"),
    };
    let drop_in_matches = match fs::read(&paths.drop_in) {
        Ok(bytes) => bytes == rendered.drop_in,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("reading packaged-unit drop-in"),
    };
    let expected_receipt = receipt_bytes(resource, unit_name, revision)?;
    let receipt_matches = match fs::read(&paths.receipt) {
        Ok(bytes) => bytes == expected_receipt,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("reading packaged-unit revision receipt"),
    };
    Ok(link_matches && drop_in_matches && receipt_matches)
}

fn receipt_bytes(resource: &ResourceId, unit_name: &str, revision: RevisionId) -> Result<Vec<u8>> {
    let receipt = RevisionReceipt {
        schema: RECEIPT_SCHEMA,
        resource,
        unit_name,
        revision,
    };
    aos_contract::canonical::to_vec(&receipt).context("encoding revision receipt")
}

fn ensure_directory(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "managed systemd path traverses symlink {}",
                    current.display()
                );
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "managed systemd path is not a directory: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("creating {}", current.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(())
}

fn publish_symlink(path: &Path, target: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && !metadata.file_type().is_symlink()
    {
        bail!(
            "refusing to replace non-symlink unit path {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unit path has no parent"))?;
    let temporary = parent.join(format!(
        ".{}.aos-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unit"),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    symlink(target, &temporary).context("creating temporary packaged-unit link")?;
    fs::rename(&temporary, path).context("publishing packaged-unit link")?;
    Ok(())
}

fn publish_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file() || metadata.file_type().is_symlink())
    {
        bail!(
            "refusing to replace non-regular managed file {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("managed file has no parent"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file below {}", parent.display()))?;
    temporary.write_all(bytes).context("writing managed file")?;
    temporary
        .as_file()
        .sync_all()
        .context("syncing managed file")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing {}", path.display()))?;
    OpenOptions::new()
        .read(true)
        .open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aos_ability_model::{EnvironmentId, InstanceId, LocalKey, ResourceId, RevisionId};
    use aos_contract::Sha256Digest;
    use tempfile::TempDir;

    use super::{matches, materialize, paths_for};
    use crate::render::RenderedUnit;

    fn resource() -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority parses"),
                    key: LocalKey::new("environment").expect("environment parses"),
                    stage: aos_ability_model::ExecutionStage::Host,
                },
                key: LocalKey::new("provider").expect("provider parses"),
            },
            key: LocalKey::new("unit").expect("resource key parses"),
        }
    }

    #[test]
    fn materialization_is_exact_and_rejects_symlinked_parent() {
        let temporary = TempDir::new().expect("temporary root exists");
        let artifact = temporary.path().join("artifact");
        fs::create_dir(&artifact).expect("artifact directory exists");
        let source = artifact.join("example.service");
        fs::write(&source, b"[Service]\nExecStart=/bin/false\n").expect("source is written");
        let rendered = RenderedUnit {
            source,
            drop_in: b"[Unit]\nDescription=test\n".to_vec(),
        };
        let digest = Sha256Digest::parse(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("digest parses");
        let revision = RevisionId(digest);
        let receipt_path = paths_for(temporary.path(), "example.service", revision).receipt;
        assert!(receipt_path.ends_with(format!("sha256/{}", digest.hex())));
        assert!(!receipt_path.ends_with("current"));

        let paths = materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("unit materializes");
        assert!(
            matches(&paths, &rendered, &resource(), "example.service", revision,)
                .expect("materialization is observable")
        );

        let files_before_concurrent_change =
            matches(&paths, &rendered, &resource(), "example.service", revision)
                .expect("first file observation succeeds");
        fs::write(&paths.drop_in, b"[Unit]\nDescription=replaced\n")
            .expect("drop-in is concurrently replaced");
        let files_after_concurrent_change =
            matches(&paths, &rendered, &resource(), "example.service", revision)
                .expect("second file observation succeeds");
        assert!(files_before_concurrent_change);
        assert!(!files_after_concurrent_change);

        materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("unit rematerializes after concurrent replacement");

        fs::write(&paths.receipt, b"{}\n").expect("receipt is corrupted");
        assert!(
            !matches(&paths, &rendered, &resource(), "example.service", revision,)
                .expect("corrupt receipt remains observable")
        );

        materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("unit rematerializes exactly");

        let next_digest = Sha256Digest::parse(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("second digest parses");
        let next_revision = RevisionId(next_digest);
        let next_paths = materialize(
            temporary.path(),
            "example.service",
            next_revision,
            &resource(),
            &rendered,
        )
        .expect("next revision materializes");
        assert_ne!(paths.receipt, next_paths.receipt);
        assert!(paths.receipt.is_file());
        assert!(next_paths.receipt.is_file());

        fs::remove_dir_all(temporary.path().join("systemd/system/example.service.d"))
            .expect("drop-in directory removes");
        std::os::unix::fs::symlink(
            temporary.path().join("artifact"),
            temporary.path().join("systemd/system/example.service.d"),
        )
        .expect("symlink fixture exists");
        assert!(
            materialize(
                temporary.path(),
                "example.service",
                revision,
                &resource(),
                &rendered
            )
            .is_err()
        );
    }
}
