//! Secure, idempotent publication of packaged units and provider drop-ins.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_ability_model::{ResourceId, RevisionId};
use tempfile::NamedTempFile;

use crate::model::{RevisionReceipt, ServiceReceiptLink, ServiceRevisionReceipt};
use crate::render::{DROP_IN_FILE, RenderedService, RenderedUnit};

const RECEIPT_SCHEMA: &str = "aos.systemd.packaged-unit-revision/v1";
const SERVICE_RECEIPT_SCHEMA: &str = "aos.systemd.service-revision/v1";

pub(crate) struct UnitPaths {
    pub(crate) unit: PathBuf,
    pub(crate) drop_in: PathBuf,
    pub(crate) receipt: PathBuf,
}

pub(crate) struct ServicePaths {
    pub(crate) units: Vec<PathBuf>,
    pub(crate) links: Vec<PathBuf>,
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

pub(crate) fn service_paths_for(
    root: &Path,
    primary_unit: &str,
    revision: RevisionId,
    rendered: &RenderedService,
) -> ServicePaths {
    ServicePaths {
        units: rendered
            .units
            .iter()
            .map(|unit| root.join("systemd/system").join(&unit.name))
            .collect(),
        links: rendered
            .links
            .iter()
            .map(|link| root.join("systemd/system").join(&link.path))
            .collect(),
        receipt: root
            .join("aos/ability-revisions")
            .join(primary_unit)
            .join("sha256")
            .join(revision.0.hex()),
    }
}

pub(crate) fn materialize_service(
    root: &Path,
    primary_unit: &str,
    revision: RevisionId,
    resource: &ResourceId,
    rendered: &RenderedService,
) -> Result<ServicePaths> {
    let paths = service_paths_for(root, primary_unit, revision, rendered);
    let systemd_root = root.join("systemd/system");
    ensure_directory(&systemd_root)?;

    for (path, unit) in paths.units.iter().zip(&rendered.units) {
        publish_file(path, &unit.bytes)?;
    }
    for (path, link) in paths.links.iter().zip(&rendered.links) {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("service installation link has no parent"))?;
        ensure_directory(parent)?;
        publish_symlink(path, Path::new(&link.target))?;
    }

    let receipt_directory = paths
        .receipt
        .parent()
        .ok_or_else(|| anyhow::anyhow!("service receipt path has no parent"))?;
    ensure_directory(receipt_directory)?;
    publish_file(
        &paths.receipt,
        &service_receipt_bytes(resource, revision, rendered)?,
    )?;

    Ok(paths)
}

pub(crate) fn service_matches(
    paths: &ServicePaths,
    rendered: &RenderedService,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<bool> {
    if paths.units.len() != rendered.units.len() {
        bail!("service path set differs from its rendered unit set");
    }
    for (path, unit) in paths.units.iter().zip(&rendered.units) {
        match fs::read(path) {
            Ok(bytes) if bytes == unit.bytes => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        }
    }
    if paths.links.len() != rendered.links.len() {
        bail!("service link path set differs from its rendered installation set");
    }
    for (path, link) in paths.links.iter().zip(&rendered.links) {
        match fs::read_link(path) {
            Ok(target) if target == Path::new(&link.target) => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        }
    }

    let expected_receipt = service_receipt_bytes(resource, revision, rendered)?;
    match fs::read(&paths.receipt) {
        Ok(bytes) => Ok(bytes == expected_receipt),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("reading service revision receipt"),
    }
}

pub(crate) fn remove_service(
    paths: &ServicePaths,
    rendered: &RenderedService,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<()> {
    let presence = service_removal_presence(paths, rendered, resource, revision)?;

    for (path, present) in paths.units.iter().zip(presence.units) {
        if present {
            remove_managed_path(path)?;
        }
    }
    for (path, present) in paths.links.iter().zip(presence.links) {
        if present {
            remove_managed_path(path)?;
        }
    }
    if presence.receipt {
        remove_managed_path(&paths.receipt)?;
    }
    Ok(())
}

pub(crate) fn service_is_absent(paths: &ServicePaths) -> Result<bool> {
    for path in paths
        .units
        .iter()
        .chain(&paths.links)
        .chain(std::iter::once(&paths.receipt))
    {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        }
    }
    Ok(true)
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

pub(crate) fn remove(
    paths: &UnitPaths,
    rendered: &RenderedUnit,
    resource: &ResourceId,
    unit_name: &str,
    revision: RevisionId,
) -> Result<()> {
    let presence = removal_presence(paths, rendered, resource, unit_name, revision)?;

    if presence.unit {
        remove_managed_path(&paths.unit)?;
    }
    if presence.drop_in {
        remove_managed_path(&paths.drop_in)?;
    }
    if presence.receipt {
        remove_managed_path(&paths.receipt)?;
    }
    Ok(())
}

pub(crate) fn validate_removal(
    paths: &UnitPaths,
    rendered: &RenderedUnit,
    resource: &ResourceId,
    unit_name: &str,
    revision: RevisionId,
) -> Result<()> {
    removal_presence(paths, rendered, resource, unit_name, revision)?;
    Ok(())
}

struct RemovalPresence {
    unit: bool,
    drop_in: bool,
    receipt: bool,
}

struct ServiceRemovalPresence {
    units: Vec<bool>,
    links: Vec<bool>,
    receipt: bool,
}

fn service_removal_presence(
    paths: &ServicePaths,
    rendered: &RenderedService,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<ServiceRemovalPresence> {
    if paths.units.len() != rendered.units.len() || paths.links.len() != rendered.links.len() {
        bail!("service path set differs from its rendered materialization");
    }

    let units = paths
        .units
        .iter()
        .zip(&rendered.units)
        .map(|(path, unit)| verify_file_exact_or_absent(path, &unit.bytes))
        .collect::<Result<Vec<_>>>()?;
    let links = paths
        .links
        .iter()
        .zip(&rendered.links)
        .map(|(path, link)| verify_symlink_exact_or_absent(path, Path::new(&link.target)))
        .collect::<Result<Vec<_>>>()?;
    let receipt = verify_file_exact_or_absent(
        &paths.receipt,
        &service_receipt_bytes(resource, revision, rendered)?,
    )?;

    Ok(ServiceRemovalPresence {
        units,
        links,
        receipt,
    })
}

fn removal_presence(
    paths: &UnitPaths,
    rendered: &RenderedUnit,
    resource: &ResourceId,
    unit_name: &str,
    revision: RevisionId,
) -> Result<RemovalPresence> {
    let expected_receipt = receipt_bytes(resource, unit_name, revision)?;
    let unit_present = verify_symlink_exact_or_absent(&paths.unit, &rendered.source)?;
    let drop_in_present = verify_file_exact_or_absent(&paths.drop_in, &rendered.drop_in)?;
    let receipt_present = verify_file_exact_or_absent(&paths.receipt, &expected_receipt)?;

    Ok(RemovalPresence {
        unit: unit_present,
        drop_in: drop_in_present,
        receipt: receipt_present,
    })
}

pub(crate) fn is_absent(paths: &UnitPaths) -> Result<bool> {
    for path in [&paths.unit, &paths.drop_in, &paths.receipt] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        }
    }
    Ok(true)
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

fn service_receipt_bytes(
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
) -> Result<Vec<u8>> {
    let receipt = ServiceRevisionReceipt {
        schema: SERVICE_RECEIPT_SCHEMA,
        resource,
        units: rendered
            .units
            .iter()
            .map(|unit| unit.name.as_str())
            .collect(),
        links: rendered
            .links
            .iter()
            .map(|link| ServiceReceiptLink {
                path: &link.path,
                target: &link.target,
            })
            .collect(),
        revision,
    };
    aos_contract::canonical::to_vec(&receipt).context("encoding service revision receipt")
}

pub(crate) fn ensure_directory(path: &Path) -> Result<()> {
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
                if let Some(parent) = current
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    sync_directory(parent)?;
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(())
}

fn verify_symlink_exact_or_absent(path: &Path, expected: &Path) -> Result<bool> {
    match fs::read_link(path) {
        Ok(target) if target == expected => Ok(true),
        Ok(_) => bail!("refusing to remove changed symlink {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

pub(crate) fn verify_file_exact_or_absent(path: &Path, expected: &[u8]) -> Result<bool> {
    match fs::read(path) {
        Ok(bytes) if bytes == expected => Ok(true),
        Ok(_) => bail!("refusing to remove changed file {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

pub(crate) fn remove_managed_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("managed path has no parent"))?;
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    sync_directory(parent)
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
    sync_directory(parent)?;
    Ok(())
}

pub(crate) fn publish_file(path: &Path, bytes: &[u8]) -> Result<()> {
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
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aos_ability_model::{EnvironmentId, InstanceId, LocalKey, ResourceId, RevisionId};
    use aos_contract::Sha256Digest;
    use tempfile::TempDir;

    use super::{
        is_absent, matches, materialize, materialize_service, paths_for, remove, remove_service,
        service_is_absent, service_matches, service_paths_for,
    };
    use crate::render::{RenderedService, RenderedServiceLink, RenderedServiceUnit, RenderedUnit};

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

    fn rendered_service() -> RenderedService {
        RenderedService {
            primary_unit: "example.service".to_string(),
            units: vec![
                RenderedServiceUnit {
                    name: "example.service".to_string(),
                    bytes: b"[Service]\nExecStart=/example\n".to_vec(),
                },
                RenderedServiceUnit {
                    name: "example.socket".to_string(),
                    bytes: b"[Socket]\nListenStream=1\n".to_vec(),
                },
            ],
            links: vec![RenderedServiceLink {
                path: "multi-user.target.wants/example.service".to_string(),
                target: "../example.service".to_string(),
            }],
        }
    }

    #[test]
    fn service_materialization_binds_all_exact_unit_bytes_to_the_receipt() {
        let root = TempDir::new().expect("temporary root");
        let revision = RevisionId(Sha256Digest::from_bytes([9; 32]));
        let rendered = rendered_service();
        let paths = materialize_service(
            root.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("service materializes");

        assert!(
            service_matches(&paths, &rendered, &resource(), revision)
                .expect("service state is readable")
        );
        assert_eq!(
            fs::read_link(&paths.links[0]).expect("installation link is readable"),
            std::path::Path::new("../example.service")
        );
        fs::write(&paths.units[1], b"[Socket]\nListenStream=2\n").expect("unit changes");
        assert!(
            !service_matches(&paths, &rendered, &resource(), revision)
                .expect("changed service state is readable")
        );
        assert_eq!(
            service_paths_for(root.path(), "example.service", revision, &rendered).units,
            paths.units
        );
    }

    #[test]
    fn service_removal_is_exact_and_idempotent() {
        let root = TempDir::new().expect("temporary root");
        let revision = RevisionId(Sha256Digest::from_bytes([10; 32]));
        let rendered = rendered_service();
        let paths = materialize_service(
            root.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("service materializes");

        remove_service(&paths, &rendered, &resource(), revision).expect("service removes");
        assert!(service_is_absent(&paths).expect("absence is observable"));
        remove_service(&paths, &rendered, &resource(), revision).expect("removal is idempotent");

        materialize_service(
            root.path(),
            "example.service",
            revision,
            &resource(),
            &rendered,
        )
        .expect("service rematerializes");
        fs::write(&paths.units[0], b"[Service]\nExecStart=/changed\n").expect("unit changes");
        assert!(remove_service(&paths, &rendered, &resource(), revision).is_err());
        assert!(paths.units[0].exists());
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

    #[test]
    fn removal_is_exact_durable_and_idempotent() {
        let temporary = TempDir::new().expect("temporary root exists");
        let artifact = temporary.path().join("artifact");
        fs::create_dir(&artifact).expect("artifact directory exists");
        let source = artifact.join("example.service");
        fs::write(&source, b"[Service]\nExecStart=/example\n").expect("source unit exists");
        let rendered = RenderedUnit {
            source,
            drop_in: b"[Service]\nSuccessExitStatus=0 2\n".to_vec(),
        };
        let revision = RevisionId(Sha256Digest::from_bytes([7; 32]));
        let resource = resource();
        let paths = materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource,
            &rendered,
        )
        .expect("materialization succeeds");

        remove(&paths, &rendered, &resource, "example.service", revision)
            .expect("exact removal succeeds");
        assert!(is_absent(&paths).expect("absence is observable"));
        remove(&paths, &rendered, &resource, "example.service", revision)
            .expect("interrupted removal reconciliation is idempotent");

        materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource,
            &rendered,
        )
        .expect("materialization can be recreated");
        fs::remove_file(&paths.unit).expect("interrupted removal can unlink the unit first");
        remove(&paths, &rendered, &resource, "example.service", revision)
            .expect("reconciliation finishes a partial removal");
        assert!(is_absent(&paths).expect("reconciled removal is observable"));

        materialize(
            temporary.path(),
            "example.service",
            revision,
            &resource,
            &rendered,
        )
        .expect("materialization can be recreated again");
        fs::write(&paths.drop_in, b"changed").expect("drop-in can change concurrently");
        assert!(remove(&paths, &rendered, &resource, "example.service", revision).is_err());
        assert!(paths.unit.is_symlink());
        assert_eq!(
            fs::read(&paths.drop_in).expect("changed drop-in remains"),
            b"changed"
        );
    }
}
