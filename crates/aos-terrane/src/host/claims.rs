//! Owns the fixed host-global administrative project-ownership claim registry.
//!
//! Records are permanent, bounded canonical TOML outside Terrane content:
//! ```toml
//! version = 1
//! epoch = "00000000000000000000000000000001"
//! owner_id = "public-owner"
//! domain = "public"
//! project_id = 41001
//! hard_limit_bytes = 2097152
//! # registry, ledger and bindings retain actual native incarnations.
//! ```
//!
//! Ownership, epoch and limit changes are deliberately refused. A separately
//! reviewed host migration must reconcile existing claims; deleting a ledger
//! never releases a project and old ledgers are never adopted automatically.
//!
//! A separate, bounded 1024-byte `project-claims.identity` sibling permanently
//! binds the registry device and inode. A surviving anchor rejects replacement
//! even for a fresh ledger. Ordinary serving never creates missing records.
//! Complete loss of all administrative records is not recoverable cache loss;
//! administrator restoration or destructive re-enrollment requires a separate
//! recovery procedure outside automatic startup and this implementation.

use super::{Binding, HostConfig, Ledger, parse_error};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use terrane_fs::host_quota::{
    ConfiguredOwner, MAX_PROJECT_CLAIM_BYTES, RetainedProjectClaim, open_host_path,
    project_claim_name,
};

/// Fixes one common host registry for every configuration and ledger pathname.
pub(super) const REGISTRY_PATH: &str = "/var/lib/terrane-host/project-claims";
const ANCHOR_PATH: &str = "/var/lib/terrane-host/project-claims.identity";
const MAX_ANCHOR_BYTES: usize = 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryAnchor {
    version: u32,
    registry: RegistryIdentity,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Serialize)]
struct LedgerIdentity {
    parent_device: u64,
    parent_inode: u64,
    file_name: PathBuf,
}

#[derive(Serialize)]
struct ClaimRecord<'a> {
    version: u32,
    registry: &'a RegistryIdentity,
    ledger: &'a LedgerIdentity,
    epoch: &'a str,
    owner_id: &'a str,
    domain: &'a str,
    filesystem_uuid: [u8; 16],
    project_id: u32,
    hard_limit_bytes: u64,
    bindings: Vec<&'a Binding>,
}

pub(super) struct Registry {
    directory: File,
    identity: RegistryIdentity,
    ledger: LedgerIdentity,
}

impl Registry {
    pub(super) fn open(
        config: &HostConfig,
        ledger: &Path,
        initial_enrollment: bool,
    ) -> io::Result<Self> {
        let registry_path = Path::new(REGISTRY_PATH);
        if config
            .owners
            .iter()
            .flat_map(|owner| &owner.roots)
            .any(|root| {
                registry_path.starts_with(&root.path) || root.path.starts_with(registry_path)
            })
            || ledger.starts_with(registry_path)
        {
            return Err(io::Error::other(
                "project registry overlaps content or per-layout ledger",
            ));
        }
        let directory = open_host_path(registry_path, true)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(io::Error::other(
                "fixed project registry lacks private root custody",
            ));
        }
        let parent = ledger
            .parent()
            .ok_or_else(|| io::Error::other("ledger has no parent"))?;
        let parent = open_host_path(parent, true)?.metadata()?;
        if parent.uid() != 0 || parent.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "ledger parent lacks protected root custody",
            ));
        }
        let identity = RegistryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        validate_anchor(&identity, initial_enrollment)?;
        let name = ledger
            .file_name()
            .ok_or_else(|| io::Error::other("ledger has no filename"))?;
        Ok(Self {
            directory,
            identity,
            ledger: LedgerIdentity {
                parent_device: parent.dev(),
                parent_inode: parent.ino(),
                file_name: PathBuf::from(name),
            },
        })
    }

    pub(super) fn directory(&self) -> &File {
        &self.directory
    }

    pub(super) fn identity(&self) -> RegistryIdentity {
        self.identity.clone()
    }

    fn validate_identity(&self, ledger: &Ledger) -> io::Result<()> {
        validate_anchor(&self.identity, false)?;
        if ledger.registry != self.identity {
            return Err(io::Error::other(
                "host-global project registry was replaced",
            ));
        }
        let current = open_host_path(Path::new(REGISTRY_PATH), true)?.metadata()?;
        if current.dev() != self.identity.device
            || current.ino() != self.identity.inode
            || current.uid() != 0
            || current.mode() & 0o7777 != 0o700
        {
            return Err(io::Error::other(
                "host-global project registry incarnation changed",
            ));
        }
        Ok(())
    }

    fn records(
        &self,
        ledger: &Ledger,
        owners: &[ConfiguredOwner],
    ) -> io::Result<Vec<(String, Vec<u8>)>> {
        self.validate_identity(ledger)?;
        let mut records = Vec::new();
        for owner in owners {
            let bindings: Vec<_> = ledger
                .bindings
                .iter()
                .filter(|binding| {
                    binding.owner_id == owner.owner_id && binding.domain == owner.domain
                })
                .collect();
            if bindings.is_empty()
                || bindings.iter().any(|binding| {
                    binding.filesystem_uuid != owner.filesystem_uuid
                        || binding.project_id != owner.project_id
                        || binding.hard_limit_bytes != owner.hard_limit_bytes
                })
            {
                return Err(io::Error::other("incomplete project claim owner binding"));
            }
            let record = ClaimRecord {
                version: 1,
                registry: &self.identity,
                ledger: &self.ledger,
                epoch: &ledger.epoch,
                owner_id: &owner.owner_id,
                domain: &owner.domain,
                filesystem_uuid: owner.filesystem_uuid,
                project_id: owner.project_id,
                hard_limit_bytes: owner.hard_limit_bytes,
                bindings,
            };
            let bytes = toml::to_string(&record).map_err(parse_error)?.into_bytes();
            if bytes.is_empty() || bytes.len() > MAX_PROJECT_CLAIM_BYTES {
                return Err(io::Error::other(
                    "host project claim exceeds bounded record capacity",
                ));
            }
            records.push((
                project_claim_name(&owner.filesystem_uuid, owner.project_id)?,
                bytes,
            ));
        }
        Ok(records)
    }

    /// Claims are installed without replacement before any ledger custody or
    /// native project mutation. A crash can reserve capacity, never transfer it.
    pub(super) fn ensure(&self, ledger: &Ledger, owners: &[ConfiguredOwner]) -> io::Result<()> {
        let records = self.records(ledger, owners)?;
        // A competing enrollment can observe a linked anchor before its writer
        // has synced the parent. Make that publication durable ourselves before
        // any project claim or native mutation can depend on it.
        open_host_path(Path::new(ANCHOR_PATH), false)?.sync_all()?;
        let anchor_parent = Path::new(ANCHOR_PATH)
            .parent()
            .ok_or_else(|| io::Error::other("anchor has no parent"))?;
        open_host_path(anchor_parent, true)?.sync_all()?;
        for ((name, bytes), owner) in records.iter().zip(owners) {
            let target = Path::new(REGISTRY_PATH).join(name);
            match fs::symlink_metadata(&target) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.publish(name, bytes)?
                }
                Err(error) => return Err(error),
            }
            RetainedProjectClaim::open(
                Path::new(REGISTRY_PATH),
                Path::new(ANCHOR_PATH),
                &self.anchor_bytes()?,
                owner.filesystem_uuid,
                owner.project_id,
                bytes,
            )?;
            open_host_path(&target, false)?.sync_all()?;
        }
        self.directory.sync_all()
    }

    pub(super) fn bind(&self, ledger: &Ledger, owners: &mut [ConfiguredOwner]) -> io::Result<()> {
        let records = self.records(ledger, owners)?;
        for ((_, bytes), owner) in records.into_iter().zip(owners) {
            owner.claim = Some(RetainedProjectClaim::open(
                Path::new(REGISTRY_PATH),
                Path::new(ANCHOR_PATH),
                &self.anchor_bytes()?,
                owner.filesystem_uuid,
                owner.project_id,
                &bytes,
            )?);
        }
        Ok(())
    }

    fn anchor_bytes(&self) -> io::Result<Vec<u8>> {
        toml::to_string(&RegistryAnchor {
            version: 1,
            registry: self.identity.clone(),
        })
        .map(String::into_bytes)
        .map_err(parse_error)
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        publish_no_replace(Path::new(REGISTRY_PATH), &self.directory, name, bytes)
    }
}

fn read_anchor() -> io::Result<RegistryAnchor> {
    let mut file = open_host_path(Path::new(ANCHOR_PATH), false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_ANCHOR_BYTES as u64
    {
        return Err(io::Error::other(
            "registry anchor lacks bounded private root custody",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ANCHOR_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ANCHOR_BYTES {
        return Err(io::Error::other("registry anchor exceeds bound"));
    }
    let text = std::str::from_utf8(&bytes).map_err(parse_error)?;
    toml::from_str(text).map_err(parse_error)
}

fn validate_anchor(identity: &RegistryIdentity, initial_enrollment: bool) -> io::Result<()> {
    let anchor = match read_anchor() {
        Ok(anchor) => anchor,
        Err(error) if error.kind() == io::ErrorKind::NotFound && initial_enrollment => {
            // Only explicit first provisioning may enroll an empty registry.
            // An existing ledger or any registry record forbids reconstruction.
            if fs::read_dir(REGISTRY_PATH)?.next().is_some() {
                return Err(io::Error::other(
                    "missing anchor for an already populated registry",
                ));
            }
            let bytes = toml::to_string(&RegistryAnchor {
                version: 1,
                registry: identity.clone(),
            })
            .map_err(parse_error)?
            .into_bytes();
            if bytes.len() > MAX_ANCHOR_BYTES {
                return Err(io::Error::other("registry anchor exceeds bound"));
            }
            let parent = Path::new(ANCHOR_PATH)
                .parent()
                .ok_or_else(|| io::Error::other("anchor has no parent"))?;
            let directory = open_host_path(parent, true)?;
            let metadata = directory.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
                return Err(io::Error::other("anchor parent lacks private root custody"));
            }
            publish_no_replace(parent, &directory, "project-claims.identity", &bytes)?;
            read_anchor()?
        }
        Err(error) => return Err(error),
    };
    if anchor.version != 1 || anchor.registry != *identity {
        return Err(io::Error::other(
            "fixed registry anchor identifies another registry incarnation",
        ));
    }
    Ok(())
}

fn publish_no_replace(parent: &Path, directory: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = parent.join(format!(".claim-{}-{sequence}", std::process::id()));
    let target = parent.join(name);
    let mut created = false;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        created = true;
        output.write_all(bytes)?;
        output.sync_all()?;
        match fs::hard_link(&temporary, &target) {
            Ok(()) => directory.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    if created {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_publication_survives_restart_and_refuses_collision() {
        let parent =
            std::env::temp_dir().join(format!("terrane-project-claim-{}", std::process::id()));
        fs::create_dir(&parent).expect("exclusive test directory");
        let directory = File::open(&parent).expect("retained directory");

        publish_no_replace(&parent, &directory, "project.toml", b"owner A").expect("first claim");
        publish_no_replace(&parent, &directory, "project.toml", b"owner A")
            .expect("matching retry");
        publish_no_replace(&parent, &directory, "project.toml", b"owner B")
            .expect("collision does not replace");

        assert_eq!(
            fs::read(parent.join("project.toml")).expect("durable claim"),
            b"owner A"
        );
        assert_eq!(fs::read_dir(&parent).expect("inventory").count(), 1);
        fs::remove_file(parent.join("project.toml")).expect("test cleanup");
        fs::remove_dir(parent).expect("directory cleanup");
    }

    #[test]
    fn concurrent_claims_publish_one_complete_record() {
        let parent = std::env::temp_dir().join(format!(
            "terrane-project-claim-concurrent-{}",
            std::process::id()
        ));
        fs::create_dir(&parent).expect("exclusive test directory");
        let workers: Vec<_> = [b"owner A".as_slice(), b"owner B".as_slice()]
            .into_iter()
            .map(|bytes| {
                let parent = parent.clone();
                std::thread::spawn(move || {
                    let directory = File::open(&parent).expect("retained directory");
                    publish_no_replace(&parent, &directory, "project.toml", bytes)
                        .expect("atomic publication");
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("publication worker");
        }

        let bytes = fs::read(parent.join("project.toml")).expect("complete record");
        assert!(bytes == b"owner A" || bytes == b"owner B");
        assert_eq!(fs::read_dir(&parent).expect("inventory").count(), 1);
        fs::remove_file(parent.join("project.toml")).expect("test cleanup");
        fs::remove_dir(parent).expect("directory cleanup");
    }
}
