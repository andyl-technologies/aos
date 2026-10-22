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
use terrane_linux::host_quota::{
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

#[derive(Serialize)]
struct InitialClaimRecord<'a> {
    version: u32,
    registry: &'a RegistryIdentity,
    ledger: &'a LedgerIdentity,
    epoch: &'a str,
    creator: &'a super::initial_enrollment::model::Creator,
    role: &'a super::initial_enrollment::model::RoleOwner,
    entries: Vec<&'a super::initial_enrollment::model::Entry>,
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
            self.directory.sync_all()?;
            #[cfg(test)]
            super::provisioning_test_checkpoint("claim-durable")?;
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

    fn initial_records(
        &self,
        ledger: &super::initial_enrollment::InitialLedger,
        owners: &[ConfiguredOwner],
    ) -> io::Result<Vec<(String, Vec<u8>)>> {
        validate_anchor(&self.identity, false)?;
        if ledger.registry != self.identity {
            return Err(io::Error::other(
                "initial project registry incarnation changed",
            ));
        }
        let current = open_host_path(Path::new(REGISTRY_PATH), true)?.metadata()?;
        if current.dev() != self.identity.device
            || current.ino() != self.identity.inode
            || current.uid() != 0
            || current.mode() & 0o7777 != 0o700
        {
            return Err(io::Error::other("initial project registry custody changed"));
        }
        let mut records = Vec::new();
        for owner in owners {
            let creator = ledger
                .creators
                .iter()
                .find(|creator| {
                    creator.owner_id == owner.owner_id && creator.domain == owner.domain
                })
                .ok_or_else(|| io::Error::other("initial claim omits a configured creator"))?;
            let entries: Vec<_> = ledger
                .entries
                .iter()
                .filter(|entry| entry.owner_id == owner.owner_id && entry.domain == owner.domain)
                .collect();
            if creator.filesystem_uuid != owner.filesystem_uuid
                || creator.project_id != owner.project_id
                || creator.hard_limit_bytes != owner.hard_limit_bytes
                || entries.is_empty()
            {
                return Err(io::Error::other(
                    "initial claim owner does not match its finite partition",
                ));
            }
            let record = InitialClaimRecord {
                version: 2,
                registry: &self.identity,
                ledger: &self.ledger,
                epoch: &ledger.epoch,
                creator,
                role: ledger
                    .roles
                    .iter()
                    .find(|role| role.owner_id == owner.owner_id && role.domain == owner.domain)
                    .ok_or_else(|| io::Error::other("initial claim has no explicit role policy"))?,
                entries,
            };
            let bytes = toml::to_string(&record).map_err(parse_error)?.into_bytes();
            if bytes.is_empty() || bytes.len() > MAX_PROJECT_CLAIM_BYTES {
                return Err(io::Error::other(
                    "initial project claim exceeds its encoded bound",
                ));
            }
            records.push((
                project_claim_name(&owner.filesystem_uuid, owner.project_id)?,
                bytes,
            ));
        }
        Ok(records)
    }

    /// Permanently binds the complete genuine first-enrollment record set.
    pub(super) fn ensure_initial(
        &self,
        ledger: &super::initial_enrollment::InitialLedger,
        owners: &[ConfiguredOwner],
    ) -> io::Result<()> {
        let records = self.initial_records(ledger, owners)?;
        open_host_path(Path::new(ANCHOR_PATH), false)?.sync_all()?;
        open_host_path(
            Path::new(ANCHOR_PATH)
                .parent()
                .ok_or_else(|| io::Error::other("anchor has no parent"))?,
            true,
        )?
        .sync_all()?;
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
            self.directory.sync_all()?;
        }
        self.directory.sync_all()
    }

    /// Retains the actual complete first claim without widening earlier claims.
    pub(super) fn bind_initial(
        &self,
        ledger: &super::initial_enrollment::InitialLedger,
        owners: &mut [ConfiguredOwner],
    ) -> io::Result<()> {
        for ((_, bytes), owner) in self
            .initial_records(ledger, owners)?
            .into_iter()
            .zip(owners)
        {
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
    let (temporary, mut output) = claim_temporary(parent, &SEQUENCE)?;
    let target = parent.join(name);
    let result = (|| {
        output.write_all(bytes)?;
        output.sync_all()?;
        match fs::hard_link(&temporary, &target) {
            Ok(()) => directory.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn claim_temporary(
    parent: &Path,
    sequence: &std::sync::atomic::AtomicU64,
) -> io::Result<(PathBuf, File)> {
    // Interrupted attempts own their temporary names permanently until an
    // administrator recovers them. Never remove a stale name to make progress.
    for _ in 0..1024 {
        let number = sequence
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |value| value.checked_add(1),
            )
            .map_err(|_| io::Error::other("claim temporary sequence exhausted"))?;
        let path = parent.join(format!(".claim-{}-{number}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("too many stale claim temporary names"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Native fixture assertions intentionally panic."
)]
mod tests {
    use super::*;

    #[test]
    fn stale_temporary_name_is_preserved_and_skipped() {
        let parent =
            std::env::temp_dir().join(format!("terrane-stale-claim-{}", std::process::id()));
        fs::create_dir(&parent).expect("exclusive test directory");
        let stale = parent.join(format!(".claim-{}-0", std::process::id()));
        fs::write(&stale, b"interrupted attempt").expect("stale attempt");
        let sequence = std::sync::atomic::AtomicU64::new(0);

        let (fresh, file) = claim_temporary(&parent, &sequence).expect("skip stale name");

        assert_ne!(fresh, stale);
        assert_eq!(
            fs::read(&stale).expect("preserved stale attempt"),
            b"interrupted attempt"
        );
        drop(file);
        fs::remove_file(fresh).expect("fresh test cleanup");
        fs::remove_file(stale).expect("stale test cleanup");
        fs::remove_dir(parent).expect("directory cleanup");
    }

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

    #[test]
    #[ignore = "requires the explicit host-quota-proof administrative VM"]
    fn host_global_claims_preserve_crash_custody_vm() {
        use std::collections::BTreeSet;
        use std::os::unix::fs::PermissionsExt;
        use terrane_linux::host_quota::{NativeProject, filesystem_uuid};

        assert_eq!(std::env::var("TERRANE_HOST_QUOTA_VM").as_deref(), Ok("1"));
        let mount =
            PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ADMIN_ROOT").expect("guest mount"));
        let a = mount.join("claims-A");
        let b = mount.join("claims-B");
        for path in [&a, &b] {
            fs::create_dir(path).expect("isolated administrative fixture");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private custody");
        }
        let config = HostConfig {
            socket: a.join("quota.sock"),
            epoch: "00000000000000000000000000000001".into(),
            tier_charge_budget_bytes: 4194304,
            owners: Vec::new(),
            project_census: None,
        };
        let file = File::open(&a).expect("actual directory");
        let uuid = filesystem_uuid(&file).expect("actual filesystem UUID");
        let metadata = file.metadata().expect("actual binding");
        let owner = |name: &str, project_id| ConfiguredOwner {
            claim: None,
            owner_id: name.into(),
            domain: "public".into(),
            filesystem_uuid: uuid,
            project_id,
            hard_limit_bytes: 2097152,
            allowed_client_uids: BTreeSet::from([840]),
            roots: Vec::new(),
            scaffolding: Vec::new(),
        };
        let binding = |name: &str, project_id| Binding {
            owner_id: name.into(),
            domain: "public".into(),
            filesystem_uuid: uuid,
            project_id,
            role_directory: "layout-root".into(),
            path: a.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            hard_limit_bytes: 2097152,
            original_uid: metadata.uid(),
            original_gid: metadata.gid(),
            original_mode: metadata.mode() & 0o7777,
        };
        let registry_a =
            Registry::open(&config, &a.join("ledger.toml"), true).expect("fixed anchored registry");
        let registry_b =
            Registry::open(&config, &b.join("ledger.toml"), true).expect("same common registry");
        let ledger = |registry: &Registry, bindings| Ledger {
            version: 2,
            epoch: config.epoch.clone(),
            registry: registry.identity(),
            phase: super::super::ProvisioningPhase::Provisioning,
            bindings,
        };
        let ledger_a = ledger(&registry_a, vec![binding("A", 49001)]);
        let mut owners_a = vec![owner("A", 49001)];

        // Crash after the permanent claim, before the per-layout ledger exists.
        registry_a
            .ensure(&ledger_a, &owners_a)
            .expect("reserve before ledger");
        assert!(!a.join("ledger.toml").exists());
        registry_a
            .ensure(&ledger_a, &owners_a)
            .expect("matching crash retry");
        super::super::persist_ledger(&a.join("ledger.toml"), &ledger_a)
            .expect("durable Provisioning");
        let ledger_b = ledger(&registry_b, vec![binding("B", 49001)]);
        assert!(registry_b.ensure(&ledger_b, &[owner("B", 49001)]).is_err());
        registry_a
            .bind(&ledger_a, &mut owners_a)
            .expect("original owner resume");
        let retained = owners_a[0].claim.as_ref().expect("actual retained claim");
        retained.verify(&uuid, 49001).expect("matching restart");
        assert!(retained.verify(&uuid, 49002).is_err());
        assert_eq!(
            NativeProject::inspect(&file)
                .expect("no native mutation")
                .project_id,
            0
        );

        // A partial multi-owner claim set never rolls back an earlier claim.
        let foreign = ledger(&registry_b, vec![binding("foreign", 49002)]);
        registry_b
            .ensure(&foreign, &[owner("foreign", 49002)])
            .expect("foreign permanent claim");
        let multi = ledger(&registry_a, vec![binding("A", 49001), binding("C", 49002)]);
        assert!(
            registry_a
                .ensure(&multi, &[owner("A", 49001), owner("C", 49002)])
                .is_err()
        );
        retained
            .verify(&uuid, 49001)
            .expect("partial set preserves first owner");

        // The sibling anchor rejects both an old owner and a fresh ledger after
        // replacement of the registry, even though the new directory is empty.
        let displaced = Path::new(REGISTRY_PATH).with_file_name("project-claims.vm-displaced");
        fs::rename(REGISTRY_PATH, &displaced).expect("VM registry replacement");
        assert!(retained.verify(&uuid, 49001).is_err());
        assert!(Registry::open(&config, &b.join("fresh.toml"), true).is_err());
        fs::create_dir(REGISTRY_PATH).expect("empty replacement");
        fs::set_permissions(REGISTRY_PATH, fs::Permissions::from_mode(0o700))
            .expect("replacement custody");
        assert!(retained.verify(&uuid, 49001).is_err());
        assert!(Registry::open(&config, &b.join("fresh.toml"), true).is_err());
        fs::remove_dir(REGISTRY_PATH).expect("remove empty VM replacement");
        fs::rename(&displaced, REGISTRY_PATH).expect("restore actual registry");
        retained
            .verify(&uuid, 49001)
            .expect("restored administrative identity");

        let missing = Path::new(ANCHOR_PATH).with_file_name("project-claims.identity.vm-displaced");
        fs::rename(ANCHOR_PATH, &missing).expect("VM anchor loss");
        assert!(retained.verify(&uuid, 49001).is_err());
        assert!(Registry::open(&config, &a.join("ledger.toml"), false).is_err());
        fs::rename(missing, ANCHOR_PATH).expect("restore anchor");
        retained
            .verify(&uuid, 49001)
            .expect("retained ownership after restoration");
        let anchor_bytes = fs::read(ANCHOR_PATH).expect("original anchor bytes");
        fs::write(ANCHOR_PATH, b"malformed anchor").expect("VM administrative corruption");
        assert!(Registry::open(&config, &b.join("fresh.toml"), true).is_err());
        assert!(retained.verify(&uuid, 49001).is_err());
        fs::write(ANCHOR_PATH, anchor_bytes).expect("VM administrator restoration");
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Native fixture assertions intentionally panic."
)]
#[path = "claim_provision_tests.rs"]
mod provision_tests;
