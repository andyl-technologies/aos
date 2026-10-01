//! Loads and rechecks fixed systemd credentials through protected directories.
//!
//! Ancestors are root-owned until ownership transitions to the service UID.
//! Symlinks, writable ancestors, nonregular files, excess bytes, and changed
//! file metadata are rejected. No key or certificate bytes appear in errors.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::PublicApiSessionError;

const MAXIMUM_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const NAMES: [&str; 4] = [
    "public-api-server-cert",
    "public-api-server-key",
    "public-api-client-ca",
    "public-api-principals",
];
const ENTITLEMENT_NAME: &str = "public-api-entitlements";
const ENTITLEMENT_KEY_NAME: &str = "public-api-entitlement-public-key";
const OPERATOR_RECOVERY_KEY_NAME: &str = "operator-recovery-controller-key-v1";
const OPERATOR_STORAGE_OWNER_KEY_NAME: &str = "operator-recovery-storage-owner-key-v1";
const PROJECT_AUTHORIZATION_ISSUER_NAME: &str = "project-authorization-issuer-v2";
const CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME: &str = "controller-source-tree-seed-issuer-v1";
const SOURCE_GENESIS_PACKET_NAMES: [&str; 2] = [
    "controller-source-tree-seed-v1",
    "project-authorization-source-v2",
];
const NIX_OWNER_DIRECTORY: &str = "/run/credentials/aos-sandbox-nixd.service";
const NIX_CONTROLLER_DIRECTORY: &str = "/run/credentials/aos-sandboxd.service";
const NIX_PUBLIC_NAMES: [&str; 12] = [
    "nix-recipe-issuer-v2",
    "nix-fixed-domain-pins-v2",
    "nix-broker-session-manifest-v1",
    "nix-preadmitted-recipes-v2",
    "ownership-lease-policy.cbor",
    "ownership-lease-public-key",
    "broker-plan-policy.cbor",
    "broker-plan-public-key",
    "broker-revocation-scope",
    "mount-broker-plan-policy.cbor",
    "mount-broker-plan-public-key",
    "mount-broker-revocation-scope",
];

/// Retains one fixed protected credential and rejects replacement before use.
pub(crate) struct PinnedSystemdCredential {
    name: &'static str,
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    file_identity: CredentialIdentity,
    bytes: Zeroizing<Vec<u8>>,
    exact_bytes: Option<u64>,
}

/// Existing operator recovery callers share the same protected file custody.
pub(crate) type PinnedOperatorRecoveryKeyV1 = PinnedSystemdCredential;

impl PinnedSystemdCredential {
    /// Opens only the existing public attach verifier; never the signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized, unsafe, or changing fixed credential custody.
    pub(crate) fn load_attach_grant_public() -> Result<Self, PublicApiSessionError> {
        Self::load_named("openssh-attach-grant-public-key")
    }

    /// Opens the exact existing deployment trust bytes signed into attach grants.
    ///
    /// # Errors
    /// Rejects missing, oversized, unsafe, or changing fixed credential custody.
    pub(crate) fn load_attach_trust() -> Result<Self, PublicApiSessionError> {
        Self::load_named("openssh-attach-trust.json")
    }

    /// Opens the dedicated controller recovery key from systemd credentials.
    pub(crate) fn load() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_RECOVERY_KEY_NAME)
    }

    /// Opens the independently pinned Storage owner public key.
    pub(crate) fn load_storage_owner_public() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_STORAGE_OWNER_KEY_NAME)
    }

    /// Opens the separate public project-authorization issuer pin.
    pub(crate) fn load_project_authorization_issuer_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named(PROJECT_AUTHORIZATION_ISSUER_NAME)
    }

    /// Opens the separate public Controller Source-tree seed issuer pin.
    pub(crate) fn load_controller_source_tree_seed_issuer_v1() -> Result<Self, PublicApiSessionError>
    {
        Self::load_named(CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME)
    }

    /// Retains the fixed independent Nix recipe issuer, never a signing seed.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub(crate) fn load_nix_recipe_issuer_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-recipe-issuer-v2")
    }

    /// Retains the fixed Nix domain/presentation and disclosure pin contract.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub(crate) fn load_nix_fixed_domain_pins_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-fixed-domain-pins-v2")
    }

    /// Retains the fixed four-role Nix public endpoint manifest.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub(crate) fn load_nix_broker_session_manifest_v1() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-broker-session-manifest-v1")
    }

    /// Retains the bounded independent recipe catalog; never a signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_preadmitted_recipes_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-preadmitted-recipes-v2")
    }

    /// Retains the existing public ownership policy without its session secret.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_ownership_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("ownership-lease-policy.cbor")
    }

    /// Retains the existing public ownership verification key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_ownership_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("ownership-lease-public-key")
    }

    /// Retains the existing public Host plan policy, never its signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_host_plan_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-plan-policy.cbor")
    }

    /// Retains the existing public Host plan key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_host_plan_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-plan-public-key")
    }

    /// Retains Host's independently provisioned plan revocation scope.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_host_plan_revocation_scope() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-revocation-scope")
    }

    /// Retains the existing public Mount plan policy, never its signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_mount_plan_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-plan-policy.cbor")
    }

    /// Retains the existing public Mount plan key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_mount_plan_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-plan-public-key")
    }

    /// Retains Mount's independently provisioned plan revocation scope.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub(crate) fn load_nix_mount_plan_revocation_scope() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-revocation-scope")
    }

    /// Retains the twelve public pins from only the fixed Nix control unit.
    ///
    /// # Errors
    /// Rejects absent, unsafe, oversized or replaced original credentials.
    /// This ignores environment-selected directories and loads no secrets.
    pub(crate) fn load_nix_owner_publics() -> Result<[Self; 12], PublicApiSessionError> {
        let load = |index| {
            Self::open_named(PathBuf::from(NIX_OWNER_DIRECTORY), NIX_PUBLIC_NAMES[index])
        };
        Ok([
            load(0)?,
            load(1)?,
            load(2)?,
            load(3)?,
            load(4)?,
            load(5)?,
            load(6)?,
            load(7)?,
            load(8)?,
            load(9)?,
            load(10)?,
            load(11)?,
        ])
    }

    /// Retains the separate exact node credential from the fixed Nix owner.
    ///
    /// # Errors
    /// Rejects missing, unsafe, replaced or nonexact sixteen-byte custody.
    pub(crate) fn load_nix_owner_node_id() -> Result<Self, PublicApiSessionError> {
        Self::load_nix_node_at(NIX_OWNER_DIRECTORY)
    }

    /// Retains the separate exact node credential from the fixed Controller.
    ///
    /// # Errors
    /// Rejects missing, unsafe, replaced or nonexact sixteen-byte custody.
    pub(crate) fn load_nix_controller_node_id() -> Result<Self, PublicApiSessionError> {
        Self::load_nix_node_at(NIX_CONTROLLER_DIRECTORY)
    }

    fn load_nix_node_at(directory: &'static str) -> Result<Self, PublicApiSessionError> {
        Self::open_optional_exact(PathBuf::from(directory), "node-id", 16)?
            .ok_or(PublicApiSessionError::Configuration)
    }

    /// Retains both exact administrative packets, or no optional startup pair.
    ///
    /// # Errors
    ///
    /// Rejects partial, unsafe, nonexact or changing protected file custody.
    pub(crate) fn load_source_genesis_packets_optional()
    -> Result<Option<[Self; 2]>, PublicApiSessionError> {
        let path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(PublicApiSessionError::Configuration)?;
        Self::source_genesis_packets_at(path)
    }

    fn source_genesis_packets_at(
        path: PathBuf,
    ) -> Result<Option<[Self; 2]>, PublicApiSessionError> {
        let lengths = [
            crate::hierarchy::source_seed::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1 as u64,
            crate::publisher_policy::PROJECT_AUTHORIZATION_SOURCE_BYTES_V2 as u64,
        ];
        let seed =
            Self::open_optional_exact(path.clone(), SOURCE_GENESIS_PACKET_NAMES[0], lengths[0])?;
        let authorization =
            Self::open_optional_exact(path, SOURCE_GENESIS_PACKET_NAMES[1], lengths[1])?;
        match (seed, authorization) {
            (None, None) => Ok(None),
            (Some(seed), Some(authorization)) => {
                seed.recheck()?;
                authorization.recheck()?;
                Ok(Some([seed, authorization]))
            }
            _ => Err(PublicApiSessionError::Configuration),
        }
    }

    fn load_named(name: &'static str) -> Result<Self, PublicApiSessionError> {
        let path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(PublicApiSessionError::Configuration)?;
        Self::open_named(path, name)
    }

    fn open(path: PathBuf) -> Result<Self, PublicApiSessionError> {
        Self::open_named(path, OPERATOR_RECOVERY_KEY_NAME)
    }

    fn open_named(path: PathBuf, name: &'static str) -> Result<Self, PublicApiSessionError> {
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let (bytes, file_identity) = read_one_with_identity(&directory, name, uid)?;
        let retained = Self {
            name,
            path,
            uid,
            directory_identity: (stat.st_dev, stat.st_ino),
            file_identity,
            bytes,
            exact_bytes: None,
        };
        retained.recheck()?;
        Ok(retained)
    }

    fn open_optional_exact(
        path: PathBuf,
        name: &'static str,
        exact_bytes: u64,
    ) -> Result<Option<Self>, PublicApiSessionError> {
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let Some((bytes, file_identity)) =
            read_optional_exact_one_with_identity(&directory, name, uid, exact_bytes)?
        else {
            return Ok(None);
        };
        let retained = Self {
            name,
            path,
            uid,
            directory_identity: (stat.st_dev, stat.st_ino),
            file_identity,
            bytes,
            exact_bytes: Some(exact_bytes),
        };
        retained.recheck()?;
        Ok(Some(retained))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reopens the fixed path and proves that its inode and bytes are unchanged.
    pub(crate) fn recheck(&self) -> Result<(), PublicApiSessionError> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(PublicApiSessionError::Stale);
        }
        let directory = open_directory(&self.path, self.uid)?;
        let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
        if (stat.st_dev, stat.st_ino) != self.directory_identity {
            return Err(PublicApiSessionError::Stale);
        }
        let (bytes, identity) = match self.exact_bytes {
            Some(length) => {
                read_optional_exact_one_with_identity(&directory, self.name, self.uid, length)?
                    .ok_or(PublicApiSessionError::Stale)?
            }
            None => read_one_with_identity(&directory, self.name, self.uid)?,
        };
        if identity != self.file_identity || bytes != self.bytes {
            return Err(PublicApiSessionError::Stale);
        }
        Ok(())
    }
}

/// Reads the current separately provisioned first-capability authority.
///
/// Both names are fixed by the controller. The caller supplies no key path or
/// trust root, and the same protected directory rules as public TLS apply.
pub(crate) fn load_entitlement_credentials()
-> Result<[Zeroizing<Vec<u8>>; 2], PublicApiSessionError> {
    let path = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or(PublicApiSessionError::Configuration)?;
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_directory(&path, uid)?;
    let before = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
    let bytes = [
        read_one(&directory, ENTITLEMENT_NAME, uid)?,
        read_one(&directory, ENTITLEMENT_KEY_NAME, uid)?,
    ];
    let after = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
        return Err(PublicApiSessionError::Stale);
    }
    Ok(bytes)
}

pub(super) struct Credentials {
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    digests: [[u8; 32]; 4],
}

impl Credentials {
    // Only public trust material is retained; the server private key digest is
    // deliberately excluded from the original decision's historical binding.
    pub(super) fn public_trust_digests(&self) -> [[u8; 32]; 3] {
        [self.digests[0], self.digests[2], self.digests[3]]
    }

    pub(super) fn load() -> Result<(Self, [Zeroizing<Vec<u8>>; 4]), PublicApiSessionError> {
        let path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(PublicApiSessionError::Configuration)?;
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let bytes = read_all(&directory, uid)?;
        let digests = std::array::from_fn(|index| Sha256::digest(&*bytes[index]).into());
        let retained = Self {
            path,
            uid,
            directory_identity: (stat.st_dev, stat.st_ino),
            digests,
        };
        retained.recheck()?;
        Ok((retained, bytes))
    }

    pub(super) fn recheck(&self) -> Result<(), PublicApiSessionError> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(PublicApiSessionError::Stale);
        }
        let directory = open_directory(&self.path, self.uid)?;
        let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
        if (stat.st_dev, stat.st_ino) != self.directory_identity {
            return Err(PublicApiSessionError::Stale);
        }
        let bytes = read_all(&directory, self.uid)?;
        for (bytes, expected) in bytes.iter().zip(self.digests) {
            let actual: [u8; 32] = Sha256::digest(&**bytes).into();
            if actual != expected {
                return Err(PublicApiSessionError::Stale);
            }
        }
        Ok(())
    }
}

fn open_directory(path: &Path, uid: u32) -> Result<OwnedFd, PublicApiSessionError> {
    if !path.is_absolute() {
        return Err(PublicApiSessionError::Configuration);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", flags, Mode::empty()).map_err(|_| PublicApiSessionError::Configuration)?;
    let mut service_owned = false;
    for component in path.components() {
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        if stat.st_mode & 0o022 != 0
            || (stat.st_uid != 0 && stat.st_uid != uid)
            || (service_owned && stat.st_uid != uid)
        {
            return Err(PublicApiSessionError::Configuration);
        }
        service_owned |= stat.st_uid == uid;
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| PublicApiSessionError::Configuration)?;
            }
            _ => return Err(PublicApiSessionError::Configuration),
        }
    }
    let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
    if stat.st_uid != uid || stat.st_mode & 0o077 != 0 {
        return Err(PublicApiSessionError::Configuration);
    }
    Ok(directory)
}

fn read_all(
    directory: &OwnedFd,
    uid: u32,
) -> Result<[Zeroizing<Vec<u8>>; 4], PublicApiSessionError> {
    Ok([
        read_one(directory, NAMES[0], uid)?,
        read_one(directory, NAMES[1], uid)?,
        read_one(directory, NAMES[2], uid)?,
        read_one(directory, NAMES[3], uid)?,
    ])
}

fn read_one(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<Zeroizing<Vec<u8>>, PublicApiSessionError> {
    read_one_with_identity(directory, name, uid).map(|(bytes, _)| bytes)
}

type CredentialIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn read_one_with_identity(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<(Zeroizing<Vec<u8>>, CredentialIdentity), PublicApiSessionError> {
    read_optional_one_with_identity(directory, name, uid, MAXIMUM_CREDENTIAL_BYTES)?
        .ok_or(PublicApiSessionError::Configuration)
}

fn read_optional_one_with_identity(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    maximum_bytes: u64,
) -> Result<Option<(Zeroizing<Vec<u8>>, CredentialIdentity)>, PublicApiSessionError> {
    if maximum_bytes == 0 || maximum_bytes > MAXIMUM_CREDENTIAL_BYTES {
        return Err(PublicApiSessionError::Configuration);
    }
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(PublicApiSessionError::Configuration),
    };
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| PublicApiSessionError::Configuration)?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(PublicApiSessionError::Configuration);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PublicApiSessionError::Configuration)?;
    let after = file
        .metadata()
        .map_err(|_| PublicApiSessionError::Configuration)?;
    if before.len() != bytes.len() as u64 || identity(&before) != identity(&after) {
        return Err(PublicApiSessionError::Stale);
    }
    Ok(Some((bytes, identity(&after))))
}

fn read_optional_exact_one_with_identity(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    exact_bytes: u64,
) -> Result<Option<(Zeroizing<Vec<u8>>, CredentialIdentity)>, PublicApiSessionError> {
    let observed = read_optional_one_with_identity(directory, name, uid, exact_bytes)?;
    if observed
        .as_ref()
        .is_some_and(|(bytes, _)| bytes.len() as u64 != exact_bytes)
    {
        return Err(PublicApiSessionError::Configuration);
    }
    Ok(observed)
}

fn identity(metadata: &std::fs::Metadata) -> CredentialIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

/// Parks the prepare-only unit's two independently delivered public originals.
///
/// This private reader supplies no startup or provisioning authority. Its
/// caller must retain the genuine selected unit and bracket every observation.
pub(crate) struct OfflinePrepareCredentialsV3 {
    ancestors: Vec<File>,
    files: [Option<File>; 2],
    originals: [Option<CredentialIdentity>; 2],
    directory_identity: Option<CredentialIdentity>,
    mount: Option<aos_sandbox_linux::inventory::MountId>,
    readbacks: Vec<[Zeroizing<Vec<u8>>; 2]>,
    named: Vec<File>,
    admitted: bool,
}

impl OfflinePrepareCredentialsV3 {
    pub(crate) fn new() -> Self {
        Self {
            ancestors: Vec::new(),
            files: [None, None],
            originals: [None, None],
            directory_identity: None,
            mount: None,
            readbacks: Vec::new(),
            named: Vec::new(),
            admitted: false,
        }
    }

    pub(crate) fn admit(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsFd as _;

        if !self.ancestors.is_empty() {
            return Err(offline_credential_rejected());
        }
        self.ancestors
            .try_reserve_exact(4)
            .map_err(std::io::Error::other)?;
        self.named
            .try_reserve_exact(48)
            .map_err(std::io::Error::other)?;
        self.readbacks
            .try_reserve_exact(16)
            .map_err(std::io::Error::other)?;

        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        self.ancestors.push(File::from(open("/", flags, Mode::empty())?));
        for name in ["run", "credentials", "aos-sandbox-nix-floor-provision.service"] {
            let parent = self.ancestors.last().ok_or_else(offline_credential_rejected)?;
            let metadata = parent.metadata()?;
            if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(offline_credential_rejected());
            }
            let next = openat(parent, name, flags, Mode::empty())?;
            self.ancestors.push(File::from(next));
        }

        let directory = self.ancestors.last().ok_or_else(offline_credential_rejected)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o500
            || !rustix::fs::fstatvfs(directory)?.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
        {
            return Err(offline_credential_rejected());
        }
        offline_credential_label(directory)?;
        self.directory_identity = Some(identity(&metadata));
        self.mount = Some(
            aos_sandbox_linux::inventory::MountId::from_fd(directory.as_fd())
                .map_err(std::io::Error::other)?,
        );
        offline_credential_names()?;

        for (index, name) in OFFLINE_PREPARE_NAMES.iter().enumerate() {
            // Park the actual returned descriptor before any metadata/read gate.
            self.files[index] = Some(File::from(openat(
                directory,
                *name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?));
            let file = self.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
            let metadata = file.metadata()?;
            require_offline_credential_file(&metadata, OFFLINE_PREPARE_LENGTHS[index])?;
            offline_credential_label(file)?;
            self.originals[index] = Some(identity(&metadata));
        }
        self.capture_bytes()?;
        let [node, approval] = self.readbacks.first().ok_or_else(offline_credential_rejected)?;
        if node.iter().all(|byte| *byte == 0)
            || approval[..16].iter().all(|byte| *byte == 0)
            || approval[16..].iter().all(|byte| *byte == 0)
        {
            return Err(offline_credential_rejected());
        }
        let public: [u8; 32] = approval[16..]
            .try_into()
            .map_err(|_| offline_credential_rejected())?;
        ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| offline_credential_rejected())?;
        self.admitted = true;
        self.recheck()
    }

    pub(crate) fn public_originals(&self) -> std::io::Result<(&[u8], &[u8])> {
        if !self.admitted {
            return Err(offline_credential_rejected());
        }
        let [node, approval] = self.readbacks.first().ok_or_else(offline_credential_rejected)?;
        Ok((node, approval))
    }

    pub(crate) fn recheck(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsFd as _;

        if !self.admitted || self.named.len() > 45 {
            return Err(offline_credential_rejected());
        }
        let directory = self.ancestors.last().ok_or_else(offline_credential_rejected)?;
        if Some(identity(&directory.metadata()?)) != self.directory_identity
            || Some(aos_sandbox_linux::inventory::MountId::from_fd(directory.as_fd())
                .map_err(std::io::Error::other)?) != self.mount
            || !rustix::fs::fstatvfs(directory)?.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
        {
            return Err(offline_credential_rejected());
        }
        offline_credential_label(directory)?;

        // Named readbacks stay resident too; failed name or content observations
        // cannot release the originals or replace the initial public preimages.
        self.named.push(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            OFFLINE_PREPARE_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?));
        let named_directory = self.named.last().ok_or_else(offline_credential_rejected)?;
        if Some(identity(&named_directory.metadata()?)) != self.directory_identity
            || Some(aos_sandbox_linux::inventory::MountId::from_fd(named_directory.as_fd())
                .map_err(std::io::Error::other)?) != self.mount
        {
            return Err(offline_credential_rejected());
        }
        for index in 0..2 {
            let file = self.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
            if Some(identity(&file.metadata()?)) != self.originals[index] {
                return Err(offline_credential_rejected());
            }
            offline_credential_label(file)?;
            self.named.push(File::from(openat(
                directory,
                OFFLINE_PREPARE_NAMES[index],
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?));
            let named = self.named.last().ok_or_else(offline_credential_rejected)?;
            if Some(identity(&named.metadata()?)) != self.originals[index] {
                return Err(offline_credential_rejected());
            }
            offline_credential_label(named)?;
        }
        offline_credential_names()?;
        self.capture_bytes()?;
        if self.readbacks.first() != self.readbacks.last() {
            return Err(offline_credential_rejected());
        }
        Ok(())
    }

    fn capture_bytes(&mut self) -> std::io::Result<()> {
        if self.readbacks.len() == 16 {
            return Err(offline_credential_rejected());
        }
        self.readbacks.push([
            Zeroizing::new(vec![0; 16]),
            Zeroizing::new(vec![0; 48]),
        ]);
        let bytes = self.readbacks.last_mut().ok_or_else(offline_credential_rejected)?;
        for index in 0..2 {
            let file = self.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
            aos_sandbox_linux::protected_file::read_exact_positioned(file, &mut bytes[index])
                .map_err(|error| std::io::Error::other(OfflinePrepareExactReadError(error)))?;
            if Some(identity(&file.metadata()?)) != self.originals[index] {
                return Err(offline_credential_rejected());
            }
            offline_credential_label(file)?;
        }
        Ok(())
    }
}

const OFFLINE_PREPARE_DIRECTORY: &str = "/run/credentials/aos-sandbox-nix-floor-provision.service";
const OFFLINE_PREPARE_NAMES: [&str; 2] = ["node-id", "nix-floor-provision-approval-public-key-v3"];
const OFFLINE_PREPARE_LENGTHS: [u64; 2] = [16, 48];

fn offline_credential_rejected() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "offline prepare credential custody differs")
}

fn require_offline_credential_file(metadata: &std::fs::Metadata, length: u64) -> std::io::Result<()> {
    if !metadata.is_file() || metadata.uid() != 0 || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o400 || metadata.nlink() != 1 || metadata.len() != length
    {
        return Err(offline_credential_rejected());
    }
    Ok(())
}

fn offline_credential_names() -> std::io::Result<()> {
    let mut names = Vec::new();
    names.try_reserve_exact(3).map_err(std::io::Error::other)?;
    for entry in std::fs::read_dir(OFFLINE_PREPARE_DIRECTORY)? {
        names.push(entry?.file_name());
        if names.len() > 2 {
            return Err(offline_credential_rejected());
        }
    }
    require_offline_credential_names(names)
}

fn require_offline_credential_names(mut names: Vec<std::ffi::OsString>) -> std::io::Result<()> {
    names.sort();
    let mut expected = OFFLINE_PREPARE_NAMES.map(std::ffi::OsString::from);
    expected.sort();
    if names != expected {
        return Err(offline_credential_rejected());
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("offline prepare original exact read failed ({0:?})")]
struct OfflinePrepareExactReadError(aos_sandbox_linux::protected_file::ExactReadError);

fn offline_credential_label(file: &File) -> std::io::Result<()> {
    let mut context = [0; 256];
    let length = rustix::fs::fgetxattr(file, "security.selinux", &mut context[..])?;
    let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
    if actual != b"system_u:object_r:aos_nix_offline_prepare_credential_t" {
        return Err(offline_credential_rejected());
    }
    let mut bytes = [0; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(file, name, &mut bytes[..]) {
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(offline_credential_rejected()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use ed25519_dalek::SigningKey;

    use crate::hierarchy::source_seed::{
        PinnedControllerSourceTreeSeedIssuerV1, encode_controller_source_tree_seed_credential_v1,
    };

    #[test]
    fn offline_prepare_names_are_an_exact_set_not_processing_order() {
        let original = OFFLINE_PREPARE_NAMES.map(std::ffi::OsString::from);
        assert!(require_offline_credential_names(original.to_vec()).is_ok());
        assert!(require_offline_credential_names(original.into_iter().rev().collect()).is_ok());

        assert!(require_offline_credential_names(vec!["node-id".into()]).is_err());
        assert!(require_offline_credential_names(vec!["node-id".into(), "node-id".into()]).is_err());
        assert!(require_offline_credential_names(vec![
            "node-id".into(),
            "nix-floor-provision-approval-public-key-v3".into(),
            "hierarchy-auth".into(),
        ]).is_err());
    }

    #[test]
    fn nix_owner_public_names_keep_the_original_twelve_pin_order_without_node() {
        assert_eq!(NIX_OWNER_DIRECTORY, "/run/credentials/aos-sandbox-nixd.service");
        assert_eq!(NIX_CONTROLLER_DIRECTORY, "/run/credentials/aos-sandboxd.service");
        assert_eq!(
            NIX_PUBLIC_NAMES,
            [
                "nix-recipe-issuer-v2",
                "nix-fixed-domain-pins-v2",
                "nix-broker-session-manifest-v1",
                "nix-preadmitted-recipes-v2",
                "ownership-lease-policy.cbor",
                "ownership-lease-public-key",
                "broker-plan-policy.cbor",
                "broker-plan-public-key",
                "broker-revocation-scope",
                "mount-broker-plan-policy.cbor",
                "mount-broker-plan-public-key",
                "mount-broker-revocation-scope",
            ],
        );
        assert!(!NIX_PUBLIC_NAMES.contains(&"node-id"));
    }

    #[test]
    fn nix_node_fixed_reader_refuses_nonexact_or_linked_originals() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        ).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let path = directory.path().join("node-id");
        let replace_node = |bytes: &[u8]| {
            let replacement = directory.path().join("node-replacement");
            std::fs::write(&replacement, bytes).unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::rename(replacement, &path).unwrap();
        };

        for width in [15, 16, 17] {
            replace_node(&vec![1; width]);
            let read = read_optional_exact_one_with_identity(&descriptor, "node-id", uid, 16);
            if width == 16 {
                assert_eq!(&**read.unwrap().unwrap().0, &[1; 16]);
            } else {
                assert!(read.is_err());
            }
        }
        replace_node(&[1; 16]);
        std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
        assert!(read_optional_exact_one_with_identity(&descriptor, "node-id", uid, 16).is_err());
    }

    #[test]
    fn accepts_only_private_single_link_regular_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        assert!(read_one(&descriptor, PROJECT_AUTHORIZATION_ISSUER_NAME, uid).is_err());

        let path = directory.path().join("credential");
        std::fs::write(&path, b"protected bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let bytes = read_one(&descriptor, "credential", uid).unwrap();

        assert_eq!(&**bytes, b"protected bytes");
        assert!(read_one(&descriptor, "credential", uid.wrapping_add(1)).is_err());

        symlink("credential", directory.path().join("symlink")).unwrap();
        assert!(read_one(&descriptor, "symlink", uid).is_err());

        std::fs::hard_link(&path, directory.path().join("hardlink")).unwrap();
        assert!(read_one(&descriptor, "credential", uid).is_err());
        assert!(read_one(&descriptor, "hardlink", uid).is_err());
    }

    #[test]
    fn rejects_public_empty_oversized_and_nonregular_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        for (name, bytes, mode) in [
            ("public", vec![1], 0o444),
            ("empty", vec![], 0o400),
            (
                "oversized",
                vec![1; MAXIMUM_CREDENTIAL_BYTES as usize + 1],
                0o400,
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();

            assert!(read_one(&descriptor, name, uid).is_err());
        }
        std::fs::create_dir(directory.path().join("directory")).unwrap();

        assert!(read_one(&descriptor, "directory", uid).is_err());
        assert!(open_directory(Path::new("relative"), uid).is_err());
    }

    #[test]
    fn recovery_credential_identity_detects_same_bytes_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let key_path = directory.path().join(OPERATOR_RECOVERY_KEY_NAME);
        std::fs::write(&key_path, b"same secret bytes").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (original, original_identity) =
            read_one_with_identity(&descriptor, OPERATOR_RECOVERY_KEY_NAME, uid).unwrap();

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"same secret bytes").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(replacement, key_path).unwrap();
        let (new_bytes, new_identity) =
            read_one_with_identity(&descriptor, OPERATOR_RECOVERY_KEY_NAME, uid).unwrap();

        assert_eq!(original, new_bytes);
        assert_ne!(original_identity, new_identity);
    }

    #[test]
    fn source_seed_issuer_absence_malformed_bytes_and_rotation_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let name = CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME;
        let path = directory.path().join(name);

        assert!(read_one_with_identity(&descriptor, name, uid).is_err());

        std::fs::write(&path, [0; 80]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (malformed, _) = read_one_with_identity(&descriptor, name, uid).unwrap();
        assert!(PinnedControllerSourceTreeSeedIssuerV1::decode(&malformed).is_err());

        let key = SigningKey::from_bytes(&[41; 32]);
        let valid =
            encode_controller_source_tree_seed_credential_v1(7, &key.verifying_key()).unwrap();
        let first = directory.path().join("first");
        std::fs::write(&first, valid).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(first, &path).unwrap();
        let (bytes, identity) = read_one_with_identity(&descriptor, name, uid).unwrap();
        assert_eq!(
            PinnedControllerSourceTreeSeedIssuerV1::decode(&bytes)
                .unwrap()
                .generation(),
            7
        );

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, valid).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(replacement, path).unwrap();
        let (new_bytes, new_identity) = read_one_with_identity(&descriptor, name, uid).unwrap();

        assert_eq!(bytes, new_bytes);
        assert_ne!(identity, new_identity);
    }

    #[test]
    fn source_genesis_fixed_file_reads_require_exact_private_packet_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let read = |name| read_optional_exact_one_with_identity(&descriptor, name, uid, 224);
        for name in SOURCE_GENESIS_PACKET_NAMES {
            assert!(read(name).unwrap().is_none());
        }
        let seed = directory.path().join(SOURCE_GENESIS_PACKET_NAMES[0]);
        let authorization = directory.path().join(SOURCE_GENESIS_PACKET_NAMES[1]);
        std::fs::write(&seed, [1; 224]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read(SOURCE_GENESIS_PACKET_NAMES[0]).unwrap().is_some());
        assert!(read(SOURCE_GENESIS_PACKET_NAMES[1]).unwrap().is_none());

        // Replace each read-only case only after its final private mode is set.
        let replace_authorization = |bytes: &[u8]| {
            let replacement = directory.path().join("authorization-replacement");
            std::fs::write(&replacement, bytes).unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::rename(&replacement, &authorization).unwrap();
        };

        for width in [223, 225, 272] {
            replace_authorization(&vec![2; width]);
            assert!(read(SOURCE_GENESIS_PACKET_NAMES[1]).is_err());
        }
        replace_authorization(&[2; 224]);
        assert_eq!(
            &**read(SOURCE_GENESIS_PACKET_NAMES[0]).unwrap().unwrap().0,
            &[1; 224]
        );
        assert_eq!(
            &**read(SOURCE_GENESIS_PACKET_NAMES[1]).unwrap().unwrap().0,
            &[2; 224]
        );
        std::fs::set_permissions(&authorization, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(read(SOURCE_GENESIS_PACKET_NAMES[1]).is_err());
    }

    #[test]
    fn source_genesis_fixed_file_reads_detect_same_bytes_inode_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let read = || {
            read_optional_exact_one_with_identity(
                &descriptor,
                SOURCE_GENESIS_PACKET_NAMES[0],
                uid,
                224,
            )
            .unwrap()
            .unwrap()
        };
        for name in SOURCE_GENESIS_PACKET_NAMES {
            let path = directory.path().join(name);
            std::fs::write(&path, [3; 224]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let original = read();
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, [3; 224]).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(
            &replacement,
            directory.path().join(SOURCE_GENESIS_PACKET_NAMES[0]),
        )
        .unwrap();

        let replaced = read();
        assert_eq!(original.0, replaced.0);
        assert_ne!(original.1, replaced.1);
    }
}
