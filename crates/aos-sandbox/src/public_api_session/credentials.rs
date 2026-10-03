//! Loads and rechecks fixed systemd credentials through protected directories.
//!
//! Ancestors are root-owned until ownership transitions to the service UID.
//! Symlinks, writable ancestors, nonregular files, excess bytes, and changed
//! file metadata are rejected. No key or certificate bytes appear in errors.
//!
//! Ordinary adapters and the closed Controller retaining owner share the same
//! traversal/read engines. Offline prepare keeps its distinct root-only policy;
//! the local/resident storage choice does not select or change that policy.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
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

#[derive(Clone, Copy, Debug)]
enum CredentialFailureClass {
    Configuration,
    Stale,
}

#[derive(Clone, Copy, Debug)]
enum CredentialOperation {
    DirectoryOpen,
    DirectoryMetadata,
    DirectoryProvenance,
    FileOpen,
    FileMetadata,
    FileProvenance,
    FileRead,
    FileSeek,
    FileChanged,
    State,
}

enum CredentialIoCause {
    Syscall(rustix::io::Errno),
    File(std::io::Error),
}

impl From<rustix::io::Errno> for CredentialIoCause {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Syscall(error)
    }
}

impl From<std::io::Error> for CredentialIoCause {
    fn from(error: std::io::Error) -> Self {
        Self::File(error)
    }
}

/// Retains the first original I/O cause without changing ordinary error classes.
pub(crate) struct ControllerNixPublicCredentialErrorV1 {
    class: CredentialFailureClass,
    operation: CredentialOperation,
    io: Option<CredentialIoCause>,
}

impl ControllerNixPublicCredentialErrorV1 {
    fn rejected(class: CredentialFailureClass, operation: CredentialOperation) -> Self {
        Self {
            class,
            operation,
            io: None,
        }
    }

    fn io(
        class: CredentialFailureClass,
        operation: CredentialOperation,
        error: impl Into<CredentialIoCause>,
    ) -> Self {
        Self {
            class,
            operation,
            io: Some(error.into()),
        }
    }

    fn into_legacy(self) -> PublicApiSessionError {
        match self.class {
            CredentialFailureClass::Configuration => PublicApiSessionError::Configuration,
            CredentialFailureClass::Stale => PublicApiSessionError::Stale,
        }
    }
}

impl std::fmt::Debug for ControllerNixPublicCredentialErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerNixPublicCredentialErrorV1")
            .field("class", &self.class)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControllerNixPublicCredentialErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Controller public credential custody failed ({:?})",
            self.operation,
        )
    }
}

impl std::error::Error for ControllerNixPublicCredentialErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.io {
            Some(CredentialIoCause::Syscall(error)) => Some(error),
            Some(CredentialIoCause::File(error)) => Some(error),
            None => None,
        }
    }
}

type CredentialResult<T> = Result<T, ControllerNixPublicCredentialErrorV1>;
type DirectoryIdentity = (u64, u64);

struct CredentialDirectorySlot {
    descriptor: Option<OwnedFd>,
    identity: Option<DirectoryIdentity>,
}

struct CredentialAncestors {
    slots: [CredentialDirectorySlot; 4],
    count: usize,
}

impl CredentialAncestors {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| CredentialDirectorySlot {
                descriptor: None,
                identity: None,
            }),
            count: 0,
        }
    }

    fn directory(&self) -> CredentialResult<&OwnedFd> {
        self.slots
            .get(self.count.wrapping_sub(1))
            .and_then(|slot| slot.descriptor.as_ref())
            .ok_or_else(credential_state_rejected)
    }
}

// This closed choice changes storage only. Ordinary traversal still replaces
// its current parent at the old assignment; resident traversal keeps every FD.
enum DirectoryCustody<'owner> {
    Local(Option<OwnedFd>),
    Resident(&'owner mut CredentialAncestors),
}

impl DirectoryCustody<'_> {
    fn open_root(&mut self, flags: OFlags) -> CredentialResult<()> {
        let destination = match self {
            Self::Local(directory) => directory,
            Self::Resident(ancestors) => {
                if ancestors.count != 0
                    || ancestors.slots.iter().any(|slot| slot.descriptor.is_some())
                {
                    return Err(credential_state_rejected());
                }
                &mut ancestors.slots[0].descriptor
            }
        };
        *destination = Some(open("/", flags, Mode::empty()).map_err(|error| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Configuration,
                CredentialOperation::DirectoryOpen,
                error,
            )
        })?);
        if let Self::Resident(ancestors) = self {
            ancestors.count = 1;
        }
        Ok(())
    }

    fn directory(&self) -> CredentialResult<&OwnedFd> {
        match self {
            Self::Local(directory) => directory.as_ref().ok_or_else(credential_state_rejected),
            Self::Resident(ancestors) => ancestors.directory(),
        }
    }

    fn record_identity(&mut self, stat: &rustix::fs::Stat) {
        if let Self::Resident(ancestors) = self {
            // A current descriptor exists only after the corresponding slot
            // was filled; recording metadata cannot relinquish that original.
            if let Some(slot) = ancestors.slots.get_mut(ancestors.count.wrapping_sub(1)) {
                slot.identity = Some((stat.st_dev, stat.st_ino));
            }
        }
    }

    fn open_child(&mut self, name: &std::ffi::OsStr, flags: OFlags) -> CredentialResult<()> {
        let open_child = |parent: &OwnedFd| {
            openat(parent, name, flags, Mode::empty()).map_err(|error| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Configuration,
                    CredentialOperation::DirectoryOpen,
                    error,
                )
            })
        };
        match self {
            Self::Local(directory) => {
                let parent = directory.as_ref().ok_or_else(credential_state_rejected)?;
                *directory = Some(open_child(parent)?);
            }
            Self::Resident(ancestors) => {
                // Establish both borrows before openat returns ownership. A
                // full fixed array is rejected before creating another FD.
                if ancestors.count >= ancestors.slots.len() {
                    return Err(credential_state_rejected());
                }
                let (previous, next) = ancestors.slots.split_at_mut(ancestors.count);
                let parent = previous
                    .last()
                    .and_then(|slot| slot.descriptor.as_ref())
                    .ok_or_else(credential_state_rejected)?;
                let destination = next.first_mut().ok_or_else(credential_state_rejected)?;
                destination.descriptor = Some(open_child(parent)?);
                ancestors.count += 1;
            }
        }
        Ok(())
    }
}

fn credential_state_rejected() -> ControllerNixPublicCredentialErrorV1 {
    ControllerNixPublicCredentialErrorV1::rejected(
        CredentialFailureClass::Stale,
        CredentialOperation::State,
    )
}

fn require_credential_ancestor(
    stat: &rustix::fs::Stat,
    uid: u32,
    service_owned: &mut bool,
) -> CredentialResult<()> {
    if stat.st_mode & 0o022 != 0
        || (stat.st_uid != 0 && stat.st_uid != uid)
        || (*service_owned && stat.st_uid != uid)
    {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Configuration,
            CredentialOperation::DirectoryProvenance,
        ));
    }
    *service_owned |= stat.st_uid == uid;
    Ok(())
}

fn require_credential_directory(stat: &rustix::fs::Stat, uid: u32) -> CredentialResult<()> {
    if stat.st_uid != uid || stat.st_mode & 0o077 != 0 {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Configuration,
            CredentialOperation::DirectoryProvenance,
        ));
    }
    Ok(())
}

fn open_directory(path: &Path, uid: u32) -> Result<OwnedFd, PublicApiSessionError> {
    let mut custody = DirectoryCustody::Local(None);
    open_directory_with_custody(path, uid, &mut custody)
        .map_err(ControllerNixPublicCredentialErrorV1::into_legacy)?;
    match custody {
        DirectoryCustody::Local(Some(directory)) => Ok(directory),
        _ => Err(PublicApiSessionError::Configuration),
    }
}

fn open_directory_with_custody(
    path: &Path,
    uid: u32,
    custody: &mut DirectoryCustody<'_>,
) -> CredentialResult<()> {
    if !path.is_absolute() {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Configuration,
            CredentialOperation::DirectoryProvenance,
        ));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    custody.open_root(flags)?;
    let mut service_owned = false;
    for component in path.components() {
        let stat = rustix::fs::fstat(custody.directory()?).map_err(|error| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Configuration,
                CredentialOperation::DirectoryMetadata,
                error,
            )
        })?;
        require_credential_ancestor(&stat, uid, &mut service_owned)?;
        custody.record_identity(&stat);

        match component {
            Component::RootDir => continue,
            Component::Normal(name) => custody.open_child(name, flags)?,
            _ => {
                return Err(ControllerNixPublicCredentialErrorV1::rejected(
                    CredentialFailureClass::Configuration,
                    CredentialOperation::DirectoryProvenance,
                ));
            }
        }
    }
    let stat = rustix::fs::fstat(custody.directory()?).map_err(|error| {
        ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::DirectoryMetadata,
            error,
        )
    })?;
    require_credential_directory(&stat, uid)?;
    custody.record_identity(&stat);
    Ok(())
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
    let mut slot = CredentialReadSlot::new();
    let observed = open_read_credential(directory, name, uid, maximum_bytes, &mut slot)
        .map_err(ControllerNixPublicCredentialErrorV1::into_legacy)?;
    match observed {
        CredentialReadOutcome::Absent(_) => Ok(None),
        CredentialReadOutcome::Present(identity) => {
            let bytes = slot.bytes.take().ok_or(PublicApiSessionError::Configuration)?;
            Ok(Some((bytes, identity)))
        }
    }
}

// Field order preserves the old local error/unwind drop order: any read buffer
// is destroyed before the File. Resident callers keep this same slot in place.
struct CredentialReadSlot {
    bytes: Option<Zeroizing<Vec<u8>>>,
    file: Option<File>,
}

impl CredentialReadSlot {
    fn new() -> Self {
        Self {
            bytes: None,
            file: None,
        }
    }
}

enum CredentialReadOutcome {
    Absent(rustix::io::Errno),
    Present(CredentialIdentity),
}

fn open_read_credential(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    maximum_bytes: u64,
    slot: &mut CredentialReadSlot,
) -> CredentialResult<CredentialReadOutcome> {
    open_read_credential_with_profile(
        directory,
        name,
        uid,
        CredentialReadProfile::Ordinary(maximum_bytes),
        slot,
    )
}

// Only this closed fixed-name profile can exceed the ordinary one-MiB bound.
#[derive(Clone, Copy)]
enum CredentialReadProfile {
    Ordinary(u64),
    PublisherPolicy,
}

impl CredentialReadProfile {
    fn maximum(self) -> u64 {
        match self {
            Self::Ordinary(maximum) => maximum,
            Self::PublisherPolicy => 4 * 1024 * 1024,
        }
    }
}

fn open_read_credential_with_profile(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    profile: CredentialReadProfile,
    slot: &mut CredentialReadSlot,
) -> CredentialResult<CredentialReadOutcome> {
    let maximum_bytes = profile.maximum();
    let allowed = match profile {
        CredentialReadProfile::Ordinary(_) => MAXIMUM_CREDENTIAL_BYTES,
        CredentialReadProfile::PublisherPolicy if name == "publisher-policy-v1.cbor" => {
            4 * 1024 * 1024
        }
        CredentialReadProfile::PublisherPolicy => 0,
    };
    if maximum_bytes == 0 || maximum_bytes > allowed {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileProvenance,
        ));
    }
    if slot.file.is_some() || slot.bytes.is_some() {
        return Err(credential_state_rejected());
    }
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error @ rustix::io::Errno::NOENT) => {
            return Ok(CredentialReadOutcome::Absent(error));
        }
        Err(error) => {
            return Err(ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Configuration,
                CredentialOperation::FileOpen,
                error,
            ));
        }
    };
    slot.file = Some(File::from(descriptor));
    let file = slot.file.as_mut().ok_or_else(credential_state_rejected)?;
    read_opened_credential(file, &mut slot.bytes, uid, maximum_bytes)
        .map(CredentialReadOutcome::Present)
}

fn read_opened_credential(
    file: &mut File,
    bytes: &mut Option<Zeroizing<Vec<u8>>>,
    uid: u32,
    maximum_bytes: u64,
) -> CredentialResult<CredentialIdentity> {
    if bytes.is_some() {
        return Err(credential_state_rejected());
    }
    let before = file.metadata().map_err(|error| {
        ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileMetadata,
            error,
        )
    })?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileProvenance,
        ));
    }

    *bytes = Some(Zeroizing::new(Vec::new()));
    let bytes = bytes.as_mut().ok_or_else(credential_state_rejected)?;
    (&mut *file)
        .take(maximum_bytes + 1)
        .read_to_end(bytes)
        .map_err(|error| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Configuration,
                CredentialOperation::FileRead,
                error,
            )
        })?;
    let after = file.metadata().map_err(|error| {
        ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileMetadata,
            error,
        )
    })?;
    if before.len() != bytes.len() as u64 || identity(&before) != identity(&after) {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Stale,
            CredentialOperation::FileChanged,
        ));
    }
    Ok(identity(&after))
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControllerCredentialPhase {
    Fresh,
    Ready,
    Closed,
}

struct OriginalControllerCredential {
    public: Option<PinnedSystemdCredential>,
    read: CredentialReadSlot,
}

struct CredentialReadback<const COUNT: usize> {
    original_bytes: [Option<Zeroizing<Vec<u8>>>; COUNT],
    named: [CredentialReadSlot; COUNT],
    ancestors: CredentialAncestors,
}

type ControllerCredentialReadback = CredentialReadback<12>;

impl<const COUNT: usize> CredentialReadback<COUNT> {
    fn new() -> Self {
        Self {
            original_bytes: std::array::from_fn(|_| None),
            named: std::array::from_fn(|_| CredentialReadSlot::new()),
            ancestors: CredentialAncestors::new(),
        }
    }
}

/// Parks the fixed Controller's twelve public credentials and opened ancestry.
///
/// This supplies protected local DATA only, not startup or currentness
/// authority. Original FDs and partial observations remain resident on failure
/// or unwind. There is no caller-selected name, path, descriptor or role.
/// Its future caller must park this owner before capture and keep it resident.
pub(crate) struct ControllerNixPublicCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 12],
    ancestors: CredentialAncestors,
    readback: ControllerCredentialReadback,
    uid: Option<u32>,
    phase: ControllerCredentialPhase,
    failure: Option<ControllerNixPublicCredentialErrorV1>,
}

impl std::fmt::Debug for ControllerNixPublicCredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixPublicCredentialCustodyV1(<resident fixed originals>)")
    }
}

impl ControllerNixPublicCredentialCustodyV1 {
    /// Creates empty fixed slots without opening files or admitting authority.
    pub(crate) fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readback: ControllerCredentialReadback::new(),
            uid: None,
            phase: ControllerCredentialPhase::Fresh,
            failure: None,
        }
    }

    /// Captures only the fixed Controller directory and existing twelve names.
    ///
    /// # Errors
    ///
    /// Returns the resident first typed cause if capture was already attempted,
    /// custody is unsafe, a read fails, or original/named observations differ.
    pub(crate) fn capture(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }

        // Close before even the UID observation. An unwinding borrowed call
        // cannot leave a partially captured or interrupted owner Ready.
        self.phase = ControllerCredentialPhase::Closed;
        self.uid = Some(rustix::process::geteuid().as_raw());
        let result = self.capture_originals();
        self.finish(result)
    }

    /// Rechecks the same opened originals and their fixed named bindings.
    ///
    /// # Errors
    ///
    /// Permanently closes on interruption, unsafe/changed custody or I/O error.
    /// Returns the first resident cause on every subsequent refused call.
    pub(crate) fn recheck(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }

        self.phase = ControllerCredentialPhase::Closed;
        // Ready certifies completion of the previous entire readback batch.
        // Retire only that completed batch, never a failed partial observation
        // or an original descriptor. This is not physical Drain or settlement.
        self.readback = ControllerCredentialReadback::new();
        let result = self.observe_originals();
        self.finish(result)
    }

    /// Borrows complete protected public DATA without copying bytes or FDs.
    ///
    /// The loan performs no I/O and is not a freshness or authority permit.
    /// Mutable observation cannot overlap this owner's immutable loan.
    pub(crate) fn publics(&self) -> Option<[&PinnedSystemdCredential; 12]> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?,
            self.originals[1].public.as_ref()?,
            self.originals[2].public.as_ref()?,
            self.originals[3].public.as_ref()?,
            self.originals[4].public.as_ref()?,
            self.originals[5].public.as_ref()?,
            self.originals[6].public.as_ref()?,
            self.originals[7].public.as_ref()?,
            self.originals[8].public.as_ref()?,
            self.originals[9].public.as_ref()?,
            self.originals[10].public.as_ref()?,
            self.originals[11].public.as_ref()?,
        ])
    }

    /// Borrows the first actual cause without displacing retained custody.
    pub(crate) fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.failure.as_ref()
    }

    /// Permanently fences this owner without releasing originals or readbacks.
    pub(crate) fn fence(&mut self) {
        self.phase = ControllerCredentialPhase::Closed;
    }

    fn finish(
        &mut self,
        result: CredentialResult<()>,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(error) => {
                self.phase = ControllerCredentialPhase::Closed;
                Err(self.failure.get_or_insert(error))
            }
        }
    }

    fn capture_originals(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        open_directory_with_custody(
            Path::new(NIX_CONTROLLER_DIRECTORY),
            uid,
            &mut DirectoryCustody::Resident(&mut self.ancestors),
        )?;
        let directory = self.ancestors.directory()?;
        let directory_identity = self.ancestors.slots[3]
            .identity
            .ok_or_else(credential_state_rejected)?;

        for (index, name) in NIX_PUBLIC_NAMES.iter().enumerate() {
            let original = &mut self.originals[index];
            let observed = open_read_credential(
                directory,
                name,
                uid,
                MAXIMUM_CREDENTIAL_BYTES,
                &mut original.read,
            )?;
            let file_identity = require_present_credential(observed)?;

            // Allocate the fixed DATA path while the read buffer is still
            // resident. Once it moves into public, construction is infallible.
            let path = PathBuf::from(NIX_CONTROLLER_DIRECTORY);
            let bytes = original.read.bytes.take().ok_or_else(credential_state_rejected)?;
            original.public = Some(PinnedSystemdCredential {
                name: *name,
                path,
                uid,
                directory_identity,
                file_identity,
                bytes,
                exact_bytes: None,
            });
        }
        self.observe_originals()
    }

    fn observe_originals(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        if rustix::process::geteuid().as_raw() != uid {
            return Err(ControllerNixPublicCredentialErrorV1::rejected(
                CredentialFailureClass::Stale,
                CredentialOperation::DirectoryProvenance,
            ));
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        open_directory_with_custody(
            Path::new(NIX_CONTROLLER_DIRECTORY),
            uid,
            &mut DirectoryCustody::Resident(&mut self.readback.ancestors),
        )?;
        for (original, named) in self
            .ancestors
            .slots
            .iter()
            .zip(&self.readback.ancestors.slots)
        {
            if original.identity != named.identity {
                return Err(ControllerNixPublicCredentialErrorV1::rejected(
                    CredentialFailureClass::Stale,
                    CredentialOperation::DirectoryProvenance,
                ));
            }
        }

        let directory = self.readback.ancestors.directory()?;
        for (index, name) in NIX_PUBLIC_NAMES.iter().enumerate() {
            let original = &mut self.originals[index];
            observe_credential_readback(
                original,
                &mut self.readback.original_bytes[index],
                &mut self.readback.named[index],
                directory,
                name,
                uid,
                CredentialReadProfile::Ordinary(MAXIMUM_CREDENTIAL_BYTES),
            )?;
        }

        // These are descriptor bookends of a bounded local observation, not an
        // atomic filesystem snapshot or external Source/Session currentness.
        for (original, named) in self.originals.iter().zip(&self.readback.named) {
            let public = original.public.as_ref().ok_or_else(credential_state_rejected)?;
            recheck_credential_file(
                original.read.file.as_ref().ok_or_else(credential_state_rejected)?,
                public.file_identity,
            )?;
            recheck_credential_file(
                named.file.as_ref().ok_or_else(credential_state_rejected)?,
                public.file_identity,
            )?;
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        recheck_credential_ancestors(&self.readback.ancestors, uid)?;
        if rustix::process::geteuid().as_raw() != uid {
            return Err(ControllerNixPublicCredentialErrorV1::rejected(
                CredentialFailureClass::Stale,
                CredentialOperation::DirectoryProvenance,
            ));
        }
        Ok(())
    }
}

fn observe_credential_readback(
    original: &mut OriginalControllerCredential,
    bytes: &mut Option<Zeroizing<Vec<u8>>>,
    named: &mut CredentialReadSlot,
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    profile: CredentialReadProfile,
) -> CredentialResult<()> {
    let public = original.public.as_ref().ok_or_else(credential_state_rejected)?;
    let file = original.read.file.as_mut().ok_or_else(credential_state_rejected)?;
    recheck_credential_file(file, public.file_identity)?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Stale,
            CredentialOperation::FileSeek,
            error,
        )
    })?;
    let observed = read_opened_credential(file, bytes, uid, profile.maximum())?;
    if observed != public.file_identity
        || bytes.as_ref().map(|bytes| bytes.as_slice()) != Some(public.bytes())
    {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Stale,
            CredentialOperation::FileChanged,
        ));
    }

    let observed = require_present_credential(open_read_credential_with_profile(
        directory,
        name,
        uid,
        profile,
        named,
    )?)?;
    if observed != public.file_identity
        || named.bytes.as_ref().map(|bytes| bytes.as_slice()) != Some(public.bytes())
    {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Stale,
            CredentialOperation::FileChanged,
        ));
    }
    Ok(())
}


#[cfg(test)]
mod publisher_bootstrap_tests {
    use super::*;

    #[test]
    fn fixed_profiles_preserve_ordinary_and_nix_ceiling() {
        assert_eq!(MAXIMUM_CREDENTIAL_BYTES, 1024 * 1024);
        assert_eq!(CredentialReadProfile::Ordinary(MAXIMUM_CREDENTIAL_BYTES).maximum(), 1024 * 1024);
        assert_eq!(publisher_read_profile(0).maximum(), 272);
        assert_eq!(publisher_read_profile(1).maximum(), 4 * 1024 * 1024);
        assert_eq!(publisher_read_profile(2).maximum(), 32);
        assert_eq!(publisher_read_profile(3).maximum(), 645);
    }

    #[test]
    fn fresh_and_fenced_fixed_holders_expose_no_ready_bytes() {
        let mut owner = PublisherPolicyBootstrapCredentialCustodyV1::new();
        assert!(owner.ready().is_none());
        assert!(owner.failure().is_none());

        owner.fence();
        assert!(owner.ready().is_none());
        assert!(owner.originals.iter().all(|original|
            original.public.is_none() && original.read.file.is_none() && original.read.bytes.is_none()));
    }
}

/// Owns the first actual fixed Publisher credential failure.
#[derive(Debug)]
pub struct PublisherPolicyBootstrapCredentialErrorV1(ControllerNixPublicCredentialErrorV1);

impl std::fmt::Display for PublisherPolicyBootstrapCredentialErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Publisher bootstrap credential custody failed")
    }
}

impl std::error::Error for PublisherPolicyBootstrapCredentialErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Retains only the four fixed Publisher bootstrap credentials and ancestry.
///
/// This is local DATA custody, not PID1, policy, funding or admission authority.
/// Every returned original and partial read remains resident on Err or unwind.
pub struct PublisherPolicyBootstrapCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 4],
    ancestors: CredentialAncestors,
    readback: CredentialReadback<4>,
    uid: Option<u32>,
    phase: ControllerCredentialPhase,
    failure: Option<PublisherPolicyBootstrapCredentialErrorV1>,
}

const PUBLISHER_BOOTSTRAP_NAMES: [&str; 4] = [
    "publisher-policy-source-v1",
    "publisher-policy-v1.cbor",
    "publisher-policy-source-public-key-v1",
    "git-upload-capacity-v1.cbor",
];

impl std::fmt::Debug for PublisherPolicyBootstrapCredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublisherPolicyBootstrapCredentialCustodyV1(<original fixed DATA>)")
    }
}

impl Default for PublisherPolicyBootstrapCredentialCustodyV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PublisherPolicyBootstrapCredentialCustodyV1 {
    /// Prepares empty fixed slots without opening files or granting authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readback: CredentialReadback::new(),
            uid: None,
            phase: ControllerCredentialPhase::Fresh,
            failure: None,
        }
    }

    /// Captures the four original fixed inputs exactly once.
    ///
    /// # Errors
    ///
    /// Permanently closes on reentry, unsafe files, bounded read failure or
    /// changed original/named bindings; borrows the resident first typed cause.
    pub fn capture(&mut self) -> Result<(), &PublisherPolicyBootstrapCredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.uid = Some(rustix::process::geteuid().as_raw());
        let result = self.capture_originals();
        self.finish(result)
    }

    /// Rechecks the same originals and fixed names under the same size profile.
    ///
    /// # Errors
    ///
    /// Closes on interruption, reentry or changed/unsafe input without replacing
    /// originals or retiring a partially failed readback batch.
    pub fn recheck(&mut self) -> Result<(), &PublisherPolicyBootstrapCredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        let result = self.observe_originals();
        self.finish(result)
    }

    /// Borrows complete input DATA without moving bytes or descriptors.
    #[must_use]
    pub fn ready(&self) -> Option<[&[u8]; 4]> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
            self.originals[2].public.as_ref()?.bytes(),
            self.originals[3].public.as_ref()?.bytes(),
        ])
    }

    /// Borrows the first failure without displacing any retained originals.
    #[must_use]
    pub fn failure(&self) -> Option<&PublisherPolicyBootstrapCredentialErrorV1> {
        self.failure.as_ref()
    }

    /// Closes DATA observation without asserting physical drain.
    pub fn fence(&mut self) {
        self.phase = ControllerCredentialPhase::Closed;
    }

    fn finish(&mut self, result: CredentialResult<()>)
        -> Result<(), &PublisherPolicyBootstrapCredentialErrorV1>
    {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(error) => {
                self.phase = ControllerCredentialPhase::Closed;
                Err(self.failure.get_or_insert(PublisherPolicyBootstrapCredentialErrorV1(error)))
            }
        }
    }

    fn capture_originals(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        open_directory_with_custody(
            Path::new(NIX_CONTROLLER_DIRECTORY),
            uid,
            &mut DirectoryCustody::Resident(&mut self.ancestors),
        )?;
        let directory = self.ancestors.directory()?;
        let directory_identity = self.ancestors.slots[3].identity
            .ok_or_else(credential_state_rejected)?;

        for (index, name) in PUBLISHER_BOOTSTRAP_NAMES.iter().enumerate() {
            let original = &mut self.originals[index];
            let file_identity = require_present_credential(open_read_credential_with_profile(
                directory,
                name,
                uid,
                publisher_read_profile(index),
                &mut original.read,
            )?)?;
            let observed_bytes = original.read.bytes.as_ref()
                .ok_or_else(credential_state_rejected)?;
            if (index == 0 && observed_bytes.len() != 272)
                || (index == 2 && observed_bytes.len() != 32)
            {
                return Err(credential_state_rejected());
            }

            let path = PathBuf::from(NIX_CONTROLLER_DIRECTORY);
            let bytes = original.read.bytes.take().ok_or_else(credential_state_rejected)?;
            original.public = Some(PinnedSystemdCredential {
                name: *name,
                path,
                uid,
                directory_identity,
                file_identity,
                bytes,
                exact_bytes: None,
            });
        }
        self.observe_originals()
    }

    fn observe_originals(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        if rustix::process::geteuid().as_raw() != uid {
            return Err(credential_state_rejected());
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        open_directory_with_custody(
            Path::new(NIX_CONTROLLER_DIRECTORY),
            uid,
            &mut DirectoryCustody::Resident(&mut self.readback.ancestors),
        )?;
        for (original, named) in self.ancestors.slots.iter().zip(&self.readback.ancestors.slots) {
            if original.identity != named.identity {
                return Err(credential_state_rejected());
            }
        }

        let directory = self.readback.ancestors.directory()?;
        for (index, name) in PUBLISHER_BOOTSTRAP_NAMES.iter().enumerate() {
            observe_credential_readback(
                &mut self.originals[index],
                &mut self.readback.original_bytes[index],
                &mut self.readback.named[index],
                directory,
                name,
                uid,
                publisher_read_profile(index),
            )?;
        }
        for (original, named) in self.originals.iter().zip(&self.readback.named) {
            let public = original.public.as_ref().ok_or_else(credential_state_rejected)?;
            recheck_credential_file(
                original.read.file.as_ref().ok_or_else(credential_state_rejected)?,
                public.file_identity,
            )?;
            recheck_credential_file(
                named.file.as_ref().ok_or_else(credential_state_rejected)?,
                public.file_identity,
            )?;
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        recheck_credential_ancestors(&self.readback.ancestors, uid)?;
        if rustix::process::geteuid().as_raw() != uid {
            return Err(credential_state_rejected());
        }
        Ok(())
    }
}

fn publisher_read_profile(index: usize) -> CredentialReadProfile {
    match index {
        0 => CredentialReadProfile::Ordinary(272),
        1 => CredentialReadProfile::PublisherPolicy,
        2 => CredentialReadProfile::Ordinary(32),
        _ => CredentialReadProfile::Ordinary(645),
    }
}


fn require_present_credential(
    observed: CredentialReadOutcome,
) -> CredentialResult<CredentialIdentity> {
    match observed {
        CredentialReadOutcome::Present(identity) => Ok(identity),
        CredentialReadOutcome::Absent(error) => Err(ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileOpen,
            error,
        )),
    }
}

fn recheck_credential_file(file: &File, expected: CredentialIdentity) -> CredentialResult<()> {
    let metadata = file.metadata().map_err(|error| {
        ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Stale,
            CredentialOperation::FileMetadata,
            error,
        )
    })?;
    if identity(&metadata) != expected {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Stale,
            CredentialOperation::FileChanged,
        ));
    }
    Ok(())
}

fn recheck_credential_ancestors(
    ancestors: &CredentialAncestors,
    uid: u32,
) -> CredentialResult<()> {
    if ancestors.count != ancestors.slots.len() {
        return Err(credential_state_rejected());
    }
    let mut service_owned = false;
    for (index, slot) in ancestors.slots.iter().enumerate() {
        let directory = slot.descriptor.as_ref().ok_or_else(credential_state_rejected)?;
        let stat = rustix::fs::fstat(directory).map_err(|error| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Stale,
                CredentialOperation::DirectoryMetadata,
                error,
            )
        })?;
        if slot.identity != Some((stat.st_dev, stat.st_ino)) {
            return Err(ControllerNixPublicCredentialErrorV1::rejected(
                CredentialFailureClass::Stale,
                CredentialOperation::DirectoryProvenance,
            ));
        }
        require_credential_ancestor(&stat, uid, &mut service_owned)?;
        if index + 1 == ancestors.count {
            require_credential_directory(&stat, uid)?;
        }
    }
    Ok(())
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
    hardware: Option<OfflineHardwareCredentialsV5>,
}

struct OfflineHardwareCredentialsV5 {
    files: [Option<File>; 2],
    originals: [Option<CredentialIdentity>; 2],
    readbacks: Vec<[Zeroizing<Vec<u8>>; 2]>,
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
            hardware: None,
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
            .try_reserve_exact(if self.hardware.is_some() { 210 } else { 48 })
            .map_err(std::io::Error::other)?;
        self.readbacks
            .try_reserve_exact(if self.hardware.is_some() { 43 } else { 16 })
            .map_err(std::io::Error::other)?;
        if let Some(hardware) = &mut self.hardware {
            hardware.readbacks.try_reserve_exact(43).map_err(std::io::Error::other)?;
        }

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
        if self.hardware.is_some() {
            offline_hardware_credential_names()?;
        } else {
            offline_credential_names()?;
        }

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
        if let Some(hardware) = &mut self.hardware {
            for (index, name) in OFFLINE_HARDWARE_NAMES.iter().enumerate() {
                hardware.files[index] = Some(File::from(openat(
                    directory, *name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?));
                let file = hardware.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
                let metadata = file.metadata()?;
                let length = metadata.len();
                if (index == 0 && (length == 0 || length > 1_048_576))
                    || (index == 1 && length != 32)
                {
                    return Err(offline_credential_rejected());
                }
                require_offline_credential_file(&metadata, length)?;
                offline_credential_label(file)?;
                hardware.originals[index] = Some(identity(&metadata));
            }
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
        if let Some(hardware) = &self.hardware {
            let [domain, hierarchy] = hardware.readbacks.first().ok_or_else(offline_credential_rejected)?;
            let pins = crate::production_operation_compiler::NixFixedDomainPinsDataV2::decode(domain)
                .map_err(std::io::Error::other)?;
            if pins.node().as_bytes() != node.as_slice()
                || hierarchy.iter().all(|byte| *byte == 0)
            {
                return Err(offline_credential_rejected());
            }
        }
        self.admitted = true;
        self.recheck()
    }

    pub(crate) fn admit_hardware(&mut self) -> std::io::Result<()> {
        if self.hardware.is_some() || !self.ancestors.is_empty() {
            return Err(offline_credential_rejected());
        }
        self.hardware = Some(OfflineHardwareCredentialsV5 {
            files: [None, None],
            originals: [None, None],
            readbacks: Vec::new(),
        });
        self.admit()
    }

    pub(crate) fn hardware_domain_original(&self) -> std::io::Result<&[u8]> {
        if !self.admitted {
            return Err(offline_credential_rejected());
        }
        let hardware = self.hardware.as_ref().ok_or_else(offline_credential_rejected)?;
        Ok(&hardware.readbacks.first().ok_or_else(offline_credential_rejected)?[0])
    }

    pub(crate) fn hardware_auth_original(&self) -> std::io::Result<&[u8; 32]> {
        if !self.admitted {
            return Err(offline_credential_rejected());
        }
        let hardware = self.hardware.as_ref().ok_or_else(offline_credential_rejected)?;
        hardware.readbacks.first().ok_or_else(offline_credential_rejected)?[1]
            .as_slice().try_into().map_err(|_| offline_credential_rejected())
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

        let named_before = if self.hardware.is_some() { 205 } else { 45 };
        if !self.admitted || self.named.len() > named_before {
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
        if let Some(hardware) = &self.hardware {
            for index in 0..2 {
                let file = hardware.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
                if Some(identity(&file.metadata()?)) != hardware.originals[index] {
                    return Err(offline_credential_rejected());
                }
                offline_credential_label(file)?;
                self.named.push(File::from(openat(
                    directory, OFFLINE_HARDWARE_NAMES[index],
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?));
                let named = self.named.last().ok_or_else(offline_credential_rejected)?;
                if Some(identity(&named.metadata()?)) != hardware.originals[index] {
                    return Err(offline_credential_rejected());
                }
                offline_credential_label(named)?;
            }
            offline_hardware_credential_names()?;
        } else {
            offline_credential_names()?;
        }
        self.capture_bytes()?;
        if self.readbacks.first() != self.readbacks.last() {
            return Err(offline_credential_rejected());
        }
        if let Some(hardware) = &self.hardware {
            if hardware.readbacks.first() != hardware.readbacks.last() {
                return Err(offline_credential_rejected());
            }
        }
        Ok(())
    }

    fn capture_bytes(&mut self) -> std::io::Result<()> {
        let maximum = if self.hardware.is_some() { 43 } else { 16 };
        if self.readbacks.len() == maximum {
            return Err(offline_credential_rejected());
        }
        self.readbacks.push([
            Zeroizing::new(vec![0; 16]),
            Zeroizing::new(vec![0; 48]),
        ]);
        let bytes = self.readbacks.last_mut().ok_or_else(offline_credential_rejected)?;
        for index in 0..2 {
            let file = self.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
            aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
                file,
                &mut bytes[index],
            )
            .map_err(|error| std::io::Error::other(OfflinePrepareExactReadError(error)))?;
            if Some(identity(&file.metadata()?)) != self.originals[index] {
                return Err(offline_credential_rejected());
            }
            offline_credential_label(file)?;
        }
        if let Some(hardware) = &mut self.hardware {
            if hardware.readbacks.len() == 43 {
                return Err(offline_credential_rejected());
            }
            hardware.readbacks.push([Zeroizing::new(Vec::new()), Zeroizing::new(Vec::new())]);
            let bytes = hardware.readbacks.last_mut().ok_or_else(offline_credential_rejected)?;
            for index in 0..2 {
                let original = hardware.originals[index].ok_or_else(offline_credential_rejected)?;
                let length = usize::try_from(original.6).map_err(|_| offline_credential_rejected())?;
                if (index == 0 && (length == 0 || length > 1_048_576))
                    || (index == 1 && length != 32)
                {
                    return Err(offline_credential_rejected());
                }
                bytes[index].try_reserve_exact(length).map_err(std::io::Error::other)?;
                bytes[index].resize(length, 0);
                let file = hardware.files[index].as_ref().ok_or_else(offline_credential_rejected)?;
                if identity(&file.metadata()?) != original {
                    return Err(offline_credential_rejected());
                }
                aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(file, &mut bytes[index])
                    .map_err(|error| std::io::Error::other(OfflinePrepareExactReadError(error)))?;
                if identity(&file.metadata()?) != original {
                    return Err(offline_credential_rejected());
                }
                offline_credential_label(file)?;
            }
        }
        Ok(())
    }
}

const OFFLINE_PREPARE_DIRECTORY: &str = "/run/credentials/aos-sandbox-nix-floor-provision.service";
const OFFLINE_PREPARE_NAMES: [&str; 2] = ["node-id", "nix-floor-provision-approval-public-key-v3"];
const OFFLINE_PREPARE_LENGTHS: [u64; 2] = [16, 48];
const OFFLINE_HARDWARE_NAMES: [&str; 2] = [
    "nix-fixed-domain-pins-v2", "nix-floor-owner-hierarchy-auth-v4",
];

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
    offline_credential_names_with_recipe(false)
}

fn offline_hardware_credential_names() -> std::io::Result<()> {
    offline_credential_names_with_recipe(true)
}

fn offline_credential_names_with_recipe(hardware: bool) -> std::io::Result<()> {
    let mut names = Vec::new();
    let count = if hardware { 4 } else { 2 };
    names.try_reserve_exact(count + 1).map_err(std::io::Error::other)?;
    for entry in std::fs::read_dir(OFFLINE_PREPARE_DIRECTORY)? {
        names.push(entry?.file_name());
        if names.len() > count {
            return Err(offline_credential_rejected());
        }
    }
    if hardware {
        names.sort();
        let mut expected = [
            OFFLINE_PREPARE_NAMES[0], OFFLINE_PREPARE_NAMES[1],
            OFFLINE_HARDWARE_NAMES[0], OFFLINE_HARDWARE_NAMES[1],
        ].map(std::ffi::OsString::from);
        expected.sort();
        if names != expected {
            return Err(offline_credential_rejected());
        }
        Ok(())
    } else {
        require_offline_credential_names(names)
    }
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
struct OfflinePrepareExactReadError(
    #[source] aos_sandbox_linux::protected_file::ExactReadFailure,
);

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
    fn controller_public_empty_owner_exposes_no_ready_data_or_opened_files() {
        let owner = ControllerNixPublicCredentialCustodyV1::new();

        assert!(owner.publics().is_none());
        assert!(owner.failure().is_none());
        assert_eq!(owner.ancestors.count, 0);
        assert_eq!(owner.readback.ancestors.count, 0);
        assert!(owner.ancestors.slots.iter().all(|slot| slot.descriptor.is_none()));
        assert!(owner.originals.iter().all(|slot| {
            slot.public.is_none() && slot.read.file.is_none() && slot.read.bytes.is_none()
        }));
        assert!(owner.readback.named.iter().all(|slot| {
            slot.file.is_none() && slot.bytes.is_none()
        }));
    }

    #[test]
    fn controller_public_fence_refuses_capture_and_recheck_without_opening() {
        let mut owner = ControllerNixPublicCredentialCustodyV1::new();
        owner.fence();

        assert!(owner.capture().is_err());
        assert!(owner.recheck().is_err());

        assert!(owner.publics().is_none());
        assert!(owner.uid.is_none());
        assert_eq!(owner.ancestors.count, 0);
        assert_eq!(owner.readback.ancestors.count, 0);
        assert!(matches!(
            owner.failure().unwrap().operation,
            CredentialOperation::State,
        ));
    }

    #[test]
    fn controller_public_first_io_cause_survives_later_refusals_and_fence() {
        use std::error::Error as _;

        let mut owner = ControllerNixPublicCredentialCustodyV1::new();
        let original = ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileRead,
            std::io::Error::from_raw_os_error(5),
        );
        assert!(owner.finish(Err(original)).is_err());
        let first = owner.failure().unwrap() as *const _;

        assert!(owner.recheck().is_err());
        assert!(owner.capture().is_err());
        owner.fence();

        let retained = owner.failure().unwrap();
        assert_eq!(first, retained as *const _);
        assert_eq!(
            retained.source().unwrap().downcast_ref::<std::io::Error>()
                .unwrap().raw_os_error(),
            Some(5),
        );
        assert!(matches!(retained.operation, CredentialOperation::FileRead));
        assert!(owner.publics().is_none());
    }

    #[test]
    fn controller_public_failed_batch_preserves_partial_buffers_without_ready_view() {
        let mut owner = ControllerNixPublicCredentialCustodyV1::new();
        owner.readback.original_bytes[2] = Some(Zeroizing::new(vec![1, 2, 3]));
        owner.readback.named[2].bytes = Some(Zeroizing::new(vec![4, 5]));

        assert!(owner.finish(Err(credential_state_rejected())).is_err());
        assert!(owner.recheck().is_err());

        assert_eq!(
            owner.readback.original_bytes[2].as_ref().unwrap().as_slice(),
            &[1, 2, 3],
        );
        assert_eq!(
            owner.readback.named[2].bytes.as_ref().unwrap().as_slice(),
            &[4, 5],
        );
        assert!(owner.publics().is_none());
        assert!(owner.ancestors.slots.iter().all(|slot| slot.descriptor.is_none()));
    }

    #[test]
    fn controller_public_missing_required_file_retains_actual_errno_and_legacy_class() {
        use std::error::Error as _;

        let error = require_present_credential(
            CredentialReadOutcome::Absent(rustix::io::Errno::NOENT),
        ).unwrap_err();

        assert_eq!(
            error.source().unwrap().downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::NOENT),
        );
        assert!(matches!(error.into_legacy(), PublicApiSessionError::Configuration));
        assert!(matches!(
            ControllerNixPublicCredentialErrorV1::rejected(
                CredentialFailureClass::Stale,
                CredentialOperation::FileChanged,
            ).into_legacy(),
            PublicApiSessionError::Stale,
        ));
    }

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
