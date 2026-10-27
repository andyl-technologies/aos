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
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use aos_sandbox_protocol::public_api_session_data::PublicApiSessionError;

mod public_recheck;
pub use public_recheck::PublicApiCredentialRecheckV1;

mod controller_q04;
pub use controller_q04::ControllerQ04NativeCredentialCustodyV1;

mod git_coverage;
pub use git_coverage::{GitCoverageCredentialCustodyV1, GitCoverageCredentialDataV1,
    GitCoverageCredentialErrorV1};

mod publisher_bootstrap;
pub use publisher_bootstrap::{PublisherPolicyBootstrapCredentialCustodyV1,
    PublisherPolicyBootstrapCredentialErrorV1};

mod runtime_deployment;
pub use runtime_deployment::RuntimeDeploymentCredentialCustodyV2;
use runtime_deployment::{
    RUNTIME_DEPLOYMENT_CREDENTIAL_NAMES, RUNTIME_DEPLOYMENT_CREDENTIAL_BYTES,
    BOOT_PREPARATION_CREDENTIAL_NAMES_V1, BOOT_PREPARATION_CREDENTIAL_BYTES_V1,
    require_runtime_deployment_credential,
};

mod host_noapply_floor;
#[cfg(test)]
mod noapply_native_fixture;
mod root_current;
mod root_delete;
mod root_fixed_public;
mod root_noapply_signing;
mod root_storage;
pub use root_noapply_signing::{RootNoApplySigningCredentialOriginalV2,RootNoApplySigningCredentialClosedV2};
pub use host_noapply_floor::{HostNoApplyRootPublicCredentialOriginalV2,
    HostNoApplyRootPublicCredentialClosedV2};
mod root_cache_memory;
pub use root_cache_memory::RootCurrentCacheMemoryCustodyV1;
mod root_broker_plan;
pub use root_broker_plan::RootCurrentBrokerPlanCredentialCustodyV1;
pub use root_storage::RootCurrentStorageManifestCustodyV1;
pub use root_delete::{RootCurrentHostManifestCustodyV2, RootDeleteBrokerManifestsCustodyV2};
pub use root_current::{RootCurrentIssuerCredentialCustodyV1,
    RootCurrentIssuerReadbackOriginalV1,
    RootCurrentOwnershipCredentialCustodyV1, ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1};

mod controller_startup;
pub use controller_startup::ControllerStartupCredentialGeometryV1;
pub use controller_startup::ControllerInitialCredentialCustodyV1;

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
const Q04_CONTROLLER_NAMES: [&str; 6] = [
    "controller-hold-signing-key",
    "controller-hold-public-key",
    "cache-owner-readback-signing-key",
    "cache-owner-readback-public-key",
    "deployment-public-key",
    "project-public-key",
];
const Q04_CONTROLLER_LENGTHS: [u64; 6] = [32, 80, 32, 80, 80, 80];
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
pub struct PinnedSystemdCredential {
    name: &'static str,
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    file_identity: CredentialIdentity,
    bytes: Zeroizing<Vec<u8>>,
    exact_bytes: Option<u64>,
}

/// Existing operator recovery callers share the same protected file custody.
pub type PinnedOperatorRecoveryKeyV1 = PinnedSystemdCredential;

impl PinnedSystemdCredential {
    /// Opens only the existing public attach verifier; never the signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized, unsafe, or changing fixed credential custody.
    pub fn load_attach_grant_public() -> Result<Self, PublicApiSessionError> {
        Self::load_named("openssh-attach-grant-public-key")
    }

    /// Opens the exact existing deployment trust bytes signed into attach grants.
    ///
    /// # Errors
    /// Rejects missing, oversized, unsafe, or changing fixed credential custody.
    pub fn load_attach_trust() -> Result<Self, PublicApiSessionError> {
        Self::load_named("openssh-attach-trust.json")
    }

    /// Opens the dedicated controller recovery key from systemd credentials.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn load() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_RECOVERY_KEY_NAME)
    }

    /// Opens the independently pinned Storage owner public key.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn load_storage_owner_public() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_STORAGE_OWNER_KEY_NAME)
    }

    /// Opens the separate public project-authorization issuer pin.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn load_project_authorization_issuer_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named(PROJECT_AUTHORIZATION_ISSUER_NAME)
    }

    /// Opens the separate public Controller Source-tree seed issuer pin.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn load_controller_source_tree_seed_issuer_v1() -> Result<Self, PublicApiSessionError>
    {
        Self::load_named(CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME)
    }

    /// Retains the fixed independent Nix recipe issuer, never a signing seed.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub fn load_nix_recipe_issuer_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-recipe-issuer-v2")
    }

    /// Retains the fixed Nix domain/presentation and disclosure pin contract.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub fn load_nix_fixed_domain_pins_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-fixed-domain-pins-v2")
    }

    /// Retains the fixed four-role Nix public endpoint manifest.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized, unsafe or changing fixed protected custody.
    pub fn load_nix_broker_session_manifest_v1() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-broker-session-manifest-v1")
    }

    /// Retains the bounded independent recipe catalog; never a signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_preadmitted_recipes_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named("nix-preadmitted-recipes-v2")
    }

    /// Retains the existing public ownership policy without its session secret.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_ownership_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("ownership-lease-policy.cbor")
    }

    /// Retains the existing public ownership verification key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_ownership_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("ownership-lease-public-key")
    }

    /// Retains the existing public Host plan policy, never its signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_host_plan_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-plan-policy.cbor")
    }

    /// Retains the existing public Host plan key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_host_plan_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-plan-public-key")
    }

    /// Retains Host's independently provisioned plan revocation scope.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_host_plan_revocation_scope() -> Result<Self, PublicApiSessionError> {
        Self::load_named("broker-revocation-scope")
    }

    /// Retains the existing public Mount plan policy, never its signing seed.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_mount_plan_policy() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-plan-policy.cbor")
    }

    /// Retains the existing public Mount plan key.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_mount_plan_public_key() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-plan-public-key")
    }

    /// Retains Mount's independently provisioned plan revocation scope.
    ///
    /// # Errors
    /// Rejects missing, oversized or unsafe fixed protected credential custody.
    pub fn load_nix_mount_plan_revocation_scope() -> Result<Self, PublicApiSessionError> {
        Self::load_named("mount-broker-revocation-scope")
    }

    /// Retains the twelve public pins from only the fixed Nix control unit.
    ///
    /// # Errors
    /// Rejects absent, unsafe, oversized or replaced original credentials.
    /// This ignores environment-selected directories and loads no secrets.
    pub fn load_nix_owner_publics() -> Result<[Self; 12], PublicApiSessionError> {
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
    pub fn load_nix_owner_node_id() -> Result<Self, PublicApiSessionError> {
        Self::load_nix_node_at(NIX_OWNER_DIRECTORY)
    }

    /// Retains the separate exact node credential from the fixed Controller.
    ///
    /// # Errors
    /// Rejects missing, unsafe, replaced or nonexact sixteen-byte custody.
    pub fn load_nix_controller_node_id() -> Result<Self, PublicApiSessionError> {
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
    pub fn load_source_genesis_packets_optional()
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
            aos_sandbox_protocol::source_seed_layout::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1 as u64,
            aos_sandbox_protocol::source_project_authorization::PROJECT_AUTHORIZATION_SOURCE_BYTES_V2 as u64,
        ];
        let seed =
            Self::open_optional_exact(path.clone(), SOURCE_GENESIS_PACKET_NAMES[0], lengths[0])?;
        let authorization = Self::open_optional_lengths(
            path, SOURCE_GENESIS_PACKET_NAMES[1],
            &[lengths[1], aos_sandbox_protocol::source_project_authorization::PROJECT_AUTHORIZATION_SOURCE_BYTES_V3 as u64],
        )?;
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
        Self::open_optional_lengths(path, name, &[exact_bytes])
    }

    // Shares the existing bounded reader and pins the actual accepted width.
    // Alternate lengths never select another credential name or trust root.
    fn open_optional_lengths(
        path: PathBuf,
        name: &'static str,
        lengths: &[u64],
    ) -> Result<Option<Self>, PublicApiSessionError> {
        let maximum = lengths.iter().copied().max().ok_or(PublicApiSessionError::Configuration)?;
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let Some((bytes, file_identity)) =
            read_optional_one_with_identity(&directory, name, uid, maximum)?
        else {
            return Ok(None);
        };
        let exact_bytes = bytes.len() as u64;
        if !lengths.contains(&exact_bytes) {
            return Err(PublicApiSessionError::Configuration);
        }
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

    /// Borrows completed raw DATA from this same native custody owner.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reopens the fixed path and proves that its inode and bytes are unchanged.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck(&self) -> Result<(), PublicApiSessionError> {
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
///
/// # Errors
/// Refuses an unsafe, missing, changed, failed, or already closed fixed
/// credential observation; it does not confer role or receiving authority.
pub fn load_entitlement_credentials()
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

/// Retains the two fixed public entitlement inputs for selected first issuance.
/// The same directory/read/readback engines own all returned files and buffers.
pub struct InitialEntitlementCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 2],
    ancestors: CredentialAncestors,
    readback: CredentialReadback<2>,
    uid: Option<u32>,
    phase: ControllerCredentialPhase,
    failure: Option<ControllerNixPublicCredentialErrorV1>,
}

impl InitialEntitlementCredentialCustodyV1 {
    /// Creates empty fixed native destinations without IO or authority.
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

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn capture(&mut self) -> Result<(), ()> {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.uid = Some(rustix::process::geteuid().as_raw());
        let result = (|| {
            let uid = self.uid.ok_or_else(credential_state_rejected)?;
            capture_controller_credential_originals(
                uid, &[ENTITLEMENT_NAME, ENTITLEMENT_KEY_NAME],
                &[MAXIMUM_CREDENTIAL_BYTES; 2], &mut self.originals, &mut self.ancestors,
            )?;
            self.observe()
        })();
        self.finish(result)
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck(&mut self) -> Result<(), ()> {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        let result = self.observe();
        self.finish(result)
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    pub fn ready(&self) -> Option<[&[u8]; 2]> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
        ])
    }

    /// Borrows the earliest retained native or state-refusal cause.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.failure.as_ref()
    }

    fn observe(&mut self) -> CredentialResult<()> {
        observe_controller_credential_readback(
            self.uid.ok_or_else(credential_state_rejected)?,
            &[ENTITLEMENT_NAME, ENTITLEMENT_KEY_NAME], &[MAXIMUM_CREDENTIAL_BYTES; 2],
            &mut self.originals, &self.ancestors, &mut self.readback,
        )
    }

    fn finish(&mut self, result: CredentialResult<()>) -> Result<(), ()> {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(cause) => {
                self.failure.get_or_insert(cause);
                self.phase = ControllerCredentialPhase::Closed;
                Err(())
            }
        }
    }
}

/// Retains the actual four public TLS credential digests and native names.
///
/// This native DATA supplies no authenticated peer or application authority.
pub struct Credentials {
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    digests: [[u8; 32]; 4],
}

impl Credentials {
    // Only public trust material is retained; the server private key digest is
    // deliberately excluded from the original decision's historical binding.
    /// Rechecks this fixed native recipe and retains its original refusal.
    pub fn public_trust_digests(&self) -> [[u8; 32]; 3] {
        [self.digests[0], self.digests[2], self.digests[3]]
    }

    /// Loads the existing fixed credential recipe through its protected native reader.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn load() -> Result<(Self, [Zeroizing<Vec<u8>>; 4]), PublicApiSessionError> {
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

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck(&self) -> Result<(), PublicApiSessionError> {
        self.recheck_inner(&mut public_recheck::RecheckCustody::ordinary())
            .map_err(ControllerNixPublicCredentialErrorV1::into_legacy)
    }

    fn recheck_inner(
        &self,
        custody: &mut public_recheck::RecheckCustody<'_>,
    ) -> CredentialResult<()> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(credential_state_rejected());
        }
        custody.open(&self.path, self.uid)?;
        let stat = rustix::fs::fstat(custody.directory()?).map_err(|cause| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Stale,
                CredentialOperation::DirectoryMetadata,
                cause,
            )
        })?;
        if (stat.st_dev, stat.st_ino) != self.directory_identity {
            return Err(credential_state_rejected());
        }
        custody.read_all(self.uid)?;
        for (index, expected) in self.digests.iter().enumerate() {
            let actual: [u8; 32] = Sha256::digest(custody.bytes(index)?).into();
            if actual != *expected {
                return Err(credential_state_rejected());
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
pub struct ControllerNixPublicCredentialErrorV1 {
    class: CredentialFailureClass,
    operation: CredentialOperation,
    io: Option<CredentialIoCause>,
}

impl ControllerNixPublicCredentialErrorV1 {
    /// Constructs a state-refusal classification without native authority.
    #[must_use]
    pub fn state_rejected_v1() -> Self {
        credential_state_rejected()
    }

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

    /// Projects the same original cause into the established redacted class.
    pub fn legacy_projection(&self) -> PublicApiSessionError {
        match self.class {
            CredentialFailureClass::Configuration => PublicApiSessionError::Configuration,
            CredentialFailureClass::Stale => PublicApiSessionError::Stale,
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
    Borrowed {
        slots: &'owner mut [CredentialDirectorySlot],
        count: &'owner mut usize,
    },
}

impl DirectoryCustody<'_> {
    fn resident_parts(&mut self) -> Option<(&mut [CredentialDirectorySlot], &mut usize)> {
        match self {
            Self::Local(_) => None,
            Self::Resident(ancestors) => Some((&mut ancestors.slots, &mut ancestors.count)),
            Self::Borrowed { slots, count } => Some((slots, count)),
        }
    }

    fn open_root(&mut self, flags: OFlags) -> CredentialResult<()> {
        if let Self::Local(directory) = self {
            *directory = Some(open("/", flags, Mode::empty()).map_err(|cause| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Configuration,
                    CredentialOperation::DirectoryOpen,
                    cause,
                )
            })?);
            return Ok(());
        }
        let (slots, count) = self.resident_parts().ok_or_else(credential_state_rejected)?;
        if *count != 0 || slots.iter().any(|slot| slot.descriptor.is_some()) {
            return Err(credential_state_rejected());
        }
        let destination = slots.first_mut().ok_or_else(credential_state_rejected)?;
        destination.descriptor = Some(open("/", flags, Mode::empty()).map_err(|cause| {
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Configuration,
                CredentialOperation::DirectoryOpen,
                cause,
            )
        })?);
        *count = 1;
        Ok(())
    }

    fn directory(&self) -> CredentialResult<&OwnedFd> {
        match self {
            Self::Local(directory) => directory.as_ref().ok_or_else(credential_state_rejected),
            Self::Resident(ancestors) => ancestors.directory(),
            Self::Borrowed { slots, count } => slots.get(count.wrapping_sub(1))
                .and_then(|slot| slot.descriptor.as_ref())
                .ok_or_else(credential_state_rejected),
        }
    }

    fn record_identity(&mut self, stat: &rustix::fs::Stat) {
        if let Some((slots, count)) = self.resident_parts() {
            if let Some(slot) = slots.get_mut(count.wrapping_sub(1)) {
                slot.identity = Some((stat.st_dev, stat.st_ino));
            }
        }
    }

    fn open_child(&mut self, name: &std::ffi::OsStr, flags: OFlags) -> CredentialResult<()> {
        let open_child = |parent: &OwnedFd| {
            openat(parent, name, flags, Mode::empty()).map_err(|cause| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Configuration,
                    CredentialOperation::DirectoryOpen,
                    cause,
                )
            })
        };
        if let Self::Local(directory) = self {
            let parent = directory.as_ref().ok_or_else(credential_state_rejected)?;
            *directory = Some(open_child(parent)?);
            return Ok(());
        }
        let (slots, count) = self.resident_parts().ok_or_else(credential_state_rejected)?;
        if *count >= slots.len() {
            return Err(credential_state_rejected());
        }
        let (previous, next) = slots.split_at_mut(*count);
        let parent = previous.last().and_then(|slot| slot.descriptor.as_ref())
            .ok_or_else(credential_state_rejected)?;
        let destination = next.first_mut().ok_or_else(credential_state_rejected)?;
        destination.descriptor = Some(open_child(parent)?);
        *count += 1;
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

/// Stores the metadata fields compared by the fixed native credential engines.
///
/// This tuple is comparison DATA and cannot construct a credential snapshot.
pub type CredentialIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

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

#[derive(Clone, Copy)]
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
    RuntimeDeployment(u64),
}

impl CredentialReadProfile {
    fn maximum(self) -> u64 {
        match self {
            Self::Ordinary(maximum) => maximum,
            Self::PublisherPolicy => 4 * 1024 * 1024,
            Self::RuntimeDeployment(maximum) => maximum,
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
        CredentialReadProfile::RuntimeDeployment(maximum)
            if RUNTIME_DEPLOYMENT_CREDENTIAL_NAMES.iter().zip(RUNTIME_DEPLOYMENT_CREDENTIAL_BYTES)
                .chain(BOOT_PREPARATION_CREDENTIAL_NAMES_V1.iter().zip(BOOT_PREPARATION_CREDENTIAL_BYTES_V1))
                .any(|(role, width)| name == *role && maximum == width) => maximum,
        CredentialReadProfile::RuntimeDeployment(_) => 0,
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
    if matches!(profile, CredentialReadProfile::RuntimeDeployment(_)) {
        require_runtime_deployment_credential(file, false)?;
    }
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
    if before.len() != bytes.len() as u64 || credential_metadata_identity_v1(&before) != credential_metadata_identity_v1(&after) {
        return Err(ControllerNixPublicCredentialErrorV1::rejected(
            CredentialFailureClass::Stale,
            CredentialOperation::FileChanged,
        ));
    }
    Ok(credential_metadata_identity_v1(&after))
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

/// Extracts metadata comparison DATA without opening or adopting a file.
#[must_use]
pub fn credential_metadata_identity_v1(metadata: &std::fs::Metadata) -> CredentialIdentity {
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

mod credential_roster;
use credential_roster::{CredentialRosterCustodyV1, CredentialRosterKindV1};

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
pub struct ControllerNixPublicCredentialCustodyV1 {
    custody: CredentialRosterCustodyV1<12, ControllerNixPublicCredentialErrorV1>,
}

impl std::fmt::Debug for ControllerNixPublicCredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixPublicCredentialCustodyV1(<resident fixed originals>)")
    }
}

impl ControllerNixPublicCredentialCustodyV1 {
    /// Creates empty fixed slots without opening files or admitting authority.
    pub fn new() -> Self {
        Self {
            custody: CredentialRosterCustodyV1::new(CredentialRosterKindV1::ControllerPublic),
        }
    }

    /// Captures only the fixed Controller directory and existing twelve names.
    ///
    /// # Errors
    ///
    /// Returns the resident first typed cause if capture was already attempted,
    /// custody is unsafe, a read fails, or original/named observations differ.
    pub fn capture(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        self.custody.capture()
    }

    /// Rechecks the same opened originals and their fixed named bindings.
    ///
    /// # Errors
    ///
    /// Permanently closes on interruption, unsafe/changed custody or I/O error.
    /// Returns the first resident cause on every subsequent refused call.
    pub fn recheck(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        self.custody.recheck()
    }

    /// Borrows complete protected public DATA without copying bytes or FDs.
    ///
    /// The loan performs no I/O and is not a freshness or authority permit.
    /// Mutable observation cannot overlap this owner's immutable loan.
    pub fn publics(&self) -> Option<[&PinnedSystemdCredential; 12]> {
        Some([
            self.custody.public(0)?,
            self.custody.public(1)?,
            self.custody.public(2)?,
            self.custody.public(3)?,
            self.custody.public(4)?,
            self.custody.public(5)?,
            self.custody.public(6)?,
            self.custody.public(7)?,
            self.custody.public(8)?,
            self.custody.public(9)?,
            self.custody.public(10)?,
            self.custody.public(11)?,
        ])
    }

    /// Borrows the first actual cause without displacing retained custody.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.custody.failure()
    }

    /// Permanently fences this owner without releasing originals or readbacks.
    pub fn fence(&mut self) {
        self.custody.fence();
    }
}

// The closed directory recipe selects literal service ancestry only. It is
// private DATA policy, not a caller path, recipient identity or authority grant.
#[derive(Clone, Copy)]
enum FixedCredentialDirectoryV1 {
    Controller,
    RootCurrent,
    HostNoApplyRoot,
}

impl FixedCredentialDirectoryV1 {
    fn path(self) -> &'static Path {
        match self {
            Self::Controller => Path::new(NIX_CONTROLLER_DIRECTORY),
            Self::RootCurrent => Path::new(
                "/run/credentials/aos-sandbox-policy-authorityd.service",
            ),
            Self::HostNoApplyRoot => Path::new(
                "/run/credentials/aos-sandbox-hostd.service",
            ),
        }
    }
}

// Existing Controller callers retain their exact closed recipe and API.
fn capture_controller_credential_originals<const COUNT: usize>(
    uid: u32,
    names: &[&'static str; COUNT],
    maximum_bytes: &[u64; COUNT],
    originals: &mut [OriginalControllerCredential; COUNT],
    ancestors: &mut CredentialAncestors,
) -> CredentialResult<()> {
    capture_fixed_credential_originals(
        FixedCredentialDirectoryV1::Controller,
        uid,
        names,
        maximum_bytes,
        originals,
        ancestors,
    )
}

// Same original-directory capture for the fixed public profiles.
fn capture_fixed_credential_originals<const COUNT: usize>(
    recipe: FixedCredentialDirectoryV1,
    uid: u32,
    names: &[&'static str; COUNT],
    maximum_bytes: &[u64; COUNT],
    originals: &mut [OriginalControllerCredential; COUNT],
    ancestors: &mut CredentialAncestors,
) -> CredentialResult<()> {
    let profiles: [_; COUNT] = std::array::from_fn(|index|
        CredentialReadProfile::Ordinary(maximum_bytes[index]));
    credential_roster::capture_roster_originals(
        recipe.path(), uid, names, &profiles, &[None; COUNT], originals, ancestors,
    )
}

// Optional startup capture keeps its absent-result contract on the same leaf reader.
fn capture_fixed_credential_original_slot(
    directory: &OwnedFd,
    path: &Path,
    directory_identity: DirectoryIdentity,
    name: &'static str,
    uid: u32,
    maximum_bytes: u64,
    original: &mut OriginalControllerCredential,
) -> CredentialResult<CredentialReadOutcome> {
    capture_credential_original_slot_inner(
        directory, path, directory_identity, name, uid, maximum_bytes, None, original,
    )
}

fn capture_credential_original_slot_inner(
    directory: &OwnedFd,
    path: &Path,
    directory_identity: DirectoryIdentity,
    name: &'static str,
    uid: u32,
    maximum_bytes: u64,
    exact_bytes: Option<u64>,
    original: &mut OriginalControllerCredential,
) -> CredentialResult<CredentialReadOutcome> {
    let observed = open_read_credential(
        directory, name, uid, maximum_bytes, &mut original.read,
    )?;
    if let Some(length) = exact_bytes {
        // Q04 has always required presence and exact width before path/pin
        // materialization. The optional and bounded recipes retain their old
        // absent-result and later width-check frontiers.
        require_present_credential(observed)?;
        if original.read.bytes.as_ref().map(|bytes| bytes.len()) != Some(length as usize) {
            return Err(credential_state_rejected());
        }
    }
    if let CredentialReadOutcome::Present(file_identity) = observed {
        // Keep the read buffer resident until fixed path construction ends.
        let path = path.to_path_buf();
        let bytes = original.read.bytes.take().ok_or_else(credential_state_rejected)?;
        original.public = Some(PinnedSystemdCredential {
            name, path, uid, directory_identity, file_identity, bytes, exact_bytes,
        });
    }
    Ok(observed)
}

/// Retains the one independently provisioned Nix generation-origin family.
///
/// Capture and readback use the same fixed Controller ancestry, original-file
/// reader and named comparator as the existing twelve public credentials. This
/// owner supplies bytes, not a current Start, Storage grant or signing key.
pub struct ControllerNixGenerationOriginCredentialCustodyV1 {
    custody: CredentialRosterCustodyV1<1, ControllerNixPublicCredentialErrorV1>,
}

impl std::fmt::Debug for ControllerNixGenerationOriginCredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixGenerationOriginCredentialCustodyV1(<resident original>)")
    }
}

impl ControllerNixGenerationOriginCredentialCustodyV1 {
    /// Creates vacant slots without opening a descriptor or admitting bytes.
    pub fn new() -> Self {
        Self {
            custody: CredentialRosterCustodyV1::new(CredentialRosterKindV1::GenerationOrigin),
        }
    }

    /// Captures the fixed name once, retaining partial reads and original FDs.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn capture(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        self.custody.capture()
    }

    /// Rechecks the original and fixed named file without releasing either.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        self.custody.recheck()
    }

    /// Borrows complete local DATA only while the last readback is complete.
    pub fn bytes(&self) -> Option<&[u8]> {
        Some(self.custody.public(0)?.bytes())
    }

    /// Borrows the first actual credential cause without displacing its owner.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.custody.failure()
    }

    /// Fences interrupted upper work without releasing files or partial bytes.
    pub fn fence(&mut self) {
        self.custody.fence();
    }
}

fn observe_controller_credential_readback<const COUNT: usize>(
    uid: u32,
    names: &[&str; COUNT],
    maximum_bytes: &[u64; COUNT],
    originals: &mut [OriginalControllerCredential; COUNT],
    ancestors: &CredentialAncestors,
    readback: &mut CredentialReadback<COUNT>,
) -> CredentialResult<()> {
    observe_fixed_credential_readback(
        FixedCredentialDirectoryV1::Controller,
        uid,
        names,
        maximum_bytes,
        originals,
        ancestors,
        readback,
    )
}

fn observe_fixed_credential_readback<const COUNT: usize>(
    recipe: FixedCredentialDirectoryV1,
    uid: u32,
    names: &[&str; COUNT],
    maximum_bytes: &[u64; COUNT],
    originals: &mut [OriginalControllerCredential; COUNT],
    ancestors: &CredentialAncestors,
    readback: &mut CredentialReadback<COUNT>,
) -> CredentialResult<()> {
    let profiles: [_; COUNT] = std::array::from_fn(|index|
        CredentialReadProfile::Ordinary(maximum_bytes[index]));
    credential_roster::observe_roster_readback(recipe.path(), uid, names, &profiles, None,
        originals, ancestors, readback)
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
    if matches!(profile, CredentialReadProfile::RuntimeDeployment(_)) {
        require_runtime_deployment_credential(file, false)?;
    }
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
    if credential_metadata_identity_v1(&metadata) != expected {
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
    for index in 0..ancestors.slots.len() {
        recheck_credential_ancestor_slot(ancestors, index, uid, &mut service_owned)?;
    }
    Ok(())
}

// One existing native/policy step, shared by ordinary traversal and the normal
// publisher's independently owed bookends over already-held directory slots.
fn recheck_credential_ancestor_slot(
    ancestors: &CredentialAncestors,
    index: usize,
    uid: u32,
    service_owned: &mut bool,
) -> CredentialResult<()> {
    let slot = ancestors.slots.get(index).ok_or_else(credential_state_rejected)?;
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
    require_credential_ancestor(&stat, uid, service_owned)?;
    if index + 1 == ancestors.count {
        require_credential_directory(&stat, uid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use ed25519_dalek::SigningKey;

    use aos_sandbox_protocol::role_credential::{decode_role_credential, encode_role_credential};

    const SOURCE_ISSUER_MAGIC: &[u8; 8] = b"AOSCSK01";
    const SOURCE_ISSUER_DOMAIN: &[u8] = b"aos.sandbox.controller-source-tree-seed.verifier.v1\0";

    #[test]
    fn controller_public_empty_owner_exposes_no_ready_data_or_opened_files() {
        let owner = ControllerNixPublicCredentialCustodyV1::new();

        assert!(owner.publics().is_none());
        assert!(owner.failure().is_none());
        assert_eq!(owner.custody.ancestors.count, 0);
        assert_eq!(owner.custody.readback.ancestors.count, 0);
        assert!(owner.custody.ancestors.slots.iter().all(|slot| slot.descriptor.is_none()));
        assert!(owner.custody.originals.iter().all(|slot| {
            slot.public.is_none() && slot.read.file.is_none() && slot.read.bytes.is_none()
        }));
        assert!(owner.custody.readback.named.iter().all(|slot| {
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
        assert!(owner.custody.uid.is_none());
        assert_eq!(owner.custody.ancestors.count, 0);
        assert_eq!(owner.custody.readback.ancestors.count, 0);
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
        assert!(owner.custody.finish(Err(original)).is_err());
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
    fn controller_public_failed_batch_preserves_opened_file_without_ready_view() {
        use std::os::fd::AsRawFd as _;

        let mut owner = ControllerNixPublicCredentialCustodyV1::new();
        let opened = tempfile::tempfile().unwrap();
        let descriptor = opened.as_raw_fd();
        owner.custody.originals[2].read.file = Some(opened);

        assert!(owner.custody.finish(Err(credential_state_rejected())).is_err());
        assert!(owner.recheck().is_err());
        assert!(owner.capture().is_err());

        let held = owner.custody.originals[2].read.file.as_ref().unwrap();
        assert_eq!(held.as_raw_fd(), descriptor);
        assert!(held.metadata().is_ok());
        assert!(owner.publics().is_none());
        assert!(owner.custody.ancestors.slots.iter().all(|slot| slot.descriptor.is_none()));
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
        assert!(decode_role_credential(&malformed, SOURCE_ISSUER_MAGIC, SOURCE_ISSUER_DOMAIN).is_none());

        let key = SigningKey::from_bytes(&[41; 32]);
        let valid =
            encode_role_credential(7, &key.verifying_key(), SOURCE_ISSUER_MAGIC, SOURCE_ISSUER_DOMAIN).unwrap();
        let first = directory.path().join("first");
        std::fs::write(&first, valid).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(first, &path).unwrap();
        let (bytes, identity) = read_one_with_identity(&descriptor, name, uid).unwrap();
        assert_eq!(
            decode_role_credential(&bytes, SOURCE_ISSUER_MAGIC, SOURCE_ISSUER_DOMAIN)
                .unwrap().0,
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
