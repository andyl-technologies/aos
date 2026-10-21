//! Retains upper credential semantics above the shared fixed native owner.
//!
//! Q04 keeps its actual role pins and signing keys here. Offline prepare keeps
//! its distinct root-only policy. All common fixed native credential recipes
//! and their original read/recheck slots have one implementation in Broker.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use rustix::fs::{Mode, OFlags, open, openat};
use zeroize::Zeroizing;

pub(crate) use aos_sandbox_broker::systemd_credentials::{
    ControllerInitialCredentialCustodyV1, ControllerNixGenerationOriginCredentialCustodyV1,
    ControllerNixPublicCredentialCustodyV1, ControllerNixPublicCredentialErrorV1,
    Credentials, InitialEntitlementCredentialCustodyV1, PinnedOperatorRecoveryKeyV1,
    PinnedSystemdCredential, ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1,
    RootCurrentIssuerCredentialCustodyV1, RootCurrentOwnershipCredentialCustodyV1,
    RootCurrentStorageManifestCustodyV1, RootCurrentBrokerPlanCredentialCustodyV1,
    RuntimeDeploymentCredentialCustodyV2, load_entitlement_credentials,
};

pub use aos_sandbox_broker::systemd_credentials::{
    ControllerStartupCredentialGeometryV1,
    GitCoverageCredentialCustodyV1,
    GitCoverageCredentialDataV1,
    GitCoverageCredentialErrorV1,
    PublisherPolicyBootstrapCredentialCustodyV1,
    PublisherPolicyBootstrapCredentialErrorV1,
};
use aos_sandbox_broker::systemd_credentials::{
    ControllerQ04NativeCredentialCustodyV1, CredentialIdentity,
    credential_metadata_identity_v1 as identity,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControllerCredentialPhase {
    Fresh,
    Ready,
    Closed,
}

fn credential_state_rejected() -> ControllerNixPublicCredentialErrorV1 {
    ControllerNixPublicCredentialErrorV1::state_rejected_v1()
}

/// Retains the original local credential failure or role-codec failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerQ04CredentialErrorV1 {
    /// The common fixed directory/read engine failed with its original cause.
    #[error(transparent)]
    Credential(std::sync::Arc<ControllerNixPublicCredentialErrorV1>),
    /// The genuine Controller-only role pin rejected its canonical bytes.
    #[error(transparent)]
    Role(#[from] crate::policy_compiler::ControllerHoldReadbackErrorV1),
    /// The existing Cache-purpose pin rejected its canonical bytes.
    #[error(transparent)]
    CacheRole(#[from] aos_sandbox_cache::CacheOwnerReadbackErrorV1),
}

// Preserve the existing upper flattened packet-error lane after the pure codec move.
impl From<aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1>
    for ControllerQ04CredentialErrorV1
{
    fn from(cause: aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1) -> Self {
        Self::CacheRole(aos_sandbox_cache::CacheOwnerReadbackErrorV1::from(cause))
    }
}

impl From<ControllerNixPublicCredentialErrorV1> for ControllerQ04CredentialErrorV1 {
    fn from(cause: ControllerNixPublicCredentialErrorV1) -> Self {
        Self::Credential(std::sync::Arc::new(cause))
    }
}

impl From<std::sync::Arc<ControllerNixPublicCredentialErrorV1>> for ControllerQ04CredentialErrorV1 {
    fn from(cause: std::sync::Arc<ControllerNixPublicCredentialErrorV1>) -> Self {
        Self::Credential(cause)
    }
}

/// Keeps both existing Controller and Cache role pairs in the selected owner.
///
/// This is only fixed credential custody. It supplies no Controller writer,
/// startup admission, Root pin, current cut or authority to publish. The caller
/// parks it before capture and retains it through all original-flight checks.
pub(crate) struct ControllerQ04CredentialCustodyV1 {
    native: ControllerQ04NativeCredentialCustodyV1,
    phase: ControllerCredentialPhase,
    failure: Option<ControllerQ04CredentialErrorV1>,
    signer: Option<ed25519_dalek::SigningKey>,
    pin: Option<aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1>,
    cache_signer: Option<ed25519_dalek::SigningKey>,
    cache_pin: Option<aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1>,
    deployment_pin: Option<(u64, ed25519_dalek::VerifyingKey)>,
    project_pin: Option<(u64, ed25519_dalek::VerifyingKey)>,
}

impl std::fmt::Debug for ControllerQ04CredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerQ04CredentialCustodyV1(<resident fixed role pairs>)")
    }
}

impl ControllerQ04CredentialCustodyV1 {
    /// Creates empty original slots without I/O, authority or key extraction.
    pub(crate) fn new() -> Self {
        Self {
            native: ControllerQ04NativeCredentialCustodyV1::new(),
            phase: ControllerCredentialPhase::Fresh,
            failure: None,
            signer: None,
            pin: None,
            cache_signer: None,
            cache_pin: None,
            deployment_pin: None,
            project_pin: None,
        }
    }

    /// Reads only the two existing fixed secrets and their separate role pins.
    ///
    /// # Errors
    ///
    /// Permanently refuses a repeated capture, unsafe or changed originals,
    /// partial pair, I/O failure, foreign role, or mismatching signing key.
    pub(crate) fn capture(&mut self) -> Result<(), &ControllerQ04CredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected().into()));
        }

        self.phase = ControllerCredentialPhase::Closed;
        let result = self.capture_pair();
        self.finish(result)
    }

    /// Brackets use with the same original files and their fixed named bindings.
    ///
    /// # Errors
    ///
    /// An interrupted, failed or fenced owner never reopens. The original typed
    /// cause and partial observations remain resident in this same owner.
    pub(crate) fn recheck(&mut self) -> Result<(), &ControllerQ04CredentialErrorV1> {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected().into()));
        }

        self.phase = ControllerCredentialPhase::Closed;
        let result = self.native.recheck().map_err(ControllerQ04CredentialErrorV1::from);
        self.finish(result)
    }

    /// Borrows the checked existing role only while original local custody is ready.
    ///
    /// This loan does no I/O and cannot overlap mutable named readback. Root
    /// still independently verifies the real role pin and original held cut.
    pub(crate) fn signer(&self) -> Option<(u64, &ed25519_dalek::SigningKey)> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some((self.pin.as_ref()?.generation(), self.signer.as_ref()?))
    }

    /// Borrows the distinct existing Cache role under the same ready originals.
    pub(crate) fn cache_signer(&self) -> Option<(u64, &ed25519_dalek::SigningKey)> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some((self.cache_pin.as_ref()?.generation(), self.cache_signer.as_ref()?))
    }

    // These are only the original fixed policy verifier loans, not Root's
    // role/currentness admission. The same credential walker owns their FDs.
    pub(crate) fn policy_pins(
        &self,
    ) -> Option<((u64, &ed25519_dalek::VerifyingKey), (u64, &ed25519_dalek::VerifyingKey))> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        let (deployment_generation, deployment) = self.deployment_pin.as_ref()?;
        let (project_generation, project) = self.project_pin.as_ref()?;
        Some(((*deployment_generation, deployment), (*project_generation, project)))
    }

    /// Keeps all originals but permanently denies later signing loans.
    pub(crate) fn fence(&mut self) {
        self.native.fence();
        self.phase = ControllerCredentialPhase::Closed;
    }

    /// Borrows the first failure without extracting any original resources.
    pub(crate) fn failure(&self) -> Option<&ControllerQ04CredentialErrorV1> {
        self.failure.as_ref()
    }

    fn finish(
        &mut self,
        result: Result<(), ControllerQ04CredentialErrorV1>,
    ) -> Result<(), &ControllerQ04CredentialErrorV1> {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(error) => {
                self.native.fence();
                self.phase = ControllerCredentialPhase::Closed;
                Err(self.failure.get_or_insert(error))
            }
        }
    }

    fn capture_pair(&mut self) -> Result<(), ControllerQ04CredentialErrorV1> {
        self.native.capture()?;
        let inputs = self.native.ready().ok_or_else(credential_state_rejected)?;

        let pin_bytes = inputs[1];
        self.pin = Some(
            aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
                pin_bytes,
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)?,
        );
        let seed_bytes = inputs[0];
        let seed = Zeroizing::new(<[u8; 32]>::try_from(seed_bytes)
            .map_err(|_| credential_state_rejected())?);
        self.signer = Some(ed25519_dalek::SigningKey::from_bytes(&seed));
        if self.pin.as_ref().map(|pin| pin.verifying_key())
            != self.signer.as_ref().map(|signer| signer.verifying_key()).as_ref()
        {
            return Err(credential_state_rejected().into());
        }

        let cache_pin_bytes = inputs[3];
        self.cache_pin = Some(aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1::decode(
            cache_pin_bytes,
        )?);
        let cache_seed_bytes = inputs[2];
        let cache_seed = Zeroizing::new(<[u8; 32]>::try_from(cache_seed_bytes)
            .map_err(|_| credential_state_rejected())?);
        self.cache_signer = Some(ed25519_dalek::SigningKey::from_bytes(&cache_seed));
        if self.cache_pin.as_ref().map(|pin| pin.verifying_key())
            != self.cache_signer.as_ref().map(|signer| signer.verifying_key()).as_ref()
            || self.cache_signer.as_ref().map(|signer| signer.verifying_key())
                == self.signer.as_ref().map(|signer| signer.verifying_key())
        {
            return Err(credential_state_rejected().into());
        }

        // Reuse the existing common role frame decoder with the exact old
        // Security policy-role magic/domains, never a second credential codec.
        let deployment_bytes = inputs[4];
        self.deployment_pin = Some(aos_sandbox_protocol::role_credential::decode_role_credential(
            deployment_bytes, b"AOSPDK01", b"aos.sandbox.policy-deployment-verifier.v1\0",
        ).ok_or_else(credential_state_rejected)?);
        let project_bytes = inputs[5];
        self.project_pin = Some(aos_sandbox_protocol::role_credential::decode_role_credential(
            project_bytes, b"AOSPPK01", b"aos.sandbox.policy-project-verifier.v1\0",
        ).ok_or_else(credential_state_rejected)?);
        Ok(())
    }

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

}
