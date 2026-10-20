//! Binds protected boot preparation to the actual successful publisher invocation.
//!
//! The signed completed055 target is historical preparation DATA. This owner
//! independently observes the current PID1 invocation, boot, immutable producer
//! image/profile and protected files; it never claims a fresh latest-NV read or
//! constructs BackendReadiness. Root's same-Control caller owns all outer posts.

mod native;
mod properties;

use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use aos_sandbox_broker::profile_data::runtime_deployment::{
    BootPreparationPublisherProfileDataV1, PUBLISHER_UNIT_V1, RuntimeDeploymentProfileDataErrorV1,
    normalize_publisher_unit_data_v1, publisher_profile_comparison_receiving_bytes_v1,
    require_boot_preparation_profile_data_v1,
};
use aos_sandbox_broker::profile_data::schema::MAXIMUM_PROFILE_BYTES;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_linux::protected_file::{
    FixedProtectedReadOriginalV3, positional_hash::PositionalHashOriginalV2,
};
use aos_sandbox_protocol::runtime_deployment::boot_preparation::{
    BOOT_PREPARATION_COMPLETION_BYTES_V1, BOOT_PREPARATION_COMPLETION_FILE_V1,
    BOOT_PREPARATION_PURPOSE_BYTES_V1, SignedBootPreparationCompletionDataV1,
    SignedBootPreparationPurposeDataV1,
};
use aos_sandbox_protocol::runtime_deployment::{DeploymentGenesisV1, DeploymentWireErrorV1};
use aos_systemd::{ServicePropertiesReadOriginalV2, SystemdClient};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::phase0_probe::ProtectedPackagedExecutableHashOriginalV2;
use crate::{HostError, Result};
use native::{BootDirectoriesOriginalV1, BootFileOriginalV1, DIRECTORIES_V1};

const CREDENTIALS: &str = "/run/credentials/aos-sandbox-hostd.service";
const PUBLICATION: &str = "/var/lib/aos/sandbox/runtime-deployment/readiness";
const GENESIS: &str = "runtime-deployment-genesis-v1";
const PIN: &str = "runtime-deployment-provisioner-pin-v1";
const PURPOSE: &str = "runtime-deployment-boot-purpose-v1";
const PROFILE: &str = "aos-runtime-deployment-startup-profile";
const FILES: usize = 7;
const COMPLETION: usize = 0;
const GENESIS_SLOT: usize = 1;
const PIN_SLOT: usize = 2;
const PURPOSE_SLOT: usize = 3;
const PROFILE_SLOT: usize = 4;
const ORIGINAL_PROFILE_SLOT: usize = 5;
const UNIT_SLOT: usize = 6;
// These are the existing shared canonical store-path and unit-normalizer bounds.
const STORE_PATH_BYTES: usize = 1024;
const UNIT_BYTES: usize = 64 * 1024;

/// Preserves an exact fixed comparison refusal without an allocated diagnostic.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Host boot preparation differs: {0}")]
pub(in crate::plan) struct BootPreparationPolicyErrorV1(&'static str);

/// Reports a failed, incomplete or repeated retained boot preparation check.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("retained Host boot preparation remains incomplete or closed")]
pub(in crate::plan) struct BootPreparationClosedV1;

#[derive(Clone, Copy)]
enum First {
    File(usize, usize),
    Directories,
    Genesis,
    Pin,
    Purpose,
    Completion,
    Profile,
    ProfileContract,
    Publisher(usize),
    Policy(usize),
    Boot(usize),
    Image,
    ImageAfter,
    Normalization,
    Order,
}

/// Owns the native successful-invocation and full signed preparation conjunction.
///
/// Construction performs no allocation or observation. The genuine Phase0
/// borrower pays the whole source quote on its already consumed Control before
/// constructing this owner. Both final destinations remain distinct once-only
/// originals; no failed prefix, account or observation slot is reset.
pub(in crate::plan) struct HostBootPreparationOriginalV1 {
    files: [[BootFileOriginalV1; FILES]; 2],
    directories: BootDirectoriesOriginalV1,
    boot: [RootOriginalKernelBootIdAttemptV1; 2],
    boot_values: [Option<[u8; 16]>; 2],
    boot_entered: [bool; 2],
    publisher_entered: [bool; 2],
    publisher: [ServicePropertiesReadOriginalV2; 2],
    manager: Option<Weak<SystemdClient>>,
    genesis: Option<std::result::Result<DeploymentGenesisV1, DeploymentWireErrorV1>>,
    pin: Option<std::result::Result<VerifyingKey, ed25519_dalek::SignatureError>>,
    purpose: Option<std::result::Result<SignedBootPreparationPurposeDataV1, DeploymentWireErrorV1>>,
    completion:
        Option<std::result::Result<SignedBootPreparationCompletionDataV1, DeploymentWireErrorV1>>,
    profile: Option<std::result::Result<BootPreparationPublisherProfileDataV1, serde_json::Error>>,
    profile_contract: Option<std::result::Result<(), RuntimeDeploymentProfileDataErrorV1>>,
    normalized: Option<std::result::Result<Vec<u8>, RuntimeDeploymentProfileDataErrorV1>>,
    image: ProtectedPackagedExecutableHashOriginalV2,
    image_entered: bool,
    image_after:
        Option<std::result::Result<(), crate::phase0_probe::PackagedExecutableHashClosedV2>>,
    policies: [Option<std::result::Result<(), BootPreparationPolicyErrorV1>>; 20],
    first: Option<First>,
    before_entered: bool,
    after_entered: bool,
    before_positive: bool,
    after_positive: bool,
    absent: bool,
}

impl HostBootPreparationOriginalV1 {
    pub(in crate::plan) fn new() -> Self {
        Self {
            files: std::array::from_fn(|_| std::array::from_fn(|_| BootFileOriginalV1::new())),
            directories: BootDirectoriesOriginalV1::new(),
            boot: std::array::from_fn(|_| RootOriginalKernelBootIdAttemptV1::new()),
            boot_values: [None; 2],
            boot_entered: [false; 2],
            publisher_entered: [false; 2],
            publisher: std::array::from_fn(|_| ServicePropertiesReadOriginalV2::new()),
            manager: None,
            genesis: None,
            pin: None,
            purpose: None,
            completion: None,
            profile: None,
            profile_contract: None,
            normalized: None,
            image: ProtectedPackagedExecutableHashOriginalV2::new(),
            image_entered: false,
            image_after: None,
            policies: std::array::from_fn(|_| None),
            first: None,
            before_entered: false,
            after_entered: false,
            before_positive: false,
            after_positive: false,
            absent: false,
        }
    }

    /// Quotes all reached file/native/model destinations before construction.
    ///
    /// Root separately adds the exact86 publisher calls and their bounded raw
    /// and decoded message backing to the SAME initial manager schedule. Host's
    /// existing hardening archive supplies Requires/After for two extra calls.
    pub(in crate::plan) fn receiving_demand_v1(
        credentials: &Path,
        _nspawn: &str,
        _hostd: &Path,
        _policy: &str,
    ) -> Option<ResourceVector> {
        if credentials != Path::new(CREDENTIALS) {
            return None;
        }
        let own = std::mem::size_of::<Self>().checked_mul(2)?;
        let mut memory = own;
        let widths = [
            BOOT_PREPARATION_COMPLETION_BYTES_V1,
            468,
            32,
            BOOT_PREPARATION_PURPOSE_BYTES_V1,
            MAXIMUM_PROFILE_BYTES,
            MAXIMUM_PROFILE_BYTES,
            UNIT_BYTES,
        ];
        for maximum in widths {
            let (native, _) = FixedProtectedReadOriginalV3::receiving_obligations_v3(maximum)?;
            let extra = native
                .checked_sub(2 * std::mem::size_of::<FixedProtectedReadOriginalV3>())?
                .checked_add(2 * STORE_PATH_BYTES)?;
            memory = memory.checked_add(2 * extra)?;
        }
        let archive = ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(
            properties::SERVICE_V1.len(),
            properties::UNIT_V1.len(),
        )?
        .checked_sub(2 * std::mem::size_of::<ServicePropertiesReadOriginalV2>())?;
        memory = memory
            .checked_add(2 * archive)?
            .checked_add(publisher_profile_comparison_receiving_bytes_v1(
                MAXIMUM_PROFILE_BYTES,
                UNIT_BYTES,
                STORE_PATH_BYTES,
            )?)?
            .checked_add(2 * RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?)?
            .checked_add(PositionalHashOriginalV2::receiving_bytes_v2()?)?
            .checked_add(STORE_PATH_BYTES)?;
        // Fixed full-body verifier arrays/preimages coexist with the original
        // signed receipt, provisioned genesis/purpose and their retained models.
        memory = memory.checked_add(
            468 + BOOT_PREPARATION_PURPOSE_BYTES_V1 + 3 * BOOT_PREPARATION_COMPLETION_BYTES_V1,
        )?;
        let path_names = (STORE_PATH_BYTES - "/nix/store/".len())
            .div_ceil(2)
            .checked_add(Path::new("/nix/store").components().count())?;
        let names = DIRECTORIES_V1
            .len()
            .checked_add(4 + 1)?
            .checked_add(3 * path_names)?
            .checked_add(1)?;
        let read_bytes = widths
            .into_iter()
            .try_fold(0_usize, |sum, width| sum.checked_add(width))?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(2 * FILES + DIRECTORIES_V1.len() + 2 + 1).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?)
            .with(D::OutputBytes, u64::try_from(2 * read_bytes + 2 * FILES + 2 * RootOriginalKernelBootIdAttemptV1::maximum_requested_read_bytes_v2()).ok()?
                .checked_add(ProtectedPackagedExecutableHashOriginalV2::maximum_requested_read_bytes_v2())?))
    }

    /// Reports the source-owned exact same-manager publisher RPC roster.
    pub(in crate::plan) const fn publisher_calls_v1() -> usize {
        2 * properties::CALLS_PER_SAMPLE_V1
    }

    /// Captures the complete preparation conjunction before any watermark write.
    pub(in crate::plan) async fn observe_before_once_v1(
        &mut self,
        systemd: &Arc<SystemdClient>,
        credentials: &Path,
        actual_host: &ServicePropertiesReadOriginalV2,
        nspawn: &str,
        hostd: &Path,
        policy: &str,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        if self.before_entered {
            self.select(First::Order);
            return Err(BootPreparationClosedV1);
        }
        self.before_entered = true;
        self.manager = Some(Arc::downgrade(systemd));
        let result = self
            .observe_before_body(systemd, credentials, actual_host, nspawn, hostd, policy)
            .await;
        self.before_positive = result.is_ok() && self.first.is_none();
        result
    }

    async fn observe_before_body(
        &mut self,
        systemd: &Arc<SystemdClient>,
        credentials: &Path,
        actual_host: &ServicePropertiesReadOriginalV2,
        nspawn: &str,
        hostd: &Path,
        policy: &str,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        self.check(
            0,
            if credentials == Path::new(CREDENTIALS) {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "Host credential directory differs",
                ))
            },
        )?;
        let companion = Path::new(PUBLICATION).join(BOOT_PREPARATION_COMPLETION_FILE_V1);
        self.read_file_with_absence(
            0,
            COMPLETION,
            &companion,
            BOOT_PREPARATION_COMPLETION_BYTES_V1,
            true,
            true,
        )?;
        if self.files[0][COMPLETION].absent_v1() {
            // The actual open and its owed named post both observed ENOENT.
            // Their failed originals remain retained as expected absence DATA;
            // this branch can never bind a present readiness JSON.
            self.absent = true;
            return Ok(());
        }
        self.check(1, properties::require_host_dependencies_v1(actual_host))?;
        if self.directories.observe_once_v1().is_err() {
            self.select(First::Directories);
            return Err(BootPreparationClosedV1);
        }
        for (index, name, maximum) in [
            (GENESIS_SLOT, GENESIS, 468),
            (PIN_SLOT, PIN, 32),
            (PURPOSE_SLOT, PURPOSE, BOOT_PREPARATION_PURPOSE_BYTES_V1),
            (PROFILE_SLOT, PROFILE, MAXIMUM_PROFILE_BYTES),
        ] {
            self.read_file(0, index, &credentials.join(name), maximum, true)?;
        }
        self.check(
            18,
            if self.file_bytes(0, GENESIS_SLOT)?.len() == 468 {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1("signed genesis width differs"))
            },
        )?;
        self.check(
            19,
            if self.file_bytes(0, PIN_SLOT)?.len() == 32 {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "provisioner pin width differs",
                ))
            },
        )?;
        let genesis_bytes: &[u8; 468] = self
            .file_bytes(0, GENESIS_SLOT)?
            .try_into()
            .map_err(|_| BootPreparationClosedV1)?;
        self.genesis = Some(DeploymentGenesisV1::decode(&genesis_bytes[..404]));
        if !matches!(self.genesis, Some(Ok(_))) {
            self.select(First::Genesis);
            return Err(BootPreparationClosedV1);
        }
        let pin: &[u8; 32] = self
            .file_bytes(0, PIN_SLOT)?
            .try_into()
            .map_err(|_| BootPreparationClosedV1)?;
        self.pin = Some(VerifyingKey::from_bytes(pin));
        if !matches!(self.pin, Some(Ok(_))) {
            self.select(First::Pin);
            return Err(BootPreparationClosedV1);
        }
        self.purpose = Some(SignedBootPreparationPurposeDataV1::verify_v1(
            self.file_bytes(0, PURPOSE_SLOT)?,
            self.file_bytes(0, GENESIS_SLOT)?
                .try_into()
                .map_err(|_| BootPreparationClosedV1)?,
            self.genesis
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(BootPreparationClosedV1)?,
            self.pin
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(BootPreparationClosedV1)?,
        ));
        if !matches!(self.purpose, Some(Ok(_))) {
            self.select(First::Purpose);
            return Err(BootPreparationClosedV1);
        }
        self.completion = Some(SignedBootPreparationCompletionDataV1::verify_v1(
            self.file_bytes(0, COMPLETION)?,
            self.purpose_v1()?,
        ));
        if !matches!(self.completion, Some(Ok(_))) {
            self.select(First::Completion);
            return Err(BootPreparationClosedV1);
        }
        self.profile = Some(serde_json::from_slice(self.file_bytes(0, PROFILE_SLOT)?));
        if !matches!(self.profile, Some(Ok(_))) {
            self.select(First::Profile);
            return Err(BootPreparationClosedV1);
        }
        self.profile_contract = Some(require_boot_preparation_profile_data_v1(
            self.file_bytes(0, PROFILE_SLOT)?,
            self.profile_v1()?,
            self.purpose_v1()?,
        ));
        if !matches!(self.profile_contract, Some(Ok(()))) {
            self.select(First::ProfileContract);
            return Err(BootPreparationClosedV1);
        }
        self.check(
            2,
            if self.profile_v1()?.nspawn_executable == nspawn
                && Path::new(&self.profile_v1()?.hostd_executable) == hostd
                && self.profile_v1()?.selinux_policy == policy
            {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "publisher profile selects foreign Host/package/policy",
                ))
            },
        )?;
        self.observe_boot(0)?;
        self.observe_publisher(0, systemd).await?;
        self.check(3, self.require_current_publisher(0))?;
        let paths = properties::require_publisher_v1(&self.publisher[0], self.profile_v1()?);
        let (fragment, original_profile) = match paths {
            Ok((fragment, original_profile)) => {
                (PathBuf::from(fragment), PathBuf::from(original_profile))
            }
            Err(error) => {
                self.check(4, Err(error))?;
                return Err(BootPreparationClosedV1);
            }
        };
        self.read_file(
            0,
            ORIGINAL_PROFILE_SLOT,
            &original_profile,
            MAXIMUM_PROFILE_BYTES,
            false,
        )?;
        self.check(
            5,
            if self.file_bytes(0, ORIGINAL_PROFILE_SLOT)? == self.file_bytes(0, PROFILE_SLOT)? {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "loaded and protected publisher profiles differ",
                ))
            },
        )?;
        self.read_file(0, UNIT_SLOT, &fragment, UNIT_BYTES, false)?;
        self.normalized = Some(normalize_publisher_unit_data_v1(
            self.file_bytes(0, UNIT_SLOT)?,
            original_profile.to_str().ok_or(BootPreparationClosedV1)?,
        ));
        if !matches!(self.normalized, Some(Ok(_))) {
            self.select(First::Normalization);
            return Err(BootPreparationClosedV1);
        }
        let unit_digest: [u8; 32] = Sha256::digest(
            self.normalized
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or(BootPreparationClosedV1)?,
        )
        .into();
        self.check(
            6,
            if unit_digest == self.profile_v1()?.publisher.unit_sha256 {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "actual immutable publisher unit differs",
                ))
            },
        )?;
        let executable = PathBuf::from(&self.profile_v1()?.publisher.executable.path);
        self.image_entered = true;
        if self.image.observe_once_v2(&executable).is_err() {
            self.select(First::Image);
            return Err(BootPreparationClosedV1);
        }
        self.check(
            7,
            if self.image.digest_v2() == Some(self.profile_v1()?.publisher.executable.sha256) {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "actual publisher ELF differs from signed program contract",
                ))
            },
        )?;
        Ok(())
    }

    /// Compares only the loader's actual canonical JSON digest/generation/boot.
    ///
    /// Root calls this after its sole existing decoder/hash and before the
    /// actual watermark writer. Optional absence can never bind present JSON.
    pub(in crate::plan) fn require_readiness_binding_v1(
        &self,
        json_digest: [u8; 32],
        generation: u64,
        boot: [u8; 16],
    ) -> Result<()> {
        if !self.before_positive || self.absent || self.first.is_some() {
            return Err(HostError::Fence(
                "actual successful boot preparation is absent",
            ));
        }
        let record = self
            .completion_v1()
            .map_err(|_| HostError::Fence("boot target receipt absent"))?
            .record_v1()
            .fields_v1();
        if record.artifact_digest != json_digest
            || record.publisher_generation != generation
            || record.boot != boot
            || self.boot_values[0] != Some(boot)
        {
            return Err(HostError::Fence(
                "readiness JSON differs from the actual completed boot preparation",
            ));
        }
        Ok(())
    }

    /// Runs the separately prepaid final observers even after primary refusal.
    pub(in crate::plan) async fn observe_after_once_v1(
        &mut self,
        systemd: &Arc<SystemdClient>,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        if !self.before_entered || self.after_entered {
            self.select(First::Order);
            return Err(BootPreparationClosedV1);
        }
        self.after_entered = true;
        let same = self
            .manager
            .as_ref()
            .is_some_and(|before| Weak::ptr_eq(before, &Arc::downgrade(systemd)));
        let _binding = self.check(
            8,
            if same {
                Ok(())
            } else {
                Err(BootPreparationPolicyErrorV1(
                    "final publisher reader has a different original manager",
                ))
            },
        );
        // No healthy-entry test controls these independent owning afters.
        for index in 0..FILES {
            if !self.files[0][index].entered_v1() {
                continue;
            }
            let Some(path) = self.files[0][index].path_v1().map(Path::to_path_buf) else {
                continue;
            };
            let maximum = file_maximum(index);
            let private = index <= PROFILE_SLOT;
            let result = self.read_file_with_absence(
                1,
                index,
                &path,
                maximum,
                private,
                self.absent && index == COMPLETION,
            );
            if result.is_ok() && !self.files[0][index].absent_v1() {
                let equal = self.files[0][index]
                    .bytes_v1()
                    .zip(self.files[1][index].bytes_v1())
                    .is_some_and(|(a, b)| a == b);
                if !equal {
                    let _post = self.check(
                        9 + index,
                        Err(BootPreparationPolicyErrorV1(
                            "protected boot preparation changed",
                        )),
                    );
                }
            }
        }
        if self.absent {
            // The retained original ENOENT is expected only for the unchanged
            // optional absence route, never as an authority for present JSON.
            if !self.files[1][COMPLETION].absent_v1() {
                let _post = self.check(
                    17,
                    Err(BootPreparationPolicyErrorV1(
                        "optional boot preparation appeared or its final absence failed",
                    )),
                );
            }
        } else {
            if self.boot_entered[0] {
                let _boot = self.observe_boot(1);
            }
            if same && self.publisher_entered[0] {
                let _publisher = self.observe_publisher(1, systemd).await;
                let result = self.require_current_publisher(1);
                let _binding = self.check(16, result);
            }
        }
        if self.image_entered {
            self.image_after = Some(self.image.observe_after_owed_once_v2());
            if matches!(self.image_after, Some(Err(_))) {
                self.select(First::ImageAfter);
            }
        }
        if self.directories.entered_v1() && self.directories.observe_after_once_v1().is_err() {
            self.select(First::Directories);
        }
        self.after_positive = self.before_positive && self.first.is_none();
        if self.after_positive {
            Ok(())
        } else {
            Err(BootPreparationClosedV1)
        }
    }

    /// Releases only complete property proxy aliases before actual manager disposal.
    pub(in crate::plan) fn retire_completed_native_aliases_v1(&mut self) -> bool {
        if !self.after_positive {
            return false;
        }
        if self.absent {
            return true;
        }
        let before = self.publisher[0].retire_completed_native_aliases_v2();
        let after = self.publisher[1].retire_completed_native_aliases_v2();
        before && after
    }

    fn read_file(
        &mut self,
        phase: usize,
        index: usize,
        path: &Path,
        maximum: usize,
        private: bool,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        self.read_file_with_absence(phase, index, path, maximum, private, false)
    }

    fn read_file_with_absence(
        &mut self,
        phase: usize,
        index: usize,
        path: &Path,
        maximum: usize,
        private: bool,
        allow_absence: bool,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        let result = self.files[phase][index].observe_once_v1(path, maximum, private);
        if result.is_err() {
            if allow_absence && self.files[phase][index].absent_v1() {
                return Ok(());
            }
            self.select(First::File(phase, index));
        }
        result
    }

    fn file_bytes(
        &self,
        phase: usize,
        index: usize,
    ) -> std::result::Result<&[u8], BootPreparationClosedV1> {
        self.files[phase][index]
            .bytes_v1()
            .ok_or(BootPreparationClosedV1)
    }

    fn purpose_v1(
        &self,
    ) -> std::result::Result<&SignedBootPreparationPurposeDataV1, BootPreparationClosedV1> {
        self.purpose
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or(BootPreparationClosedV1)
    }

    fn completion_v1(
        &self,
    ) -> std::result::Result<&SignedBootPreparationCompletionDataV1, BootPreparationClosedV1> {
        self.completion
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or(BootPreparationClosedV1)
    }

    fn profile_v1(
        &self,
    ) -> std::result::Result<&BootPreparationPublisherProfileDataV1, BootPreparationClosedV1> {
        self.profile
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or(BootPreparationClosedV1)
    }

    fn observe_boot(&mut self, phase: usize) -> std::result::Result<(), BootPreparationClosedV1> {
        self.boot_entered[phase] = true;
        match self.boot[phase].observe_once() {
            Ok(boot) => {
                self.boot_values[phase] = Some(boot.into_bytes());
                Ok(())
            }
            Err(_) => {
                self.select(First::Boot(phase));
                Err(BootPreparationClosedV1)
            }
        }
    }

    async fn observe_publisher(
        &mut self,
        phase: usize,
        systemd: &Arc<SystemdClient>,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        self.publisher_entered[phase] = true;
        let result = self.publisher[phase]
            .observe_successful_oneshot_once_v1(
                systemd,
                PUBLISHER_UNIT_V1,
                properties::SERVICE_V1,
                properties::UNIT_V1,
            )
            .await;
        if result.is_err() {
            self.select(First::Publisher(phase));
            return Err(BootPreparationClosedV1);
        }
        Ok(())
    }

    fn require_current_publisher(
        &self,
        phase: usize,
    ) -> std::result::Result<(), BootPreparationPolicyErrorV1> {
        let receipt = self
            .completion_v1()
            .map_err(|_| BootPreparationPolicyErrorV1("completed target receipt absent"))?;
        let record = receipt.record_v1().fields_v1();
        if self.publisher[phase].completed_invocation_data_v1() != Some(record.publisher_invocation)
            || self.boot_values[phase] != Some(record.boot)
            || (phase == 1 && self.boot_values[1] != self.boot_values[0])
        {
            return Err(BootPreparationPolicyErrorV1(
                "current boot/invocation differs from completed issuer",
            ));
        }
        if phase == 1 {
            let profile = self
                .profile_v1()
                .map_err(|_| BootPreparationPolicyErrorV1("boot profile absent"))?;
            properties::require_publisher_v1(&self.publisher[1], profile)?;
            if self.publisher[0].service_values_v2() != self.publisher[1].service_values_v2()
                || self.publisher[0].unit_values_v2() != self.publisher[1].unit_values_v2()
            {
                return Err(BootPreparationPolicyErrorV1(
                    "publisher properties changed around ingestion",
                ));
            }
        }
        Ok(())
    }

    fn select(&mut self, cause: First) {
        self.first.get_or_insert(cause);
    }

    fn check(
        &mut self,
        index: usize,
        result: std::result::Result<(), BootPreparationPolicyErrorV1>,
    ) -> std::result::Result<(), BootPreparationClosedV1> {
        if self.policies[index].is_some() {
            self.select(First::Order);
            return Err(BootPreparationClosedV1);
        }
        let refused = result.is_err();
        self.policies[index] = Some(result);
        if refused {
            self.select(First::Policy(index));
            Err(BootPreparationClosedV1)
        } else {
            Ok(())
        }
    }

    /// Borrows the actual first native, signature, serde or comparison cause.
    pub(in crate::plan) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        fn error<T, E: StdError + 'static>(
            r: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn StdError + 'static)> {
            r.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn StdError)
        }
        match self.first? {
            First::File(p, i) => self.files[p][i].failure(),
            First::Directories => self.directories.failure(),
            First::Genesis => error(&self.genesis),
            First::Pin => error(&self.pin),
            First::Purpose => error(&self.purpose),
            First::Completion => error(&self.completion),
            First::Profile => error(&self.profile),
            First::ProfileContract => error(&self.profile_contract),
            First::Publisher(i) => self.publisher[i].failure().map(|e| e as &dyn StdError),
            First::Policy(i) => error(&self.policies[i]),
            First::Boot(i) => self.boot[i].failure(),
            First::Image | First::ImageAfter => self.image.failure_v2(),
            First::Normalization => error(&self.normalized),
            First::Order => Some(&BootPreparationClosedV1),
        }
    }
}

const fn file_maximum(index: usize) -> usize {
    match index {
        COMPLETION => BOOT_PREPARATION_COMPLETION_BYTES_V1,
        GENESIS_SLOT => 468,
        PIN_SLOT => 32,
        PURPOSE_SLOT => BOOT_PREPARATION_PURPOSE_BYTES_V1,
        PROFILE_SLOT | ORIGINAL_PROFILE_SLOT => MAXIMUM_PROFILE_BYTES,
        _ => UNIT_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_policy_refusal_preserves_the_selected_earlier_original() {
        let mut original = HostBootPreparationOriginalV1::new();
        assert!(
            original
                .check(1, Err(BootPreparationPolicyErrorV1("first")))
                .is_err()
        );
        let first = original.failure().unwrap() as *const dyn StdError;

        assert!(
            original
                .check(16, Err(BootPreparationPolicyErrorV1("later")))
                .is_err()
        );
        assert!(original.check(1, Ok(())).is_err());
        assert!(std::ptr::eq(
            first,
            original.failure().unwrap() as *const dyn StdError
        ));
        assert_eq!(
            original.failure().unwrap().to_string(),
            "Host boot preparation differs: first"
        );
    }

    #[test]
    fn empty_or_optional_absence_cannot_bind_present_readiness_json() {
        let mut original = HostBootPreparationOriginalV1::new();
        assert!(
            original
                .require_readiness_binding_v1([1; 32], 2, [2; 16])
                .is_err()
        );

        // Exercise the pure absent branch, never a native invocation issuer.
        original.before_positive = true;
        original.absent = true;
        assert!(
            original
                .require_readiness_binding_v1([1; 32], 2, [2; 16])
                .is_err()
        );
    }
}
