//! Retains the fixed Runtime deployment credential originals and native policy.
//!
//! This owner shares the sole native read and named-readback engines. It
//! supplies DATA custody only; purpose, payment, and issuer authority stay upper.

use super::*;

const RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY: &str =
    "/run/credentials/aos-sandbox-runtime-publisher.service";
pub(super) const RUNTIME_DEPLOYMENT_CREDENTIAL_NAMES: [&str; 5] = [
    "runtime-deployment-genesis-v1",
    "runtime-deployment-provisioner-pin-v1",
    "runtime-deployment-signing-seed-v1",
    "runtime-deployment-tpm-index-auth-v1",
    "runtime-deployment-canary-purpose-v2",
];
pub(super) const RUNTIME_DEPLOYMENT_CREDENTIAL_BYTES: [u64; 5] = [468, 32, 32, 32, 496];

pub(super) const BOOT_PREPARATION_CREDENTIAL_NAMES_V1: [&str; 5] = [
    "runtime-deployment-genesis-v1",
    "runtime-deployment-provisioner-pin-v1",
    "runtime-deployment-signing-seed-v1",
    "runtime-deployment-tpm-index-auth-v1",
    "runtime-deployment-boot-purpose-v1",
];
pub(super) const BOOT_PREPARATION_CREDENTIAL_BYTES_V1: [u64; 5] = [
    468, 32, 32, 32,
    aos_sandbox_protocol::runtime_deployment::boot_preparation::BOOT_PREPARATION_PURPOSE_BYTES_V1 as u64,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuntimeDeploymentCredentialRecipeV3 {
    Canary,
    BootPreparation,
}

impl RuntimeDeploymentCredentialRecipeV3 {
    const fn names(self) -> &'static [&'static str; 5] {
        match self {
            Self::Canary => &RUNTIME_DEPLOYMENT_CREDENTIAL_NAMES,
            Self::BootPreparation => &BOOT_PREPARATION_CREDENTIAL_NAMES_V1,
        }
    }

    const fn widths(self) -> &'static [u64; 5] {
        match self {
            Self::Canary => &RUNTIME_DEPLOYMENT_CREDENTIAL_BYTES,
            Self::BootPreparation => &BOOT_PREPARATION_CREDENTIAL_BYTES_V1,
        }
    }
}


/// Retains the five fixed selected publisher credentials and their readback.
///
/// This is only local protected custody. The genuine startup and separately
/// signed purpose must authenticate the mode and roles before these DATA loans
/// can be used. Capture, read errors and unwinds never release returned files.
pub struct RuntimeDeploymentCredentialCustodyV2 {
    recipe: RuntimeDeploymentCredentialRecipeV3,
    originals: [OriginalControllerCredential; 5],
    ancestors: CredentialAncestors,
    readback: CredentialReadback<5>,
    normal_posts: BootCredentialPostsV1,
    boot_owed: Option<BootCredentialOwedRecheckV1>,
    phase: ControllerCredentialPhase,
    failure: std::sync::Arc<Option<ControllerNixPublicCredentialErrorV1>>,
}

impl RuntimeDeploymentCredentialCustodyV2 {
    /// Prepares resident slots without opening files or selecting authority.
    pub fn new() -> Self {
        Self::new_with_recipe(RuntimeDeploymentCredentialRecipeV3::Canary)
    }

    /// Prepares the distinct fixed normal-purpose delivery without native IO.
    ///
    /// This passive custody constructor grants no Source, mode, genesis or
    /// publication authority. The real normal Source owner pays the complete
    /// shape before even this constructor's diagnostic Arc allocation.
    #[must_use]
    pub fn new_boot_preparation_v1() -> Self {
        Self::new_with_recipe(RuntimeDeploymentCredentialRecipeV3::BootPreparation)
    }

    /// Quotes the fixed normal custody before its allocation or native reads.
    ///
    /// The actual five-role engine keeps original/named files and four pinned
    /// ancestors per traversal. Three secret byte copies coexist; allocator
    /// growth, fixed SELinux/ACL scratch and path backing are included in Memory.
    /// The actual Self layout includes the resident normal native-result slots
    /// and the separate inert owed-frame carrier. Additional owed readback
    /// backing and descriptors use its separate same-Source demand below.
    /// The separate optional phase-0 public key is priced by its facts collector.
    #[must_use]
    pub fn boot_preparation_receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let mut memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<ControllerNixPublicCredentialErrorV1>())?
            .checked_add(2_usize.checked_mul(std::mem::size_of::<usize>())?)?
            .checked_add(4096 + 256)?;
        let mut input = 0_u64;
        for (name, width) in BOOT_PREPARATION_CREDENTIAL_NAMES_V1.iter()
            .zip(BOOT_PREPARATION_CREDENTIAL_BYTES_V1) {
            let bytes = usize::try_from(width).ok()?.checked_add(1)?;
            input = input.checked_add(width.checked_add(1)?.checked_mul(3)?)?;
            memory = memory.checked_add(bytes.checked_mul(12)?)?
                .checked_add(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY.len()
                    .checked_add(1)?.checked_add(name.len())?.checked_mul(3)?)?;
        }
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 2 * (4 + 5))
            // One shared four-component protected ancestry plus five leaves.
            .with(D::MetadataEntries, 4 + 5))
            .map(|demand| demand.with(D::OutputBytes, input))
    }

    fn new_with_recipe(recipe: RuntimeDeploymentCredentialRecipeV3) -> Self {
        Self {
            recipe,
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readback: CredentialReadback::new(),
            normal_posts: BootCredentialPostsV1::new(),
            boot_owed: None,
            phase: ControllerCredentialPhase::Fresh,
            failure: std::sync::Arc::new(None),
        }
    }

    /// Captures the exact fixed root-only delivery once, before secret access.
    ///
    /// # Errors
    /// Refuses repetition, foreign effective UID, unsafe mount/SID/ACL/metadata,
    /// nonexact roles and failed reads. The first typed cause remains resident.
    pub fn capture(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.failure.is_some() {
            return Err(self.failure.as_ref().as_ref().unwrap_or_else(|| std::process::abort()));
        }
        self.require_vacant_failure();
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        if self.recipe == RuntimeDeploymentCredentialRecipeV3::BootPreparation {
            let result = self.capture_delivery_originals();
            self.retain_first_failure(result);
            self.observe_normal_originals();
            return self.finish_normal_observation(false);
        }
        let result = self.capture_originals();
        self.finish(result)
    }

    /// Compares the same originals and fixed names without renewing admission.
    ///
    /// # Errors
    /// Permanently refuses interrupted/failed custody or any original change.
    pub fn recheck(&mut self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.failure.is_some() {
            return Err(self.failure.as_ref().as_ref().unwrap_or_else(|| std::process::abort()));
        }
        self.require_vacant_failure();
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        if self.recipe == RuntimeDeploymentCredentialRecipeV3::BootPreparation {
            self.normal_posts = BootCredentialPostsV1::new();
            self.observe_normal_originals();
            return self.finish_normal_observation(false);
        }
        let result = self.observe_originals();
        self.finish(result)
    }

    /// Quotes an additional parked normal observation before its construction.
    ///
    /// The real caller reserves this on the same genuine Source before prepare.
    /// It covers this observation's four named ancestors, five named leaves,
    /// both fixed readback byte planes including EOF, and retained native errors.
    /// It creates no Source, account, credential loan, or effect permission.
    #[must_use]
    pub fn boot_preparation_owed_recheck_receiving_demand_v1(
        &self,
    ) -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        if self.recipe != RuntimeDeploymentCredentialRecipeV3::BootPreparation {
            return None;
        }
        let mut memory = std::mem::size_of::<BootCredentialOwedRecheckV1>()
            .checked_mul(2)?.checked_add(4096 + 256)?;
        let mut input = 0_u64;
        for (name, width) in BOOT_PREPARATION_CREDENTIAL_NAMES_V1.iter()
            .zip(BOOT_PREPARATION_CREDENTIAL_BYTES_V1)
        {
            let bytes = usize::try_from(width).ok()?.checked_add(1)?;
            input = input.checked_add(width.checked_add(1)?.checked_mul(2)?)?;
            memory = memory.checked_add(bytes.checked_mul(8)?)?
                .checked_add(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY.len()
                    .checked_add(1)?.checked_add(name.len())?.checked_mul(2)?)?;
        }
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 4 + 5)
            .with(D::MetadataEntries, 4 + 5)
            .with(D::OutputBytes, input))
    }

    /// Parks a separate normal observation after the caller's Source reserve.
    ///
    /// This constructs only inert slots. Ordinary recheck uses its own slots
    /// while this owed observation stays resident. A completed successful
    /// observation can be replaced; a failed or interrupted one cannot.
    ///
    /// # Errors
    /// Refuses a foreign recipe, closed custody, or an unfinished observation.
    pub fn prepare_boot_owed_recheck_v1(
        &mut self,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.failure.is_some() {
            return self.normal_result();
        }
        self.require_vacant_failure();
        if self.recipe != RuntimeDeploymentCredentialRecipeV3::BootPreparation
            || self.phase != ControllerCredentialPhase::Ready
            || self.boot_owed.as_ref().is_some_and(|owed| !owed.complete)
        {
            return self.finish(Err(credential_state_rejected()));
        }
        self.boot_owed = Some(BootCredentialOwedRecheckV1::new());
        Ok(())
    }

    /// Runs the prepaid normal observation independently of current health.
    ///
    /// Every native group is marked entered before entry. A failure preserves
    /// the first cause and still runs other genuinely independent bookends.
    /// An unwind leaves its actual files, bytes, results, and progress resident.
    ///
    /// # Errors
    /// Returns the first resident failure or refuses absent/repeated entry.
    pub fn observe_boot_owed_recheck_once_v1(
        &mut self,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if !self.boot_owed.as_ref().is_some_and(|owed| !owed.started) {
            self.retain_first_failure(Err(credential_state_rejected()));
            return self.normal_result();
        }
        if let Some(owed) = self.boot_owed.as_mut() {
            owed.started = true;
            observe_boot_credentials_v1(
                &mut self.originals, &self.ancestors,
                &mut owed.readback, &mut owed.posts,
            );
            owed.complete = true;
        }
        self.finish_normal_observation(true)
    }

    /// Drains unentered prepaid normal groups after a caught unwind once.
    ///
    /// No pending or already completed observation is a no-op. An entered
    /// interrupted group is closed without replay; remaining independent
    /// bookends still run. This requires neither fresh Source nor healthy body.
    ///
    /// # Errors
    /// Returns the original primary failure or the earliest reached post error.
    pub fn drain_boot_owed_recheck_after_unwind_once_v1(
        &mut self,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if !self.boot_owed.as_ref().is_some_and(|owed| !owed.complete && !owed.drained) {
            return Ok(());
        }
        if let Some(owed) = self.boot_owed.as_mut() {
            owed.started = true;
            owed.drained = true;
            observe_boot_credentials_v1(
                &mut self.originals, &self.ancestors,
                &mut owed.readback, &mut owed.posts,
            );
            owed.complete = true;
        }
        self.finish_normal_observation(true)
    }

    fn observe_normal_originals(&mut self) {
        observe_boot_credentials_v1(
            &mut self.originals, &self.ancestors,
            &mut self.readback, &mut self.normal_posts,
        );
    }

    fn retain_first_failure(&mut self, result: CredentialResult<()>) {
        if let Err(error) = result {
            // Callers only extract a post error when this slot is vacant;
            // later post errors remain in their original fixed destinations.
            if self.failure.is_none() {
                let destination = std::sync::Arc::get_mut(&mut self.failure)
                    .unwrap_or_else(|| std::process::abort());
                *destination = Some(error);
            }
            self.phase = ControllerCredentialPhase::Closed;
        }
    }

    fn normal_result(&self) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        match self.failure.as_ref().as_ref() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn finish_normal_observation(
        &mut self,
        owed: bool,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.failure.is_none() {
            let result = if owed {
                self.boot_owed.as_mut().map_or_else(
                    || Err(credential_state_rejected()),
                    |original| original.posts.take_first_failure(),
                )
            } else {
                self.normal_posts.take_first_failure()
            };
            self.retain_first_failure(result);
        }
        if !owed && self.failure.is_none() {
            self.phase = ControllerCredentialPhase::Ready;
        }
        self.normal_result()
    }

    /// Borrows the five exact role bytes only during completed local custody.
    pub fn ready(&self) -> Option<[&[u8]; 5]> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
            self.originals[2].public.as_ref()?.bytes(),
            self.originals[3].public.as_ref()?.bytes(),
            self.originals[4].public.as_ref()?.bytes(),
        ])
    }

    /// Borrows the first cause without extracting descriptors or secret bytes.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.failure.as_ref().as_ref()
    }

    /// Shares only a completed, immutable typed diagnostic, never an empty slot.
    pub fn diagnostic(&self)
        -> std::sync::Arc<Option<ControllerNixPublicCredentialErrorV1>>
    {
        if self.failure.is_none() {
            std::process::abort();
        }
        std::sync::Arc::clone(&self.failure)
    }

    fn require_vacant_failure(&mut self) {
        if self.failure.is_some() || std::sync::Arc::get_mut(&mut self.failure).is_none() {
            std::process::abort();
        }
    }

    /// Compares an additional original signing leaf against the retained delivery.
    ///
    /// This is a unit DATA comparison, not a secret loan or signer. The extra
    /// File has its own OFD; only its protected identity and fixed named inode
    /// are compared to the genuine three-level ancestry and five-role capture.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn compare_signing_original(
        &mut self,
        directory: &File,
        signing_file: &File,
    ) -> Result<(), &ControllerNixPublicCredentialErrorV1> {
        if self.failure.is_some() {
            return Err(self.failure.as_ref().as_ref().unwrap_or_else(|| std::process::abort()));
        }
        self.require_vacant_failure();
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        let result = self.observe_originals().and_then(|()| {
            let retained = self.originals[2].public.as_ref()
                .ok_or_else(credential_state_rejected)?;
            require_runtime_deployment_credential(directory, true)?;
            require_runtime_deployment_credential(signing_file, false)?;
            recheck_credential_file(signing_file, retained.file_identity)?;
            let flags = rustix::fs::fcntl_getfl(signing_file).map_err(|error| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Stale, CredentialOperation::FileProvenance, error,
                )
            })?;
            let stat = rustix::fs::fstat(directory).map_err(|error| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Stale, CredentialOperation::DirectoryMetadata, error,
                )
            })?;
            if flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
                || flags.contains(rustix::fs::OFlags::PATH)
                || (stat.st_dev, stat.st_ino) != retained.directory_identity
            {
                return Err(credential_state_rejected());
            }
            let named = rustix::fs::statat(
                directory, RUNTIME_DEPLOYMENT_CREDENTIAL_NAMES[2],
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ).map_err(|error| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Stale, CredentialOperation::FileMetadata, error,
                )
            })?;
            let actual = signing_file.metadata().map_err(|error| {
                ControllerNixPublicCredentialErrorV1::io(
                    CredentialFailureClass::Stale, CredentialOperation::FileMetadata, error,
                )
            })?;
            if named.st_dev != actual.dev() || named.st_ino != actual.ino()
                || named.st_size != 32 || named.st_uid != 0 || named.st_gid != 0
                || named.st_mode & 0o7777 != 0o400
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::RegularFile
            {
                return Err(credential_state_rejected());
            }
            Ok(())
        });
        self.finish(result)
    }

    /// Permanently closes loans while leaving actual originals resident.
    pub fn fence(&mut self) {
        self.phase = ControllerCredentialPhase::Closed;
    }

    fn finish(&mut self, result: CredentialResult<()>)
        -> Result<(), &ControllerNixPublicCredentialErrorV1>
    {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(error) => {
                self.phase = ControllerCredentialPhase::Closed;
                if self.failure.is_none() {
                    let slot = std::sync::Arc::get_mut(&mut self.failure)
                        .unwrap_or_else(|| std::process::abort());
                    *slot = Some(error);
                }
                Err(self.failure.as_ref().as_ref().unwrap_or_else(|| std::process::abort()))
            }
        }
    }

    fn capture_originals(&mut self) -> CredentialResult<()> {
        self.capture_delivery_originals()?;
        self.observe_originals()
    }

    fn capture_delivery_originals(&mut self) -> CredentialResult<()> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(credential_state_rejected());
        }
        open_directory_with_custody(
            Path::new(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY),
            0,
            &mut DirectoryCustody::Resident(&mut self.ancestors),
        )?;
        let directory = self.ancestors.directory()?;
        require_runtime_deployment_credential(directory, true)?;
        let directory_identity = self.ancestors.slots[3].identity
            .ok_or_else(credential_state_rejected)?;

        let names = self.recipe.names();
        let widths = self.recipe.widths();
        for (index, name) in names.iter().enumerate() {
            let original = &mut self.originals[index];
            let file_identity = require_present_credential(open_read_credential_with_profile(
                directory, name, 0,
                CredentialReadProfile::RuntimeDeployment(widths[index]),
                &mut original.read,
            )?)?;
            if original.read.bytes.as_ref().map(|bytes| bytes.len() as u64)
                != Some(widths[index])
            {
                return Err(credential_state_rejected());
            }

            // Construct metadata while bytes and the returned original File
            // remain parked. Only infallible moves follow the checked take.
            let path = PathBuf::from(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY);
            let bytes = original.read.bytes.take().ok_or_else(credential_state_rejected)?;
            original.public = Some(PinnedSystemdCredential {
                name: *name, path, uid: 0, directory_identity, file_identity, bytes,
                exact_bytes: Some(widths[index]),
            });
        }
        Ok(())
    }

    fn observe_originals(&mut self) -> CredentialResult<()> {
        if self.recipe == RuntimeDeploymentCredentialRecipeV3::BootPreparation {
            self.normal_posts = BootCredentialPostsV1::new();
            self.observe_normal_originals();
            return self.normal_posts.take_first_failure();
        }
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(credential_state_rejected());
        }
        recheck_credential_ancestors(&self.ancestors, 0)?;
        require_runtime_deployment_credential(self.ancestors.directory()?, true)?;
        open_directory_with_custody(
            Path::new(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY), 0,
            &mut DirectoryCustody::Resident(&mut self.readback.ancestors),
        )?;
        for (original, named) in self.ancestors.slots.iter().zip(&self.readback.ancestors.slots) {
            if original.identity != named.identity {
                return Err(credential_state_rejected());
            }
        }
        let directory = self.readback.ancestors.directory()?;
        require_runtime_deployment_credential(directory, true)?;
        let names = self.recipe.names();
        let widths = self.recipe.widths();
        for (index, name) in names.iter().enumerate() {
            observe_credential_readback(
                &mut self.originals[index], &mut self.readback.original_bytes[index],
                &mut self.readback.named[index], directory, name, 0,
                CredentialReadProfile::RuntimeDeployment(widths[index]),
            )?;
        }
        for (original, named) in self.originals.iter().zip(&self.readback.named) {
            let public = original.public.as_ref().ok_or_else(credential_state_rejected)?;
            for file in [original.read.file.as_ref(), named.file.as_ref()] {
                let file = file.ok_or_else(credential_state_rejected)?;
                recheck_credential_file(file, public.file_identity)?;
                require_runtime_deployment_credential(file, false)?;
            }
        }
        recheck_credential_ancestors(&self.ancestors, 0)?;
        recheck_credential_ancestors(&self.readback.ancestors, 0)?;
        require_runtime_deployment_credential(self.ancestors.directory()?, true)?;
        require_runtime_deployment_credential(self.readback.ancestors.directory()?, true)?;
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(credential_state_rejected());
        }
        Ok(())
    }
}

// This is the existing normal observation's concrete native order. The held
// descriptor bookends remain owed when a dependent name/read step refuses.
#[derive(Clone, Copy)]
enum BootCredentialActionV1 {
    Uid,
    HeldAncestor(usize),
    HeldDirectoryPolicy,
    NamedWalk,
    NamedAncestry,
    NamedDirectoryPolicy,
    Readback(usize),
    HeldMetadata(usize),
    HeldPolicy(usize),
    NamedMetadata(usize),
    NamedPolicy(usize),
    NamedAncestor(usize),
}

const BOOT_CREDENTIAL_ACTIONS_V1: [BootCredentialActionV1; 45] = {
    use BootCredentialActionV1::*;
    [
        Uid,
        HeldAncestor(0), HeldAncestor(1), HeldAncestor(2), HeldAncestor(3),
        HeldDirectoryPolicy,
        NamedWalk, NamedAncestry, NamedDirectoryPolicy,
        Readback(0), Readback(1), Readback(2), Readback(3), Readback(4),
        HeldMetadata(0), HeldPolicy(0), NamedMetadata(0), NamedPolicy(0),
        HeldMetadata(1), HeldPolicy(1), NamedMetadata(1), NamedPolicy(1),
        HeldMetadata(2), HeldPolicy(2), NamedMetadata(2), NamedPolicy(2),
        HeldMetadata(3), HeldPolicy(3), NamedMetadata(3), NamedPolicy(3),
        HeldMetadata(4), HeldPolicy(4), NamedMetadata(4), NamedPolicy(4),
        HeldAncestor(0), HeldAncestor(1), HeldAncestor(2), HeldAncestor(3),
        NamedAncestor(0), NamedAncestor(1), NamedAncestor(2), NamedAncestor(3),
        HeldDirectoryPolicy, NamedDirectoryPolicy,
        Uid,
    ]
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BootCredentialPostStateV1 {
    Unentered,
    Entered,
    Complete,
    Skipped,
}

struct BootCredentialPostV1 {
    state: BootCredentialPostStateV1,
    result: Option<CredentialResult<()>>,
}

struct BootCredentialPostsV1 {
    slots: [BootCredentialPostV1; BOOT_CREDENTIAL_ACTIONS_V1.len()],
}

impl BootCredentialPostsV1 {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| BootCredentialPostV1 {
                state: BootCredentialPostStateV1::Unentered,
                result: None,
            }),
        }
    }

    fn succeeded(&self, range: std::ops::Range<usize>) -> bool {
        self.slots[range].iter().all(|slot| matches!(slot.result, Some(Ok(()))))
    }

    fn take_first_failure(&mut self) -> CredentialResult<()> {
        for slot in &mut self.slots {
            if matches!(slot.result, Some(Err(_))) {
                if let Some(result) = slot.result.take() {
                    return result;
                }
            }
        }
        Ok(())
    }
}

struct BootCredentialOwedRecheckV1 {
    readback: CredentialReadback<5>,
    posts: BootCredentialPostsV1,
    started: bool,
    drained: bool,
    complete: bool,
}

impl BootCredentialOwedRecheckV1 {
    fn new() -> Self {
        Self {
            readback: CredentialReadback::new(),
            posts: BootCredentialPostsV1::new(),
            started: false,
            drained: false,
            complete: false,
        }
    }
}

fn observe_boot_credentials_v1(
    originals: &mut [OriginalControllerCredential; 5],
    ancestors: &CredentialAncestors,
    readback: &mut CredentialReadback<5>,
    posts: &mut BootCredentialPostsV1,
) {
    use BootCredentialActionV1 as Action;
    use BootCredentialPostStateV1 as State;

    for (index, action) in BOOT_CREDENTIAL_ACTIONS_V1.iter().copied().enumerate() {
        match posts.slots[index].state {
            State::Complete | State::Skipped => continue,
            State::Entered => {
                // The native original was entered before an unwind. Its
                // retained prefix stays parked; never replay that original.
                posts.slots[index].result = Some(Err(credential_state_rejected()));
                posts.slots[index].state = State::Complete;
                continue;
            }
            State::Unentered => {}
        }

        let eligible = match action {
            Action::NamedWalk => posts.succeeded(0..6)
                && originals.iter().all(|original| original.public.is_some()),
            Action::NamedAncestry => posts.succeeded(6..7),
            Action::Readback(_) => posts.succeeded(0..9),
            Action::HeldDirectoryPolicy => ancestors.count == ancestors.slots.len(),
            Action::NamedDirectoryPolicy => readback.ancestors.count == readback.ancestors.slots.len(),
            Action::HeldMetadata(role) => originals[role].public.is_some()
                && originals[role].read.file.is_some(),
            Action::HeldPolicy(role) => originals[role].read.file.is_some(),
            Action::NamedMetadata(role) => originals[role].public.is_some()
                && readback.named[role].file.is_some(),
            Action::NamedPolicy(role) => readback.named[role].file.is_some(),
            Action::HeldAncestor(slot) if index >= 14 => ancestors.slots[slot].descriptor.is_some(),
            Action::NamedAncestor(slot) => readback.ancestors.slots[slot].descriptor.is_some(),
            _ => true,
        };
        if !eligible {
            posts.slots[index].state = State::Skipped;
            continue;
        }

        posts.slots[index].state = State::Entered;
        let result = (|| {
            match action {
                Action::Uid => {
                    if rustix::process::geteuid().as_raw() != 0 {
                        return Err(credential_state_rejected());
                    }
                    Ok(())
                }
                Action::HeldAncestor(slot) | Action::NamedAncestor(slot) => {
                    let held = if matches!(action, Action::HeldAncestor(_)) {
                        ancestors
                    } else {
                        &readback.ancestors
                    };
                    // Normal credentials have fixed uid zero: the ordinary
                    // service-owned ancestry predicate is root at every slot.
                    recheck_credential_ancestor_slot(held, slot, 0, &mut false)
                }
                Action::HeldDirectoryPolicy => {
                    require_runtime_deployment_credential(ancestors.directory()?, true)
                }
                Action::NamedDirectoryPolicy => {
                    require_runtime_deployment_credential(readback.ancestors.directory()?, true)
                }
                Action::NamedWalk => open_directory_with_custody(
                    Path::new(RUNTIME_DEPLOYMENT_CREDENTIAL_DIRECTORY), 0,
                    &mut DirectoryCustody::Resident(&mut readback.ancestors),
                ),
                Action::NamedAncestry => {
                    if ancestors.slots.iter().zip(&readback.ancestors.slots)
                        .any(|(original, named)| original.identity != named.identity)
                    {
                        return Err(credential_state_rejected());
                    }
                    Ok(())
                }
                Action::Readback(role) => observe_credential_readback(
                    &mut originals[role], &mut readback.original_bytes[role],
                    &mut readback.named[role], readback.ancestors.directory()?,
                    BOOT_PREPARATION_CREDENTIAL_NAMES_V1[role], 0,
                    CredentialReadProfile::RuntimeDeployment(BOOT_PREPARATION_CREDENTIAL_BYTES_V1[role]),
                ),
                Action::HeldMetadata(role) | Action::NamedMetadata(role) => {
                    let original = &originals[role];
                    let public = original.public.as_ref().ok_or_else(credential_state_rejected)?;
                    let file = if matches!(action, Action::HeldMetadata(_)) {
                        original.read.file.as_ref()
                    } else {
                        readback.named[role].file.as_ref()
                    }.ok_or_else(credential_state_rejected)?;
                    recheck_credential_file(file, public.file_identity)
                }
                Action::HeldPolicy(role) | Action::NamedPolicy(role) => {
                    let file = if matches!(action, Action::HeldPolicy(_)) {
                        originals[role].read.file.as_ref()
                    } else {
                        readback.named[role].file.as_ref()
                    }.ok_or_else(credential_state_rejected)?;
                    require_runtime_deployment_credential(file, false)
                }
            }
        })();
        posts.slots[index].result = Some(result);
        posts.slots[index].state = State::Complete;
    }
}

pub(super) fn require_runtime_deployment_credential(file: &impl AsFd, directory: bool)
    -> CredentialResult<()>
{
    let operation = CredentialOperation::FileProvenance;
    let native = |error| ControllerNixPublicCredentialErrorV1::io(
        CredentialFailureClass::Configuration, operation, error,
    );
    let stat = rustix::fs::fstat(file).map_err(native)?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if stat.st_uid != 0 || stat.st_gid != 0
        || stat.st_mode & 0o7777 != if directory { 0o500 } else { 0o400 }
        || kind != if directory { rustix::fs::FileType::Directory } else { rustix::fs::FileType::RegularFile }
        || (!directory && stat.st_nlink != 1)
        || !rustix::fs::fstatvfs(file).map_err(native)?.f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        return Err(credential_state_rejected());
    }
    let mut context = [0; 256];
    let length = rustix::fs::fgetxattr(file, "security.selinux", &mut context[..]).map_err(native)?;
    let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
    if actual != b"system_u:object_r:aos_runtime_deployment_credential_t" {
        return Err(credential_state_rejected());
    }
    let mut acl = [0; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(file, name, &mut acl[..]) {
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(native(error)),
            Ok(_) => return Err(credential_state_rejected()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_post_archive_moves_first_cause_and_retains_later_native_errors() {
        let mut owner = RuntimeDeploymentCredentialCustodyV2::new_boot_preparation_v1();
        owner.normal_posts.slots[9].result = Some(Err(
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Stale,
                CredentialOperation::FileRead,
                rustix::io::Errno::IO,
            ),
        ));
        owner.normal_posts.slots[14].result = Some(Err(
            ControllerNixPublicCredentialErrorV1::io(
                CredentialFailureClass::Stale,
                CredentialOperation::FileMetadata,
                rustix::io::Errno::BADF,
            ),
        ));
        let later = std::ptr::from_ref(
            owner.normal_posts.slots[14].result.as_ref().unwrap().as_ref().unwrap_err(),
        );

        assert!(owner.finish_normal_observation(false).is_err());
        assert!(matches!(owner.failure().unwrap().operation, CredentialOperation::FileRead));
        assert!(matches!(owner.failure().unwrap().io,
            Some(CredentialIoCause::Syscall(rustix::io::Errno::IO))));
        let primary = std::ptr::from_ref(owner.failure().unwrap());

        assert!(owner.finish_normal_observation(false).is_err());
        assert_eq!(primary, std::ptr::from_ref(owner.failure().unwrap()));
        assert_eq!(later, std::ptr::from_ref(
            owner.normal_posts.slots[14].result.as_ref().unwrap().as_ref().unwrap_err(),
        ));
        assert!(owner.ready().is_none());
    }

    #[test]
    fn parked_owed_archive_is_separate_and_empty_drain_has_no_native_entry() {
        let mut owner = RuntimeDeploymentCredentialCustodyV2::new_boot_preparation_v1();
        assert!(owner.drain_boot_owed_recheck_after_unwind_once_v1().is_ok());
        assert!(owner.boot_owed.is_none());

        // This checks only inert storage plumbing; no fixture claims native
        // credential readiness or bypasses production capture.
        owner.phase = ControllerCredentialPhase::Ready;
        assert!(owner.prepare_boot_owed_recheck_v1().is_ok());
        assert!(owner.boot_owed.as_ref().unwrap().posts.slots.iter()
            .all(|slot| slot.state == BootCredentialPostStateV1::Unentered));
        owner.readback = CredentialReadback::new();
        owner.normal_posts = BootCredentialPostsV1::new();
        assert!(!owner.boot_owed.as_ref().unwrap().started);
        assert!(!owner.boot_owed.as_ref().unwrap().complete);
        assert!(owner.boot_preparation_owed_recheck_receiving_demand_v1().is_some());
    }
}
