//! Installed runtime identity and path-free guest deployment capture.

use super::*;

/// Installed Crucible-suite runtime identity required by a portable replay.
///
/// The capture embeds guest and lifecycle data, but it deliberately does not
/// distribute QEMU or the plugin. A consumer authenticates its installed pair
/// against these marker-derived values before launching either executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingProductionReplayRuntimeIdentity {
    pub(super) qemu_build_id: String,
    pub(super) qemu_patch_series_hash: String,
    pub(super) plugin_abi: String,
    pub(super) shmem_abi_version: String,
}

impl FindingProductionReplayRuntimeIdentity {
    /// Builds an explicit marker-derived installed runtime requirement.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRuntimeIdentity`]
    /// when a field is empty or exceeds its fixed string bound.
    pub fn new(
        qemu_build_id: impl Into<String>,
        qemu_patch_series_hash: impl Into<String>,
        plugin_abi: impl Into<String>,
        shmem_abi_version: impl Into<String>,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let value = Self {
            qemu_build_id: qemu_build_id.into(),
            qemu_patch_series_hash: qemu_patch_series_hash.into(),
            plugin_abi: plugin_abi.into(),
            shmem_abi_version: shmem_abi_version.into(),
        };
        validate_runtime_identity(&value)?;
        Ok(value)
    }

    /// Copies the authenticated identity of an installed QEMU/plugin pair.
    #[must_use]
    pub fn from_authenticated(identity: &crucible_qemu::QemuLaunchArtifactIdentity) -> Self {
        Self {
            qemu_build_id: identity.qemu_build_id().to_owned(),
            qemu_patch_series_hash: identity.qemu_patch_series_hash().to_owned(),
            plugin_abi: identity.plugin_abi().to_owned(),
            shmem_abi_version: identity.shmem_abi_version().to_owned(),
        }
    }

    /// Returns the normalized QEMU build identity.
    #[must_use]
    pub fn qemu_build_id(&self) -> &str {
        &self.qemu_build_id
    }

    /// Returns the QEMU patch-series identity.
    #[must_use]
    pub fn qemu_patch_series_hash(&self) -> &str {
        &self.qemu_patch_series_hash
    }

    /// Returns the matched plugin ABI label.
    #[must_use]
    pub fn plugin_abi(&self) -> &str {
        &self.plugin_abi
    }

    /// Returns the matched shared-memory ABI version.
    #[must_use]
    pub fn shmem_abi_version(&self) -> &str {
        &self.shmem_abi_version
    }

    /// Verifies an installed QEMU/plugin pair against this capture.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::RuntimeIdentity`] when
    /// marker authentication fails or the installed identity differs.
    pub fn verify_installed(
        &self,
        qemu: impl Into<std::path::PathBuf>,
        plugin: impl Into<std::path::PathBuf>,
    ) -> Result<crucible_qemu::QemuLaunchArtifactIdentity, FindingProductionReplayCaptureError>
    {
        let actual = crucible_qemu::QemuLaunchArtifactIdentity::authenticate(qemu, plugin)
            .map_err(FindingProductionReplayCaptureError::RuntimeAuthentication)?;
        if Self::from_authenticated(&actual) != *self {
            return Err(FindingProductionReplayCaptureError::RuntimeIdentity);
        }
        Ok(actual)
    }
}

/// On-disk format of the captured immutable guest root image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingProductionReplayRootImageFormat {
    /// The captured root is a QCOW2 image.
    Qcow2,
    /// The captured root is a raw disk or filesystem image.
    Raw,
}

impl From<crucible_api::ProductionRootImageFormat> for FindingProductionReplayRootImageFormat {
    fn from(value: crucible_api::ProductionRootImageFormat) -> Self {
        match value {
            crucible_api::ProductionRootImageFormat::Qcow2 => Self::Qcow2,
            crucible_api::ProductionRootImageFormat::Raw => Self::Raw,
        }
    }
}

/// One authenticated immutable guest file embedded in the capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayAsset {
    pub(super) identity: ContentHash,
    pub(super) bytes: Arc<[u8]>,
}

impl FindingProductionReplayAsset {
    /// Owns bytes and derives their BLAKE3 content identity.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            identity: ContentHash::from_bytes(&bytes),
            bytes: bytes.into(),
        }
    }

    /// Returns the authenticated content identity.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the immutable file bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Portable guest assets selected for one VM architecture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayGuestAssets {
    pub(super) architecture: VmArchitecture,
    pub(super) kernel: FindingProductionReplayAsset,
    pub(super) root_image: FindingProductionReplayAsset,
    pub(super) kernel_cmdline_prefix: Option<String>,
}

impl FindingProductionReplayGuestAssets {
    /// Builds the complete guest inputs for one architecture.
    #[must_use]
    pub fn new(
        architecture: VmArchitecture,
        kernel: FindingProductionReplayAsset,
        root_image: FindingProductionReplayAsset,
        kernel_cmdline_prefix: Option<String>,
    ) -> Self {
        Self {
            architecture,
            kernel,
            root_image,
            kernel_cmdline_prefix,
        }
    }

    /// Returns the guest architecture.
    #[must_use]
    pub const fn architecture(&self) -> VmArchitecture {
        self.architecture
    }

    /// Returns the captured guest kernel.
    #[must_use]
    pub const fn kernel(&self) -> &FindingProductionReplayAsset {
        &self.kernel
    }

    /// Returns the captured immutable root image.
    #[must_use]
    pub const fn root_image(&self) -> &FindingProductionReplayAsset {
        &self.root_image
    }

    /// Returns the package-supplied command-line prefix for this architecture.
    #[must_use]
    pub fn kernel_cmdline_prefix(&self) -> Option<&str> {
        self.kernel_cmdline_prefix.as_deref()
    }
}

/// Path-free deployment inputs needed to launch a fresh replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayDeployment {
    pub(super) runtime: FindingProductionReplayRuntimeIdentity,
    pub(super) root_image_format: FindingProductionReplayRootImageFormat,
    pub(super) guest_assets: Vec<FindingProductionReplayGuestAssets>,
    pub(super) initrd: Option<FindingProductionReplayAsset>,
}

impl FindingProductionReplayDeployment {
    /// Builds an installed-runtime prerequisite and embedded guest asset set.
    #[must_use]
    pub fn new(
        runtime: FindingProductionReplayRuntimeIdentity,
        root_image_format: FindingProductionReplayRootImageFormat,
        guest_assets: Vec<FindingProductionReplayGuestAssets>,
        initrd: Option<FindingProductionReplayAsset>,
    ) -> Self {
        Self {
            runtime,
            root_image_format,
            guest_assets,
            initrd,
        }
    }

    /// Returns the required installed Crucible-suite runtime identity.
    #[must_use]
    pub const fn runtime(&self) -> &FindingProductionReplayRuntimeIdentity {
        &self.runtime
    }

    /// Returns the captured root-image format.
    #[must_use]
    pub const fn root_image_format(&self) -> FindingProductionReplayRootImageFormat {
        self.root_image_format
    }

    /// Returns the exact guest asset set for each scenario architecture.
    #[must_use]
    pub fn guest_assets(&self) -> &[FindingProductionReplayGuestAssets] {
        &self.guest_assets
    }

    /// Returns the shared captured initrd, when configured.
    #[must_use]
    pub const fn initrd(&self) -> Option<&FindingProductionReplayAsset> {
        self.initrd.as_ref()
    }
}

/// Captures one reusable static context directly from a lifecycle config.
///
/// The runtime markers, scenario-selected guest files, and configured signal
/// and World stores are resolved at one producer boundary. `static_byte_limit`
/// is an optional publication budget applied across unique guest paths and
/// lifecycle objects before the context is returned. Standalone callers can
/// pass [`u64::MAX`] and retain the independent limits in `limits`.
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when runtime
/// authentication, lifecycle projection, file capture, store traversal, or
/// bounded validation fails.
pub fn capture_finding_replay_shared_context(
    finding: &FindingReproductionArtifact,
    config: &crucible_api::ProductionVmLifecycleConfig,
    static_byte_limit: u64,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<
    FindingProductionReplayCaptureOutcome<Arc<FindingProductionReplaySharedContext>>,
    FindingProductionReplayCaptureError,
> {
    let installed = crucible_qemu::QemuLaunchArtifactIdentity::authenticate(
        config.executable(),
        config.plugin(),
    )
    .map_err(FindingProductionReplayCaptureError::RuntimeAuthentication)?;
    let runtime = FindingProductionReplayRuntimeIdentity::from_authenticated(&installed);
    let paths = config
        .portable_replay_asset_paths(finding.artifact.scenario_form())
        .map_err(FindingProductionReplayCaptureError::Lifecycle)?;
    let captured = match capture_finding_replay_deployment_with_static_limit(
        finding.artifact.scenario_form(),
        &paths,
        runtime,
        limits,
        static_byte_limit,
    ) {
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-static-bytes",
        }) => {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::PublicationLimitExceeded,
            ));
        }
        Err(error) => return Err(error),
        Ok(captured) => captured,
    };
    let lifecycle_result = capture_finding_replay_lifecycle_objects_with_budget(
        finding,
        config.signal_artifacts(),
        config.world_artifacts(),
        limits,
        &captured.unique_identities,
        captured.unique_bytes,
        static_byte_limit,
    );
    let lifecycle_objects = match lifecycle_result {
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-static-bytes",
        }) => {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::PublicationLimitExceeded,
            ));
        }
        Err(error) => return Err(error),
        Ok(FindingProductionReplayCaptureOutcome::Complete(objects)) => objects,
        Ok(FindingProductionReplayCaptureOutcome::Incomplete(reason)) => {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(reason));
        }
    };
    if unique_static_bytes(&captured.deployment, &lifecycle_objects)? > static_byte_limit {
        return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::PublicationLimitExceeded,
        ));
    }

    let recipe = FindingProductionReplayRecipe::from_lifecycle_config(config)?;
    let context = FindingProductionReplaySharedContext::new(
        finding,
        recipe,
        captured.deployment,
        lifecycle_objects,
        limits,
    )?;
    Ok(FindingProductionReplayCaptureOutcome::Complete(Arc::new(
        context,
    )))
}

fn unique_static_bytes(
    deployment: &FindingProductionReplayDeployment,
    lifecycle_objects: &BTreeMap<ContentHash, Vec<u8>>,
) -> Result<u64, FindingProductionReplayCaptureError> {
    let mut identities = BTreeSet::new();
    let mut total = 0_u64;
    for asset in deployment
        .guest_assets
        .iter()
        .flat_map(|assets| [&assets.kernel, &assets.root_image])
        .chain(deployment.initrd.iter())
    {
        if identities.insert(asset.identity) {
            total = charge_bytes(
                total,
                asset.bytes.len(),
                u64::MAX,
                "finding-production-replay-static-bytes",
            )?;
        }
    }
    for (identity, bytes) in lifecycle_objects {
        if identities.insert(*identity) {
            total = charge_bytes(
                total,
                bytes.len(),
                u64::MAX,
                "finding-production-replay-static-bytes",
            )?;
        }
    }
    Ok(total)
}

/// Copies the exact selected guest files into a path-free deployment capture.
///
/// The caller supplies a marker-authenticated installed runtime identity. QEMU
/// and the plugin remain an installed Crucible-suite prerequisite; guest
/// kernel, root-image, and initrd bytes are embedded in the returned value.
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when a selected file is
/// unavailable, changes while being read, exceeds `limits`, or disagrees with
/// the scenario's declared content references.
pub fn capture_finding_replay_deployment(
    scenario: &crucible::ScenarioDefForm,
    paths: &crucible_api::ProductionVmPortableReplayAssetPaths,
    runtime: FindingProductionReplayRuntimeIdentity,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<FindingProductionReplayDeployment, FindingProductionReplayCaptureError> {
    capture_finding_replay_deployment_with_static_limit(scenario, paths, runtime, limits, u64::MAX)
        .map(|captured| captured.deployment)
}

pub(super) struct CapturedDeployment {
    pub(super) deployment: FindingProductionReplayDeployment,
    pub(super) unique_identities: BTreeSet<ContentHash>,
    pub(super) unique_bytes: u64,
}

pub(super) fn capture_finding_replay_deployment_with_static_limit(
    scenario: &crucible::ScenarioDefForm,
    paths: &crucible_api::ProductionVmPortableReplayAssetPaths,
    runtime: FindingProductionReplayRuntimeIdentity,
    limits: FindingProductionReplayCaptureLimits,
    static_byte_limit: u64,
) -> Result<CapturedDeployment, FindingProductionReplayCaptureError> {
    let mut unique_bytes = 0_u64;
    let mut captured_paths = BTreeMap::new();
    let mut captured_content = BTreeMap::new();
    let mut guest_assets = Vec::new();
    guest_assets
        .try_reserve_exact(paths.guest_assets().len())
        .map_err(|_| FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-count",
        })?;

    for selected in paths.guest_assets() {
        let (kernel, next_total) = read_or_clone_guest_asset(
            selected.kernel(),
            &mut captured_paths,
            &mut captured_content,
            unique_bytes,
            limits.max_guest_asset_bytes,
            static_byte_limit,
        )?;
        let (root_image, next_total) = read_or_clone_guest_asset(
            selected.root_image(),
            &mut captured_paths,
            &mut captured_content,
            next_total,
            limits.max_guest_asset_bytes,
            static_byte_limit,
        )?;
        unique_bytes = next_total;
        guest_assets.push(FindingProductionReplayGuestAssets::new(
            selected.architecture(),
            kernel,
            root_image,
            selected.kernel_cmdline_prefix().map(ToOwned::to_owned),
        ));
    }

    let initrd = paths
        .initrd()
        .map(|path| {
            read_or_clone_guest_asset(
                path,
                &mut captured_paths,
                &mut captured_content,
                unique_bytes,
                limits.max_guest_asset_bytes,
                static_byte_limit,
            )
        })
        .transpose()?
        .map(|(asset, total)| {
            unique_bytes = total;
            asset
        });
    let deployment = FindingProductionReplayDeployment::new(
        runtime,
        paths.root_image_format().into(),
        guest_assets,
        initrd,
    );
    validate_deployment(scenario, &deployment, limits)?;

    Ok(CapturedDeployment {
        deployment,
        unique_identities: captured_content.into_keys().collect(),
        unique_bytes,
    })
}

fn read_or_clone_guest_asset(
    path: &std::path::Path,
    captured_paths: &mut BTreeMap<std::path::PathBuf, FindingProductionReplayAsset>,
    captured_content: &mut BTreeMap<ContentHash, FindingProductionReplayAsset>,
    retained_bytes: u64,
    guest_byte_limit: u64,
    static_byte_limit: u64,
) -> Result<(FindingProductionReplayAsset, u64), FindingProductionReplayCaptureError> {
    if let Some(asset) = captured_paths.get(path) {
        return Ok((asset.clone(), retained_bytes));
    }

    let mut file = std::fs::File::open(path).map_err(|source| {
        FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "open",
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !file
        .metadata()
        .map_err(|source| FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "inspect",
            path: path.to_path_buf(),
            source,
        })?
        .is_file()
    {
        return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
    }

    let mut counted = CountingReader::new(&mut file);
    let identity = ContentHash::from_reader(&mut counted).map_err(|source| {
        FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "hash",
            path: path.to_path_buf(),
            source,
        }
    })?;
    let length = counted.bytes_read();
    if let Some(asset) = captured_content.get(&identity) {
        captured_paths.insert(path.to_path_buf(), asset.clone());
        return Ok((asset.clone(), retained_bytes));
    }

    let total = charge_streamed_asset_bytes(retained_bytes, length, guest_byte_limit)?;
    if total > static_byte_limit {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-static-bytes",
        });
    }
    let length = usize::try_from(length).map_err(|_| {
        FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes",
        }
    })?;
    use std::io::{Read as _, Seek as _};
    file.rewind()
        .map_err(|source| FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "rewind",
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| {
        FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes",
        }
    })?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes).map_err(|source| {
        FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "read",
            path: path.to_path_buf(),
            source,
        }
    })?;
    let mut tail = [0_u8; 1];
    if file
        .read(&mut tail)
        .map_err(|source| FindingProductionReplayCaptureError::GuestAssetIo {
            operation: "finish reading",
            path: path.to_path_buf(),
            source,
        })?
        != 0
        || ContentHash::from_bytes(&bytes) != identity
    {
        return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
    }

    let asset = FindingProductionReplayAsset::from_bytes(bytes);
    captured_paths.insert(path.to_path_buf(), asset.clone());
    captured_content.insert(identity, asset.clone());
    Ok((asset, total))
}

fn charge_streamed_asset_bytes(
    retained_bytes: u64,
    additional: u64,
    limit: u64,
) -> Result<u64, FindingProductionReplayCaptureError> {
    let total = retained_bytes.checked_add(additional).ok_or(
        FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes",
        },
    )?;
    if total > limit {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes",
        });
    }
    Ok(total)
}

struct CountingReader<'a, R> {
    inner: &'a mut R,
    bytes_read: u64,
}

impl<'a, R> CountingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: std::io::Read> std::io::Read for CountingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(u64::try_from(read).map_err(|_| {
                std::io::Error::other("guest asset read length is not representable")
            })?)
            .ok_or_else(|| std::io::Error::other("guest asset byte count overflow"))?;
        Ok(read)
    }
}
