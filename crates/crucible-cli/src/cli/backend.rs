// Backend discovery, validation, routing, and command outcome projection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendSelectionPlan {
    subcommand: CliSubcommand,
    target: BackendExecutionTarget,
    requested_backend: Backend,
    resolved_backend: Option<ResolvedLocalBackend>,
    reason: BackendSelectionReason,
    daemon: Option<String>,
    remote_uses_control_api: bool,
    local_uses_simulation_backend: bool,
    local_remote_equivalence_contract: bool,
}

impl BackendSelectionPlan {
    fn proves_t_cli_3(&self) -> bool {
        self.local_remote_equivalence_contract
            && match self.target {
                BackendExecutionTarget::RemoteDaemon => {
                    self.daemon
                        .as_deref()
                        .is_some_and(|daemon| !daemon.is_empty())
                        && self.resolved_backend.is_none()
                        && self.remote_uses_control_api
                        && !self.local_uses_simulation_backend
                        && self.reason == BackendSelectionReason::RemoteDaemon
                }
                BackendExecutionTarget::Local => {
                    self.daemon.is_none()
                        && self.resolved_backend.is_some()
                        && !self.remote_uses_control_api
                        && self.local_uses_simulation_backend
                        && match (self.requested_backend, &self.resolved_backend, self.reason) {
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::AutoQemuArtifactsSupplied,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::AutoFallbackDouble,
                            )
                            | (
                                Backend::Double,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::ExplicitDouble,
                            ) => true,
                            (
                                Backend::Qemu,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::ExplicitQemu,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            _ => false,
                        }
                }
            }
    }

    fn proves_t_cli_5(&self) -> bool {
        match (&self.target, &self.resolved_backend, self.requested_backend) {
            (BackendExecutionTarget::RemoteDaemon, None, _) => true,
            (BackendExecutionTarget::Local, Some(ResolvedLocalBackend::Double), Backend::Auto)
            | (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                Backend::Double,
            ) => true,
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu {
                    qemu,
                    plugin,
                    qemu_build_id,
                    qemu_patch_series_hash,
                    plugin_abi,
                    shmem_abi_version,
                    qemu_source,
                    plugin_source,
                }),
                Backend::Auto | Backend::Qemu,
            ) => {
                let required_plugin_abi = required_qemu_plugin_abi();
                !qemu.as_os_str().is_empty()
                    && !plugin.as_os_str().is_empty()
                    && is_content_address(qemu_build_id)
                    && !qemu_patch_series_hash.is_empty()
                    && plugin_abi == &required_plugin_abi
                    && shmem_abi_version == &crucible::SHMEM_ABI_VERSION.to_string()
                    && qemu_source.is_hermetic()
                    && plugin_source.is_hermetic()
            }
            _ => false,
        }
    }

    fn should_announce(&self, quiet: bool) -> bool {
        !quiet
            && matches!(
                self.reason,
                BackendSelectionReason::AutoFallbackDouble
                    | BackendSelectionReason::AutoQemuArtifactsSupplied
            )
    }

    fn announcement(&self) -> String {
        match (&self.target, &self.resolved_backend, self.reason) {
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu { .. }),
                BackendSelectionReason::AutoQemuArtifactsSupplied,
            ) => String::from(
                "crucible: backend = qemu (--backend auto; patched QEMU and plugin discovered)",
            ),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                BackendSelectionReason::AutoFallbackDouble,
            ) => String::from(
                "crucible: backend = double (--backend auto; patched QEMU/plugin not discoverable)",
            ),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                BackendSelectionReason::ExplicitDouble,
            ) => String::from("crucible: backend = double (explicit --backend double)"),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu { .. }),
                BackendSelectionReason::ExplicitQemu,
            ) => String::from(
                "crucible: backend = qemu (explicit --backend qemu with hermetic QEMU/plugin discovery)",
            ),
            (BackendExecutionTarget::RemoteDaemon, None, BackendSelectionReason::RemoteDaemon) => {
                format!(
                    "crucible: backend = daemon (remote API {}; daemon backend fidelity applies)",
                    self.daemon.as_deref().unwrap_or("<unset>")
                )
            }
            _ => String::from("crucible: backend selection is invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendExecutionTarget {
    Local,
    RemoteDaemon,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResolvedLocalBackend {
    Qemu {
        qemu: PathBuf,
        plugin: PathBuf,
        qemu_build_id: String,
        qemu_patch_series_hash: String,
        plugin_abi: String,
        shmem_abi_version: String,
        qemu_source: QemuDiscoverySource,
        plugin_source: QemuDiscoverySource,
    },
    Double,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum QemuDiscoverySource {
    Flag,
    Environment,
    AosPackageSet,
}

impl QemuDiscoverySource {
    const fn is_hermetic(self) -> bool {
        matches!(self, Self::Flag | Self::Environment | Self::AosPackageSet)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuDiscoveryCandidate {
    path: PathBuf,
    source: QemuDiscoverySource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuArtifactIdentity {
    qemu_build_id: String,
    qemu_patch_series_hash: String,
    plugin_abi: String,
    shmem_abi_version: String,
}

#[derive(Debug)]
struct QemuBuildMarker {
    raw_build_id: String,
    artifact_build_id: String,
    qemu_patch_series_hash: String,
    shmem_abi_version: String,
    shmem_abi: String,
    shmem_header_hash: String,
}

#[derive(Debug)]
struct PluginBuildMarker {
    plugin_abi: String,
    qemu_build_id: String,
    shmem_abi_version: String,
    shmem_abi: String,
    shmem_header_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendSelectionReason {
    RemoteDaemon,
    ExplicitDouble,
    ExplicitQemu,
    AutoQemuArtifactsSupplied,
    AutoFallbackDouble,
}

trait BackendRouteRecorder {
    fn record_remote_daemon(&mut self, daemon: &str);

    fn record_local_backend(&mut self, backend: &ResolvedLocalBackend);

    fn record_backend_announcement(&mut self, message: &str);
}

#[derive(Default)]
struct NullBackendRouteRecorder;

impl BackendRouteRecorder for NullBackendRouteRecorder {
    fn record_remote_daemon(&mut self, _daemon: &str) {}

    fn record_local_backend(&mut self, _backend: &ResolvedLocalBackend) {}

    fn record_backend_announcement(&mut self, _message: &str) {}
}

#[cfg(not(test))]
fn plan_backend_selection(cli: &Cli) -> Result<Option<BackendSelectionPlan>, CliError> {
    plan_backend_selection_with_discovery(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &CompileTimeAosQemuPackageSet,
    )
}

#[cfg(test)]
fn plan_backend_selection(cli: &Cli) -> Result<Option<BackendSelectionPlan>, CliError> {
    plan_backend_selection_with_discovery(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &NoAosQemuPackageSet,
    )
}

fn plan_backend_selection_with_discovery(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<Option<BackendSelectionPlan>, CliError> {
    if !subcommand_uses_backend_selection(&cli.command) {
        return Ok(None);
    }
    let subcommand = CliSubcommand::from_command(&cli.command);
    if matches!(cli.command, Commands::Serve(_)) && cli.daemon.is_some() {
        return Err(usage_error(
            "serve hosts the daemon and cannot itself use --daemon",
        ));
    }

    if let Some(daemon) = &cli.daemon {
        if daemon.is_empty() {
            return Err(usage_error("--daemon must not be empty"));
        }
        return Ok(Some(BackendSelectionPlan {
            subcommand,
            target: BackendExecutionTarget::RemoteDaemon,
            requested_backend: cli.backend,
            resolved_backend: None,
            reason: BackendSelectionReason::RemoteDaemon,
            daemon: Some(daemon.clone()),
            remote_uses_control_api: true,
            local_uses_simulation_backend: false,
            local_remote_equivalence_contract: true,
        }));
    }

    let (resolved_backend, reason) = match cli.backend {
        Backend::Double => (
            ResolvedLocalBackend::Double,
            BackendSelectionReason::ExplicitDouble,
        ),
        Backend::Qemu => (
            require_qemu_artifacts(cli, environment, package_set)?,
            BackendSelectionReason::ExplicitQemu,
        ),
        Backend::Auto => match discover_qemu_artifacts(cli, environment, package_set)? {
            Some(artifacts) => (artifacts, BackendSelectionReason::AutoQemuArtifactsSupplied),
            None => (
                ResolvedLocalBackend::Double,
                BackendSelectionReason::AutoFallbackDouble,
            ),
        },
    };

    Ok(Some(BackendSelectionPlan {
        subcommand,
        target: BackendExecutionTarget::Local,
        requested_backend: cli.backend,
        resolved_backend: Some(resolved_backend),
        reason,
        daemon: None,
        remote_uses_control_api: false,
        local_uses_simulation_backend: true,
        local_remote_equivalence_contract: true,
    }))
}

trait QemuDiscoveryEnvironment {
    fn variable(&self, name: &'static str) -> Option<String>;
}

#[derive(Default)]
struct ProcessQemuDiscoveryEnvironment;

impl QemuDiscoveryEnvironment for ProcessQemuDiscoveryEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
}

trait AosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf>;

    fn plugin_path(&self) -> Option<PathBuf>;
}

#[derive(Default)]
struct CompileTimeAosQemuPackageSet;

impl AosQemuPackageSet for CompileTimeAosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf> {
        option_env!("CRUCIBLE_AOS_QEMU").map(PathBuf::from)
    }

    fn plugin_path(&self) -> Option<PathBuf> {
        option_env!("CRUCIBLE_AOS_PLUGIN").map(PathBuf::from)
    }
}

#[cfg(test)]
#[derive(Default)]
struct NoAosQemuPackageSet;

#[cfg(test)]
impl AosQemuPackageSet for NoAosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf> {
        None
    }

    fn plugin_path(&self) -> Option<PathBuf> {
        None
    }
}

fn require_qemu_artifacts(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<ResolvedLocalBackend, CliError> {
    discover_qemu_artifacts(cli, environment, package_set)?.ok_or_else(|| {
        qemu_backend_config_error(format!(
            "--backend qemu could not discover both patched QEMU and plugin; {}",
            qemu_discovery_order_help()
        ))
    })
}

fn discover_qemu_artifacts(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<Option<ResolvedLocalBackend>, CliError> {
    let qemu = select_qemu_candidate(
        cli.qemu.as_ref(),
        environment.variable(CRUCIBLE_QEMU_ENV),
        package_set.qemu_path(),
    );
    let plugin = select_plugin_candidate(
        cli.plugin.as_ref(),
        environment.variable(CRUCIBLE_PLUGIN_ENV),
        package_set.plugin_path(),
    );
    let (Some(qemu), Some(plugin)) = (qemu, plugin) else {
        return Ok(None);
    };
    let identity = validate_qemu_artifacts(&qemu.path, &plugin.path)?;
    Ok(Some(ResolvedLocalBackend::Qemu {
        qemu: qemu.path,
        plugin: plugin.path,
        qemu_build_id: identity.qemu_build_id,
        qemu_patch_series_hash: identity.qemu_patch_series_hash,
        plugin_abi: identity.plugin_abi,
        shmem_abi_version: identity.shmem_abi_version,
        qemu_source: qemu.source,
        plugin_source: plugin.source,
    }))
}

fn select_qemu_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    select_qemu_discovery_candidate(flag, environment, package_set)
}

fn select_plugin_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    select_qemu_discovery_candidate(flag, environment, package_set)
}

fn select_qemu_discovery_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    if let Some(path) = flag {
        return Some(QemuDiscoveryCandidate {
            path: path.clone(),
            source: QemuDiscoverySource::Flag,
        });
    }
    if let Some(value) = environment.filter(|value| !value.trim().is_empty()) {
        return Some(QemuDiscoveryCandidate {
            path: PathBuf::from(value),
            source: QemuDiscoverySource::Environment,
        });
    }
    package_set.map(|path| QemuDiscoveryCandidate {
        path,
        source: QemuDiscoverySource::AosPackageSet,
    })
}

fn validate_qemu_artifacts(qemu: &Path, plugin: &Path) -> Result<QemuArtifactIdentity, CliError> {
    validate_readable_file_artifact("patched QEMU", qemu)?;
    validate_readable_file_artifact("plugin", plugin)?;
    let qemu_marker = read_qemu_build_marker(qemu)?;
    let plugin_marker = read_plugin_build_marker(plugin)?;
    let required_plugin_abi = required_qemu_plugin_abi();
    if plugin_marker.plugin_abi != required_plugin_abi {
        return Err(qemu_backend_config_error(format!(
            "plugin `{}` advertises ABI `{}` but this CLI requires `{}`; {}",
            plugin.display(),
            plugin_marker.plugin_abi,
            required_plugin_abi,
            qemu_discovery_order_help()
        )));
    }
    if plugin_marker.qemu_build_id != qemu_marker.raw_build_id {
        return Err(qemu_backend_config_error(format!(
            "plugin `{}` was built for QEMU identity `{}` but patched QEMU `{}` advertises `{}`; {}",
            plugin.display(),
            plugin_marker.qemu_build_id,
            qemu.display(),
            qemu_marker.raw_build_id,
            qemu_discovery_order_help()
        )));
    }
    if qemu_marker.shmem_abi != plugin_marker.plugin_abi {
        return Err(qemu_backend_config_error(format!(
            "patched QEMU `{}` advertises shmem ABI `{}` but plugin `{}` advertises `{}`; {}",
            qemu.display(),
            qemu_marker.shmem_abi,
            plugin.display(),
            plugin_marker.plugin_abi,
            qemu_discovery_order_help()
        )));
    }
    if plugin_marker.shmem_abi != plugin_marker.plugin_abi {
        return Err(qemu_backend_config_error(format!(
            "plugin `{}` advertises plugin ABI `{}` but its shmem ABI marker is `{}`; {}",
            plugin.display(),
            plugin_marker.plugin_abi,
            plugin_marker.shmem_abi,
            qemu_discovery_order_help()
        )));
    }
    if qemu_marker.shmem_abi_version != plugin_marker.shmem_abi_version {
        return Err(qemu_backend_config_error(format!(
            "patched QEMU `{}` advertises shmem ABI version `{}` but plugin `{}` advertises `{}`; {}",
            qemu.display(),
            qemu_marker.shmem_abi_version,
            plugin.display(),
            plugin_marker.shmem_abi_version,
            qemu_discovery_order_help()
        )));
    }
    if qemu_marker.shmem_header_hash != plugin_marker.shmem_header_hash {
        return Err(qemu_backend_config_error(format!(
            "patched QEMU `{}` advertises shmem header hash `{}` but plugin `{}` was built with `{}`; {}",
            qemu.display(),
            qemu_marker.shmem_header_hash,
            plugin.display(),
            plugin_marker.shmem_header_hash,
            qemu_discovery_order_help()
        )));
    }
    Ok(QemuArtifactIdentity {
        qemu_build_id: qemu_marker.artifact_build_id,
        qemu_patch_series_hash: qemu_marker.qemu_patch_series_hash,
        plugin_abi: plugin_marker.plugin_abi,
        shmem_abi_version: plugin_marker.shmem_abi_version,
    })
}

fn validate_readable_file_artifact(label: &'static str, path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(qemu_backend_config_error(format!(
            "--backend qemu cannot read {label} artifact `{}`: not a regular file; {}",
            path.display(),
            qemu_discovery_order_help()
        )));
    }
    fs::File::open(path).map_err(|error| {
        qemu_backend_config_error(format!(
            "--backend qemu cannot read {label} artifact `{}`: {error}; {}",
            path.display(),
            qemu_discovery_order_help()
        ))
    })?;
    Ok(())
}

fn qemu_backend_config_error(reason: impl Into<String>) -> CliError {
    CliError::Backend(reason.into())
}
// The session boundary re-exports the ABI derived from `crucible_shmem::ABI_VERSION`.
fn required_qemu_plugin_abi() -> String {
    shmem_abi_label_for_version(&crucible::SHMEM_ABI_VERSION.to_string())
}

fn shmem_abi_label_for_version(version: &str) -> String {
    format!("{CRUCIBLE_QEMU_PLUGIN_ABI_PREFIX}{version}")
}

fn current_guest_host_protocol_version() -> String {
    CONTROL_PROTOCOL_VERSION.to_string()
}

fn current_rpc_abi_version() -> String {
    format!("{RPC_PROTOCOL_MAJOR}.{RPC_PROTOCOL_MINOR}.{RPC_PROTOCOL_PATCH}")
}

fn current_rpc_abi_build() -> String {
    RPC_PROTOCOL_BUILD.to_string()
}

fn qemu_discovery_order_help() -> String {
    format!(
        "discovery order is --qemu/--plugin, {CRUCIBLE_QEMU_ENV}/{CRUCIBLE_PLUGIN_ENV}, then AOS package-set hints {CRUCIBLE_AOS_QEMU_ENV}/{CRUCIBLE_AOS_PLUGIN_ENV}; host $PATH QEMU is never used; supply a matched qemu-crucible/crucible-qemu-plugin pair or use --backend double"
    )
}

fn read_qemu_build_marker(qemu: &Path) -> Result<QemuBuildMarker, CliError> {
    let marker = existing_metadata_path(qemu_build_marker_paths(qemu)).ok_or_else(|| {
        qemu_backend_config_error(format!(
            "patched QEMU `{}` is missing its sim-capability marker `share/aos/crucible/qemu-build-identity.env`; {}",
            qemu.display(),
            qemu_discovery_order_help()
        ))
    })?;
    let fields = read_key_value_metadata(&marker)?;
    let sim_capability = required_metadata_field(&fields, "qemu_sim_capability", &marker)?;
    if sim_capability != "qemu-crucible" {
        return Err(qemu_backend_config_error(format!(
            "QEMU `{}` does not advertise the qemu-crucible sim capability (qemu_sim_capability={sim_capability}); {}",
            qemu.display(),
            qemu_discovery_order_help()
        )));
    }
    let patches_applied =
        required_metadata_field(&fields, "qemu_crucible_patches_applied", &marker)?;
    if patches_applied != "true" {
        return Err(qemu_backend_config_error(format!(
            "QEMU `{}` is not the patched Crucible build (qemu_crucible_patches_applied={patches_applied}); {}",
            qemu.display(),
            qemu_discovery_order_help()
        )));
    }
    let plugins_enabled = required_metadata_field(&fields, "qemu_plugins_enabled", &marker)?;
    if plugins_enabled != "true" {
        return Err(qemu_backend_config_error(format!(
            "QEMU `{}` was built without plugin support (qemu_plugins_enabled={plugins_enabled}); {}",
            qemu.display(),
            qemu_discovery_order_help()
        )));
    }
    let raw_build_id = required_metadata_field(&fields, "qemu_build_id", &marker)?;
    let qemu_patch_series_hash =
        required_metadata_field(&fields, "qemu_patch_series_hash", &marker)?;
    if raw_build_id.is_empty() {
        return Err(qemu_backend_config_error(format!(
            "QEMU marker `{}` has an empty qemu_build_id; {}",
            marker.display(),
            qemu_discovery_order_help()
        )));
    }
    let shmem_abi_version = required_metadata_field(&fields, "qemu_shmem_abi_version", &marker)?;
    let shmem_abi = required_metadata_field(&fields, "qemu_shmem_abi", &marker)?;
    let shmem_header = required_metadata_field(&fields, "qemu_shmem_header", &marker)?;
    let shmem_header_hash = required_metadata_field(&fields, "qemu_shmem_header_hash", &marker)?;
    if qemu_patch_series_hash.is_empty()
        || shmem_abi_version.is_empty()
        || shmem_abi.is_empty()
        || shmem_header.is_empty()
        || shmem_header_hash.is_empty()
    {
        return Err(qemu_backend_config_error(format!(
            "QEMU marker `{}` must contain non-empty qemu_patch_series_hash, qemu_shmem_abi_version, qemu_shmem_abi, qemu_shmem_header, and qemu_shmem_header_hash; {}",
            marker.display(),
            qemu_discovery_order_help()
        )));
    }
    let expected_shmem_abi = shmem_abi_label_for_version(&shmem_abi_version);
    if shmem_abi != expected_shmem_abi {
        return Err(qemu_backend_config_error(format!(
            "QEMU marker `{}` has qemu_shmem_abi_version `{}` but qemu_shmem_abi `{}`; expected `{}`; {}",
            marker.display(),
            shmem_abi_version,
            shmem_abi,
            expected_shmem_abi,
            qemu_discovery_order_help()
        )));
    }
    let artifact_build_id = if is_content_address(&raw_build_id) {
        raw_build_id.clone()
    } else {
        content_address_bytes(raw_build_id.as_bytes())
    };
    Ok(QemuBuildMarker {
        raw_build_id,
        artifact_build_id,
        qemu_patch_series_hash,
        shmem_abi_version,
        shmem_abi,
        shmem_header_hash,
    })
}

fn read_plugin_build_marker(plugin: &Path) -> Result<PluginBuildMarker, CliError> {
    let marker = existing_metadata_path(plugin_build_marker_paths(plugin)).ok_or_else(|| {
        qemu_backend_config_error(format!(
            "plugin `{}` is missing `nix-support/crucible-qemu-plugin-build-info`; {}",
            plugin.display(),
            qemu_discovery_order_help()
        ))
    })?;
    let fields = read_key_value_metadata(&marker)?;
    let plugin_abi = required_metadata_field(&fields, "plugin_abi", &marker)?;
    let qemu_build_id = required_metadata_field(&fields, "qemu_build_id", &marker)?;
    let shmem_abi_version = required_metadata_field(&fields, "shmem_abi_version", &marker)?;
    let shmem_abi = required_metadata_field(&fields, "shmem_abi", &marker)?;
    let shmem_header_hash =
        required_metadata_field(&fields, "shmem_generated_header_hash", &marker)?;
    if plugin_abi.is_empty()
        || qemu_build_id.is_empty()
        || shmem_abi_version.is_empty()
        || shmem_abi.is_empty()
        || shmem_header_hash.is_empty()
    {
        return Err(qemu_backend_config_error(format!(
            "plugin marker `{}` must contain non-empty plugin_abi, qemu_build_id, shmem_abi_version, shmem_abi, and shmem_generated_header_hash; {}",
            marker.display(),
            qemu_discovery_order_help()
        )));
    }
    let expected_shmem_abi = shmem_abi_label_for_version(&shmem_abi_version);
    if shmem_abi != expected_shmem_abi {
        return Err(qemu_backend_config_error(format!(
            "plugin marker `{}` has shmem_abi_version `{}` but shmem_abi `{}`; expected `{}`; {}",
            marker.display(),
            shmem_abi_version,
            shmem_abi,
            expected_shmem_abi,
            qemu_discovery_order_help()
        )));
    }
    Ok(PluginBuildMarker {
        plugin_abi,
        qemu_build_id,
        shmem_abi_version,
        shmem_abi,
        shmem_header_hash,
    })
}

fn qemu_build_marker_paths(qemu: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(parent) = qemu.parent() {
        if parent.file_name().and_then(|name| name.to_str()) == Some("bin")
            && let Some(root) = parent.parent()
        {
            paths.push(root.join("share/aos/crucible/qemu-build-identity.env"));
        }
        paths.push(parent.join("qemu-build-identity.env"));
    }
    paths
}

fn plugin_build_marker_paths(plugin: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(parent) = plugin.parent() {
        if parent.file_name().and_then(|name| name.to_str()) == Some("lib")
            && let Some(root) = parent.parent()
        {
            paths.push(root.join("nix-support/crucible-qemu-plugin-build-info"));
        }
        paths.push(parent.join("crucible-qemu-plugin-build-info"));
    }
    paths
}

fn existing_metadata_path(paths: Vec<PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| path.is_file())
}

fn read_key_value_metadata(path: &Path) -> Result<BTreeMap<String, String>, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        qemu_backend_config_error(format!(
            "cannot read metadata marker `{}`: {error}",
            path.display()
        ))
    })?;
    let mut fields = BTreeMap::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(qemu_backend_config_error(format!(
                "metadata marker `{}` line {} is not key=value",
                path.display(),
                line_index + 1
            )));
        };
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(fields)
}

fn required_metadata_field(
    fields: &BTreeMap<String, String>,
    key: &'static str,
    marker: &Path,
) -> Result<String, CliError> {
    fields.get(key).cloned().ok_or_else(|| {
        qemu_backend_config_error(format!(
            "metadata marker `{}` is missing `{key}`; {}",
            marker.display(),
            qemu_discovery_order_help()
        ))
    })
}

fn subcommand_uses_backend_selection(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Run(_)
            | Commands::Verify(_)
            | Commands::Save(_)
            | Commands::Resume(_)
            | Commands::Fork(_)
            | Commands::Replay(_)
            | Commands::Search(_)
            | Commands::Fuzz(_)
            | Commands::Serve(_)
    )
}

fn execute_backend_selection_plan(
    plan: &BackendSelectionPlan,
    quiet: bool,
    recorder: &mut impl BackendRouteRecorder,
) -> Result<(), CliError> {
    if !plan.proves_t_cli_3() {
        return Err(CliError::Backend(
            "CLI backend selection violates the RFC-0010 local/remote split".to_string(),
        ));
    }
    if !plan.proves_t_cli_5() {
        return Err(CliError::Backend(
            "CLI QEMU discovery violates the RFC-0010 hermetic discovery contract".to_string(),
        ));
    }

    match (&plan.target, &plan.resolved_backend, &plan.daemon) {
        (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => {
            recorder.record_remote_daemon(daemon);
        }
        (BackendExecutionTarget::Local, Some(backend), None) => {
            recorder.record_local_backend(backend);
        }
        _ => {
            return Err(CliError::Backend(
                "CLI backend selection is internally inconsistent".to_string(),
            ));
        }
    }
    if plan.should_announce(quiet) {
        recorder.record_backend_announcement(&plan.announcement());
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendCommandOutcome {
    subcommand: CliSubcommand,
    status: BackendCommandStatus,
    exit_code: i32,
    stdout: Vec<String>,
    stderr: Vec<String>,
    canonical_log: Vec<CanonicalLogEntry>,
    canonical_log_digest: String,
    artifact_digest: String,
    terminal_savepoint: Option<crucible::ContentHash>,
    savepoint_oracle: Option<SavepointOracleProof>,
    reproduction_artifact: Option<Vec<u8>>,
    side_reproduction_artifacts: Vec<(String, Vec<u8>)>,
}

impl BackendCommandOutcome {
    #[cfg(test)]
    fn normalized(&self) -> BackendCommandOutcomeProjection {
        BackendCommandOutcomeProjection {
            subcommand: self.subcommand,
            status: self.status,
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            canonical_log_digest: self.canonical_log_digest.clone(),
            artifact_digest: self.artifact_digest.clone(),
            terminal_savepoint: self.terminal_savepoint,
            savepoint_oracle: self.savepoint_oracle.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendCommandStatus {
    Passed,
    Failed,
    Crashed,
    Timeout,
}

impl BackendCommandStatus {
    fn exit_code(self) -> i32 {
        CliError::Outcome(self).exit_code()
    }

    fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Timeout => "timeout",
        }
    }

    fn non_passing_variants() -> [Self; 3] {
        [Self::Failed, Self::Crashed, Self::Timeout]
    }

    fn is_non_passing(self) -> bool {
        !matches!(self, Self::Passed)
    }

    fn failure_slug(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Timeout => "timeout",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendCommandOutcomeProjection {
    subcommand: CliSubcommand,
    status: BackendCommandStatus,
    exit_code: i32,
    stdout: Vec<String>,
    stderr: Vec<String>,
    canonical_log_digest: String,
    artifact_digest: String,
    terminal_savepoint: Option<crucible::ContentHash>,
    savepoint_oracle: Option<SavepointOracleProof>,
}

trait BackendCommandRunner {
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError>;

    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError>;
}

#[derive(Default)]
struct NullBackendCommandRunner;

impl BackendCommandRunner for NullBackendCommandRunner {
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError> {
        if let Some(verify_plan) = verify_plan {
            return match (&verify_plan.mode, backend) {
                (VerifyMode::CompareArtifacts { .. }, _) => {
                    let report = verify_compare_artifacts(verify_plan, Some(backend))?;
                    finish_verify_workflow_outcome(
                        thin_plan,
                        backend_plan,
                        ergonomics_plan,
                        verify_plan,
                        report,
                    )
                }
                (VerifyMode::RunScenario { .. }, ResolvedLocalBackend::Double) => {
                    run_local_double_verify_workflow(
                        thin_plan,
                        backend_plan,
                        ergonomics_plan,
                        verify_plan,
                    )
                }
                (VerifyMode::RunScenario { .. }, ResolvedLocalBackend::Qemu { .. }) => {
                    run_local_qemu_verify_workflow(
                        thin_plan,
                        backend_plan,
                        ergonomics_plan,
                        verify_plan,
                    )
                }
            };
        }
        if let Some(save_plan) = save_plan {
            return match backend {
                ResolvedLocalBackend::Double => run_local_double_save_workflow(
                    thin_plan,
                    backend_plan,
                    ergonomics_plan,
                    save_plan,
                ),
                ResolvedLocalBackend::Qemu { .. } => run_local_qemu_save_workflow(
                    thin_plan,
                    backend_plan,
                    ergonomics_plan,
                    save_plan,
                ),
            };
        }
        if let Some(run_plan) = run_plan {
            return match backend {
                ResolvedLocalBackend::Double => {
                    run_local_double_workflow(thin_plan, backend_plan, ergonomics_plan, run_plan)
                }
                ResolvedLocalBackend::Qemu { .. } => Ok(backend_command_outcome(
                    thin_plan,
                    backend_plan,
                    ergonomics_plan,
                )),
            };
        }
        Ok(backend_command_outcome(
            thin_plan,
            backend_plan,
            ergonomics_plan,
        ))
    }

    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError> {
        if let Some(save_plan) = save_plan {
            return run_remote_save_workflow(
                daemon,
                thin_plan,
                backend_plan,
                ergonomics_plan,
                save_plan,
            );
        }
        if let Some(run_plan) = run_plan {
            return run_remote_workflow(daemon, thin_plan, backend_plan, ergonomics_plan, run_plan);
        }
        if let Some(verify_plan) = verify_plan {
            return run_remote_verify_workflow(
                daemon,
                thin_plan,
                backend_plan,
                ergonomics_plan,
                verify_plan,
            );
        }
        Ok(backend_command_outcome(
            thin_plan,
            backend_plan,
            ergonomics_plan,
        ))
    }
}

fn execute_backend_routed_command(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: Option<&RunInvocationPlan>,
    verify_plan: Option<&VerifyInvocationPlan>,
    save_plan: Option<&SaveInvocationPlan>,
    runner: &mut impl BackendCommandRunner,
) -> Result<BackendCommandOutcome, CliError> {
    if !thin_plan.proves_t_cli_2() || !backend_plan.proves_t_cli_3() {
        return Err(CliError::Backend(
            "CLI command route violates the RFC-0010 backend split".to_string(),
        ));
    }
    if thin_plan.subcommand != backend_plan.subcommand {
        return Err(CliError::Backend(
            "CLI backend route does not match the command dispatch plan".to_string(),
        ));
    }

    match (
        &backend_plan.target,
        &backend_plan.resolved_backend,
        &backend_plan.daemon,
    ) {
        (BackendExecutionTarget::Local, Some(backend), None) => runner.run_local(
            backend,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
            save_plan,
        ),
        (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => runner.run_remote(
            daemon,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
            save_plan,
        ),
        _ => Err(CliError::Backend(
            "CLI backend route is internally inconsistent".to_string(),
        )),
    }
}
