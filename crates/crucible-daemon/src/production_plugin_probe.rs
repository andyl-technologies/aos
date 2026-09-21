//! Guarded host ownership for the production loaded-QEMU plugin probe.
//!
//! The CLI supplies immutable package assets and host policy. This module owns
//! QEMU launch admission, the writable run directory, and complete process
//! cleanup so the command boundary never depends on the QEMU implementation
//! crate directly.

use std::path::PathBuf;

use crucible::{ContentHash, VmArchitecture};
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LivePluginGuestArchitecture, LivePluginInstallAdmission,
    LivePluginInstallGateConfig, LivePluginInstallGateError, QemuLaunchPluginSwitch,
    QemuLaunchResourceRequirements, QemuRootImageFormat, QemuVmRealizationError,
    run_live_plugin_install_gate,
};

use crate::{
    LinuxQemuAttemptHostResourceFactory, QemuAttemptHostResourceFactory,
    QemuAttemptHostResourceOwner,
};

const PROBE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const PROBE_DISK_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const PROBE_GUEST_MEMORY_MIB: u32 = 64;
const PROBE_GUEST_VCPUS: u16 = 1;

/// Immutable inputs and host policy for one production plugin probe.
#[derive(Clone, Debug)]
pub struct ProductionPluginProbeRequest {
    qemu: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    architecture: VmArchitecture,
    host: LinuxQemuAttemptHostConfig,
    kernel_cmdline: Option<String>,
}

impl ProductionPluginProbeRequest {
    /// Creates a probe request for one authenticated package pair and guest.
    #[must_use]
    pub fn new(
        qemu: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        architecture: VmArchitecture,
        host: LinuxQemuAttemptHostConfig,
    ) -> Self {
        Self {
            qemu: qemu.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            root_image: root_image.into(),
            architecture,
            host,
            kernel_cmdline: None,
        }
    }

    /// Adds the authenticated guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }
}

/// Host-visible evidence from one guarded production plugin probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPluginProbeReport {
    /// Exact completed instruction count published by the plugin.
    pub completed_icount: u64,
    /// Authenticated execution fingerprint when sampling was enabled.
    pub execution_fingerprint: Option<ContentHash>,
}

/// Failure from a guarded production plugin probe.
#[derive(Debug, thiserror::Error)]
pub enum ProductionPluginProbeError {
    /// Fixed probe resource policy could not be represented.
    #[error("configure production plugin probe resources: {message}")]
    ResourcePolicy {
        /// Resource-policy diagnostic.
        message: String,
    },
    /// Host allocation or launch preparation failed.
    #[error("{stage}: {source}")]
    Host {
        /// Stable lifecycle stage.
        stage: &'static str,
        /// Typed QEMU host failure.
        #[source]
        source: QemuVmRealizationError,
    },
    /// Fresh root-overlay preparation failed under the admitted process contract.
    #[error("prepare production plugin probe artifacts: {message}")]
    ImagePreparation {
        /// Image-tool failure after retaining any unreaped helper authority.
        message: String,
    },
    /// The live loaded-plugin execution failed.
    #[error("execute production loaded-QEMU plugin probe: {0}")]
    Gate(#[source] LivePluginInstallGateError),
    /// Host cleanup failed after successful plugin execution.
    #[error("finish production plugin probe resources: {0}")]
    Finish(#[source] QemuVmRealizationError),
    /// Host cleanup also failed after an earlier probe failure.
    #[error(
        "production plugin probe failed ({operation}); resource cleanup also failed: {cleanup}"
    )]
    FailureAndFinish {
        /// Original probe failure.
        operation: Box<Self>,
        /// Cleanup failure retained with the original diagnostic.
        cleanup: QemuVmRealizationError,
    },
}

/// Executes one loaded-QEMU plugin probe under daemon-owned host authority.
///
/// # Errors
///
/// Returns [`ProductionPluginProbeError`] when resource admission, launch
/// preparation, live plugin execution, child reap, or host cleanup fails.
pub fn run_guarded_production_plugin_probe(
    request: ProductionPluginProbeRequest,
) -> Result<ProductionPluginProbeReport, ProductionPluginProbeError> {
    let mut factory =
        LinuxQemuAttemptHostResourceFactory::open(request.host).map_err(|source| {
            ProductionPluginProbeError::Host {
                stage: "open production plugin probe host owner",
                source,
            }
        })?;
    let resources = AttemptResourceLimits::new(1, PROBE_MEMORY_BYTES, PROBE_DISK_BYTES, 1)
        .map_err(|error| ProductionPluginProbeError::ResourcePolicy {
            message: error.to_string(),
        })?;
    let mut owner =
        factory
            .begin(resources)
            .map_err(|source| ProductionPluginProbeError::Host {
                stage: "admit production plugin probe resources",
                source,
            })?;

    let operation =
        (|| {
            let requirements = QemuLaunchResourceRequirements::from_vm_shape(
                PROBE_GUEST_MEMORY_MIB,
                PROBE_GUEST_VCPUS,
                true,
            );
            let mut run_directory = owner
                .prepare_generation_run_directory(requirements)
                .map_err(|source| ProductionPluginProbeError::Host {
                    stage: "prepare production plugin probe directory",
                    source,
                })?;
            let process_contract = owner.child_process_contract().map_err(|source| {
                ProductionPluginProbeError::Host {
                    stage: "authenticate production plugin probe process",
                    source,
                }
            })?;
            if let Err(mut error) = run_directory.prepare_fresh_artifacts_guarded(
                &request.qemu,
                Some(&request.root_image),
                process_contract,
            ) {
                if let Some(child) = error.take_unreaped_child() {
                    owner.retain_failed_launch_child(child);
                }
                return Err(ProductionPluginProbeError::ImagePreparation {
                    message: error.to_string(),
                });
            }
            let process_contract = owner.child_process_contract().map_err(|source| {
                ProductionPluginProbeError::Host {
                    stage: "reauthenticate production plugin probe process",
                    source,
                }
            })?;

            let architecture = match request.architecture {
                VmArchitecture::X86_64 => LivePluginGuestArchitecture::X86_64,
                VmArchitecture::Aarch64 => LivePluginGuestArchitecture::Aarch64,
            };
            let mut config = LivePluginInstallGateConfig::new(
                &request.qemu,
                &request.plugin,
                &request.kernel,
                &request.root_image,
                run_directory.path(),
                architecture,
            )
            .with_root_image_format(QemuRootImageFormat::Raw)
            .with_fingerprint(QemuLaunchPluginSwitch::On);
            if let Some(kernel_cmdline) = request.kernel_cmdline.as_deref() {
                config = config.with_kernel_cmdline(kernel_cmdline);
            }
            let admission =
                LivePluginInstallAdmission::admit(&config, &run_directory, process_contract)
                    .map_err(ProductionPluginProbeError::Gate)?;
            let report = run_live_plugin_install_gate(&config, admission)
                .map_err(ProductionPluginProbeError::Gate)?;
            Ok(ProductionPluginProbeReport {
                completed_icount: report.completed_icount,
                execution_fingerprint: report.execution_fingerprint.map(|sample| sample.hash),
            })
        })();
    let cleanup = owner.finish();

    match (operation, cleanup) {
        (Ok(report), Ok(())) => Ok(report),
        (Ok(_), Err(error)) => Err(ProductionPluginProbeError::Finish(error)),
        (Err(error), Ok(())) => Err(error),
        (Err(operation), Err(cleanup)) => Err(ProductionPluginProbeError::FailureAndFinish {
            operation: Box::new(operation),
            cleanup,
        }),
    }
}
