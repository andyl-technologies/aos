//! Typed environment scopes and observed execution inventories.
//!
//! Layers run from the outer host to the subject. A profile constrains each
//! layer independently; omitted constraints never fabricate observed identities.
//!
//! ```text
//! profile: physical host -> QEMU (KVM or TCG) -> subject
//! inventory: exact CPU, backend, firmware, devices, kernel and resources
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::platform::Platform;

/// Version of a retained, concrete execution inventory.
pub const INVENTORY_V1: &str = "aos.release.environment-inventory/v1";

/// Acceleration mechanism used by one QEMU layer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Accelerator {
    /// QEMU instruction translation, without a native virtualization claim.
    Tcg,
    /// Kernel-assisted virtualization on the recorded host.
    Kvm,
}

/// Closed container runtime implementation supported by qualification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerRuntime {
    /// AOS-built containerd and runc.
    ContainerdRunc,
}

/// Backend identity or constraints for one execution layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Backend {
    /// Direct execution on physical hardware.
    Physical {
        /// Board or system identity; required in physical execution evidence.
        board: Option<String>,
        /// Chipset or SoC identity; required in physical execution evidence.
        chipset: Option<String>,
    },
    /// A QEMU virtual machine with an explicit accelerator.
    Qemu {
        /// Machine family, such as q35 or virt.
        machine: String,
        /// Versioned machine compatibility identity.
        machine_version: Option<String>,
        /// QEMU build/version identity.
        version: Option<String>,
        /// Acceleration is independent of the guest architecture.
        accelerator: Accelerator,
        /// Actual guest CPU model requested from QEMU.
        cpu_model: Option<String>,
    },
    /// A provider-managed VM with a bounded deployment scope.
    Cloud {
        /// Cloud provider identity.
        provider: String,
        /// Provider service identity.
        service: String,
        /// Exact instance SKU, not only its family.
        sku: String,
        /// Region constraint or observed region.
        region: Option<String>,
    },
    /// A container executed by the recorded host runtime.
    Container {
        /// Container runtime implementation.
        runtime: ContainerRuntime,
        /// Runtime version/build identity.
        version: Option<String>,
        /// Cgroup mode, such as v2.
        cgroup: Option<String>,
        /// Network implementation and configuration identity.
        network: Option<String>,
        /// Persistent volume implementation and configuration identity.
        volume: Option<String>,
    },
}

/// CPU predicates for a compatibility scope.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CpuScope {
    /// Accepted vendors; empty means no vendor restriction.
    pub vendors: Vec<String>,
    /// Accepted family/model identities; empty means no model restriction.
    pub models: Vec<String>,
    /// Accepted exact SKUs; unknown observed SKUs cannot satisfy this list.
    pub skus: Vec<String>,
    /// Features required by the artifact or claim.
    pub features: Vec<String>,
}

/// CPU identity recorded by the execution authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CpuIdentity {
    /// Observed vendor or architecture implementer.
    pub vendor: String,
    /// Observed family/model or implementer/part identity.
    pub model: String,
    /// Exact SKU when exposed by the environment.
    pub sku: Option<String>,
    /// Stepping or revision when exposed.
    pub revision: Option<String>,
    /// Microcode revision when exposed.
    pub microcode: Option<String>,
    /// Observed CPU features.
    pub features: Vec<String>,
}

/// Constraints on one layer of a target environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerProfile {
    /// Required platform; an unconstrained outer host may omit it.
    pub platform: Option<Platform>,
    /// Backend-specific constraints.
    pub backend: Backend,
    /// CPU compatibility predicates.
    pub cpu: CpuScope,
}

/// Observed identity of one layer of a target environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerInventory {
    /// Actual execution architecture and operating system.
    pub platform: Platform,
    /// Actual backend identity, including concrete versions.
    pub backend: Backend,
    /// Actual CPU identity and features.
    pub cpu: CpuIdentity,
    /// Host kernel identity when the layer executes a kernel.
    pub kernel_release: Option<String>,
}

/// Boot implementations admitted by the current system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootImplementation {
    /// UEFI systemd-boot launches an authenticated unified kernel image.
    SystemdBootUki,
    /// Linux container entrypoint running under the host kernel.
    LinuxContainer,
    /// Native process or direct kernel test without a qualified image boot claim.
    Native,
}

/// Security conditions required by a scope or observed in an execution.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityState {
    /// UEFI authenticated boot is required or active.
    pub secure_boot: bool,
    /// TPM-backed boot measurement is required or active.
    pub measured_boot: bool,
    /// Verified immutable root storage is required or active.
    pub verity: bool,
    /// Persistent state encryption is required or active.
    pub encrypted_state: bool,
    /// Firmware and TPM state persist across cold boots.
    pub persistent_firmware: bool,
}

/// Minimum or observed resources of the subject environment.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    /// Number of logical CPUs available to the subject.
    pub cpus: u64,
    /// Available memory in MiB.
    pub memory_mib: u64,
    /// Available persistent storage in MiB.
    pub disk_mib: u64,
}

/// Stage at which the image must make a device driver available.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootStage {
    /// Initial ramdisk before switch-root.
    Initrd,
    /// Normal Linux userspace.
    Runtime,
    /// Authenticated recovery environment.
    Recovery,
}

/// Required device and driver behavior within a compatibility scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequirement {
    /// Linux driver name, normalized with underscores.
    pub driver: String,
    /// Bus identity when restricted, such as pci, usb, virtio or platform.
    pub bus: Option<String>,
    /// Required vendor/implementer identity when restricted.
    pub vendor: Option<String>,
    /// Required product/device identity when restricted.
    pub product: Option<String>,
    /// Required hardware revision when restricted.
    pub revision: Option<String>,
    /// Driver availability stage required by the function.
    pub stage: BootStage,
    /// Firmware paths that must be present at the required stage.
    pub firmware: Vec<String>,
}

/// Device identity and bound driver observed during execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInventory {
    /// Stable address within this machine inventory.
    pub address: String,
    /// Observed bus.
    pub bus: String,
    /// Observed vendor/implementer identity when exposed.
    pub vendor: Option<String>,
    /// Observed product/device identity when exposed.
    pub product: Option<String>,
    /// Observed revision when exposed.
    pub revision: Option<String>,
    /// Bound driver, rather than an available but unused module.
    pub driver: String,
    /// Device firmware revision when exposed.
    pub firmware_revision: Option<String>,
}

/// Typed compatibility scope of a release target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentProfile {
    /// Ordered outer-host-to-subject topology.
    pub layers: Vec<LayerProfile>,
    /// Required boot implementation; no automatic substitution is permitted.
    pub boot: BootImplementation,
    /// Required security properties of the current boot configuration.
    pub security: SecurityState,
    /// Minimum resources for the execution.
    pub resources: Resources,
    /// Device and boot-stage driver requirements.
    pub devices: Vec<DeviceRequirement>,
    /// Required values in the resolved, built kernel configuration.
    pub kernel_options: BTreeMap<String, String>,
}

/// Concrete environment bound into retained qualification evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInventory {
    /// Exact inventory schema.
    pub schema_version: String,
    /// Ordered observed execution topology.
    pub layers: Vec<LayerInventory>,
    /// Observed boot implementation.
    pub boot: BootImplementation,
    /// Firmware implementation and version when applicable.
    pub firmware: Option<String>,
    /// Observed boot security state.
    pub security: SecurityState,
    /// Measured available resources.
    pub resources: Resources,
    /// Observed devices and driver bindings.
    pub devices: Vec<DeviceInventory>,
    /// Digest of the subject's built image capability document, when applicable.
    pub image_capabilities_digest: Option<Sha256Digest>,
}

impl EnvironmentProfile {
    /// Validates scope structure without requiring a physical machine.
    ///
    /// # Errors
    /// Returns an error for an empty topology, inconsistent acceleration,
    /// malformed identities or invalid device/kernel requirements.
    pub fn validate(&self, platform: Platform) -> Result<()> {
        if self.layers.is_empty() || self.layers.len() > 8 {
            bail!("environment requires one through eight explicit layers");
        }
        if self.layers.last().and_then(|layer| layer.platform) != Some(platform) {
            bail!("environment subject platform differs from its target");
        }
        for (index, layer) in self.layers.iter().enumerate() {
            layer.backend.validate(false)?;
            if index != 0 && layer.platform.is_none() {
                bail!("only the outer execution host may have an unconstrained platform");
            }
            if (index == 0
                && matches!(
                    layer.backend,
                    Backend::Qemu { .. } | Backend::Container { .. }
                ))
                || (index != 0
                    && matches!(
                        layer.backend,
                        Backend::Physical { .. } | Backend::Cloud { .. }
                    ))
            {
                bail!("environment topology must begin with its physical or provider-managed host");
            }
            for values in [
                &layer.cpu.vendors,
                &layer.cpu.models,
                &layer.cpu.skus,
                &layer.cpu.features,
            ] {
                unique_text(values)?;
            }
            if matches!(
                layer.backend,
                Backend::Qemu {
                    accelerator: Accelerator::Kvm,
                    ..
                }
            ) && (index == 0 || self.layers[index - 1].platform != layer.platform)
            {
                bail!("KVM requires an explicit host with the guest's platform");
            }
            if matches!(layer.backend, Backend::Container { .. })
                && (index == 0 || self.layers[index - 1].platform != layer.platform)
            {
                bail!("native containers require an explicit matching host platform");
            }
        }
        if (self.boot == BootImplementation::LinuxContainer)
            != self
                .layers
                .last()
                .is_some_and(|layer| matches!(layer.backend, Backend::Container { .. }))
        {
            bail!("container boot requires a container subject layer");
        }
        for device in &self.devices {
            require_text(&device.driver)?;
            unique_text(&device.firmware)?;
        }
        for (key, value) in &self.kernel_options {
            if !key.starts_with("CONFIG_") || value.trim().is_empty() {
                bail!("invalid resolved-kernel requirement");
            }
        }
        Ok(())
    }

    /// Matches concrete evidence against every required environment dimension.
    ///
    /// # Errors
    /// Returns an error for unknown required identities, mismatched topology,
    /// insufficient resources, missing security properties or unbound devices.
    pub fn matches(&self, observed: &EnvironmentInventory) -> Result<()> {
        observed.validate()?;
        if self.layers.len() != observed.layers.len() || self.boot != observed.boot {
            bail!("observed execution topology or boot implementation differs from the scope");
        }
        for (scope, actual) in self.layers.iter().zip(&observed.layers) {
            if scope
                .platform
                .is_some_and(|platform| platform != actual.platform)
                || !scope.backend.matches(&actual.backend)
                || !contains_or_unconstrained(&scope.cpu.vendors, Some(&actual.cpu.vendor))
                || !contains_or_unconstrained(&scope.cpu.models, Some(&actual.cpu.model))
                || !contains_or_unconstrained(&scope.cpu.skus, actual.cpu.sku.as_deref())
                || !scope
                    .cpu
                    .features
                    .iter()
                    .all(|feature| actual.cpu.features.contains(feature))
            {
                bail!("observed backend, CPU or platform does not satisfy the compatibility scope");
            }
        }
        let required = &self.security;
        let actual = &observed.security;
        if (required.secure_boot && !actual.secure_boot)
            || (required.measured_boot && !actual.measured_boot)
            || (required.verity && !actual.verity)
            || (required.encrypted_state && !actual.encrypted_state)
            || (required.persistent_firmware && !actual.persistent_firmware)
            || observed.resources.cpus < self.resources.cpus
            || observed.resources.memory_mib < self.resources.memory_mib
            || observed.resources.disk_mib < self.resources.disk_mib
        {
            bail!("observed security state or resources do not satisfy the scope");
        }
        for required in &self.devices {
            if !observed.devices.iter().any(|actual| {
                required.driver == actual.driver
                    && optional_matches(&required.bus, &Some(actual.bus.clone()))
                    && optional_matches(&required.vendor, &actual.vendor)
                    && optional_matches(&required.product, &actual.product)
                    && optional_matches(&required.revision, &actual.revision)
            }) {
                bail!(
                    "required device/driver binding was not observed: {}",
                    required.driver
                );
            }
        }
        Ok(())
    }
}

impl EnvironmentInventory {
    /// Validates concrete inventory identities and topology.
    ///
    /// # Errors
    /// Returns an error for missing observed versions, empty identities,
    /// duplicate devices or a malformed inventory schema.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != INVENTORY_V1 || self.layers.is_empty() || self.layers.len() > 8 {
            bail!("invalid environment inventory schema or topology");
        }
        if self.resources.cpus == 0 || self.resources.memory_mib == 0 {
            bail!("execution inventory requires measured CPU and memory resources");
        }
        for (index, layer) in self.layers.iter().enumerate() {
            layer.backend.validate(true)?;
            if (index == 0
                && matches!(
                    layer.backend,
                    Backend::Qemu { .. } | Backend::Container { .. }
                ))
                || (index != 0
                    && matches!(
                        layer.backend,
                        Backend::Physical { .. } | Backend::Cloud { .. }
                    ))
            {
                bail!("observed topology lacks a valid host boundary");
            }
            if matches!(
                layer.backend,
                Backend::Container { .. }
                    | Backend::Qemu {
                        accelerator: Accelerator::Kvm,
                        ..
                    }
            ) && (index == 0 || self.layers[index - 1].platform != layer.platform)
            {
                bail!(
                    "native virtualization requires matching observed host and subject platforms"
                );
            }
            require_text(layer.kernel_release.as_deref().ok_or_else(|| {
                anyhow::anyhow!("execution inventory omits its kernel identity")
            })?)?;
            require_text(&layer.cpu.vendor)?;
            require_text(&layer.cpu.model)?;
            unique_text(&layer.cpu.features)?;
            for value in [&layer.cpu.sku, &layer.cpu.revision, &layer.cpu.microcode]
                .into_iter()
                .flatten()
            {
                require_text(value)?;
            }
        }
        if self.boot == BootImplementation::SystemdBootUki
            && (self
                .firmware
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
                || self.image_capabilities_digest.is_none())
        {
            bail!("image execution requires firmware and built-capability identities");
        }
        let mut addresses = BTreeSet::new();
        for device in &self.devices {
            require_text(&device.address)?;
            require_text(&device.driver)?;
            require_text(&device.bus)?;
            if !addresses.insert(&device.address) {
                bail!("duplicate observed device address");
            }
        }
        Ok(())
    }

    /// Computes the canonical inventory digest used by observations.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::of_bytes(crate::canonical::to_vec(self)?))
    }
}

impl Backend {
    fn validate(&self, observed: bool) -> Result<()> {
        let (required, optional): (Vec<&str>, Vec<&Option<String>>) = match self {
            Self::Physical { board, chipset } => (vec![], vec![board, chipset]),
            Self::Qemu {
                machine,
                machine_version,
                version,
                cpu_model,
                ..
            } => (vec![machine], vec![machine_version, version, cpu_model]),
            Self::Cloud {
                provider,
                service,
                sku,
                region,
            } => (vec![provider, service, sku], vec![region]),
            Self::Container {
                version,
                cgroup,
                network,
                volume,
                ..
            } => (vec![], vec![version, cgroup, network, volume]),
        };
        for value in required {
            require_text(value)?;
        }
        for value in optional {
            match value {
                Some(value) => require_text(value)?,
                None if observed => bail!("execution inventory omits a required backend identity"),
                None => {}
            }
        }
        Ok(())
    }

    fn matches(&self, actual: &Self) -> bool {
        match (self, actual) {
            (
                Self::Physical { board, chipset },
                Self::Physical {
                    board: ab,
                    chipset: ac,
                },
            ) => optional_matches(board, ab) && optional_matches(chipset, ac),
            (
                Self::Qemu {
                    machine,
                    machine_version,
                    version,
                    accelerator,
                    cpu_model,
                },
                Self::Qemu {
                    machine: am,
                    machine_version: avm,
                    version: av,
                    accelerator: aa,
                    cpu_model: ac,
                },
            ) => {
                machine == am
                    && accelerator == aa
                    && optional_matches(machine_version, avm)
                    && optional_matches(version, av)
                    && optional_matches(cpu_model, ac)
            }
            (
                Self::Cloud {
                    provider,
                    service,
                    sku,
                    region,
                },
                Self::Cloud {
                    provider: ap,
                    service: av,
                    sku: ask,
                    region: ar,
                },
            ) => provider == ap && service == av && sku == ask && optional_matches(region, ar),
            (
                Self::Container {
                    runtime,
                    version,
                    cgroup,
                    network,
                    volume,
                },
                Self::Container {
                    runtime: ar,
                    version: av,
                    cgroup: ac,
                    network: an,
                    volume: avo,
                },
            ) => {
                runtime == ar
                    && optional_matches(version, av)
                    && optional_matches(cgroup, ac)
                    && optional_matches(network, an)
                    && optional_matches(volume, avo)
            }
            _ => false,
        }
    }
}

fn optional_matches(required: &Option<String>, actual: &Option<String>) -> bool {
    required
        .as_ref()
        .is_none_or(|value| actual.as_ref() == Some(value))
}

fn contains_or_unconstrained(values: &[String], actual: Option<&str>) -> bool {
    values.is_empty() || actual.is_some_and(|actual| values.iter().any(|value| value == actual))
}

fn require_text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        bail!("environment identity must be bounded nonempty text");
    }
    Ok(())
}

fn unique_text(values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_text(value)?;
        if !seen.insert(value) {
            bail!("duplicate environment identity");
        }
    }
    Ok(())
}
