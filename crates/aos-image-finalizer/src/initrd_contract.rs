//! Closed stage and handoff contract for an unsigned normal-initrd input.
//!
//! The contract records the exact archive identity and the stage-1 dependency
//! roots that the existing systemd initrd builder assembled. It describes the
//! existing switch-root handoff; it does not schedule boot work. External
//! finalization rebuilds the archive after module signing and records those
//! final bytes separately, so this digest remains input-assembly provenance.
//!
//! ```json
//! {"schema_version":"aos.boot.initrd-stage-contract/v1",
//!  "stage":"initrd","platform":"x86_64-linux",
//!  "artifact":{"path":"initrd.img","size_bytes":1,"sha256":"sha256:..."},
//!  "dependency_roots":[],"rendered_units":[],"rendered_networks":[],
//!  "load_modules":[],"masked_units":[],"handoff":{"to_stage":"host"}}
//! ```

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use aos_release::artifact::{BundlePath, require_identifier, require_store_path};
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use serde::{Deserialize, Serialize};

/// Schema for a normal initrd's exact stage and switch-root contract.
pub const INITRD_STAGE_CONTRACT_V1: &str = "aos.boot.initrd-stage-contract/v1";

const MAX_LIST_ITEMS: usize = 4096;

/// Execution stages admitted by the initrd artifact contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactExecutionStage {
    /// Runs while constructing an immutable artifact.
    Build,
    /// Runs before switch-root under the initrd system manager.
    Initrd,
    /// Runs after switch-root under the host system manager.
    Host,
}

/// Closed purposes for exact store roots consumed by initrd assembly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InitrdDependencyKind {
    /// Feature-specific runtime package added by another initrd module.
    ExtraPackage,
    /// Firmware package copied into the initrd.
    FirmwarePackage,
    /// Kernel output supplying the exact module tree.
    Kernel,
    /// Out-of-tree kernel module package.
    KernelModulePackage,
    /// Rendered stage-1 systemd-networkd configuration.
    NetworkConfiguration,
    /// Runtime package whose closure remains available during stage 1.
    RuntimePackage,
    /// Rendered stage-1 systemd unit tree.
    UnitConfiguration,
}

/// One exact store root and the earliest execution stage at which it exists.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitrdDependencyRootV1 {
    /// Classifies why the root enters the initrd assembly.
    pub kind: InitrdDependencyKind,
    /// Exact non-derivation Nix store output.
    pub store_path: String,
    /// Declares the stage in which the root is available.
    pub available_stage: ArtifactExecutionStage,
}

/// Exact normal-initrd archive bytes described by the contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitrdArtifactV1 {
    /// Stable path relative to the initrd derivation output.
    pub path: BundlePath,
    /// Exact archive length.
    pub size_bytes: u64,
    /// SHA-256 of the exact compressed archive bytes.
    pub sha256: Sha256Digest,
}

/// One mount carried through the existing systemd switch-root operation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreservedMountV1 {
    /// Path as seen by the initrd manager.
    pub initrd_path: String,
    /// Path as seen by the receiving host manager.
    pub host_path: String,
}

/// One durable state root populated by stage 1 and reopened by stage 2.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableStateRootV1 {
    /// Path as seen by the initrd manager.
    pub initrd_path: String,
    /// Path as seen by the receiving host manager.
    pub host_path: String,
}

/// Existing systemd switch-root handoff represented as data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitrdHandoffV1 {
    /// Receiving execution stage.
    pub to_stage: ArtifactExecutionStage,
    /// Existing handoff mechanism.
    pub mechanism: String,
    /// Target whose successful transaction gates switch-root.
    pub completion_target: String,
    /// Boot-substrate units that must be present and ordered before completion.
    pub required_units: Vec<String>,
    /// Mounts carried through the existing switch-root implementation.
    pub preserved_mounts: Vec<PreservedMountV1>,
    /// Durable roots whose logical identity survives the handoff.
    pub durable_state_roots: Vec<DurableStateRootV1>,
    /// Whether a process-private handle may cross the stage boundary.
    pub transferable_handles: bool,
    /// Whether the receiving stage must independently authorize resources.
    pub receiving_stage_reauthorizes: bool,
    /// Whether the receiving stage must reacquire process-local handles.
    pub receiving_stage_reacquires: bool,
}

/// Complete unsigned normal-initrd contract emitted by the existing builder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitrdStageContractV1 {
    /// Carries [`INITRD_STAGE_CONTRACT_V1`].
    pub schema_version: String,
    /// Exact execution stage supplied by this artifact.
    pub stage: ArtifactExecutionStage,
    /// Linux target for the archive contents.
    pub platform: Platform,
    /// Exact kernel release whose module tree is present.
    pub kernel_release: String,
    /// Exact compressed archive identity.
    pub artifact: InitrdArtifactV1,
    /// Sorted exact roots from which the initrd was assembled and their first
    /// available execution stage.
    pub dependency_roots: Vec<InitrdDependencyRootV1>,
    /// Sorted unit files rendered into the stage-1 manager.
    pub rendered_units: Vec<String>,
    /// Sorted network files rendered into stage 1.
    pub rendered_networks: Vec<String>,
    /// Sorted kernel module names requested during stage 1.
    pub load_modules: Vec<String>,
    /// Sorted unit names masked in stage 1.
    pub masked_units: Vec<String>,
    /// Checked switch-root boundary owned by the boot substrate.
    pub handoff: InitrdHandoffV1,
}

impl InitrdStageContractV1 {
    /// Validates stage availability, ordering inputs, and handoff semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or stage, malformed archive
    /// identity, late-stage or duplicate dependency, missing boot unit,
    /// noncanonical path, or a handoff that transfers handles or skips host
    /// authorization and reacquisition.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != INITRD_STAGE_CONTRACT_V1
            || self.stage != ArtifactExecutionStage::Initrd
            || !self.platform.supports_images()
        {
            bail!(
                "initrd contract requires the version-1 schema, initrd stage, and Linux platform"
            );
        }
        require_identifier(&self.kernel_release, "initrd kernel release")?;
        if self.artifact.path.as_str() != "initrd.img" || self.artifact.size_bytes == 0 {
            bail!("initrd contract requires a nonempty initrd.img artifact");
        }

        require_bounded_sorted_unique(&self.dependency_roots, "initrd dependency roots")?;
        if self.dependency_roots.is_empty() {
            bail!("initrd contract requires dependency roots");
        }
        for dependency in &self.dependency_roots {
            require_store_path(&dependency.store_path, false)?;
            if dependency.available_stage > ArtifactExecutionStage::Initrd {
                bail!("initrd dependency root is unavailable during the initrd stage");
            }
            let expected_stage = match dependency.kind {
                InitrdDependencyKind::ExtraPackage | InitrdDependencyKind::RuntimePackage => {
                    ArtifactExecutionStage::Initrd
                }
                InitrdDependencyKind::FirmwarePackage
                | InitrdDependencyKind::Kernel
                | InitrdDependencyKind::KernelModulePackage
                | InitrdDependencyKind::NetworkConfiguration
                | InitrdDependencyKind::UnitConfiguration => ArtifactExecutionStage::Build,
            };
            if dependency.available_stage != expected_stage {
                bail!("initrd dependency kind has the wrong availability stage");
            }
        }
        let count_kind = |kind| {
            self.dependency_roots
                .iter()
                .filter(|dependency| dependency.kind == kind)
                .count()
        };
        if count_kind(InitrdDependencyKind::Kernel) != 1
            || count_kind(InitrdDependencyKind::UnitConfiguration) != 1
        {
            bail!("initrd contract requires exactly one kernel and unit-configuration root");
        }
        let expected_network_roots = usize::from(!self.rendered_networks.is_empty());
        if count_kind(InitrdDependencyKind::NetworkConfiguration) != expected_network_roots {
            bail!("initrd network-configuration root differs from its rendered network inventory");
        }

        for (values, label) in [
            (&self.rendered_units, "rendered initrd units"),
            (&self.rendered_networks, "rendered initrd networks"),
            (&self.load_modules, "initrd load modules"),
            (&self.masked_units, "masked initrd units"),
        ] {
            require_bounded_sorted_unique(values, label)?;
            for value in values {
                require_identifier(value, label)?;
            }
        }

        self.handoff
            .validate(&self.rendered_units, &self.masked_units)
    }
}

impl InitrdHandoffV1 {
    fn validate(&self, rendered_units: &[String], masked_units: &[String]) -> Result<()> {
        if self.to_stage != ArtifactExecutionStage::Host
            || self.mechanism != "systemd-switch-root"
            || self.completion_target != "initrd-fs.target"
        {
            bail!("initrd handoff must use the supported initrd-to-host systemd boundary");
        }
        if self.transferable_handles
            || !self.receiving_stage_reauthorizes
            || !self.receiving_stage_reacquires
        {
            bail!(
                "initrd handoff cannot transfer handles and requires host reauthorization and reacquisition"
            );
        }

        require_bounded_sorted_unique(&self.required_units, "initrd handoff units")?;
        if self.required_units.is_empty() {
            bail!("initrd handoff requires at least one boot-substrate unit");
        }
        let rendered = rendered_units
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let masked = masked_units
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for unit in &self.required_units {
            require_identifier(unit, "initrd handoff unit")?;
            if !rendered.contains(unit.as_str()) {
                bail!("initrd handoff unit is absent from the rendered stage-1 manager");
            }
            if masked.contains(unit.as_str()) {
                bail!("initrd handoff unit is masked in the stage-1 manager");
            }
        }

        require_bounded_sorted_unique(&self.preserved_mounts, "preserved initrd mounts")?;
        require_bounded_sorted_unique(&self.durable_state_roots, "initrd durable state roots")?;
        if self.preserved_mounts.is_empty() || self.durable_state_roots.is_empty() {
            bail!("initrd handoff must identify preserved mounts and durable state roots");
        }
        let mut initrd_mounts = BTreeSet::new();
        let mut host_mounts = BTreeSet::new();
        for mount in &self.preserved_mounts {
            require_absolute_normal_path(&mount.initrd_path, "initrd mount path")?;
            require_absolute_normal_path(&mount.host_path, "host mount path")?;
            if !initrd_mounts.insert(mount.initrd_path.as_str())
                || !host_mounts.insert(mount.host_path.as_str())
            {
                bail!("initrd handoff contains an ambiguous preserved-mount mapping");
            }
        }
        let mut initrd_state_roots = BTreeSet::new();
        let mut host_state_roots = BTreeSet::new();
        for root in &self.durable_state_roots {
            require_absolute_normal_path(&root.initrd_path, "initrd state path")?;
            require_absolute_normal_path(&root.host_path, "host state path")?;
            if !initrd_state_roots.insert(root.initrd_path.as_str())
                || !host_state_roots.insert(root.host_path.as_str())
            {
                bail!("initrd handoff contains an ambiguous durable-state mapping");
            }
            if !self.preserved_mounts.iter().any(|mount| {
                root.initrd_path
                    .strip_prefix(&mount.initrd_path)
                    .is_some_and(|suffix| {
                        suffix.starts_with('/')
                            && root.host_path == format!("{}{}", mount.host_path, suffix)
                    })
            }) {
                bail!("initrd durable state root is outside its preserved mount mapping");
            }
        }
        Ok(())
    }
}

fn require_bounded_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.len() > MAX_LIST_ITEMS {
        bail!("{label} exceeds the {MAX_LIST_ITEMS}-item limit");
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{label} must be sorted and unique");
    }
    Ok(())
}

fn require_absolute_normal_path(value: &str, label: &str) -> Result<()> {
    if value.len() > 4096
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\0')
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        bail!("{label} must be a bounded normalized absolute path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency(
        kind: InitrdDependencyKind,
        store_path: &str,
        available_stage: ArtifactExecutionStage,
    ) -> InitrdDependencyRootV1 {
        InitrdDependencyRootV1 {
            kind,
            store_path: store_path.to_owned(),
            available_stage,
        }
    }

    fn complete_contract() -> InitrdStageContractV1 {
        let shared_package = "/nix/store/00000000000000000000000000000000-shared";

        InitrdStageContractV1 {
            schema_version: INITRD_STAGE_CONTRACT_V1.to_owned(),
            stage: ArtifactExecutionStage::Initrd,
            platform: Platform::X86_64Linux,
            kernel_release: "6.18.33".to_owned(),
            artifact: InitrdArtifactV1 {
                path: BundlePath::parse("initrd.img").unwrap_or_else(|error| panic!("{error}")),
                size_bytes: 1,
                sha256: Sha256Digest::of_bytes(b"initrd"),
            },
            dependency_roots: vec![
                dependency(
                    InitrdDependencyKind::ExtraPackage,
                    shared_package,
                    ArtifactExecutionStage::Initrd,
                ),
                dependency(
                    InitrdDependencyKind::FirmwarePackage,
                    "/nix/store/11111111111111111111111111111111-firmware",
                    ArtifactExecutionStage::Build,
                ),
                dependency(
                    InitrdDependencyKind::Kernel,
                    "/nix/store/22222222222222222222222222222222-kernel",
                    ArtifactExecutionStage::Build,
                ),
                dependency(
                    InitrdDependencyKind::KernelModulePackage,
                    "/nix/store/33333333333333333333333333333333-kernel-module",
                    ArtifactExecutionStage::Build,
                ),
                dependency(
                    InitrdDependencyKind::NetworkConfiguration,
                    "/nix/store/44444444444444444444444444444444-network",
                    ArtifactExecutionStage::Build,
                ),
                dependency(
                    InitrdDependencyKind::RuntimePackage,
                    shared_package,
                    ArtifactExecutionStage::Initrd,
                ),
                dependency(
                    InitrdDependencyKind::UnitConfiguration,
                    "/nix/store/55555555555555555555555555555555-units",
                    ArtifactExecutionStage::Build,
                ),
            ],
            rendered_units: vec!["aos-config-seed.service".to_owned()],
            rendered_networks: vec!["80-dhcp.network".to_owned()],
            load_modules: vec![],
            masked_units: vec![],
            handoff: InitrdHandoffV1 {
                to_stage: ArtifactExecutionStage::Host,
                mechanism: "systemd-switch-root".to_owned(),
                completion_target: "initrd-fs.target".to_owned(),
                required_units: vec!["aos-config-seed.service".to_owned()],
                preserved_mounts: vec![PreservedMountV1 {
                    initrd_path: "/sysroot/var".to_owned(),
                    host_path: "/var".to_owned(),
                }],
                durable_state_roots: vec![DurableStateRootV1 {
                    initrd_path: "/sysroot/var/lib/aos".to_owned(),
                    host_path: "/var/lib/aos".to_owned(),
                }],
                transferable_handles: false,
                receiving_stage_reauthorizes: true,
                receiving_stage_reacquires: true,
            },
        }
    }

    #[test]
    fn accepts_one_store_path_in_distinct_dependency_roles() {
        assert!(complete_contract().validate().is_ok());
    }

    #[test]
    fn rejects_a_duplicate_dependency_tuple() {
        let mut contract = complete_contract();
        contract
            .dependency_roots
            .insert(1, contract.dependency_roots[0].clone());

        assert!(contract.validate().is_err());
    }

    #[test]
    fn requires_the_fixed_stage_for_every_dependency_kind() {
        let contract = complete_contract();

        for root_index in 0..contract.dependency_roots.len() {
            let mut changed = contract.clone();
            changed.dependency_roots[root_index].available_stage =
                match changed.dependency_roots[root_index].available_stage {
                    ArtifactExecutionStage::Build => ArtifactExecutionStage::Initrd,
                    ArtifactExecutionStage::Initrd => ArtifactExecutionStage::Build,
                    ArtifactExecutionStage::Host => unreachable!(),
                };

            assert!(changed.validate().is_err());
        }
    }
}
