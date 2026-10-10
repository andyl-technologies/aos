//! Projects a complete admitted execution into retained RAM launch partitions.
//!
//! Known metadata and scratch floors come from checked format and allocation
//! bounds. Remaining resident and writable entitlement belongs explicitly to
//! QEMU/device state and writable overlays. It is never interpreted as a sparse
//! RAM peak or additional metadata proof. Authenticated native startup reports
//! its entire sealed inventory before guest execution, so the existing actor
//! can reclassify exact metadata and staging requirements from these retained
//! process/device allowances without increasing complete peaks.

use std::collections::BTreeMap;

use crate::host_operational::{
    HostRamBackingPartition, HostRamInventoryLimits, HostRamInventoryRegion,
    HostRamInventoryRegionClass, HostRamInventoryTopology,
};
use crucible_campaign::AttemptResourceLimits;
use crucible_linux_resource::ram_policy::HostResourceVector;

mod process_family;
pub use process_family::{
    HostRamProcessFamilyNativeAllowances, HostRamProcessFamilyPartition,
    HostRamProcessNativeAllowance,
};

/// Typed failure while retaining an exact host RAM launch contract.
#[derive(Debug, thiserror::Error)]
pub enum HostRamAdmissionError {
    /// A malformed, stale or insufficient launch contract cannot be retained.
    #[error("host RAM launch contract refused: {message}")]
    Contract {
        /// Diagnostic naming the violated ownership or resource invariant.
        message: String,
    },
    /// Logical geometry or a checked allocation bound is invalid.
    #[error("host RAM geometry refused: {0}")]
    Geometry(#[from] crucible_ram::RamError),
    /// Distinct spill, CAS, device and staging ownership cannot fit its peak.
    #[error("host RAM backing refused: {0}")]
    Backing(#[from] crate::host_operational::HostRamBackingError),
    /// The live operational registry refused resource ownership.
    #[error("host RAM authority refused: {0}")]
    Authority(#[from] crate::host_operational::HostOperationalError),
    /// Original-start supervision is unavailable or already terminal.
    #[error("host RAM supervision refused: {0}")]
    Supervision(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
    /// Concrete node host-service ownership cannot be reserved safely.
    #[error("host RAM service admission refused: {0}")]
    Services(#[from] crucible_linux_resource::host_services::HostServiceError),
}

impl HostRamAdmissionError {
    /// Constructs a diagnostic for a violated launch ownership invariant.
    pub fn contract(message: impl Into<String>) -> Self {
        Self::Contract {
            message: message.into(),
        }
    }
}

/// Explicit node startup task and descriptor entitlements retained before spawn.
///
/// The deployed contract includes native startup actors, independently owned
/// host services and prospective pager/fork service resources. Observed native
/// counts can refuse this contract, but cannot retroactively widen its peaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamBootstrapLimits {
    native_task_slots: u64,
    native_file_descriptors: u64,
    host_service_task_slots: u64,
    host_service_file_descriptors: u64,
    host_service_resident_bytes: u64,
    total_task_slots: u64,
    total_file_descriptors: u64,
}

impl HostRamBootstrapLimits {
    /// Validates independently authored finite task and descriptor ceilings.
    ///
    /// # Errors
    /// Rejects a zero task, descriptor or resident ceiling or an overflowing combined
    /// native and host-service entitlement.
    pub fn new(
        native_task_slots: u64,
        native_file_descriptors: u64,
        host_service_task_slots: u64,
        host_service_file_descriptors: u64,
        host_service_resident_bytes: u64,
    ) -> Result<Self, HostRamAdmissionError> {
        if native_task_slots == 0
            || native_file_descriptors == 0
            || host_service_task_slots == 0
            || host_service_file_descriptors == 0
            || host_service_resident_bytes == 0
        {
            return Err(HostRamAdmissionError::contract(
                "node bootstrap ceilings must be nonzero",
            ));
        }
        let total_task_slots = native_task_slots
            .checked_add(host_service_task_slots)
            .ok_or_else(|| HostRamAdmissionError::contract("node task entitlement overflow"))?;
        let total_file_descriptors = native_file_descriptors
            .checked_add(host_service_file_descriptors)
            .ok_or_else(|| {
                HostRamAdmissionError::contract("node descriptor entitlement overflow")
            })?;
        Ok(Self {
            native_task_slots,
            native_file_descriptors,
            host_service_task_slots,
            host_service_file_descriptors,
            host_service_resident_bytes,
            total_task_slots,
            total_file_descriptors,
        })
    }

    /// Returns the complete node task entitlement retained before process launch.
    pub const fn task_slots(self) -> u64 {
        self.total_task_slots
    }

    /// Returns the complete node descriptor entitlement retained before process launch.
    pub const fn file_descriptors(self) -> u64 {
        self.total_file_descriptors
    }

    /// Returns the native process task ceiling enforced by its cgroup.
    pub const fn native_task_slots(self) -> u64 {
        self.native_task_slots
    }

    /// Returns the native process descriptor ceiling enforced before execution.
    pub const fn native_file_descriptors(self) -> u64 {
        self.native_file_descriptors
    }

    /// Returns the independently retained host service task subset.
    pub const fn host_service_task_slots(self) -> u64 {
        self.host_service_task_slots
    }

    /// Returns the independently retained host service descriptor subset.
    pub const fn host_service_file_descriptors(self) -> u64 {
        self.host_service_file_descriptors
    }

    /// Returns the independently authored resident allowance outside QEMU.
    pub const fn host_service_resident_bytes(self) -> u64 {
        self.host_service_resident_bytes
    }
}

/// Declared shape of one node in a complete admitted launch world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionHostRamLaunchShape {
    /// Exact host-local node name used for operational owner lookup.
    pub node: String,
    /// Complete declared main RAM; sealed native topology remains authoritative.
    pub declared_ram_bytes: u64,
    /// Positive guest virtual CPU count.
    pub vcpus: u32,
}

/// Backend-owned physical floors for one declared launch node.
///
/// The host composition adapter computes these requirements for the selected
/// execution and preservation backend before the generic admission layer runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionHostRamLaunchRequirements {
    /// Complete resident floor and independently accounted metadata and staging.
    pub resource_floor: HostResourceVector,
    /// Exclusive physical quota for mutable preservation storage.
    pub spill_bytes: u64,
    /// Exclusive device and machine-state writable envelope.
    pub device_state_bytes: u64,
}

/// Kernel-enforced native peaks after separately retained host owners are removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionHostRamNativeWorldLimits {
    /// Complete native CPU allowance for this world.
    pub cpu_slots: u32,
    /// Resident peak shared by the world's QEMU processes and GPL services.
    pub resident_bytes: u64,
    /// Writable peak shared by native spill, VMState, devices and overlays.
    pub writable_bytes: u64,
    /// Independently retained host service and CAS transport resident bytes.
    pub outside_resident_bytes: u64,
    /// Independently retained immutable CAS graphs and staging bytes.
    pub outside_backing_bytes: u64,
}

/// Explicit retained node partitions inside one immutable attempt entitlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionHostRamPartition {
    /// Independently bounded resource subsets and complete peaks by node name.
    pub nodes: BTreeMap<String, HostResourceVector>,
    /// Disjoint disk-owner entitlements for the same admitted node names.
    pub backing: BTreeMap<String, HostRamBackingPartition>,
    /// Complete retained aggregate; resident and disk equal the admitted totals.
    pub ceiling: HostResourceVector,
}

/// Partitions all RAM, metadata, scratch and complete process entitlements.
///
/// Four live RAM versions may coexist during candidate extension; their canonical
/// byte bound is logical admission in the separately contained catalog service.
/// Node backing retains private spill, scratch and the fixed VMState baseline
/// before distributing writable-overlay headroom. One CAS operation per node
/// is initially admitted. Native kernel containment receives a disjoint subset of the
/// retained complete peak; host services and CAS transport remain separately
/// owned outside the QEMU cgroup.
///
/// # Errors
/// Returns a diagnostic for malformed or duplicate shapes, arithmetic overflow,
/// or an admitted total below the complete required floor.
pub fn partition_host_ram_launch_resources(
    shapes: &[ProductionHostRamLaunchShape],
    admitted: AttemptResourceLimits,
    bootstrap: HostRamBootstrapLimits,
    requirements: &BTreeMap<String, ProductionHostRamLaunchRequirements>,
) -> Result<ProductionHostRamPartition, HostRamAdmissionError> {
    if shapes.is_empty() {
        return Err(HostRamAdmissionError::contract(
            "host RAM admission requires a complete nonempty world",
        ));
    }

    if requirements.len() != shapes.len() {
        return Err(HostRamAdmissionError::contract(
            "backend requirements must cover the complete world",
        ));
    }

    let mut nodes = BTreeMap::new();
    let mut backing = BTreeMap::new();
    let mut ceiling = HostResourceVector::default();
    for shape in shapes {
        if shape.node.is_empty()
            || shape.vcpus == 0
            || shape.declared_ram_bytes == 0
            || !shape.declared_ram_bytes.is_multiple_of(1024 * 1024)
        {
            return Err(HostRamAdmissionError::contract(
                "host RAM admission has an invalid declared shape",
            ));
        }
        let backend = requirements.get(&shape.node).ok_or_else(|| {
            HostRamAdmissionError::contract("node has no declared backend resource requirements")
        })?;
        let mut resources = backend.resource_floor;
        if resources.metadata_bytes == 0
            || resources.staging_bytes == 0
            || resources.paging_io_slots == 0
            || backend.spill_bytes == 0
            || backend.device_state_bytes == 0
            || resources
                .metadata_bytes
                .checked_add(resources.staging_bytes)
                .and_then(|bytes| bytes.checked_add(shape.declared_ram_bytes))
                .is_none_or(|floor| floor > resources.resident_peak_bytes)
        {
            return Err(HostRamAdmissionError::contract(
                "backend resource requirements do not contain their declared RAM floor",
            ));
        }
        resources.resident_peak_bytes = resources
            .resident_peak_bytes
            .checked_add(bootstrap.host_service_resident_bytes())
            .ok_or_else(|| {
                HostRamAdmissionError::contract("host service resident entitlement overflow")
            })?;
        let topology = HostRamInventoryTopology::new(
            vec![HostRamInventoryRegion::new(
                "declared-main",
                HostRamInventoryRegionClass::MutableMain,
                shape.declared_ram_bytes,
            )?],
            HostRamInventoryLimits::default(),
        )?;
        let disk = HostRamBackingPartition::required(
            &topology,
            backend.spill_bytes,
            resources.staging_bytes,
            backend.device_state_bytes,
        )?;
        resources.backing_peak_bytes = disk.peak_bytes;
        resources.cpu_slots = u64::from(shape.vcpus);
        resources.task_slots = bootstrap.task_slots();
        resources.file_descriptors = bootstrap.file_descriptors();

        if nodes.insert(shape.node.clone(), resources).is_some() {
            return Err(HostRamAdmissionError::contract(
                "host RAM admission repeats a node name",
            ));
        }
        backing.insert(shape.node.clone(), disk);
        add_resources(&mut ceiling, resources)?;
    }
    if ceiling.cpu_slots > u64::from(admitted.maximum_vcpus()) {
        return Err(HostRamAdmissionError::contract(
            "host RAM world exceeds admitted CPU slots",
        ));
    }
    let resident_surplus = admitted
        .maximum_resident_bytes()
        .checked_sub(ceiling.resident_peak_bytes)
        .ok_or_else(|| {
            HostRamAdmissionError::contract(
                "host RAM metadata, scratch and full guest peak exceed admission",
            )
        })?;
    let disk_surplus = admitted
        .maximum_disk_bytes()
        .checked_sub(ceiling.backing_peak_bytes)
        .ok_or_else(|| {
            HostRamAdmissionError::contract(
                "host RAM live versions and VMState backing exceed admission",
            )
        })?;
    let count = u64::try_from(nodes.len())
        .map_err(|_| HostRamAdmissionError::contract("host RAM node inventory overflow"))?;
    for (index, resources) in nodes.values_mut().enumerate() {
        let index = u64::try_from(index)
            .map_err(|_| HostRamAdmissionError::contract("host RAM node index overflow"))?;
        resources.resident_peak_bytes +=
            resident_surplus / count + u64::from(index < resident_surplus % count);
        resources.backing_peak_bytes +=
            disk_surplus / count + u64::from(index < disk_surplus % count);
    }
    ceiling.resident_peak_bytes = admitted.maximum_resident_bytes();
    ceiling.backing_peak_bytes = admitted.maximum_disk_bytes();

    for (node, resources) in &nodes {
        let disk = backing
            .get_mut(node)
            .ok_or_else(|| HostRamAdmissionError::contract("node backing partition is missing"))?;
        *disk = disk.within_peak(resources.backing_peak_bytes)?;
    }
    Ok(ProductionHostRamPartition {
        nodes,
        backing,
        ceiling,
    })
}

fn add_resources(
    total: &mut HostResourceVector,
    additional: HostResourceVector,
) -> Result<(), HostRamAdmissionError> {
    macro_rules! add {
        ($($field:ident),+ $(,)?) => {$(
            total.$field = total.$field.checked_add(additional.$field)
                .ok_or_else(|| HostRamAdmissionError::contract(format!("host RAM {} aggregate overflow", stringify!($field))))?;
        )+};
    }
    add!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots,
        cpu_slots,
        task_slots,
        file_descriptors
    );
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn shapes() -> Vec<ProductionHostRamLaunchShape> {
        ["a", "b"]
            .into_iter()
            .map(|node| ProductionHostRamLaunchShape {
                node: node.into(),
                declared_ram_bytes: 64 * 1024 * 1024,
                vcpus: 1,
            })
            .collect()
    }

    fn fixture_requirements() -> BTreeMap<String, ProductionHostRamLaunchRequirements> {
        shapes()
            .into_iter()
            .map(|shape| {
                (
                    shape.node,
                    ProductionHostRamLaunchRequirements {
                        resource_floor: HostResourceVector {
                            resident_peak_bytes: 96 << 20,
                            metadata_bytes: 24 << 20,
                            staging_bytes: 4 << 20,
                            paging_io_slots: 1,
                            ..HostResourceVector::default()
                        },
                        spill_bytes: 128 << 20,
                        device_state_bytes: 512 << 20,
                    },
                )
            })
            .collect()
    }

    fn fixture_bootstrap_limits() -> HostRamBootstrapLimits {
        HostRamBootstrapLimits::new(64, 128, 4, 32, 8 * 1024 * 1024).unwrap()
    }

    #[test]
    fn bootstrap_contract_retains_native_and_service_scopes_without_overflow() {
        let limits = fixture_bootstrap_limits();

        assert_eq!(limits.native_task_slots(), 64);
        assert_eq!(limits.native_file_descriptors(), 128);
        assert_eq!(limits.host_service_task_slots(), 4);
        assert_eq!(limits.host_service_file_descriptors(), 32);
        assert_eq!(limits.task_slots(), 68);
        assert_eq!(limits.file_descriptors(), 160);
        assert_eq!(limits.host_service_resident_bytes(), 8 * 1024 * 1024);
        assert!(HostRamBootstrapLimits::new(64, 128, 4, 32, 0).is_err());

        for invalid in [
            (0, 128, 4, 32),
            (64, 0, 4, 32),
            (64, 128, 0, 32),
            (64, 128, 4, 0),
            (u64::MAX, 128, 1, 32),
            (64, u64::MAX, 4, 1),
        ] {
            assert!(
                HostRamBootstrapLimits::new(
                    invalid.0,
                    invalid.1,
                    invalid.2,
                    invalid.3,
                    8 * 1024 * 1024
                )
                .is_err()
            );
        }
    }

    #[test]
    fn complete_partition_retains_all_entitlement_and_nonzero_subsets() {
        let admitted = AttemptResourceLimits::new(2, 512 << 20, 2 << 30, 100).unwrap();
        let partition = partition_host_ram_launch_resources(
            &shapes(),
            admitted,
            fixture_bootstrap_limits(),
            &fixture_requirements(),
        )
        .unwrap();
        let mut sum = HostResourceVector::default();
        for resources in partition.nodes.values() {
            assert!(resources.metadata_bytes > 0);
            assert!(resources.staging_bytes > 0);
            assert!(resources.resident_peak_bytes > 64 << 20);
            assert!(resources.backing_peak_bytes > 256 << 20);
            add_resources(&mut sum, *resources).unwrap();
        }
        assert_eq!(sum, partition.ceiling);
        assert_eq!(sum.resident_peak_bytes, admitted.maximum_resident_bytes());
        assert_eq!(sum.backing_peak_bytes, admitted.maximum_disk_bytes());
        for (node, disk) in &partition.backing {
            assert_eq!(disk.peak_bytes, partition.nodes[node].backing_peak_bytes);
            assert_eq!(disk.spill_bytes, 2 * 64 * 1024 * 1024);
            assert!(disk.canonical_capture_bytes > 4 * 64 * 1024 * 1024);
        }
    }

    #[test]
    fn guest_only_peak_and_incomplete_backing_refuse_before_launch() {
        let guest_only = AttemptResourceLimits::new(2, 128 << 20, 2 << 30, 100).unwrap();
        assert!(
            partition_host_ram_launch_resources(
                &shapes(),
                guest_only,
                fixture_bootstrap_limits(),
                &fixture_requirements()
            )
            .is_err()
        );
        let insufficient_disk = AttemptResourceLimits::new(2, 512 << 20, 128 << 20, 100).unwrap();
        assert!(
            partition_host_ram_launch_resources(
                &shapes(),
                insufficient_disk,
                fixture_bootstrap_limits(),
                &fixture_requirements(),
            )
            .is_err()
        );
        let mut duplicate = shapes();
        duplicate[1].node = duplicate[0].node.clone();
        assert!(
            partition_host_ram_launch_resources(
                &duplicate,
                AttemptResourceLimits::new(2, 512 << 20, 2 << 30, 100).unwrap(),
                fixture_bootstrap_limits(),
                &fixture_requirements(),
            )
            .is_err()
        );
    }
}
