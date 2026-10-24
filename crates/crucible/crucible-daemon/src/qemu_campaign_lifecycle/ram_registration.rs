//! Binds complete admitted world partitions to live operational RAM owners.
//!
//! The existing executor actor retains each partition before native launch.
//! Exact sealed topology and native metadata subsequently reclassify retained
//! resource subsets through authenticated independent pager setup, before the
//! CPU can run. Neither declared main RAM nor a socket qualifies eviction safety
//! or a lower execution peak.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::vm_lifecycle::ProductionHostRamRegistrationFactory;
use crucible_control_api::host_operational::{
    HostRamAdmissionError, HostRamBootstrapLimits, HostRamProcessFamilyPartition,
    ProductionHostRamLaunchRequirements, ProductionHostRamLaunchShape,
    ProductionHostRamNativeNodeLimits, ProductionHostRamNativeWorldIdentity,
    ProductionHostRamNativeWorldLimits, ProductionHostRamPartition,
    partition_host_ram_launch_resources,
};
use crucible_campaign::AttemptResourceLimits;
use crucible_host_resources::host_supervision::HostOperationSupervisor;
use crucible_host_resources::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_qemu_host::ram_control::RamControlRegistration;

use crate::{AttemptExecutionContext, HostOperationalRegistry};

mod park_drain_registration;
mod process_family;
pub(crate) use park_drain_registration::ConfiguredParkDrainRegistration;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(crate) use process_family::{ConfiguredStageOperation, StagePrepareError};

#[cfg(test)]
mod native_initial;

static NEXT_ARENA_GENERATION: AtomicU64 = AtomicU64::new(1);

struct PreparedWorld {
    // One fixed diagnostic cache/snapshot peak belongs to the Apache world
    // runtime, independent of QEMU's native metadata allowance.
    _fault_diagnostic_resources: crucible_host_resources::host_services::HostServiceLease,
    shapes: Vec<ProductionHostRamLaunchShape>,
    partition: ProductionHostRamPartition,
    registrars: std::collections::BTreeMap<
        String,
        Arc<dyn crucible_qemu_host::ram_control::RamControlRegistrar>,
    >,
    families: Vec<process_family::ConfiguredProcessFamily>,
    controller_leases: Vec<Option<crucible_host_resources::host_services::HostServiceLease>>,
    services: std::collections::BTreeMap<
        String,
        crucible_host_resources::host_services::HostServiceAllocator,
    >,
    // The new fixed family array is destroyed before this SAME host-service
    // lease; its inline supervisors never create another bank or deadline.
    _family_control_resources: crucible_host_resources::host_services::HostServiceLease,
}

fn native_node_outside(
    world: &PreparedWorld,
    node: &str,
    bootstrap: HostRamBootstrapLimits,
) -> Result<(u64, u64), HostRamAdmissionError> {
    let resources = world.partition.nodes.get(node).ok_or_else(|| {
        HostRamAdmissionError::contract("native node has no retained resource partition")
    })?;
    let resident = resources
        .paging_io_slots
        .checked_mul(crucible_qemu_host::ram_admission::RAM_CAS_OPERATION_SCRATCH_BYTES)
        .and_then(|bytes| bytes.checked_add(bootstrap.host_service_resident_bytes()))
        .ok_or_else(|| HostRamAdmissionError::contract("outside resident overflow"))?;
    let backing = world.partition.backing.get(node).ok_or_else(|| {
        HostRamAdmissionError::contract("native node has no retained backing partition")
    })?;
    Ok((resident, backing.staging_bytes))
}

struct AdmittedRamRegistrationFactory {
    #[cfg(test)]
    component_ram_facts: bool,
    initial_mode: HostRamMode,
    registry: HostOperationalRegistry,
    daemon_epoch: [u8; 32],
    owner_id: [u8; 32],
    retained_template: bool,
    admitted: AttemptResourceLimits,
    ceiling: HostResourceVector,
    bootstrap: HostRamBootstrapLimits,
    supervisor: HostOperationSupervisor,
    world: Mutex<Option<PreparedWorld>>,
}

/// Creates the shared registration allocator for an existing admitted operational owner.
///
/// # Errors
/// Refuses a detached context without its live registry, admitted owner identity,
/// or original-start host supervisor.
pub(crate) fn create_host_ram_registration_factory(
    context: &AttemptExecutionContext,
) -> Result<Arc<dyn ProductionHostRamRegistrationFactory>, HostRamAdmissionError> {
    let registration = create_registration_factory(context, HostRamMode::Managed)?;
    Ok(registration)
}

/// Creates setup's registration and its fixed later-stage issuer together.
///
/// Both aliases refer to the same existing factory allocation. The concrete
/// factory and its private original context remain hidden behind the pair.
///
/// # Errors
/// Refuses an absent, detached, or terminal original operational assignment.
pub(crate) fn create_host_ram_registration_with_park_owner(
    context: &AttemptExecutionContext,
) -> Result<
    (
        Arc<dyn ProductionHostRamRegistrationFactory>,
        ConfiguredParkDrainRegistration,
    ),
    HostRamAdmissionError,
> {
    let registration = create_registration_factory(context, HostRamMode::Managed)?;
    let companion =
        ConfiguredParkDrainRegistration::from_assignment(Arc::clone(&registration), context)?;
    Ok((registration, companion))
}

#[cfg(test)]
pub(crate) fn create_native_qualification_ram_registration_factory(
    context: &AttemptExecutionContext,
    mode: HostRamMode,
) -> Result<Arc<dyn ProductionHostRamRegistrationFactory>, HostRamAdmissionError> {
    if mode != HostRamMode::ResidentRequired || context.uses_component_ram_facts() {
        return Err(HostRamAdmissionError::contract(
            "strict child requires genuine native owner",
        ));
    }
    let registration = create_registration_factory(context, mode)?;
    Ok(registration)
}

fn create_registration_factory(
    context: &AttemptExecutionContext,
    initial_mode: HostRamMode,
) -> Result<Arc<AdmittedRamRegistrationFactory>, HostRamAdmissionError> {
    let registry = context
        .host_operational_registry()
        .cloned()
        .ok_or_else(|| {
            HostRamAdmissionError::contract("host RAM registry is not attached to this owner")
        })?;
    let owner_id = context.host_ram_owner_id().ok_or_else(|| {
        HostRamAdmissionError::contract("host RAM owner has no exact admitted reservation")
    })?;
    let ceiling = context.host_ram_resource_ceiling().ok_or_else(|| {
        HostRamAdmissionError::contract("host RAM owner has no immutable complete resource ceiling")
    })?;
    let supervisor = context
        .host_operation_supervisor()
        .cloned()
        .ok_or_else(|| {
            HostRamAdmissionError::contract("host RAM owner has no live host supervisor")
        })?;
    let bootstrap = context.host_ram_bootstrap_limits().ok_or_else(|| {
        HostRamAdmissionError::contract(
            "host RAM node bootstrap entitlements are not attached to this owner",
        )
    })?;

    // Physical backing includes spill and immutable CAS graphs even when the
    // original guest request declares no writable disk. This local partition
    // leaves the authenticated request and its modeled limits unchanged.
    let admitted = AttemptResourceLimits::new(
        u32::try_from(ceiling.cpu_slots).map_err(|_| {
            HostRamAdmissionError::contract("physical host CPU entitlement exceeds the node domain")
        })?,
        ceiling.resident_peak_bytes,
        ceiling.backing_peak_bytes,
        context.resources().maximum_execution_quanta(),
    )
    .map_err(|error| HostRamAdmissionError::contract(error.to_string()))?;

    Ok(Arc::new(AdmittedRamRegistrationFactory {
        #[cfg(test)]
        component_ram_facts: context.uses_component_ram_facts(),
        initial_mode,
        registry,
        daemon_epoch: context.host_daemon_epoch(),
        owner_id,
        retained_template: context.host_ram_retained_template(),
        admitted,
        ceiling,
        bootstrap,
        supervisor,
        world: Mutex::new(None),
    }))
}

/// Computes selected-backend floors at the host composition boundary.
pub(crate) fn host_ram_launch_requirements(
    shapes: &[ProductionHostRamLaunchShape],
) -> Result<
    std::collections::BTreeMap<String, ProductionHostRamLaunchRequirements>,
    HostRamAdmissionError,
> {
    shapes
        .iter()
        .map(|shape| {
            let memory_mib =
                u32::try_from(shape.declared_ram_bytes / (1024 * 1024)).map_err(|_| {
                    HostRamAdmissionError::contract("native memory shape exceeds its domain")
                })?;
            let vcpus = u16::try_from(shape.vcpus).map_err(|_| {
                HostRamAdmissionError::contract("native CPU shape exceeds its domain")
            })?;
            let topology = crucible_control_api::host_operational::HostRamInventoryTopology::new(
                vec![crucible_control_api::host_operational::HostRamInventoryRegion::new(
                    "declared-main",
                    crucible_control_api::host_operational::HostRamInventoryRegionClass::MutableMain,
                    shape.declared_ram_bytes,
                )?],
                crucible_control_api::host_operational::HostRamInventoryLimits::default(),
            )?;
            Ok((
                shape.node.clone(),
                ProductionHostRamLaunchRequirements {
                    resource_floor: crucible_qemu_host::ram_admission::known_ram_launch_requirements(
                        shape.declared_ram_bytes,
                        1,
                    )?,
                    spill_bytes: crucible_qemu_host::ram_admission::private_spill_quota_bytes(
                        &topology,
                    )?,
                    device_state_bytes:
                        crucible_qemu_host::QemuLaunchResourceRequirements::from_vm_shape(
                            memory_mib, vcpus, true,
                        )
                        .minimum_writable_bytes(),
                },
            ))
        })
        .collect()
}

impl ProductionHostRamRegistrationFactory for AdmittedRamRegistrationFactory {
    fn configure_world(
        &self,
        shapes: &[ProductionHostRamLaunchShape],
    ) -> Result<(), HostRamAdmissionError> {
        let mut shapes = shapes.to_vec();
        shapes.sort_by(|left, right| left.node.cmp(&right.node));
        let partition = partition_host_ram_launch_resources(
            &shapes,
            self.admitted,
            self.bootstrap,
            &host_ram_launch_requirements(&shapes)?,
        )?;
        if !partition.ceiling.fits(self.ceiling) {
            return Err(HostRamAdmissionError::contract(
                "complete host RAM world exceeds its authored owner ceiling",
            ));
        }
        let mut world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world allocation ownership is uncertain")
        })?;
        if let Some(existing) = &*world {
            return if existing.shapes == shapes && existing.partition == partition {
                Ok(())
            } else {
                Err(HostRamAdmissionError::contract(
                    "host RAM world allocation cannot change after preparation",
                ))
            };
        }

        self.registry
            .configure_owner(self.daemon_epoch, self.owner_id, self.ceiling)
            .map_err(HostRamAdmissionError::Authority)?;
        let services: std::collections::BTreeMap<_, _> = partition
            .nodes
            .keys()
            .map(|node| {
                Ok((
                    node.clone(),
                    crucible_host_resources::host_services::HostServiceAllocator::new(
                        self.bootstrap.host_service_task_slots(),
                        self.bootstrap.host_service_file_descriptors(),
                        self.bootstrap.host_service_resident_bytes(),
                    )?,
                ))
            })
            .collect::<Result<_, HostRamAdmissionError>>()?;
        let diagnostic_allocator = services.values().next().ok_or_else(|| {
            HostRamAdmissionError::contract("host RAM world has no diagnostic allocator")
        })?;
        let fault_diagnostic_resources = diagnostic_allocator.reserve_resources(
            0,
            0,
            crucible_qemu_host::MEMORY_SERVICE_EVIDENCE_RESIDENT_BYTES
                .checked_add(
                    crucible_host_resources::host_services::HostServiceLease::metadata_bytes(),
                )
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("fault diagnostic metadata size overflow")
                })?,
        )?;
        let family_bytes = shapes
            .len()
            .checked_mul(
                std::mem::size_of::<process_family::ConfiguredProcessFamily>()
                    + std::mem::size_of::<
                        Option<crucible_host_resources::host_services::HostServiceLease>,
                    >(),
            )
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| {
                bytes.checked_add(
                    crucible_host_resources::host_services::HostServiceLease::metadata_bytes(),
                )
            })
            .ok_or_else(|| {
                HostRamAdmissionError::contract("process family control extent overflow")
            })?;
        let family_control_resources =
            diagnostic_allocator.reserve_resources(0, 0, family_bytes)?;
        let mut families = Vec::with_capacity(shapes.len());
        let mut controller_leases = Vec::with_capacity(shapes.len());
        for shape in &shapes {
            controller_leases.push(None);
            let resources = partition.nodes.get(&shape.node).copied().ok_or_else(|| {
                HostRamAdmissionError::contract("configured family envelope is missing")
            })?;
            // The current backend declares one process. A retained template
            // does not authorize another full-vector generation; a staged
            // route must supply its matched floor before this initial issuance.
            families.push(process_family::ConfiguredProcessFamily::new(
                HostRamProcessFamilyPartition::single(resources)?,
                self.supervisor.clone(),
            ));
        }
        *world = Some(PreparedWorld {
            _fault_diagnostic_resources: fault_diagnostic_resources,
            registrars: shapes
                .iter()
                .map(|shape| (shape.node.clone(), self.initial_registrar()))
                .collect(),
            families,
            controller_leases,
            shapes,
            partition,
            services,
            _family_control_resources: family_control_resources,
        });
        Ok(())
    }

    fn bind_node_registrar(
        &self,
        node: &str,
        registrar: Arc<dyn crucible_qemu_host::ram_control::RamControlRegistrar>,
    ) -> Result<(), HostRamAdmissionError> {
        let mut world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM allocation ownership is uncertain")
        })?;
        let world = world
            .as_mut()
            .ok_or_else(|| HostRamAdmissionError::contract("world is not admitted"))?;
        let index = world.shapes.iter().position(|shape| shape.node == node);
        if index
            .and_then(|index| world.families.get(index))
            .is_none_or(|family| family.is_issued())
            || !world.registrars.contains_key(node)
        {
            return Err(HostRamAdmissionError::contract(
                "node registrar cannot replace a prepared or unknown node",
            ));
        }
        world.registrars.insert(node.to_owned(), registrar);
        Ok(())
    }

    fn native_world_limits(
        &self,
    ) -> Result<ProductionHostRamNativeWorldLimits, HostRamAdmissionError> {
        let world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world ownership is uncertain")
        })?;
        let world = world.as_ref().ok_or_else(|| {
            HostRamAdmissionError::contract("host RAM world has not been partitioned")
        })?;
        let mut outside_resident = 0_u64;
        let mut outside_backing = 0_u64;
        for (node, resources) in &world.partition.nodes {
            let host_scratch = resources
                .paging_io_slots
                .checked_mul(crucible_qemu_host::ram_admission::RAM_CAS_OPERATION_SCRATCH_BYTES)
                .ok_or_else(|| HostRamAdmissionError::contract("host CAS scratch overflow"))?;
            outside_resident = outside_resident
                .checked_add(self.bootstrap.host_service_resident_bytes())
                .and_then(|bytes| bytes.checked_add(host_scratch))
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("outside resident aggregate overflow")
                })?;
            let backing = world.partition.backing.get(node).ok_or_else(|| {
                HostRamAdmissionError::contract("native backing ownership is missing")
            })?;
            outside_backing = outside_backing
                .checked_add(backing.staging_bytes)
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("outside backing aggregate overflow")
                })?;
        }
        Ok(ProductionHostRamNativeWorldLimits {
            cpu_slots: u32::try_from(world.partition.ceiling.cpu_slots)
                .map_err(|_| HostRamAdmissionError::contract("native CPU aggregate overflow"))?,
            resident_bytes: self
                .admitted
                .maximum_resident_bytes()
                .checked_sub(outside_resident)
                .filter(|bytes| *bytes != 0)
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("native resident partition exhausted")
                })?,
            writable_bytes: self
                .admitted
                .maximum_disk_bytes()
                .checked_sub(outside_backing)
                .filter(|bytes| *bytes != 0)
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("native writable partition exhausted")
                })?,
            outside_resident_bytes: outside_resident,
            outside_backing_bytes: outside_backing,
        })
    }

    fn native_world_identity(
        &self,
    ) -> Result<ProductionHostRamNativeWorldIdentity, HostRamAdmissionError> {
        let world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world ownership is uncertain")
        })?;
        if world.is_none() || self.owner_id == [0; 32] || self.daemon_epoch == [0; 32] {
            return Err(HostRamAdmissionError::contract(
                "native world has no original assignment",
            ));
        }
        Ok(ProductionHostRamNativeWorldIdentity {
            owner: self.owner_id,
            selection: self.daemon_epoch,
        })
    }

    fn visit_native_nodes(
        &self,
        visitor: &mut dyn FnMut(
            &str,
            ProductionHostRamNativeNodeLimits,
        ) -> Result<(), HostRamAdmissionError>,
    ) -> Result<(), HostRamAdmissionError> {
        let world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world ownership is uncertain")
        })?;
        let world = world.as_ref().ok_or_else(|| {
            HostRamAdmissionError::contract("native world has not been partitioned")
        })?;
        // One physical contract clone has two mandatory descriptors and one
        // optional directory descriptor; its other aliases duplicate no FDs.
        let (source_host_descriptors, target_host_descriptors) =
            crucible_qemu_host::LinuxQemuAttemptHostFactory::normal_node_host_descriptor_peaks(
                self.bootstrap.native_file_descriptors(),
                3,
            )
            .map_err(|error| HostRamAdmissionError::contract(error.to_string()))?;
        for (name, complete) in &world.partition.nodes {
            let outside = native_node_outside(world, name, self.bootstrap)?;
            let resources = HostResourceVector {
                resident_peak_bytes: complete
                    .resident_peak_bytes
                    .checked_sub(outside.0)
                    .ok_or_else(|| {
                        HostRamAdmissionError::contract("native resident partition exhausted")
                    })?,
                backing_peak_bytes: complete
                    .backing_peak_bytes
                    .checked_sub(outside.1)
                    .ok_or_else(|| {
                        HostRamAdmissionError::contract("native backing partition exhausted")
                    })?,
                task_slots: self.bootstrap.native_task_slots(),
                file_descriptors: self.bootstrap.native_file_descriptors(),
                ..*complete
            };
            visitor(
                name,
                ProductionHostRamNativeNodeLimits {
                    node: node_identity(self.owner_id, name),
                    resources,
                    source_host_descriptors,
                    target_host_descriptors,
                },
            )?;
        }
        Ok(())
    }

    fn reserve_native_controller_resources(
        &self,
        node: &str,
    ) -> Result<
        Option<crucible_host_resources::host_services::HostServiceLease>,
        HostRamAdmissionError,
    > {
        let mut world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world ownership is uncertain")
        })?;
        let world = world.as_mut().ok_or_else(|| {
            HostRamAdmissionError::contract("native controller has no configured world")
        })?;
        let index = world
            .shapes
            .iter()
            .position(|shape| shape.node == node)
            .ok_or_else(|| {
                HostRamAdmissionError::contract("native controller has no configured node")
            })?;
        let services = world.services.get(node).ok_or_else(|| {
            HostRamAdmissionError::contract(
                "controller has no retained node host-service entitlement",
            )
        })?;
        let retained = world.controller_leases.get_mut(index).ok_or_else(|| {
            HostRamAdmissionError::contract("controller descriptor custody is uncertain")
        })?;
        if retained.is_none() {
            *retained = Some(services.reserve_resources(
                0,
                2,
                crucible_host_resources::host_services::HostServiceLease::metadata_bytes(),
            )?);
        }
        Ok(retained.clone())
    }

    fn bind_native_resource_controller(
        &self,
        node: &str,
        controller: Option<crucible_qemu_host::LinuxQemuNativeResourceController>,
    ) -> Result<(), HostRamAdmissionError> {
        #[cfg(test)]
        if self.component_ram_facts {
            if controller.is_some() {
                return Err(HostRamAdmissionError::contract(
                    "component facts cannot replace actual kernel authority",
                ));
            }
            return Ok(());
        }
        let controller = controller.ok_or_else(|| {
            HostRamAdmissionError::contract(
                "live RAM ownership requires a retained native kernel controller",
            )
        })?;
        let world = self.world.lock().map_err(|_| {
            HostRamAdmissionError::contract("host RAM world ownership is uncertain")
        })?;
        let world = world
            .as_ref()
            .ok_or_else(|| HostRamAdmissionError::contract("host RAM world was not partitioned"))?;
        let index = world
            .shapes
            .iter()
            .position(|shape| shape.node == node)
            .ok_or_else(|| {
                HostRamAdmissionError::contract("native controller has no configured node")
            })?;
        let resources = world.partition.nodes.get(node).copied().ok_or_else(|| {
            HostRamAdmissionError::contract("native controller has no retained node partition")
        })?;
        let outside = native_node_outside(world, node, self.bootstrap)?;
        let lease = world
            .controller_leases
            .get(index)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or_else(|| {
                HostRamAdmissionError::contract("node controller descriptors were not reserved")
            })?;
        self.registry
            .bind_native_node_resources(
                self.daemon_epoch,
                self.owner_id,
                node_identity(self.owner_id, node),
                controller,
                lease,
                resources,
                outside,
            )
            .map_err(HostRamAdmissionError::Authority)
    }

    fn prepare(
        &self,
        node: &str,
        process_generation: u64,
        declared_ram_bytes: u64,
        vcpus: u32,
    ) -> Result<RamControlRegistration, HostRamAdmissionError> {
        if process_generation == 0 {
            return Err(HostRamAdmissionError::contract(
                "host RAM process generation must be nonzero",
            ));
        }
        let (target, resources, spill_quota_bytes, host_services, registrar) = {
            let mut world = self.world.lock().map_err(|_| {
                HostRamAdmissionError::contract("host RAM world allocation ownership is uncertain")
            })?;
            let world = world.as_mut().ok_or_else(|| {
                HostRamAdmissionError::contract("complete host RAM world was not admitted")
            })?;
            if !world.shapes.iter().any(|shape| {
                shape.node == node
                    && shape.declared_ram_bytes == declared_ram_bytes
                    && shape.vcpus == vcpus
            }) {
                return Err(HostRamAdmissionError::contract(
                    "host RAM node shape differs from its retained partition",
                ));
            }
            let resources = *world.partition.nodes.get(node).ok_or_else(|| {
                HostRamAdmissionError::contract("host RAM node has no retained partition")
            })?;
            let disk = world.partition.backing.get(node).ok_or_else(|| {
                HostRamAdmissionError::contract("host RAM node has no retained backing partition")
            })?;
            let arena_generation = NEXT_ARENA_GENERATION
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| {
                    HostRamAdmissionError::contract("host RAM arena generation exhausted")
                })?;
            let target = HostRamTarget {
                daemon_epoch: self.daemon_epoch,
                owner_id: self.owner_id,
                node_id: node_identity(self.owner_id, node),
                owner_generation: process_generation,
                arena_generation,
                retained_template: self.retained_template,
            };
            let index = world
                .shapes
                .iter()
                .position(|shape| shape.node == node)
                .ok_or_else(|| {
                    HostRamAdmissionError::contract("configured process family is missing")
                })?;
            let family = world.families.get_mut(index).ok_or_else(|| {
                HostRamAdmissionError::contract("configured process family control is missing")
            })?;
            let assigned = family.prepare_initial(target)?;
            family.verify_initial(target, resources)?;
            if assigned != resources {
                return Err(HostRamAdmissionError::contract(
                    "initial process allowance differs from the configured family",
                ));
            }
            // Registrar selection and one-shot publication share this lock.
            // Replacement cannot slip between the snapshot and its issuer.
            let registrar = world.registrars.get(node).cloned().ok_or_else(|| {
                HostRamAdmissionError::contract("node operational registrar is missing")
            })?;
            (
                target,
                resources,
                disk.spill_bytes,
                world.services.get(node).cloned().ok_or_else(|| {
                    HostRamAdmissionError::contract("host service allocation is missing")
                })?,
                registrar,
            )
        };
        let (_, latency) = self
            .supervisor
            .budgets()
            .map_err(HostRamAdmissionError::Supervision)?;
        let initial_policy = HostRamPolicy {
            mode: self.initial_mode,
            resident_target_bytes: declared_ram_bytes,
            eviction_preference: 0,
            writeback_bytes_per_second:
                crucible_qemu_host::ram_admission::RAM_CAS_OPERATION_SCRATCH_BYTES,
            maximum_paging_io_in_flight: 1,
            prefetch_on_increase: false,
            latency,
        };

        #[cfg(test)]
        let require_native = !self.component_ram_facts;
        #[cfg(not(test))]
        let require_native = true;
        if require_native {
            self.registry
                .bind_native_node_target(target)
                .map_err(HostRamAdmissionError::Authority)?;
        }
        self.registry
            .admit_node(target, resources)
            .map_err(HostRamAdmissionError::Authority)?;
        Ok(RamControlRegistration {
            target,
            initial_policy,
            resources,
            spill_quota_bytes,
            host_services,
            registrar,
        })
    }
}

impl AdmittedRamRegistrationFactory {
    fn initial_registrar(&self) -> Arc<dyn crucible_qemu_host::ram_control::RamControlRegistrar> {
        #[cfg(test)]
        if self.initial_mode == HostRamMode::ResidentRequired {
            return Arc::new(native_initial::NativeInitialRegistrar::new(
                self.registry.clone(),
            ));
        }
        Arc::new(self.registry.clone())
    }
}

fn node_identity(owner: [u8; 32], node: &str) -> [u8; 32] {
    let mut identity = blake3::Hasher::new();
    identity.update(b"crucible.host-ram.node-owner.v1\0");
    identity.update(&owner);
    identity.update(node.as_bytes());
    *identity.finalize().as_bytes()
}
