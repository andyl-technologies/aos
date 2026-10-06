//! Retains one real native kernel authority and disjoint outside-owner floors.

use super::*;
use crucible_qemu::LinuxQemuNativeResourceController;

pub(super) struct NativeWorldResources {
    controller: LinuxQemuNativeResourceController,
    controller_resources: Option<crucible_linux_resource::host_services::HostServiceLease>,
    complete: HostResourceVector,
    outside: BTreeMap<[u8; 32], (u64, u64)>,
    targets: BTreeMap<[u8; 32], HostRamTarget>,
}

impl HostOperationalRegistry {
    pub(crate) fn bind_native_world_resources(
        &self,
        daemon: [u8; 32],
        owner: [u8; 32],
        controller: LinuxQemuNativeResourceController,
        complete: HostResourceVector,
        outside: BTreeMap<[u8; 32], (u64, u64)>,
    ) -> Result<(), HostOperationalError> {
        if outside.is_empty() {
            return Err(HostOperationalError::Unavailable);
        }
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        if let Some(existing) = worlds.get(&(daemon, owner))
            && existing.controller.is_physically_retained()
        {
            return if existing.controller.same_incarnation(&controller)
                && existing.complete == complete
                && existing.outside == outside
            {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        let limits = controller.current_limits().map_err(unavailable)?;
        let (resident, backing) = outside.values().try_fold((0_u64, 0_u64), |sum, next| {
            Ok::<_, HostOperationalError>((
                sum.0
                    .checked_add(next.0)
                    .ok_or(HostOperationalError::Unavailable)?,
                sum.1
                    .checked_add(next.1)
                    .ok_or(HostOperationalError::Unavailable)?,
            ))
        })?;
        if limits
            != (
                complete
                    .resident_peak_bytes
                    .checked_sub(resident)
                    .ok_or(HostOperationalError::Unavailable)?,
                complete
                    .backing_peak_bytes
                    .checked_sub(backing)
                    .ok_or(HostOperationalError::Unavailable)?,
            )
        {
            return Err(HostOperationalError::Unavailable);
        }
        if !worlds.contains_key(&(daemon, owner)) && worlds.len() >= MAX_OWNERS {
            return Err(HostOperationalError::Unavailable);
        }
        let other_nodes = worlds
            .iter()
            .filter(|(identity, _)| **identity != (daemon, owner))
            .try_fold(0_usize, |count, (_, world)| {
                count.checked_add(world.outside.len())
            })
            .ok_or(HostOperationalError::Unavailable)?;
        if other_nodes
            .checked_add(outside.len())
            .is_none_or(|count| count > MAX_OWNERS)
        {
            return Err(HostOperationalError::Unavailable);
        }
        worlds.insert(
            (daemon, owner),
            NativeWorldResources {
                controller,
                controller_resources: None,
                complete,
                outside,
                targets: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub(crate) fn retain_native_controller_resources(
        &self,
        daemon: [u8; 32],
        owner: [u8; 32],
        lease: crucible_linux_resource::host_services::HostServiceLease,
    ) -> Result<(), HostOperationalError> {
        if lease.file_descriptors() != 2 {
            return Err(HostOperationalError::Unavailable);
        }
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        let world = worlds
            .get_mut(&(daemon, owner))
            .ok_or(HostOperationalError::Unavailable)?;
        if world.controller_resources.is_some() {
            return Err(HostOperationalError::Unavailable);
        }
        world.controller_resources = Some(lease);
        Ok(())
    }

    pub(crate) fn bind_native_node_target(
        &self,
        target: HostRamTarget,
    ) -> Result<(), HostOperationalError> {
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        if self
            .shared
            .state
            .lock()
            .map_err(unavailable)?
            .retired
            .contains(&target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        let world = worlds
            .get_mut(&(target.daemon_epoch, target.owner_id))
            .ok_or(HostOperationalError::Unavailable)?;
        if !world.outside.contains_key(&target.node_id)
            || world
                .targets
                .get(&target.node_id)
                .is_some_and(|existing| *existing != target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        world.targets.insert(target.node_id, target);
        Ok(())
    }

    // Only final physical cleanup removes a target. The outside floors remain
    // monotonic across generations under this same retained kernel authority.
    pub(super) fn finish_native_node_cleanup(
        &self,
        target: HostRamTarget,
        release: impl FnOnce() -> Result<(), HostOperationalError>,
    ) -> Result<(), HostOperationalError> {
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        let world = worlds.get_mut(&(target.daemon_epoch, target.owner_id));
        if let Some(world) = world.as_ref()
            && world
                .targets
                .get(&target.node_id)
                .is_some_and(|current| *current != target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        // Hold the exact binding through the actor transaction: neither a new
        // generation nor a failed metadata lock can race successful discharge.
        release()?;
        if let Some(world) = world {
            world.targets.remove(&target.node_id);
        }
        Ok(())
    }

    pub(crate) fn tighten_native_resources(
        &self,
        target: HostRamTarget,
        outside_resident: u64,
        outside_backing: u64,
    ) -> Result<(), HostOperationalError> {
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        let world = worlds
            .get_mut(&(target.daemon_epoch, target.owner_id))
            .ok_or(HostOperationalError::Unavailable)?;
        if world.targets.get(&target.node_id) != Some(&target) {
            return Err(HostOperationalError::Unavailable);
        }
        let old = *world
            .outside
            .get(&target.node_id)
            .ok_or(HostOperationalError::Unavailable)?;
        let new = (old.0.max(outside_resident), old.1.max(outside_backing));
        let (resident, backing) =
            world
                .outside
                .iter()
                .try_fold((0_u64, 0_u64), |sum, (node, value)| {
                    let value = if *node == target.node_id { new } else { *value };
                    Ok::<_, HostOperationalError>((
                        sum.0
                            .checked_add(value.0)
                            .ok_or(HostOperationalError::Unavailable)?,
                        sum.1
                            .checked_add(value.1)
                            .ok_or(HostOperationalError::Unavailable)?,
                    ))
                })?;
        let resident = world
            .complete
            .resident_peak_bytes
            .checked_sub(resident)
            .ok_or(HostOperationalError::Unavailable)?;
        let backing = world
            .complete
            .backing_peak_bytes
            .checked_sub(backing)
            .ok_or(HostOperationalError::Unavailable)?;
        // Partial kernel failure is sticky in the retained controller. The old
        // ledger floor stays retained, and no guest grant follows the refusal.
        world
            .controller
            .tighten(resident, backing)
            .map_err(unavailable)?;
        world.outside.insert(target.node_id, new);
        Ok(())
    }
}
