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
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn retire_original_native_world(
        &self,
        physical: crucible_qemu::OriginalNativePhysicalRetirement<'_>,
    ) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        physical.check_cleanup()?;
        let finish = || {
            let _transaction = self.shared.mutation.try_lock().map_err(|source| {
                crucible_qemu::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let mut worlds = self.shared.native_resources.lock().map_err(|source| {
                crucible_qemu::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let state = self.shared.state.lock().map_err(|source| {
                crucible_qemu::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let selection = select_original_world(
                &worlds,
                |world| {
                    physical
                        .matches_controller(&world.controller)
                        .map_err(|source| crucible_qemu::QemuVmRealizationError::ModelCopy {
                            source: Box::new(source),
                        })
                },
                |world| world.targets.is_empty(),
                |identity| {
                    !state
                        .nodes
                        .keys()
                        .any(|target| (target.daemon_epoch, target.owner_id) == *identity)
                },
            );
            drop(state);
            let identity = match selection {
                Ok(identity) => identity,
                Err(source) => return Err(source),
            };
            if let Some(identity) = identity {
                let world = worlds.get_mut(&identity).ok_or_else(|| {
                    crucible_qemu::QemuVmRealizationError::Executor {
                        operation: "retire original native world",
                        message: String::from("selected original world disappeared"),
                    }
                })?;
                physical.close_registry_control(&mut world.controller)?;
                // The atomic native control has physically closed. Its same
                // registry row and lease remained held through that free.
                drop(worlds.remove(&identity));
            }
            Ok(())
        };
        physical.after_registry_retirement(finish())?;
        physical.close()
    }

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

// The caller holds the registry mutation and world/state locks. Allocation
// identity comes only from the lower physical-retirement witness. Empty node
// rosters are additional refusal checks, never a substitute for that witness.
#[cfg(feature = "private-measurement-domain")]
fn select_original_world<W>(
    worlds: &BTreeMap<NativeWorldIdentity, W>,
    mut matches: impl FnMut(&W) -> Result<bool, crucible_qemu::QemuVmRealizationError>,
    targets_closed: impl Fn(&W) -> bool,
    nodes_closed: impl Fn(&NativeWorldIdentity) -> bool,
) -> Result<Option<NativeWorldIdentity>, crucible_qemu::QemuVmRealizationError> {
    let mut selected = None;
    for (identity, world) in worlds.iter() {
        if matches(world)? {
            if selected.is_some() || !targets_closed(world) || !nodes_closed(identity) {
                return Err(crucible_qemu::QemuVmRealizationError::ModelCopy {
                    source: Box::new(HostOperationalError::Unavailable),
                });
            }
            selected = Some(*identity);
        }
    }
    Ok(selected)
}

#[cfg(all(test, feature = "private-measurement-domain"))]
// crucible-lint: allow panic-shortcut -- these allocation-identity and retained-node refusal controls panic only on custody invariant violations; they perform no kernel or VM admission.
#[allow(clippy::unwrap_used)]
mod original_world_tests {
    use super::*;

    struct World {
        controller: Weak<u64>,
        targets: BTreeSet<u64>,
    }

    #[test]
    fn records_feature_private_retirement_custody_geometry() {
        eprintln!(
            "original_retirement_guard_bytes={}",
            std::mem::size_of::<
                crate::ComposedQemuAttemptResourceGuard<crate::LinuxQemuAttemptHostResourceOwner>,
            >()
        );
        eprintln!(
            "original_physical_retirement_borrow_bytes={}",
            std::mem::size_of::<crucible_qemu::OriginalNativePhysicalRetirement<'_>>()
        );
        eprintln!(
            "original_registry_alias_bytes={}",
            std::mem::size_of::<HostOperationalRegistry>()
        );
    }

    #[test]
    fn exact_allocation_selects_only_the_physically_closed_world() {
        let same = Arc::new(31);
        let other = Arc::new(31);
        let first = ([1; 32], [2; 32]);
        let second = ([3; 32], [4; 32]);
        let mut worlds = BTreeMap::from([
            (
                first,
                World {
                    controller: Arc::downgrade(&same),
                    targets: BTreeSet::new(),
                },
            ),
            (
                second,
                World {
                    controller: Arc::downgrade(&other),
                    targets: BTreeSet::new(),
                },
            ),
        ]);
        let matches =
            |world: &World| Ok(std::ptr::eq(world.controller.as_ptr(), Arc::as_ptr(&same)));

        let selected =
            select_original_world(&worlds, matches, |world| world.targets.is_empty(), |_| true)
                .unwrap();
        assert_eq!(selected, Some(first));
        drop(worlds.remove(&selected.unwrap()));

        assert!(!worlds.contains_key(&first));
        assert!(worlds.contains_key(&second));
        assert!(Arc::get_mut(&mut Arc::clone(&other)).is_none());
        assert_eq!(Arc::weak_count(&same), 0);
    }

    #[test]
    fn unfinished_node_or_target_retains_the_exact_controller() {
        let same = Arc::new(37);
        let identity = ([1; 32], [2; 32]);
        let mut worlds = BTreeMap::from([(
            identity,
            World {
                controller: Arc::downgrade(&same),
                targets: BTreeSet::from([7]),
            },
        )]);
        let matches =
            |world: &World| Ok(std::ptr::eq(world.controller.as_ptr(), Arc::as_ptr(&same)));

        assert!(
            select_original_world(&worlds, matches, |world| world.targets.is_empty(), |_| true)
                .is_err()
        );
        worlds.get_mut(&identity).unwrap().targets.clear();
        assert!(
            select_original_world(
                &worlds,
                matches,
                |world| world.targets.is_empty(),
                |_| false
            )
            .is_err()
        );

        assert_eq!(Arc::weak_count(&same), 1);
        let selected =
            select_original_world(&worlds, matches, |world| world.targets.is_empty(), |_| true)
                .unwrap();
        drop(worlds.remove(&selected.unwrap()));
        assert!(worlds.is_empty());
        assert_eq!(Arc::weak_count(&same), 0);
    }
}
