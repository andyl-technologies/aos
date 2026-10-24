//! Retains exact node kernel authorities and their disjoint outside-owner floors.

use super::*;
use crucible_qemu_host::LinuxQemuNativeResourceController;

pub(super) struct NativeWorldResources {
    nodes: BTreeMap<[u8; 32], NativeNodeResources>,
}

struct NativeNodeResources {
    // The controller closes before its actual descriptor credit is returned.
    controller: LinuxQemuNativeResourceController,
    _controller_resources: crucible_host_resources::host_services::HostServiceLease,
    complete: HostResourceVector,
    outside: (u64, u64),
    target: Option<HostRamTarget>,
}

impl HostOperationalRegistry {
    pub(crate) fn retire_original_native_world(
        &self,
        physical: crucible_qemu_host::OriginalNativePhysicalRetirement<'_>,
    ) -> Result<(), crucible_qemu_host::QemuVmRealizationError> {
        physical.check_cleanup()?;
        let finish = || {
            let _transaction = self.shared.mutation.try_lock().map_err(|source| {
                crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let mut worlds = self.shared.native_resources.lock().map_err(|source| {
                crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let state = self.shared.state.lock().map_err(|source| {
                crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                    source: Box::new(unavailable(source)),
                }
            })?;
            let mut selected = None;
            for (identity, world) in worlds.iter() {
                let node = select_original_controller(
                    &world.nodes,
                    |node| {
                        physical
                            .matches_controller(&node.controller)
                            .map_err(|source| crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                                source: Box::new(source),
                            })
                    },
                    |node| node.target.is_none(),
                    |node_id| {
                        !state.nodes.keys().any(|target| {
                            (target.daemon_epoch, target.owner_id) == *identity
                                && target.node_id == *node_id
                        })
                    },
                )?;
                if let Some(node) = node {
                    if selected.replace((*identity, node)).is_some() {
                        return Err(crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                            source: Box::new(HostOperationalError::Unavailable),
                        });
                    }
                }
            }
            drop(state);
            if let Some((identity, node_id)) = selected {
                let world = worlds.get_mut(&identity).ok_or_else(|| {
                    crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                        source: Box::new(HostOperationalError::Unavailable),
                    }
                })?;
                let node = world.nodes.get_mut(&node_id).ok_or_else(|| {
                    crucible_qemu_host::QemuVmRealizationError::ModelCopy {
                        source: Box::new(HostOperationalError::Unavailable),
                    }
                })?;
                physical.close_registry_control(&mut node.controller)?;
                // Retire only this exact allocation. Sibling controllers and
                // their descriptor leases remain discoverable in the world.
                drop(world.nodes.remove(&node_id));
                if world.nodes.is_empty() {
                    drop(worlds.remove(&identity));
                }
            }
            Ok(())
        };
        physical.after_registry_retirement(finish())?;
        physical.close()
    }

    pub(crate) fn bind_native_node_resources(
        &self,
        daemon: [u8; 32],
        owner: [u8; 32],
        node_id: [u8; 32],
        controller: LinuxQemuNativeResourceController,
        controller_resources: crucible_host_resources::host_services::HostServiceLease,
        complete: HostResourceVector,
        outside: (u64, u64),
    ) -> Result<(), HostOperationalError> {
        if controller_resources.file_descriptors() != 2 {
            return Err(HostOperationalError::Unavailable);
        }
        let limits = (
            complete
                .resident_peak_bytes
                .checked_sub(outside.0)
                .ok_or(HostOperationalError::Unavailable)?,
            complete
                .backing_peak_bytes
                .checked_sub(outside.1)
                .ok_or(HostOperationalError::Unavailable)?,
        );
        if controller.current_limits().map_err(unavailable)? != limits {
            return Err(HostOperationalError::Unavailable);
        }
        let mut worlds = self.shared.native_resources.lock().map_err(unavailable)?;
        if let Some(existing) = worlds
            .get(&(daemon, owner))
            .and_then(|world| world.nodes.get(&node_id))
        {
            return if existing.controller.is_physically_retained()
                && existing.controller.same_incarnation(&controller)
                && existing.complete == complete
                && existing.outside == outside
            {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        let nodes = worlds
            .values()
            .try_fold(0_usize, |count, world| count.checked_add(world.nodes.len()))
            .ok_or(HostOperationalError::Unavailable)?;
        if nodes >= MAX_OWNERS
            || (!worlds.contains_key(&(daemon, owner)) && worlds.len() >= MAX_OWNERS)
        {
            return Err(HostOperationalError::Unavailable);
        }
        worlds
            .entry((daemon, owner))
            .or_insert_with(|| NativeWorldResources {
                nodes: BTreeMap::new(),
            })
            .nodes
            .insert(
                node_id,
                NativeNodeResources {
                    controller,
                    _controller_resources: controller_resources,
                    complete,
                    outside,
                    target: None,
                },
            );
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
        let node = worlds
            .get_mut(&(target.daemon_epoch, target.owner_id))
            .and_then(|world| world.nodes.get_mut(&target.node_id))
            .ok_or(HostOperationalError::Unavailable)?;
        if node.target.is_some_and(|existing| existing != target) {
            return Err(HostOperationalError::Unavailable);
        }
        node.target = Some(target);
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
        let node = worlds
            .get_mut(&(target.daemon_epoch, target.owner_id))
            .and_then(|world| world.nodes.get_mut(&target.node_id));
        if node
            .as_ref()
            .is_some_and(|node| node.target.is_some_and(|current| current != target))
        {
            return Err(HostOperationalError::Unavailable);
        }
        // Keep the exact generation bound through the actor transaction.
        release()?;
        if let Some(node) = node {
            node.target = None;
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
        let node = worlds
            .get_mut(&(target.daemon_epoch, target.owner_id))
            .and_then(|world| world.nodes.get_mut(&target.node_id))
            .ok_or(HostOperationalError::Unavailable)?;
        if node.target != Some(target) {
            return Err(HostOperationalError::Unavailable);
        }
        let outside = (
            node.outside.0.max(outside_resident),
            node.outside.1.max(outside_backing),
        );
        let resident = node
            .complete
            .resident_peak_bytes
            .checked_sub(outside.0)
            .ok_or(HostOperationalError::Unavailable)?;
        let backing = node
            .complete
            .backing_peak_bytes
            .checked_sub(outside.1)
            .ok_or(HostOperationalError::Unavailable)?;
        // Partial kernel failure remains sticky in this exact node controller;
        // sibling nodes never lend capacity to satisfy its retained floor.
        node.controller
            .tighten(resident, backing)
            .map_err(unavailable)?;
        node.outside = outside;
        Ok(())
    }
}

// The caller holds the registry mutation and world/state locks. Allocation
// identity comes only from the lower physical-retirement witness. Empty node
// rosters are additional refusal checks, never a substitute for that witness.
fn select_original_controller<I: Ord + Copy, W>(
    worlds: &BTreeMap<I, W>,
    mut matches: impl FnMut(&W) -> Result<bool, crucible_qemu_host::QemuVmRealizationError>,
    targets_closed: impl Fn(&W) -> bool,
    nodes_closed: impl Fn(&I) -> bool,
) -> Result<Option<I>, crucible_qemu_host::QemuVmRealizationError> {
    let mut selected = None;
    for (identity, world) in worlds.iter() {
        if matches(world)? {
            if selected.is_some() || !targets_closed(world) || !nodes_closed(identity) {
                return Err(crucible_qemu_host::QemuVmRealizationError::ModelCopy {
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
            std::mem::size_of::<crucible_qemu_host::OriginalNativePhysicalRetirement<'_>>()
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

        let selected = select_original_controller(
            &worlds,
            matches,
            |world| world.targets.is_empty(),
            |_| true,
        )
        .unwrap();
        assert_eq!(selected, Some(first));
        drop(worlds.remove(&selected.unwrap()));

        assert!(!worlds.contains_key(&first));
        assert!(worlds.contains_key(&second));
        assert!(Arc::get_mut(&mut Arc::clone(&other)).is_none());
        assert_eq!(Arc::weak_count(&same), 0);
    }

    #[test]
    fn a_live_sibling_does_not_prevent_the_exact_closed_controller_return() {
        let completed = Arc::new(41);
        let sibling = Arc::new(43);
        let completed_id = [1; 32];
        let sibling_id = [2; 32];
        let mut nodes = BTreeMap::from([
            (
                completed_id,
                World {
                    controller: Arc::downgrade(&completed),
                    targets: BTreeSet::new(),
                },
            ),
            (
                sibling_id,
                World {
                    controller: Arc::downgrade(&sibling),
                    targets: BTreeSet::from([7]),
                },
            ),
        ]);

        let selected = select_original_controller(
            &nodes,
            |node: &World| {
                Ok(std::ptr::eq(
                    node.controller.as_ptr(),
                    Arc::as_ptr(&completed),
                ))
            },
            |node| node.targets.is_empty(),
            |node_id| *node_id != sibling_id,
        )
        .unwrap();
        assert_eq!(selected, Some(completed_id));
        drop(nodes.remove(&completed_id));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[&sibling_id].targets, BTreeSet::from([7]));
        assert_eq!(Arc::weak_count(&completed), 0);
        assert_eq!(Arc::weak_count(&sibling), 1);
    }

    #[test]
    fn duplicate_controller_identity_retains_every_registry_alias() {
        let same = Arc::new(47);
        let nodes = BTreeMap::from([
            (
                [1; 32],
                World {
                    controller: Arc::downgrade(&same),
                    targets: BTreeSet::new(),
                },
            ),
            (
                [2; 32],
                World {
                    controller: Arc::downgrade(&same),
                    targets: BTreeSet::new(),
                },
            ),
        ]);

        assert!(
            select_original_controller(
                &nodes,
                |node: &World| Ok(std::ptr::eq(node.controller.as_ptr(), Arc::as_ptr(&same))),
                |node| node.targets.is_empty(),
                |_| true,
            )
            .is_err()
        );
        assert_eq!(nodes.len(), 2);
        assert_eq!(Arc::weak_count(&same), 2);
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
            select_original_controller(
                &worlds,
                matches,
                |world| world.targets.is_empty(),
                |_| true
            )
            .is_err()
        );
        worlds.get_mut(&identity).unwrap().targets.clear();
        assert!(
            select_original_controller(
                &worlds,
                matches,
                |world| world.targets.is_empty(),
                |_| false
            )
            .is_err()
        );

        assert_eq!(Arc::weak_count(&same), 1);
        let selected = select_original_controller(
            &worlds,
            matches,
            |world| world.targets.is_empty(),
            |_| true,
        )
        .unwrap();
        drop(worlds.remove(&selected.unwrap()));
        assert!(worlds.is_empty());
        assert_eq!(Arc::weak_count(&same), 0);
    }
}
