//! Resolves immutable World storage artifacts into live coordinator bindings.

use super::*;

/// Logical queue identity retained with its original canonical World.
#[derive(Clone)]
pub(in crate::vm_lifecycle) struct ProductionQueueIdentity {
    world: ContentHash,
    node: crucible::NodeId,
}

impl ProductionQueueIdentity {
    fn from_world(world: &World, node: &crucible::NodeId) -> Self {
        Self {
            world: world.id(),
            node: node.clone(),
        }
    }

    /// Returns the queue identity only for the original canonical World.
    ///
    /// # Errors
    ///
    /// Rejects a different World, including one with matching queue names.
    pub(in crate::vm_lifecycle) fn node_for_world(
        &self,
        world: &World,
    ) -> Result<&crucible::NodeId, LifecycleApiError> {
        if world.id() != self.world {
            return Err(loop_factory_error(
                "retained storage queue belongs to a different canonical World",
            ));
        }
        Ok(&self.node)
    }
}

/// Authenticated World material retained for launch and coordinator binding.
#[derive(Clone)]
pub(in crate::vm_lifecycle) struct ProductionBlockBinding {
    /// Canonical logical device identity and producer retained by the live queue.
    pub(in crate::vm_lifecycle) queue: ProductionQueueIdentity,
    /// Immutable base image passed to the live servicer.
    pub(in crate::vm_lifecycle) base: BaseImage,
    /// Complete World durability contract.
    pub(in crate::vm_lifecycle) durability: BlockDurabilityConfig,
    /// Resolved signal target for every request opportunity.
    pub(in crate::vm_lifecycle) target: ResolvedFaultTarget,
    /// Immutable World hash indexing the authoritative live device.
    device_hash: ContentHash,
}

impl ProductionBlockBinding {
    pub(in crate::vm_lifecycle) fn device_hash(&self) -> ContentHash {
        self.device_hash
    }
}

/// Authenticated World material retained for one production 9p device.
#[derive(Clone)]
pub(in crate::vm_lifecycle) struct ProductionNinepBinding {
    /// Canonical logical device identity and producer retained by the live queue.
    pub(in crate::vm_lifecycle) queue: ProductionQueueIdentity,
    /// Immutable filesystem tree passed to the live servicer.
    pub(in crate::vm_lifecycle) tree: FsTree,
    /// Deterministic World-declared latency model.
    pub(in crate::vm_lifecycle) latency: NinepLatency,
    /// Resolved signal target for typed 9p opportunities.
    pub(in crate::vm_lifecycle) target: ResolvedFaultTarget,
}

/// Resolves the optional block device owned by one World VM.
pub(in crate::vm_lifecycle) fn block_binding_for_vm(
    world: &World,
    vm: &crucible::NodeId,
    artifacts: Option<&Arc<dyn crucible::model::DagStore>>,
) -> Result<Option<ProductionBlockBinding>, LifecycleApiError> {
    let blocks = world
        .io_nodes()
        .filter(|node| node.owner == *vm && matches!(node.kind, WorldIoNodeKind::Block { .. }))
        .collect::<Vec<_>>();
    if blocks.len() > 1 {
        return Err(loop_factory_error(format!(
            "node `{}` declares {} block devices but the current shared-memory transport has one block executor slot",
            vm.name,
            blocks.len()
        )));
    }
    let Some(node) = blocks.first().copied() else {
        return Ok(None);
    };
    let WorldIoNodeKind::Block {
        base_image,
        base_length,
        ..
    } = &node.kind
    else {
        return Err(loop_factory_error("selected World block node changed kind"));
    };
    let store = artifacts.ok_or_else(|| {
        loop_factory_error(format!(
            "node `{}` owns block device `{}` but no production World artifact store was configured",
            vm.name, node.id.name
        ))
    })?;
    let bytes = store.get(&base_image.hash()).map_err(|error| {
        loop_factory_error(format!(
            "load block base image for `{}` from the World artifact store: {error}",
            node.id.name
        ))
    })?;
    let base = BaseImage::new(bytes);
    let actual = ContentHash { bytes: base.hash() };
    if actual != base_image.hash() || base.len() != *base_length {
        return Err(loop_factory_error(format!(
            "World block base image for `{}` differs from its declared hash or length",
            node.id.name
        )));
    }
    let target = ResolvedFaultTarget::BlockDevice {
        device: node.fault_target_hash(),
    };
    let durability = block_durability_config(world, &target).map_err(|error| {
        loop_factory_error(format!(
            "resolve block durability for `{}`: {error}",
            node.id.name
        ))
    })?;
    Ok(Some(ProductionBlockBinding {
        queue: ProductionQueueIdentity::from_world(world, &node.id),
        base,
        durability,
        target,
        device_hash: node.fault_target_hash(),
    }))
}

/// Resolves the optional 9p device owned by one World VM.
pub(in crate::vm_lifecycle) fn ninep_binding_for_vm(
    world: &World,
    vm: &crucible::NodeId,
    artifacts: Option<&Arc<dyn crucible::model::DagStore>>,
) -> Result<Option<ProductionNinepBinding>, LifecycleApiError> {
    let devices = world
        .io_nodes()
        .filter(|node| node.owner == *vm && matches!(node.kind, WorldIoNodeKind::NineP { .. }))
        .collect::<Vec<_>>();
    if devices.len() > 1 {
        return Err(loop_factory_error(format!(
            "node `{}` declares {} 9p devices but the shared-memory transport has one 9p executor slot",
            vm.name,
            devices.len()
        )));
    }
    let Some(node) = devices.first().copied() else {
        return Ok(None);
    };
    let WorldIoNodeKind::NineP {
        tree: artifact,
        latency,
    } = &node.kind
    else {
        return Err(loop_factory_error("selected World 9p node changed kind"));
    };
    let store = artifacts.ok_or_else(|| {
        loop_factory_error(format!(
            "node `{}` owns 9p device `{}` but no production World artifact store was configured",
            vm.name, node.id.name
        ))
    })?;
    let bytes = store.get(&artifact.hash()).map_err(|error| {
        loop_factory_error(format!(
            "load 9p tree for `{}` from the World artifact store: {error}",
            node.id.name
        ))
    })?;
    let tree = FsTree::from_canonical_bytes(&bytes).map_err(|error| {
        loop_factory_error(format!(
            "decode canonical 9p tree for `{}`: {error}",
            node.id.name
        ))
    })?;
    let actual = ContentHash {
        bytes: tree.content_hash(),
    };
    if actual != artifact.hash() {
        return Err(loop_factory_error(format!(
            "World 9p tree for `{}` differs from its declared hash",
            node.id.name
        )));
    }
    Ok(Some(ProductionNinepBinding {
        queue: ProductionQueueIdentity::from_world(world, &node.id),
        tree,
        latency: NinepLatency::new(latency.control_ns, latency.data_ns, latency.per_byte_ns),
        target: ResolvedFaultTarget::NinePDevice {
            device: node.fault_target_hash(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::{
        ContentAddressedBlobRef, Icount, NodeTemplate, ReadyPoint, VmArchitecture, WhiteBoxPolicy,
        WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
    };

    fn world(memory_mib: u32) -> World {
        let owner = crucible::NodeId { name: "vm".into() };
        World::from_node_defs_and_links(
            vec![
                WorldNodeDef::Vm(WorldNode {
                    id: owner.clone(),
                    arch: VmArchitecture::X86_64,
                    memory_mib,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 0 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: 1,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                }),
                WorldNodeDef::Io(WorldIoNode::block(
                    crucible::NodeId {
                        name: "disk".into(),
                    },
                    owner,
                    WorldIoCoreConfig::new(),
                    ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"base")),
                    512,
                    WorldBlockLatency::new(0, 0, 0, 0, 0),
                )),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("actual declared World: {error}"))
    }

    #[test]
    fn logical_queue_identity_keeps_original_world_through_clone() {
        let original = world(NodeTemplate::DEFAULT_MEMORY_MIB);
        let id = crucible::NodeId {
            name: "disk".into(),
        };
        assert!(original.io_node(&id).is_some());

        let retained = ProductionQueueIdentity::from_world(&original, &id).clone();

        assert_eq!(
            retained
                .node_for_world(&original)
                .unwrap_or_else(|error| panic!("original World binding: {error}")),
            &id,
        );
    }

    #[test]
    fn matching_queue_name_cannot_rebind_to_a_different_world() {
        let original = world(NodeTemplate::DEFAULT_MEMORY_MIB);
        let changed = world(NodeTemplate::DEFAULT_MEMORY_MIB + 1);
        let id = crucible::NodeId {
            name: "disk".into(),
        };
        assert!(original.io_node(&id).is_some());
        assert!(changed.io_node(&id).is_some());
        assert_ne!(original.id(), changed.id());
        let retained = ProductionQueueIdentity::from_world(&original, &id);

        assert!(retained.node_for_world(&changed).is_err());
        assert_eq!(
            retained
                .node_for_world(&original)
                .unwrap_or_else(|error| panic!("original World binding: {error}")),
            &id,
        );
    }
}
