//! Resolves immutable World storage artifacts into live coordinator bindings.

use super::*;

/// Authenticated World material retained for launch and coordinator binding.
#[derive(Clone)]
pub(in crate::vm_lifecycle) struct ProductionBlockBinding {
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
            "QEMU node `{}` declares {} block devices but the current shared-memory transport has one block executor slot",
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
            "QEMU node `{}` owns block device `{}` but no production World artifact store was configured",
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
            "QEMU node `{}` declares {} 9p devices but the shared-memory transport has one 9p executor slot",
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
            "QEMU node `{}` owns 9p device `{}` but no production World artifact store was configured",
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
        tree,
        latency: NinepLatency::new(latency.control_ns, latency.data_ns, latency.per_byte_ns),
        target: ResolvedFaultTarget::NinePDevice {
            device: node.fault_target_hash(),
        },
    }))
}
