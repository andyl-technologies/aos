//! World-derived queue identity retained across launch, fork, and restore.

use crucible::model::{World, WorldDeviceKind};
use crucible::{ContentHash, NodeId, WorldIoInstantiationLayout, WorldIoLayoutPolicy};

/// Failure to bind a live queue to its canonical World declaration.
#[derive(Debug, thiserror::Error)]
pub enum QemuWorldIoBindingError {
    /// The requested logical device is absent from the World.
    #[error("World I/O device `{device}` is not declared")]
    MissingDevice {
        /// Name of the requested logical device.
        device: String,
    },
    /// The canonical physical queue layout is invalid.
    #[error(transparent)]
    Layout(#[from] crucible::WorldIoLayoutError),
    /// The declared device is absent from the derived queue layout.
    #[error("World I/O device `{device}` has no canonical binding")]
    MissingBinding {
        /// Name of the declared logical device.
        device: String,
    },
}

/// Immutable World identity and canonical producer number for one live queue.
///
/// This binds configuration and restore state. Physical publication still
/// requires the retained native input boundary and the exact computed queue
/// key; a binding is never guest execution authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QemuWorldIoBinding {
    world: ContentHash,
    device: NodeId,
    owner: NodeId,
    block: bool,
    artifact: ContentHash,
    source_node: u32,
}

impl QemuWorldIoBinding {
    /// Derives a queue binding from the actual canonical World declaration.
    ///
    /// # Errors
    ///
    /// Rejects an absent device or an invalid canonical runtime layout.
    pub fn from_world(world: &World, device: &NodeId) -> Result<Self, QemuWorldIoBindingError> {
        let node = world
            .io_node(device)
            .ok_or_else(|| QemuWorldIoBindingError::MissingDevice {
                device: device.name.clone(),
            })?;
        let layout = WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy::default())?;
        let source = layout
            .get(device)
            .ok_or_else(|| QemuWorldIoBindingError::MissingBinding {
                device: device.name.clone(),
            })?;
        Ok(Self {
            world: world.id(),
            device: node.id.clone(),
            owner: node.owner.clone(),
            block: node.kind.family() == WorldDeviceKind::Block,
            artifact: node.fault_target_hash(),
            source_node: source.source_node,
        })
    }

    pub(crate) const fn source_node(&self) -> u32 {
        self.source_node
    }

    pub(crate) const fn is_block(&self) -> bool {
        self.block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{
        ContentAddressedBlobRef, Icount, NodeTemplate, ReadyPoint, VmArchitecture, WhiteBoxPolicy,
        WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
    };

    fn world() -> World {
        let owner = NodeId { name: "vm".into() };
        let mut definitions = vec![WorldNodeDef::Vm(WorldNode {
            id: owner.clone(),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            kernel: None,
            root_image: None,
            initrd: None,
        })];
        for name in ["disk-a", "disk-b"] {
            definitions.push(WorldNodeDef::Io(WorldIoNode::block(
                NodeId { name: name.into() },
                owner.clone(),
                WorldIoCoreConfig::new(),
                ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"immutable disk")),
                512,
                WorldBlockLatency::new(0, 0, 0, 0, 0),
            )));
        }
        World::from_node_defs_and_links(definitions, Vec::new())
            .unwrap_or_else(|error| panic!("actual configured World: {error}"))
    }

    #[test]
    fn binding_uses_actual_world_layout_and_rejects_missing_device() {
        let world = world();
        let layout = WorldIoInstantiationLayout::derive(&world, WorldIoLayoutPolicy::default())
            .unwrap_or_else(|error| panic!("actual layout: {error}"));
        let mut bindings = Vec::new();
        for name in ["disk-a", "disk-b"] {
            let id = NodeId { name: name.into() };
            let binding = QemuWorldIoBinding::from_world(&world, &id)
                .unwrap_or_else(|error| panic!("actual declared queue: {error}"));
            assert_eq!(binding.world, world.id());
            assert_eq!(
                binding.source_node(),
                layout
                    .get(&id)
                    .unwrap_or_else(|| panic!("declared layout"))
                    .source_node
            );
            assert!(binding.is_block());
            let bytes = serde_json::to_vec(&binding)
                .unwrap_or_else(|error| panic!("binding encode: {error:?}"));
            assert_eq!(
                serde_json::from_slice::<QemuWorldIoBinding>(&bytes)
                    .unwrap_or_else(|error| panic!("binding restore: {error:?}")),
                binding
            );
            bindings.push(binding);
        }
        assert_ne!(bindings[0].source_node(), bindings[1].source_node());
        assert!(matches!(
            QemuWorldIoBinding::from_world(
                &world,
                &NodeId {
                    name: "missing".into()
                }
            ),
            Err(QemuWorldIoBindingError::MissingDevice { device }) if device == "missing"
        ));
    }

    #[test]
    fn serialized_binding_requires_every_original_identity_field() {
        let world = world();
        let binding = QemuWorldIoBinding::from_world(
            &world,
            &NodeId {
                name: "disk-a".into(),
            },
        )
        .unwrap_or_else(|error| panic!("actual declared device: {error:?}"));
        for field in [
            "world",
            "device",
            "owner",
            "block",
            "artifact",
            "source_node",
        ] {
            let mut encoded = serde_json::to_value(&binding)
                .unwrap_or_else(|error| panic!("binding encode: {error:?}"));
            encoded
                .as_object_mut()
                .unwrap_or_else(|| panic!("binding object"))
                .remove(field);
            assert!(serde_json::from_value::<QemuWorldIoBinding>(encoded).is_err());
        }
    }
}
