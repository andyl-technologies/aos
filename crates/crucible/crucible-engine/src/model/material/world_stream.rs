//! Borrowed world identity formatting without canonical topology clones.
//!
//! Validated constructors sort their owned collections once. This renderer
//! visits those canonical collections and emits exactly the ordinary textual
//! identity material, including the VM-only representation and heterogeneous
//! node-kind tags.

use super::*;
use std::fmt::{self, Display, Write};

pub(in crate::model) struct WorldMaterial<'a> {
    pub(in crate::model) nodes: &'a [WorldNodeDef],
    pub(in crate::model) links: &'a [LinkDef],
    pub(in crate::model) fault_topology: ContentHash,
}

impl Display for WorldMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "min_link_latency_ticks={}\nnodes={}",
            MIN_LINK_LATENCY.ticks,
            self.nodes.len()
        )?;
        let heterogeneous = self
            .nodes
            .iter()
            .any(|node| matches!(node, WorldNodeDef::Io(_)));
        for node in self.nodes {
            output.write_char('\n')?;
            match node {
                WorldNodeDef::Vm(node) => {
                    if heterogeneous {
                        output.write_str("node_kind=vm\n")?;
                    }
                    write_vm(output, node)?;
                }
                WorldNodeDef::Io(node) => write_io(output, node)?,
            }
        }
        write!(output, "\nlinks={}", self.links.len())?;
        for link in self.links {
            let (left, right) = link.endpoints();
            write!(
                output,
                "\nlink_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}\nlink_latency_ticks={}\nlink_jitter_ticks={}\nlink_loss_millionths={}\nlink_bandwidth_bps=",
                left.name.len(),
                left.name,
                right.name.len(),
                right.name,
                link.latency().ticks,
                link.jitter().ticks,
                link.loss().millionths()
            )?;
            match link.bandwidth_bps() {
                Some(bandwidth) => write!(output, "{bandwidth}")?,
                None => output.write_str("none")?,
            }
        }
        write!(
            output,
            "\nfault-topology={}",
            Hex(&self.fault_topology.bytes)
        )
    }
}

fn write_vm(output: &mut impl Write, node: &WorldNode) -> fmt::Result {
    write!(
        output,
        "node_id_len={}\nnode_id={}\narch={}\nmemory_mib={}\ncmdline_len={}\ncmdline={}\nsmp_vcpus={}\nkernel_ref={}\nroot_image_ref={}\ninitrd_ref={}\n",
        node.id.name.len(),
        node.id.name,
        node.arch.material(),
        node.memory_mib,
        node.cmdline.len(),
        node.cmdline,
        node.smp_vcpus,
        BlobReference(node.kernel),
        BlobReference(node.root_image),
        BlobReference(node.initrd)
    )?;
    match &node.ready_point {
        ReadyPoint::FixedIcount { icount } => write!(
            output,
            "ready_point=fixed-icount\nready_icount={}",
            icount.retired
        )?,
        ReadyPoint::NetworkIdle { window } => write!(
            output,
            "ready_point=network-idle\nidle_window_ns={}",
            window.ticks
        )?,
        ReadyPoint::ConsoleMarker { marker } => write!(
            output,
            "ready_point=console-marker\nmarker_len={}\nmarker={marker}",
            marker.len()
        )?,
        ReadyPoint::AgentSignal => output.write_str("ready_point=agent-signal")?,
    }
    write!(output, "\nwhite_box={}", white_box_material(node.white_box))
}

fn write_io(output: &mut impl Write, node: &WorldIoNode) -> fmt::Result {
    write!(
        output,
        "node_id_len={}\nnode_id={}\nowner_id_len={}\nowner_id={}\n",
        node.id.name.len(),
        node.id.name,
        node.owner.name.len(),
        node.owner.name
    )?;
    match &node.kind {
        WorldIoNodeKind::Block {
            base_image,
            base_length,
            latency,
        } => write!(
            output,
            "node_kind=block\nartifact=blake3:{}\nartifact_length={}\nlatency.read_base_ns={}\nlatency.write_base_ns={}\nlatency.flush_ns={}\nlatency.get_length_ns={}\nlatency.per_byte_ns={}",
            Hex(&base_image.hash().bytes),
            base_length,
            latency.read_base_ns,
            latency.write_base_ns,
            latency.flush_ns,
            latency.get_length_ns,
            latency.per_byte_ns
        ),
        WorldIoNodeKind::NineP { tree, latency } => write!(
            output,
            "node_kind=9p\nartifact=blake3:{}\nlatency.control_ns={}\nlatency.data_ns={}\nlatency.per_byte_ns={}",
            Hex(&tree.hash().bytes),
            latency.control_ns,
            latency.data_ns,
            latency.per_byte_ns
        ),
    }
}

struct BlobReference(Option<ContentAddressedBlobRef>);

impl Display for BlobReference {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(reference) => write!(output, "blake3:{}", Hex(&reference.hash().bytes)),
            None => output.write_str("none"),
        }
    }
}

pub(in crate::model) struct Hex<'a>(pub(in crate::model) &'a [u8]);

impl Display for Hex<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            output.write_char(char::from(HEX[usize::from(byte >> 4)]))?;
            output.write_char(char::from(HEX[usize::from(byte & 0x0f)]))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_world_material_matches_ordinary_vm_and_io_material() -> Result<(), EngineError> {
        let vm = WorldNode {
            id: NodeId {
                name: "vm-é".into(),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: "quiet 水".into(),
            ready_point: ReadyPoint::ConsoleMarker {
                marker: "ready-é".into(),
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            kernel: None,
            root_image: None,
            initrd: None,
        };
        let artifact = ContentAddressedBlobRef::parse(
            "fixture",
            &format!("blake3:{}", ContentHash::default().to_hex()),
        )?;
        let block = WorldIoNode::block(
            NodeId {
                name: "disk".into(),
            },
            vm.id.clone(),
            WorldIoCoreConfig,
            artifact,
            4096,
            WorldBlockLatency::new(1, 2, 3, 4, 5),
        );
        let ninep = WorldIoNode::ninep(
            NodeId {
                name: "tree".into(),
            },
            vm.id.clone(),
            WorldIoCoreConfig,
            artifact,
            WorldNinePLatency::new(1, 2, 3),
        );
        let vm_only = vec![WorldNodeDef::Vm(vm.clone())];
        let heterogeneous = vec![
            WorldNodeDef::Io(block),
            WorldNodeDef::Io(ninep),
            WorldNodeDef::Vm(vm),
        ];
        for nodes in [vm_only, heterogeneous] {
            let digest = ContentHash::from_canonical_material("fixture", "topology");
            let expected = format!(
                "{}\nfault-topology={}",
                world_material(&nodes, &[]),
                digest.to_hex()
            );
            let material = WorldMaterial {
                nodes: &nodes,
                links: &[],
                fault_topology: digest,
            };
            assert_eq!(format!("{material}"), expected);
            assert_eq!(
                canonical::hash_material("crucible.model.world.v6", &material)?,
                ContentHash::from_canonical_material("crucible.model.world.v6", &expected)
            );
        }
        Ok(())
    }
}
