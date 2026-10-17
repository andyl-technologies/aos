//! Canonical identity encoding for one admitted store-graph configuration.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::{StoreGraphConfig, StoreNodeId, StoreNodeSpec, invalid_graph};
use crate::content_store::{GraphViolation, StoreError};

const GRAPH_CONFIGURATION_V13_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v13\0";

pub(super) fn canonical_graph_configuration(
    config: &StoreGraphConfig,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(GRAPH_CONFIGURATION_V13_MAGIC);
    encode_node_id(&mut bytes, &config.root)?;
    match &config.gc_mark_root {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            encode_node_id(&mut bytes, root)?;
        }
    }
    encode_count(&mut bytes, config.admitted_kinds.len())?;
    let mut admitted_kinds = config
        .admitted_kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    admitted_kinds.sort_unstable();
    for kind in admitted_kinds {
        encode_string(&mut bytes, kind)?;
    }
    encode_count(&mut bytes, config.nodes.len())?;
    for (id, node) in &config.nodes {
        encode_node_id(&mut bytes, id)?;
        match node {
            StoreNodeSpec::Memory {
                max_logical_bytes,
                max_objects,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&max_logical_bytes.to_be_bytes());
                bytes.extend_from_slice(&max_objects.to_be_bytes());
            }
            StoreNodeSpec::Directory { root } => {
                bytes.push(2);
                encode_path(&mut bytes, root)?;
            }
            StoreNodeSpec::Sqlite { root } => {
                bytes.push(20);
                encode_path(&mut bytes, root)?;
            }
            StoreNodeSpec::CompressedDirectory {
                root,
                maximum_logical_object_bytes,
            } => {
                bytes.push(11);
                encode_path(&mut bytes, root)?;
                bytes.extend_from_slice(&maximum_logical_object_bytes.to_be_bytes());
            }
            StoreNodeSpec::EncryptedDirectory {
                root,
                maximum_logical_object_bytes,
                key_id,
            } => {
                bytes.push(13);
                encode_path(&mut bytes, root)?;
                bytes.extend_from_slice(&maximum_logical_object_bytes.to_be_bytes());
                encode_string(&mut bytes, key_id.as_str())?;
            }
            StoreNodeSpec::CompressedEncryptedDirectory {
                root,
                maximum_logical_object_bytes,
                key_id,
            } => {
                bytes.push(14);
                encode_path(&mut bytes, root)?;
                bytes.extend_from_slice(&maximum_logical_object_bytes.to_be_bytes());
                encode_string(&mut bytes, key_id.as_str())?;
            }
            StoreNodeSpec::Packed {
                root,
                target_pack_bytes,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(super::super::packed::INDEX_VERSION_MARKER);
                encode_path(&mut bytes, root)?;
                bytes.extend_from_slice(&target_pack_bytes.to_be_bytes());
            }
            StoreNodeSpec::S3 {
                endpoint,
                bucket,
                prefix,
                maximum_logical_object_bytes,
                multipart_part_bytes,
            } => {
                bytes.push(19);
                encode_string(&mut bytes, endpoint.as_str())?;
                encode_string(&mut bytes, bucket)?;
                encode_string(&mut bytes, prefix)?;
                bytes.extend_from_slice(&maximum_logical_object_bytes.to_be_bytes());
                bytes.extend_from_slice(&multipart_part_bytes.to_be_bytes());
            }
            StoreNodeSpec::Verified { child } => {
                bytes.push(4);
                encode_node_id(&mut bytes, child)?;
            }
            StoreNodeSpec::Routed { routes } => {
                bytes.push(5);
                encode_count(&mut bytes, routes.len())?;
                let mut routes = routes.iter().collect::<Vec<_>>();
                routes.sort_unstable_by_key(|(kind, _child)| kind.as_str());
                for (kind, child) in routes {
                    encode_string(&mut bytes, kind.as_str())?;
                    encode_node_id(&mut bytes, child)?;
                }
            }
            StoreNodeSpec::Tiered { tiers } => {
                bytes.push(6);
                encode_count(&mut bytes, tiers.len())?;
                for tier in tiers {
                    encode_node_id(&mut bytes, &tier.child)?;
                    bytes.push(u8::from(tier.readable));
                    bytes.push(u8::from(tier.writable));
                    bytes.push(u8::from(tier.promote_reads));
                }
            }
            StoreNodeSpec::ReadThrough { cache, source } => {
                bytes.push(7);
                encode_node_id(&mut bytes, cache)?;
                encode_node_id(&mut bytes, source)?;
            }
            StoreNodeSpec::WriteThrough { children } => {
                bytes.push(8);
                encode_count(&mut bytes, children.len())?;
                for child in children {
                    encode_node_id(&mut bytes, child)?;
                }
            }
            StoreNodeSpec::WriteBack {
                staging,
                destination,
                journal_root,
                maximum_pending_objects,
                maximum_pending_bytes,
            } => {
                bytes.push(9);
                encode_node_id(&mut bytes, staging)?;
                encode_node_id(&mut bytes, destination)?;
                encode_path(&mut bytes, journal_root)?;
                bytes.extend_from_slice(&maximum_pending_objects.to_be_bytes());
                bytes.extend_from_slice(&maximum_pending_bytes.to_be_bytes());
            }
            StoreNodeSpec::DurabilityPolicy {
                child,
                requirements,
            } => {
                bytes.push(15);
                encode_node_id(&mut bytes, child)?;
                encode_count(&mut bytes, requirements.len())?;
                let mut requirements = requirements.iter().collect::<Vec<_>>();
                requirements.sort_unstable_by_key(|(kind, _requirement)| kind.as_str());
                for (kind, requirement) in requirements {
                    encode_string(&mut bytes, kind.as_str())?;
                    bytes
                        .extend_from_slice(&requirement.minimum_durable_placements().to_be_bytes());
                    bytes.push(u8::from(requirement.allows_deferred_write()));
                }
            }
            StoreNodeSpec::Metrics { child } => {
                bytes.push(10);
                encode_node_id(&mut bytes, child)?;
            }
            StoreNodeSpec::LogicalQuota {
                child,
                state_root,
                maximum_objects,
                maximum_logical_bytes,
            } => {
                bytes.push(12);
                encode_node_id(&mut bytes, child)?;
                encode_path(&mut bytes, state_root)?;
                bytes.extend_from_slice(&maximum_objects.to_be_bytes());
                bytes.extend_from_slice(&maximum_logical_bytes.to_be_bytes());
            }
            StoreNodeSpec::Namespaced { child, namespace } => {
                bytes.push(16);
                encode_node_id(&mut bytes, child)?;
                encode_string(&mut bytes, namespace.as_str())?;
            }
            StoreNodeSpec::ProfileValidated { child, policy } => {
                bytes.push(17);
                encode_node_id(&mut bytes, child)?;
                encode_string(&mut bytes, policy.as_str())?;
            }
            StoreNodeSpec::PhysicalQuota {
                child,
                policy,
                project_id,
                maximum_physical_bytes,
                maximum_inodes,
            } => {
                bytes.push(18);
                encode_node_id(&mut bytes, child)?;
                encode_string(&mut bytes, policy.as_str())?;
                bytes.extend_from_slice(&project_id.to_be_bytes());
                bytes.extend_from_slice(&maximum_physical_bytes.to_be_bytes());
                bytes.extend_from_slice(&maximum_inodes.to_be_bytes());
            }
        }
    }
    Ok(bytes)
}

fn encode_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), StoreError> {
    let count =
        u16::try_from(count).map_err(|_| invalid_graph("<graph>", GraphViolation::TooManyNodes))?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn encode_node_id(bytes: &mut Vec<u8>, id: &StoreNodeId) -> Result<(), StoreError> {
    encode_string(bytes, id.as_str())
}

fn encode_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
    let length = u16::try_from(value.len())
        .map_err(|_| invalid_graph("<graph>", GraphViolation::InvalidNodeId))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_path(bytes: &mut Vec<u8>, path: &Path) -> Result<(), StoreError> {
    let encoded = path.as_os_str().as_bytes();
    let length = u32::try_from(encoded.len())
        .map_err(|_| invalid_graph("<graph>", GraphViolation::AdministrativePathTooLong))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(encoded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::content_store::graph::StoreGraphConfigurationId;

    fn memory_configuration(max_objects: u64) -> Result<StoreGraphConfig, StoreError> {
        let root = StoreNodeId::new("r")?;
        Ok(StoreGraphConfig {
            root: root.clone(),
            gc_mark_root: None,
            admitted_kinds: BTreeSet::new(),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 4096,
                    max_objects,
                },
            )]),
        })
    }

    #[test]
    fn memory_namespace_capacity_has_a_new_literal_configuration_format() -> Result<(), StoreError>
    {
        // One root, no GC root or admitted kinds, then one Memory node with
        // independently framed byte and object capacities.
        const EXPECTED: &[u8] = b"crucible.content-store.graph-configuration.v13\0\
            \x00\x01r\x00\x00\x00\x00\x01\x00\x01r\x01\
            \x00\x00\x00\x00\x00\x00\x10\x00\
            \x00\x00\x00\x00\x00\x00\x00\x07";
        let configuration = memory_configuration(7)?;

        assert_eq!(canonical_graph_configuration(&configuration)?, EXPECTED);
        assert_eq!(
            StoreGraphConfigurationId::for_config(&configuration)?.as_bytes(),
            [
                11, 117, 122, 14, 166, 213, 208, 143, 188, 134, 22, 181, 23, 148, 47, 215, 6, 206,
                232, 245, 173, 206, 165, 145, 208, 112, 52, 144, 4, 104, 250, 121,
            ],
        );
        assert_ne!(
            StoreGraphConfigurationId::for_config(&configuration)?,
            StoreGraphConfigurationId::for_config(&memory_configuration(8)?)?,
        );
        Ok(())
    }

    #[test]
    fn packed_identity_explicitly_selects_the_bounded_index_version() -> Result<(), StoreError> {
        let root = StoreNodeId::new("r")?;
        let configuration = StoreGraphConfig {
            root: root.clone(),
            gc_mark_root: None,
            admitted_kinds: BTreeSet::new(),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::Packed {
                    root: "/packed".into(),
                    target_pack_bytes: 65_536,
                },
            )]),
        };
        const EXPECTED: &[u8] = b"crucible.content-store.graph-configuration.v13\0\
            \x00\x01r\x00\x00\x00\x00\x01\x00\x01r\x03packed-index-v2\0\
            \x00\x00\x00\x07/packed\x00\x00\x00\x00\x00\x01\x00\x00";

        assert_eq!(canonical_graph_configuration(&configuration)?, EXPECTED);
        Ok(())
    }
}
