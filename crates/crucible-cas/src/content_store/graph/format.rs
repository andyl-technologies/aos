//! Canonical identity encoding for one admitted store-graph configuration.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::{StoreGraphConfig, StoreNodeId, StoreNodeSpec, invalid_graph};
use crate::content_store::{GraphViolation, StoreError};

const GRAPH_CONFIGURATION_V1_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v1\0";
const GRAPH_CONFIGURATION_V2_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v2\0";
const GRAPH_CONFIGURATION_V3_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v3\0";
const GRAPH_CONFIGURATION_V4_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v4\0";
const GRAPH_CONFIGURATION_V5_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v5\0";
const GRAPH_CONFIGURATION_V6_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v6\0";
const GRAPH_CONFIGURATION_V7_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v7\0";
const GRAPH_CONFIGURATION_V8_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v8\0";
const GRAPH_CONFIGURATION_V9_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v9\0";
const GRAPH_CONFIGURATION_V10_MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v10\0";

pub(super) fn canonical_graph_configuration(
    config: &StoreGraphConfig,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    let has_compressed_directory = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::CompressedDirectory { .. }));
    let has_logical_quota = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::LogicalQuota { .. }));
    let has_encrypted_directory = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::EncryptedDirectory { .. }));
    let has_compressed_encrypted_directory = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::CompressedEncryptedDirectory { .. }));
    let has_durability_policy = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::DurabilityPolicy { .. }));
    let has_namespaced = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::Namespaced { .. }));
    let has_profile_validation = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::ProfileValidated { .. }));
    let has_physical_quota = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::PhysicalQuota { .. }));
    let has_s3 = config
        .nodes
        .values()
        .any(|node| matches!(node, StoreNodeSpec::S3 { .. }));
    bytes.extend_from_slice(if has_s3 {
        GRAPH_CONFIGURATION_V10_MAGIC
    } else if has_physical_quota {
        GRAPH_CONFIGURATION_V9_MAGIC
    } else if has_profile_validation {
        GRAPH_CONFIGURATION_V8_MAGIC
    } else if has_namespaced {
        GRAPH_CONFIGURATION_V7_MAGIC
    } else if has_durability_policy {
        GRAPH_CONFIGURATION_V6_MAGIC
    } else if has_compressed_encrypted_directory {
        GRAPH_CONFIGURATION_V5_MAGIC
    } else if has_encrypted_directory {
        GRAPH_CONFIGURATION_V4_MAGIC
    } else if has_logical_quota {
        GRAPH_CONFIGURATION_V3_MAGIC
    } else if has_compressed_directory {
        GRAPH_CONFIGURATION_V2_MAGIC
    } else {
        GRAPH_CONFIGURATION_V1_MAGIC
    });
    encode_node_id(&mut bytes, &config.root)?;
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
            StoreNodeSpec::Memory { max_logical_bytes } => {
                bytes.push(1);
                bytes.extend_from_slice(&max_logical_bytes.to_be_bytes());
            }
            StoreNodeSpec::Directory { root } => {
                bytes.push(2);
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
            StoreNodeSpec::Tiered {
                tiers,
                write_tier,
                promote_reads,
            } => {
                bytes.push(6);
                encode_count(&mut bytes, tiers.len())?;
                for child in tiers {
                    encode_node_id(&mut bytes, child)?;
                }
                let write_tier = u16::try_from(*write_tier)
                    .map_err(|_| invalid_graph(id.as_str(), GraphViolation::TooManyNodes))?;
                bytes.extend_from_slice(&write_tier.to_be_bytes());
                bytes.push(u8::from(*promote_reads));
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
