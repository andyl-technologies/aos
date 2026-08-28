//! Strict deployment-file adapter for a composed local campaign store.
//!
//! The authored TOML carries non-secret graph configuration and paths to
//! separately protected key material. Unknown fields, unsupported versions,
//! duplicate identifiers, volatile roots, and insecure files or directories
//! fail before the campaign repository or endpoint is opened.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Take};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crucible_campaign::{CAMPAIGN_OBJECT_PROFILE_POLICY_V1, CampaignObjectProfiler};
use crucible_cas::content_store::{
    ContentId, DirectoryRefBackend, DurabilityRequirement, ObjectKind, StoreEncryptionKey,
    StoreEncryptionKeyId, StoreGraph, StoreGraphAdmin, StoreGraphConfig, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders,
    StoreGraphS3Clients, StoreNamespaceAuthorizer, StoreNamespaceId, StoreNamespaceOperation,
    StoreNodeId, StoreNodeSpec, StoreObjectProfilePolicyId, StorePhysicalQuotaPolicyId,
};
use crucible_linux_resource::LinuxProjectQuotaBinder;
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use super::*;

const CAMPAIGN_STORE_SCHEMA: &str = "crucible.campaign-repository-store";
const CAMPAIGN_STORE_VERSION: u32 = 1;
const MAX_CAMPAIGN_STORE_DEPLOYMENT_BYTES: usize = 256 * 1024;
const MAX_CAMPAIGN_STORE_KEY_BYTES: usize = 32;
const CAMPAIGN_STORE_OBJECT_KINDS: [ObjectKind; 14] = [
    ObjectKind::CampaignFact,
    ObjectKind::CampaignSnapshot,
    ObjectKind::MerkleNode,
    ObjectKind::Scenario,
    ObjectKind::Configuration,
    ObjectKind::Policy,
    ObjectKind::ExactManifest,
    ObjectKind::RamExtent,
    ObjectKind::DiskExtent,
    ObjectKind::DeviceState,
    ObjectKind::Observation,
    ObjectKind::Finding,
    ObjectKind::Projection,
    ObjectKind::Trace,
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignStoreDeployment {
    schema: String,
    version: u32,
    root: String,
    admitted_kinds: Vec<String>,
    ref_directory: PathBuf,
    #[serde(default)]
    keys: Vec<AuthoredEncryptionKey>,
    #[serde(default)]
    namespaces: Vec<AuthoredNamespacePolicy>,
    #[serde(default)]
    physical_quota_policies: Vec<String>,
    nodes: Vec<AuthoredStoreNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEncryptionKey {
    id: String,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredNamespacePolicy {
    id: String,
    operations: Vec<AuthoredNamespaceOperation>,
    object_kinds: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum AuthoredNamespaceOperation {
    Contains,
    Read,
    Put,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredStoreNode {
    id: String,
    spec: AuthoredStoreNodeSpec,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AuthoredStoreNodeSpec {
    Directory {
        root: PathBuf,
    },
    CompressedDirectory {
        root: PathBuf,
        maximum_logical_object_bytes: u64,
    },
    EncryptedDirectory {
        root: PathBuf,
        maximum_logical_object_bytes: u64,
        key_id: String,
    },
    CompressedEncryptedDirectory {
        root: PathBuf,
        maximum_logical_object_bytes: u64,
        key_id: String,
    },
    Packed {
        root: PathBuf,
        target_pack_bytes: u64,
    },
    Verified {
        child: String,
    },
    Routed {
        routes: BTreeMap<String, String>,
    },
    Tiered {
        tiers: Vec<String>,
        write_tier: usize,
        promote_reads: bool,
    },
    ReadThrough {
        cache: String,
        source: String,
    },
    WriteThrough {
        children: Vec<String>,
    },
    WriteBack {
        staging: String,
        destination: String,
        journal_root: PathBuf,
        maximum_pending_objects: u64,
        maximum_pending_bytes: u64,
    },
    DurabilityPolicy {
        child: String,
        requirements: BTreeMap<String, AuthoredDurabilityRequirement>,
    },
    Metrics {
        child: String,
    },
    LogicalQuota {
        child: String,
        state_root: PathBuf,
        maximum_objects: u64,
        maximum_logical_bytes: u64,
    },
    PhysicalQuota {
        child: String,
        policy: String,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    },
    Namespaced {
        child: String,
        namespace: String,
    },
    ProfileValidated {
        child: String,
        policy: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredDurabilityRequirement {
    minimum_durable_placements: u16,
    allow_deferred_write: bool,
}

#[derive(Debug)]
struct StaticNamespaceAuthorizer {
    operations: BTreeSet<AuthoredNamespaceOperation>,
    object_kinds: BTreeSet<ObjectKind>,
}

impl StoreNamespaceAuthorizer for StaticNamespaceAuthorizer {
    fn authorize(
        &self,
        operation: StoreNamespaceOperation,
        id: ContentId,
    ) -> Result<(), crucible_cas::content_store::StoreError> {
        let operation = match operation {
            StoreNamespaceOperation::Contains => AuthoredNamespaceOperation::Contains,
            StoreNamespaceOperation::Read => AuthoredNamespaceOperation::Read,
            StoreNamespaceOperation::Put => AuthoredNamespaceOperation::Put,
        };
        if self.operations.contains(&operation) && self.object_kinds.contains(&id.kind()) {
            Ok(())
        } else {
            Err(crucible_cas::content_store::StoreError::Unauthorized)
        }
    }
}

pub(super) fn load_campaign_repository_store(
    deployment_path: &Path,
) -> Result<crucible_daemon::CampaignLocalRepositoryStore, CliError> {
    let (graph, refs, maintenance) = load_campaign_repository_graph(deployment_path)?;
    crucible_daemon::CampaignLocalRepositoryStore::new_with_maintenance(graph, refs, maintenance)
        .map_err(|error| {
            campaign_store_error(format!("repository-store admission failed: {error}"))
        })
}

fn load_campaign_repository_graph(
    deployment_path: &Path,
) -> Result<(Arc<StoreGraph>, Arc<DirectoryRefBackend>, StoreGraphAdmin), CliError> {
    let bytes = read_secure_file(
        deployment_path,
        MAX_CAMPAIGN_STORE_DEPLOYMENT_BYTES,
        "campaign store deployment",
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| campaign_store_error(format!("deployment is not UTF-8: {error}")))?;
    let deployment: CampaignStoreDeployment = toml::from_str(text)
        .map_err(|error| campaign_store_error(format!("invalid deployment: {error}")))?;
    if deployment.schema != CAMPAIGN_STORE_SCHEMA || deployment.version != CAMPAIGN_STORE_VERSION {
        return Err(campaign_store_error("unsupported schema or version"));
    }

    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    validate_secure_directory(
        &deployment.ref_directory,
        user_id,
        group_id,
        "ref directory",
    )?;

    let admitted_kinds = parse_object_kind_set(&deployment.admitted_kinds, "admitted kind")?;
    if admitted_kinds != BTreeSet::from(CAMPAIGN_STORE_OBJECT_KINDS) {
        return Err(campaign_store_error(
            "admitted kinds do not exactly cover the campaign repository profile",
        ));
    }
    let mut nodes = BTreeMap::new();
    for authored in deployment.nodes {
        let id = StoreNodeId::new(authored.id)
            .map_err(|error| campaign_store_error(format!("invalid node ID: {error}")))?;
        let spec = authored.spec.into_store(user_id, group_id)?;
        if nodes.insert(id, spec).is_some() {
            return Err(campaign_store_error("duplicate node ID"));
        }
    }

    let required_keys = nodes
        .values()
        .filter_map(|node| match node {
            StoreNodeSpec::EncryptedDirectory { key_id, .. }
            | StoreNodeSpec::CompressedEncryptedDirectory { key_id, .. } => Some(key_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut authored_keys = BTreeMap::new();
    for authored in deployment.keys {
        let id = StoreEncryptionKeyId::new(authored.id)
            .map_err(|error| campaign_store_error(format!("invalid key ID: {error}")))?;
        if authored_keys.insert(id, authored.path).is_some() {
            return Err(campaign_store_error("duplicate encryption key ID"));
        }
    }
    if authored_keys.keys().cloned().collect::<BTreeSet<_>>() != required_keys {
        return Err(campaign_store_error(
            "encryption-key capabilities do not exactly match encrypted graph leaves",
        ));
    }
    let mut keys = StoreGraphKeyring::new();
    for (id, path) in authored_keys {
        let bytes = read_secure_file(
            &path,
            MAX_CAMPAIGN_STORE_KEY_BYTES,
            "campaign store encryption key",
        )?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            campaign_store_error("campaign store encryption key is not exactly 32 bytes")
        })?;
        let key = StoreEncryptionKey::new(bytes)
            .map_err(|error| campaign_store_error(format!("invalid encryption key: {error}")))?;
        keys.insert(id, key)
            .map_err(|error| campaign_store_error(format!("duplicate encryption key: {error}")))?;
    }

    let required_namespaces = nodes
        .values()
        .filter_map(|node| match node {
            StoreNodeSpec::Namespaced { namespace, .. } => Some(namespace.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut authored_namespaces = BTreeMap::new();
    for authored in deployment.namespaces {
        let namespace = StoreNamespaceId::new(authored.id).map_err(|error| {
            campaign_store_error(format!("invalid namespace policy ID: {error}"))
        })?;
        if authored_namespaces
            .insert(namespace, (authored.operations, authored.object_kinds))
            .is_some()
        {
            return Err(campaign_store_error("duplicate namespace policy ID"));
        }
    }
    if authored_namespaces.keys().cloned().collect::<BTreeSet<_>>() != required_namespaces {
        return Err(campaign_store_error(
            "namespace capabilities do not exactly match namespaced graph nodes",
        ));
    }
    let mut authorizers = StoreGraphNamespaceAuthorizers::new();
    for (namespace, (authored_operations, authored_object_kinds)) in authored_namespaces {
        let operation_count = authored_operations.len();
        let operations = authored_operations.into_iter().collect::<BTreeSet<_>>();
        let object_kinds = parse_object_kind_set(&authored_object_kinds, "namespace object kind")?;
        if operations.len() != operation_count
            || operations
                != BTreeSet::from([
                    AuthoredNamespaceOperation::Contains,
                    AuthoredNamespaceOperation::Read,
                    AuthoredNamespaceOperation::Put,
                ])
            || object_kinds != BTreeSet::from(CAMPAIGN_STORE_OBJECT_KINDS)
        {
            return Err(campaign_store_error(
                "namespace policy must grant each repository operation and campaign object kind exactly once",
            ));
        }
        authorizers
            .insert(
                namespace,
                Arc::new(StaticNamespaceAuthorizer {
                    operations,
                    object_kinds,
                }),
            )
            .map_err(|error| {
                campaign_store_error(format!("duplicate namespace policy: {error}"))
            })?;
    }

    let mut profilers = StoreGraphObjectProfilers::new();
    let campaign_profile = StoreObjectProfilePolicyId::new(CAMPAIGN_OBJECT_PROFILE_POLICY_V1)
        .map_err(|error| {
            campaign_store_error(format!("campaign profile ID is invalid: {error}"))
        })?;
    if nodes.values().any(|node| {
        matches!(
            node,
            StoreNodeSpec::ProfileValidated { policy, .. } if policy != &campaign_profile
        )
    }) {
        return Err(campaign_store_error(
            "profile-validated graph node does not name the canonical campaign policy",
        ));
    }
    profilers
        .insert(campaign_profile, Arc::new(CampaignObjectProfiler))
        .map_err(|error| campaign_store_error(format!("campaign profiler is invalid: {error}")))?;

    let required_physical_quotas = nodes
        .values()
        .filter_map(|node| match node {
            StoreNodeSpec::PhysicalQuota { policy, .. } => Some(policy.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut configured_physical_quotas = BTreeSet::new();
    for policy in deployment.physical_quota_policies {
        let policy = StorePhysicalQuotaPolicyId::new(policy).map_err(|error| {
            campaign_store_error(format!("invalid physical-quota policy ID: {error}"))
        })?;
        if !configured_physical_quotas.insert(policy) {
            return Err(campaign_store_error("duplicate physical-quota policy ID"));
        }
    }
    if configured_physical_quotas != required_physical_quotas {
        return Err(campaign_store_error(
            "physical-quota capabilities do not exactly match graph nodes",
        ));
    }
    let mut physical_quotas = StoreGraphPhysicalQuotaBinders::new();
    for policy in configured_physical_quotas {
        physical_quotas
            .insert(policy, Arc::new(LinuxProjectQuotaBinder::new()))
            .map_err(|error| {
                campaign_store_error(format!("duplicate physical-quota policy: {error}"))
            })?;
    }

    let root = StoreNodeId::new(deployment.root)
        .map_err(|error| campaign_store_error(format!("invalid root node ID: {error}")))?;
    let (graph, maintenance) = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root,
            admitted_kinds,
            nodes,
        },
        &keys,
        &authorizers,
        &profilers,
        &physical_quotas,
        &StoreGraphS3Clients::new(),
    )
    .map_err(|error| campaign_store_error(format!("graph admission failed: {error}")))?;
    let refs = Arc::new(DirectoryRefBackend::new(deployment.ref_directory));
    Ok((Arc::new(graph), refs, maintenance))
}

impl AuthoredStoreNodeSpec {
    fn into_store(self, user_id: u32, group_id: u32) -> Result<StoreNodeSpec, CliError> {
        match self {
            Self::Directory { root } => {
                validate_secure_directory(&root, user_id, group_id, "directory leaf")?;
                Ok(StoreNodeSpec::Directory { root })
            }
            Self::CompressedDirectory {
                root,
                maximum_logical_object_bytes,
            } => {
                validate_secure_directory(&root, user_id, group_id, "compressed directory leaf")?;
                Ok(StoreNodeSpec::CompressedDirectory {
                    root,
                    maximum_logical_object_bytes,
                })
            }
            Self::EncryptedDirectory {
                root,
                maximum_logical_object_bytes,
                key_id,
            } => {
                validate_secure_directory(&root, user_id, group_id, "encrypted directory leaf")?;
                Ok(StoreNodeSpec::EncryptedDirectory {
                    root,
                    maximum_logical_object_bytes,
                    key_id: StoreEncryptionKeyId::new(key_id).map_err(|error| {
                        campaign_store_error(format!("invalid encrypted leaf key ID: {error}"))
                    })?,
                })
            }
            Self::CompressedEncryptedDirectory {
                root,
                maximum_logical_object_bytes,
                key_id,
            } => {
                validate_secure_directory(
                    &root,
                    user_id,
                    group_id,
                    "compressed encrypted directory leaf",
                )?;
                Ok(StoreNodeSpec::CompressedEncryptedDirectory {
                    root,
                    maximum_logical_object_bytes,
                    key_id: StoreEncryptionKeyId::new(key_id).map_err(|error| {
                        campaign_store_error(format!("invalid encrypted leaf key ID: {error}"))
                    })?,
                })
            }
            Self::Packed {
                root,
                target_pack_bytes,
            } => {
                validate_secure_directory(&root, user_id, group_id, "packed leaf")?;
                Ok(StoreNodeSpec::Packed {
                    root,
                    target_pack_bytes,
                })
            }
            Self::Verified { child } => Ok(StoreNodeSpec::Verified {
                child: parse_node_id(child, "verified child")?,
            }),
            Self::Routed { routes } => Ok(StoreNodeSpec::Routed {
                routes: parse_routes(routes)?,
            }),
            Self::Tiered {
                tiers,
                write_tier,
                promote_reads,
            } => Ok(StoreNodeSpec::Tiered {
                tiers: parse_node_ids(tiers, "tier")?,
                write_tier,
                promote_reads,
            }),
            Self::ReadThrough { cache, source } => Ok(StoreNodeSpec::ReadThrough {
                cache: parse_node_id(cache, "read-through cache")?,
                source: parse_node_id(source, "read-through source")?,
            }),
            Self::WriteThrough { children } => Ok(StoreNodeSpec::WriteThrough {
                children: parse_node_ids(children, "write-through child")?,
            }),
            Self::WriteBack {
                staging,
                destination,
                journal_root,
                maximum_pending_objects,
                maximum_pending_bytes,
            } => {
                validate_secure_directory(&journal_root, user_id, group_id, "write-back journal")?;
                Ok(StoreNodeSpec::WriteBack {
                    staging: parse_node_id(staging, "write-back staging child")?,
                    destination: parse_node_id(destination, "write-back destination child")?,
                    journal_root,
                    maximum_pending_objects,
                    maximum_pending_bytes,
                })
            }
            Self::DurabilityPolicy {
                child,
                requirements,
            } => Ok(StoreNodeSpec::DurabilityPolicy {
                child: parse_node_id(child, "durability-policy child")?,
                requirements: parse_durability_requirements(requirements)?,
            }),
            Self::Metrics { child } => Ok(StoreNodeSpec::Metrics {
                child: parse_node_id(child, "metrics child")?,
            }),
            Self::LogicalQuota {
                child,
                state_root,
                maximum_objects,
                maximum_logical_bytes,
            } => {
                validate_secure_directory(&state_root, user_id, group_id, "logical-quota state")?;
                Ok(StoreNodeSpec::LogicalQuota {
                    child: parse_node_id(child, "logical-quota child")?,
                    state_root,
                    maximum_objects,
                    maximum_logical_bytes,
                })
            }
            Self::PhysicalQuota {
                child,
                policy,
                project_id,
                maximum_physical_bytes,
                maximum_inodes,
            } => Ok(StoreNodeSpec::PhysicalQuota {
                child: parse_node_id(child, "physical-quota child")?,
                policy: StorePhysicalQuotaPolicyId::new(policy).map_err(|error| {
                    campaign_store_error(format!("invalid physical-quota policy ID: {error}"))
                })?,
                project_id,
                maximum_physical_bytes,
                maximum_inodes,
            }),
            Self::Namespaced { child, namespace } => Ok(StoreNodeSpec::Namespaced {
                child: parse_node_id(child, "namespaced child")?,
                namespace: StoreNamespaceId::new(namespace).map_err(|error| {
                    campaign_store_error(format!("invalid namespace policy ID: {error}"))
                })?,
            }),
            Self::ProfileValidated { child, policy } => Ok(StoreNodeSpec::ProfileValidated {
                child: parse_node_id(child, "profile-validated child")?,
                policy: StoreObjectProfilePolicyId::new(policy).map_err(|error| {
                    campaign_store_error(format!("invalid object-profile policy ID: {error}"))
                })?,
            }),
        }
    }
}

fn parse_node_id(value: String, role: &str) -> Result<StoreNodeId, CliError> {
    StoreNodeId::new(value)
        .map_err(|error| campaign_store_error(format!("invalid {role} node ID: {error}")))
}

fn parse_node_ids(values: Vec<String>, role: &str) -> Result<Vec<StoreNodeId>, CliError> {
    values
        .into_iter()
        .map(|value| parse_node_id(value, role))
        .collect()
}

fn parse_routes(
    routes: BTreeMap<String, String>,
) -> Result<BTreeMap<ObjectKind, StoreNodeId>, CliError> {
    let mut parsed = BTreeMap::new();
    for (kind, child) in routes {
        let kind = parse_object_kind(&kind)?;
        if parsed
            .insert(kind, parse_node_id(child, "route child")?)
            .is_some()
        {
            return Err(campaign_store_error("duplicate routed object kind"));
        }
    }
    Ok(parsed)
}

fn parse_durability_requirements(
    requirements: BTreeMap<String, AuthoredDurabilityRequirement>,
) -> Result<BTreeMap<ObjectKind, DurabilityRequirement>, CliError> {
    let mut parsed = BTreeMap::new();
    for (kind, requirement) in requirements {
        let kind = parse_object_kind(&kind)?;
        let requirement = DurabilityRequirement::new(
            requirement.minimum_durable_placements,
            requirement.allow_deferred_write,
        )
        .map_err(|error| {
            campaign_store_error(format!("invalid durability requirement: {error}"))
        })?;
        if parsed.insert(kind, requirement).is_some() {
            return Err(campaign_store_error(
                "duplicate durability-requirement object kind",
            ));
        }
    }
    Ok(parsed)
}

fn parse_object_kind_set(values: &[String], role: &str) -> Result<BTreeSet<ObjectKind>, CliError> {
    let mut parsed = BTreeSet::new();
    for value in values {
        let kind = parse_object_kind(value)?;
        if !parsed.insert(kind) {
            return Err(campaign_store_error(format!("duplicate {role}: {value}")));
        }
    }
    Ok(parsed)
}

fn parse_object_kind(value: &str) -> Result<ObjectKind, CliError> {
    let kind = match value {
        "campaign-fact" => ObjectKind::CampaignFact,
        "campaign-snapshot" => ObjectKind::CampaignSnapshot,
        "merkle-node" => ObjectKind::MerkleNode,
        "scenario" => ObjectKind::Scenario,
        "configuration" => ObjectKind::Configuration,
        "policy" => ObjectKind::Policy,
        "exact-manifest" => ObjectKind::ExactManifest,
        "ram-extent" => ObjectKind::RamExtent,
        "disk-extent" => ObjectKind::DiskExtent,
        "device-state" => ObjectKind::DeviceState,
        "observation" => ObjectKind::Observation,
        "finding" => ObjectKind::Finding,
        "projection" => ObjectKind::Projection,
        "trace" => ObjectKind::Trace,
        _ => {
            return Err(campaign_store_error(format!(
                "unknown object kind: {value}"
            )));
        }
    };
    Ok(kind)
}

fn validate_secure_directory(
    path: &Path,
    user_id: u32,
    group_id: u32,
    role: &str,
) -> Result<(), CliError> {
    validate_absolute_normal_path(path, role)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        campaign_store_error(format!("cannot inspect {role} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != user_id
        || metadata.gid() != group_id
        || metadata.mode() & 0o022 != 0
    {
        return Err(campaign_store_error(format!(
            "{role} {} is not an exact-owner non-group/other-writable directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_absolute_normal_path(path: &Path, role: &str) -> Result<(), CliError> {
    let valid = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !valid {
        return Err(campaign_store_error(format!(
            "{role} path must be absolute and lexically normalized"
        )));
    }
    Ok(())
}

fn read_secure_file(path: &Path, maximum_bytes: usize, role: &str) -> Result<Vec<u8>, CliError> {
    validate_absolute_normal_path(path, role)?;
    let before = fs::symlink_metadata(path).map_err(|error| {
        campaign_store_error(format!("cannot inspect {role} {}: {error}", path.display()))
    })?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    if !before.file_type().is_file()
        || before.uid() != user_id
        || before.gid() != group_id
        || before.mode() & 0o777 != 0o600
        || before.len() > maximum_bytes as u64
    {
        return Err(campaign_store_error(format!(
            "{role} {} is not an exact-owner mode-0600 bounded file",
            path.display()
        )));
    }
    let opened = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        campaign_store_error(format!("cannot open {role} {}: {error}", path.display()))
    })?;
    let mut opened = File::from(opened);
    let after = opened.metadata().map_err(|error| {
        campaign_store_error(format!(
            "cannot authenticate {role} {}: {error}",
            path.display()
        ))
    })?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != user_id
        || after.gid() != group_id
        || after.mode() & 0o777 != 0o600
        || after.len() != before.len()
    {
        return Err(campaign_store_error(format!(
            "{role} {} changed while it was opened",
            path.display()
        )));
    }
    let maximum = u64::try_from(maximum_bytes)
        .map_err(|_| campaign_store_error(format!("{role} byte limit is invalid")))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(after.len())
            .map_err(|_| campaign_store_error(format!("{role} length is invalid")))?,
    );
    let mut bounded: Take<&mut File> = Read::by_ref(&mut opened).take(maximum.saturating_add(1));
    bounded.read_to_end(&mut bytes).map_err(|error| {
        campaign_store_error(format!("cannot read {role} {}: {error}", path.display()))
    })?;
    if bytes.len() > maximum_bytes || bytes.len() as u64 != after.len() {
        return Err(campaign_store_error(format!(
            "{role} {} changed while it was read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn campaign_store_error(detail: impl std::fmt::Display) -> CliError {
    serve_error(format!(
        "campaign repository-store deployment error: {detail}"
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use crucible_cas::content_store::{BlobHandle, ImmutableBlobBackend};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn strict_composed_store_loads_and_reauthenticates_encryption_on_restart() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment("");

        let (graph, refs, _maintenance) =
            load_campaign_repository_graph(&deployment).expect("load composed campaign store");
        let bytes = b"initialize encrypted campaign storage";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        graph
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("initialize encrypted campaign storage");
        drop(refs);
        drop(graph);
        load_campaign_repository_store(&deployment).expect("restart composed campaign store");

        fs::write(&fixture.key, [0x52; 32]).expect("replace key generation");
        let (wrong_key, _refs, _maintenance) =
            load_campaign_repository_graph(&deployment).expect("construct wrong-key graph");
        let _error = wrong_key
            .contains(id)
            .expect_err("changed key must not authenticate encrypted storage");
    }

    #[test]
    fn strict_composed_store_rejects_unknown_fields_before_backend_effects() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment("unknown_field = true\n");

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("unknown deployment field was accepted");
        };
        assert!(error.to_string().contains("unknown field"));
        assert!(
            fs::read_dir(&fixture.objects)
                .expect("objects directory")
                .next()
                .is_none()
        );
        assert!(
            fs::read_dir(&fixture.refs)
                .expect("refs directory")
                .next()
                .is_none()
        );
    }

    #[test]
    fn strict_composed_store_requires_the_complete_campaign_kind_profile() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment_with_kinds("[\"campaign-fact\"]", "");

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("partial campaign kind profile was accepted");
        };
        assert!(error.to_string().contains("do not exactly cover"));
    }

    #[test]
    fn strict_composed_store_rejects_extraneous_keys_before_reading_them() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment(
            r#"[[keys]]
id = "unused-key"
path = "/definitely/missing/campaign-store-key.bin"
"#,
        );

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("extraneous encryption-key capability was accepted");
        };
        assert!(
            error
                .to_string()
                .contains("do not exactly match encrypted graph leaves")
        );
    }

    #[test]
    fn strict_composed_store_rejects_insecure_deployment_permissions() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment("");
        fs::set_permissions(&deployment, fs::Permissions::from_mode(0o640))
            .expect("weaken deployment mode");

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("insecure deployment mode was accepted");
        };
        assert!(error.to_string().contains("mode-0600"));
    }

    #[test]
    fn serve_selects_the_composed_store_without_creating_default_leafs() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment("");
        let state = fixture.root.join("state");
        fs::create_dir(&state).expect("campaign state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("secure campaign state");
        let metadata = fs::metadata(&fixture.root).expect("fixture metadata");
        let policy = fixture.root.join("policy.toml");
        fs::write(
            &policy,
            format!(
                r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "operator"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"
"#,
                metadata.uid(),
                metadata.gid()
            ),
        )
        .expect("campaign policy");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600))
            .expect("secure campaign policy");
        let socket = fixture.root.join("campaign.sock");
        let cli = Cli::parse_from([
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-unauthenticated-bind",
            "--campaign-socket",
            socket.to_str().expect("socket path"),
            "--campaign-state",
            state.to_str().expect("state path"),
            "--campaign-policy",
            policy.to_str().expect("policy path"),
            "--campaign-store",
            deployment.to_str().expect("deployment path"),
        ]);
        let Commands::Serve(args) = &cli.command else {
            panic!("expected serve command");
        };
        validate_serve_invocation(args).expect("valid composed-store serve profile");
        let service = open_local_campaign_service(args, None)
            .expect("open composed-store service")
            .expect("configured campaign service");
        assert!(!state.join("objects").exists());
        assert!(!state.join("refs").exists());
        drop(service);
    }

    struct StoreDeploymentFixture {
        _directory: TempDir,
        root: PathBuf,
        objects: PathBuf,
        refs: PathBuf,
        key: PathBuf,
    }

    impl StoreDeploymentFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("campaign store fixture");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("secure fixture root");
            let objects = directory.path().join("objects");
            let refs = directory.path().join("refs");
            fs::create_dir(&objects).expect("objects directory");
            fs::create_dir(&refs).expect("refs directory");
            fs::set_permissions(&objects, fs::Permissions::from_mode(0o700))
                .expect("secure objects directory");
            fs::set_permissions(&refs, fs::Permissions::from_mode(0o700))
                .expect("secure refs directory");
            let key = directory.path().join("key.bin");
            fs::write(&key, [0x31; 32]).expect("encryption key");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
                .expect("secure encryption key");
            Self {
                root: directory.path().to_owned(),
                _directory: directory,
                objects,
                refs,
                key,
            }
        }

        fn write_deployment(&self, extra: &str) -> PathBuf {
            self.write_deployment_with_kinds(&all_object_kinds_toml(), extra)
        }

        fn write_deployment_with_kinds(&self, kinds: &str, extra: &str) -> PathBuf {
            let deployment = self.root.join("store.toml");
            fs::write(
                &deployment,
                format!(
                    r#"schema = "crucible.campaign-repository-store"
version = 1
root = "profile"
admitted_kinds = {kinds}
ref_directory = {refs:?}
{extra}
[[keys]]
id = "campaign-key"
path = {key:?}

[[namespaces]]
id = "campaign/local"
operations = ["contains", "read", "put"]
object_kinds = {kinds}

[[nodes]]
id = "encrypted"
[nodes.spec]
kind = "encrypted-directory"
root = {objects:?}
maximum_logical_object_bytes = 67108864
key_id = "campaign-key"

[[nodes]]
id = "namespace"
[nodes.spec]
kind = "namespaced"
child = "encrypted"
namespace = "campaign/local"

[[nodes]]
id = "profile"
[nodes.spec]
kind = "profile-validated"
child = "namespace"
policy = "crucible.campaign.object-profile.v1"
"#,
                    refs = self.refs,
                    key = self.key,
                    objects = self.objects,
                ),
            )
            .expect("write campaign store deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600))
                .expect("secure campaign store deployment");
            deployment
        }
    }

    fn all_object_kinds_toml() -> String {
        let kinds = CAMPAIGN_STORE_OBJECT_KINDS
            .into_iter()
            .map(|kind| format!("{:?}", kind.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{kinds}]")
    }
}
