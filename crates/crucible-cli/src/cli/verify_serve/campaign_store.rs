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
    BlobInventoryRecord, ContentId, DirectoryRefBackend, DurabilityRequirement, ObjectKind,
    S3RefBackend, StoreEncryptionKey, StoreEncryptionKeyId, StoreGraph, StoreGraphAdmin,
    StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers,
    StoreGraphPhysicalQuotaBinders, StoreNamespaceAuthorizer, StoreNamespaceId,
    StoreNamespaceOperation, StoreNodeId, StoreNodeSpec, StoreObjectProfilePolicyId,
    StorePhysicalQuotaPolicyId,
};
use crucible_linux_resource::LinuxProjectQuotaBinder;
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use super::*;

#[path = "campaign_store/s3.rs"]
mod s3;

use s3::{
    AuthoredS3Endpoint, AuthoredS3RefBackend, ResolvedS3RefBackend, index_s3_endpoints,
    load_s3_capabilities, s3_endpoint_ids, validate_s3_namespace_separation,
    validate_s3_storage_configuration,
};

const CAMPAIGN_STORE_SCHEMA: &str = "crucible.campaign-repository-store";
const CAMPAIGN_STORE_VERSION_1: u32 = 1;
const CAMPAIGN_STORE_VERSION_2: u32 = 2;
const MAX_CAMPAIGN_STORE_DEPLOYMENT_BYTES: usize = 256 * 1024;
const MAX_CAMPAIGN_STORE_KEY_BYTES: usize = 32;
pub(super) const MAX_STORE_VERIFY_PLACEMENTS: u64 = 65_536;
pub(super) const MAX_STORE_VERIFY_LOGICAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;
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
    #[serde(default)]
    ref_directory: Option<PathBuf>,
    #[serde(default)]
    s3_ref: Option<AuthoredS3RefBackend>,
    #[serde(default)]
    s3_endpoints: Vec<AuthoredS3Endpoint>,
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
    S3 {
        endpoint: String,
        bucket: String,
        prefix: String,
        maximum_logical_object_bytes: u64,
        multipart_part_bytes: u64,
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

enum LoadedRefBackend {
    Directory(Arc<DirectoryRefBackend>),
    S3(Arc<S3RefBackend>),
}

enum ResolvedRefBackend {
    Directory(PathBuf),
    S3(ResolvedS3RefBackend),
}

struct LoadedCampaignRepositoryStore {
    graph: Arc<StoreGraph>,
    refs: LoadedRefBackend,
    maintenance: StoreGraphAdmin,
}

pub(super) struct VerifiedCampaignStoreInventory {
    pub(super) configuration: [u8; 32],
    pub(super) placements: u64,
    pub(super) logical_bytes: u64,
    pub(super) physical: Vec<VerifiedCampaignStorePhysicalInventory>,
}

pub(super) struct VerifiedCampaignStorePhysicalInventory {
    pub(super) backend: String,
    pub(super) generation: String,
    pub(super) placements: u64,
    pub(super) logical_bytes: u64,
}

#[derive(Clone, Copy)]
struct StoreVerifyLimits {
    placements: u64,
    logical_bytes: u64,
}

impl StoreVerifyLimits {
    const PRODUCTION: Self = Self {
        placements: MAX_STORE_VERIFY_PLACEMENTS,
        logical_bytes: MAX_STORE_VERIFY_LOGICAL_BYTES,
    };
}

impl LoadedCampaignRepositoryStore {
    fn into_store(self) -> Result<crucible_daemon::CampaignLocalRepositoryStore, CliError> {
        let result = match self.refs {
            LoadedRefBackend::Directory(refs) => {
                crucible_daemon::CampaignLocalRepositoryStore::new_with_maintenance(
                    self.graph,
                    refs,
                    self.maintenance,
                )
            }
            LoadedRefBackend::S3(refs) => {
                crucible_daemon::CampaignLocalRepositoryStore::new_with_maintenance(
                    self.graph,
                    refs,
                    self.maintenance,
                )
            }
        };
        result.map_err(|error| {
            campaign_store_error(format!("repository-store admission failed: {error}"))
        })
    }
}

pub(super) fn load_campaign_repository_store(
    deployment_path: &Path,
) -> Result<crucible_daemon::CampaignLocalRepositoryStore, CliError> {
    load_campaign_repository_graph(deployment_path)?.into_store()
}

pub(super) fn load_campaign_store_graph(
    deployment_path: &Path,
) -> Result<Arc<StoreGraph>, CliError> {
    Ok(load_campaign_repository_graph(deployment_path)?.graph)
}

pub(super) fn verify_campaign_store_inventory(
    deployment_path: &Path,
) -> Result<VerifiedCampaignStoreInventory, CliError> {
    let loaded = load_campaign_repository_graph(deployment_path)?;
    verify_loaded_campaign_store_inventory(
        loaded,
        StoreVerifyLimits::PRODUCTION,
        &mut |_graph, _node| Ok(()),
    )
}

fn verify_loaded_campaign_store_inventory(
    loaded: LoadedCampaignRepositoryStore,
    limits: StoreVerifyLimits,
    after_reads: &mut dyn FnMut(&StoreGraph, StoreNodeId) -> Result<(), CliError>,
) -> Result<VerifiedCampaignStoreInventory, CliError> {
    let mut placements = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut physical = Vec::new();
    for leaf in loaded.maintenance.physical() {
        let mut records = Vec::new();
        let mut exceeded = false;
        let first = {
            let mut fence = leaf.admin().acquire_inventory_fence().map_err(|error| {
                campaign_store_error(format!(
                    "cannot fence physical node {}: {error}",
                    leaf.node().as_str()
                ))
            })?;
            fence
                .visit_inventory(&mut |record: BlobInventoryRecord| {
                    placements = placements.checked_add(1).ok_or_else(|| {
                        exceeded = true;
                        crucible_cas::content_store::StoreError::Quota
                    })?;
                    logical_bytes = logical_bytes
                        .checked_add(record.logical_length())
                        .ok_or_else(|| {
                            exceeded = true;
                            crucible_cas::content_store::StoreError::Quota
                        })?;
                    if placements > limits.placements || logical_bytes > limits.logical_bytes {
                        exceeded = true;
                        return Err(crucible_cas::content_store::StoreError::Quota);
                    }
                    records.push(record);
                    Ok(())
                })
                .map_err(|error| {
                    if exceeded {
                        campaign_store_error(
                            "physical inventory exceeds the fixed verification bound",
                        )
                    } else {
                        campaign_store_error(format!(
                            "cannot inventory physical node {}: {error}",
                            leaf.node().as_str()
                        ))
                    }
                })?
        };

        for record in &records {
            let handle = leaf.read(record.id()).map_err(|error| {
                campaign_store_error(format!(
                    "cannot read physical node {} object {}: {error}",
                    leaf.node().as_str(),
                    record.id().encode()
                ))
            })?;
            if handle.logical_length() != record.logical_length() {
                return Err(campaign_store_error(format!(
                    "physical node {} object {} changed logical length",
                    leaf.node().as_str(),
                    record.id().encode()
                )));
            }
            handle.copy_to(&mut std::io::sink()).map_err(|error| {
                campaign_store_error(format!(
                    "cannot authenticate physical node {} object {}: {error}",
                    leaf.node().as_str(),
                    record.id().encode()
                ))
            })?;
        }

        after_reads(loaded.graph.as_ref(), leaf.node().clone())?;

        let second = {
            let mut fence = leaf.admin().acquire_inventory_fence().map_err(|error| {
                campaign_store_error(format!(
                    "cannot reacquire the physical node {} inventory fence: {error}",
                    leaf.node().as_str()
                ))
            })?;
            let mut rechecked = 0_u64;
            let mut changed = false;
            fence
                .visit_inventory(&mut |_record| {
                    rechecked = rechecked
                        .checked_add(1)
                        .ok_or(crucible_cas::content_store::StoreError::Quota)?;
                    if rechecked > first.objects() {
                        changed = true;
                        return Err(crucible_cas::content_store::StoreError::Quota);
                    }
                    Ok(())
                })
                .map_err(|error| {
                    if changed {
                        campaign_store_error(format!(
                            "physical node {} changed while it was verified",
                            leaf.node().as_str()
                        ))
                    } else {
                        campaign_store_error(format!(
                            "cannot reproduce physical node {} inventory: {error}",
                            leaf.node().as_str()
                        ))
                    }
                })?
        };
        if second != first {
            return Err(campaign_store_error(format!(
                "physical node {} changed while it was verified",
                leaf.node().as_str()
            )));
        }
        physical.push(VerifiedCampaignStorePhysicalInventory {
            backend: first.backend().to_owned(),
            generation: first.generation().to_hex(),
            placements: first.objects(),
            logical_bytes: first.logical_bytes(),
        });
    }
    Ok(VerifiedCampaignStoreInventory {
        configuration: loaded.graph.configuration_id().as_bytes(),
        placements,
        logical_bytes,
        physical,
    })
}

fn load_campaign_repository_graph(
    deployment_path: &Path,
) -> Result<LoadedCampaignRepositoryStore, CliError> {
    let bytes = read_secure_file(
        deployment_path,
        MAX_CAMPAIGN_STORE_DEPLOYMENT_BYTES,
        "campaign store deployment",
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| campaign_store_error(format!("deployment is not UTF-8: {error}")))?;
    let mut deployment: CampaignStoreDeployment = toml::from_str(text)
        .map_err(|error| campaign_store_error(format!("invalid deployment: {error}")))?;
    if deployment.schema != CAMPAIGN_STORE_SCHEMA
        || !matches!(
            deployment.version,
            CAMPAIGN_STORE_VERSION_1 | CAMPAIGN_STORE_VERSION_2
        )
    {
        return Err(campaign_store_error("unsupported schema or version"));
    }
    let ref_backend = resolve_ref_backend(
        deployment.version,
        deployment.ref_directory.take(),
        deployment.s3_ref.take(),
        deployment.s3_endpoints.is_empty(),
    )?;

    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    if let ResolvedRefBackend::Directory(path) = &ref_backend {
        validate_secure_directory(path, user_id, group_id, "ref directory")?;
    }

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

    let mut required_s3_endpoints = nodes
        .values()
        .filter_map(|node| match node {
            StoreNodeSpec::S3 { endpoint, .. } => Some(endpoint.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if let ResolvedRefBackend::S3(refs) = &ref_backend {
        required_s3_endpoints.insert(refs.endpoint().clone());
    }
    validate_s3_namespace_separation(
        &nodes,
        match &ref_backend {
            ResolvedRefBackend::S3(refs) => Some(refs),
            ResolvedRefBackend::Directory(_) => None,
        },
    )?;
    let authored_s3_endpoints = index_s3_endpoints(deployment.s3_endpoints)?;
    if s3_endpoint_ids(&authored_s3_endpoints) != required_s3_endpoints {
        return Err(campaign_store_error(
            "S3 endpoint capabilities do not exactly match graph and ref requirements",
        ));
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

    let s3_capabilities = load_s3_capabilities(authored_s3_endpoints)?;

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
        &s3_capabilities.graph,
    )
    .map_err(|error| campaign_store_error(format!("graph admission failed: {error}")))?;
    let refs = match ref_backend {
        ResolvedRefBackend::Directory(path) => {
            LoadedRefBackend::Directory(Arc::new(DirectoryRefBackend::new(path)))
        }
        ResolvedRefBackend::S3(refs) => LoadedRefBackend::S3(refs.build(&s3_capabilities)?),
    };
    Ok(LoadedCampaignRepositoryStore {
        graph: Arc::new(graph),
        refs,
        maintenance,
    })
}

fn resolve_ref_backend(
    version: u32,
    ref_directory: Option<PathBuf>,
    s3_ref: Option<AuthoredS3RefBackend>,
    s3_endpoints_empty: bool,
) -> Result<ResolvedRefBackend, CliError> {
    match (version, ref_directory, s3_ref) {
        (CAMPAIGN_STORE_VERSION_1, Some(path), None) if s3_endpoints_empty => {
            Ok(ResolvedRefBackend::Directory(path))
        }
        (CAMPAIGN_STORE_VERSION_2, Some(path), None) => Ok(ResolvedRefBackend::Directory(path)),
        (CAMPAIGN_STORE_VERSION_2, None, Some(refs)) => Ok(ResolvedRefBackend::S3(refs.resolve()?)),
        (CAMPAIGN_STORE_VERSION_1, _, _) => Err(campaign_store_error(
            "version-one deployment requires only ref_directory and no S3 endpoints",
        )),
        (CAMPAIGN_STORE_VERSION_2, _, _) => Err(campaign_store_error(
            "version-two deployment requires exactly one of ref_directory or s3_ref",
        )),
        _ => Err(campaign_store_error("unsupported schema or version")),
    }
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
            Self::S3 {
                endpoint,
                bucket,
                prefix,
                maximum_logical_object_bytes,
                multipart_part_bytes,
            } => {
                validate_s3_storage_configuration(
                    &bucket,
                    &prefix,
                    maximum_logical_object_bytes,
                    multipart_part_bytes,
                )?;
                Ok(StoreNodeSpec::S3 {
                    endpoint: crucible_cas::content_store::StoreS3EndpointId::new(endpoint)
                        .map_err(|error| {
                            campaign_store_error(format!("invalid S3 endpoint ID: {error}"))
                        })?,
                    bucket,
                    prefix,
                    maximum_logical_object_bytes,
                    multipart_part_bytes,
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

        let loaded =
            load_campaign_repository_graph(&deployment).expect("load composed campaign store");
        let graph = loaded.graph.clone();
        let bytes = b"initialize encrypted campaign storage";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        graph
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("initialize encrypted campaign storage");
        drop(loaded);
        drop(graph);
        load_campaign_repository_store(&deployment).expect("restart composed campaign store");

        fs::write(&fixture.key, [0x52; 32]).expect("replace key generation");
        let wrong_key =
            load_campaign_repository_graph(&deployment).expect("construct wrong-key graph");
        let _error = wrong_key
            .graph
            .contains(id)
            .expect_err("changed key must not authenticate encrypted storage");
    }

    #[test]
    fn physical_verification_is_bounded_and_rejects_a_generation_race() {
        let fixture = StoreDeploymentFixture::new();
        let deployment = fixture.write_deployment("");
        let loaded =
            load_campaign_repository_graph(&deployment).expect("load bounded verification graph");
        let first_bytes = b"first physical placement";
        let first_id = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
        loaded
            .graph
            .put_if_absent(first_id, &BlobHandle::from_bytes(first_bytes.to_vec()))
            .expect("publish first physical placement");

        let Err(error) = verify_loaded_campaign_store_inventory(
            loaded,
            StoreVerifyLimits {
                placements: 0,
                logical_bytes: u64::MAX,
            },
            &mut |_graph, _node| Ok(()),
        ) else {
            panic!("placement-count bound must fail during the first inventory");
        };
        assert!(error.to_string().contains("fixed verification bound"));

        let loaded = load_campaign_repository_graph(&deployment).expect("reload byte-bound graph");
        let Err(error) = verify_loaded_campaign_store_inventory(
            loaded,
            StoreVerifyLimits {
                placements: 1,
                logical_bytes: first_bytes.len() as u64 - 1,
            },
            &mut |_graph, _node| Ok(()),
        ) else {
            panic!("logical-byte bound must fail during the first inventory");
        };
        assert!(error.to_string().contains("fixed verification bound"));

        let loaded =
            load_campaign_repository_graph(&deployment).expect("reload race verification graph");
        let second_bytes = b"second physical placement";
        let second_id = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
        let mut injected = false;
        let Err(error) = verify_loaded_campaign_store_inventory(
            loaded,
            StoreVerifyLimits::PRODUCTION,
            &mut |graph, _node| {
                if !injected {
                    graph
                        .put_if_absent(second_id, &BlobHandle::from_bytes(second_bytes.to_vec()))
                        .map_err(|error| {
                            campaign_store_error(format!(
                                "cannot inject verification race: {error}"
                            ))
                        })?;
                    injected = true;
                }
                Ok(())
            },
        ) else {
            panic!("generation change must fail the closing inventory fence");
        };
        assert!(injected);
        assert!(error.to_string().contains("changed while it was verified"));
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
    fn strict_s3_store_binds_remote_graph_refs_and_maintenance_without_network_io() {
        let fixture = StoreDeploymentFixture::new();
        let credentials = fixture.write_s3_credentials(None);
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-primary",
            "campaign/s3-primary",
            &credentials,
            "https://s3.example.invalid",
        );

        let loaded =
            load_campaign_repository_graph(&deployment).expect("load strict S3 deployment");
        assert!(loaded.graph.describe().iter().any(|node| {
            node.kind == crucible_cas::content_store::StoreNodeKind::S3 && node.capabilities.durable
        }));
        assert_eq!(loaded.maintenance.physical().len(), 1);
        assert_eq!(loaded.maintenance.s3_multipart_cleanup().len(), 1);
        assert!(matches!(&loaded.refs, LoadedRefBackend::S3(_)));
        loaded.into_store().expect("bind maintained S3 store");
    }

    #[test]
    fn strict_s3_store_rejects_expired_credentials_before_worker_start() {
        let fixture = StoreDeploymentFixture::new();
        let credentials = fixture.write_s3_credentials(Some(1));
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-expired",
            "campaign/s3-expired",
            &credentials,
            "https://s3.example.invalid",
        );

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("expired S3 credentials were accepted");
        };
        assert!(error.to_string().contains("credential is expired"));
    }

    #[test]
    fn strict_s3_store_never_reflects_malformed_secret_material() {
        let fixture = StoreDeploymentFixture::new();
        let credentials = fixture.root.join("malformed-s3-credentials.toml");
        let secret = "must-not-appear-in-diagnostics";
        fs::write(
            &credentials,
            format!(
                r#"schema = "crucible.campaign-s3-credentials"
version = 1
access_key_id = "CAMPAIGNACCESSKEY"
secret_access_key = "{secret}"
unknown_secret_field = true
"#,
            ),
        )
        .expect("write malformed S3 credentials");
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600))
            .expect("secure malformed S3 credentials");
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-redaction",
            "campaign/s3-redaction",
            &credentials,
            "https://s3.example.invalid",
        );

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("malformed S3 credentials were accepted");
        };
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("invalid S3 credential body"));
        assert!(!diagnostic.contains(secret));
    }

    #[test]
    fn strict_s3_store_rejects_endpoint_mismatch_before_credential_io() {
        let fixture = StoreDeploymentFixture::new();
        let missing = fixture.root.join("missing-credentials.toml");
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-required",
            "campaign/s3-unused",
            &missing,
            "https://s3.example.invalid",
        );

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("mismatched S3 endpoint capability was accepted");
        };
        assert!(
            error
                .to_string()
                .contains("do not exactly match graph and ref requirements")
        );
    }

    #[test]
    fn strict_s3_store_rejects_non_https_endpoint_before_credential_io() {
        let fixture = StoreDeploymentFixture::new();
        let missing = fixture.root.join("missing-credentials.toml");
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-insecure",
            "campaign/s3-insecure",
            &missing,
            "http://s3.example.invalid",
        );

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("plaintext S3 endpoint was accepted");
        };
        assert!(error.to_string().contains("bounded HTTPS origin"));
    }

    #[test]
    fn strict_s3_store_requires_explicit_strong_cas_attestation_before_credential_io() {
        let fixture = StoreDeploymentFixture::new();
        let missing = fixture.root.join("missing-credentials.toml");
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-unattested",
            "campaign/s3-unattested",
            &missing,
            "https://s3.example.invalid",
        );
        let body = fs::read_to_string(&deployment).expect("read S3 deployment");
        fs::write(
            &deployment,
            body.replace(
                "strong_cas_conformance = true",
                "strong_cas_conformance = false",
            ),
        )
        .expect("remove S3 strong-CAS attestation");

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("unattested S3 service was accepted");
        };
        assert!(
            error
                .to_string()
                .contains("strong-CAS conformance attestation")
        );
    }

    #[test]
    fn strict_s3_store_rejects_overlapping_graph_and_ref_namespaces_before_credential_io() {
        let fixture = StoreDeploymentFixture::new();
        let missing = fixture.root.join("missing-credentials.toml");
        let deployment = fixture.write_s3_deployment(
            "campaign/s3-overlap",
            "campaign/s3-overlap",
            &missing,
            "https://s3.example.invalid",
        );
        let body = fs::read_to_string(&deployment).expect("read S3 deployment");
        fs::write(
            &deployment,
            body.replace(
                "prefix = \"campaign/refs\"",
                "prefix = \"campaign/objects\"",
            ),
        )
        .expect("overlap S3 namespaces");

        let Err(error) = load_campaign_repository_store(&deployment) else {
            panic!("overlapping S3 physical namespaces were accepted");
        };
        assert!(error.to_string().contains("physical namespaces overlap"));
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

        fn write_s3_credentials(&self, expiry: Option<u64>) -> PathBuf {
            let path = self.root.join("s3-credentials.toml");
            let expiry = expiry
                .map(|seconds| format!("expires_at_unix_seconds = {seconds}\n"))
                .unwrap_or_default();
            fs::write(
                &path,
                format!(
                    r#"schema = "crucible.campaign-s3-credentials"
version = 1
access_key_id = "CAMPAIGNACCESSKEY"
secret_access_key = "campaign-secret-access-key"
session_token = "campaign-session-token"
{expiry}"#,
                ),
            )
            .expect("write S3 credentials");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure S3 credentials");
            path
        }

        fn write_s3_deployment(
            &self,
            required_endpoint: &str,
            configured_endpoint: &str,
            credential_path: &Path,
            endpoint_url: &str,
        ) -> PathBuf {
            let deployment = self.root.join("store-s3.toml");
            let kinds = all_object_kinds_toml();
            fs::write(
                &deployment,
                format!(
                    r#"schema = "crucible.campaign-repository-store"
version = 2
root = "profile"
admitted_kinds = {kinds}

[s3_ref]
endpoint = {required_endpoint:?}
bucket = "campaign-store"
prefix = "campaign/refs"

[[s3_endpoints]]
id = {configured_endpoint:?}
region = "us-west-2"
endpoint_url = {endpoint_url:?}
force_path_style = true
credential_path = {credential_path:?}
maximum_queued_commands = 8
maximum_in_flight_operations = 2
maximum_retained_command_bytes = 134217728
operation_timeout_ms = 1000
strong_cas_conformance = true

[[nodes]]
id = "s3"
[nodes.spec]
kind = "s3"
endpoint = {required_endpoint:?}
bucket = "campaign-store"
prefix = "campaign/objects"
maximum_logical_object_bytes = 67108864
multipart_part_bytes = 5242880

[[nodes]]
id = "profile"
[nodes.spec]
kind = "profile-validated"
child = "s3"
policy = "crucible.campaign.object-profile.v1"
"#,
                ),
            )
            .expect("write S3 deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600))
                .expect("secure S3 deployment");
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
