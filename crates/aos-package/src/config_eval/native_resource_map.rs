//! Bounded physical-resource qualifications for native ability adapters.
//!
//! The native resource map binds each logical resource in one desired state to
//! its exact provider implementation and to the physical host object that the
//! trusted adapter may touch. Validation here is deliberately intrinsic: it
//! checks the closed wire shape, bounds, canonical ordering, and collision
//! domains. The activation loader separately proves that every identity and
//! output locator came from the authenticated planning and package inputs.
//!
//! ```text
//! {
//!   "schema": "aos.ability.native-resource-map/v2",
//!   "desired_state": "sha256:<64 lowercase hex characters>",
//!   "entries": [
//!     {
//!       "resource": { "provider": "<structured instance>", "key": "config" },
//!       "revision": "sha256:<64 lowercase hex characters>",
//!       "owner_package": "sha256:<64 lowercase hex characters>",
//!       "binding": "managed-terminal",
//!       "implementation": "<provider implementation reference>",
//!       "qualification": {
//!         "kind": "managed-configuration",
//!         "destination": "/etc/example.conf",
//!         "candidate": "<native output locator>",
//!         "resource_reference": "<native output locator>"
//!       }
//!     }
//!   ]
//! }
//! ```

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::SocketAddr;

use anyhow::{Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AggregateId, ArtifactReference, BindingId, InstanceId, InterfaceKey,
    LocalKey, ProviderImplementationReference, ResourceId, RevisionId,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Maps one canonical desired state to its qualified native resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceMap {
    /// Carries [`Self::SCHEMA`].
    pub schema: String,
    /// Identifies the exact specialized desired-state document.
    pub desired_state: Sha256Digest,
    /// Lists qualified resources in strict logical-resource order.
    pub entries: Vec<NativeResourceMapping>,
}

impl NativeResourceMap {
    /// Current native resource-map schema.
    pub const SCHEMA: &'static str = "aos.ability.native-resource-map/v2";

    /// Constructs and validates a canonically ordered native resource map.
    ///
    /// # Errors
    ///
    /// Returns an error when two entries name the same logical resource, an
    /// entry exceeds the version-1 bounds, a physical qualification is unsafe,
    /// or distinct resources claim the same physical host object.
    pub fn new(
        desired_state: Sha256Digest,
        mut entries: Vec<NativeResourceMapping>,
    ) -> Result<Self> {
        entries.sort_by(|left, right| left.resource.cmp(&right.resource));

        let resource_map = Self {
            schema: Self::SCHEMA.to_string(),
            desired_state,
            entries,
        };
        resource_map.validate()?;
        Ok(resource_map)
    }

    /// Validates intrinsic native resource-map invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, noncanonical or duplicate
    /// resources, exceeded version-1 bounds, unsafe host paths or service unit
    /// names, and physical resource collisions.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported native resource-map schema {:?}",
            self.schema
        );
        validate_string(&self.schema, "native resource-map schema")?;
        ensure!(
            self.entries.len() <= ABILITY_LIMITS_V1.max_graph_nodes as usize,
            "native resource map exceeds the version-1 graph-node limit"
        );
        ensure!(
            self.entries
                .windows(2)
                .all(|pair| pair[0].resource < pair[1].resource),
            "native resource map entries are not in strict resource order"
        );

        let mut remaining_items = ABILITY_LIMITS_V1.max_collection_items;
        consume_items(&mut remaining_items, 3)?;
        consume_items(&mut remaining_items, self.entries.len())?;

        let mut claimed_paths: Vec<(&str, &ResourceId)> = Vec::new();
        let mut claimed_units: BTreeMap<&str, &ResourceId> = BTreeMap::new();
        let mut claimed_consumer_endpoints: BTreeMap<SocketAddr, &ResourceId> = BTreeMap::new();
        let mut claimed_kubernetes_objects: BTreeMap<
            (String, String, Option<String>, String),
            &ResourceId,
        > = BTreeMap::new();
        for entry in &self.entries {
            validate_mapping(entry, &mut remaining_items)?;

            match &entry.qualification {
                NativeResourceQualification::ManagedConfiguration { destination, .. } => {
                    claimed_paths.push((destination, &entry.resource));
                }
                NativeResourceQualification::SystemdService {
                    unit,
                    consumer_observation,
                    ..
                } => {
                    claim_physical(&mut claimed_units, unit, &entry.resource, "systemd unit")?;
                    if let Some(consumer_observation) = consumer_observation {
                        let endpoint = parse_consumer_endpoint(consumer_observation)?;
                        claim_physical(
                            &mut claimed_consumer_endpoints,
                            endpoint,
                            &entry.resource,
                            "consumer observation endpoint",
                        )?;
                    }
                }
                NativeResourceQualification::NginxValidation {
                    validation_prefix, ..
                } => {
                    claimed_paths.push((validation_prefix, &entry.resource));
                }
                NativeResourceQualification::KubernetesObject {
                    api_version,
                    object_kind,
                    namespace,
                    name,
                    ..
                } => {
                    claim_physical(
                        &mut claimed_kubernetes_objects,
                        (
                            api_version.clone(),
                            object_kind.clone(),
                            namespace.clone(),
                            name.clone(),
                        ),
                        &entry.resource,
                        "Kubernetes object",
                    )?;
                }
            }
        }
        validate_path_claims(&mut claimed_paths)?;

        let mut writer = BoundedWriter::new(ABILITY_LIMITS_V1.max_document_bytes);
        if let Err(source) = serde_json::to_writer(&mut writer, self) {
            if writer.exceeded {
                bail!("native resource map exceeds the version-1 encoded-byte limit");
            }
            return Err(source.into());
        }
        Ok(())
    }
}

/// Qualifies one logical resource and exact provider implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceMapping {
    /// Identifies the stable provider-owned logical resource.
    pub resource: ResourceId,
    /// Identifies the exact semantic content revision being activated.
    pub revision: RevisionId,
    /// Identifies the authenticated package that owns the implementation.
    pub owner_package: Sha256Digest,
    /// Identifies the binding that selected the implementation.
    pub binding: BindingId,
    /// Pins the exact retained implementation artifact and handler.
    pub implementation: ProviderImplementationReference,
    /// Names the physical host object and its typed planning outputs.
    pub qualification: NativeResourceQualification,
}

/// Locates one typed field in the output of a provider aggregation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOutputLocator {
    /// Identifies the provider aggregation that produced the value.
    pub aggregate: AggregateId,
    /// Identifies the exact output interface contract.
    pub interface: InterfaceKey,
    /// Names the interface output port.
    pub port: LocalKey,
    /// Selects a nested field beneath the output port in traversal order.
    pub field_path: Vec<LocalKey>,
}

/// Qualifies the physical object used by one trusted native adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeResourceQualification {
    /// Publishes a candidate file at one managed host destination.
    ManagedConfiguration {
        /// Names the canonical destination beneath `/etc` or `/var/lib`.
        destination: String,
        /// Locates the candidate byte content in the provider output.
        candidate: NativeOutputLocator,
        /// Locates the logical resource reference authorizing the write.
        resource_reference: NativeOutputLocator,
    },
    /// Controls one exact host systemd service unit.
    SystemdService {
        /// Names the safe `.service` unit controlled by the adapter.
        unit: String,
        /// Locates the logical resource reference authorizing service control.
        resource_reference: NativeOutputLocator,
        /// Optionally defines a bounded read-only proof from an HTTP consumer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consumer_observation: Option<NativeHttpConsumerObservation>,
    },
    /// Validates an nginx candidate beneath one private host prefix.
    NginxValidation {
        /// Pins the exact authenticated nginx executable artifact.
        executable: ArtifactReference,
        /// Names the canonical private prefix beneath `/etc` or `/var/lib`.
        validation_prefix: String,
        /// Locates the candidate nginx configuration in the provider output.
        candidate: NativeOutputLocator,
    },
    /// Applies, observes, or deletes one exact Kubernetes API object.
    KubernetesObject {
        /// Pins the exact authenticated kubectl executable artifact.
        kubectl: ArtifactReference,
        /// Names the protected root-owned kubeconfig used for this cluster.
        kubeconfig: String,
        /// Names the exact Kubernetes API version, such as `apps/v1`.
        api_version: String,
        /// Names the exact Kubernetes kind, such as `Deployment`.
        object_kind: String,
        /// Names the namespace, or is absent for a cluster-scoped object.
        namespace: Option<String>,
        /// Names the exact object within its scope.
        name: String,
        /// Locates the canonical JSON object supplied by planning.
        object_json: NativeOutputLocator,
        /// Locates the logical resource reference authorizing the effect.
        resource_reference: NativeOutputLocator,
    },
}

/// Defines the versioned loopback HTTP proof emitted by an active consumer.
///
/// The authenticated resource map supplies the only permitted socket, HTTP
/// authority, and path. The response must identify the exact checked consumer
/// instance and the same revision as the systemd resource mapping.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHttpConsumerObservation {
    /// Carries [`Self::SCHEMA`].
    pub schema: String,
    /// Names one numeric loopback socket such as `127.0.0.1:18081`.
    pub endpoint: String,
    /// Supplies the exact HTTP `Host` authority sent to the consumer.
    pub authority: String,
    /// Supplies the exact origin-form request target sent to the consumer.
    pub path: String,
    /// Identifies the checked instance that must answer the request.
    pub expected_instance: InstanceId,
    /// Identifies the service-controller revision that the process must report.
    pub expected_controller_revision: RevisionId,
    /// Names the consumer-owned content resource whose bytes are active.
    pub content_resource: ResourceId,
    /// Identifies the content-specific revision that the process must report.
    pub expected_content_revision: RevisionId,
}

impl NativeHttpConsumerObservation {
    /// Current native HTTP consumer-observation schema.
    pub const SCHEMA: &'static str = "aos.ability.native-http-consumer-observation/v1";
}

/// Computes the stable ownership annotation for one logical Kubernetes resource.
///
/// # Errors
///
/// Returns an error when the structured resource identity cannot be encoded in
/// the canonical AOS JSON dialect.
pub(crate) fn kubernetes_resource_owner(resource: &ResourceId) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical("aos.ability.kubernetes-object-owner/v1", resource)
}

fn validate_mapping(mapping: &NativeResourceMapping, remaining_items: &mut u64) -> Result<()> {
    consume_items(remaining_items, 6)?;
    validate_string(
        &mapping.implementation.artifact.store_path,
        "native implementation artifact store path",
    )?;

    match &mapping.qualification {
        NativeResourceQualification::ManagedConfiguration {
            destination,
            candidate,
            resource_reference,
        } => {
            consume_items(remaining_items, 4)?;
            validate_safe_host_path(destination, "managed-configuration destination")?;
            validate_locator(candidate, remaining_items)?;
            validate_locator(resource_reference, remaining_items)?;
        }
        NativeResourceQualification::SystemdService {
            unit,
            resource_reference,
            consumer_observation,
        } => {
            consume_items(remaining_items, 4)?;
            validate_string(unit, "systemd service unit")?;
            crate::types::validate_unit_name(unit)?;
            ensure!(
                unit.ends_with(".service"),
                "native systemd unit must be a .service unit"
            );
            validate_locator(resource_reference, remaining_items)?;
            if let Some(consumer_observation) = consumer_observation {
                validate_http_consumer_observation(consumer_observation, remaining_items)?;
                ensure!(
                    consumer_observation.expected_controller_revision == mapping.revision,
                    "native consumer observation revision differs from its systemd resource"
                );
            }
        }
        NativeResourceQualification::NginxValidation {
            executable,
            validation_prefix,
            candidate,
        } => {
            consume_items(remaining_items, 4)?;
            validate_string(
                &executable.store_path,
                "nginx validation executable store path",
            )?;
            validate_safe_host_path(validation_prefix, "nginx validation prefix")?;
            validate_locator(candidate, remaining_items)?;
        }
        NativeResourceQualification::KubernetesObject {
            kubectl,
            kubeconfig,
            api_version,
            object_kind,
            namespace,
            name,
            object_json,
            resource_reference,
        } => {
            consume_items(remaining_items, 9)?;
            validate_string(&kubectl.store_path, "kubectl executable store path")?;
            validate_safe_host_path(kubeconfig, "Kubernetes kubeconfig")?;
            validate_kubernetes_api_version(api_version)?;
            validate_kubernetes_kind(object_kind)?;
            if let Some(namespace) = namespace {
                validate_kubernetes_name(namespace, "Kubernetes namespace")?;
            }
            validate_kubernetes_name(name, "Kubernetes object name")?;
            validate_locator(object_json, remaining_items)?;
            validate_locator(resource_reference, remaining_items)?;
        }
    }
    Ok(())
}

fn validate_http_consumer_observation(
    observation: &NativeHttpConsumerObservation,
    remaining_items: &mut u64,
) -> Result<()> {
    consume_items(remaining_items, 8)?;
    validate_string(&observation.schema, "native consumer observation schema")?;
    validate_string(
        &observation.endpoint,
        "native consumer observation endpoint",
    )?;
    validate_string(
        &observation.authority,
        "native consumer observation authority",
    )?;
    validate_string(&observation.path, "native consumer observation path")?;
    ensure!(
        observation.schema == NativeHttpConsumerObservation::SCHEMA,
        "unsupported native consumer observation schema {:?}",
        observation.schema
    );
    let endpoint = parse_consumer_endpoint(observation)?;
    ensure!(
        endpoint.ip().is_loopback() && endpoint.port() != 0,
        "native consumer observation endpoint must be a nonzero loopback socket"
    );
    ensure!(
        !observation.authority.is_empty()
            && observation
                .authority
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\' | b'#')),
        "native consumer observation authority is not a safe HTTP authority"
    );
    ensure!(
        observation.path.starts_with('/')
            && !observation.path.starts_with("//")
            && observation
                .path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'#'),
        "native consumer observation path is not a safe origin-form target"
    );
    ensure!(
        observation.content_resource.provider == observation.expected_instance,
        "native consumer content resource belongs to another instance"
    );
    Ok(())
}

fn parse_consumer_endpoint(observation: &NativeHttpConsumerObservation) -> Result<SocketAddr> {
    observation
        .endpoint
        .parse()
        .map_err(|_| anyhow::anyhow!("native consumer observation endpoint is not numeric"))
}

fn validate_locator(locator: &NativeOutputLocator, remaining_items: &mut u64) -> Result<()> {
    consume_items(remaining_items, 4)?;
    consume_items(remaining_items, locator.field_path.len())?;
    ensure!(
        locator.field_path.len() <= ABILITY_LIMITS_V1.max_structural_depth as usize,
        "native output locator exceeds the version-1 structural-depth limit"
    );
    Ok(())
}

fn validate_kubernetes_api_version(value: &str) -> Result<()> {
    validate_string(value, "Kubernetes API version")?;
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'/') })
            && !value.starts_with('/')
            && !value.ends_with('/')
            && value.matches('/').count() <= 1,
        "Kubernetes API version is not canonical"
    );
    Ok(())
}

fn validate_kubernetes_kind(value: &str) -> Result<()> {
    validate_string(value, "Kubernetes kind")?;
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric(),
        "Kubernetes kind is not canonical"
    );
    Ok(())
}

fn validate_kubernetes_name(value: &str, label: &str) -> Result<()> {
    validate_string(value, label)?;
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-'))
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric(),
        "{label} is not a canonical DNS-style Kubernetes name"
    );
    Ok(())
}

fn validate_string(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() as u64 <= ABILITY_LIMITS_V1.max_string_bytes,
        "{label} exceeds the version-1 string limit"
    );
    ensure!(
        !value.as_bytes().contains(&0),
        "{label} contains a NUL byte"
    );
    Ok(())
}

fn validate_safe_host_path(path: &str, label: &str) -> Result<()> {
    validate_string(path, label)?;
    let canonical = path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| matches!(component, "." | ".."));
    ensure!(canonical, "{label} is not a canonical absolute path");
    ensure!(
        path.starts_with("/etc/") || path.starts_with("/var/lib/"),
        "{label} must be beneath /etc or /var/lib"
    );

    const RESERVED_ROOTS: [&str; 4] = [
        "/etc/aos",
        "/var/lib/profiles",
        "/var/lib/aos/ability-runtime",
        "/var/lib/aos/ability-authority",
    ];
    ensure!(
        !RESERVED_ROOTS.iter().any(|root| paths_overlap(path, root)),
        "{label} overlaps a reserved AOS state tree"
    );
    Ok(())
}

fn validate_path_claims(claims: &mut [(&str, &ResourceId)]) -> Result<()> {
    // Component ordering places an ancestor immediately before its first
    // descendant even when punctuation sorts between their raw byte strings.
    claims.sort_by(|(left, _), (right, _)| left.split('/').cmp(right.split('/')));
    if let Some(pair) = claims
        .windows(2)
        .find(|pair| paths_overlap(pair[0].0, pair[1].0))
    {
        let (claimed, owner) = pair[0];
        let (path, resource) = pair[1];
        bail!(
            "native host paths {claimed:?} and {path:?} overlap across distinct resources {owner:?} and {resource:?}"
        );
    }
    Ok(())
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn claim_physical<'a, Physical>(
    claims: &mut BTreeMap<Physical, &'a ResourceId>,
    physical: Physical,
    resource: &'a ResourceId,
    label: &str,
) -> Result<()>
where
    Physical: Ord + std::fmt::Debug,
{
    if let Some(owner) = claims.get(&physical) {
        bail!(
            "native {label} {physical:?} is claimed by distinct resources {owner:?} and {resource:?}"
        );
    }
    claims.insert(physical, resource);
    Ok(())
}

fn consume_items(remaining: &mut u64, count: usize) -> Result<()> {
    *remaining = remaining.checked_sub(count as u64).ok_or_else(|| {
        anyhow::anyhow!("native resource map exceeds the version-1 collection-item limit")
    })?;
    Ok(())
}

struct BoundedWriter {
    remaining: u64,
    exceeded: bool,
}

impl BoundedWriter {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "native resource-map encoding exceeds its bound",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId, InterfaceName};

    use super::*;

    #[test]
    fn constructor_sorts_entries_and_round_trips_canonically() {
        let map = NativeResourceMap::new(
            digest("desired"),
            vec![
                mapping("z", qualification("/etc/nginx/z.conf")),
                mapping("a", qualification("/etc/nginx/a.conf")),
            ],
        )
        .expect("valid native map is constructed");

        assert_eq!(map.entries[0].resource.key.as_str(), "a");
        let encoded = aos_contract::canonical::to_vec(&map).expect("map encodes canonically");
        let decoded: NativeResourceMap =
            serde_json::from_slice(&encoded).expect("canonical map decodes");
        decoded.validate().expect("decoded map remains valid");
    }

    #[test]
    fn validation_rejects_duplicate_logical_and_physical_resources() {
        let duplicate_logical = NativeResourceMap::new(
            digest("desired"),
            vec![
                mapping("same", qualification("/etc/a.conf")),
                mapping("same", qualification("/etc/b.conf")),
            ],
        )
        .expect_err("duplicate logical resource must fail");
        assert!(
            duplicate_logical
                .to_string()
                .contains("strict resource order")
        );

        let duplicate_physical = NativeResourceMap::new(
            digest("desired"),
            vec![
                mapping("a", qualification("/etc/shared.conf")),
                mapping("b", qualification("/etc/shared.conf")),
            ],
        )
        .expect_err("duplicate physical resource must fail");
        assert!(
            duplicate_physical
                .to_string()
                .contains("overlap across distinct resources")
        );
    }

    #[test]
    fn validation_rejects_noncanonical_reserved_paths_and_non_service_units() {
        for destination in [
            "etc/nginx.conf",
            "/etc/../etc/nginx.conf",
            "/etc/aos/native.conf",
            "/var/lib/profiles/native",
            "/var/lib/aos/ability-runtime/native",
            "/var/lib/aos/ability-authority/native",
            "/var/lib/aos",
        ] {
            assert!(
                NativeResourceMap::new(
                    digest("desired"),
                    vec![mapping("resource", qualification(destination))]
                )
                .is_err(),
                "accepted unsafe destination {destination:?}"
            );
        }

        let mut entry = mapping("resource", qualification("/etc/nginx.conf"));
        let observation = http_observation(entry.revision);
        entry.qualification = NativeResourceQualification::SystemdService {
            unit: "nginx.target".to_string(),
            resource_reference: locator(),
            consumer_observation: Some(observation),
        };
        assert!(NativeResourceMap::new(digest("desired"), vec![entry]).is_err());
    }

    #[test]
    fn validation_rejects_ancestor_path_collisions() {
        let mut prefix = mapping("validation", qualification("/etc/unused"));
        prefix.qualification = NativeResourceQualification::NginxValidation {
            executable: artifact("nginx"),
            validation_prefix: "/var/lib/example/nginx".to_string(),
            candidate: locator(),
        };

        let overlap = NativeResourceMap::new(
            digest("desired"),
            vec![
                mapping(
                    "configuration",
                    qualification("/var/lib/example/nginx/config.conf"),
                ),
                mapping("punctuation", qualification("/var/lib/example/nginx-old")),
                prefix,
            ],
        )
        .expect_err("a managed path beneath a validation prefix must fail");
        assert!(
            overlap
                .to_string()
                .contains("overlap across distinct resources")
        );

        let mut outer = mapping("outer", qualification("/etc/unused-a"));
        outer.qualification = NativeResourceQualification::NginxValidation {
            executable: artifact("nginx"),
            validation_prefix: "/var/lib/example/outer".to_string(),
            candidate: locator(),
        };
        let mut inner = mapping("inner", qualification("/etc/unused-b"));
        inner.qualification = NativeResourceQualification::NginxValidation {
            executable: artifact("nginx"),
            validation_prefix: "/var/lib/example/outer/inner".to_string(),
            candidate: locator(),
        };
        assert!(
            NativeResourceMap::new(digest("desired"), vec![outer, inner]).is_err(),
            "nested validation prefixes must fail"
        );
    }

    #[test]
    fn systemd_consumer_observation_is_loopback_and_revision_bound() {
        let mut entry = mapping("service", qualification("/etc/unused"));
        let valid_observation = http_observation(entry.revision);
        entry.qualification = NativeResourceQualification::SystemdService {
            unit: "fixture.service".to_string(),
            resource_reference: locator(),
            consumer_observation: Some(valid_observation),
        };
        NativeResourceMap::new(digest("desired"), vec![entry.clone()])
            .expect("valid consumer observation");

        let NativeResourceQualification::SystemdService {
            consumer_observation,
            ..
        } = &mut entry.qualification
        else {
            panic!("fixture remains a systemd service");
        };
        consumer_observation
            .as_mut()
            .expect("fixture has consumer observation")
            .endpoint = "192.0.2.10:18081".to_string();
        assert!(NativeResourceMap::new(digest("desired"), vec![entry]).is_err());

        let mut entry = mapping("service", qualification("/etc/unused"));
        let mut observation = http_observation(entry.revision);
        observation.expected_controller_revision = RevisionId(digest("another controller"));
        entry.qualification = NativeResourceQualification::SystemdService {
            unit: "fixture.service".to_string(),
            resource_reference: locator(),
            consumer_observation: Some(observation),
        };
        assert!(NativeResourceMap::new(digest("desired"), vec![entry]).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_consumer_observation_sockets() {
        let mut first = mapping("service-a", qualification("/etc/unused-a"));
        first.qualification = NativeResourceQualification::SystemdService {
            unit: "fixture-a.service".to_string(),
            resource_reference: locator(),
            consumer_observation: Some(http_observation(first.revision)),
        };
        let mut second = mapping("service-b", qualification("/etc/unused-b"));
        second.qualification = NativeResourceQualification::SystemdService {
            unit: "fixture-b.service".to_string(),
            resource_reference: locator(),
            consumer_observation: Some(http_observation(second.revision)),
        };

        let error = NativeResourceMap::new(digest("desired"), vec![first, second])
            .expect_err("one loopback socket cannot prove two distinct consumers");
        assert!(error.to_string().contains("consumer observation endpoint"));
    }

    #[test]
    fn kubernetes_qualifications_validate_names_and_object_collisions() {
        let first = mapping("object-a", kubernetes_qualification("example"));
        let second = mapping("object-b", kubernetes_qualification("example"));
        let error = NativeResourceMap::new(digest("desired"), vec![first, second])
            .expect_err("one Kubernetes API object cannot back two logical resources");
        assert!(error.to_string().contains("Kubernetes object"));

        let invalid_name = mapping("invalid", kubernetes_qualification("Example_Invalid"));
        assert!(NativeResourceMap::new(digest("desired"), vec![invalid_name]).is_err());

        let mut unsafe_kubeconfig = mapping("unsafe", kubernetes_qualification("example"));
        let NativeResourceQualification::KubernetesObject { kubeconfig, .. } =
            &mut unsafe_kubeconfig.qualification
        else {
            panic!("fixture remains a Kubernetes object");
        };
        *kubeconfig = "/tmp/kubeconfig".to_string();
        assert!(NativeResourceMap::new(digest("desired"), vec![unsafe_kubeconfig]).is_err());
    }

    fn mapping(key: &str, qualification: NativeResourceQualification) -> NativeResourceMapping {
        NativeResourceMapping {
            resource: ResourceId {
                provider: instance("provider"),
                key: local(key),
            },
            revision: RevisionId(digest(&format!("revision-{key}"))),
            owner_package: digest("owner package"),
            binding: BindingId(local(&format!("binding-{key}"))),
            implementation: ProviderImplementationReference {
                descriptor: digest("implementation"),
                artifact: artifact("runtime"),
                handler: Some(local("handler")),
            },
            qualification,
        }
    }

    fn qualification(destination: &str) -> NativeResourceQualification {
        NativeResourceQualification::ManagedConfiguration {
            destination: destination.to_string(),
            candidate: locator(),
            resource_reference: locator(),
        }
    }

    fn kubernetes_qualification(name: &str) -> NativeResourceQualification {
        NativeResourceQualification::KubernetesObject {
            kubectl: artifact("kubectl"),
            kubeconfig: "/etc/rancher/k3s/k3s.yaml".to_string(),
            api_version: "apps/v1".to_string(),
            object_kind: "Deployment".to_string(),
            namespace: Some("default".to_string()),
            name: name.to_string(),
            object_json: locator(),
            resource_reference: locator(),
        }
    }

    fn http_observation(expected_revision: RevisionId) -> NativeHttpConsumerObservation {
        NativeHttpConsumerObservation {
            schema: NativeHttpConsumerObservation::SCHEMA.to_string(),
            endpoint: "127.0.0.1:18081".to_string(),
            authority: "fixture.invalid".to_string(),
            path: "/__aos/consumer".to_string(),
            expected_instance: instance("consumer"),
            expected_controller_revision: expected_revision,
            content_resource: ResourceId {
                provider: instance("consumer"),
                key: local("content"),
            },
            expected_content_revision: RevisionId(digest("content revision")),
        }
    }

    fn locator() -> NativeOutputLocator {
        NativeOutputLocator {
            aggregate: AggregateId {
                provider: instance("provider"),
                group: local("aggregate"),
            },
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test").expect("valid interface name"),
                abi: NonZeroU32::new(1).expect("nonzero ABI"),
                descriptor: digest("interface"),
            },
            port: local("output"),
            field_path: vec![local("nested")],
        }
    }

    fn artifact(label: &str) -> ArtifactReference {
        ArtifactReference {
            content: digest(&format!("{label} content")),
            store_path: format!("/nix/store/00000000000000000000000000000000-{label}"),
            nar_hash: digest(&format!("{label} nar")),
            closure: digest(&format!("{label} closure")),
        }
    }

    fn instance(key: &str) -> InstanceId {
        InstanceId {
            environment: EnvironmentId {
                authority: local("test"),
                key: local("host"),
                stage: ExecutionStage::Host,
            },
            key: local(key),
        }
    }

    fn local(value: &str) -> LocalKey {
        LocalKey::new(value).expect("valid local key")
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(value)
    }
}
