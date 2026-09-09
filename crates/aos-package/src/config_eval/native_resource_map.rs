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
//!   "schema": "aos.ability.native-resource-map/v1",
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

use anyhow::{Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AggregateId, ArtifactReference, BindingId, InterfaceKey, LocalKey,
    ProviderImplementationReference, ResourceId, RevisionId,
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
    pub const SCHEMA: &'static str = "aos.ability.native-resource-map/v1";

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
        for entry in &self.entries {
            validate_mapping(entry, &mut remaining_items)?;

            match &entry.qualification {
                NativeResourceQualification::ManagedConfiguration { destination, .. } => {
                    claimed_paths.push((destination, &entry.resource));
                }
                NativeResourceQualification::SystemdService { unit, .. } => {
                    claim_physical(&mut claimed_units, unit, &entry.resource, "systemd unit")?;
                }
                NativeResourceQualification::NginxValidation {
                    validation_prefix, ..
                } => {
                    claimed_paths.push((validation_prefix, &entry.resource));
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
        } => {
            consume_items(remaining_items, 3)?;
            validate_string(unit, "systemd service unit")?;
            crate::types::validate_unit_name(unit)?;
            ensure!(
                unit.ends_with(".service"),
                "native systemd unit must be a .service unit"
            );
            validate_locator(resource_reference, remaining_items)?;
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
    }
    Ok(())
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

fn claim_physical<'a>(
    claims: &mut BTreeMap<&'a str, &'a ResourceId>,
    physical: &'a str,
    resource: &'a ResourceId,
    label: &str,
) -> Result<()> {
    if let Some(owner) = claims.insert(physical, resource) {
        bail!(
            "native {label} {physical:?} is claimed by distinct resources {owner:?} and {resource:?}"
        );
    }
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
        entry.qualification = NativeResourceQualification::SystemdService {
            unit: "nginx.target".to_string(),
            resource_reference: locator(),
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
