//! Public ability interfaces and provider-owned implementation declarations.
//!
//! Public descriptors contain caller-visible semantics. Provider lower
//! requirements, constructors, handlers, and implementation authority remain
//! in separate implementation records so they do not alter the public API by
//! accident.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::bail;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::{InterfaceKey, InterfaceName, LocalKey};
use crate::plan::OperationFamily;
use crate::schema::ValueSchema;
use crate::value::{AbilityValue, ArtifactReference, ResourceLifetime};

/// Identifies one exact immutable guarantee semantic.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeKey {
    /// Names the guarantee within its namespace.
    pub name: InterfaceName,
    /// Identifies the guarantee contract version.
    pub version: std::num::NonZeroU32,
    /// Identifies the exact authenticated semantic descriptor.
    pub descriptor: Sha256Digest,
}

/// Identifies when a value becomes available to a consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValuePhase {
    /// Exists during pure configuration evaluation.
    Evaluation,
    /// Exists after immutable artifact construction.
    Artifact,
    /// Exists after provider selection and pure plan construction.
    Planning,
    /// Exists after runtime admission and handle acquisition.
    Admission,
    /// Exists after an admitted effect settles successfully.
    Runtime,
    /// Exists only after an explicit observation establishes it.
    Observation,
}

/// Defines who may inspect a method result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueVisibility {
    /// May appear in public package and interface views.
    Public,
    /// May appear only in authorized deployment views.
    Protected,
    /// Remains restricted to its producing provider and runtime controller.
    Private,
}

/// Describes one typed output port of a public interface or method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDescriptor {
    /// Defines the exact output value shape.
    pub schema: ValueSchema,
    /// States when the output becomes available.
    pub phase: ValuePhase,
    /// Defines who may inspect the output.
    pub visibility: ValueVisibility,
    /// Bounds the output by the lifetime of its underlying resource.
    pub lifetime: ResourceLifetime,
}

/// Defines how an indeterminate method outcome can be resolved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndeterminateSemantics {
    /// A named provider observation can establish the actual outcome.
    Reconcile,
    /// Automatic recovery is unavailable and operator intervention is needed.
    InterventionRequired,
}

/// Defines caller-visible completion and failure semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeSemantics {
    /// Defines evidence returned after successful completion.
    pub completion_evidence: ValueSchema,
    /// Defines evidence for rejection, uncertainty, and recovery observations.
    pub observation_evidence: ValueSchema,
    /// States whether the provider can prove some rejections precede effects.
    pub supports_rejected_before_effect: bool,
    /// Defines the public handling promised after an ambiguous effect.
    pub indeterminate: IndeterminateSemantics,
}

/// Describes lifecycle properties shared by an interface's resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSemantics {
    /// States whether resources retain logical identity across revisions.
    pub stable_resource_identity: bool,
    /// States whether disabling an instance releases ephemeral resources.
    pub releases_ephemeral_on_disable: bool,
    /// States whether persistent state is retained by default.
    pub retains_persistent_by_default: bool,
    /// Names a separately authorized deletion operation, when supported.
    pub persistent_delete_method: Option<LocalKey>,
}

/// Describes one caller-visible interface method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MethodDescriptor {
    /// Retains the method's high-level semantic operation family.
    pub operation_family: OperationFamily,
    /// Defines the closed parameter record.
    pub parameters: ValueSchema,
    /// Names the resource interface targeted by the method.
    pub target_resource: InterfaceName,
    /// Defines output ports in canonical name order.
    pub outputs: BTreeMap<LocalKey, OutputDescriptor>,
    /// Names resource operations the method may request in canonical order.
    pub permitted_operations: Vec<LocalKey>,
    /// Names exact guarantees callers may require in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Defines caller-visible completion and ambiguous-outcome behavior.
    pub outcome: OutcomeSemantics,
}

/// Defines one exact public ability interface without provider internals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDescriptor {
    /// Names the public interface.
    pub name: InterfaceName,
    /// Identifies the caller-visible ABI family.
    pub abi: std::num::NonZeroU32,
    /// Defines one contribution or request value.
    pub request: ValueSchema,
    /// Defines aggregate caller-visible outputs.
    pub outputs: BTreeMap<LocalKey, OutputDescriptor>,
    /// Defines callable methods in canonical name order.
    pub methods: BTreeMap<LocalKey, MethodDescriptor>,
    /// Defines interface-wide resource lifecycle behavior.
    pub lifecycle: LifecycleSemantics,
    /// Names interface-wide exact guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
}

/// Defines the ownership scope of one contribution aggregate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregationScope {
    /// Aggregates independently for every provider instance.
    ProviderInstance,
}

/// Defines how a provider combines authorized contributions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationContract {
    /// Selects the ownership scope of the aggregate.
    pub scope: AggregationScope,
    /// Names the contribution-key convention.
    pub key: LocalKey,
    /// Names the authenticated lifecycle-controller group for shared resources.
    pub controller_group: LocalKey,
    /// Rejects two contributors claiming one exclusive slot.
    pub reject_slot_collisions: bool,
    /// Names an explicit field-level merge contract, when one is supported.
    pub merge_contract: Option<Sha256Digest>,
}

/// Classifies a lower-interface requirement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementStrength {
    /// Must bind or become a discharged deployment obligation.
    Required,
    /// May be omitted only with its declared fallback behavior.
    Advisory,
}

/// Defines a provider implementation's named lower-interface requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementDeclaration {
    /// Names the requirement inside the provider implementation.
    pub alias: LocalKey,
    /// Lists exact accepted interface descriptors in canonical order.
    pub accepted_interfaces: Vec<InterfaceKey>,
    /// Names required methods in canonical order.
    pub methods: Vec<LocalKey>,
    /// Names required guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Defines whether omission is allowed.
    pub strength: RequirementStrength,
    /// Defines exact literal outputs when an advisory requirement is omitted.
    pub fallback: Option<RequirementFallback>,
}

/// Supplies the complete typed result of omitting one advisory requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementFallback {
    /// Maps every accepted interface output port to its exact literal value.
    pub outputs: BTreeMap<LocalKey, AbilityValue>,
}

/// Identifies how a provider realizes one exported interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ImplementationKind {
    /// Uses authenticated Nix entry points to construct finite child graphs.
    PureComposition {
        /// Names the pure composition entry point.
        compose_entry: LocalKey,
        /// Names the pure transition entry point.
        transition_entry: LocalKey,
    },
    /// Terminates composition at an exact trusted adapter or cataloged helper.
    TerminalHandler {
        /// Names the handler in the package's handler catalog.
        handler: LocalKey,
    },
}

/// Declares one provider's implementation separately from its public interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImplementation {
    /// Identifies the exact public interface implemented.
    pub interface: InterfaceKey,
    /// Identifies the authenticated implementation artifact.
    pub artifact: ArtifactReference,
    /// Lists the bounded lower-interface discovery vocabulary.
    pub requirements: Vec<RequirementDeclaration>,
    /// Defines how recursive composition terminates or expands.
    pub implementation: ImplementationKind,
    /// Names provider-owned resource kinds in canonical order.
    pub owns_resource_kinds: Vec<InterfaceName>,
}

impl ProviderImplementation {
    /// Computes the shared domain-separated implementation descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the implementation cannot be represented in the
    /// canonical AOS JSON dialect or exceeds the version-1 structural,
    /// collection, string, or encoded-byte ceilings.
    pub fn descriptor_digest(&self) -> anyhow::Result<Sha256Digest> {
        validate_provider_implementation_limits(self)?;
        Sha256Digest::of_canonical("aos.ability.provider-implementation/v1", self)
    }
}

fn validate_provider_implementation_limits(
    implementation: &ProviderImplementation,
) -> anyhow::Result<()> {
    let limits = crate::ABILITY_LIMITS_V1;
    if implementation.artifact.store_path.len() as u64 > limits.max_string_bytes {
        bail!("provider implementation artifact path exceeds the version-1 string limit");
    }

    let mut remaining_items = limits.max_collection_items;
    consume_provider_implementation_items(
        implementation,
        &mut remaining_items,
        limits.max_structural_depth,
    )?;

    let mut writer = BoundedWriter::new(limits.max_document_bytes);
    if let Err(source) = serde_json::to_writer(&mut writer, implementation) {
        if writer.exceeded {
            bail!("provider implementation exceeds the version-1 encoded-byte limit");
        }
        return Err(source.into());
    }
    Ok(())
}

fn consume_provider_implementation_items(
    implementation: &ProviderImplementation,
    remaining_items: &mut u64,
    max_depth: u32,
) -> anyhow::Result<()> {
    // Count the fixed provider, interface-key, artifact, and tagged implementation
    // record members alongside every dynamic collection below.
    consume_items(remaining_items, 5)?;
    consume_items(remaining_items, 3)?;
    consume_items(remaining_items, 4)?;
    consume_items(
        remaining_items,
        match implementation.implementation {
            ImplementationKind::PureComposition { .. } => 3,
            ImplementationKind::TerminalHandler { .. } => 2,
        },
    )?;
    consume_items(remaining_items, implementation.requirements.len())?;
    consume_items(remaining_items, implementation.owns_resource_kinds.len())?;
    for requirement in &implementation.requirements {
        consume_items(remaining_items, 6)?;
        consume_items(remaining_items, requirement.accepted_interfaces.len())?;
        consume_items(
            remaining_items,
            requirement.accepted_interfaces.len().saturating_mul(3),
        )?;
        consume_items(remaining_items, requirement.methods.len())?;
        consume_items(remaining_items, requirement.guarantees.len())?;
        consume_items(
            remaining_items,
            requirement.guarantees.len().saturating_mul(3),
        )?;
        if let Some(fallback) = &requirement.fallback {
            consume_items(remaining_items, 1)?;
            consume_items(remaining_items, fallback.outputs.len())?;
            for value in fallback.outputs.values() {
                consume_json_value(value.as_json(), remaining_items, 6, max_depth)?;
            }
        }
    }
    Ok(())
}

fn consume_json_value(
    root: &serde_json::Value,
    remaining_items: &mut u64,
    root_depth: u32,
    max_depth: u32,
) -> anyhow::Result<()> {
    let mut stack = vec![(root, root_depth)];
    while let Some((value, depth)) = stack.pop() {
        if depth > max_depth {
            bail!("provider implementation fallback exceeds the version-1 depth limit");
        }
        let child_depth = depth.saturating_add(1);
        match value {
            serde_json::Value::Array(values) => {
                consume_items(remaining_items, values.len())?;
                stack.extend(values.iter().map(|value| (value, child_depth)));
            }
            serde_json::Value::Object(values) => {
                consume_items(remaining_items, values.len())?;
                stack.extend(values.values().map(|value| (value, child_depth)));
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn consume_items(remaining: &mut u64, count: usize) -> anyhow::Result<()> {
    *remaining = remaining.checked_sub(count as u64).ok_or_else(|| {
        anyhow::anyhow!("provider implementation exceeds the version-1 item limit")
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
                "provider implementation encoding exceeds its bound",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Pins one exact provider implementation used by a binding or environment root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImplementationReference {
    /// Identifies the canonical provider implementation descriptor.
    pub descriptor: Sha256Digest,
    /// Identifies the retained executable implementation artifact.
    pub artifact: ArtifactReference,
    /// Names a terminal handler within that artifact, when applicable.
    pub handler: Option<LocalKey>,
}

/// Declares one package export and its aggregation boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDeclaration {
    /// Names the export within the package.
    pub name: LocalKey,
    /// Identifies the exact public interface contract.
    pub interface: InterfaceKey,
    /// Defines contribution aggregation, when the export accepts contributions.
    pub aggregation: Option<AggregationContract>,
    /// Identifies the separate provider implementation.
    pub implementation: Sha256Digest,
}

/// Collects a package's provider implementations and handler catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImplementation {
    /// Lists provider implementations in canonical interface order.
    pub providers: Vec<ProviderImplementation>,
    /// Maps handler names to exact constrained handler artifacts.
    pub handlers: BTreeMap<LocalKey, HandlerDescriptor>,
}

/// Describes one constrained terminal handler artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerDescriptor {
    /// Identifies the exact executable artifact and retained closure.
    pub artifact: ArtifactReference,
    /// Names the entry point relative to that artifact.
    pub entry_point: String,
    /// Defines the handler's closed argument schema.
    pub arguments: ValueSchema,
    /// Defines the handler's closed result schema.
    pub result: ValueSchema,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn collection_item_count(value: &serde_json::Value) -> u64 {
        match value {
            serde_json::Value::Array(values) => {
                values.len() as u64 + values.iter().map(collection_item_count).sum::<u64>()
            }
            serde_json::Value::Object(values) => {
                values.len() as u64 + values.values().map(collection_item_count).sum::<u64>()
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => 0,
        }
    }

    fn provider_implementation() -> ProviderImplementation {
        let accepted_interface = InterfaceKey {
            name: InterfaceName::new("aos.test.lower").expect("valid interface name"),
            abi: std::num::NonZeroU32::new(1).expect("nonzero ABI"),
            descriptor: digest(5),
        };
        let guarantee = GuaranteeKey {
            name: InterfaceName::new("aos.test.guarantee").expect("valid guarantee name"),
            version: std::num::NonZeroU32::new(1).expect("nonzero guarantee version"),
            descriptor: digest(6),
        };
        let fallback = RequirementFallback {
            outputs: [(
                LocalKey::new("ready").expect("valid output name"),
                AbilityValue::new(serde_json::json!({"items": [true, false]}))
                    .expect("bounded fallback value"),
            )]
            .into_iter()
            .collect(),
        };

        ProviderImplementation {
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test.provider").expect("valid interface name"),
                abi: std::num::NonZeroU32::new(1).expect("nonzero ABI"),
                descriptor: digest(1),
            },
            artifact: ArtifactReference {
                content: digest(2),
                store_path: "/nix/store/provider".to_string(),
                nar_hash: digest(3),
                closure: digest(4),
            },
            requirements: vec![RequirementDeclaration {
                alias: LocalKey::new("lower").expect("valid requirement alias"),
                accepted_interfaces: vec![accepted_interface],
                methods: vec![LocalKey::new("observe").expect("valid method name")],
                guarantees: vec![guarantee],
                strength: RequirementStrength::Advisory,
                fallback: Some(fallback),
            }],
            implementation: ImplementationKind::PureComposition {
                compose_entry: LocalKey::new("compose").expect("valid entry name"),
                transition_entry: LocalKey::new("transition").expect("valid entry name"),
            },
            owns_resource_kinds: vec![
                InterfaceName::new("aos.test.resource").expect("valid resource name")
            ],
        }
    }

    #[test]
    fn provider_fallback_values_share_one_aggregate_item_budget() {
        let first = serde_json::json!([null, null]);
        let second = serde_json::json!([null, null]);
        let mut remaining_items = 3;

        assert!(consume_json_value(&first, &mut remaining_items, 6, 64).is_ok());
        assert!(consume_json_value(&second, &mut remaining_items, 6, 64).is_err());
    }

    #[test]
    fn provider_preflight_counts_every_serialized_collection_item() {
        let implementation = provider_implementation();
        let encoded = serde_json::to_value(&implementation).expect("implementation serializes");
        let exact_items = collection_item_count(&encoded);
        let mut exact_remaining = exact_items;

        consume_provider_implementation_items(&implementation, &mut exact_remaining, 64)
            .expect("the exact serialized item budget is sufficient");
        assert_eq!(exact_remaining, 0);

        let mut short_remaining = exact_items - 1;
        assert!(
            consume_provider_implementation_items(&implementation, &mut short_remaining, 64)
                .is_err()
        );
    }
}
