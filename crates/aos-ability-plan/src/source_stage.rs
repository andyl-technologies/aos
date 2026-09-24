//! Portable source-composed stage authority and effect templates.
//!
//! Source-built stages already select every provider through their complete
//! module fixed point. This bundle retains that exact fixed point, its checked
//! binding, effect template, and pure transition-constructor transcript.
//! It deliberately contains no resolution policy or provider-search replay.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result as AnyResult, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactIdentity, BindingPlanDocument, DeclarationAuthority,
    DesiredStateDocument, EffectPlanDocument, EnvironmentDocument, EnvironmentId, InstanceId,
    InterfaceDocument, InterfaceKey, InterfaceName, LocalKey, PackageDocument, PlanId, RequestId,
    RequirementDeclaration, ResourceId, ResourceLifetime, ResourceReference, ResourceRevision,
    RevisionId, ScopePath, ValuePhase, VersionedDocument,
};
use aos_ability_validate::{
    BindingValidationInputs, CheckedBindingPlan, CheckedEffectPlan, ValidatedEffectTemplate,
    ValidationContext, package_source_supported_features,
};
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CompositionEvaluator, SourceTransitionPlan, TransitionError, TransitionEvaluation,
    TransitionEvaluationResult, TransitionPlanner,
};

mod admission;

pub use admission::{
    CheckedSourceStageAdmission, SOURCE_STAGE_ADMISSION_SCHEMA, SourceStageAdmission,
    SourceStageAdmissionError,
};

/// Exact schema discriminator for one source-composed stage bundle.
pub const SOURCE_STAGE_BUNDLE_SCHEMA: &str = "aos.ability.source-stage-bundle/v1";

const SOURCE_STAGE_COMPONENT_LIMIT: usize = 12;

/// Maximum canonical byte length accepted for a source-composed stage bundle.
pub const SOURCE_STAGE_BUNDLE_MAX_BYTES: usize =
    (ABILITY_LIMITS_V1.max_document_bytes as usize).saturating_mul(SOURCE_STAGE_COMPONENT_LIMIT);

/// Binds stage authority to one canonical bootable static contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageStaticContract {
    /// Carries the canonical immutable contract identity.
    pub identity: String,
    /// Commits to the exact canonical contract bytes.
    pub sha256: Sha256Digest,
}

/// Retains the final source module fixed point used for native activation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageFixedPoint {
    /// Identifies the exact target environment selected by module evaluation.
    pub environment: EnvironmentId,
    /// Retains configured instances with evaluator-injected declaration provenance.
    pub instances: BTreeMap<String, SourceStageInstance>,
    /// Retains canonical instance identities derived by the module system.
    pub instance_identities: BTreeMap<String, InstanceId>,
    /// Retains evaluated root requests from every authenticated module authority.
    pub requests: BTreeMap<String, SourceStageRequest>,
    /// Retains exact evaluated root requirement declarations.
    pub requirements: BTreeMap<String, RequirementDeclaration>,
    /// Retains provider-authored child requests from the completed fixed point.
    pub composition_requests: BTreeMap<String, SourceStageRequest>,
    /// Retains exact child requirement contracts selected by composition.
    pub composition_requirements: BTreeMap<String, SourceStageCompositionRequirement>,
    /// Retains exact selected bindings keyed by their qualified declaration key.
    pub bindings: BTreeMap<String, SourceStageBinding>,
    /// Retains typed planning outputs keyed by request and output name.
    pub composition_outputs: BTreeMap<String, BTreeMap<String, SourceStageOutput>>,
    /// Proves that the completed fixed point has no unresolved child request.
    pub composition_pending_requests: BTreeMap<String, AbilityValue>,
    /// Retains exact desired and published resource projections.
    pub resolved_resources: BTreeMap<String, SourceStageResolvedResource>,
    /// Selects the protected package-provided execution observation channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_observer: Option<SourceStageExecutionObserver>,
}

/// Selects one protected execution-boundary observer from the fixed point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageExecutionObserver {
    /// Names the exact fixed-point request that published the observer outputs.
    pub request: String,
    /// Carries the protected retained observer resource.
    pub resource: ResourceReference,
    /// Carries the resolved canonical Unix socket path.
    pub socket: String,
}

/// Retains one standard module-system instance declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageInstance {
    /// Retains the exact module authority and local declaration key.
    pub provenance: SourceStageDeclarationProvenance,
    /// Identifies the package implementation used by this instance, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<LocalKey>,
    /// Selects an instance's configured implementation, when it has one.
    ///
    /// Bindings remain authoritative for the implementations used through an
    /// instance because one provider instance may expose several interfaces.
    pub implementation: Option<SourceStageImplementation>,
    /// Carries typed instance configuration.
    pub configuration: AbilityValue,
}

impl SourceStageInstance {
    /// Checks whether one selected binding respects this instance's package provenance.
    #[must_use]
    pub fn accepts_binding_package(&self, package: &LocalKey) -> bool {
        let authority_matches = self
            .provenance
            .authority
            .package()
            .is_none_or(|owner| owner == package);
        let declaration_matches = match (&self.package, &self.implementation) {
            (None, None) => true,
            (Some(owner), Some(implementation)) => {
                owner == package && &implementation.package == owner
            }
            _ => false,
        };

        authority_matches && declaration_matches
    }
}

/// Retains module-evaluator provenance without conflating it with package artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageDeclarationProvenance {
    /// Identifies the authenticated module authority that authored the declaration.
    pub authority: DeclarationAuthority,
    /// Names the declaration inside that authority's module scope.
    pub local_key: LocalKey,
}

/// Identifies one implementation through retained package provenance.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageImplementation {
    /// Identifies the authenticated package that owns the implementation.
    pub package: LocalKey,
    /// Names the implementation inside that package's checked projection.
    pub local_key: LocalKey,
}

/// Retains one standard module-system request declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageRequest {
    /// Retains the exact module authority and local declaration key.
    pub provenance: SourceStageDeclarationProvenance,
    /// Names the selected parent request that delegated this child request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_request: Option<String>,
    /// Identifies the exact root or generated requirement declaration.
    pub requirement: SourceStageRequirementReference,
    /// Names the consuming instance declaration.
    pub consumer: String,
    /// Carries the authored request scope.
    pub scope: ScopePath,
    /// Declares the request's semantic resource lifetime.
    pub lifetime: ResourceLifetime,
    /// Carries typed request parameters.
    pub parameters: AbilityValue,
}

/// Identifies a requirement without deriving provenance from a declaration key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SourceStageRequirementReference {
    /// Selects one exact requirement from the completed module fixed point.
    FixedPoint {
        /// Names the evaluated requirement declaration retained in the bundle.
        declaration: String,
    },
    /// Selects one generated requirement by its exact fixed-point declaration key.
    Composition {
        /// Names the generated requirement retained in the same fixed point.
        declaration: String,
    },
}

/// Retains one provider-activated nested requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageCompositionRequirement {
    /// Identifies the selected implementation that activated this requirement.
    pub implementation: SourceStageImplementation,
    /// Names the implementation-local requirement alias.
    pub alias: LocalKey,
    /// Carries the authenticated package requirement declaration.
    pub requirement: RequirementDeclaration,
}

/// Retains one exact source-authored provider selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageBinding {
    /// Names the selected root or child request declaration.
    pub request: String,
    /// Identifies the selected package implementation declaration.
    pub implementation: SourceStageImplementation,
    /// Names the selected provider instance declaration.
    pub provider_instance: String,
    /// Names its exclusive aggregate contribution slot.
    pub slot: LocalKey,
}

/// Retains one typed planning output from source composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageOutput {
    /// Carries the typed output value or symbolic expression.
    pub value: AbilityValue,
    /// Declares the earliest phase in which the value is available.
    pub phase: ValuePhase,
    /// Declares public or protected visibility.
    pub visibility: String,
    /// Declares the output's resource retention boundary.
    pub lifetime: ResourceLifetime,
}

/// Retains one checked module-system resource projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageResolvedResource {
    /// Identifies the logical provider-owned resource.
    pub resource: ResourceId,
    /// Identifies the schema that owns the desired resource value.
    pub kind: InterfaceName,
    /// Declares the resource retention boundary.
    pub lifetime: ResourceLifetime,
    /// Retains the exact semantic desired resource value.
    pub value: AbilityValue,
    /// Retains the selected provider's typed backend realization.
    pub realization: AbilityValue,
    /// Carries the centrally derived semantic revision after materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<RevisionId>,
    /// Names the source binding that controls mutation, when any.
    pub controller: Option<String>,
}

impl SourceStageResolvedResource {
    /// Projects this materialized fixed-point record into the runtime resource model.
    ///
    /// # Errors
    ///
    /// Returns an error before central materialization has assigned its revision.
    pub fn resource_revision(&self) -> AnyResult<ResourceRevision> {
        Ok(ResourceRevision {
            resource: self.resource.clone(),
            kind: self.kind.clone(),
            lifetime: self.lifetime,
            value: self.value.clone(),
            realization: self.realization.clone(),
            revision: self
                .revision
                .context("source resource has no centrally derived revision")?,
        })
    }
}

impl SourceStageFixedPoint {
    /// Derives every resource revision from the resolved fixed point and package catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when a resource has no exact request, binding, instance,
    /// or authenticated implementation, or when semantic material cannot be encoded.
    pub fn derive_resource_revisions(&mut self, packages: &[PackageDocument]) -> AnyResult<()> {
        let revisions = self
            .resolved_resources
            .iter()
            .map(|(name, resource)| {
                Ok((
                    name.clone(),
                    derive_resource_revision(self, packages, resource)?,
                ))
            })
            .collect::<AnyResult<BTreeMap<_, _>>>()?;

        for (name, revision) in revisions {
            self.resolved_resources
                .get_mut(&name)
                .context("source resource disappeared during revision derivation")?
                .revision = Some(revision);
        }
        Ok(())
    }
}

fn derive_resource_revision(
    fixed_point: &SourceStageFixedPoint,
    packages: &[PackageDocument],
    resource: &SourceStageResolvedResource,
) -> AnyResult<RevisionId> {
    let resource_value = serde_json::json!({
        "resource": resource.resource,
        "kind": resource.kind,
        "lifetime": resource.lifetime,
        "value": resource.value,
        "realization": resource.realization,
    });
    let mut materials = Vec::new();

    if let Some(controller) = resource.controller.as_deref() {
        let binding = fixed_point
            .bindings
            .get(controller)
            .with_context(|| format!("resource controller {controller:?} is absent"))?;
        let (instance, identity, implementation) = selected_resource_implementation(
            fixed_point,
            packages,
            &binding.provider_instance,
            &binding.implementation,
        )?;
        let request = source_request(fixed_point, &binding.request)?;
        materials.push(serde_json::json!({
            "schema": "aos.ability.selected-resource/v1",
            "instance": {
                "declaration": binding.provider_instance,
                "identity": identity,
                "configuration": instance.configuration,
            },
            "request": {
                "declaration": binding.request,
                "value": request,
            },
            "controller": {
                "binding": controller,
                "slot": binding.slot,
            },
            "implementation": implementation,
            "resource": resource_value,
        }));
    } else {
        for (request_name, outputs) in &fixed_point.composition_outputs {
            let publishes_resource = outputs.values().any(|output| {
                resource_reference(output.value.as_json())
                    .is_ok_and(|reference| reference.resource == resource.resource)
            });
            if !publishes_resource {
                continue;
            }
            let matching_bindings = fixed_point
                .bindings
                .iter()
                .filter(|(_, binding)| binding.request == *request_name)
                .collect::<Vec<_>>();
            ensure!(
                matching_bindings.len() == 1,
                "published resource request has no exact selected binding"
            );
            let (_, binding) = matching_bindings[0];
            let (instance, identity, implementation) = selected_resource_implementation(
                fixed_point,
                packages,
                &binding.provider_instance,
                &binding.implementation,
            )?;
            let request = source_request(fixed_point, request_name)?;
            materials.push(serde_json::json!({
                "schema": "aos.ability.selected-published-resource/v1",
                "instance": {
                    "identity": identity,
                    "configuration": instance.configuration,
                },
                "request": request,
                "implementation": implementation,
                "resource": resource_value,
            }));
        }
        ensure!(
            !materials.is_empty(),
            "published resource has no exact fixed-point output"
        );
    }

    let normalized = materials
        .into_iter()
        .map(normalize_revision_artifacts)
        .collect::<AnyResult<Vec<_>>>()?;
    ensure!(
        normalized.windows(2).all(|pair| pair[0] == pair[1]),
        "published resource has conflicting semantic publications"
    );
    Ok(RevisionId(Sha256Digest::of_canonical(
        "aos.ability.resource-revision/v1",
        &normalized[0],
    )?))
}

fn source_request<'a>(
    fixed_point: &'a SourceStageFixedPoint,
    name: &str,
) -> AnyResult<&'a SourceStageRequest> {
    fixed_point
        .requests
        .get(name)
        .or_else(|| fixed_point.composition_requests.get(name))
        .with_context(|| format!("source resource request {name:?} is absent"))
}

fn resource_reference(value: &serde_json::Value) -> AnyResult<ResourceReference> {
    let mut value = value.clone();
    let fields = value
        .as_object_mut()
        .context("resource reference is not an object")?;
    if let Some(marker) = fields.remove("_type") {
        ensure!(
            marker.as_str() == Some("aos-resource-reference"),
            "resource reference has an unexpected authoring marker"
        );
    }

    // Module-authored values carry a marker; checked provider outputs use the
    // same exact portable schema without it.
    serde_json::from_value(value).context("decoding resource reference")
}

fn selected_resource_implementation<'a>(
    fixed_point: &'a SourceStageFixedPoint,
    packages: &'a [PackageDocument],
    instance_name: &str,
    implementation_reference: &SourceStageImplementation,
) -> AnyResult<(&'a SourceStageInstance, &'a InstanceId, serde_json::Value)> {
    let instance = fixed_point
        .instances
        .get(instance_name)
        .with_context(|| format!("source resource instance {instance_name:?} is absent"))?;
    let identity = fixed_point
        .instance_identities
        .get(instance_name)
        .context("source resource instance has no canonical identity")?;
    ensure!(
        instance.accepts_binding_package(&implementation_reference.package),
        "source resource implementation crosses package provenance"
    );
    let package = packages
        .iter()
        .find(|package| package.package.name == implementation_reference.package)
        .context("source resource implementation package is absent")?;
    let implementation = package
        .implementation
        .providers
        .iter()
        .find(|implementation| implementation.name == implementation_reference.local_key)
        .context("source resource implementation is absent")?;
    let descriptor = implementation.descriptor_digest()?;
    ensure!(
        package.exports.iter().any(|export| {
            export.implementation_name == implementation.name
                && export.implementation == descriptor
                && export.interface == implementation.interface
        }),
        "source resource implementation is not exported"
    );
    Ok((
        instance,
        identity,
        serde_json::json!({
            "package": package.package.name,
            "name": implementation.name,
            "interface": implementation.interface,
            "descriptor": descriptor,
            "artifact": implementation.artifact.identity(),
        }),
    ))
}

fn normalize_revision_artifacts(mut value: serde_json::Value) -> AnyResult<serde_json::Value> {
    fn normalize(value: &mut serde_json::Value, depth: u32) -> AnyResult<()> {
        ensure!(
            depth <= ABILITY_LIMITS_V1.max_structural_depth,
            "resource revision material exceeds the structural depth limit"
        );
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    normalize(value, depth.saturating_add(1))?;
                }
            }
            serde_json::Value::Object(fields)
                if (fields.len() == 4 || fields.len() == 5)
                    && fields.contains_key("content")
                    && fields.contains_key("store_path")
                    && fields.contains_key("nar_hash")
                    && fields.contains_key("closure") =>
            {
                let mut artifact = fields.clone();
                if artifact.len() == 5 {
                    ensure!(
                        artifact.get("_type").and_then(serde_json::Value::as_str)
                            == Some("aos-artifact-reference"),
                        "resource revision artifact has an invalid authoring marker"
                    );
                    artifact.remove("_type");
                }
                let artifact: aos_ability_model::ArtifactReference =
                    serde_json::from_value(serde_json::Value::Object(artifact))
                        .context("decoding resource revision artifact")?;
                *value = serde_json::to_value(ArtifactIdentity {
                    content: artifact.content,
                    nar_hash: artifact.nar_hash,
                    closure: artifact.closure,
                })?;
            }
            serde_json::Value::Object(fields) => {
                for value in fields.values_mut() {
                    normalize(value, depth.saturating_add(1))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    normalize(&mut value, 1)?;
    Ok(value)
}

/// Retains pure transition construction performed under source authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageTransitionProvenance {
    /// Commits to the source fixed point and checked binding inputs.
    pub authority: Sha256Digest,
    /// Retains exact pure constructor exchanges in evaluation order.
    pub evaluations: Vec<TransitionEvaluation>,
}

/// Carries one sealed source-composed stage template and its authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageBundle {
    schema: String,
    authority: Sha256Digest,
    static_contract: SourceStageStaticContract,
    evaluation_base_lib: String,
    fixed_point: SourceStageFixedPoint,
    binding_plan: PlanId,
    effect_plan: PlanId,
    interfaces: Vec<InterfaceDocument>,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    packages: Vec<PackageDocument>,
    binding_document: BindingPlanDocument,
    effect_document: EffectPlanDocument,
    transition: SourceStageTransitionProvenance,
}

/// Carries a source bundle whose complete graph passed common validation.
#[derive(Debug)]
pub struct CheckedSourceStageBundle {
    bundle: SourceStageBundle,
    digest: Sha256Digest,
    plan: CheckedEffectPlan,
}

/// Retains a source stage whose offline graph passed template validation.
///
/// Planned providers without readiness remain unresolved. This value cannot
/// be used to open an execution transaction.
#[derive(Debug)]
pub struct ValidatedSourceStageTemplate {
    bundle: SourceStageBundle,
    digest: Sha256Digest,
    template: ValidatedEffectTemplate,
}

/// Reports why source-composed stage authority cannot be accepted.
#[derive(Debug, Error)]
pub enum SourceStageBundleError {
    /// Bounded strict JSON decoding failed.
    #[error("source stage bundle decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// Canonical JSON encoding failed.
    #[error("source stage bundle encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// The encoded bundle exceeds its explicit version bound.
    #[error("source stage bundle exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The schema discriminator is unsupported.
    #[error("source stage bundle has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("source stage bundle is not canonically encoded")]
    NoncanonicalEncoding,
    /// An independently supplied bundle commitment differs.
    #[error("source stage bundle differs from its external commitment")]
    CommitmentMismatch,
    /// The static contract identity is malformed.
    #[error("source stage static contract identity is invalid")]
    StaticContractIdentity,
    /// The frozen evaluation library is not one exact Nix store root.
    #[error("source stage evaluation library is not an exact store root")]
    EvaluationBaseLibIdentity,
    /// Fixed-point authority differs from the checked binding graph.
    #[error("source stage fixed point differs from its checked binding authority")]
    FixedPointAuthority,
    /// Transition provenance is malformed or names another source authority.
    #[error("source stage transition provenance is invalid")]
    TransitionProvenance,
    /// Common binding or effect-plan validation failed.
    #[error("source stage semantic validation failed: {0}")]
    Validation(#[source] aos_ability_validate::ValidationErrors),
    /// Runtime inventory changed a sealed source-stage input.
    #[error("source stage runtime inventory differs from its sealed template")]
    RootInventoryMismatch,
    /// The instantiated graph still has unresolved deployment obligations.
    #[error("source stage runtime plan is not executable")]
    PlanNotExecutable,
    /// Pure transition construction or transcript replay failed.
    #[error("source stage transition failed: {0}")]
    Transition(#[source] TransitionError),
    /// A claimed authority, binding plan, or effect plan identity differs.
    #[error("source stage bundle identity linkage is inconsistent")]
    IdentityMismatch,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SourceAuthorityMaterial<'a> {
    schema: &'static str,
    static_contract: &'a SourceStageStaticContract,
    evaluation_base_lib: &'a str,
    fixed_point: &'a SourceStageFixedPoint,
    interfaces: &'a [InterfaceDocument],
    environment: &'a EnvironmentDocument,
    desired_state: &'a DesiredStateDocument,
    packages: &'a [PackageDocument],
    binding_document: &'a BindingPlanDocument,
}

impl SourceStageBundle {
    /// Constructs a canonical bundle from one validated offline template.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed point differs from the checked binding
    /// graph, transition provenance is incomplete, or encoding exceeds bounds.
    pub fn from_template(
        static_contract: SourceStageStaticContract,
        evaluation_base_lib: String,
        fixed_point: SourceStageFixedPoint,
        template: &ValidatedEffectTemplate,
        evaluations: Vec<TransitionEvaluation>,
    ) -> Result<Self, SourceStageBundleError> {
        Self::from_parts(
            static_contract,
            evaluation_base_lib,
            fixed_point,
            template.binding_plan(),
            template.document(),
            template.interfaces(),
            evaluations,
        )
    }

    fn from_parts(
        static_contract: SourceStageStaticContract,
        evaluation_base_lib: String,
        fixed_point: SourceStageFixedPoint,
        binding: &CheckedBindingPlan,
        effect_document: &EffectPlanDocument,
        interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
        evaluations: Vec<TransitionEvaluation>,
    ) -> Result<Self, SourceStageBundleError> {
        let mut bundle = Self {
            schema: SOURCE_STAGE_BUNDLE_SCHEMA.to_string(),
            authority: Sha256Digest::separated(SOURCE_STAGE_BUNDLE_SCHEMA, []),
            static_contract,
            evaluation_base_lib,
            fixed_point,
            binding_plan: binding.id(),
            effect_plan: PlanId(
                effect_document
                    .content_digest()
                    .map_err(|error| SourceStageBundleError::Encode(anyhow::Error::new(error)))?,
            ),
            interfaces: interfaces.values().cloned().collect(),
            environment: binding.environment().clone(),
            desired_state: binding.desired_state().clone(),
            packages: binding.packages().to_vec(),
            binding_document: binding.document().clone(),
            effect_document: effect_document.clone(),
            transition: SourceStageTransitionProvenance {
                authority: Sha256Digest::separated(SOURCE_STAGE_BUNDLE_SCHEMA, []),
                evaluations,
            },
        };
        bundle.authority = bundle.source_authority()?;
        bundle.transition.authority = bundle.authority;
        bundle.validate_linkage()?;
        bundle.canonical_bytes()?;
        Ok(bundle)
    }

    /// Derives source authority before pure transition construction.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical authority material cannot be encoded.
    pub fn authority_for(
        static_contract: &SourceStageStaticContract,
        evaluation_base_lib: &str,
        fixed_point: &SourceStageFixedPoint,
        binding: &aos_ability_validate::CheckedBindingPlan,
        interfaces: &[InterfaceDocument],
    ) -> Result<Sha256Digest, SourceStageBundleError> {
        source_authority(
            static_contract,
            evaluation_base_lib,
            fixed_point,
            interfaces,
            binding.environment(),
            binding.desired_state(),
            binding.packages(),
            binding.document(),
        )
    }

    /// Returns the source authority committed by the bundle.
    #[must_use]
    pub const fn authority(&self) -> Sha256Digest {
        self.authority
    }

    /// Returns the exact frozen module library selected during image construction.
    #[must_use]
    pub fn evaluation_base_lib(&self) -> &str {
        &self.evaluation_base_lib
    }

    /// Returns the canonical static contract binding.
    #[must_use]
    pub const fn static_contract(&self) -> &SourceStageStaticContract {
        &self.static_contract
    }

    /// Returns the final fixed-point activation projection.
    #[must_use]
    pub const fn fixed_point(&self) -> &SourceStageFixedPoint {
        &self.fixed_point
    }

    /// Returns the claimed checked effect-plan identity.
    #[must_use]
    pub const fn effect_plan(&self) -> PlanId {
        self.effect_plan
    }

    /// Returns the retained transition-constructor provenance.
    #[must_use]
    pub const fn transition(&self) -> &SourceStageTransitionProvenance {
        &self.transition
    }

    /// Encodes the bundle in bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when linkage is invalid or serialization exceeds the
    /// version-1 bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SourceStageBundleError> {
        self.validate_linkage()?;

        let mut writer = BoundedWriter::new(
            SOURCE_STAGE_BUNDLE_MAX_BYTES as u64,
            "serialized source stage bundle exceeds its byte limit",
        );
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded() {
                SourceStageBundleError::EncodedSizeLimit
            } else {
                SourceStageBundleError::Encode(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(SourceStageBundleError::Encode)
    }

    /// Computes the domain-separated canonical bundle identity.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest, SourceStageBundleError> {
        Ok(Sha256Digest::separated(
            SOURCE_STAGE_BUNDLE_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes one strictly bounded canonical source stage bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, or internally
    /// inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceStageBundleError> {
        let bundle = source_stage_limits()
            .decode::<Self>(bytes, SOURCE_STAGE_BUNDLE_SCHEMA)
            .map_err(SourceStageBundleError::Decode)?;
        if bundle.schema != SOURCE_STAGE_BUNDLE_SCHEMA {
            return Err(SourceStageBundleError::UnsupportedSchema);
        }
        if bundle.canonical_bytes()? != bytes {
            return Err(SourceStageBundleError::NoncanonicalEncoding);
        }
        Ok(bundle)
    }

    /// Reconstructs and validates the complete checked source plan.
    ///
    /// # Errors
    ///
    /// Returns an error when an external commitment differs, the fixed point
    /// and transition provenance do not match their source authority, or common
    /// binding/effect validation fails.
    pub fn check(
        self,
        expected_digest: Option<Sha256Digest>,
    ) -> Result<CheckedSourceStageBundle, SourceStageBundleError> {
        let digest = self.digest()?;
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(SourceStageBundleError::CommitmentMismatch);
        }

        let (context, binding) = self.validate_binding()?;
        let rebuilt = TransitionPlanner::new(&context)
            .verify_source_transcript(
                self.authority,
                &binding,
                &self.fixed_point,
                &self.transition.evaluations,
                self.effect_plan,
            )
            .map_err(SourceStageBundleError::Transition)?;
        let plan = rebuilt.checked_effect().clone();
        if plan.document() != &self.effect_document {
            return Err(SourceStageBundleError::IdentityMismatch);
        }

        Ok(CheckedSourceStageBundle {
            bundle: self,
            digest,
            plan,
        })
    }

    /// Reconstructs and validates an offline source-stage template.
    ///
    /// This check retains unresolved planned-provider bindings and produces no
    /// executable plan handle. Boot-time admission must provide fresh root
    /// evidence before any transaction may open.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle commitment, fixed-point authority,
    /// binding plan, or structural effect graph is invalid.
    pub fn check_template(
        self,
        expected_digest: Option<Sha256Digest>,
    ) -> Result<ValidatedSourceStageTemplate, SourceStageBundleError> {
        let digest = self.digest()?;
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(SourceStageBundleError::CommitmentMismatch);
        }

        let (context, binding) = self.validate_binding()?;
        let rebuilt = TransitionPlanner::new(&context)
            .verify_source_template_transcript(
                self.authority,
                &binding,
                &self.fixed_point,
                &self.transition.evaluations,
                self.effect_plan,
            )
            .map_err(SourceStageBundleError::Transition)?;
        let template = rebuilt.effect_template().clone();
        if template.document() != &self.effect_document {
            return Err(SourceStageBundleError::IdentityMismatch);
        }

        Ok(ValidatedSourceStageTemplate {
            bundle: self,
            digest,
            template,
        })
    }

    /// Instantiates a complete plan from a trusted stage-entry environment.
    ///
    /// The caller must authenticate and freshness-check the root observation.
    /// Only provider state, incarnation, and freshness may differ from the
    /// sealed template. Pure transition constructors receive those observations,
    /// so the effect graph must be rebuilt from the freshly checked binding.
    /// The returned transcript belongs to the admitted plan and must be kept
    /// with its durable transaction evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed template, altered sealed input,
    /// transition evaluation failure, unresolved provider readiness, or an
    /// invalid runtime effect plan.
    pub fn instantiate_from_trusted_environment(
        &self,
        observed: EnvironmentDocument,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<SourceTransitionPlan, SourceStageBundleError> {
        let (context, binding) = self.runtime_binding(observed)?;
        let transition = TransitionPlanner::new(&context)
            .plan_source(self.authority, &binding, &self.fixed_point, evaluator)
            .map_err(SourceStageBundleError::Transition)?;
        if !transition.checked_effect().is_executable() {
            return Err(SourceStageBundleError::PlanNotExecutable);
        }
        Ok(transition)
    }

    fn runtime_binding(
        &self,
        observed: EnvironmentDocument,
    ) -> Result<(ValidationContext, CheckedBindingPlan), SourceStageBundleError> {
        self.clone().check_template(None)?;
        if observed.providers.len() != self.environment.providers.len()
            || observed
                .providers
                .iter()
                .zip(&self.environment.providers)
                .any(|(actual, sealed)| {
                    actual.provider != sealed.provider
                        || actual.interface != sealed.interface
                        || actual.implementation != sealed.implementation
                        || actual.guarantees != sealed.guarantees
                })
        {
            return Err(SourceStageBundleError::RootInventoryMismatch);
        }
        let mut normalized = observed.clone();
        normalized.providers = self.environment.providers.clone();
        normalized.freshness = self.environment.freshness.clone();
        if normalized != self.environment {
            return Err(SourceStageBundleError::RootInventoryMismatch);
        }

        let mut desired_state = self.desired_state.clone();
        desired_state.environment = observed
            .content_digest()
            .map_err(|error| SourceStageBundleError::Encode(anyhow::Error::new(error)))?;
        let mut binding_document = self.binding_document.clone();
        binding_document.environment = desired_state.environment;
        binding_document.desired_state = desired_state
            .content_digest()
            .map_err(|error| SourceStageBundleError::Encode(anyhow::Error::new(error)))?;

        let context = self.validation_context()?;
        let binding = context
            .validate_binding_plan(
                binding_document,
                BindingValidationInputs {
                    environment: observed,
                    desired_state,
                    packages: self.packages.clone(),
                },
            )
            .map_err(SourceStageBundleError::Validation)?;
        self.validate_fixed_point(&binding)?;
        Ok((context, binding))
    }

    fn validate_binding(
        &self,
    ) -> Result<(ValidationContext, CheckedBindingPlan), SourceStageBundleError> {
        let context = self.validation_context()?;
        let binding = context
            .validate_binding_plan(
                self.binding_document.clone(),
                BindingValidationInputs {
                    environment: self.environment.clone(),
                    desired_state: self.desired_state.clone(),
                    packages: self.packages.clone(),
                },
            )
            .map_err(SourceStageBundleError::Validation)?;
        if binding.id() != self.binding_plan {
            return Err(SourceStageBundleError::IdentityMismatch);
        }
        self.validate_fixed_point(&binding)?;
        Ok((context, binding))
    }

    fn validation_context(&self) -> Result<ValidationContext, SourceStageBundleError> {
        let supported_features = package_source_supported_features()
            .map_err(|error| SourceStageBundleError::Encode(error.into()))?;
        ValidationContext::new(supported_features, self.interfaces.clone())
            .map_err(SourceStageBundleError::Validation)
    }

    fn validate_linkage(&self) -> Result<(), SourceStageBundleError> {
        if self.schema != SOURCE_STAGE_BUNDLE_SCHEMA {
            return Err(SourceStageBundleError::UnsupportedSchema);
        }
        validate_contract_identity(&self.static_contract.identity)?;
        validate_evaluation_base_lib(&self.evaluation_base_lib)?;
        let binding_digest = self
            .binding_document
            .content_digest()
            .map_err(|error| SourceStageBundleError::Encode(error.into()))?;
        let effect_digest = self
            .effect_document
            .content_digest()
            .map_err(|error| SourceStageBundleError::Encode(error.into()))?;
        if self.authority != self.source_authority()?
            || self.transition.authority != self.authority
            || binding_digest != self.binding_plan.0
            || effect_digest != self.effect_plan.0
            || self.effect_document.binding_plan != self.binding_plan.0
        {
            return Err(SourceStageBundleError::IdentityMismatch);
        }
        validate_transition_provenance(&self.transition.evaluations)?;
        Ok(())
    }

    fn source_authority(&self) -> Result<Sha256Digest, SourceStageBundleError> {
        source_authority(
            &self.static_contract,
            &self.evaluation_base_lib,
            &self.fixed_point,
            &self.interfaces,
            &self.environment,
            &self.desired_state,
            &self.packages,
            &self.binding_document,
        )
    }

    fn validate_fixed_point(
        &self,
        binding: &aos_ability_validate::CheckedBindingPlan,
    ) -> Result<(), SourceStageBundleError> {
        let fixed = &self.fixed_point;
        if fixed.environment != binding.environment().environment
            || !fixed.composition_pending_requests.is_empty()
            || fixed.instances.len() != fixed.instance_identities.len()
            || fixed.instances.keys().ne(fixed.instance_identities.keys())
            || fixed.bindings.len() != binding.bindings().len()
        {
            return Err(SourceStageBundleError::FixedPointAuthority);
        }

        let requests = fixed
            .requests
            .iter()
            .chain(&fixed.composition_requests)
            .map(|(name, request)| {
                let consumer = fixed.instance_identities.get(&request.consumer)?;
                Some((
                    name.as_str(),
                    RequestId {
                        consumer: consumer.clone(),
                        scope: request.scope.clone(),
                        key: request.provenance.local_key.clone(),
                    },
                ))
            })
            .collect::<Option<BTreeMap<_, _>>>()
            .ok_or(SourceStageBundleError::FixedPointAuthority)?;
        if requests.len() != binding.document().requests.len() {
            return Err(SourceStageBundleError::FixedPointAuthority);
        }
        for selected in fixed.bindings.values() {
            let request = requests
                .get(selected.request.as_str())
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            let provider = fixed
                .instance_identities
                .get(&selected.provider_instance)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            let matches = binding
                .bindings()
                .iter()
                .filter(|checked| {
                    checked.request == *request
                        && checked.provider == *provider
                        && (checked.caller_grant.contributions.is_empty()
                            || checked.caller_grant.contributions.iter().any(|permission| {
                                permission.slot == selected.slot
                                    && permission.aggregate.provider == *provider
                            }))
                        && implementation_reference(binding.packages(), checked)
                            .is_some_and(|reference| reference == selected.implementation)
                })
                .count();
            if matches != 1 {
                return Err(SourceStageBundleError::FixedPointAuthority);
            }
        }

        let mut projected_resources = self
            .fixed_point
            .resolved_resources
            .values()
            .map(SourceStageResolvedResource::resource_revision)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SourceStageBundleError::FixedPointAuthority)?;
        projected_resources.sort_by(|left, right| left.resource.cmp(&right.resource));
        let mut checked_resources = binding.desired_state().resources.clone();
        checked_resources.sort_by(|left, right| left.resource.cmp(&right.resource));
        if projected_resources != checked_resources {
            return Err(SourceStageBundleError::FixedPointAuthority);
        }
        Ok(())
    }
}

impl SourceStageFixedPoint {
    pub(crate) fn enabled_providers(
        &self,
        packages: &[PackageDocument],
    ) -> Result<Vec<crate::transition::SourceEnabledProvider>, SourceStageBundleError> {
        let selected = |name: &str,
                        instance: &SourceStageInstance,
                        reference: &SourceStageImplementation|
         -> Result<
            crate::transition::SourceEnabledProvider,
            SourceStageBundleError,
        > {
            let identity = self
                .instance_identities
                .get(name)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            if !instance.accepts_binding_package(&reference.package) {
                return Err(SourceStageBundleError::FixedPointAuthority);
            }
            let package = packages
                .iter()
                .find(|package| package.package.name == reference.package)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            let implementation = package
                .implementation
                .providers
                .iter()
                .find(|provider| provider.name == reference.local_key)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            Ok(crate::transition::SourceEnabledProvider {
                instance: identity.clone(),
                implementation: aos_ability_model::ProviderImplementationReference {
                    descriptor: implementation
                        .descriptor_digest()
                        .map_err(SourceStageBundleError::Encode)?,
                    artifact: implementation.artifact.clone(),
                    handler: implementation.handler.clone(),
                },
                package: package
                    .content_digest()
                    .map_err(|error| SourceStageBundleError::Encode(anyhow::Error::new(error)))?,
            })
        };

        let mut providers = Vec::new();
        for binding in self.bindings.values() {
            let instance = self
                .instances
                .get(&binding.provider_instance)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            providers.push(selected(
                &binding.provider_instance,
                instance,
                &binding.implementation,
            )?);
        }
        for (name, instance) in &self.instances {
            let Some(reference) = &instance.implementation else {
                continue;
            };
            providers.push(selected(name, instance, reference)?);
        }
        providers.sort_by(|left, right| {
            left.instance
                .cmp(&right.instance)
                .then_with(|| left.package.cmp(&right.package))
                .then_with(|| {
                    left.implementation
                        .descriptor
                        .cmp(&right.implementation.descriptor)
                })
        });
        providers.dedup();
        Ok(providers)
    }
}

fn source_authority(
    static_contract: &SourceStageStaticContract,
    evaluation_base_lib: &str,
    fixed_point: &SourceStageFixedPoint,
    interfaces: &[InterfaceDocument],
    environment: &EnvironmentDocument,
    desired_state: &DesiredStateDocument,
    packages: &[PackageDocument],
    binding_document: &BindingPlanDocument,
) -> Result<Sha256Digest, SourceStageBundleError> {
    validate_evaluation_base_lib(evaluation_base_lib)?;
    let material = SourceAuthorityMaterial {
        schema: "aos.ability.source-stage-authority/v1",
        static_contract,
        evaluation_base_lib,
        fixed_point,
        interfaces,
        environment,
        desired_state,
        packages,
        binding_document,
    };
    let bytes =
        aos_contract::canonical::to_vec(&material).map_err(SourceStageBundleError::Encode)?;
    Ok(Sha256Digest::separated(material.schema, bytes))
}

fn implementation_reference(
    packages: &[PackageDocument],
    binding: &aos_ability_model::Binding,
) -> Option<SourceStageImplementation> {
    let package_digest = binding.provider_package?;
    packages.iter().find_map(|package| {
        if package.content_digest().ok()? != package_digest {
            return None;
        }
        package
            .implementation
            .providers
            .iter()
            .find(|provider| {
                provider.descriptor_digest().ok() == Some(binding.implementation.descriptor)
            })
            .map(|provider| SourceStageImplementation {
                package: package.package.name.clone(),
                local_key: provider.name.clone(),
            })
    })
}

impl CheckedSourceStageBundle {
    /// Returns the exact portable bundle that was checked.
    #[must_use]
    pub const fn bundle(&self) -> &SourceStageBundle {
        &self.bundle
    }

    /// Returns the canonical bundle identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the reconstructed semantically checked effect plan.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }
}

impl ValidatedSourceStageTemplate {
    /// Returns the exact portable bundle that was validated.
    #[must_use]
    pub const fn bundle(&self) -> &SourceStageBundle {
        &self.bundle
    }

    /// Returns the canonical bundle identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the offline effect template and its unresolved provider set.
    #[must_use]
    pub const fn template(&self) -> &ValidatedEffectTemplate {
        &self.template
    }
}

fn validate_contract_identity(identity: &str) -> Result<(), SourceStageBundleError> {
    let canonical = identity.starts_with('/')
        && identity != "/"
        && !identity.ends_with('/')
        && !identity.contains("//")
        && !identity
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        && identity.len() as u64 <= ABILITY_LIMITS_V1.max_string_bytes;
    if !canonical {
        return Err(SourceStageBundleError::StaticContractIdentity);
    }
    Ok(())
}

fn validate_evaluation_base_lib(path: &str) -> Result<(), SourceStageBundleError> {
    let Some((hash, name)) = path
        .strip_prefix("/nix/store/")
        .and_then(|component| component.split_once('-'))
    else {
        return Err(SourceStageBundleError::EvaluationBaseLibIdentity);
    };
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|character| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&character))
        || name.is_empty()
        || name.contains('/')
        || path.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
    {
        return Err(SourceStageBundleError::EvaluationBaseLibIdentity);
    }
    Ok(())
}

fn validate_transition_provenance(
    evaluations: &[TransitionEvaluation],
) -> Result<(), SourceStageBundleError> {
    if evaluations.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
        || evaluations.iter().any(|evaluation| {
            matches!(evaluation.result, TransitionEvaluationResult::Failed { .. })
        })
    {
        return Err(SourceStageBundleError::TransitionProvenance);
    }
    let identities = evaluations
        .iter()
        .map(|evaluation| {
            (
                evaluation.provider.clone(),
                evaluation.implementation.descriptor,
            )
        })
        .collect::<BTreeSet<_>>();
    if identities.len() != evaluations.len() {
        return Err(SourceStageBundleError::TransitionProvenance);
    }
    Ok(())
}

fn source_stage_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: SOURCE_STAGE_BUNDLE_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 2,
        max_items: (ABILITY_LIMITS_V1.max_collection_items as usize)
            .saturating_mul(SOURCE_STAGE_COMPONENT_LIMIT),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EmptyTransitionEvaluator, verified_planning_transition_fixture};

    #[test]
    fn published_resource_reference_accepts_checked_provider_output() {
        let reference = serde_json::json!({
            "interface": {
                "name": "aos.test.resource",
                "abi": 1,
                "descriptor": Sha256Digest::of_bytes(b"test interface"),
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "system",
                        "stage": "initrd",
                    },
                    "key": "provider",
                },
                "key": "resource",
            },
            "operations": ["observe"],
            "lifetime": "instance",
        });
        let mut authored = reference.clone();
        authored["_type"] = serde_json::json!("aos-resource-reference");

        assert_eq!(
            resource_reference(&reference).expect("checked provider output"),
            resource_reference(&authored).expect("module-authored reference")
        );
        authored["_type"] = serde_json::json!("unexpected");
        assert!(resource_reference(&authored).is_err());
    }

    #[test]
    fn system_selected_provider_uses_binding_package_provenance() {
        let selected = LocalKey::new("systemd").expect("selected package key");
        let other = LocalKey::new("other").expect("other package key");
        let mut instance = SourceStageInstance {
            provenance: SourceStageDeclarationProvenance {
                authority: DeclarationAuthority::System,
                local_key: LocalKey::new("provider").expect("provider key"),
            },
            package: None,
            implementation: None,
            configuration: AbilityValue::new(serde_json::json!({}))
                .expect("empty provider configuration"),
        };

        assert!(instance.accepts_binding_package(&selected));

        instance.provenance.authority = DeclarationAuthority::Package {
            package: selected.clone(),
        };
        assert!(instance.accepts_binding_package(&selected));
        assert!(!instance.accepts_binding_package(&other));

        instance.package = Some(selected.clone());
        instance.implementation = Some(SourceStageImplementation {
            package: selected.clone(),
            local_key: LocalKey::new("service").expect("implementation key"),
        });
        assert!(instance.accepts_binding_package(&selected));
        instance
            .implementation
            .as_mut()
            .expect("implementation")
            .package = other;
        assert!(!instance.accepts_binding_package(&selected));
    }

    fn bundle() -> SourceStageBundle {
        let (context, planning, transition) = verified_planning_transition_fixture();
        let plan = transition.checked_effect();
        let binding = plan.binding_plan();
        let mut instance_names = binding
            .desired_state()
            .instances
            .iter()
            .enumerate()
            .map(|(index, instance)| (instance.instance.clone(), format!("instance-{index}")))
            .collect::<BTreeMap<_, _>>();
        for request in &binding.document().requests {
            let next = instance_names.len();
            instance_names
                .entry(request.id.consumer.clone())
                .or_insert_with(|| format!("instance-{next}"));
        }
        for selected in binding.bindings() {
            let next = instance_names.len();
            instance_names
                .entry(selected.provider.clone())
                .or_insert_with(|| format!("instance-{next}"));
        }
        let instance_identities = instance_names
            .iter()
            .map(|(identity, name)| (name.clone(), identity.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut instances = binding
            .desired_state()
            .instances
            .iter()
            .map(|instance| {
                let name = instance_names[&instance.instance].clone();
                let package = binding
                    .packages()
                    .iter()
                    .find(|package| package.content_digest().ok() == instance.package)
                    .expect("instance package");
                let implementation = binding
                    .bindings()
                    .iter()
                    .find(|selected| selected.provider == instance.instance)
                    .and_then(|selected| implementation_reference(binding.packages(), selected));
                (
                    name,
                    SourceStageInstance {
                        provenance: SourceStageDeclarationProvenance {
                            authority: instance.authority.clone(),
                            local_key: LocalKey::new("fixture-instance")
                                .expect("instance declaration key"),
                        },
                        package: Some(package.package.name.clone()),
                        implementation,
                        configuration: instance
                            .configuration
                            .clone()
                            .unwrap_or_else(|| AbilityValue::new(serde_json::json!({})).unwrap()),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for request in &binding.document().requests {
            let name = instance_names[&request.id.consumer].clone();
            instances
                .entry(name)
                .or_insert_with(|| SourceStageInstance {
                    provenance: SourceStageDeclarationProvenance {
                        authority: request.authority.clone(),
                        local_key: LocalKey::new("fixture-consumer")
                            .expect("consumer declaration key"),
                    },
                    package: request.authority.package().cloned(),
                    implementation: None,
                    configuration: AbilityValue::new(serde_json::json!({}))
                        .expect("consumer configuration"),
                });
        }
        for selected in binding.bindings() {
            let name = instance_names[&selected.provider].clone();
            let package_digest = selected.provider_package.expect("provider package");
            let package = binding
                .packages()
                .iter()
                .find(|package| package.content_digest().ok() == Some(package_digest))
                .expect("provider package document");
            instances
                .entry(name)
                .or_insert_with(|| SourceStageInstance {
                    provenance: SourceStageDeclarationProvenance {
                        authority: DeclarationAuthority::Package {
                            package: package.package.name.clone(),
                        },
                        local_key: LocalKey::new("fixture-provider")
                            .expect("provider declaration key"),
                    },
                    package: Some(package.package.name.clone()),
                    implementation: implementation_reference(binding.packages(), selected),
                    configuration: AbilityValue::new(serde_json::json!({}))
                        .expect("provider configuration"),
                });
        }
        let request_names = binding
            .document()
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| (request.id.clone(), format!("request-{index}")))
            .collect::<BTreeMap<_, _>>();
        let requests = binding
            .document()
            .requests
            .iter()
            .map(|request| {
                (
                    request_names[&request.id].clone(),
                    SourceStageRequest {
                        provenance: SourceStageDeclarationProvenance {
                            authority: request.authority.clone(),
                            local_key: request.id.key.clone(),
                        },
                        owner_request: None,
                        requirement: SourceStageRequirementReference::FixedPoint {
                            declaration: request_names[&request.id].clone(),
                        },
                        consumer: instance_names[&request.id.consumer].clone(),
                        scope: request.id.scope.clone(),
                        lifetime: request.lifetime,
                        parameters: request.parameters.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let requirements = binding
            .document()
            .requests
            .iter()
            .map(|request| {
                (
                    request_names[&request.id].clone(),
                    RequirementDeclaration {
                        alias: request.id.key.clone(),
                        description: "Source-stage fixture requirement.".to_string(),
                        accepted_interfaces: request
                            .accepted_interfaces
                            .iter()
                            .cloned()
                            .map(Into::into)
                            .collect(),
                        methods: request.methods.clone(),
                        guarantees: request.guarantees.clone(),
                        strength: aos_ability_model::RequirementStrength::Required,
                        fallback: None,
                    },
                )
            })
            .collect();
        let bindings = binding
            .bindings()
            .iter()
            .enumerate()
            .map(|(index, selected)| {
                (
                    format!("source-binding-{index}"),
                    SourceStageBinding {
                        request: request_names[&selected.request].clone(),
                        implementation: implementation_reference(binding.packages(), selected)
                            .expect("implementation name"),
                        provider_instance: instance_names[&selected.provider].clone(),
                        slot: selected.caller_grant.contributions.first().map_or_else(
                            || LocalKey::new("selected").expect("fixture slot"),
                            |permission| permission.slot.clone(),
                        ),
                    },
                )
            })
            .collect();
        let resolved_resources = planning
            .checked_binding()
            .desired_state()
            .resources
            .iter()
            .enumerate()
            .map(|(index, resource)| {
                (
                    format!("resource-{index}"),
                    SourceStageResolvedResource {
                        resource: resource.resource.clone(),
                        kind: resource.kind.clone(),
                        lifetime: resource.lifetime,
                        value: resource.value.clone(),
                        realization: resource.realization.clone(),
                        revision: Some(resource.revision),
                        controller: None,
                    },
                )
            })
            .collect();

        let static_contract = SourceStageStaticContract {
            identity: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-initrd-contract/contract.json"
                .to_string(),
            sha256: Sha256Digest::separated("aos.test.contract/v1", b"contract"),
        };
        let fixed_point = SourceStageFixedPoint {
            environment: binding.environment().environment.clone(),
            instances,
            instance_identities,
            requests,
            requirements,
            composition_requests: BTreeMap::new(),
            composition_requirements: BTreeMap::new(),
            bindings,
            composition_outputs: BTreeMap::new(),
            composition_pending_requests: BTreeMap::new(),
            resolved_resources,
            execution_observer: None,
        };
        let interfaces = plan.interfaces().values().cloned().collect::<Vec<_>>();
        let evaluation_base_lib = "/nix/store/00000000000000000000000000000000-initrd-evaluation";
        let authority = SourceStageBundle::authority_for(
            &static_contract,
            evaluation_base_lib,
            &fixed_point,
            binding,
            &interfaces,
        )
        .expect("source stage fixture authority");
        let source_transition = TransitionPlanner::new(&context)
            .plan_source_template(
                authority,
                binding,
                &fixed_point,
                &mut EmptyTransitionEvaluator,
            )
            .expect("source stage fixture transition");

        SourceStageBundle::from_template(
            static_contract,
            evaluation_base_lib.to_string(),
            fixed_point,
            source_transition.effect_template(),
            source_transition.evaluations().to_vec(),
        )
        .expect("source stage fixture must validate")
    }

    #[test]
    fn source_stage_round_trip_reconstructs_the_checked_plan() {
        let bundle = bundle();
        let digest = bundle.digest().expect("bundle digest");
        let bytes = bundle.canonical_bytes().expect("canonical bundle");

        let checked = SourceStageBundle::decode(&bytes)
            .expect("decoded bundle")
            .check(Some(digest))
            .expect("checked source bundle");

        assert_eq!(checked.digest(), digest);
        assert_eq!(checked.plan().id(), bundle.effect_plan());
        assert_eq!(checked.bundle(), &bundle);
    }

    #[test]
    fn source_stage_template_round_trip_preserves_checked_inputs() {
        let original = bundle();
        let bytes = original.canonical_bytes().expect("offline source bundle");
        let validated = SourceStageBundle::decode(&bytes)
            .expect("decoded bundle")
            .check_template(None)
            .expect("validated source template");
        let reconstructed = SourceStageBundle::from_template(
            original.static_contract.clone(),
            original.evaluation_base_lib.clone(),
            original.fixed_point.clone(),
            validated.template(),
            original.transition.evaluations.clone(),
        )
        .expect("bundle from validated template");

        assert_eq!(validated.bundle(), &original);
        assert_eq!(validated.digest(), original.digest().unwrap());
        assert_eq!(reconstructed, original);

        let mut changed_evaluator = original.clone();
        changed_evaluator.evaluation_base_lib =
            "/nix/store/11111111111111111111111111111111-initrd-evaluation".to_string();
        assert!(matches!(
            changed_evaluator.check_template(None),
            Err(SourceStageBundleError::IdentityMismatch)
        ));

        let mut changed_transcript = original;
        changed_transcript.transition.evaluations[0].entry =
            LocalKey::new("wrong-transition").expect("test key");
        assert!(matches!(
            changed_transcript.check_template(None),
            Err(SourceStageBundleError::Transition(
                TransitionError::Transcript(_)
            ))
        ));
    }

    #[test]
    fn source_stage_admission_replays_only_the_exact_observed_plan() {
        let template = bundle();
        let observed = template.environment.clone();
        let admission = template
            .admit_from_trusted_environment(observed.clone(), &mut EmptyTransitionEvaluator)
            .expect("admitted source stage");
        let digest = admission.digest().expect("admission digest");
        let bytes = admission.canonical_bytes().expect("canonical admission");
        let checked = SourceStageAdmission::decode(&bytes)
            .expect("decoded admission")
            .check(&template, observed.clone(), Some(digest))
            .expect("replayed admission");

        assert_eq!(checked.admission(), &admission);
        assert_eq!(checked.digest(), digest);
        assert_eq!(checked.plan().id(), admission.effect_plan());

        let mut changed_observation = observed.clone();
        changed_observation.providers[0].state = aos_ability_model::document::ProviderState::Stale;
        assert!(matches!(
            admission
                .clone()
                .check(&template, changed_observation, None),
            Err(SourceStageAdmissionError::ObservationMismatch)
        ));

        let mut changed_transcript = serde_json::to_value(&admission).expect("admission JSON");
        changed_transcript["evaluations"][0]["entry"] = serde_json::json!("wrong-transition");
        let changed_bytes =
            aos_contract::canonical::to_vec(&changed_transcript).expect("canonical changed record");
        let changed = SourceStageAdmission::decode(&changed_bytes).expect("changed admission");
        assert!(matches!(
            changed.check(&template, observed, None),
            Err(SourceStageAdmissionError::Transition(
                TransitionError::Transcript(_)
            ))
        ));
    }

    #[test]
    fn source_stage_instantiation_rebinds_only_runtime_inventory() {
        let bundle = bundle();
        let mut observed = bundle.environment.clone();
        observed.freshness.generation = RevisionId(Sha256Digest::separated(
            "aos.test.root-observation/v1",
            b"fresh",
        ));

        let admitted = bundle
            .instantiate_from_trusted_environment(observed.clone(), &mut EmptyTransitionEvaluator)
            .expect("fresh inventory admits the same source graph");
        assert!(admitted.checked_effect().is_executable());
        assert_ne!(admitted.checked_effect().id(), bundle.effect_plan());
        assert_eq!(
            admitted.checked_effect().binding_plan().environment(),
            &observed
        );
        assert!(!admitted.evaluations().is_empty());
        for evaluation in admitted.evaluations() {
            let context: crate::TransitionContext =
                serde_json::from_value(evaluation.input.as_json().clone())
                    .expect("fresh transition context");
            assert_eq!(context.observations.freshness, observed.freshness);
        }
        assert_ne!(
            admitted.evaluations()[0].input,
            bundle.transition.evaluations[0].input,
        );

        let mut changed_provider = observed;
        changed_provider.providers[0].implementation.descriptor =
            Sha256Digest::separated("aos.test.foreign-implementation/v1", b"foreign");
        assert!(matches!(
            bundle.instantiate_from_trusted_environment(
                changed_provider,
                &mut EmptyTransitionEvaluator,
            ),
            Err(SourceStageBundleError::RootInventoryMismatch)
        ));
    }

    #[test]
    fn source_stage_authority_is_bound_to_the_static_contract() {
        let bundle = bundle();
        let mut value = serde_json::to_value(&bundle).expect("bundle value");
        value["static_contract"]["identity"] = serde_json::Value::String(
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other/contract.json".to_string(),
        );
        let bytes = aos_contract::canonical::to_vec(&value).expect("tampered bytes");

        assert!(SourceStageBundle::decode(&bytes).is_err());
    }

    fn centrally_derived_revision(
        store_path: &str,
        nar_material: &[u8],
        request_marker: &str,
    ) -> RevisionId {
        let bundle = bundle();
        let packages = bundle.packages.clone();
        let mut fixed_point = bundle.fixed_point.clone();
        let controllers = fixed_point
            .resolved_resources
            .iter()
            .map(|(name, resource)| {
                let controller = fixed_point
                    .bindings
                    .iter()
                    .find(|(_, binding)| {
                        fixed_point.instance_identities[&binding.provider_instance]
                            == resource.resource.provider
                    })
                    .map(|(name, _)| name.clone())
                    .expect("fixture resource must have a provider binding");
                (name.clone(), controller)
            })
            .collect::<BTreeMap<_, _>>();
        for (name, resource) in &mut fixed_point.resolved_resources {
            resource.controller = Some(controllers[name].clone());
            resource.revision = None;
        }

        let resource_name = fixed_point
            .resolved_resources
            .keys()
            .next()
            .cloned()
            .expect("fixture resource");
        let controller_name = controllers[&resource_name].clone();
        let binding = fixed_point.bindings[&controller_name].clone();
        let artifact = aos_ability_model::ArtifactReference {
            content: Sha256Digest::of_bytes(b"semantic content"),
            store_path: store_path.to_string(),
            nar_hash: Sha256Digest::of_bytes(nar_material),
            closure: Sha256Digest::of_bytes(b"semantic closure"),
        };
        fixed_point
            .instances
            .get_mut(&binding.provider_instance)
            .expect("fixture provider instance")
            .configuration = AbilityValue::new(serde_json::json!({"artifact": artifact}))
            .expect("fixture provider configuration");
        let request = if let Some(request) = fixed_point.requests.get_mut(&binding.request) {
            request
        } else {
            fixed_point
                .composition_requests
                .get_mut(&binding.request)
                .expect("fixture binding request")
        };
        request.parameters = AbilityValue::new(serde_json::json!({"marker": request_marker}))
            .expect("fixture request parameters");

        fixed_point
            .derive_resource_revisions(&packages)
            .expect("central resource revision derivation");
        fixed_point.resolved_resources[&resource_name]
            .revision
            .expect("derived revision")
    }

    #[test]
    fn resource_revisions_use_resolved_semantics_without_store_locators() {
        let original = centrally_derived_revision(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-provider",
            b"provider nar",
            "request-a",
        );
        let relocated = centrally_derived_revision(
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-provider",
            b"provider nar",
            "request-a",
        );
        let changed_artifact = centrally_derived_revision(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-provider",
            b"changed provider nar",
            "request-a",
        );
        let changed_request = centrally_derived_revision(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-provider",
            b"provider nar",
            "request-b",
        );

        assert_eq!(original, relocated);
        assert_ne!(original, changed_artifact);
        assert_ne!(original, changed_request);
    }

    #[test]
    fn direct_source_transition_uses_checked_bindings_without_policy_resolution() {
        let (context, planning, _) = verified_planning_transition_fixture();
        let authority = Sha256Digest::separated("aos.test.source-authority/v1", b"source");
        let fixed_point = bundle();

        let transition = crate::TransitionPlanner::new(&context)
            .plan_source(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                &mut EmptyTransitionEvaluator,
            )
            .expect("direct source transition");
        let template = crate::TransitionPlanner::new(&context)
            .plan_source_template(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                &mut EmptyTransitionEvaluator,
            )
            .expect("offline source transition template");
        let replayed = crate::TransitionPlanner::new(&context)
            .verify_source_transcript(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                transition.evaluations(),
                transition.checked_effect().id(),
            )
            .expect("source transcript replay");

        assert_eq!(
            transition.checked_effect().binding_plan().id(),
            planning.checked_binding().id()
        );
        assert_eq!(
            template.effect_template().document(),
            transition.checked_effect().document()
        );
        assert!(
            template
                .effect_template()
                .unresolved_provider_bindings()
                .is_empty()
        );
        assert_eq!(template.evaluations(), transition.evaluations());
        assert!(!transition.evaluations().is_empty());
        assert_eq!(
            replayed.checked_effect().document(),
            transition.checked_effect().document()
        );
        assert_eq!(replayed.evaluations(), transition.evaluations());
        assert!(transition.evaluations().iter().all(|evaluation| {
            evaluation
                .input
                .as_json()
                .get("desired_planning")
                .is_some_and(|value| value == &serde_json::json!(authority))
        }));

        let mut changed_call = transition.evaluations().to_vec();
        changed_call[0].entry = LocalKey::new("wrong-transition").expect("test key");
        assert!(matches!(
            crate::TransitionPlanner::new(&context).verify_source_transcript(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                &changed_call,
                transition.checked_effect().id(),
            ),
            Err(TransitionError::Transcript(_))
        ));
    }

    #[test]
    fn source_transition_transcript_retains_skipped_calls() {
        struct SkippingSourceEvaluator;

        impl CompositionEvaluator for SkippingSourceEvaluator {
            fn evaluate(
                &mut self,
                _implementation: &aos_ability_model::ProviderImplementationReference,
                _module: &aos_ability_model::ModuleLocator,
                _entry: &LocalKey,
                _input: &AbilityValue,
            ) -> Result<AbilityValue, crate::EvaluationError> {
                Err(crate::EvaluationError::new(
                    "source evaluation must use the batch",
                ))
            }

            fn evaluate_source_batch(
                &mut self,
                requests: &[crate::SourceEvaluationRequest],
            ) -> Result<
                Vec<Result<Option<AbilityValue>, crate::EvaluationError>>,
                crate::EvaluationError,
            > {
                Ok(requests.iter().map(|_| Ok(None)).collect())
            }
        }

        let (context, planning, _) = verified_planning_transition_fixture();
        let authority = Sha256Digest::separated("aos.test.source-authority/v1", b"skipped");
        let fixed_point = bundle();
        let transition = crate::TransitionPlanner::new(&context)
            .plan_source(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                &mut SkippingSourceEvaluator,
            )
            .expect("source transition with skipped calls");

        assert!(!transition.evaluations().is_empty());
        assert!(
            transition
                .evaluations()
                .iter()
                .all(|evaluation| matches!(evaluation.result, TransitionEvaluationResult::Skipped))
        );

        let replayed = crate::TransitionPlanner::new(&context)
            .verify_source_transcript(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                transition.evaluations(),
                transition.checked_effect().id(),
            )
            .expect("replay skipped source calls");
        assert_eq!(replayed.evaluations(), transition.evaluations());

        let incomplete = &transition.evaluations()[..transition.evaluations().len() - 1];
        assert!(matches!(
            crate::TransitionPlanner::new(&context).verify_source_transcript(
                authority,
                planning.checked_binding(),
                fixed_point.fixed_point(),
                incomplete,
                transition.checked_effect().id(),
            ),
            Err(TransitionError::Transcript(_))
        ));
    }
}
