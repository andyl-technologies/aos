//! Portable source-composed stage authority and checked plan bundle.
//!
//! Source-built stages already select every provider through their complete
//! module fixed point. This bundle retains that exact fixed point, its checked
//! binding and effect plans, and the pure transition-constructor transcript.
//! It deliberately contains no resolution policy or provider-search replay.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, BindingPlanDocument, DesiredStateDocument, EffectPlanDocument,
    EnvironmentDocument, EnvironmentId, InstanceId, InterfaceDocument, LocalKey, PackageDocument,
    PlanId, RequestId, RequirementDeclaration, ResourceLifetime, ResourceReference,
    ResourceRevision, ScopePath, ValuePhase, VersionedDocument,
};
use aos_ability_validate::{
    BindingValidationInputs, CheckedEffectPlan, ValidationContext,
    package_source_supported_features,
};
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{TransitionEvaluation, TransitionEvaluationResult};

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
    /// Retains configured instances with carrier-injected package provenance.
    pub instances: BTreeMap<String, SourceStageInstance>,
    /// Retains canonical instance identities derived by the module system.
    pub instance_identities: BTreeMap<String, InstanceId>,
    /// Retains package-authored root requests.
    pub requests: BTreeMap<String, SourceStageRequest>,
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
    /// Identifies the package carrier that declared the instance.
    pub package: LocalKey,
    /// Selects the exact provider implementation for enabled providers.
    pub implementation: Option<String>,
    /// Carries typed instance configuration.
    pub configuration: AbilityValue,
}

/// Retains one standard module-system request declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStageRequest {
    /// Identifies the package carrier that authored the request.
    pub package: LocalKey,
    /// Names the exact root or generated requirement declaration.
    pub requirement: String,
    /// Names the consuming instance declaration.
    pub consumer: String,
    /// Carries the authored request scope.
    pub scope: ScopePath,
    /// Carries the authored local semantic key.
    pub local_key: LocalKey,
    /// Declares the request's semantic resource lifetime.
    pub lifetime: ResourceLifetime,
    /// Carries typed request parameters.
    pub parameters: AbilityValue,
}

/// Retains one provider-activated nested requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageCompositionRequirement {
    /// Names the selected implementation that activated this requirement.
    pub implementation: String,
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
    /// Names the selected package implementation declaration.
    pub implementation: String,
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
#[serde(deny_unknown_fields)]
pub struct SourceStageResolvedResource {
    /// Carries the portable desired resource revision.
    #[serde(flatten)]
    pub revision: ResourceRevision,
    /// Names the source binding that controls mutation, when any.
    pub controller: Option<String>,
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

/// Carries one complete source-composed stage plan and its authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageBundle {
    schema: String,
    authority: Sha256Digest,
    static_contract: SourceStageStaticContract,
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
    /// Fixed-point authority differs from the checked binding graph.
    #[error("source stage fixed point differs from its checked binding authority")]
    FixedPointAuthority,
    /// Transition provenance is malformed or names another source authority.
    #[error("source stage transition provenance is invalid")]
    TransitionProvenance,
    /// Common binding or effect-plan validation failed.
    #[error("source stage semantic validation failed: {0}")]
    Validation(#[source] aos_ability_validate::ValidationErrors),
    /// A claimed authority, binding plan, or effect plan identity differs.
    #[error("source stage bundle identity linkage is inconsistent")]
    IdentityMismatch,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SourceAuthorityMaterial<'a> {
    schema: &'static str,
    static_contract: &'a SourceStageStaticContract,
    fixed_point: &'a SourceStageFixedPoint,
    interfaces: &'a [InterfaceDocument],
    environment: &'a EnvironmentDocument,
    desired_state: &'a DesiredStateDocument,
    packages: &'a [PackageDocument],
    binding_document: &'a BindingPlanDocument,
}

impl SourceStageBundle {
    /// Constructs a canonical bundle from one already checked source plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed point differs from the checked binding
    /// graph, transition provenance is incomplete, or encoding exceeds bounds.
    pub fn from_checked(
        static_contract: SourceStageStaticContract,
        fixed_point: SourceStageFixedPoint,
        plan: &CheckedEffectPlan,
        evaluations: Vec<TransitionEvaluation>,
    ) -> Result<Self, SourceStageBundleError> {
        let binding = plan.binding_plan();
        let mut bundle = Self {
            schema: SOURCE_STAGE_BUNDLE_SCHEMA.to_string(),
            authority: Sha256Digest::separated(SOURCE_STAGE_BUNDLE_SCHEMA, []),
            static_contract,
            fixed_point,
            binding_plan: binding.id(),
            effect_plan: plan.id(),
            interfaces: plan.interfaces().values().cloned().collect(),
            environment: binding.environment().clone(),
            desired_state: binding.desired_state().clone(),
            packages: binding.packages().to_vec(),
            binding_document: binding.document().clone(),
            effect_document: plan.document().clone(),
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
        fixed_point: &SourceStageFixedPoint,
        binding: &aos_ability_validate::CheckedBindingPlan,
        interfaces: &[InterfaceDocument],
    ) -> Result<Sha256Digest, SourceStageBundleError> {
        source_authority(
            static_contract,
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

        let supported_features = package_source_supported_features()
            .map_err(|error| SourceStageBundleError::Encode(error.into()))?;
        let context = ValidationContext::new(supported_features, self.interfaces.clone())
            .map_err(SourceStageBundleError::Validation)?;
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
        let plan = context
            .validate_effect_plan(self.effect_document.clone(), binding)
            .map_err(SourceStageBundleError::Validation)?;
        if plan.id() != self.effect_plan {
            return Err(SourceStageBundleError::IdentityMismatch);
        }

        Ok(CheckedSourceStageBundle {
            bundle: self,
            digest,
            plan,
        })
    }

    fn validate_linkage(&self) -> Result<(), SourceStageBundleError> {
        if self.schema != SOURCE_STAGE_BUNDLE_SCHEMA {
            return Err(SourceStageBundleError::UnsupportedSchema);
        }
        validate_contract_identity(&self.static_contract.identity)?;
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
                        key: request.local_key.clone(),
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
                        && implementation_name(binding.packages(), checked)
                            .is_some_and(|name| name == selected.implementation)
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
            .map(|value| value.revision.clone())
            .collect::<Vec<_>>();
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
        let mut providers = Vec::new();
        for (name, instance) in &self.instances {
            let Some(qualified) = &instance.implementation else {
                continue;
            };
            let identity = self
                .instance_identities
                .get(name)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            let (package_name, implementation_name) = qualified
                .split_once(':')
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            if package_name != instance.package.as_str() {
                return Err(SourceStageBundleError::FixedPointAuthority);
            }
            let package = packages
                .iter()
                .find(|package| package.package.name.as_str() == package_name)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            let implementation = package
                .implementation
                .providers
                .iter()
                .find(|provider| provider.name.as_str() == implementation_name)
                .ok_or(SourceStageBundleError::FixedPointAuthority)?;
            providers.push(crate::transition::SourceEnabledProvider {
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
            });
        }
        providers.sort_by(|left, right| {
            left.instance.cmp(&right.instance).then_with(|| {
                left.implementation
                    .descriptor
                    .cmp(&right.implementation.descriptor)
            })
        });
        Ok(providers)
    }
}

fn source_authority(
    static_contract: &SourceStageStaticContract,
    fixed_point: &SourceStageFixedPoint,
    interfaces: &[InterfaceDocument],
    environment: &EnvironmentDocument,
    desired_state: &DesiredStateDocument,
    packages: &[PackageDocument],
    binding_document: &BindingPlanDocument,
) -> Result<Sha256Digest, SourceStageBundleError> {
    let material = SourceAuthorityMaterial {
        schema: "aos.ability.source-stage-authority/v1",
        static_contract,
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

fn implementation_name(
    packages: &[PackageDocument],
    binding: &aos_ability_model::Binding,
) -> Option<String> {
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
            .map(|provider| {
                format!(
                    "{}:{}",
                    package.package.name.as_str(),
                    provider.name.as_str()
                )
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
    use crate::test_support::{
        EmptyTransitionEvaluator, verified_planning_transition_fixture,
        verified_planning_transition_plan,
    };

    fn bundle() -> SourceStageBundle {
        let (planning, transition) = verified_planning_transition_plan();
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
                    .find(|package| package.content_digest().ok() == Some(instance.package))
                    .expect("instance package");
                let implementation = binding
                    .bindings()
                    .iter()
                    .find(|selected| selected.provider == instance.instance)
                    .and_then(|selected| implementation_name(binding.packages(), selected));
                (
                    name,
                    SourceStageInstance {
                        package: package.package.name.clone(),
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
                    package: request.package.clone(),
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
                    package: package.package.name.clone(),
                    implementation: implementation_name(binding.packages(), selected),
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
                        package: request.package.clone(),
                        requirement: format!("{}:fixture", request.package.as_str()),
                        consumer: instance_names[&request.id.consumer].clone(),
                        scope: request.id.scope.clone(),
                        local_key: request.id.key.clone(),
                        lifetime: request.lifetime,
                        parameters: request.parameters.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let bindings = binding
            .bindings()
            .iter()
            .enumerate()
            .map(|(index, selected)| {
                (
                    format!("source-binding-{index}"),
                    SourceStageBinding {
                        request: request_names[&selected.request].clone(),
                        implementation: implementation_name(binding.packages(), selected)
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
                        revision: resource.clone(),
                        controller: None,
                    },
                )
            })
            .collect();

        SourceStageBundle::from_checked(
            SourceStageStaticContract {
                identity:
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-initrd-contract/contract.json"
                        .to_string(),
                sha256: Sha256Digest::separated("aos.test.contract/v1", b"contract"),
            },
            SourceStageFixedPoint {
                environment: binding.environment().environment.clone(),
                instances,
                instance_identities,
                requests,
                composition_requests: BTreeMap::new(),
                composition_requirements: BTreeMap::new(),
                bindings,
                composition_outputs: BTreeMap::new(),
                composition_pending_requests: BTreeMap::new(),
                resolved_resources,
                execution_observer: None,
            },
            plan,
            transition.snapshot().evaluations().to_vec(),
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
    fn source_stage_authority_is_bound_to_the_static_contract() {
        let bundle = bundle();
        let mut value = serde_json::to_value(&bundle).expect("bundle value");
        value["static_contract"]["identity"] = serde_json::Value::String(
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other/contract.json".to_string(),
        );
        let bytes = aos_contract::canonical::to_vec(&value).expect("tampered bytes");

        assert!(SourceStageBundle::decode(&bytes).is_err());
    }

    #[test]
    fn direct_source_transition_uses_checked_bindings_without_policy_resolution() {
        let (context, planning, _) = verified_planning_transition_fixture();
        let authority = Sha256Digest::separated("aos.test.source-authority/v1", b"source");

        let transition = crate::TransitionPlanner::new(&context)
            .plan_source(
                authority,
                planning.checked_binding(),
                bundle().fixed_point(),
                &mut EmptyTransitionEvaluator,
            )
            .expect("direct source transition");

        assert_eq!(
            transition.checked_effect().binding_plan().id(),
            planning.checked_binding().id()
        );
        assert!(transition.evaluations().iter().all(|evaluation| {
            evaluation
                .input
                .as_json()
                .get("desired_planning")
                .is_some_and(|value| value == &serde_json::json!(authority))
        }));
    }
}
