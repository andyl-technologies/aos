//! Stage-entry inventory of existing terminal provider facilities.
//!
//! The source template selects handlers but cannot observe a future boot.
//! This adapter invokes only those handlers through their authenticated
//! package artifacts, checks each native response, and constructs the live
//! environment used to admit the source plan before any effect is journaled.

use std::collections::BTreeSet;
use std::time::Instant;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::document::{ProviderInventory, ProviderState};
use aos_ability_model::{
    EnvironmentDocument, ProviderImplementationReference, RequestId, ResourceRevision, RevisionId,
};
use aos_ability_plan::ValidatedSourceStageTemplate;
use aos_ability_plan::source_stage::SourceActivationOwner;
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    InvocationControl, ROOT_OBSERVATION_REQUEST_SCHEMA, ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA,
    RootObservationRequest, RootObservationResult, RootResourceObservationRequest,
    RootResourceObservationResult, validate_boot_id, validate_root_observation,
    validate_root_resource_observation,
};
use serde::Serialize;

use super::command_handler::{
    observe_selected_resource_root_handler, observe_selected_root_handler,
};
use crate::package_contract::{VerifiedPackageContract, VerifiedPackageContractSet};

/// Carries the fresh inventory and native responses used for stage admission.
pub(crate) struct ObservedSourceRoots {
    pub(crate) environment: EnvironmentDocument,
    pub(crate) requests: Vec<RootObservationRequest>,
    pub(crate) responses: Vec<RootObservationResult>,
    pub(crate) resource_requests: Vec<RootResourceObservationRequest>,
    pub(crate) resource_responses: Vec<RootResourceObservationResult>,
    observed_at: Vec<Instant>,
    resource_observed_at: Vec<Instant>,
}

impl ObservedSourceRoots {
    /// Rejects an inventory whose first provider observation has already aged out.
    pub(crate) fn ensure_fresh(&self) -> Result<()> {
        ensure!(
            self.responses
                .iter()
                .zip(&self.observed_at)
                .all(|(response, observed_at)| {
                    observed_at.elapsed().as_millis()
                        <= u128::from(response.freshness.max_age_millis)
                }),
            "source-stage root inventory expired before plan admission"
        );
        ensure!(
            self.resource_responses
                .iter()
                .zip(&self.resource_observed_at)
                .all(|(response, observed_at)| {
                    observed_at.elapsed().as_millis()
                        <= u128::from(response.root.freshness.max_age_millis)
                }),
            "source-stage image resource inventory expired before plan admission"
        );
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryGeneration<'a> {
    schema: &'static str,
    boot_id: &'a str,
    providers: Vec<ProviderGeneration<'a>>,
    resources: Vec<ResourceGeneration<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceGeneration<'a> {
    resource: &'a aos_ability_model::ResourceId,
    revision: RevisionId,
    evidence: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderGeneration<'a> {
    provider: &'a aos_ability_model::InstanceId,
    implementation: &'a ProviderImplementationReference,
    incarnation: &'a aos_ability_model::IncarnationId,
    generation: RevisionId,
}

/// Observes selected terminal providers without an in-plan readiness producer.
///
/// The caller supplies a canonical current boot identity and bounded probe
/// policy. An unavailable provider or missing authenticated package handler
/// rejects the whole inventory before the source effect plan can be admitted.
///
/// # Errors
///
/// Returns an error when a selected package, handler, response, native
/// assignment, or freshness bound cannot be authenticated.
pub(crate) fn observe_source_roots(
    template: &ValidatedSourceStageTemplate,
    packages: &VerifiedPackageContractSet,
    boot_id: &str,
    maximum_age_millis: u64,
    invocation_budget_millis: u64,
) -> Result<ObservedSourceRoots> {
    ensure!(
        !boot_id.is_empty() && maximum_age_millis > 0 && invocation_budget_millis > 0,
        "source-stage root observation requires a boot identity and bounded budgets"
    );
    let binding = template.template().binding_plan();
    packages.verify_plan_inputs(
        &binding.environment().platform,
        binding.packages(),
        &binding.environment().artifacts,
    )?;
    packages.reverify_live_retention()?;

    let selected_roots = selected_roots(template)?;
    let mut requests = Vec::with_capacity(selected_roots.len());
    let mut responses = Vec::with_capacity(selected_roots.len());
    let mut observed_at = Vec::with_capacity(selected_roots.len());
    for selected in selected_roots {
        let package = selected_package(packages, binding, selected)?;
        let request = RootObservationRequest {
            schema: ROOT_OBSERVATION_REQUEST_SCHEMA.to_string(),
            provider: selected.provider.clone(),
            interface: selected.interface.clone(),
            implementation: selected.implementation.clone(),
            policy_revision: binding.environment().policy_revision,
            boot_id: boot_id.to_string(),
            challenge: Sha256Digest::of_bytes(rand::random::<[u8; 32]>()),
            maximum_age_millis,
            control: InvocationControl {
                attempt_remaining_millis: invocation_budget_millis,
                recovery_remaining_millis: invocation_budget_millis,
                cancelled: false,
            },
        };
        let started_at = Instant::now();
        let response = observe_selected_root_handler(
            package,
            &selected.interface,
            &selected.implementation,
            &request,
        )
        .with_context(|| format!("observing selected root provider {:?}", selected.provider))?;
        ensure!(
            response.state == ProviderState::Available,
            "selected source-stage root provider {:?} is unavailable",
            selected.provider
        );
        requests.push(request);
        responses.push(response);
        observed_at.push(started_at);
    }

    let image_resources = selected_image_resources(template)?;
    let mut resource_requests = Vec::with_capacity(image_resources.len());
    let mut resource_responses = Vec::with_capacity(image_resources.len());
    let mut resource_observed_at = Vec::with_capacity(image_resources.len());
    for (resource, selected) in &image_resources {
        let package = selected_package(packages, binding, selected)?;
        let request = RootResourceObservationRequest {
            schema: ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA.to_string(),
            root: RootObservationRequest {
                schema: ROOT_OBSERVATION_REQUEST_SCHEMA.to_string(),
                provider: selected.provider.clone(),
                interface: selected.interface.clone(),
                implementation: selected.implementation.clone(),
                policy_revision: binding.environment().policy_revision,
                boot_id: boot_id.to_string(),
                challenge: Sha256Digest::of_bytes(rand::random::<[u8; 32]>()),
                maximum_age_millis,
                control: InvocationControl {
                    attempt_remaining_millis: invocation_budget_millis,
                    recovery_remaining_millis: invocation_budget_millis,
                    cancelled: false,
                },
            },
            resource: resource.clone(),
        };
        let started_at = Instant::now();
        let response = observe_selected_resource_root_handler(
            package,
            &selected.interface,
            &selected.implementation,
            &request,
        )
        .with_context(|| format!("observing image-owned resource {:?}", resource.resource))?;
        ensure!(
            response.ready,
            "image-owned resource {:?} is not ready in this boot",
            resource.resource
        );
        resource_requests.push(request);
        resource_responses.push(response);
        resource_observed_at.push(started_at);
    }

    verify_image_resource_exchanges(
        &image_resources,
        &resource_requests,
        &resource_responses,
        &responses,
        binding.environment().policy_revision,
        boot_id,
    )?;
    let environment = environment_from_responses(
        binding.environment(),
        &responses,
        &resource_responses,
        boot_id,
    )?;
    let observation = ObservedSourceRoots {
        environment,
        requests,
        responses,
        resource_requests,
        resource_responses,
        observed_at,
        resource_observed_at,
    };
    observation.ensure_fresh()?;
    Ok(observation)
}

fn selected_image_resources(
    template: &ValidatedSourceStageTemplate,
) -> Result<Vec<(ResourceRevision, ProviderInventory)>> {
    let fixed_point = template.bundle().fixed_point();
    let binding_plan = template.template().binding_plan();
    let mut selected_resources = Vec::new();
    for resource in fixed_point
        .resolved_resources
        .values()
        .filter(|resource| resource.activation_owner == SourceActivationOwner::Image)
    {
        let revision = resource.resource_revision()?;
        ensure!(
            binding_plan.environment().resources.contains(&revision),
            "image-owned resource is absent from the sealed current inventory"
        );
        let controller_name = resource
            .controller
            .as_ref()
            .context("image-owned resource has no selected controller")?;
        let controller = fixed_point
            .bindings
            .get(controller_name)
            .context("image-owned resource controller is absent")?;
        let request = fixed_point
            .requests
            .get(&controller.request)
            .or_else(|| fixed_point.composition_requests.get(&controller.request))
            .context("image-owned resource controller request is absent")?;
        let request_id = RequestId {
            consumer: fixed_point
                .instance_identities
                .get(&request.consumer)
                .context("image-owned resource controller consumer is absent")?
                .clone(),
            scope: request.scope.clone(),
            key: request.provenance.local_key.clone(),
        };
        let bindings = binding_plan
            .bindings()
            .iter()
            .filter(|binding| {
                binding.request == request_id
                    && binding.provider == revision.resource.provider
                    && binding.implementation.handler.is_some()
                    && binding.caller_grant.resources.iter().any(|permission| {
                        permission.resource == revision.resource && permission.access.is_write()
                    })
            })
            .collect::<Vec<_>>();
        let [controller] = bindings.as_slice() else {
            bail!("image-owned resource has no unique selected terminal controller")
        };
        let selected = binding_plan
            .environment()
            .providers
            .iter()
            .find(|provider| {
                provider.provider == controller.provider
                    && provider.interface == controller.interface
                    && provider.implementation == controller.implementation
            })
            .context("image-owned resource controller has no selected root provider")?;
        selected_resources.push((revision, selected.clone()));
    }
    selected_resources.sort_by(|left, right| left.0.resource.cmp(&right.0.resource));
    Ok(selected_resources)
}

fn selected_roots(template: &ValidatedSourceStageTemplate) -> Result<Vec<&ProviderInventory>> {
    let binding = template.template().binding_plan();
    let unresolved = template.template().unresolved_provider_bindings();
    let image_providers = selected_image_resources(template)?;
    for binding_id in unresolved {
        let selected_binding = binding
            .binding(binding_id)
            .context("unresolved source binding is absent from the checked plan")?;
        ensure!(
            binding.environment().providers.iter().any(|provider| {
                provider.provider == selected_binding.provider
                    && provider.interface == selected_binding.interface
                    && provider.implementation == selected_binding.implementation
            }),
            "unresolved source binding has no selected terminal provider"
        );
    }

    Ok(binding
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            image_providers
                .iter()
                .any(|(_, selected)| selected == *provider)
                || unresolved.iter().any(|binding_id| {
                    binding.binding(binding_id).is_some_and(|selected_binding| {
                        provider.provider == selected_binding.provider
                            && provider.interface == selected_binding.interface
                            && provider.implementation == selected_binding.implementation
                    })
                })
        })
        .collect::<Vec<_>>())
}

/// Reconstructs the environment committed by recorded root exchanges.
///
/// This proves exact coverage and wire identity of the historical observation;
/// callers must separately obtain a fresh current inventory before resuming.
///
/// # Errors
///
/// Returns an error when a recorded exchange omits, duplicates, or changes a
/// selected root, or when its claimed environment cannot be reconstructed.
pub(crate) fn verify_recorded_source_roots(
    template: &ValidatedSourceStageTemplate,
    requests: &[RootObservationRequest],
    responses: &[RootObservationResult],
    resource_requests: &[RootResourceObservationRequest],
    resource_responses: &[RootResourceObservationResult],
    boot_id: &str,
) -> Result<EnvironmentDocument> {
    let roots = selected_roots(template)?;
    let image_resources = selected_image_resources(template)?;
    verify_image_resource_exchanges(
        &image_resources,
        resource_requests,
        resource_responses,
        responses,
        template
            .template()
            .binding_plan()
            .environment()
            .policy_revision,
        boot_id,
    )?;
    verify_recorded_exchanges(
        template.template().binding_plan().environment(),
        &roots,
        requests,
        responses,
        resource_responses,
        boot_id,
    )
}

fn verify_image_resource_exchanges(
    selected: &[(ResourceRevision, ProviderInventory)],
    requests: &[RootResourceObservationRequest],
    responses: &[RootResourceObservationResult],
    roots: &[RootObservationResult],
    policy_revision: RevisionId,
    boot_id: &str,
) -> Result<()> {
    ensure!(
        requests.len() == selected.len() && responses.len() == selected.len(),
        "image-owned resource observations differ from the selected resource set"
    );
    for (((resource, provider), request), response) in selected.iter().zip(requests).zip(responses)
    {
        ensure!(
            request.resource == *resource
                && request.root.provider == provider.provider
                && request.root.interface == provider.interface
                && request.root.implementation == provider.implementation
                && request.root.policy_revision == policy_revision
                && request.root.boot_id == boot_id,
            "image-owned resource probe differs from its selected controller"
        );
        validate_root_resource_observation(request, response)?;
        ensure!(response.ready, "image-owned resource was not ready");
        ensure!(
            roots.iter().any(|root| {
                root.provider == response.root.provider
                    && root.interface == response.root.interface
                    && root.implementation == response.root.implementation
                    && root.incarnation == response.root.incarnation
                    && root.freshness.generation == response.root.freshness.generation
            }),
            "image-owned resource observation differs from its selected provider assignment"
        );
    }
    Ok(())
}

fn verify_recorded_exchanges(
    sealed: &EnvironmentDocument,
    roots: &[&ProviderInventory],
    requests: &[RootObservationRequest],
    responses: &[RootObservationResult],
    resource_responses: &[RootResourceObservationResult],
    boot_id: &str,
) -> Result<EnvironmentDocument> {
    ensure!(
        requests.len() == roots.len() && responses.len() == roots.len(),
        "recorded source root evidence differs from the selected root set"
    );
    for ((selected, request), response) in roots.iter().zip(requests).zip(responses) {
        ensure!(
            request.provider == selected.provider
                && request.interface == selected.interface
                && request.implementation == selected.implementation
                && request.policy_revision == sealed.policy_revision
                && request.boot_id == boot_id,
            "recorded root request differs from the selected implementation"
        );
        validate_root_observation(request, response)?;
        ensure!(
            response.state == ProviderState::Available,
            "recorded source root was not available"
        );
    }
    environment_from_responses(sealed, responses, resource_responses, boot_id)
}

fn selected_package<'a>(
    packages: &'a VerifiedPackageContractSet,
    binding: &aos_ability_validate::CheckedBindingPlan,
    selected: &ProviderInventory,
) -> Result<&'a VerifiedPackageContract> {
    let package_digests = binding
        .bindings()
        .iter()
        .filter(|candidate| {
            candidate.provider == selected.provider
                && candidate.interface == selected.interface
                && candidate.implementation == selected.implementation
        })
        .map(|candidate| candidate.provider_package)
        .collect::<BTreeSet<_>>();
    ensure!(
        package_digests.len() == 1,
        "source-stage root provider has no unique selected package authority"
    );
    let package_digest = package_digests
        .into_iter()
        .next()
        .flatten()
        .context("source-stage root provider has no authenticated package identity")?;
    let matches = packages
        .iter()
        .filter(|package| package.package_digest() == package_digest)
        .collect::<Vec<_>>();
    let [package] = matches.as_slice() else {
        bail!("source-stage root provider has no unique authenticated package")
    };
    Ok(*package)
}

fn environment_from_responses(
    sealed: &EnvironmentDocument,
    responses: &[RootObservationResult],
    resource_responses: &[RootResourceObservationResult],
    boot_id: &str,
) -> Result<EnvironmentDocument> {
    validate_boot_id(boot_id)?;
    let mut environment = sealed.clone();
    let mut generations = Vec::with_capacity(responses.len());
    let mut maximum_age_millis = u64::MAX;
    let mut observed_providers = BTreeSet::new();
    for response in responses {
        ensure!(
            response.boot_id == boot_id,
            "source-stage root observation belongs to another boot"
        );
        let selected = environment
            .providers
            .iter_mut()
            .find(|provider| {
                provider.provider == response.provider
                    && provider.interface == response.interface
                    && provider.implementation == response.implementation
            })
            .context("root observation names no selected terminal provider")?;
        ensure!(
            response.state == ProviderState::Available
                && observed_providers
                    .insert((selected.provider.clone(), selected.interface.clone())),
            "source-stage root observation is unavailable or duplicated"
        );
        let incarnation = response
            .incarnation
            .as_ref()
            .context("available source-stage root provider has no incarnation")?;
        selected.state = ProviderState::Available;
        selected.incarnation = Some(incarnation.clone());
        generations.push(ProviderGeneration {
            provider: &response.provider,
            implementation: &response.implementation,
            incarnation,
            generation: response.freshness.generation,
        });
        maximum_age_millis = maximum_age_millis.min(response.freshness.max_age_millis);
    }

    let generation = InventoryGeneration {
        schema: "aos.ability.stage-root-inventory/v1",
        boot_id,
        providers: generations,
        resources: resource_responses
            .iter()
            .map(|response| {
                Ok(ResourceGeneration {
                    resource: &response.resource,
                    revision: response
                        .observed_revision
                        .context("ready image resource has no observed revision")?,
                    evidence: Sha256Digest::of_canonical(
                        "aos.ability.image-resource-observation/v1",
                        &response.evidence,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    for response in resource_responses {
        maximum_age_millis = maximum_age_millis.min(response.root.freshness.max_age_millis);
    }
    environment.freshness.generation = RevisionId(Sha256Digest::separated(
        "aos.ability.stage-root-inventory/v1",
        aos_contract::canonical::to_vec(&generation)?,
    ));
    if !responses.is_empty() || !resource_responses.is_empty() {
        environment.freshness.max_age_millis = maximum_age_millis;
    }
    Ok(environment)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::document::{FreshnessCondition, ProviderState};
    use aos_ability_model::{
        AbilityValue, EnvironmentDocument, IncarnationId, InterfaceName, LocalKey, ResourceId,
        ResourceLifetime, ResourceRevision, RevisionId, ValueExpression,
    };
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::{
        InvocationControl, ROOT_OBSERVATION_REQUEST_SCHEMA, ROOT_OBSERVATION_RESULT_SCHEMA,
        ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA, ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA,
        RootObservationRequest, RootObservationResult, RootResourceObservationRequest,
        RootResourceObservationResult,
    };

    use super::{
        environment_from_responses, verify_image_resource_exchanges, verify_recorded_exchanges,
    };

    const BOOT_A: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const BOOT_B: &str = "11234567-89ab-cdef-0123-456789abcdef";

    fn sealed_environment() -> EnvironmentDocument {
        serde_json::from_value(serde_json::json!({
            "schema": "aos.ability.environment/v1",
            "required_features": [],
            "environment": {"authority":"system-image","key":"test","stage":"initrd"},
            "platform": {"system":"linux","architecture":"x86_64"},
            "policy_revision": Sha256Digest::of_bytes(b"source policy"),
            "providers": [{
                "provider": {
                    "environment": {"authority":"system-image","key":"test","stage":"initrd"},
                    "key": "manager"
                },
                "interface": {
                    "name": "aos.test.manager",
                    "abi": 1,
                    "descriptor": Sha256Digest::of_bytes(b"manager interface")
                },
                "implementation": {
                    "descriptor": Sha256Digest::of_bytes(b"manager implementation"),
                    "artifact": {
                        "content": Sha256Digest::of_bytes(b"manager artifact"),
                        "store_path": "/nix/store/00000000000000000000000000000000-manager",
                        "nar_hash": Sha256Digest::of_bytes(b"manager NAR"),
                        "closure": Sha256Digest::of_bytes(b"manager closure")
                    },
                    "handler": "manager"
                },
                "state": "planned",
                "incarnation": null,
                "guarantees": []
            }],
            "artifacts": [],
            "resources": [],
            "controllers": [],
            "guarantees": [],
            "freshness": {
                "generation": Sha256Digest::of_bytes(b"image generation"),
                "max_age_millis": 10000
            }
        }))
        .expect("sealed environment")
    }

    fn response(sealed: &EnvironmentDocument) -> RootObservationResult {
        let selected = &sealed.providers[0];
        RootObservationResult {
            schema: ROOT_OBSERVATION_RESULT_SCHEMA.to_string(),
            challenge: Sha256Digest::of_bytes(b"challenge"),
            provider: selected.provider.clone(),
            interface: selected.interface.clone(),
            implementation: selected.implementation.clone(),
            policy_revision: sealed.policy_revision,
            boot_id: BOOT_A.to_string(),
            state: ProviderState::Available,
            incarnation: Some(IncarnationId::new("manager-boot-a").expect("incarnation")),
            freshness: FreshnessCondition {
                generation: RevisionId(Sha256Digest::of_bytes(b"manager generation")),
                max_age_millis: 5000,
            },
            evidence: AbilityValue::new(serde_json::json!({"manager":"connected"}))
                .expect("evidence"),
        }
    }

    fn request(sealed: &EnvironmentDocument) -> RootObservationRequest {
        let selected = &sealed.providers[0];
        RootObservationRequest {
            schema: ROOT_OBSERVATION_REQUEST_SCHEMA.to_string(),
            provider: selected.provider.clone(),
            interface: selected.interface.clone(),
            implementation: selected.implementation.clone(),
            policy_revision: sealed.policy_revision,
            boot_id: BOOT_A.to_string(),
            challenge: Sha256Digest::of_bytes(b"challenge"),
            maximum_age_millis: 10_000,
            control: InvocationControl {
                attempt_remaining_millis: 5_000,
                recovery_remaining_millis: 5_000,
                cancelled: false,
            },
        }
    }

    #[test]
    fn root_inventory_generation_follows_boot_and_native_assignment() {
        let mut sealed = sealed_environment();
        let mut future_provider = sealed.providers[0].clone();
        future_provider.provider.key = "planned".parse().expect("provider key");
        sealed.providers.push(future_provider);
        let observed = response(&sealed);
        let first = environment_from_responses(&sealed, &[observed.clone()], &[], BOOT_A)
            .expect("first root inventory");
        let same = environment_from_responses(&sealed, &[observed.clone()], &[], BOOT_A)
            .expect("same root inventory");
        assert_eq!(first, same);
        assert_eq!(first.providers[0].state, ProviderState::Available);
        assert_eq!(first.providers[1].state, ProviderState::Planned);
        assert_eq!(first.freshness.max_age_millis, 5000);
        assert!(environment_from_responses(&sealed, &[observed.clone()], &[], BOOT_B).is_err());

        let mut next_boot_observation = observed.clone();
        next_boot_observation.boot_id = BOOT_B.to_string();
        let next_boot = environment_from_responses(&sealed, &[next_boot_observation], &[], BOOT_B)
            .expect("next boot inventory");
        assert_ne!(first.freshness.generation, next_boot.freshness.generation);

        let mut changed = observed;
        changed.incarnation = Some(IncarnationId::new("manager-boot-b").expect("incarnation"));
        let next_assignment = environment_from_responses(&sealed, &[changed], &[], BOOT_A)
            .expect("changed assignment inventory");
        assert_ne!(
            first.freshness.generation,
            next_assignment.freshness.generation
        );
    }

    #[test]
    fn root_inventory_rejects_unselected_or_duplicate_observations() {
        let sealed = sealed_environment();
        let observed = response(&sealed);

        assert!(
            environment_from_responses(&sealed, &[observed.clone(), observed.clone()], &[], BOOT_A)
                .is_err()
        );

        let mut unselected = observed;
        unselected.provider.key = "other".parse().expect("provider key");
        assert!(environment_from_responses(&sealed, &[unselected], &[], BOOT_A).is_err());
    }

    #[test]
    fn recorded_root_evidence_requires_exact_selected_exchange() {
        let sealed = sealed_environment();
        let roots = [&sealed.providers[0]];
        let request = request(&sealed);
        let response = response(&sealed);

        verify_recorded_exchanges(
            &sealed,
            &roots,
            &[request.clone()],
            &[response.clone()],
            &[],
            BOOT_A,
        )
        .expect("selected root exchange");
        assert!(verify_recorded_exchanges(&sealed, &roots, &[], &[], &[], BOOT_A).is_err());

        let mut stale = response;
        stale.challenge = Sha256Digest::of_bytes(b"older challenge");
        assert!(
            verify_recorded_exchanges(&sealed, &roots, &[request], &[stale], &[], BOOT_A).is_err()
        );
    }

    #[test]
    fn image_resource_evidence_requires_selected_revision_and_manager_assignment() {
        let sealed = sealed_environment();
        let selected = sealed.providers[0].clone();
        let root = response(&sealed);
        let resource = ResourceRevision {
            resource: ResourceId {
                provider: selected.provider.clone(),
                key: LocalKey::new("service").expect("resource key"),
            },
            kind: InterfaceName::new("aos.service.instance").expect("resource kind"),
            lifetime: ResourceLifetime::Instance,
            value: AbilityValue::new(serde_json::json!({"service":"example"}))
                .expect("desired resource"),
            realization: ValueExpression::Literal {
                value: AbilityValue::new(serde_json::json!({"unit":"example.service"}))
                    .expect("realization"),
            },
            revision: RevisionId(Sha256Digest::of_bytes(b"desired service")),
        };
        let request = RootResourceObservationRequest {
            schema: ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA.to_string(),
            root: request(&sealed),
            resource: resource.clone(),
        };
        let observed = RootResourceObservationResult {
            schema: ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA.to_string(),
            root: root.clone(),
            resource: resource.resource.clone(),
            observed_revision: Some(resource.revision),
            ready: true,
            evidence: AbilityValue::new(serde_json::json!({"unit":"active"}))
                .expect("native observation"),
        };
        let selected_resources = [(resource, selected)];

        verify_image_resource_exchanges(
            &selected_resources,
            &[request.clone()],
            &[observed.clone()],
            &[root.clone()],
            sealed.policy_revision,
            BOOT_A,
        )
        .expect("selected image resource");

        let mut wrong_revision = observed.clone();
        wrong_revision.observed_revision = Some(RevisionId(Sha256Digest::of_bytes(b"old")));
        assert!(
            verify_image_resource_exchanges(
                &selected_resources,
                &[request.clone()],
                &[wrong_revision],
                &[root.clone()],
                sealed.policy_revision,
                BOOT_A,
            )
            .is_err()
        );

        let mut wrong_assignment = observed;
        wrong_assignment.root.incarnation =
            Some(IncarnationId::new("another-manager").expect("incarnation"));
        assert!(
            verify_image_resource_exchanges(
                &selected_resources,
                &[request],
                &[wrong_assignment],
                &[root],
                sealed.policy_revision,
                BOOT_A,
            )
            .is_err()
        );
    }
}
