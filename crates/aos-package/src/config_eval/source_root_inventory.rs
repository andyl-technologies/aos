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
use aos_ability_model::{EnvironmentDocument, ProviderImplementationReference, RevisionId};
use aos_ability_plan::ValidatedSourceStageTemplate;
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    InvocationControl, ROOT_OBSERVATION_REQUEST_SCHEMA, RootObservationRequest,
    RootObservationResult, validate_boot_id, validate_root_observation,
};
use serde::Serialize;

use super::command_handler::observe_selected_root_handler;
use crate::package_contract::{VerifiedPackageContract, VerifiedPackageContractSet};

/// Carries the fresh inventory and native responses used for stage admission.
pub(crate) struct ObservedSourceRoots {
    pub(crate) environment: EnvironmentDocument,
    pub(crate) requests: Vec<RootObservationRequest>,
    pub(crate) responses: Vec<RootObservationResult>,
    observed_at: Vec<Instant>,
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
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryGeneration<'a> {
    schema: &'static str,
    boot_id: &'a str,
    providers: Vec<ProviderGeneration<'a>>,
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
        observed_at.push(Instant::now());
    }

    let environment = environment_from_responses(binding.environment(), &responses, boot_id)?;
    let observation = ObservedSourceRoots {
        environment,
        requests,
        responses,
        observed_at,
    };
    observation.ensure_fresh()?;
    Ok(observation)
}

fn selected_roots(template: &ValidatedSourceStageTemplate) -> Result<Vec<&ProviderInventory>> {
    let binding = template.template().binding_plan();
    let unresolved = template.template().unresolved_provider_bindings();
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
            unresolved.iter().any(|binding_id| {
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
    boot_id: &str,
) -> Result<EnvironmentDocument> {
    let roots = selected_roots(template)?;
    verify_recorded_exchanges(
        template.template().binding_plan().environment(),
        &roots,
        requests,
        responses,
        boot_id,
    )
}

fn verify_recorded_exchanges(
    sealed: &EnvironmentDocument,
    roots: &[&ProviderInventory],
    requests: &[RootObservationRequest],
    responses: &[RootObservationResult],
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
    environment_from_responses(sealed, responses, boot_id)
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
    };
    environment.freshness.generation = RevisionId(Sha256Digest::separated(
        "aos.ability.stage-root-inventory/v1",
        aos_contract::canonical::to_vec(&generation)?,
    ));
    if !responses.is_empty() {
        environment.freshness.max_age_millis = maximum_age_millis;
    }
    Ok(environment)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::document::{FreshnessCondition, ProviderState};
    use aos_ability_model::{AbilityValue, EnvironmentDocument, IncarnationId, RevisionId};
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::{
        InvocationControl, ROOT_OBSERVATION_REQUEST_SCHEMA, ROOT_OBSERVATION_RESULT_SCHEMA,
        RootObservationRequest, RootObservationResult,
    };

    use super::{environment_from_responses, verify_recorded_exchanges};

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
        let first = environment_from_responses(&sealed, &[observed.clone()], BOOT_A)
            .expect("first root inventory");
        let same = environment_from_responses(&sealed, &[observed.clone()], BOOT_A)
            .expect("same root inventory");
        assert_eq!(first, same);
        assert_eq!(first.providers[0].state, ProviderState::Available);
        assert_eq!(first.providers[1].state, ProviderState::Planned);
        assert_eq!(first.freshness.max_age_millis, 5000);
        assert!(environment_from_responses(&sealed, &[observed.clone()], BOOT_B).is_err());

        let mut next_boot_observation = observed.clone();
        next_boot_observation.boot_id = BOOT_B.to_string();
        let next_boot = environment_from_responses(&sealed, &[next_boot_observation], BOOT_B)
            .expect("next boot inventory");
        assert_ne!(first.freshness.generation, next_boot.freshness.generation);

        let mut changed = observed;
        changed.incarnation = Some(IncarnationId::new("manager-boot-b").expect("incarnation"));
        let next_assignment = environment_from_responses(&sealed, &[changed], BOOT_A)
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
            environment_from_responses(&sealed, &[observed.clone(), observed.clone()], BOOT_A)
                .is_err()
        );

        let mut unselected = observed;
        unselected.provider.key = "other".parse().expect("provider key");
        assert!(environment_from_responses(&sealed, &[unselected], BOOT_A).is_err());
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
            BOOT_A,
        )
        .expect("selected root exchange");
        assert!(verify_recorded_exchanges(&sealed, &roots, &[], &[], BOOT_A).is_err());

        let mut stale = response;
        stale.challenge = Sha256Digest::of_bytes(b"older challenge");
        assert!(verify_recorded_exchanges(&sealed, &roots, &[request], &[stale], BOOT_A).is_err());
    }
}
