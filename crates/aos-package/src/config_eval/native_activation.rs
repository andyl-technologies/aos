//! Production orchestration for structured native ability activation.
//!
//! The orchestrator holds the existing system switch lock across candidate
//! validation, configuration publication, native transaction execution, and
//! final activation evidence. It authenticates the desired and retained
//! generation inputs before the configuration commit. Failures after that
//! commit preserve the selected generation and surface as degraded activation.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, LocalKey, RequiredFeature, RevisionId, TransactionId, VersionedDocument,
};
use aos_ability_plan::{
    RUNTIME_OBSERVATIONS_SCHEMA, ResolutionPolicyDocument, TransitionReconciliation,
};
use aos_ability_runtime::adapter::{MonotonicClock, SystemMonotonicClock};
use aos_ability_runtime::execution::TerminalResult;
use aos_ability_runtime::journal::JournalLimits;
use aos_contract::Sha256Digest;

use super::ability::{AbilityEvaluationLimits, RestrictedAbilityEvaluator};
use super::ability_activation::{
    SpecializedAbilityActivation, VerifiedAbilityActivationInputs, specialize_activation,
    specialize_adoption_reconciliation, specialize_reconciliation, verify_generation_packages,
};
use super::ability_policy::{
    CurrentAuthorityScope, CurrentPlatformPolicyDocument, PublishingNativeAdmissionPolicy,
    validate_independent_binding_authority,
};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::ability_store::{
    NativeAbilitySession, NativeObservationSession, RetainedAbilityDiagnosticSource,
};
use super::activation::{ActivateConfigParams, ActivationFailure};
use super::materialize::ConfigManifest;
use super::native_boundary_observer::NativeExecutionBoundaryObserver;
use super::native_dispatch::{
    NativeDispatcher, NativeNoOpEvidence, OperatorAuthorizedPolicy, RetainedNativeNoOpVerifier,
    TrustedNativeNoOpVerifier,
};
use crate::config::ApmConfig;
use crate::types::ProfileScope;

const EVALUATOR_CACHE: &str = "/var/cache/aos-ability-evaluator";
const CURRENT_AUTHORITY_MAX_AGE_MILLIS: u64 = 60_000;
const SYSTEMD_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Activates one already parsed structured configuration manifest.
pub(super) fn activate_config(
    params: &ActivateConfigParams,
    desired_manifest: ConfigManifest,
) -> Result<u32> {
    ensure!(
        params.profile == ProfileScope::System.profile_path(),
        "structured native activation requires the canonical system profile"
    );
    let switch_lock = Arc::new(super::activation::acquire_switch_lock_pub(
        &params.switch_lock,
    )?);
    let transaction_manifest = crate::graph_compile::graph_transaction(&desired_manifest)
        .context("identifying the preflighted structured manifest")?
        .manifest;
    let pending = load_pending_activation(params)?;
    let failed = if pending.is_none() {
        load_failed_activation(params)?
    } else {
        None
    };
    if let Some((recovery, manifest)) = required_manifest_recovery(
        pending.as_ref().map(|pending| &pending.manifest),
        failed.as_ref().map(|failed| &failed.manifest),
        &desired_manifest,
    ) {
        let recovery_manifest = manifest.clone();
        drop(switch_lock);
        activate_config(params, recovery_manifest).with_context(|| match recovery {
            NativeManifestRecovery::Pending => {
                "pending native transaction must settle successfully before replacement"
            }
            NativeManifestRecovery::Failed => {
                "failed native manifest must recover successfully before replacement"
            }
        })?;
        return activate_config(params, desired_manifest);
    }
    let current_generation = match &pending {
        Some(pending) if pending.prior_generation != 0 => Some((
            pending.prior_generation,
            load_generation_manifest(params, pending.prior_generation)?,
        )),
        Some(_) => None,
        None if failed
            .as_ref()
            .is_some_and(|failed| failed.manifest == desired_manifest) =>
        {
            match failed.as_ref().map(|failed| failed.prior_generation) {
                Some(0) | None => None,
                Some(prior_generation) => Some((
                    prior_generation,
                    load_successful_generation_manifest(params, prior_generation)?,
                )),
            }
        }
        None => load_current_manifest(params)?,
    };
    let current_manifest = current_generation.as_ref().map(|(_, manifest)| manifest);
    let config = ApmConfig::load(ProfileScope::System)
        .context("loading system registry trust for native activation")?;
    let operator_authority = OperatorPolicyAuthorityStore::open()
        .context("opening operator policy authority for native activation")?;
    let desired_inputs =
        VerifiedAbilityActivationInputs::load(&desired_manifest, &operator_authority)
            .context("authenticating desired native activation inputs")?;
    let current_inputs = current_manifest
        .filter(|manifest| manifest.inputs.ability_activation.is_some())
        .map(|manifest| VerifiedAbilityActivationInputs::load(manifest, &operator_authority))
        .transpose()
        .context("authenticating retained native activation inputs")?;
    let manifests = current_manifest.map_or_else(
        || vec![&desired_manifest],
        |current| vec![&desired_manifest, current],
    );
    let packages = verify_generation_packages(&config, &manifests)
        .context("reverifying desired and retained native packages")?;
    let mut evaluator = production_evaluator()?;
    let source_activation = specialize_activation(
        &desired_inputs,
        current_inputs.as_ref(),
        &packages,
        &mut evaluator,
    )
    .context("specializing the structured native transition")?;
    NativeDispatcher::preflight(&source_activation, &packages)
        .context("preflighting every native activation route")?;
    let resolution_policy = resolution_policy(&desired_inputs, &source_activation)?;
    let platform_policy = desired_inputs.policy_set().platform_policy.clone();
    validate_independent_binding_authority(
        source_activation.plan(),
        &resolution_policy,
        platform_policy.as_ref(),
        desired_inputs.policy_set().transition_authority.as_ref(),
    )
    .context("checking source authority before native drift classification")?;
    let supported_features = supported_features()?;
    let receipt_resources =
        super::ability_store::inventory::provider_adoption_receipt_resources(&params.profile)?;
    let settled_failed_adoptions =
        super::ability_store::inventory::settled_failed_provider_adoption_resources(
            &params.profile,
            &supported_features,
        )?;
    let transaction = pending
        .as_ref()
        .map(|pending| pending.transaction.clone())
        .map_or_else(new_transaction_id, Ok)?;
    let activation = reconcile_native_drift(
        params,
        source_activation,
        current_generation
            .as_ref()
            .map(|(generation, _)| *generation),
        &desired_inputs,
        current_inputs.as_ref(),
        &packages,
        &mut evaluator,
        &operator_authority,
        &resolution_policy,
        platform_policy.as_ref(),
        &supported_features,
        &receipt_resources,
        &settled_failed_adoptions,
        &transaction,
        pending.as_ref(),
        Arc::clone(&switch_lock),
    )?;
    NativeDispatcher::preflight(&activation, &packages)
        .context("preflighting the selected native activation routes")?;
    validate_independent_binding_authority(
        activation.plan(),
        &resolution_policy,
        platform_policy.as_ref(),
        desired_inputs.policy_set().transition_authority.as_ref(),
    )
    .context("checking independent authority for every native binding")?;
    let linked_adoption_no_op = activation.plan().operations().is_empty()
        && activation
            .bundle()
            .reconciliation()
            .is_some_and(|reconciliation| !reconciliation.unsettled_provider_adoptions.is_empty());
    let retained_no_op = if activation.plan().operations().is_empty() && !linked_adoption_no_op {
        current_generation
            .as_ref()
            .map(|(generation, _)| {
                load_retained_no_op_source(params, *generation, supported_features.clone())
            })
            .transpose()?
    } else {
        None
    };

    let (generation, generation_id) = match pending {
        Some(pending) => (pending.generation, pending.generation_id),
        None => {
            let prior_generation = current_generation
                .as_ref()
                .map_or(0, |(generation, _)| *generation);
            let generation = commit_configuration(
                params,
                &desired_manifest,
                &transaction,
                prior_generation,
                &transaction_manifest,
            )
            .context("committing structured configuration generation")?;
            (generation, committed_generation_id(params, generation)?)
        }
    };
    let committed_manifest = super::activation::load_config_manifest(
        &params
            .profile
            .join(format!("gen-{generation}/manifest.json")),
    )
    .context("reloading committed structured manifest")?;
    if committed_manifest != desired_manifest {
        return Err(ActivationFailure::degraded(format!(
            "configuration generation {generation} differs from the committed preflight input"
        ))
        .into());
    }

    let execution = execute_native_transition(
        params,
        generation,
        transaction.clone(),
        activation,
        packages.clone(),
        &desired_inputs,
        &operator_authority,
        resolution_policy,
        platform_policy,
        supported_features,
        retained_no_op,
        Arc::clone(&switch_lock),
    );
    let terminal = match execution {
        Ok(terminal) => terminal,
        Err(error) => {
            return Err(ActivationFailure::degraded(format!(
                "configuration generation {generation} remains committed, but native ability activation failed: {error:#}"
            ))
            .into());
        }
    };
    if terminal == TerminalResult::SettledFailure {
        let failed = PendingActivation {
            generation,
            generation_id: generation_id.clone(),
            prior_generation: current_generation
                .as_ref()
                .map_or(0, |(generation, _)| *generation),
            transaction: transaction.clone(),
            transaction_manifest: transaction_manifest.clone(),
            manifest: desired_manifest.clone(),
        };
        publish_settled_native_failure(params, &failed)?;
        return Err(ActivationFailure::degraded(format!(
            "configuration generation {generation} reached a settled native ability failure"
        ))
        .into());
    }
    ensure!(
        terminal == TerminalResult::Succeeded,
        "native transaction reached unsupported terminal result {terminal:?}"
    );
    super::activation::publish_structured_activation_success(
        params,
        generation,
        &generation_id,
        &transaction_manifest,
        &transaction,
    )
    .map_err(|error| {
        ActivationFailure::degraded(format!(
            "native abilities converged for generation {generation}, but publishing final activation evidence failed: {error:#}"
        ))
    })?;
    Ok(generation)
}

fn commit_configuration(
    params: &ActivateConfigParams,
    manifest: &ConfigManifest,
    transaction: &TransactionId,
    prior_generation: u32,
    transaction_manifest: &str,
) -> Result<u32> {
    match super::activation::commit_structured_config_while_locked(
        params,
        manifest,
        transaction,
        prior_generation,
    ) {
        Ok(_) => bail!("structured configuration committed without native-pending evidence"),
        Err(error) => {
            let Some(failure) = error.downcast_ref::<ActivationFailure>() else {
                return Err(error);
            };
            if failure.exit_code() != 6 {
                return Err(error);
            }
            let state = crate::sysroot::recover_generation_state_pub(&params.profile)?;
            ensure!(
                state.current != 0,
                "degraded configuration commit did not select a current generation"
            );
            let generation = state.current;
            let generation_id = committed_generation_id(params, generation)?;
            let record_path = params
                .profile
                .join(format!("gen-{generation}/activation.json"));
            let record: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&record_path)
                    .with_context(|| format!("reading {}", record_path.display()))?,
            )
            .with_context(|| format!("parsing {}", record_path.display()))?;
            let status = record
                .get("status")
                .and_then(serde_json::Value::as_str)
                .context("structured configuration activation has no status")?;
            ensure!(
                record.get("schema").and_then(serde_json::Value::as_str)
                    == Some("aos.config-activation/v1")
                    && record.get("generation").and_then(serde_json::Value::as_u64)
                        == Some(u64::from(generation))
                    && record
                        .get("generation_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(generation_id.as_str())
                    && record
                        .get("transaction_manifest")
                        .and_then(serde_json::Value::as_str)
                        == Some(transaction_manifest)
                    && record
                        .get("activation_exit")
                        .and_then(serde_json::Value::as_i64)
                        == Some(6)
                    && record
                        .get("native_ability_transaction")
                        .and_then(serde_json::Value::as_str)
                        == Some(transaction.0.as_str())
                    && record
                        .get("native_ability_prior_generation")
                        .and_then(serde_json::Value::as_u64)
                        == Some(u64::from(prior_generation))
                    && matches!(status, "native-pending" | "degraded"),
                "degraded configuration commit differs from its structured recovery identity"
            );
            if status == "native-pending" {
                Ok(generation)
            } else {
                Err(error)
            }
        }
    }
}

fn committed_generation_id(params: &ActivateConfigParams, generation: u32) -> Result<String> {
    let state = crate::sysroot::recover_generation_state_pub(&params.profile)?;
    state
        .generations
        .iter()
        .find(|record| record.number == generation)
        .map(|record| record.manifest_hash.clone())
        .context("committed structured generation is absent from generation state")
}

struct PendingActivation {
    generation: u32,
    generation_id: String,
    prior_generation: u32,
    transaction: TransactionId,
    transaction_manifest: String,
    manifest: ConfigManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeManifestRecovery {
    Pending,
    Failed,
}

fn required_manifest_recovery<'a, T: Eq>(
    pending: Option<&'a T>,
    failed: Option<&'a T>,
    desired: &T,
) -> Option<(NativeManifestRecovery, &'a T)> {
    pending
        .filter(|manifest| *manifest != desired)
        .map(|manifest| (NativeManifestRecovery::Pending, manifest))
        .or_else(|| {
            failed
                .filter(|manifest| *manifest != desired)
                .map(|manifest| (NativeManifestRecovery::Failed, manifest))
        })
}

#[allow(clippy::too_many_arguments)]
fn reconcile_native_drift(
    params: &ActivateConfigParams,
    source: SpecializedAbilityActivation,
    current_generation: Option<u32>,
    desired_inputs: &VerifiedAbilityActivationInputs,
    current_inputs: Option<&VerifiedAbilityActivationInputs>,
    packages: &crate::ability_package::VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    operator_authority: &OperatorPolicyAuthorityStore,
    resolution_policy: &ResolutionPolicyDocument,
    platform_policy: Option<&CurrentPlatformPolicyDocument>,
    supported_features: &std::collections::BTreeSet<RequiredFeature>,
    receipt_resources: &std::collections::BTreeSet<aos_ability_model::ResourceId>,
    settled_failed_adoptions: &std::collections::BTreeSet<aos_ability_model::ResourceId>,
    transaction: &TransactionId,
    pending: Option<&PendingActivation>,
    switch_lock: Arc<super::activation::SwitchLockGuard>,
) -> Result<SpecializedAbilityActivation> {
    let (Some(current_generation), Some(current_inputs)) = (current_generation, current_inputs)
    else {
        ensure!(
            settled_failed_adoptions.is_empty(),
            "settled provider-adoption recovery has no authenticated current generation"
        );
        return Ok(source);
    };

    let activation_resources = source
        .desired_native_resources()
        .entries
        .iter()
        .chain(
            source
                .current_native_resources()
                .into_iter()
                .flat_map(|resources| &resources.entries),
        )
        .map(|mapping| mapping.resource.clone())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        receipt_resources.is_subset(&activation_resources),
        "native ownership ledger contains an adoption receipt outside the selected desired/current resources"
    );
    ensure!(
        settled_failed_adoptions.is_subset(&activation_resources),
        "settled provider-adoption receipt lies outside the selected desired/current resources"
    );

    let retained = pending
        .map(|pending| load_pending_reconciliation(params, pending, supported_features.clone()))
        .transpose()?
        .flatten();
    if let Some(reconciliation) = retained {
        ensure!(
            reconciliation.transaction == *transaction,
            "pending repair graph names another activation transaction"
        );
        source.reauthorize(operator_authority)?;
        // The retained v2 snapshot supplies exactly the original live
        // classification, while normal execution admission reobserves all
        // resources before any resumed effect.
        let linked_receipt_resources = reconciliation
            .unsettled_provider_adoptions
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            linked_receipt_resources.is_subset(&receipt_resources),
            "pending repair graph lost an unsettled provider-adoption receipt"
        );
        let repaired = if linked_receipt_resources.is_empty() {
            specialize_reconciliation(
                desired_inputs,
                current_inputs,
                packages,
                evaluator,
                &source,
                reconciliation,
                supported_features,
            )
        } else {
            specialize_adoption_reconciliation(
                desired_inputs,
                current_inputs,
                packages,
                evaluator,
                &source,
                reconciliation,
                supported_features,
                &linked_receipt_resources,
            )
        }
        .context("replaying the pending native repair graph")?;
        repaired
            .reauthorize(operator_authority)
            .context("reauthorizing operator policy after repair replay")?;
        return Ok(repaired);
    }
    if !source.plan().operations().is_empty() && settled_failed_adoptions.is_empty() {
        return Ok(source);
    }

    source
        .reauthorize(operator_authority)
        .context("reauthorizing operator policy before drift classification")?;
    let systemd = systemd_connection()?;
    let mut dispatcher = NativeDispatcher::new(&source, packages, systemd)
        .context("constructing the native drift classifier")?;
    let observation_session = NativeObservationSession::open(
        &params.profile.join(format!("gen-{current_generation}")),
        transaction.clone(),
        source.plan(),
        supported_features.clone(),
        switch_lock,
    )
    .context("opening the retained native observation boundary")?;
    let classification = dispatcher
        .classify_retained_resources(&observation_session, &settled_failed_adoptions)
        .context("classifying retained native resources")?;
    source
        .reauthorize(operator_authority)
        .context("reauthorizing operator policy after drift classification")?;
    if !classification.requires_reconciliation() {
        return Ok(source);
    }

    let policy_digest = Sha256Digest::parse(&desired_inputs.policy_sidecar().document_sha256)
        .context("decoding drift-classification operator policy fence")?;
    let scope = CurrentAuthorityScope {
        plan: source.plan().id(),
        transaction: transaction.clone(),
    };
    let mut current_policy = PublishingNativeAdmissionPolicy::new(
        &scope,
        RevisionId(policy_digest),
        resolution_policy.clone(),
        platform_policy.cloned(),
        desired_inputs.policy_set().transition_authority.clone(),
        supported_features.clone(),
        CURRENT_AUTHORITY_MAX_AGE_MILLIS,
        true,
    );
    let authority = current_policy
        .publish_authority(
            source.plan(),
            classification.assignments(),
            classification.authority_observations().to_vec(),
        )
        .context("publishing protected drift-classification authority")?;
    source
        .reauthorize(operator_authority)
        .context("reauthorizing operator policy before repair planning")?;
    let clock = SystemMonotonicClock::new();
    let age = clock
        .restart_stable_millis()
        .checked_sub(authority.observed_at_restart_millis)
        .context("drift-classification authority observation is in the future")?;
    ensure!(
        age <= authority.max_age_millis,
        "drift-classification authority expired before repair planning"
    );
    let reconciliation = TransitionReconciliation {
        schema: RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
        source_plan: source.plan().id(),
        transaction: transaction.clone(),
        policy_fence: authority.policy_fence,
        authority_epoch: authority.authority_epoch,
        sequence: authority.sequence,
        observed_at_restart_millis: authority.observed_at_restart_millis,
        max_age_millis: authority.max_age_millis,
        authority_publication: authority.content_digest()?,
        authority_document: AbilityValue::new(
            serde_json::to_value(&authority)
                .context("encoding protected drift-classification authority")?,
        )
        .context("bounding protected drift-classification authority")?,
        unsettled_provider_adoptions: settled_failed_adoptions.iter().cloned().collect(),
        observations: classification.runtime_observations().to_vec(),
    };
    let repaired = if settled_failed_adoptions.is_empty() {
        specialize_reconciliation(
            desired_inputs,
            current_inputs,
            packages,
            evaluator,
            &source,
            reconciliation,
            supported_features,
        )
    } else {
        specialize_adoption_reconciliation(
            desired_inputs,
            current_inputs,
            packages,
            evaluator,
            &source,
            reconciliation,
            supported_features,
            &settled_failed_adoptions,
        )
    }
    .context("constructing a linked native repair graph")?;
    repaired
        .reauthorize(operator_authority)
        .context("reauthorizing operator policy after repair planning")?;
    Ok(repaired)
}

fn load_pending_reconciliation(
    params: &ActivateConfigParams,
    pending: &PendingActivation,
    supported_features: std::collections::BTreeSet<RequiredFeature>,
) -> Result<Option<TransitionReconciliation>> {
    let generation = params.profile.join(format!("gen-{}", pending.generation));
    let transaction_dir = generation
        .join("ability-transactions")
        .join(pending.transaction.0.as_str());
    match std::fs::symlink_metadata(&transaction_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", transaction_dir.display()));
        }
        Ok(_) => {}
    }
    let source =
        RetainedAbilityDiagnosticSource::load(generation, &pending.transaction, supported_features)
            .context("loading pending native repair provenance")?;
    Ok(source.reconciliation().cloned())
}

fn load_pending_activation(params: &ActivateConfigParams) -> Result<Option<PendingActivation>> {
    load_selected_native_activation(params, "native-pending")
}

fn load_failed_activation(params: &ActivateConfigParams) -> Result<Option<PendingActivation>> {
    load_selected_native_activation(params, "native-failed")
}

fn load_selected_native_activation(
    params: &ActivateConfigParams,
    expected_status: &str,
) -> Result<Option<PendingActivation>> {
    let state = crate::sysroot::recover_generation_state_pub(&params.profile)?;
    if state.current == 0 {
        return Ok(None);
    }
    let generation_id = committed_generation_id(params, state.current)?;
    let generation_dir = params.profile.join(format!("gen-{}", state.current));
    let record_path = generation_dir.join("activation.json");
    let record: serde_json::Value = match std::fs::read(&record_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", record_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", record_path.display()));
        }
    };
    if record.get("status").and_then(serde_json::Value::as_str) != Some(expected_status) {
        return Ok(None);
    }
    ensure!(
        record.get("schema").and_then(serde_json::Value::as_str)
            == Some("aos.config-activation/v1")
            && record.get("generation").and_then(serde_json::Value::as_u64)
                == Some(u64::from(state.current))
            && record
                .get("generation_id")
                .and_then(serde_json::Value::as_str)
                == Some(generation_id.as_str()),
        "selected native activation differs from its generation identity"
    );
    let manifest = load_generation_manifest(params, state.current)?;
    let transaction_manifest = crate::graph_compile::graph_transaction(&manifest)?.manifest;
    ensure!(
        record
            .get("transaction_manifest")
            .and_then(serde_json::Value::as_str)
            == Some(transaction_manifest.as_str()),
        "selected native activation differs from its retained manifest identity"
    );
    let transaction = serde_json::from_value(
        record
            .get("native_ability_transaction")
            .cloned()
            .context("selected native activation has no transaction")?,
    )
    .context("decoding selected native transaction")?;
    let prior_generation_u64 = record
        .get("native_ability_prior_generation")
        .and_then(serde_json::Value::as_u64)
        .context("selected native activation has no prior generation")?;
    let prior_generation = u32::try_from(prior_generation_u64)
        .context("selected native prior generation exceeds u32")?;
    ensure!(
        prior_generation == 0
            || state
                .generations
                .iter()
                .any(|generation| generation.number == prior_generation),
        "selected native activation prior generation is not retained"
    );
    Ok(Some(PendingActivation {
        generation: state.current,
        generation_id,
        prior_generation,
        transaction,
        transaction_manifest,
        manifest,
    }))
}

fn publish_settled_native_failure(
    params: &ActivateConfigParams,
    pending: &PendingActivation,
) -> Result<()> {
    super::activation::publish_structured_activation_settled_failure(
        params,
        pending.generation,
        &pending.generation_id,
        &pending.transaction_manifest,
        &pending.transaction,
    )
}

fn execute_native_transition(
    params: &ActivateConfigParams,
    generation: u32,
    transaction: TransactionId,
    activation: SpecializedAbilityActivation,
    packages: crate::ability_package::VerifiedAbilityPackageSet,
    desired_inputs: &VerifiedAbilityActivationInputs,
    operator_authority: &OperatorPolicyAuthorityStore,
    resolution_policy: ResolutionPolicyDocument,
    platform_policy: Option<CurrentPlatformPolicyDocument>,
    supported_features: std::collections::BTreeSet<RequiredFeature>,
    retained_no_op: Option<RetainedAbilityDiagnosticSource>,
    switch_lock: Arc<super::activation::SwitchLockGuard>,
) -> Result<TerminalResult> {
    let cancellation = super::native_cancellation::NativeCancellationGuard::install()
        .context("installing native activation cancellation listeners")?;
    let systemd = systemd_connection()?;
    let mut dispatcher = NativeDispatcher::new(&activation, &packages, systemd)
        .context("constructing native dispatcher")?;
    let mut session = NativeAbilitySession::open_with_switch_lock(
        activation.plan(),
        transaction.clone(),
        JournalLimits::default(),
        params.profile.join(format!("gen-{generation}")),
        supported_features.clone(),
        activation.bundle().clone(),
        packages.clone(),
        switch_lock,
    )
    .context("opening generation-bound native transaction")?;
    let policy_digest = Sha256Digest::parse(&desired_inputs.policy_sidecar().document_sha256)
        .context("decoding operator-authorized policy fence")?;
    let scope = CurrentAuthorityScope {
        plan: activation.plan().id(),
        transaction,
    };
    let transaction_linked = activation.bundle().reconciliation().is_some();
    let retained_consumer_features = supported_features.clone();
    let current_policy = PublishingNativeAdmissionPolicy::new(
        &scope,
        RevisionId(policy_digest),
        resolution_policy,
        platform_policy,
        desired_inputs.policy_set().transition_authority.clone(),
        supported_features,
        CURRENT_AUTHORITY_MAX_AGE_MILLIS,
        transaction_linked,
    );
    let mut policy = OperatorAuthorizedPolicy::new(&activation, operator_authority, current_policy);
    let mut no_op_verifier = ProductionNoOpVerifier {
        retained: retained_no_op.map(|source| {
            RetainedNativeNoOpVerifier::new(
                source,
                JournalLimits::default(),
                retained_consumer_features,
            )
        }),
    };
    let mut boundary_observer = NativeExecutionBoundaryObserver::load()
        .context("opening protected native execution observation channel")?;
    let terminal = dispatcher.run_to_terminal_with_observer(
        &mut session,
        &mut policy,
        &mut no_op_verifier,
        cancellation.token(),
        &mut boundary_observer,
    )?;
    Ok(terminal)
}

fn load_current_manifest(params: &ActivateConfigParams) -> Result<Option<(u32, ConfigManifest)>> {
    let state = crate::sysroot::recover_generation_state_pub(&params.profile)?;
    if state.current == 0 {
        return Ok(None);
    }
    let record = state
        .generations
        .iter()
        .find(|generation| generation.number == state.current)
        .context("current generation is absent from system generation state")?;
    let manifest = load_generation_manifest(params, record.number)?;
    Ok(Some((state.current, manifest)))
}

fn load_generation_manifest(
    params: &ActivateConfigParams,
    generation: u32,
) -> Result<ConfigManifest> {
    let state = crate::sysroot::recover_generation_state_pub(&params.profile)?;
    let record = state
        .generations
        .iter()
        .find(|record| record.number == generation)
        .context("selected generation is absent from system generation state")?;
    let path = params
        .profile
        .join(format!("gen-{generation}/manifest.json"));
    let manifest = super::activation::load_config_manifest(&path)?;
    let value = serde_json::to_value(&manifest).context("encoding retained config manifest")?;
    ensure!(
        crate::graph_compile::reproject::hash_cjson(&value) == record.manifest_hash,
        "retained current manifest differs from its generation identity"
    );
    Ok(manifest)
}

fn load_successful_generation_manifest(
    params: &ActivateConfigParams,
    generation: u32,
) -> Result<ConfigManifest> {
    let generation_id = committed_generation_id(params, generation)?;
    let record_path = params
        .profile
        .join(format!("gen-{generation}/activation.json"));
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&record_path)
            .with_context(|| format!("reading {}", record_path.display()))?,
    )
    .with_context(|| format!("parsing {}", record_path.display()))?;
    ensure!(
        record.get("schema").and_then(serde_json::Value::as_str)
            == Some("aos.config-activation/v1")
            && record.get("generation").and_then(serde_json::Value::as_u64)
                == Some(u64::from(generation))
            && record
                .get("generation_id")
                .and_then(serde_json::Value::as_str)
                == Some(generation_id.as_str())
            && record.get("status").and_then(serde_json::Value::as_str) == Some("complete")
            && record
                .get("activation_exit")
                .and_then(serde_json::Value::as_i64)
                == Some(0),
        "failed native activation does not name a complete prior generation"
    );
    load_generation_manifest(params, generation)
}

fn load_retained_no_op_source(
    params: &ActivateConfigParams,
    generation: u32,
    supported_features: std::collections::BTreeSet<RequiredFeature>,
) -> Result<RetainedAbilityDiagnosticSource> {
    let generation_dir = params.profile.join(format!("gen-{generation}"));
    let record_path = generation_dir.join("activation.json");
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&record_path)
            .with_context(|| format!("reading {}", record_path.display()))?,
    )
    .with_context(|| format!("parsing {}", record_path.display()))?;
    ensure!(
        record.get("schema").and_then(serde_json::Value::as_str)
            == Some("aos.config-activation/v1")
            && record.get("generation").and_then(serde_json::Value::as_u64)
                == Some(u64::from(generation))
            && record.get("status").and_then(serde_json::Value::as_str) == Some("complete"),
        "retained generation lacks complete native activation evidence"
    );
    let transaction: TransactionId = serde_json::from_value(
        record
            .get("native_ability_transaction")
            .cloned()
            .context("retained generation has no selected native transaction")?,
    )
    .context("decoding retained native transaction selection")?;
    RetainedAbilityDiagnosticSource::load(generation_dir, &transaction, supported_features)
        .context("loading selected retained native transaction")
}

fn production_evaluator() -> Result<RestrictedAbilityEvaluator> {
    let nix_instantiate = std::env::var("AOS_NIX_INSTANTIATE")
        .context("reading AOS_NIX_INSTANTIATE for native activation")?;
    let prlimit =
        std::env::var("AOS_PRLIMIT").context("reading AOS_PRLIMIT for native activation")?;
    RestrictedAbilityEvaluator::new(
        nix_instantiate,
        prlimit,
        Path::new(EVALUATOR_CACHE),
        AbilityEvaluationLimits::default(),
    )
}

fn supported_features() -> Result<std::collections::BTreeSet<RequiredFeature>> {
    [
        crate::types::FEATURE_ABILITIES_V1,
        crate::types::FEATURE_ABILITY_EFFECTS_V1,
        "native-platform-policy-v1",
        "native-resource-map-v2",
        aos_ability_model::PROVIDER_STATE_FORMAT_V1,
        aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
    ]
    .into_iter()
    .map(RequiredFeature::new)
    .collect::<std::result::Result<_, _>>()
    .context("constructing native runtime implementation feature set")
}

fn resolution_policy(
    inputs: &VerifiedAbilityActivationInputs,
    activation: &SpecializedAbilityActivation,
) -> Result<ResolutionPolicyDocument> {
    let binding = activation.plan().binding_plan().document();
    let matching = inputs
        .policy_set()
        .policies
        .iter()
        .filter(|policy| {
            policy.desired_state == binding.desired_state
                && policy.environment == binding.environment
                && policy.policy_revision == binding.policy_revision
        })
        .collect::<Vec<_>>();
    let [policy] = matching.as_slice() else {
        bail!(
            "checked native binding plan does not select exactly one authenticated resolution policy"
        );
    };
    Ok((*policy).clone())
}

fn systemd_connection() -> Result<Arc<aos_systemd::SystemdManagerConnection>> {
    let runtime = tokio::runtime::Handle::try_current()
        .context("native activation requires a Tokio runtime")?;
    ensure!(
        runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread,
        "native activation requires a multi-thread Tokio runtime"
    );
    let connection = tokio::task::block_in_place(|| {
        runtime.block_on(async {
            tokio::time::timeout(
                SYSTEMD_CONNECT_TIMEOUT,
                aos_systemd::SystemdManagerConnection::system(),
            )
            .await
        })
    })
    .context("timing out while connecting to systemd")?
    .context("connecting to the host systemd manager")?;
    Ok(Arc::new(connection))
}

fn new_transaction_id() -> Result<TransactionId> {
    let random = rand::random::<u128>();
    let key = LocalKey::new(format!("activation-{random:032x}"))
        .context("constructing native activation transaction identity")?;
    Ok(TransactionId(key))
}

struct ProductionNoOpVerifier {
    retained: Option<RetainedNativeNoOpVerifier>,
}

impl TrustedNativeNoOpVerifier for ProductionNoOpVerifier {
    fn verify_no_op(&mut self, evidence: NativeNoOpEvidence<'_>) -> Result<()> {
        ensure!(
            evidence.plan.operations().is_empty()
                && evidence.desired_state == evidence.current_desired_state
                && evidence.current_resources.desired_state
                    == evidence.desired_state.content_digest()?
                && evidence.resources.len() == evidence.current_resources.entries.len(),
            "native no-op evidence differs from the retained desired state"
        );
        ensure!(
            evidence.current_resources.entries.iter().all(|mapping| {
                let provider = evidence
                    .plan
                    .binding_plan()
                    .binding(&mapping.binding)
                    .map(|binding| &binding.provider)
                    .or_else(|| {
                        evidence
                            .plan
                            .binding_plan()
                            .bindings()
                            .iter()
                            .find_map(|binding| {
                                matches!(
                                    evidence.plan.binding_plan().binding_authority(&binding.id),
                                    Some(aos_ability_validate::BindingAuthorityKind::Teardown {
                                        source_binding,
                                        ..
                                    }) if source_binding == &mapping.binding
                                )
                                .then_some(&binding.provider)
                            })
                    });
                evidence
                    .assignments
                    .iter()
                    .any(|assignment| Some(&assignment.provider) == provider)
            }),
            "native no-op evidence lacks a live assignment for a retained resource"
        );
        ensure!(
            !evidence.transaction.0.as_str().is_empty(),
            "native no-op transaction identity is empty"
        );
        self.retained
            .as_mut()
            .context("empty native transition has no selected retained transaction evidence")?
            .verify_no_op(evidence)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[test]
    fn a_different_manifest_cannot_bypass_pending_or_failed_recovery() {
        let failed_manifest = "B removes the owned resource";
        let later_manifest = "C also omits it and changes another resource";

        assert_eq!(
            super::required_manifest_recovery(None, Some(&failed_manifest), &later_manifest,),
            Some((super::NativeManifestRecovery::Failed, &failed_manifest))
        );
        assert_eq!(
            super::required_manifest_recovery(Some(&failed_manifest), None, &later_manifest,),
            Some((super::NativeManifestRecovery::Pending, &failed_manifest))
        );
        assert_eq!(
            super::required_manifest_recovery(None, Some(&failed_manifest), &failed_manifest),
            None
        );
    }

    #[test]
    fn activation_owner_retains_switch_lock_through_final_publication() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let lock_path = directory.path().join("switch.lock");
        let owner = Arc::new(
            super::super::activation::acquire_switch_lock_pub(&lock_path)
                .expect("activation owner acquires switch lock"),
        );

        let execution_owner = Arc::clone(&owner);
        drop(execution_owner);
        let (entered_tx, entered_rx) = mpsc::channel();
        let contender_path = lock_path.clone();
        let contender = std::thread::spawn(move || {
            let entered =
                super::super::activation::acquire_switch_lock_pub(&contender_path).is_ok();
            entered_tx.send(entered).expect("report contender entry");
        });

        assert!(
            !entered_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender reports lock result"),
            "a concurrent switch entered before final activation publication"
        );
        contender.join().expect("contender thread succeeds");
        drop(owner);
        let _next = super::super::activation::acquire_switch_lock_pub(&lock_path)
            .expect("next switch enters after final publication releases owner");
    }
}
