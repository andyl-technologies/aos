//! Production orchestration for structured native ability activation.
//!
//! The orchestrator holds the existing system switch lock across candidate
//! validation, configuration publication, native transaction execution, and
//! final activation evidence. It authenticates the desired and retained
//! generation inputs before the configuration commit. Failures after that
//! commit preserve the selected generation and surface as degraded activation.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{LocalKey, RequiredFeature, RevisionId, TransactionId};
use aos_ability_plan::{ResolutionPolicyDocument, TransitionReconciliation};
use aos_ability_runtime::execution::TerminalResult;
use aos_ability_runtime::journal::JournalLimits;
use aos_contract::Sha256Digest;

use super::ability::{AbilityEvaluationLimits, RestrictedAbilityEvaluator};
use super::ability_activation::{
    SpecializedAbilityActivation, VerifiedAbilityActivationInputs, specialize_activation,
    specialize_reconciliation, verify_generation_packages,
};
use super::ability_policy::{
    CurrentAuthorityScope, CurrentPlatformPolicyDocument, PublishingNativeAdmissionPolicy,
    validate_independent_binding_authority,
};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::activation::{ActivateConfigParams, ActivationFailure};
use super::execution_observer::AbilityExecutionBoundaryObserver;
use super::handler_dispatch::HandlerDispatcher;
use super::materialize::ConfigManifest;
use super::transaction_store::{AbilityTransactionSession, RetainedAbilityDiagnosticSource};
use crate::config::ApmConfig;
use crate::sysroot::image_rollout::authenticate_single_image_rollout_fragment;
use crate::types::ProfileScope;

const EVALUATOR_CACHE: &str = "/var/cache/aos-ability-evaluator";
const CURRENT_AUTHORITY_MAX_AGE_MILLIS: u64 = 60_000;

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
    HandlerDispatcher::preflight(&source_activation, &packages)
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
    let supported_features = supported_native_ability_features()?;
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
        &transaction,
        pending.as_ref(),
        Arc::clone(&switch_lock),
    )?;
    HandlerDispatcher::preflight(&activation, &packages)
        .context("preflighting the selected native activation routes")?;
    validate_independent_binding_authority(
        activation.plan(),
        &resolution_policy,
        platform_policy.as_ref(),
        desired_inputs.policy_set().transition_authority.as_ref(),
    )
    .context("checking independent authority for every native binding")?;
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

/// Authenticates and preflights a retained structured manifest without effects.
///
/// This probe reopens current operator policy, verifies desired and current
/// package artifacts, specializes the complete transition, validates every
/// native route, and opens the scoped host manager capability. It does not
/// publish a generation, journal event, observation, or resource mutation.
///
/// # Errors
///
/// Returns an error when retained inputs, current authority, packages, binding
/// policy, native routes, or the host provider capability cannot be verified.
pub(crate) fn preflight_retained_manifest(
    params: &ActivateConfigParams,
    desired_manifest: &ConfigManifest,
) -> std::result::Result<(), RetainedNativePreflightError> {
    let config = ApmConfig::load(ProfileScope::System)
        .context("loading system registry trust for retained activation")
        .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    let operator_authority = OperatorPolicyAuthorityStore::open()
        .context("opening current operator policy authority")
        .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    let desired_inputs =
        VerifiedAbilityActivationInputs::load(desired_manifest, &operator_authority)
            .context("authenticating retained desired ability inputs")
            .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    let current_manifest =
        crate::sysroot::authenticated_current_generation_manifest(&params.profile)
            .map_err(RetainedNativePreflightError::Artifact)?
            .map(|path| super::activation::load_config_manifest(&path))
            .transpose()
            .context("loading the authenticated current ability manifest")
            .map_err(RetainedNativePreflightError::Artifact)?;
    let current_inputs = current_manifest
        .as_ref()
        .filter(|manifest| manifest.inputs.ability_activation.is_some())
        .map(|manifest| VerifiedAbilityActivationInputs::load(manifest, &operator_authority))
        .transpose()
        .context("authenticating current ability inputs")
        .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    let manifests = current_manifest.as_ref().map_or_else(
        || vec![desired_manifest],
        |current| vec![desired_manifest, current],
    );
    let packages = verify_generation_packages(&config, &manifests)
        .context("reverifying retained and current native packages")
        .map_err(RetainedNativePreflightError::Artifact)?;
    let mut evaluator = production_evaluator().map_err(RetainedNativePreflightError::Provider)?;
    let activation = specialize_activation(
        &desired_inputs,
        current_inputs.as_ref(),
        &packages,
        &mut evaluator,
    )
    .context("specializing retained native transition")
    .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    HandlerDispatcher::preflight(&activation, &packages)
        .context("preflighting retained package handler routes")
        .map_err(RetainedNativePreflightError::Provider)?;
    let resolution_policy = resolution_policy(&desired_inputs, &activation)
        .map_err(RetainedNativePreflightError::CurrentAuthority)?;
    validate_independent_binding_authority(
        activation.plan(),
        &resolution_policy,
        desired_inputs.policy_set().platform_policy.as_ref(),
        desired_inputs.policy_set().transition_authority.as_ref(),
    )
    .context("checking current authority for retained native bindings")
    .map_err(RetainedNativePreflightError::CurrentAuthority)?;

    HandlerDispatcher::new(&activation, &packages)
        .context("binding retained activation to authenticated package handlers")
        .map_err(RetainedNativePreflightError::Provider)?;
    Ok(())
}

/// Classifies a retained native preflight failure by failed trust boundary.
#[derive(Debug)]
pub(crate) enum RetainedNativePreflightError {
    /// Current registry or operator authority rejected the retained input.
    CurrentAuthority(anyhow::Error),
    /// A retained package, manifest, or implementation artifact failed authentication.
    Artifact(anyhow::Error),
    /// The exact provider route or scoped live manager could not be acquired.
    Provider(anyhow::Error),
}

impl std::fmt::Display for RetainedNativePreflightError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentAuthority(error) => write!(
                formatter,
                "current activation authority rejected the retained target: {error:#}"
            ),
            Self::Artifact(error) => write!(
                formatter,
                "retained activation artifact is unavailable: {error:#}"
            ),
            Self::Provider(error) => write!(
                formatter,
                "retained activation provider is unavailable: {error:#}"
            ),
        }
    }
}

impl std::error::Error for RetainedNativePreflightError {}

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
    _current_generation: Option<u32>,
    desired_inputs: &VerifiedAbilityActivationInputs,
    current_inputs: Option<&VerifiedAbilityActivationInputs>,
    packages: &crate::ability_package::VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    operator_authority: &OperatorPolicyAuthorityStore,
    _resolution_policy: &ResolutionPolicyDocument,
    _platform_policy: Option<&CurrentPlatformPolicyDocument>,
    supported_features: &std::collections::BTreeSet<RequiredFeature>,
    transaction: &TransactionId,
    pending: Option<&PendingActivation>,
    _switch_lock: Arc<super::activation::SwitchLockGuard>,
) -> Result<SpecializedAbilityActivation> {
    let retained = pending
        .map(|pending| load_pending_reconciliation(params, pending, supported_features.clone()))
        .transpose()?
        .flatten();
    if let Some(reconciliation) = retained {
        let current_inputs = current_inputs
            .context("pending package-handler recovery has no authenticated current generation")?;
        ensure!(
            reconciliation.transaction == *transaction,
            "pending repair graph names another activation transaction"
        );
        source.reauthorize(operator_authority)?;

        let repaired = specialize_reconciliation(
            desired_inputs,
            current_inputs,
            packages,
            evaluator,
            &source,
            reconciliation,
            supported_features,
        )
        .context("replaying the pending ability repair graph")?;
        repaired
            .reauthorize(operator_authority)
            .context("reauthorizing operator policy after repair replay")?;
        return Ok(repaired);
    }

    Ok(source)
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
    switch_lock: Arc<super::activation::SwitchLockGuard>,
) -> Result<TerminalResult> {
    let cancellation = super::cancellation::AbilityCancellationGuard::install()
        .context("installing native activation cancellation listeners")?;
    let dispatcher = HandlerDispatcher::new(&activation, &packages)
        .context("constructing package handler dispatcher")?;
    let mut session = AbilityTransactionSession::open_with_switch_lock(
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
    let mut boundary_observer = AbilityExecutionBoundaryObserver::load()
        .context("opening protected native execution observation channel")?;
    let terminal = dispatcher.run_to_terminal(
        &mut session,
        operator_authority,
        current_policy,
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

/// Returns the semantic feature set implemented by the native runtime.
///
/// Retained plan-bundle consumers use this same set so offline replay cannot
/// accept semantics that the activation path would reject.
///
/// # Errors
///
/// Returns an error if a built-in feature name violates the bounded feature
/// identity contract.
pub fn supported_native_ability_features() -> Result<std::collections::BTreeSet<RequiredFeature>> {
    [
        crate::types::FEATURE_ABILITIES_V1,
        crate::types::FEATURE_ABILITY_EFFECTS_V1,
        "native-platform-policy-v1",
        "native-resource-map-v1",
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

fn new_transaction_id() -> Result<TransactionId> {
    let random = rand::random::<u128>();
    let key = LocalKey::new(format!("activation-{random:032x}"))
        .context("constructing native activation transaction identity")?;
    Ok(TransactionId(key))
}

/// Verifies the exact successful native rollout transaction before boot commit.
///
/// # Errors
///
/// Returns an error when the retained plan or journal is invalid, the
/// transaction did not settle successfully, its rollout requests differ, or
/// provider-owned health evidence does not authorize the running image.
pub(crate) fn verify_rollout_boot_commit(
    generation: u32,
    transaction: &TransactionId,
    running: u32,
) -> Result<()> {
    let generation = ProfileScope::System
        .profile_path()
        .join(format!("gen-{generation}"));
    let source = RetainedAbilityDiagnosticSource::load(
        generation,
        transaction,
        supported_native_ability_features()?,
    )
    .context("authenticating retained rollout transaction")?;
    let request = authenticate_single_image_rollout_fragment(source.plan())
        .context("authenticating the retained rollout fragment")?;
    ensure!(
        source.terminal_result(JournalLimits::default())? == Some(TerminalResult::Succeeded),
        "native rollout transaction did not settle successfully"
    );
    crate::sysroot::image_rollout::NativeAbRolloutBackend::new("/var/lib/profiles/image", "/boot")
        .verify_boot_commit(&request, running)
        .context("verifying provider-owned rollout health evidence")
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
