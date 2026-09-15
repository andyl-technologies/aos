//! Hermetic build-stage resolution of an authenticated ability fixed point.
//!
//! The adapter accepts only existing canonical planning documents, resolved
//! package companions, and a data-only Nix intent module. It replays the
//! approved planning snapshot, resolves selected provider modules through
//! those exact package documents, and runs the same bounded stock-Nix rounds
//! as the live evaluator. Its output contains no pending requests and can be
//! consumed by package-owned static materializers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    EnvironmentId, ExecutionStage, InterfaceDocument, LocalKey, PackageDocument,
};
use aos_ability_plan::{
    PlanningReplayInputs, PlanningSnapshot, TransitionInputs, TransitionPlanner,
};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_validate::PackageOutputSelector;
use aos_ability_validate::build_frontend::ResolvedPackageOutput;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ability_activation::{ActivationDesiredInputDocument, AuthenticatedPolicySetDocument};
use super::ability_rounds::resolve_ability_rounds;
use super::stock::{StockAbilityRoundEvaluator, StockAbilityRoundResolver, StockNixEvaluator};
use super::{EvalAttempt, PackageOutputs, WorkingSetMember};
use crate::package_contract::VerifiedPackagePlanningCatalog;

const BUILD_STAGE_SPEC_SCHEMA: &str = "aos.ability.build-stage-resolution/v1";
const BUILD_STAGE_PLAN_SCHEMA: &str = "aos.ability.build-stage-plan/v1";
const BUILD_STAGE_OUTPUT_SCHEMA: &str = "aos.ability.resolved-stage/v1";
const MAXIMUM_SPEC_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStagePlanningSpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    desired_input: PathBuf,
    authenticated_policy_set: PathBuf,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStageResolutionSpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    base_lib: PathBuf,
    intent_module: PathBuf,
    desired_input: PathBuf,
    authenticated_policy_set: PathBuf,
    planning_artifact: PathBuf,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStagePlanManifest {
    schema: String,
    environment: aos_ability_model::EnvironmentId,
    planning_snapshot: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedBuildStage {
    schema: String,
    environment: EnvironmentId,
    planning_snapshot: Sha256Digest,
    fixed_point: super::ability_rounds::AbilityFixedPointProjection,
    plan_bundle: ReloadablePlanBundle,
}

/// Carries one fully replayed build-stage execution selection.
pub(super) struct CheckedResolvedBuildStage {
    /// Identifies the exact stage environment selected by the parent system.
    pub(super) environment: EnvironmentId,
    /// Carries the structurally replayed checked effect plan.
    pub(super) plan: aos_ability_validate::CheckedEffectPlan,
    /// Retains the canonical bundle used for durable transaction recovery.
    pub(super) bundle: ReloadablePlanBundle,
    /// Carries the fixed point bound to the replayed desired planning state.
    pub(super) fixed_point: super::ability_rounds::AbilityFixedPointProjection,
}

/// Plans one build-stage graph from authenticated package and policy inputs.
///
/// # Errors
///
/// Returns an error when the adapter input is noncanonical, a package source or
/// policy is invalid, the target environment differs, or bounded composition
/// cannot produce one checked planning snapshot.
pub fn plan_build_stage(spec_path: &Path, output_path: &Path) -> Result<()> {
    let spec: BuildStagePlanningSpec =
        read_canonical(spec_path, "build-stage planning specification")?;
    validate_planning_spec(&spec)?;

    let desired: ActivationDesiredInputDocument =
        read_canonical(&spec.desired_input, "build-stage desired input")?;
    desired.validate()?;
    let policies: AuthenticatedPolicySetDocument = read_canonical(
        &spec.authenticated_policy_set,
        "build-stage authenticated policy set",
    )?;
    policies.validate(&desired)?;
    validate_environment(&desired, spec.stage, &spec.authority, &spec.key)?;

    let LoadedPackages { documents, .. } = load_packages(&spec.packages)?;
    let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(documents)?;
    let mut composition_evaluator = super::native_activation::production_evaluator()?;
    let outcome = catalog.composer().compose(
        &policies.policies,
        desired.seed.clone(),
        desired.environment.clone(),
        catalog.packages().to_vec(),
        &mut composition_evaluator,
    )?;
    let snapshot = PlanningSnapshot::from_outcome(&outcome)?;
    let expected_digest = snapshot.digest()?;
    snapshot.verify_structure(
        &catalog.composer(),
        PlanningReplayInputs {
            expected_digest,
            authenticated_policies: &policies.policies,
            seed: desired.seed.clone(),
            environment: desired.environment.clone(),
            packages: catalog.packages().to_vec(),
        },
    )?;

    let snapshot_bytes = snapshot.canonical_bytes()?;
    let manifest = BuildStagePlanManifest {
        schema: BUILD_STAGE_PLAN_SCHEMA.to_string(),
        environment: desired.environment.environment.clone(),
        planning_snapshot: expected_digest,
    };
    let manifest_bytes =
        aos_contract::canonical::to_vec(&manifest).context("encoding build-stage plan manifest")?;
    fs::create_dir_all(output_path)
        .with_context(|| format!("creating build-stage plan output {}", output_path.display()))?;
    fs::write(output_path.join("snapshot.json"), snapshot_bytes)
        .context("writing retained build-stage planning snapshot")?;
    fs::write(output_path.join("manifest.json"), manifest_bytes)
        .context("writing retained build-stage plan manifest")
}

/// Resolves one checked stage graph and writes its canonical build projection.
///
/// # Errors
///
/// Returns an error when the adapter specification or any existing planning
/// document is noncanonical, a package companion is malformed, planning replay
/// differs, provider selection is inexact, Nix evaluation fails, or the final
/// fixed point differs from the checked binding plan.
pub fn resolve_build_stage(spec_path: &Path, output_path: &Path, eval_root: &Path) -> Result<()> {
    let spec: BuildStageResolutionSpec = read_canonical(spec_path, "build-stage specification")?;
    validate_spec(&spec)?;

    let desired: ActivationDesiredInputDocument =
        read_canonical(&spec.desired_input, "build-stage desired input")?;
    desired.validate()?;
    let policies: AuthenticatedPolicySetDocument = read_canonical(
        &spec.authenticated_policy_set,
        "build-stage authenticated policy set",
    )?;
    policies.validate(&desired)?;
    let plan_manifest: BuildStagePlanManifest = read_canonical(
        &spec.planning_artifact.join("manifest.json"),
        "build-stage plan manifest",
    )?;
    ensure!(
        plan_manifest.schema == BUILD_STAGE_PLAN_SCHEMA,
        "unsupported build-stage plan manifest schema"
    );
    let planning_bytes = read_bounded(
        &spec.planning_artifact.join("snapshot.json"),
        "build-stage planning snapshot",
    )?;
    let planning = PlanningSnapshot::decode(&planning_bytes)
        .context("decoding build-stage planning snapshot")?;
    let planning_snapshot_digest = plan_manifest.planning_snapshot;
    ensure!(
        planning.digest()? == planning_snapshot_digest,
        "build-stage planning snapshot differs from its retained commitment"
    );

    let LoadedPackages {
        working_set,
        documents,
        artifact_locators,
    } = load_packages(&spec.packages)?;
    let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(documents)?;
    let mut composition_evaluator = super::native_activation::production_evaluator()?;
    let verified = planning.replay_with(
        &catalog.composer(),
        PlanningReplayInputs {
            expected_digest: planning_snapshot_digest,
            authenticated_policies: &policies.policies,
            seed: desired.seed.clone(),
            environment: desired.environment.clone(),
            packages: catalog.packages().to_vec(),
        },
        &mut composition_evaluator,
    )?;

    validate_environment(&desired, spec.stage, &spec.authority, &spec.key)?;
    ensure!(
        plan_manifest.environment == desired.environment.environment,
        "build-stage plan manifest names a different environment"
    );

    let evaluator = StockNixEvaluator::new(eval_root, 0);
    let attempt = EvalAttempt {
        host_nix: &spec.intent_module,
        runtime_modules: &[],
        base_lib: &spec.base_lib,
        facts_json: None,
        working_set: &working_set,
        iteration: 0,
    };
    let round_evaluator = StockAbilityRoundEvaluator::for_build_stage(
        &evaluator,
        attempt,
        stage_name(spec.stage),
        spec.authority.as_str(),
        spec.key.as_str(),
    );
    let round_resolver =
        StockAbilityRoundResolver::for_build_stage(&working_set, &verified, &artifact_locators);
    let mut outcome = resolve_ability_rounds(
        &round_evaluator,
        &round_resolver,
        aos_ability_model::ABILITY_LIMITS_V1.max_resolver_rounds,
    )?;
    outcome
        .fixed_point
        .bind_checked_planning(&verified, &outcome.selections)?;

    let transition = TransitionPlanner::new(catalog.validation_context())
        .plan(
            &verified,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut composition_evaluator,
        )
        .context("constructing checked build-stage transition")?;
    let plan_bundle = ReloadablePlanBundle::from_verified(&verified, None, None, &transition)
        .context("constructing reloadable build-stage plan bundle")?;

    let output = ResolvedBuildStage {
        schema: BUILD_STAGE_OUTPUT_SCHEMA.to_string(),
        environment: desired.environment.environment.clone(),
        planning_snapshot: verified.snapshot_digest(),
        fixed_point: outcome.fixed_point,
        plan_bundle,
    };
    let bytes = aos_contract::canonical::to_vec(&output)
        .context("encoding resolved build-stage projection")?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating build-stage output {}", parent.display()))?;
    }
    fs::write(output_path, bytes)
        .with_context(|| format!("writing resolved build stage {}", output_path.display()))
}

/// Decodes and independently replays one embedded resolved-stage selection.
///
/// # Errors
///
/// Returns an error when the document is oversized, noncanonical, names an
/// unsupported schema, cannot replay its checked bundle, or its fixed point
/// differs from the exact replayed desired planning state.
pub(super) fn decode_resolved_stage(bytes: &[u8]) -> Result<CheckedResolvedBuildStage> {
    ensure!(
        bytes.len() as u64 <= MAXIMUM_SPEC_BYTES,
        "resolved build stage exceeds its document bound"
    );
    let resolved: ResolvedBuildStage =
        serde_json::from_slice(bytes).context("decoding resolved build stage")?;
    ensure!(
        resolved.schema == BUILD_STAGE_OUTPUT_SCHEMA,
        "unsupported resolved build-stage schema"
    );
    ensure!(
        aos_contract::canonical::to_vec(&resolved)? == bytes,
        "resolved build stage is not canonical JSON"
    );

    let bundle = resolved.plan_bundle;
    ensure!(
        bundle.desired_planning_digest() == resolved.planning_snapshot,
        "resolved build stage differs from its planning commitment"
    );
    let (plan, planning) = bundle
        .clone()
        .revalidate_with_desired(super::native_activation::supported_native_ability_features()?)
        .context("replaying resolved build-stage plan bundle")?;
    resolved
        .fixed_point
        .validate_replayed_planning(&planning)
        .context("binding resolved build-stage fixed point")?;
    ensure!(
        plan.binding_plan().environment().environment == resolved.environment,
        "resolved build-stage environment differs from its checked plan"
    );

    Ok(CheckedResolvedBuildStage {
        environment: resolved.environment,
        plan,
        bundle,
        fixed_point: resolved.fixed_point,
    })
}

fn validate_planning_spec(spec: &BuildStagePlanningSpec) -> Result<()> {
    ensure!(
        spec.schema == BUILD_STAGE_SPEC_SCHEMA,
        "unsupported build-stage planning schema"
    );
    validate_stage_inputs(
        spec.stage,
        [&spec.desired_input, &spec.authenticated_policy_set],
        &spec.packages,
    )
}

fn validate_environment(
    desired: &ActivationDesiredInputDocument,
    stage: ExecutionStage,
    authority: &LocalKey,
    key: &LocalKey,
) -> Result<()> {
    ensure!(
        desired.environment.environment.stage == stage
            && desired.environment.environment.authority == *authority
            && desired.environment.environment.key == *key,
        "build-stage identity differs from the authenticated planning environment"
    );
    Ok(())
}

fn validate_spec(spec: &BuildStageResolutionSpec) -> Result<()> {
    ensure!(
        spec.schema == BUILD_STAGE_SPEC_SCHEMA,
        "unsupported build-stage resolution schema"
    );
    validate_stage_inputs(
        spec.stage,
        [
            &spec.base_lib,
            &spec.intent_module,
            &spec.desired_input,
            &spec.authenticated_policy_set,
            &spec.planning_artifact,
        ],
        &spec.packages,
    )
}

fn validate_stage_inputs<'a>(
    stage: ExecutionStage,
    fixed_inputs: impl IntoIterator<Item = &'a PathBuf>,
    packages: &'a [PathBuf],
) -> Result<()> {
    ensure!(
        stage != ExecutionStage::Build,
        "build-stage resolver cannot target the artifact-construction stage"
    );
    ensure!(
        !packages.is_empty()
            && packages.len() as u64
                <= u64::from(aos_ability_model::ABILITY_LIMITS_V1.max_collection_items),
        "build-stage package companion count is outside the supported bound"
    );
    ensure!(
        packages.windows(2).all(|pair| pair[0] < pair[1]),
        "build-stage package companions are not unique canonical order"
    );
    for path in fixed_inputs.into_iter().chain(packages.iter()) {
        super::stock::store_root_and_suffix(path)?;
    }
    Ok(())
}

struct LoadedPackages {
    working_set: Vec<WorkingSetMember>,
    documents: Vec<(PackageDocument, Vec<InterfaceDocument>)>,
    artifact_locators:
        BTreeMap<String, BTreeMap<PackageOutputSelector, aos_ability_model::ArtifactReference>>,
}

fn load_packages(companions: &[PathBuf]) -> Result<LoadedPackages> {
    let mut working_set = Vec::with_capacity(companions.len());
    let mut documents = Vec::with_capacity(companions.len());
    let mut artifact_locators = BTreeMap::new();

    for companion in companions {
        let package_path = companion.join("package.json");
        let interface_path = companion.join("interfaces");
        aos_ability_validate::build_frontend::validate_package_source(
            &package_path,
            &interface_path,
        )?;
        let package: PackageDocument = read_canonical(&package_path, "resolved package document")?;
        let interfaces = load_package_interfaces(&package, &interface_path)?;
        let resolved: Vec<ResolvedPackageOutput> = read_canonical(
            &companion.join("selectors.json"),
            "resolved selector manifest",
        )?;
        let (outputs, locators) = package_outputs(&package, resolved)?;
        let name = package.package.name.as_str().to_string();
        ensure!(
            artifact_locators.insert(name.clone(), locators).is_none(),
            "build-stage package catalog repeats {name:?}"
        );
        working_set.push(WorkingSetMember {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: name,
            version: Some(package.package.version.clone()),
            contract: Some(super::ResolvedPackageContract {
                document: package.clone(),
                interfaces: interfaces.clone(),
            }),
            outputs,
        });
        documents.push((package, interfaces));
    }
    working_set.sort_by(|left, right| left.package.cmp(&right.package));
    ensure!(
        working_set
            .windows(2)
            .all(|pair| pair[0].package < pair[1].package),
        "build-stage package documents do not have unique names"
    );

    Ok(LoadedPackages {
        working_set,
        documents,
        artifact_locators,
    })
}

fn load_package_interfaces(
    package: &PackageDocument,
    directory: &Path,
) -> Result<Vec<InterfaceDocument>> {
    package
        .interfaces
        .values()
        .map(|expected| {
            let path = directory.join(format!("{}.json", expected.descriptor.hex()));
            let document: InterfaceDocument =
                read_canonical(&path, "resolved package interface document")?;
            ensure!(
                document.interface_key()? == *expected,
                "resolved package interface {} disagrees with its package contract",
                path.display()
            );
            Ok(document)
        })
        .collect()
}

fn package_outputs(
    package: &PackageDocument,
    resolved: Vec<ResolvedPackageOutput>,
) -> Result<(
    PackageOutputs,
    BTreeMap<PackageOutputSelector, aos_ability_model::ArtifactReference>,
)> {
    let mut outputs = PackageOutputs {
        self_output: Some(package.package.payload.store_path.clone()),
        dependencies: BTreeMap::new(),
    };
    let mut locators = BTreeMap::new();
    let mut previous = None;
    for selected in resolved {
        let key = (selected.package.clone(), selected.output.clone());
        ensure!(
            previous.as_ref().is_none_or(|prior| prior < &key),
            "resolved selector manifest is not unique canonical order"
        );
        previous = Some(key);
        let selector = PackageOutputSelector {
            package: LocalKey::new(selected.package.clone())?,
            output: LocalKey::new(selected.output.clone())?,
        };
        if selected.package == "self" && selected.output == "out" {
            ensure!(
                selected.artifact == package.package.payload,
                "resolved self output differs from package payload"
            );
            outputs.self_output = Some(selected.artifact.store_path.clone());
        } else if selected.package != "self" && selected.output == "out" {
            outputs.dependencies.insert(
                selected.package.clone(),
                selected.artifact.store_path.clone(),
            );
        }
        ensure!(
            locators.insert(selector, selected.artifact).is_none(),
            "resolved selector manifest contains a duplicate selector"
        );
    }
    Ok((outputs, locators))
}

fn read_canonical<T>(path: &Path, owner: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read_bounded(path, owner)?;
    let value: T = serde_json::from_slice(&bytes).with_context(|| format!("decoding {owner}"))?;
    ensure!(
        aos_contract::canonical::to_vec(&value)? == bytes,
        "{owner} is not canonical JSON"
    );
    Ok(value)
}

fn read_bounded(path: &Path, owner: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {owner} metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{owner} is not a regular file: {}", path.display());
    }
    ensure!(
        metadata.len() > 0 && metadata.len() <= MAXIMUM_SPEC_BYTES,
        "{owner} size is outside the supported bound"
    );
    fs::read(path).with_context(|| format!("reading {owner} {}", path.display()))
}

const fn stage_name(stage: ExecutionStage) -> &'static str {
    match stage {
        ExecutionStage::Build => "build",
        ExecutionStage::Initrd => "initrd",
        ExecutionStage::Host => "host",
        ExecutionStage::SystemContainer => "system-container",
        ExecutionStage::User => "user",
        ExecutionStage::ApplicationContainer => "application-container",
    }
}

#[cfg(test)]
mod tests {
    use super::package_outputs;
    use aos_ability_validate::build_frontend::ResolvedPackageOutput;

    #[test]
    fn resolved_output_manifest_must_use_package_then_output_order() {
        let fixture = aos_ability_validate::test_support::stateful_owner_plan_fixture();
        let package = &fixture.binding_inputs.packages[0];
        let artifact = package.package.payload.clone();
        let unordered = vec![
            ResolvedPackageOutput {
                package: "z-provider".to_string(),
                output: "out".to_string(),
                artifact: artifact.clone(),
            },
            ResolvedPackageOutput {
                package: "a-provider".to_string(),
                output: "out".to_string(),
                artifact,
            },
        ];

        let error = package_outputs(package, unordered)
            .expect_err("an output-before-package manifest must fail closed");

        assert!(error.to_string().contains("canonical order"));
    }
}
