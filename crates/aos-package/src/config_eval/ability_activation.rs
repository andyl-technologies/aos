//! Immutable inputs for native structured ability activation.
//!
//! A version-3 configuration manifest pins two canonical JSON sidecars. The
//! desired sidecar carries the original composition seed and its target
//! environment; the policy sidecar carries the independently authenticated
//! resolution-policy sequence. This module verifies each complete Nix store
//! object before reading its document through a descriptor-relative,
//! no-symlink path and checking the exact document commitment.
//!
//! The two sidecar document shapes are:
//!
//! ```json
//! {"environment":{"schema":"aos.ability.environment/v1","...":"..."},"schema":"aos.ability.activation-desired/v1","seed":{"schema":"aos.ability.desired-state/v1","...":"..."}}
//! {"policies":[{"schema":"aos.ability.resolution-policy/v1","...":"..."}],"schema":"aos.ability.authenticated-policy-set/v1","transition_authority":null}
//! ```

use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, DesiredStateDocument, EnvironmentDocument, TransitionAuthorizationDocument,
    VersionedDocument,
};
use aos_ability_plan::{
    PlanningReplayInputs, PlanningSnapshot, ResolutionPolicyDocument, TransitionInputs,
    TransitionPlanner, VerifiedPlanningSnapshot,
};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_validate::{
    CheckedEffectPlan, CheckedTransitionAuthority, TransitionAuthorityInputs,
};
use aos_contract::Sha256Digest;
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::ability::RestrictedAbilityEvaluator;
use super::materialize::{
    AbilityActivationInput, AbilityPackageCoordinate as PinnedAbilityPackageCoordinate,
    ConfigManifest, PinnedAbilitySidecar,
};
use super::runtime::RuntimePackageOrigin;
use crate::ability_package::{
    AbilityPackageCoordinate, NativeAbilityRetentionVerifier, VerifiedAbilityPackageSet,
};
use crate::config::ApmConfig;

/// Canonical desired-state input supplied to native composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationDesiredInputDocument {
    /// Carries `aos.ability.activation-desired/v1`.
    pub schema: String,
    /// Supplies the original normalized desired-state composition seed.
    pub seed: DesiredStateDocument,
    /// Supplies the authenticated target environment and current inventory.
    pub environment: EnvironmentDocument,
}

impl ActivationDesiredInputDocument {
    /// Current activation desired-input schema.
    pub const SCHEMA: &'static str = "aos.ability.activation-desired/v1";

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported ability activation desired-input schema {:?}",
            self.schema
        );
        validate_embedded_document(&self.seed, "activation desired seed")?;
        validate_embedded_document(&self.environment, "activation target environment")?;
        let environment = self
            .environment
            .content_digest()
            .context("identifying activation target environment")?;
        ensure!(
            self.seed.environment == environment,
            "activation desired seed names a different target environment"
        );
        Ok(())
    }
}

/// Canonical independently authenticated policy sequence for composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPolicySetDocument {
    /// Carries `aos.ability.authenticated-policy-set/v1`.
    pub schema: String,
    /// Lists exact policy snapshots in canonical desired-state order.
    pub policies: Vec<ResolutionPolicyDocument>,
    /// Supplies fresh authority for exact teardown bindings, when needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_authority: Option<TransitionAuthorizationDocument>,
}

impl AuthenticatedPolicySetDocument {
    /// Current authenticated policy-set schema.
    pub const SCHEMA: &'static str = "aos.ability.authenticated-policy-set/v1";

    fn validate(&self, desired: &ActivationDesiredInputDocument) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported authenticated ability policy-set schema {:?}",
            self.schema
        );
        ensure!(
            self.policies
                .windows(2)
                .all(|pair| pair[0].desired_state < pair[1].desired_state),
            "authenticated ability policies are not in strict desired-state order"
        );

        let environment = desired
            .environment
            .content_digest()
            .context("identifying activation target environment")?;
        for policy in &self.policies {
            validate_embedded_document(policy, "authenticated resolution policy")?;
            ensure!(
                policy.environment == environment,
                "authenticated resolution policy names a different target environment"
            );
        }
        if let Some(authority) = &self.transition_authority {
            validate_embedded_document(authority, "authenticated transition authority")?;
        }
        Ok(())
    }
}

/// Holds live-verified immutable inputs ready for native specialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAbilityActivationInputs {
    desired: ActivationDesiredInputDocument,
    policy_set: AuthenticatedPolicySetDocument,
    packages: Vec<PinnedAbilityPackageCoordinate>,
}

/// Owns one checked native effect graph and its reloadable provenance.
#[derive(Clone, Debug)]
pub struct SpecializedAbilityActivation {
    plan: CheckedEffectPlan,
    bundle: ReloadablePlanBundle,
    desired_state: DesiredStateDocument,
}

impl SpecializedAbilityActivation {
    /// Returns the checked effect graph selected for execution.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }

    /// Returns the reloadable planning and transition provenance.
    #[must_use]
    pub const fn bundle(&self) -> &ReloadablePlanBundle {
        &self.bundle
    }

    /// Returns the freshly specialized fixed-point desired state.
    #[must_use]
    pub const fn desired_state(&self) -> &DesiredStateDocument {
        &self.desired_state
    }

    /// Separates the owned checked graph from its reloadable provenance.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CheckedEffectPlan,
        ReloadablePlanBundle,
        DesiredStateDocument,
    ) {
        (self.plan, self.bundle, self.desired_state)
    }
}

impl VerifiedAbilityActivationInputs {
    /// Loads and authenticates the structured activation inputs from a manifest.
    ///
    /// The manifest must carry the version-3 activation descriptor. Both
    /// complete sidecar store objects are checked against their pinned NAR and
    /// reference identities before either document is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest lacks activation inputs, a store
    /// object differs from its commitment, a document path traverses a link or
    /// special object, or a document is noncanonical, malformed, or
    /// inconsistent with the other input.
    pub fn load(
        manifest: &ConfigManifest,
        independently_authenticated_policy: &PinnedAbilitySidecar,
    ) -> Result<Self> {
        manifest.validate()?;
        let activation = manifest
            .inputs
            .ability_activation
            .as_ref()
            .context("config manifest does not carry native ability activation inputs")?;
        ensure!(
            activation.authenticated_policy_set == *independently_authenticated_policy,
            "config manifest policy-set descriptor differs from independently authenticated operator policy"
        );
        Self::load_activation(activation)
    }

    /// Returns the original desired-state seed and target environment.
    #[must_use]
    pub const fn desired(&self) -> &ActivationDesiredInputDocument {
        &self.desired
    }

    /// Returns the independently authenticated resolution-policy sequence.
    #[must_use]
    pub const fn policy_set(&self) -> &AuthenticatedPolicySetDocument {
        &self.policy_set
    }

    fn load_activation(activation: &AbilityActivationInput) -> Result<Self> {
        let desired_bytes = load_sidecar(&activation.desired_state, "desired state")?;
        let desired: ActivationDesiredInputDocument =
            decode_canonical_sidecar(&desired_bytes, ActivationDesiredInputDocument::SCHEMA)?;
        desired.validate()?;

        let policy_bytes = load_sidecar(
            &activation.authenticated_policy_set,
            "authenticated policy set",
        )?;
        let policy_set: AuthenticatedPolicySetDocument =
            decode_canonical_sidecar(&policy_bytes, AuthenticatedPolicySetDocument::SCHEMA)?;
        policy_set.validate(&desired)?;

        Ok(Self {
            desired,
            policy_set,
            packages: activation.packages.clone(),
        })
    }
}

/// Specializes authenticated package modules into one checked native graph.
///
/// Desired and prior planning each use the exact sealed package catalog pinned
/// by their own generation. Their union is used only to validate a transition
/// that can retain artifacts from both generations. Prior state is planning
/// provenance only. Any removal must also carry the freshly authenticated
/// transition authority from the desired policy set.
///
/// # Errors
///
/// Returns an error when composition, snapshot reconstruction, teardown
/// authorization, transition evaluation, or reload-bundle construction fails.
pub fn specialize_activation(
    desired: &VerifiedAbilityActivationInputs,
    current: Option<&VerifiedAbilityActivationInputs>,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
) -> Result<SpecializedAbilityActivation> {
    let desired_packages = packages_for_inputs(desired, packages)?;
    let desired_catalog = desired_packages.planning_catalog()?;
    let desired_planning = specialize_planning(desired, &desired_catalog, evaluator)
        .context("specializing desired ability planning state")?;
    let current_planning = current
        .map(|current| {
            let current_packages = packages_for_inputs(current, packages)?;
            let current_catalog = current_packages.planning_catalog()?;
            specialize_planning(current, &current_catalog, evaluator)
                .context("specializing retained current ability planning state")
        })
        .transpose()?;
    let transition_catalog = packages.planning_catalog()?;
    let authority = authenticate_transition_authority(
        desired,
        &transition_catalog,
        &desired_planning,
        current_planning.as_ref(),
    )?;
    let transition = TransitionPlanner::new(transition_catalog.validation_context())
        .plan(
            &desired_planning,
            TransitionInputs {
                current: current_planning.as_ref(),
                authority: authority.as_ref(),
            },
            evaluator,
        )
        .context("specializing native ability transition")?;
    let bundle = ReloadablePlanBundle::from_verified(
        &desired_planning,
        current_planning.as_ref(),
        authority.as_ref(),
        &transition,
    )
    .context("constructing reloadable native ability plan")?;
    let desired_state = desired_planning.outcome().desired_state.clone();
    let plan = transition.into_checked_effect();
    Ok(SpecializedAbilityActivation {
        plan,
        bundle,
        desired_state,
    })
}

fn packages_for_inputs(
    inputs: &VerifiedAbilityActivationInputs,
    packages: &VerifiedAbilityPackageSet,
) -> Result<VerifiedAbilityPackageSet> {
    let mut selected = Vec::with_capacity(inputs.packages.len());
    for coordinate in &inputs.packages {
        let package = packages
            .get(&coordinate.name, &coordinate.version, &coordinate.platform)
            .with_context(|| {
                format!(
                    "ability package {}@{} ({}) is absent from the verified generation union",
                    coordinate.name, coordinate.version, coordinate.platform
                )
            })?;
        ensure!(
            package.manifest_sha256().to_string() == coordinate.manifest_sha256
                && package.package_digest().to_string() == coordinate.package_digest,
            "ability package {}@{} ({}) seal differs from its generation coordinate",
            coordinate.name,
            coordinate.version,
            coordinate.platform
        );
        selected.push(package.clone());
    }
    VerifiedAbilityPackageSet::from_verified(selected)
}

fn specialize_planning(
    inputs: &VerifiedAbilityActivationInputs,
    catalog: &crate::ability_package::VerifiedAbilityPlanningCatalog,
    evaluator: &mut RestrictedAbilityEvaluator,
) -> Result<VerifiedPlanningSnapshot> {
    let outcome = catalog.composer().compose(
        &inputs.policy_set.policies,
        inputs.desired.seed.clone(),
        inputs.desired.environment.clone(),
        catalog.packages().to_vec(),
        evaluator,
    )?;
    let snapshot = PlanningSnapshot::from_outcome(&outcome)?;
    let expected_digest = snapshot.digest()?;
    snapshot
        .verify_structure(
            &catalog.composer(),
            PlanningReplayInputs {
                expected_digest,
                authenticated_policies: &inputs.policy_set.policies,
                seed: inputs.desired.seed.clone(),
                environment: inputs.desired.environment.clone(),
                packages: catalog.packages().to_vec(),
            },
        )
        .map_err(anyhow::Error::new)
}

fn authenticate_transition_authority(
    desired: &VerifiedAbilityActivationInputs,
    catalog: &crate::ability_package::VerifiedAbilityPlanningCatalog,
    desired_planning: &VerifiedPlanningSnapshot,
    current_planning: Option<&VerifiedPlanningSnapshot>,
) -> Result<Option<CheckedTransitionAuthority>> {
    let Some(document) = desired.policy_set.transition_authority.clone() else {
        return Ok(None);
    };
    let current = current_planning
        .context("transition authority is present without retained current planning state")?;
    let expected_digest = document
        .content_digest()
        .context("identifying authenticated transition authority")?;
    let authority = catalog.validation_context().validate_transition_authority(
        document.clone(),
        TransitionAuthorityInputs {
            expected_digest,
            desired_planning: desired_planning.snapshot_digest(),
            current_planning: current.snapshot_digest(),
            authorization_policy_revision: document.authorization_policy_revision,
            desired: desired_planning.checked_binding(),
            current: current.checked_binding(),
        },
    )?;
    Ok(Some(authority))
}

/// Reconstructs fresh sealed packages for desired and retained generations.
///
/// Every registry package is reverified against the currently trusted key
/// roster, its dedicated provenance statement, its exact companion manifest,
/// and the live retention catalog. Callers should pass both the candidate and
/// current generation manifests when transition planning may tear down prior
/// owners.
///
/// # Errors
///
/// Returns an error when a manifest is invalid, a coordinate is missing or
/// inconsistent, an image-local package lacks replayable registry trust, or
/// current provenance, package bytes, and live store objects do not reproduce
/// an exact verified package seal.
pub fn verify_generation_packages(
    config: &ApmConfig,
    manifests: &[&ConfigManifest],
) -> Result<VerifiedAbilityPackageSet> {
    let mut packages = Vec::new();
    for manifest in manifests {
        manifest.validate()?;
        let Some(activation) = &manifest.inputs.ability_activation else {
            continue;
        };
        for pinned in &activation.packages {
            let package = manifest
                .package_outputs
                .get(&pinned.name)
                .with_context(|| {
                    format!(
                        "generation packageOutputs omits ability package {:?}",
                        pinned.name
                    )
                })?;
            ensure!(
                package.origin == RuntimePackageOrigin::Registry,
                "image-local structured ability package {:?} has no replayable registry trust receipt",
                pinned.name
            );
            let ability = package
                .ability
                .as_ref()
                .context("ability coordinate has no authenticated package metadata")?;
            let (_, provenance) = crate::install::read_provenance_artifact(
                &config.cache_path(),
                &pinned.registry,
                &ability.provenance,
            )?;
            let trusted_keys = crate::install::read_registry_provenance_trusted_keys(
                &config.cache_path(),
                &pinned.registry,
            )?;
            let manifest_bytes =
                crate::ability_package::read_package_manifest(&pinned.ability_store_path)?;
            let coordinate = AbilityPackageCoordinate {
                name: &pinned.name,
                version: &pinned.version,
                platform: &pinned.platform,
                store_path: &pinned.runtime_store_path,
                nar_hash: &pinned.runtime_nar_hash,
            };
            let verified = crate::ability_package::verify_pinned_ability_package(
                coordinate,
                ability,
                &manifest_bytes,
                &provenance,
                &pinned.registry,
                &trusted_keys,
                &NativeAbilityRetentionVerifier::new(),
            )
            .with_context(|| {
                format!(
                    "reverifying generation ability package {}@{}",
                    pinned.name, pinned.version
                )
            })?;
            packages.push(verified);
        }
    }
    VerifiedAbilityPackageSet::from_verified(packages)
}

fn load_sidecar(sidecar: &PinnedAbilitySidecar, label: &str) -> Result<Vec<u8>> {
    let nar_hex = aos_registry_surface::store::canonical_digest_hex(&sidecar.nar_hash)
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    let nar_hash = Sha256Digest::parse(&format!("sha256:{nar_hex}"))
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    crate::ability_package::retention::verify_store_object(
        &sidecar.store_path,
        nar_hash,
        sidecar.nar_size,
        &sidecar.references,
    )
    .with_context(|| format!("verifying ability {label} store object"))?;

    let bytes = read_regular_file_beneath(
        Path::new(&sidecar.store_path),
        Path::new(&sidecar.document),
        sidecar.document_size,
    )
    .with_context(|| format!("reading pinned ability {label} document"))?;
    let expected = Sha256Digest::parse(&sidecar.document_sha256)
        .with_context(|| format!("decoding ability {label} document identity"))?;
    ensure!(
        Sha256Digest::of_bytes(&bytes) == expected,
        "ability {label} document differs from its exact byte commitment"
    );
    Ok(bytes)
}

fn read_regular_file_beneath(root: &Path, relative: &Path, expected_size: u64) -> Result<Vec<u8>> {
    ensure!(
        !relative.as_os_str().is_empty()
            && !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "ability document path is not a safe relative path"
    );

    let mut directory = fs::openat(
        fs::CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening sidecar root {}", root.display()))?;
    let components = relative.components().collect::<Vec<_>>();
    for component in &components[..components.len().saturating_sub(1)] {
        let Component::Normal(name) = component else {
            bail!("ability document path changed during validated traversal");
        };
        directory = fs::openat(
            &directory,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening ability document directory {name:?}"))?;
    }

    let Some(Component::Normal(file_name)) = components.last() else {
        bail!("ability document path has no final file name");
    };
    let descriptor = fs::openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("opening ability document {file_name:?}"))?;
    let metadata = fs::fstat(&descriptor).context("statting ability document descriptor")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile,
        "ability document is not a regular file"
    );
    ensure!(
        u64::try_from(metadata.st_size).ok() == Some(expected_size),
        "ability document size differs from its commitment"
    );

    let limit = expected_size
        .checked_add(1)
        .context("ability document byte limit overflowed")?;
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    File::from(descriptor)
        .take(limit)
        .read_to_end(&mut bytes)
        .context("reading ability document bytes")?;
    ensure!(
        u64::try_from(bytes.len()).ok() == Some(expected_size),
        "ability document bytes differ from its committed size"
    );
    Ok(bytes)
}

fn decode_canonical_sidecar<T>(bytes: &[u8], schema: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let limits = aos_contract::limits::JsonLimits {
        max_bytes: ABILITY_LIMITS_V1.max_document_bytes as usize,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 2,
        max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    };
    let document = limits
        .decode::<T>(bytes, schema)
        .with_context(|| format!("decoding {schema}"))?;
    let canonical = aos_contract::canonical::to_vec(&document)
        .with_context(|| format!("encoding canonical {schema}"))?;
    ensure!(
        canonical == bytes,
        "{schema} is not encoded as exact canonical JSON"
    );
    Ok(document)
}

fn validate_embedded_document<T>(document: &T, label: &str) -> Result<()>
where
    T: VersionedDocument,
{
    aos_ability_model::document::encode_canonical(document)
        .with_context(|| format!("validating {label}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;

    use aos_ability_model::{AbilityActivationMode, PackageDocument, PackageImplementation};

    use super::*;

    #[test]
    fn descriptor_relative_reader_rejects_symlink_escape() {
        let root = tempfile::tempdir().expect("temporary sidecar root");
        let outside = tempfile::tempdir().expect("temporary outside directory");
        fs::write(outside.path().join("desired.json"), b"{}").expect("write outside document");
        symlink(outside.path(), root.path().join("mutable")).expect("create intermediate symlink");

        let error = read_regular_file_beneath(root.path(), Path::new("mutable/desired.json"), 2)
            .expect_err("sidecar reader must reject an intermediate symlink");
        assert!(error.to_string().contains("document directory"));

        symlink(
            outside.path().join("desired.json"),
            root.path().join("desired.json"),
        )
        .expect("create final symlink");
        let error = read_regular_file_beneath(root.path(), Path::new("desired.json"), 2)
            .expect_err("sidecar reader must reject a final symlink");
        assert!(error.to_string().contains("opening ability document"));
    }

    #[test]
    fn descriptor_relative_reader_checks_exact_regular_file_size() {
        let root = tempfile::tempdir().expect("temporary sidecar root");
        fs::create_dir(root.path().join("inputs")).expect("create input directory");
        fs::write(root.path().join("inputs/desired.json"), b"{}").expect("write desired document");

        let bytes = read_regular_file_beneath(root.path(), Path::new("inputs/desired.json"), 2)
            .expect("read exact regular document");
        assert_eq!(bytes, b"{}");
        let error = read_regular_file_beneath(root.path(), Path::new("inputs/desired.json"), 3)
            .expect_err("sidecar reader must check exact size");
        assert!(error.to_string().contains("size differs"));
    }

    #[test]
    fn canonical_sidecar_decoder_rejects_equivalent_noncanonical_json() {
        #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        struct Example {
            schema: String,
            value: u32,
        }

        let canonical = br#"{"schema":"example/v1","value":1}"#;
        let decoded: Example =
            decode_canonical_sidecar(canonical, "example/v1").expect("canonical sidecar");
        assert_eq!(decoded.value, 1);

        let error = decode_canonical_sidecar::<Example>(
            br#"{ "schema": "example/v1", "value": 1 }"#,
            "example/v1",
        )
        .expect_err("noncanonical bytes must fail");
        assert!(error.to_string().contains("exact canonical JSON"));
    }

    #[test]
    fn specialization_keeps_upgrade_generations_on_their_exact_package_universes() {
        let (fixture, _) = aos_ability_plan::test_support::verified_planning_transition_plan();
        let mut environment = fixture.checked_binding().environment().clone();
        environment.providers.clear();
        environment.resources.clear();
        environment.controllers.clear();
        environment.guarantees.clear();
        let environment_digest = environment.content_digest().unwrap();
        let mut seed = fixture.outcome().seed.clone();
        seed.environment = environment_digest;
        seed.instances.clear();
        seed.contributions.clear();
        seed.child_requests.clear();
        seed.resources.clear();
        seed.outputs.clear();
        seed.controllers.clear();
        let mut policy = fixture.outcome().policies[0].clone();
        policy.desired_state = seed.content_digest().unwrap();
        policy.environment = environment_digest;
        policy.policy_revision = environment.policy_revision;
        policy.candidates.clear();
        policy.explicit_bindings.clear();
        policy.existing_pins.clear();
        policy.operator_orders.clear();
        policy.enabled_providers.clear();
        policy.obligations.clear();

        let sealed_v1 = crate::ability_package::seal_test_package(test_package("1.0.0")).unwrap();
        let sealed_v2 = crate::ability_package::seal_test_package(test_package("2.0.0")).unwrap();
        let current = test_inputs(&seed, &environment, &policy, &sealed_v1);
        let desired = test_inputs(&seed, &environment, &policy, &sealed_v2);
        let packages =
            VerifiedAbilityPackageSet::from_verified(vec![sealed_v1, sealed_v2]).unwrap();
        let mut evaluator = RestrictedAbilityEvaluator::new(
            "/unreachable/nix-instantiate",
            "/unreachable/prlimit",
            "/unreachable/cache",
            super::super::ability::AbilityEvaluationLimits::default(),
        )
        .unwrap();

        let specialized =
            specialize_activation(&desired, Some(&current), &packages, &mut evaluator)
                .unwrap_or_else(|error| panic!("specialization failed: {error:#?}"));

        let bundle: serde_json::Value = serde_json::from_slice(
            &specialized
                .bundle()
                .canonical_bytes()
                .expect("upgrade bundle must encode"),
        )
        .expect("upgrade bundle must be JSON");
        assert_eq!(
            bundle["desired"]["packages"][0]["package"]["version"],
            "2.0.0"
        );
        assert_eq!(
            bundle["current"]["packages"][0]["package"]["version"],
            "1.0.0"
        );
        assert!(specialized.plan().operations().is_empty());
    }

    fn test_package(version: &str) -> PackageDocument {
        let (_, effect) = aos_ability_plan::test_support::verified_planning_effect_plan();
        let mut package = effect.binding_plan().packages()[0].clone();
        package.package.version = version.to_string();
        package.activation_mode = AbilityActivationMode::StructuredEffects;
        package.exports.clear();
        package.requirements.clear();
        package.module_entry_points.clear();
        package.implementation = PackageImplementation {
            providers: Vec::new(),
            handlers: BTreeMap::new(),
        };
        package.ownership.clear();
        package
    }

    fn test_inputs(
        seed: &DesiredStateDocument,
        environment: &EnvironmentDocument,
        policy: &ResolutionPolicyDocument,
        package: &crate::ability_package::VerifiedAbilityPackage,
    ) -> VerifiedAbilityActivationInputs {
        VerifiedAbilityActivationInputs {
            desired: ActivationDesiredInputDocument {
                schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
                seed: seed.clone(),
                environment: environment.clone(),
            },
            policy_set: AuthenticatedPolicySetDocument {
                schema: AuthenticatedPolicySetDocument::SCHEMA.to_string(),
                policies: vec![policy.clone()],
                transition_authority: None,
            },
            packages: vec![PinnedAbilityPackageCoordinate {
                name: package.package_name().to_string(),
                version: package.package_version().to_string(),
                platform: package.platform().to_string(),
                registry: "test".to_string(),
                runtime_store_path: package.package().package.payload.store_path.clone(),
                runtime_nar_hash: package.package().package.payload.nar_hash.to_string(),
                runtime_nar_size: 1,
                ability_store_path: package
                    .retention_manifest()
                    .companion_store_path()
                    .to_string(),
                ability_nar_hash: package
                    .retention_manifest()
                    .companion_nar_hash()
                    .to_string(),
                manifest_sha256: package.manifest_sha256().to_string(),
                package_digest: package.package_digest().to_string(),
            }],
        }
    }
}
