//! Hermetic materialization of one source-composed stage bundle.
//!
//! The materializer consumes the completed standard module fixed point and one
//! bootable static contract. It retains each declaration's authenticated module
//! authority, resolves selected package artifacts through their authenticated
//! companions, validates the exact explicit bindings, constructs the pure
//! effect graph, and emits the canonical source bundle. It performs no provider
//! search and accepts no resolution policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
    ProviderState,
};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, AggregateOutput, ArtifactReference, AuthorityGrant,
    Binding, BindingId, BindingPlanDocument, BindingRequest, BindingSource, ContributionPermission,
    ControllerAssignment, DesiredStateDocument, EnvironmentDocument, ExecutionStage, InstanceId,
    InterfaceDocument, InterfaceKey, LocalKey, PackageDocument, ProviderImplementation,
    ProviderImplementationReference, RequestId, ResourceId, ResourcePermission, ResourceReference,
    RevisionId, ValueExpression, VersionedDocument,
};
use aos_ability_plan::{
    SourceStageBinding, SourceStageBundle, SourceStageFixedPoint, SourceStageRequest,
    SourceStageRequirementReference, SourceStageStaticContract, TransitionPlanner,
};
use aos_ability_validate::{
    BindingValidationInputs, PackageOutputSelector, ValidationContext,
    package_source_supported_features, resolve_artifact_selectors,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

const SOURCE_STAGE_SPEC_SCHEMA: &str = "aos.ability.source-stage-materialization/v1";
const MAXIMUM_SPEC_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceStageMaterializationSpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    platform: PlatformIdentity,
    static_contract: SourceStageContractInput,
    fixed_point: PathBuf,
    base_lib: PathBuf,
    artifact_outputs: Vec<SourceStageArtifactOutput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceStageArtifactOutput {
    selector: PackageOutputSelector,
    path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceStageContractInput {
    identity: String,
    path: PathBuf,
}

struct SourceCatalog {
    packages: Vec<PackageDocument>,
    interfaces: Vec<InterfaceDocument>,
    package_by_name: BTreeMap<LocalKey, usize>,
    interface_by_key: BTreeMap<InterfaceKey, usize>,
    package_outputs: BTreeMap<PackageOutputSelector, ArtifactReference>,
}

struct SelectedImplementation<'a> {
    package: &'a PackageDocument,
    implementation: &'a ProviderImplementation,
    interface: &'a InterfaceDocument,
    provider: InstanceId,
    reference: ProviderImplementationReference,
}

/// Materializes one canonical source-composed stage bundle.
///
/// # Errors
///
/// Returns an error when the specification or fixed point is noncanonical, the
/// static contract differs from its authenticated companions, any source
/// selection is incomplete, common binding/effect validation fails, or pure
/// transition construction rejects an implementation.
pub fn materialize_source_stage(
    spec_path: &Path,
    exported_graph_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let spec: SourceStageMaterializationSpec =
        read_canonical(spec_path, "source-stage materialization specification")?;
    validate_spec(&spec)?;
    let mut fixed_point: SourceStageFixedPoint =
        read_canonical(&spec.fixed_point, "completed source ability fixed point")?;
    let environment_id = aos_ability_model::EnvironmentId {
        authority: spec.authority.clone(),
        key: spec.key.clone(),
        stage: spec.stage,
    };
    ensure!(
        spec.stage == ExecutionStage::Initrd && fixed_point.environment == environment_id,
        "source stage fixed point names another execution environment"
    );
    ensure!(
        fixed_point.composition_pending_requests.is_empty(),
        "source stage fixed point retains unresolved provider requests"
    );

    let contract_bytes = read_bounded(&spec.static_contract.path, "initrd static contract")?;
    let static_contract = SourceStageStaticContract {
        identity: spec.static_contract.identity,
        sha256: Sha256Digest::of_bytes(&contract_bytes),
    };
    let mut catalog = load_static_catalog(&contract_bytes)?;
    load_source_artifacts(&spec.artifact_outputs, exported_graph_path, &mut catalog)?;
    let used_artifacts = resolve_fixed_point_artifacts(&mut fixed_point, &catalog)?;
    let declared_artifacts = spec
        .artifact_outputs
        .iter()
        .map(|output| output.selector.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        used_artifacts == declared_artifacts,
        "source-stage artifact outputs differ from the completed fixed point"
    );
    fixed_point.derive_resource_revisions(&catalog.packages)?;
    let context = ValidationContext::new(
        package_source_supported_features()?,
        catalog.interfaces.clone(),
    )?;
    let source_revision = source_revision(&static_contract, &fixed_point)?;
    let source = SourceComposition::new(&fixed_point, &catalog, source_revision)?;
    let environment = source.environment(environment_id, spec.platform)?;
    let desired_state = source.desired_state(environment.content_digest()?)?;
    let binding_document = source.binding_document(&environment, &desired_state)?;
    let checked_binding = context.validate_binding_plan(
        binding_document,
        BindingValidationInputs {
            environment,
            desired_state,
            packages: catalog.packages.clone(),
        },
    )?;
    let source_authority = SourceStageBundle::authority_for(
        &static_contract,
        &fixed_point,
        &checked_binding,
        &catalog.interfaces,
    )?;
    let mut evaluator = super::native_activation::production_evaluator()?
        .with_source_fixed_point(spec.base_lib, static_contract.identity.clone())?;
    let transition = TransitionPlanner::new(&context).plan_source(
        source_authority,
        &checked_binding,
        &fixed_point,
        &mut evaluator,
    )?;
    let bundle = SourceStageBundle::from_checked(
        static_contract,
        fixed_point,
        transition.checked_effect(),
        transition.evaluations().to_vec(),
    )?;
    ensure!(
        bundle.authority() == source_authority,
        "source transition authority differs from the final stage bundle"
    );
    let bytes = bundle.canonical_bytes()?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating source stage output {}", parent.display()))?;
    }
    fs::write(output_path, bytes)
        .with_context(|| format!("writing source stage bundle {}", output_path.display()))
}

/// Decodes and validates an embedded source-composed stage bundle.
///
/// # Errors
///
/// Returns an error when the document is oversized, noncanonical, internally
/// inconsistent, or fails common binding/effect validation.
pub(super) fn decode_source_stage(
    bytes: &[u8],
) -> Result<aos_ability_plan::CheckedSourceStageBundle> {
    ensure!(
        bytes.len() as u64 <= aos_ability_plan::SOURCE_STAGE_BUNDLE_MAX_BYTES as u64,
        "source stage bundle exceeds its document bound"
    );
    SourceStageBundle::decode(bytes)?
        .check(None)
        .map_err(Into::into)
}

fn validate_spec(spec: &SourceStageMaterializationSpec) -> Result<()> {
    ensure!(
        spec.schema == SOURCE_STAGE_SPEC_SCHEMA,
        "unsupported source-stage materialization schema"
    );
    ensure!(
        spec.stage == ExecutionStage::Initrd,
        "only initrd source stages are materialized"
    );
    validate_absolute_path(&spec.static_contract.identity, "static contract identity")?;
    validate_absolute_path(
        spec.static_contract
            .path
            .to_str()
            .context("static contract read path is not UTF-8")?,
        "static contract read path",
    )?;
    super::stock::store_root_and_suffix(&spec.static_contract.path)?;
    super::stock::store_root_and_suffix(&spec.fixed_point)?;
    let (_, source_suffix) = super::stock::store_root_and_suffix(&spec.base_lib)?;
    ensure!(
        source_suffix.as_os_str().is_empty(),
        "source stage base library is not an exact store path"
    );
    ensure!(
        spec.artifact_outputs
            .windows(2)
            .all(|pair| pair[0].selector < pair[1].selector),
        "source-stage artifact selectors are not unique and canonically ordered"
    );
    for output in &spec.artifact_outputs {
        ensure!(
            output.selector.package.as_str() != "self",
            "source-stage artifact selector is not package-qualified"
        );
        let (_, suffix) = super::stock::store_root_and_suffix(&output.path)?;
        ensure!(
            suffix.as_os_str().is_empty(),
            "source-stage artifact output is not an exact store root"
        );
    }
    Ok(())
}

fn validate_absolute_path(path: &str, label: &str) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && path != "/"
            && !path.ends_with('/')
            && !path.contains("//")
            && !path
                .split('/')
                .any(|component| matches!(component, "." | "..")),
        "{label} is not a normalized absolute path"
    );
    Ok(())
}

fn load_static_catalog(contract_bytes: &[u8]) -> Result<SourceCatalog> {
    use aos_ability_validate::{
        StaticAbilityArtifactClass, StaticAbilityContractExpectation, StaticAbilityExecutionStage,
    };

    let checked = aos_ability_validate::validate_static_ability_artifacts_at_store_root(
        contract_bytes,
        &StaticAbilityContractExpectation {
            artifact_class: StaticAbilityArtifactClass::Bootable,
            execution_stage: Some(StaticAbilityExecutionStage::Initrd),
            platform: None,
        },
        Path::new("/nix/store"),
    )?;
    let mut packages = Vec::new();
    let mut interfaces = BTreeMap::new();
    let mut package_outputs = BTreeMap::new();
    for selected in checked.packages() {
        let package = selected
            .package_document()
            .context("validated static contract omitted its package companion")?
            .clone();
        for interface in selected.retained_interfaces() {
            let key = interface.interface_key()?;
            if let Some(existing) = interfaces.insert(key, interface.clone()) {
                ensure!(
                    existing == *interface,
                    "static contract repeats an interface identity with different content"
                );
            }
        }
        for output in selected.resolved_outputs() {
            let selector = PackageOutputSelector {
                package: output.package.clone(),
                output: output.output.clone(),
            };
            if let Some(existing) = package_outputs.insert(selector, output.artifact.clone()) {
                ensure!(
                    existing == output.artifact,
                    "static contract resolves one package output to different artifacts"
                );
            }
        }
        packages.push(package);
    }
    let package_names = packages
        .iter()
        .map(|package| package.package.name.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        package_names.len() == packages.len(),
        "static contract package names are not unique"
    );
    let package_count = packages.len();
    let packages_by_digest = packages
        .into_iter()
        .map(|package| Ok((package.content_digest()?, package)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        packages_by_digest.len() == package_count,
        "static contract repeats an exact package document"
    );
    let packages = packages_by_digest.into_values().collect::<Vec<_>>();
    let interfaces = interfaces.into_values().collect::<Vec<_>>();
    let package_by_name = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package.package.name.clone(), index))
        .collect();
    let interface_by_key = interfaces
        .iter()
        .enumerate()
        .map(|(index, interface)| Ok((interface.interface_key()?, index)))
        .collect::<Result<_>>()?;
    Ok(SourceCatalog {
        packages,
        interfaces,
        package_by_name,
        interface_by_key,
        package_outputs,
    })
}

fn load_source_artifacts(
    outputs: &[SourceStageArtifactOutput],
    exported_graph_path: &Path,
    catalog: &mut SourceCatalog,
) -> Result<()> {
    let exported_graph: serde_json::Value = serde_json::from_slice(
        &fs::read(exported_graph_path).context("reading source-stage exported Nix graph")?,
    )
    .context("decoding source-stage exported Nix graph")?;

    for output in outputs {
        let artifact =
            aos_ability_validate::build_frontend::artifact_reference_from_exported_graph(
                &output.path,
                "sourceStageArtifacts",
                &exported_graph,
            )?;
        if let Some(existing) = catalog
            .package_outputs
            .insert(output.selector.clone(), artifact.clone())
        {
            ensure!(
                existing == artifact,
                "source-stage artifact differs from its static contract output"
            );
        }
    }
    Ok(())
}

fn resolve_fixed_point_artifacts(
    fixed_point: &mut SourceStageFixedPoint,
    catalog: &SourceCatalog,
) -> Result<BTreeSet<PackageOutputSelector>> {
    fn resolve(
        value: &mut AbilityValue,
        catalog: &SourceCatalog,
        used: &mut BTreeSet<PackageOutputSelector>,
    ) -> Result<()> {
        let mut json = value.as_json().clone();
        resolve_artifact_selectors(&mut json, |selector| {
            used.insert(selector.clone());
            catalog
                .package_outputs
                .get(selector)
                .cloned()
                .with_context(|| {
                    format!(
                        "source fixed point references unresolved package output ({}, {})",
                        selector.package.as_str(),
                        selector.output.as_str()
                    )
                })
        })?;
        *value = AbilityValue::new(json)?;
        Ok(())
    }

    let mut used = BTreeSet::new();
    for instance in fixed_point.instances.values_mut() {
        resolve(&mut instance.configuration, catalog, &mut used)?;
    }
    for request in fixed_point
        .requests
        .values_mut()
        .chain(fixed_point.composition_requests.values_mut())
    {
        resolve(&mut request.parameters, catalog, &mut used)?;
    }
    for requirement in fixed_point.composition_requirements.values_mut() {
        if let Some(fallback) = requirement.requirement.fallback.as_mut() {
            for output in fallback.outputs.values_mut() {
                resolve(output, catalog, &mut used)?;
            }
        }
    }
    for outputs in fixed_point.composition_outputs.values_mut() {
        for output in outputs.values_mut() {
            resolve(&mut output.value, catalog, &mut used)?;
        }
    }
    for resource in fixed_point.resolved_resources.values_mut() {
        resolve(&mut resource.value, catalog, &mut used)?;
        resolve(&mut resource.realization, catalog, &mut used)?;
        ensure!(
            resource.revision.is_none(),
            "source fixed point must not supply a resource revision"
        );
    }
    Ok(used)
}

fn source_revision(
    contract: &SourceStageStaticContract,
    fixed_point: &SourceStageFixedPoint,
) -> Result<RevisionId> {
    #[derive(Serialize)]
    struct RevisionMaterial<'a> {
        schema: &'static str,
        static_contract: &'a SourceStageStaticContract,
        fixed_point: &'a SourceStageFixedPoint,
    }

    let material = RevisionMaterial {
        schema: "aos.ability.source-stage-revision/v1",
        static_contract: contract,
        fixed_point,
    };
    Ok(RevisionId(Sha256Digest::of_canonical(
        material.schema,
        &material,
    )?))
}

struct SourceComposition<'a> {
    fixed_point: &'a SourceStageFixedPoint,
    catalog: &'a SourceCatalog,
    binding_by_request: BTreeMap<&'a str, (&'a str, &'a SourceStageBinding)>,
    revision: RevisionId,
}

impl<'a> SourceComposition<'a> {
    fn new(
        fixed_point: &'a SourceStageFixedPoint,
        catalog: &'a SourceCatalog,
        revision: RevisionId,
    ) -> Result<Self> {
        ensure!(
            fixed_point.instances.len() == fixed_point.instance_identities.len()
                && fixed_point
                    .instances
                    .keys()
                    .eq(fixed_point.instance_identities.keys()),
            "source instances differ from their canonical identity projection"
        );
        let mut binding_by_request = BTreeMap::new();
        for (name, binding) in &fixed_point.bindings {
            ensure!(
                binding_by_request
                    .insert(binding.request.as_str(), (name.as_str(), binding))
                    .is_none(),
                "source request {:?} has several exact bindings",
                binding.request
            );
        }
        let source = Self {
            fixed_point,
            catalog,
            binding_by_request,
            revision,
        };
        let request_names = fixed_point
            .requests
            .keys()
            .chain(fixed_point.composition_requests.keys())
            .collect::<BTreeSet<_>>();
        ensure!(
            request_names.len() == fixed_point.bindings.len()
                && request_names
                    .iter()
                    .all(|name| source.binding_by_request.contains_key(name.as_str())),
            "source bindings do not select every request exactly once"
        );
        for name in fixed_point.instances.keys() {
            source.instance_identity(name)?;
        }
        Ok(source)
    }

    fn environment(
        &self,
        environment: aos_ability_model::EnvironmentId,
        platform: PlatformIdentity,
    ) -> Result<EnvironmentDocument> {
        let mut artifacts_by_content = BTreeMap::new();
        for artifact in self.catalog.package_outputs.values() {
            if let Some(existing) = artifacts_by_content.insert(artifact.content, artifact.clone())
            {
                ensure!(
                    existing == *artifact,
                    "source outputs resolve one content identity to different artifacts"
                );
            }
        }
        let mut providers = Vec::new();
        for (name, binding) in &self.fixed_point.bindings {
            let selected = self.selected_implementation(name, binding)?;
            if selected.reference.handler.is_none() {
                continue;
            }

            providers.push(ProviderInventory {
                provider: selected.provider,
                interface: selected.implementation.interface.clone(),
                implementation: selected.reference,
                state: ProviderState::Planned,
                incarnation: None,
                guarantees: selected.implementation.guarantees.clone(),
            });
        }
        providers.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
        });
        providers.dedup();
        let mut published_resources = self
            .fixed_point
            .resolved_resources
            .values()
            .filter(|resource| resource.controller.is_none())
            .map(|resource| resource.resource_revision())
            .collect::<Result<Vec<_>>>()?;
        published_resources.sort_by(|left, right| left.resource.cmp(&right.resource));

        Ok(EnvironmentDocument {
            schema: EnvironmentDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment,
            platform,
            policy_revision: self.revision,
            providers,
            artifacts: artifacts_by_content.into_values().collect(),
            // Pure planning publications have no lifecycle controller and
            // therefore are not changes for effectful activation.
            resources: published_resources,
            controllers: Vec::new(),
            guarantees: Vec::new(),
            freshness: FreshnessCondition {
                generation: self.revision,
                max_age_millis: aos_ability_model::MAX_SAFE_INTEGER,
            },
        })
    }

    fn desired_state(&self, environment: Sha256Digest) -> Result<DesiredStateDocument> {
        let package_digests = self
            .catalog
            .packages
            .iter()
            .map(|package| Ok((package.package.name.clone(), package.content_digest()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut instances = self
            .fixed_point
            .instances
            .iter()
            .map(|(name, instance)| {
                Ok(DesiredInstance {
                    instance: self.instance_identity(name)?.clone(),
                    authority: instance.provenance.authority.clone(),
                    package: instance
                        .package
                        .as_ref()
                        .map(|package| {
                            package_digests.get(package).copied().with_context(|| {
                                format!("source instance {name:?} references an absent package")
                            })
                        })
                        .transpose()?,
                    enabled: true,
                    configuration: Some(instance.configuration.clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        instances.sort_by(|left, right| left.instance.cmp(&right.instance));

        let mut requests = self
            .fixed_point
            .requests
            .iter()
            .chain(&self.fixed_point.composition_requests)
            .map(|(name, request)| self.binding_request(name, request))
            .collect::<Result<Vec<_>>>()?;
        requests.sort_by(|left, right| left.id.cmp(&right.id));

        let mut contributions = self
            .fixed_point
            .bindings
            .iter()
            .map(|(name, binding)| self.contribution(name, binding))
            .collect::<Result<Vec<_>>>()?;
        contributions.sort_by(|left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.slot.cmp(&right.slot))
        });

        let mut resources = self
            .fixed_point
            .resolved_resources
            .values()
            .map(|resource| resource.resource_revision())
            .collect::<Result<Vec<_>>>()?;
        resources.sort_by(|left, right| left.resource.cmp(&right.resource));
        let mut controllers = self
            .fixed_point
            .resolved_resources
            .values()
            .filter_map(|resource| {
                resource.controller.as_deref().map(|binding| {
                    resource
                        .resource_revision()
                        .and_then(|revision| self.controller(&revision, binding))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        controllers.sort_by(|left, right| left.resource.cmp(&right.resource));
        let mut outputs = self.outputs()?;
        outputs.sort_by(|left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.interface.cmp(&right.interface))
                .then_with(|| left.port.cmp(&right.port))
        });

        Ok(DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment,
            instances,
            contributions,
            child_requests: requests,
            resources,
            outputs,
            controllers,
        })
    }

    fn binding_document(
        &self,
        environment: &EnvironmentDocument,
        desired: &DesiredStateDocument,
    ) -> Result<BindingPlanDocument> {
        let mut bindings = self
            .fixed_point
            .bindings
            .iter()
            .map(|(name, binding)| self.binding(name, binding))
            .collect::<Result<Vec<_>>>()?;
        bindings.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(BindingPlanDocument {
            schema: BindingPlanDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired.content_digest()?,
            environment: environment.content_digest()?,
            policy_revision: self.revision,
            requests: desired.child_requests.clone(),
            bindings,
            resources: desired.resources.clone(),
            obligations: Vec::new(),
        })
    }

    fn binding_request(&self, name: &str, source: &SourceStageRequest) -> Result<BindingRequest> {
        let requirement = self.requirement(name, source)?;
        let accepted_interfaces = requirement
            .accepted_interfaces
            .iter()
            .map(|selector| {
                let matches = self
                    .catalog
                    .interfaces
                    .iter()
                    .filter_map(|interface| interface.interface_key().ok())
                    .filter(|key| selector.matches(key))
                    .collect::<Vec<_>>();
                let [selected] = matches.as_slice() else {
                    bail!("source request {name:?} does not select one exact interface")
                };
                Ok((*selected).clone())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(BindingRequest {
            authority: source.provenance.authority.clone(),
            id: RequestId {
                consumer: self.instance_identity(&source.consumer)?.clone(),
                scope: source.scope.clone(),
                key: source.provenance.local_key.clone(),
            },
            accepted_interfaces,
            methods: requirement.methods.clone(),
            guarantees: requirement.guarantees.clone(),
            lifetime: source.lifetime,
            parameters: source.parameters.clone(),
        })
    }

    fn binding(&self, name: &str, source: &SourceStageBinding) -> Result<Binding> {
        let request_source = self.request(&source.request)?;
        let request = self.binding_request(&source.request, request_source)?;
        let selected = self.selected_implementation(name, source)?;
        let id = binding_id(name, source, &request.id)?;
        let contribution = ContributionPermission {
            aggregate: AggregateId {
                provider: selected.provider.clone(),
                group: selected
                    .interface
                    .interface
                    .aggregation
                    .controller_group
                    .clone(),
            },
            slot: source.slot.clone(),
        };
        let delegated_controller = if let Some(owner_request_name) = &request_source.owner_request {
            ensure!(
                self.fixed_point
                    .composition_requests
                    .contains_key(&source.request),
                "only a provider child request can delegate resource control"
            );
            let (owner_binding_name, owner_binding) = self
                .binding_by_request
                .get(owner_request_name.as_str())
                .context("delegated resource owner has no selected binding")?;
            let owner_implementation =
                self.selected_implementation(owner_binding_name, owner_binding)?;
            ensure!(
                owner_binding.provider_instance == request_source.consumer
                    && request_source.provenance.authority.package()
                        == Some(&owner_implementation.package.package.name),
                "child resource delegation differs from its selected parent request"
            );
            if owner_binding.provider_instance == source.provider_instance
                && owner_binding.slot == source.slot
            {
                Some(*owner_binding_name)
            } else {
                None
            }
        } else {
            None
        };
        let controlled_resources = self
            .fixed_point
            .resolved_resources
            .values()
            .filter(|resource| {
                resource.controller.as_deref() == Some(name)
                    || delegated_controller.is_some_and(|controller| {
                        resource.controller.as_deref() == Some(controller)
                            && resource.resource.key == source.slot
                    })
            })
            .map(|resource| {
                let matching_methods = request
                    .methods
                    .iter()
                    .filter(|method_name| {
                        selected
                            .interface
                            .interface
                            .methods
                            .get(*method_name)
                            .is_some_and(|method| method.target_resource == resource.kind)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let has_write_method = matching_methods.iter().any(|method_name| {
                    selected
                        .interface
                        .interface
                        .methods
                        .get(method_name)
                        .is_some_and(|method| {
                            method.semantics.required_target_access == AccessMode::ExclusiveWrite
                        })
                });
                if !has_write_method {
                    ensure!(
                        resource.controller.as_deref() != Some(name),
                        "source binding {name:?} has no selected exclusive-write method for resource {:?} of kind {:?}",
                        resource.resource,
                        resource.kind
                    );
                    Ok(None)
                } else {
                    Ok(Some((resource.resource.clone(), matching_methods)))
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut resource_grants: BTreeMap<ResourceId, (AccessMode, BTreeSet<LocalKey>)> =
            BTreeMap::new();
        for (resource, operations) in controlled_resources {
            resource_grants.insert(
                resource,
                (AccessMode::ExclusiveWrite, operations.into_iter().collect()),
            );
        }
        let mut references = Vec::new();
        collect_resource_references(request.parameters.as_json(), &mut references)?;
        for reference in references {
            ensure!(
                !reference.operations.is_empty(),
                "source request resource reference names no read operation"
            );
            let interface = &self.catalog.interfaces[*self
                .catalog
                .interface_by_key
                .get(&reference.interface)
                .context("source request references an unavailable interface")?];
            ensure!(
                self.fixed_point
                    .resolved_resources
                    .values()
                    .any(|resource| {
                        resource.resource == reference.resource
                            && resource.lifetime == reference.lifetime
                            && reference.operations.iter().all(|operation| {
                                interface
                                    .interface
                                    .methods
                                    .get(operation)
                                    .is_some_and(|method| {
                                        method.target_resource == resource.kind
                                            && method.semantics.required_target_access
                                                == AccessMode::Read
                                    })
                            })
                    }),
                "source request references a resource absent from the completed fixed point"
            );
            let grant = resource_grants
                .entry(reference.resource)
                .or_insert_with(|| (AccessMode::Read, BTreeSet::new()));
            grant.1.extend(reference.operations);
        }
        let resources = resource_grants
            .into_iter()
            .map(|(resource, (access, operations))| ResourcePermission {
                resource,
                access,
                operations: operations.into_iter().collect(),
            })
            .collect();
        Ok(Binding {
            id,
            request: request.id.clone(),
            interface: selected.implementation.interface.clone(),
            provider: selected.provider.clone(),
            provider_package: Some(selected.package.content_digest()?),
            implementation: selected.reference,
            source: BindingSource::Explicit,
            caller_grant: AuthorityGrant {
                principal: request.id.consumer,
                methods: request.methods,
                contributions: vec![contribution],
                resources,
            },
            provider_grant: AuthorityGrant {
                principal: selected.provider,
                methods: Vec::new(),
                contributions: Vec::new(),
                resources: Vec::new(),
            },
            guarantees: selected.implementation.guarantees.clone(),
            policy_revision: self.revision,
            lifetime: request.lifetime,
            mediation_allowed: false,
        })
    }

    fn contribution(&self, name: &str, source: &SourceStageBinding) -> Result<Contribution> {
        let request_source = self.request(&source.request)?;
        let request = self.binding_request(&source.request, request_source)?;
        let selected = self.selected_implementation(name, source)?;
        Ok(Contribution {
            request: request.id.clone(),
            aggregate: AggregateId {
                provider: selected.provider,
                group: selected
                    .interface
                    .interface
                    .aggregation
                    .controller_group
                    .clone(),
            },
            slot: source.slot.clone(),
            grant: binding_id(name, source, &request.id)?,
            value: request.parameters,
        })
    }

    fn controller(
        &self,
        resource: &aos_ability_model::ResourceRevision,
        binding_name: &str,
    ) -> Result<ControllerAssignment> {
        let binding = self
            .fixed_point
            .bindings
            .get(binding_name)
            .with_context(|| format!("resource controller {binding_name:?} is absent"))?;
        let selected = self.selected_implementation(binding_name, binding)?;
        ensure!(
            selected.provider == resource.resource.provider,
            "resource controller provider differs from its resource identity"
        );
        Ok(ControllerAssignment {
            resource: resource.resource.clone(),
            controller: AggregateId {
                provider: selected.provider,
                group: selected
                    .interface
                    .interface
                    .aggregation
                    .controller_group
                    .clone(),
            },
        })
    }

    fn outputs(&self) -> Result<Vec<AggregateOutput>> {
        let mut outputs = Vec::new();
        for (request_name, ports) in &self.fixed_point.composition_outputs {
            let (_, binding) = self
                .binding_by_request
                .get(request_name.as_str())
                .with_context(|| format!("output request {request_name:?} has no binding"))?;
            let selected = self.selected_implementation(request_name, binding)?;
            for (port_name, output) in ports {
                let port = LocalKey::new(port_name.clone())?;
                let descriptor = selected
                    .interface
                    .interface
                    .outputs
                    .get(&port)
                    .with_context(|| {
                        format!("output {request_name:?}/{port_name:?} is undeclared")
                    })?;
                ensure!(
                    descriptor.phase == output.phase && descriptor.lifetime == output.lifetime,
                    "source output descriptor differs from its interface contract"
                );
                outputs.push(AggregateOutput {
                    aggregate: AggregateId {
                        provider: selected.provider.clone(),
                        group: selected
                            .interface
                            .interface
                            .aggregation
                            .controller_group
                            .clone(),
                    },
                    interface: selected.implementation.interface.clone(),
                    port,
                    value: value_expression(output.value.as_json())?,
                });
            }
        }
        Ok(outputs)
    }

    fn request(&self, name: &str) -> Result<&'a SourceStageRequest> {
        self.fixed_point
            .requests
            .get(name)
            .or_else(|| self.fixed_point.composition_requests.get(name))
            .with_context(|| format!("source binding names absent request {name:?}"))
    }

    fn requirement(
        &self,
        name: &str,
        source: &SourceStageRequest,
    ) -> Result<&'a aos_ability_model::RequirementDeclaration> {
        match &source.requirement {
            SourceStageRequirementReference::FixedPoint { declaration } => {
                ensure!(
                    self.fixed_point.requests.contains_key(name),
                    "child request references a root fixed-point requirement"
                );
                self.fixed_point
                    .requirements
                    .get(declaration)
                    .with_context(|| format!("source root request {name:?} has no requirement"))
            }
            SourceStageRequirementReference::Composition { declaration } => {
                ensure!(
                    self.fixed_point.composition_requests.contains_key(name),
                    "root request references a composition requirement"
                );
                Ok(&self
                    .fixed_point
                    .composition_requirements
                    .get(declaration)
                    .with_context(|| format!("source child request {name:?} has no requirement"))?
                    .requirement)
            }
        }
    }

    fn selected_implementation(
        &self,
        binding_name: &str,
        binding: &SourceStageBinding,
    ) -> Result<SelectedImplementation<'a>> {
        let instance = self
            .fixed_point
            .instances
            .get(&binding.provider_instance)
            .with_context(|| format!("binding {binding_name:?} has no provider instance"))?;
        ensure!(
            instance.accepts_binding_package(&binding.implementation.package),
            "binding crosses package provenance"
        );
        let package = self.package(&binding.implementation.package)?;
        let implementation = package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.name == binding.implementation.local_key)
            .with_context(|| format!("binding {binding_name:?} has no implementation"))?;
        let descriptor = implementation.descriptor_digest()?;
        ensure!(
            package.exports.iter().any(|export| {
                export.implementation_name == implementation.name
                    && export.implementation == descriptor
                    && export.interface == implementation.interface
            }),
            "binding {binding_name:?} selects an unexported implementation"
        );
        let interface = &self.catalog.interfaces[*self
            .catalog
            .interface_by_key
            .get(&implementation.interface)
            .context("selected implementation interface is absent")?];
        Ok(SelectedImplementation {
            package,
            implementation,
            interface,
            provider: self.instance_identity(&binding.provider_instance)?.clone(),
            reference: ProviderImplementationReference {
                descriptor,
                artifact: implementation.artifact.clone(),
                handler: implementation.handler.clone(),
            },
        })
    }

    fn package(&self, name: &LocalKey) -> Result<&'a PackageDocument> {
        self.catalog
            .package_by_name
            .get(name)
            .map(|index| &self.catalog.packages[*index])
            .with_context(|| format!("source fixed point names absent package {name:?}"))
    }

    fn instance_identity(&self, name: &str) -> Result<&'a InstanceId> {
        self.fixed_point
            .instance_identities
            .get(name)
            .with_context(|| format!("source fixed point names absent instance {name:?}"))
    }
}

fn binding_id(name: &str, binding: &SourceStageBinding, request: &RequestId) -> Result<BindingId> {
    #[derive(Serialize)]
    struct BindingIdentity<'a> {
        schema: &'static str,
        declaration: &'a str,
        selection: &'a SourceStageBinding,
        request: &'a RequestId,
    }
    let digest = Sha256Digest::of_canonical(
        "aos.ability.source-binding/v1",
        &BindingIdentity {
            schema: "aos.ability.source-binding/v1",
            declaration: name,
            selection: binding,
            request,
        },
    )?;
    Ok(BindingId(LocalKey::new(format!(
        "source-{}",
        digest.hex()
    ))?))
}

fn value_expression(value: &serde_json::Value) -> Result<ValueExpression> {
    let marker = value
        .as_object()
        .and_then(|object| object.get("_type"))
        .and_then(serde_json::Value::as_str);
    match marker {
        Some("aos-resource-reference") => {
            let mut reference = value.clone();
            reference
                .as_object_mut()
                .context("resource reference is not an object")?
                .remove("_type");
            Ok(ValueExpression::ResourceReference {
                reference: serde_json::from_value(reference)?,
            })
        }
        Some("aos-artifact-reference") => {
            let mut reference = value.clone();
            reference
                .as_object_mut()
                .context("artifact reference is not an object")?
                .remove("_type");
            Ok(ValueExpression::ArtifactReference {
                reference: serde_json::from_value(reference)?,
            })
        }
        Some("aos-runtime-path") => {
            let object = value.as_object().context("runtime path is not an object")?;
            Ok(ValueExpression::PathWithin {
                base: Box::new(value_expression(
                    object.get("base").context("runtime path has no base")?,
                )?),
                relative_path: serde_json::from_value(
                    object
                        .get("relative_path")
                        .context("runtime path has no relative path")?
                        .clone(),
                )?,
            })
        }
        _ if contains_typed_reference(value) => match value {
            serde_json::Value::Array(items) => Ok(ValueExpression::List {
                items: items
                    .iter()
                    .map(value_expression)
                    .collect::<Result<Vec<_>>>()?,
            }),
            serde_json::Value::Object(fields) => Ok(ValueExpression::Object {
                fields: fields
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), value_expression(value)?)))
                    .collect::<Result<_>>()?,
            }),
            _ => bail!("typed source output reference occurs under a scalar value"),
        },
        _ => Ok(ValueExpression::Literal {
            value: aos_ability_model::AbilityValue::new(value.clone())?,
        }),
    }
}

fn contains_typed_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(contains_typed_reference),
        serde_json::Value::Object(fields) => {
            fields
                .get("_type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|marker| {
                    matches!(
                        marker,
                        "aos-resource-reference" | "aos-artifact-reference" | "aos-runtime-path"
                    )
                })
                || fields.values().any(contains_typed_reference)
        }
        _ => false,
    }
}

fn collect_resource_references(
    value: &serde_json::Value,
    references: &mut Vec<ResourceReference>,
) -> Result<()> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_resource_references(item, references)?;
            }
        }
        serde_json::Value::Object(fields)
            if fields.len() == 4
                && fields.contains_key("interface")
                && fields.contains_key("resource")
                && fields.contains_key("operations")
                && fields.contains_key("lifetime") =>
        {
            references.push(serde_json::from_value(value.clone())?);
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                collect_resource_references(item, references)?;
            }
        }
        _ => {}
    }
    Ok(())
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
