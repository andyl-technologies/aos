//! Symbolic package ability projections and their orchestration-time resolution.
//!
//! Package builds emit this closed projection without realizing or inspecting
//! any selected output. Release and image orchestrators resolve each package
//! output selector through their authenticated artifact inventory, then
//! validate the resulting public package document.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_ability_model::document::PackageSubject;
use aos_ability_model::{
    AbilityActivationMode, ArtifactReference, ExportDeclaration, GuaranteeDeclaration,
    GuaranteeKey, HandlerDescriptor, InterfaceDocument, InterfaceKey, InterfaceName, LocalKey,
    ModuleLocator, PackageDocument, PackageImplementation, PackageOptionDeclaration, PackageProbe,
    PackageProbeArtifact, PackageProbeHarness, PackageProbeOperation, PackageProbeStep,
    PackageProbeTemplate, PackageProbeTemplateFragment, PackageQualification,
    ProviderImplementation, ProviderQualification, ProviderStateFormat, RelativePath,
    RequiredFeature, RequirementDeclaration, ValueSchema, VersionedDocument,
    validate_package_option_declarations,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Exact schema emitted by package ability projection outputs.
pub const PACKAGE_PROJECTION_SCHEMA: &str = "aos.ability.package-projection/v1";

/// Exact authoring marker for a symbolic package output selector.
pub const PACKAGE_OUTPUT_SELECTOR_MARKER: &str = "aos-package-output-selector";

/// Exact authoring marker for a symbolic evaluated configuration artifact selector.
pub const CONFIG_ARTIFACT_SELECTOR_MARKER: &str = "aos-config-artifact-selector";

/// Selects one named output from a package in the enclosing orchestration set.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOutputSelector {
    /// Package name, or 'self' for the package owning the projection.
    pub package: LocalKey,
    /// Nix output name.
    pub output: LocalKey,
}

/// Selects one named artifact from the enclosing evaluated system configuration.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigArtifactSelector {
    /// Name in the authoritative `aos.config.artifacts` projection.
    pub name: LocalKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaggedPackageOutputSelector {
    #[serde(rename = "_type")]
    marker: String,
    package: LocalKey,
    output: LocalKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaggedConfigArtifactSelector {
    #[serde(rename = "_type")]
    marker: String,
    name: LocalKey,
}

struct PackageOutputResolver<F> {
    resolved: BTreeMap<PackageOutputSelector, ArtifactReference>,
    resolve: F,
}

impl<F> PackageOutputResolver<F>
where
    F: FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
{
    fn new(resolve: F) -> Self {
        Self {
            resolved: BTreeMap::new(),
            resolve,
        }
    }

    fn select(&mut self, selector: &PackageOutputSelector) -> Result<ArtifactReference> {
        if let Some(artifact) = self.resolved.get(selector) {
            return Ok(artifact.clone());
        }
        let artifact = (self.resolve)(selector).with_context(|| {
            format!(
                "resolving ability artifact selector ({}, {})",
                selector.package.as_str(),
                selector.output.as_str()
            )
        })?;
        self.resolved.insert(selector.clone(), artifact.clone());
        Ok(artifact)
    }
}

struct ArtifactSelectorResolver<P, C> {
    packages: PackageOutputResolver<P>,
    config_artifacts: BTreeMap<ConfigArtifactSelector, ArtifactReference>,
    resolve_config_artifact: C,
}

impl<P, C> ArtifactSelectorResolver<P, C>
where
    P: FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
    C: FnMut(&ConfigArtifactSelector) -> Result<ArtifactReference>,
{
    fn resolve_value(&mut self, value: &mut serde_json::Value, depth: u32) -> Result<()> {
        if depth > aos_ability_model::ABILITY_LIMITS_V1.max_structural_depth {
            bail!("symbolic ability value exceeds the structural depth limit");
        }

        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    self.resolve_value(value, depth.saturating_add(1))?;
                }
            }
            serde_json::Value::Object(fields)
                if fields.get("_type").and_then(serde_json::Value::as_str)
                    == Some(PACKAGE_OUTPUT_SELECTOR_MARKER) =>
            {
                let tagged: TaggedPackageOutputSelector = serde_json::from_value(value.clone())
                    .context("decoding symbolic package output selector")?;
                if tagged.marker != PACKAGE_OUTPUT_SELECTOR_MARKER {
                    bail!("symbolic package output selector has an invalid marker");
                }
                let artifact = self.packages.select(&PackageOutputSelector {
                    package: tagged.package,
                    output: tagged.output,
                })?;
                *value = serde_json::to_value(artifact)
                    .context("encoding resolved package output artifact")?;
            }
            serde_json::Value::Object(fields)
                if fields.get("_type").and_then(serde_json::Value::as_str)
                    == Some(CONFIG_ARTIFACT_SELECTOR_MARKER) =>
            {
                let tagged: TaggedConfigArtifactSelector = serde_json::from_value(value.clone())
                    .context("decoding symbolic configuration artifact selector")?;
                if tagged.marker != CONFIG_ARTIFACT_SELECTOR_MARKER {
                    bail!("symbolic configuration artifact selector has an invalid marker");
                }
                let selector = ConfigArtifactSelector { name: tagged.name };
                let artifact = if let Some(artifact) = self.config_artifacts.get(&selector) {
                    artifact.clone()
                } else {
                    let artifact =
                        (self.resolve_config_artifact)(&selector).with_context(|| {
                            format!(
                                "resolving evaluated configuration artifact selector '{}'",
                                selector.name.as_str()
                            )
                        })?;
                    self.config_artifacts.insert(selector, artifact.clone());
                    artifact
                };
                *value = serde_json::to_value(artifact)
                    .context("encoding resolved configuration artifact")?;
            }
            serde_json::Value::Object(fields) => {
                for value in fields.values_mut() {
                    self.resolve_value(value, depth.saturating_add(1))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Resolves symbolic artifact selectors nested in one evaluated ability value.
///
/// Only exact closed package-output and evaluated-configuration selector
/// objects are replaced. Relative entry points, file paths, and arguments
/// remain ordinary portable data around the resolved [`ArtifactReference`].
///
/// # Errors
///
/// Returns an error when a tagged selector is malformed, cannot be resolved,
/// or exceeds the version-1 structural-depth limit.
pub fn resolve_artifact_selectors(
    value: &mut serde_json::Value,
    resolve_package_output: impl FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
    resolve_config_artifact: impl FnMut(&ConfigArtifactSelector) -> Result<ArtifactReference>,
) -> Result<()> {
    ArtifactSelectorResolver {
        packages: PackageOutputResolver::new(resolve_package_output),
        config_artifacts: BTreeMap::new(),
        resolve_config_artifact,
    }
    .resolve_value(value, 1)
}

/// Identifies the package owning a symbolic ability projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProjectionSubject {
    /// Canonical package name.
    pub name: LocalKey,
    /// Public package version.
    pub version: String,
}

/// Declares an export before its implementation artifact is resolved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportProjection {
    /// Name of the package export.
    pub name: LocalKey,
    /// Exact public interface identity.
    pub interface: InterfaceKey,
    /// Names the exact projected implementation for this export.
    pub implementation: LocalKey,
}

/// Selects the artifact declaring one persistent provider state format.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateFormatProjection {
    /// Canonical state-format descriptor.
    pub descriptor: Sha256Digest,
    /// Symbolic artifact selector.
    pub artifact: PackageOutputSelector,
}

/// Declares a provider implementation with a symbolic artifact selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImplementationProjection {
    /// Names this implementation within the package projection.
    pub name: LocalKey,
    /// Describes this implementation in the signed package document.
    pub description: String,
    /// Exact public interface implemented by this provider.
    pub interface: InterfaceKey,
    /// Exact execution guarantees supplied by this provider.
    pub guarantees: Vec<GuaranteeKey>,
    /// Symbolic implementation artifact.
    pub artifact: PackageOutputSelector,
    /// Lower-interface requirements.
    pub requirements: Vec<RequirementDeclaration>,
    /// Resource kinds controlled by this implementation on the current signed schema.
    pub owns_resource_kinds: Vec<InterfaceName>,
    /// Portable realization schema for the selected provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_schema: Option<ValueSchema>,
    /// Symbolic locator for selected pure provider semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_module: Option<ModuleLocatorProjection>,
    /// Optional handler catalog entry used by runtime operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<LocalKey>,
    /// Optional persistent-state format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_format: Option<ProviderStateFormatProjection>,
}

/// Declares a terminal handler with a symbolic artifact selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerProjection {
    /// Symbolic executable artifact.
    pub artifact: PackageOutputSelector,
    /// Relative executable entry point.
    pub entry_point: String,
    /// Portable handler argument schema.
    pub arguments: ValueSchema,
    /// Portable handler result schema.
    pub result: ValueSchema,
}

/// Locates one provider module through a symbolic artifact selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLocatorProjection {
    /// Symbolic artifact containing the provider module.
    pub artifact: PackageOutputSelector,
    /// Normalized module file below the selected artifact root.
    pub path: RelativePath,
}

/// Collects unresolved provider and handler declarations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImplementationProjection {
    /// Provider declarations in canonical interface order.
    pub providers: Vec<ProviderImplementationProjection>,
    /// Handler declarations keyed by local handler name.
    pub handlers: BTreeMap<LocalKey, HandlerProjection>,
}

/// Declares package-owned native qualification evidence for one implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProjection {
    /// Semantic conformance families claimed by the implementation.
    pub conformance_families: Vec<LocalKey>,
    /// Package-owned observer used to collect independent qualification evidence.
    pub observer: HandlerProjection,
}

/// Collects every symbolic package-owned qualification declaration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageQualificationProjection {
    /// Defines the package's functional probe, when one is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_probe: Option<PackageProbeProjection>,
    /// Maps implementation aliases to package-owned qualification claims.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub implementations: BTreeMap<LocalKey, QualificationProjection>,
}

/// Defines the symbolic package functional probe embedded in a projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProbeProjection {
    /// Exercises one representative successful package operation.
    pub primary: PackageProbeOperationProjection,
    /// Exercises one malformed or unsupported input that must be rejected.
    pub bad_input: PackageProbeOperationProjection,
}

/// Defines one symbolic package-probe operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProbeOperationProjection {
    /// Describes the supplied input.
    pub input: String,
    /// Describes the operation under test.
    pub operation: String,
    /// Describes the expected semantic result.
    pub expected: String,
    /// Maps confined work paths to exact input contents.
    pub files: BTreeMap<RelativePath, PackageProbeTemplateProjection>,
    /// Lists commands in their required execution order.
    pub steps: Vec<PackageProbeStepProjection>,
    /// Lists exact artifacts observed after the commands finish.
    pub artifacts: Vec<PackageProbeArtifact>,
}

/// Defines one symbolic package-probe command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProbeStepProjection {
    /// Supplies the executable and arguments as typed templates.
    pub argv: Vec<PackageProbeTemplateProjection>,
    /// Supplies standard input, when required.
    pub stdin: Option<PackageProbeTemplateProjection>,
    /// Checks exact standard output, when present.
    pub stdout: Option<PackageProbeTemplateProjection>,
    /// Checks exact standard error, when present.
    pub stderr: Option<PackageProbeTemplateProjection>,
    /// Selects the expected process status.
    pub exit_code: u8,
    /// Bounds command execution time in seconds.
    pub timeout_seconds: Option<u16>,
    /// Records whether the step independently demonstrates rejection.
    pub observes_rejection: bool,
}

/// Builds one projected probe string from explicit typed fragments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProbeTemplateProjection {
    /// Lists fragments concatenated to form the final string.
    pub fragments: Vec<PackageProbeTemplateFragmentProjection>,
}

/// Selects one explicit source for a projected probe fragment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PackageProbeTemplateFragmentProjection {
    /// Emits exact package-authored text.
    Literal {
        /// Supplies the literal text.
        text: String,
    },
    /// Emits the root of one symbolically selected package artifact.
    ArtifactRoot {
        /// Selects the package artifact.
        artifact: PackageOutputSelector,
    },
    /// Emits a path beneath one symbolic package output.
    ArtifactPath {
        /// Selects the package output.
        artifact: PackageOutputSelector,
        /// Selects a path beneath the output root.
        path: RelativePath,
    },
    /// Emits a path beneath the operation's confined work directory.
    WorkPath {
        /// Selects a path beneath the work root.
        path: RelativePath,
    },
    /// Emits the exact executable path for one qualification harness tool.
    Harness {
        /// Selects the bounded harness tool.
        tool: PackageProbeHarness,
    },
}

/// Carries one canonical interface document emitted with the projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDocumentProjection {
    /// Descriptor derived from the canonical interface document envelope.
    pub descriptor: Sha256Digest,
    /// Canonical public interface document.
    pub document: InterfaceDocument,
}

/// Canonical package-authored ability projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAbilityProjection {
    /// Carries PACKAGE_PROJECTION_SCHEMA.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Selects the package activation mode.
    pub activation_mode: AbilityActivationMode,
    /// Identifies the owning package.
    pub package: PackageProjectionSubject,
    /// Lists additional artifacts selected for retention.
    pub artifacts: Vec<PackageOutputSelector>,
    /// Maps package-local interface declaration aliases to exact public identities.
    pub interfaces: BTreeMap<LocalKey, InterfaceKey>,
    /// Maps package-local guarantee aliases to authored semantics and documentation.
    pub guarantees: BTreeMap<LocalKey, GuaranteeDeclaration>,
    /// Symbolic locator for the package's executable ability/configuration module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_module: Option<ModuleLocatorProjection>,
    /// Retains package-owned option declarations from the authenticated module evaluation.
    pub option_declarations: Vec<PackageOptionDeclaration>,
    /// Lists public exports in canonical name order.
    pub exports: Vec<ExportProjection>,
    /// Carries the pure interface documents retained by this projection.
    pub interface_documents: Vec<InterfaceDocumentProjection>,
    /// Lists package-level requirements.
    pub requirements: Vec<RequirementDeclaration>,
    /// Contains symbolic provider and handler declarations.
    pub implementation: PackageImplementationProjection,
    /// Contains every package-owned qualification declaration.
    pub qualification: PackageQualificationProjection,
}

/// Decodes one canonical, bounded package ability projection.
///
/// # Errors
///
/// Returns an error when the input is empty, too large, noncanonical,
/// structurally invalid, or carries an unsupported projection schema.
pub fn decode_package_projection(bytes: &[u8]) -> Result<PackageAbilityProjection> {
    let limit = aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes as usize;
    if bytes.is_empty() || bytes.len() > limit {
        bail!("ability package projection size is outside 1..={limit}");
    }
    aos_contract::canonical::require_canonical(bytes, "ability package projection")?;
    let projection: PackageAbilityProjection =
        serde_json::from_slice(bytes).context("decoding ability package projection")?;
    if projection.schema != PACKAGE_PROJECTION_SCHEMA {
        bail!(
            "unsupported ability package projection schema '{}'",
            projection.schema
        );
    }
    validate_projection_structure(&projection)?;
    validate_projected_interfaces(&projection)?;
    Ok(projection)
}

fn resolve_probe_template<F>(
    template: PackageProbeTemplateProjection,
    resolver: &mut PackageOutputResolver<F>,
) -> Result<PackageProbeTemplate>
where
    F: FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
{
    let fragments = template
        .fragments
        .into_iter()
        .map(|fragment| match fragment {
            PackageProbeTemplateFragmentProjection::Literal { text } => {
                Ok(PackageProbeTemplateFragment::Literal { text })
            }
            PackageProbeTemplateFragmentProjection::ArtifactRoot { artifact } => {
                Ok(PackageProbeTemplateFragment::ArtifactRoot {
                    artifact: resolver.select(&artifact)?,
                })
            }
            PackageProbeTemplateFragmentProjection::ArtifactPath { artifact, path } => {
                Ok(PackageProbeTemplateFragment::ArtifactPath {
                    artifact: resolver.select(&artifact)?,
                    path,
                })
            }
            PackageProbeTemplateFragmentProjection::WorkPath { path } => {
                Ok(PackageProbeTemplateFragment::WorkPath { path })
            }
            PackageProbeTemplateFragmentProjection::Harness { tool } => {
                Ok(PackageProbeTemplateFragment::Harness { tool })
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PackageProbeTemplate { fragments })
}

fn resolve_probe_operation<F>(
    operation: PackageProbeOperationProjection,
    resolver: &mut PackageOutputResolver<F>,
) -> Result<PackageProbeOperation>
where
    F: FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
{
    let files = operation
        .files
        .into_iter()
        .map(|(path, template)| Ok((path, resolve_probe_template(template, resolver)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let steps = operation
        .steps
        .into_iter()
        .map(|step| {
            Ok(PackageProbeStep {
                argv: step
                    .argv
                    .into_iter()
                    .map(|template| resolve_probe_template(template, resolver))
                    .collect::<Result<Vec<_>>>()?,
                stdin: step
                    .stdin
                    .map(|template| resolve_probe_template(template, resolver))
                    .transpose()?,
                stdout: step
                    .stdout
                    .map(|template| resolve_probe_template(template, resolver))
                    .transpose()?,
                stderr: step
                    .stderr
                    .map(|template| resolve_probe_template(template, resolver))
                    .transpose()?,
                exit_code: step.exit_code,
                timeout_seconds: step.timeout_seconds,
                observes_rejection: step.observes_rejection,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PackageProbeOperation {
        input: operation.input,
        operation: operation.operation,
        expected: operation.expected,
        files,
        steps,
        artifacts: operation.artifacts,
    })
}

fn resolve_package_probe<F>(
    probe: PackageProbeProjection,
    resolver: &mut PackageOutputResolver<F>,
) -> Result<PackageProbe>
where
    F: FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
{
    Ok(PackageProbe {
        primary: resolve_probe_operation(probe.primary, resolver)?,
        bad_input: resolve_probe_operation(probe.bad_input, resolver)?,
    })
}

/// Resolves one package projection into the public package document.
///
/// The payload and source come from the enclosing release or image
/// orchestration. The resolver must bind every symbolic selector through that
/// orchestration's exact package-output inventory.
///
/// # Errors
///
/// Returns an error when a selector cannot be resolved, an export lacks one
/// exact provider, or an implementation descriptor cannot be computed.
pub fn resolve_package_projection(
    projection: PackageAbilityProjection,
    payload: ArtifactReference,
    source: ArtifactReference,
    resolve: impl FnMut(&PackageOutputSelector) -> Result<ArtifactReference>,
) -> Result<PackageDocument> {
    validate_projected_interfaces(&projection)?;
    let mut resolver = PackageOutputResolver::new(resolve);
    let package_module = projection
        .package_module
        .map(|locator| -> Result<ModuleLocator> {
            Ok(ModuleLocator {
                artifact: resolver.select(&locator.artifact)?,
                path: locator.path,
            })
        })
        .transpose()?;
    if package_module.is_none() && projection.qualification.package_probe.is_none() {
        bail!("publishable package projection has neither a module nor a package probe");
    }

    let mut artifacts = projection
        .artifacts
        .iter()
        .map(|selector| resolver.select(selector))
        .collect::<Result<Vec<_>>>()?;
    if let Some(module) = &package_module {
        artifacts.push(module.artifact.clone());
    }
    artifacts.sort_by_key(|artifact| (artifact.content, artifact.nar_hash, artifact.closure));
    let mut semantic_identities = BTreeSet::new();
    artifacts.retain(|artifact| {
        semantic_identities.insert((artifact.content, artifact.nar_hash, artifact.closure))
    });

    let mut provider_names = BTreeMap::new();
    let providers = projection
        .implementation
        .providers
        .into_iter()
        .map(|provider| {
            let provider_name = provider.name.clone();
            let artifact = resolver.select(&provider.artifact)?;
            let state_format = provider
                .state_format
                .map(|state_format| -> Result<ProviderStateFormat> {
                    Ok(ProviderStateFormat {
                        descriptor: state_format.descriptor,
                        artifact: resolver.select(&state_format.artifact)?,
                    })
                })
                .transpose()?;
            let provider_module = provider
                .provider_module
                .map(|locator| -> Result<ModuleLocator> {
                    Ok(ModuleLocator {
                        artifact: resolver.select(&locator.artifact)?,
                        path: locator.path,
                    })
                })
                .transpose()?;
            let resolved = ProviderImplementation {
                name: provider.name,
                description: provider.description,
                interface: provider.interface,
                guarantees: provider.guarantees,
                artifact,
                requirements: provider.requirements,
                owns_resource_kinds: provider.owns_resource_kinds,
                desired_schema: provider.desired_schema,
                provider_module,
                handler: provider.handler,
                state_format,
            };
            let position = provider_names.len();
            if provider_names.insert(provider_name, position).is_some() {
                bail!("ability projection repeats an implementation name");
            }
            Ok(resolved)
        })
        .collect::<Result<Vec<_>>>()?;
    let handlers = projection
        .implementation
        .handlers
        .into_iter()
        .map(|(name, handler)| {
            Ok((
                name,
                HandlerDescriptor {
                    artifact: resolver.select(&handler.artifact)?,
                    entry_point: handler.entry_point,
                    arguments: handler.arguments,
                    result: handler.result,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let package_probe = projection
        .qualification
        .package_probe
        .map(|probe| resolve_package_probe(probe, &mut resolver))
        .transpose()?;
    let qualification = projection
        .qualification
        .implementations
        .into_iter()
        .map(|(name, qualification)| {
            let provider = provider_names
                .get(&name)
                .and_then(|position| providers.get(*position))
                .with_context(|| {
                    format!(
                        "ability qualification claim '{}' has no matching implementation",
                        name.as_str()
                    )
                })?;
            Ok((
                provider.descriptor_digest()?,
                ProviderQualification {
                    conformance_families: qualification.conformance_families,
                    observer: HandlerDescriptor {
                        artifact: resolver.select(&qualification.observer.artifact)?,
                        entry_point: qualification.observer.entry_point,
                        arguments: qualification.observer.arguments,
                        result: qualification.observer.result,
                    },
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let exports = projection
        .exports
        .into_iter()
        .map(|export| {
            let implementation_name = export.implementation.clone();
            let provider = provider_names
                .get(&export.implementation)
                .and_then(|position| providers.get(*position))
                .with_context(|| {
                    format!(
                        "ability export '{}' has no matching implementation",
                        export.name.as_str()
                    )
                })?;
            if provider.interface != export.interface {
                bail!(
                    "ability export '{}' interface differs from its implementation",
                    export.name.as_str()
                );
            }
            Ok(ExportDeclaration {
                name: export.name,
                interface: export.interface,
                implementation_name,
                implementation: provider.descriptor_digest()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: projection.required_features,
        activation_mode: projection.activation_mode,
        package: PackageSubject {
            name: projection.package.name,
            version: projection.package.version,
            payload,
            source,
        },
        artifacts,
        interfaces: projection.interfaces,
        guarantees: projection.guarantees,
        package_module,
        option_declarations: projection.option_declarations,
        exports,
        requirements: projection.requirements,
        implementation: PackageImplementation {
            providers,
            handlers,
        },
        qualification: PackageQualification {
            package_probe,
            implementations: qualification,
        },
    })
}

fn validate_projection_structure(projection: &PackageAbilityProjection) -> Result<()> {
    validate_package_option_declarations(
        &projection.option_declarations,
        &aos_ability_model::ABILITY_LIMITS_V1,
    )
    .context("validating projected package option declarations")?;
    let required_features = projection
        .required_features
        .iter()
        .map(RequiredFeature::as_str)
        .collect::<Vec<_>>();
    if required_features.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("ability projection required features are not unique and canonically ordered");
    }
    if projection
        .artifacts
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        bail!("ability projection artifact selectors are not unique and canonically ordered");
    }
    if projection
        .exports
        .windows(2)
        .any(|pair| pair[0].name >= pair[1].name)
    {
        bail!("ability projection exports are not unique and canonically ordered");
    }
    if projection
        .requirements
        .windows(2)
        .any(|pair| pair[0].alias >= pair[1].alias)
    {
        bail!("ability projection requirements are not unique and canonically ordered");
    }
    if projection.implementation.providers.windows(2).any(|pair| {
        pair[0].interface > pair[1].interface
            || (pair[0].interface == pair[1].interface && pair[0].name >= pair[1].name)
    }) {
        bail!("ability projection implementations are not in canonical interface/name order");
    }
    if projection.implementation.providers.iter().any(|provider| {
        provider
            .guarantees
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    }) {
        bail!("ability projection implementation guarantees are repeated or unordered");
    }
    let provider_names = projection
        .implementation
        .providers
        .iter()
        .map(|provider| &provider.name)
        .collect::<BTreeSet<_>>();
    for (implementation, qualification) in &projection.qualification.implementations {
        if !provider_names.contains(implementation) {
            bail!("ability qualification claim has no exact implementation");
        }
        if qualification.conformance_families.is_empty()
            || qualification
                .conformance_families
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            bail!("ability qualification families are empty, repeated, or unordered");
        }
        RelativePath::new(&qualification.observer.entry_point)
            .context("validating qualification observer entry point")?;
        if !projection
            .artifacts
            .contains(&qualification.observer.artifact)
        {
            bail!("ability qualification observer artifact is not retained");
        }
    }

    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    let value = serde_json::to_value(projection).context("projecting ability package limits")?;
    let mut collection_items = 0_u64;
    validate_projection_value_budget(&value, 1, &mut collection_items, &limits)?;
    for interface in &projection.interface_documents {
        interface.document.validate_structure(&limits)?;
    }

    Ok(())
}

fn validate_projection_value_budget(
    value: &serde_json::Value,
    depth: u32,
    collection_items: &mut u64,
    limits: &aos_ability_model::LimitProfile,
) -> Result<()> {
    if depth > limits.max_structural_depth {
        bail!("ability package projection exceeds the structural depth limit");
    }
    match value {
        serde_json::Value::Array(values) => {
            *collection_items = collection_items
                .checked_add(values.len() as u64)
                .context("ability package projection collection count overflowed")?;
            for value in values {
                validate_projection_value_budget(
                    value,
                    depth.saturating_add(1),
                    collection_items,
                    limits,
                )?;
            }
        }
        serde_json::Value::Object(fields) => {
            *collection_items = collection_items
                .checked_add(fields.len() as u64)
                .context("ability package projection collection count overflowed")?;
            for (name, value) in fields {
                if name.len() as u64 > limits.max_string_bytes {
                    bail!("ability package projection contains an oversized member name");
                }
                validate_projection_value_budget(
                    value,
                    depth.saturating_add(1),
                    collection_items,
                    limits,
                )?;
            }
        }
        serde_json::Value::String(value) if value.len() as u64 > limits.max_string_bytes => {
            bail!("ability package projection contains an oversized string");
        }
        _ => {}
    }
    if *collection_items > limits.max_collection_items {
        bail!("ability package projection exceeds the collection item limit");
    }

    Ok(())
}

fn validate_projected_interfaces(projection: &PackageAbilityProjection) -> Result<()> {
    if projection
        .interface_documents
        .windows(2)
        .any(|pair| pair[0].descriptor >= pair[1].descriptor)
    {
        bail!("retained interface documents are not in canonical descriptor order");
    }
    let mut retained = BTreeMap::new();
    for entry in &projection.interface_documents {
        let identity = entry
            .document
            .interface_key()
            .context("deriving retained interface identity")?;
        if identity.descriptor != entry.descriptor {
            bail!("retained interface descriptor differs from its document");
        }
        if retained.insert(identity.clone(), ()).is_some() {
            bail!("ability projection repeats a retained interface document");
        }
    }

    let declared = projection
        .interfaces
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    let retained = retained.into_keys().collect::<BTreeSet<_>>();
    if declared != retained {
        bail!("package interface declarations differ from retained interface documents");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_package_projection, resolve_artifact_selectors, resolve_package_projection,
        validate_projection_value_budget,
    };
    use aos_ability_model::{
        ABILITY_LIMITS_V1, ArtifactReference, LimitProfile, LocalKey, VersionedDocument,
    };
    use aos_contract::Sha256Digest;
    use serde_json::json;

    fn artifact(label: &str, store_path: &str) -> ArtifactReference {
        ArtifactReference {
            content: Sha256Digest::of_bytes(format!("{label}-content")),
            store_path: store_path.to_string(),
            nar_hash: Sha256Digest::of_bytes(format!("{label}-nar")),
            closure: Sha256Digest::of_bytes(format!("{label}-closure")),
        }
    }

    fn projection() -> serde_json::Value {
        json!({
            "schema": "aos.ability.package-projection/v1",
            "required_features": ["abilities-v1"],
            "activation_mode": "contracts-only",
            "package": {"name": "owner", "version": "1"},
            "artifacts": [
                {"package": "dependency", "output": "bin"},
                {"package": "self", "output": "out"}
            ],
            "interfaces": {},
            "guarantees": {},
            "package_module": {
                "artifact": {"package": "self", "output": "module"},
                "path": "module.nix"
            },
            "option_declarations": [],
            "exports": [],
            "interface_documents": [],
            "requirements": [],
            "implementation": {"providers": [], "handlers": {}},
            "qualification": {"implementations": {}}
        })
    }

    fn package_probe() -> serde_json::Value {
        fn template(fragment: serde_json::Value) -> serde_json::Value {
            json!({"fragments": [fragment]})
        }

        json!({
            "primary": {
                "input": "A fixed input document.",
                "operation": "Copy the document through the package executable.",
                "expected": "The output exactly matches the input.",
                "files": {
                    "input.txt": template(json!({
                        "kind": "literal",
                        "text": "qualified input\n"
                    }))
                },
                "steps": [{
                    "argv": [
                        template(json!({
                            "kind": "artifact-path",
                            "artifact": {"package": "self", "output": "out"},
                            "path": "bin/copy"
                        })),
                        template(json!({"kind": "work-path", "path": "input.txt"}))
                    ],
                    "stdout": template(json!({
                        "kind": "literal",
                        "text": "qualified input\n"
                    })),
                    "exit_code": 0,
                    "observes_rejection": false
                }],
                "artifacts": []
            },
            "bad_input": {
                "input": "An unsupported command-line option.",
                "operation": "Invoke the package executable with that option.",
                "expected": "The executable rejects the option.",
                "files": {},
                "steps": [{
                    "argv": [
                        template(json!({"kind": "harness", "tool": "bash"})),
                        template(json!({"kind": "literal", "text": "--invalid"}))
                    ],
                    "exit_code": 2,
                    "observes_rejection": true
                }],
                "artifacts": [{
                    "kind": "text",
                    "path": "diagnostic.txt",
                    "text": "unsupported option\n"
                }]
            }
        })
    }

    fn resolve(projection: serde_json::Value) -> aos_ability_model::PackageDocument {
        let bytes = aos_contract::canonical::to_vec(&projection).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        resolve_package_projection(projection, payload.clone(), source, |selector| {
            match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
                _ => unreachable!("fixture contains only declared selectors"),
            }
        })
        .unwrap()
    }

    #[test]
    fn recursive_projection_budget_rejects_wide_values() {
        let limits = LimitProfile {
            max_collection_items: 4,
            ..ABILITY_LIMITS_V1
        };
        let value = json!([null, null, null, null, null]);
        let mut items = 0;

        assert!(validate_projection_value_budget(&value, 1, &mut items, &limits).is_err());
    }

    #[test]
    fn selector_order_matches_the_nix_projection_boundary() {
        let expected = json!([
            {"package": "ability-package-smoke", "output": "out"},
            {"package": "ability-package-smoke-provider", "output": "out"},
            {"package": "self", "output": "module"},
            {"package": "self", "output": "out"}
        ]);
        let mut canonical = projection();
        canonical["artifacts"] = expected;
        let canonical_bytes = aos_contract::canonical::to_vec(&canonical).unwrap();

        decode_package_projection(&canonical_bytes).unwrap();

        let mut output_first = canonical;
        output_first["artifacts"] = json!([
            {"package": "self", "output": "module"},
            {"package": "ability-package-smoke", "output": "out"},
            {"package": "ability-package-smoke-provider", "output": "out"},
            {"package": "self", "output": "out"}
        ]);
        let output_first_bytes = aos_contract::canonical::to_vec(&output_first).unwrap();

        assert!(decode_package_projection(&output_first_bytes).is_err());
    }

    #[test]
    fn resolves_symbolic_selectors_into_exact_artifact_references() {
        let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        let document =
            resolve_package_projection(projection, payload.clone(), source.clone(), |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("dependency", "bin") => {
                        Ok(artifact("dependency", "/nix/store/dependency-bin"))
                    }
                    ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .unwrap();

        assert_eq!(document.package.payload, payload);
        assert_eq!(document.package.source, source);
        assert_eq!(document.artifacts.len(), 3);
        assert!(
            document
                .artifacts
                .iter()
                .any(|artifact| artifact.store_path == "/nix/store/payload")
        );
        assert!(
            document
                .artifacts
                .iter()
                .any(|artifact| artifact.store_path == "/nix/store/dependency-bin")
        );
        assert!(
            document
                .artifacts
                .iter()
                .any(|artifact| artifact.store_path == "/nix/store/owner-module")
        );
    }

    #[test]
    fn resolves_probe_only_packages_without_an_ability_module() {
        let mut value = projection();
        value["package_module"] = serde_json::Value::Null;
        value["qualification"]["package_probe"] = package_probe();

        let document = resolve(value);
        let probe = document
            .qualification
            .package_probe
            .as_ref()
            .expect("package probe should be retained");
        let fragment = &probe.primary.steps[0].argv[0].fragments[0];

        assert!(document.package_module.is_none());
        assert!(matches!(
            fragment,
            aos_ability_model::PackageProbeTemplateFragment::ArtifactPath { artifact, path }
                if artifact == &document.package.payload && path.as_str() == "bin/copy"
        ));
    }

    #[test]
    fn rejects_publishable_projection_without_module_or_probe() {
        let mut value = projection();
        value["package_module"] = serde_json::Value::Null;
        let bytes = aos_contract::canonical::to_vec(&value).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        let error = resolve_package_projection(projection, payload, source, |_| {
            unreachable!("projection has no symbolic artifact references")
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("neither a module nor a package probe")
        );
    }

    #[test]
    fn rejects_open_package_probe_fragments() {
        let mut value = projection();
        value["package_module"] = serde_json::Value::Null;
        value["qualification"]["package_probe"] = package_probe();
        value["qualification"]["package_probe"]["primary"]["steps"][0]["argv"][0]["fragments"][0]
            ["unchecked"] = json!(true);
        let bytes = aos_contract::canonical::to_vec(&value).unwrap();

        assert!(decode_package_projection(&bytes).is_err());
    }

    #[test]
    fn package_probe_identity_uses_artifact_content_without_store_locator() {
        let mut value = projection();
        value["package_module"] = serde_json::Value::Null;
        value["qualification"]["package_probe"] = package_probe();
        let document = resolve(value);
        let semantic = document.content_digest().unwrap();

        let mut relocated = document.clone();
        let probe = relocated
            .qualification
            .package_probe
            .as_mut()
            .expect("package probe should be retained");
        let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
            artifact: selected_artifact,
            ..
        } = &mut probe.primary.steps[0].argv[0].fragments[0]
        else {
            panic!("fixture should retain one artifact-path fragment");
        };
        selected_artifact.store_path = "/nix/store/relocated-payload".to_string();
        assert_eq!(semantic, relocated.content_digest().unwrap());

        let mut changed = document;
        let probe = changed
            .qualification
            .package_probe
            .as_mut()
            .expect("package probe should be retained");
        let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
            artifact: selected_artifact,
            ..
        } = &mut probe.primary.steps[0].argv[0].fragments[0]
        else {
            panic!("fixture should retain one artifact-path fragment");
        };
        selected_artifact.closure = Sha256Digest::of_bytes("changed probe closure");
        assert_ne!(semantic, changed.content_digest().unwrap());
    }

    #[test]
    fn rejects_package_probe_artifacts_outside_the_retained_package_set() {
        let mut value = projection();
        value["package_module"] = serde_json::Value::Null;
        value["qualification"]["package_probe"] = package_probe();
        let mut document = resolve(value);
        let probe = document
            .qualification
            .package_probe
            .as_mut()
            .expect("package probe should be retained");
        let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
            artifact: selected_artifact,
            ..
        } = &mut probe.primary.steps[0].argv[0].fragments[0]
        else {
            panic!("fixture should retain one artifact-path fragment");
        };
        *selected_artifact = artifact("foreign", "/nix/store/foreign");

        assert!(aos_ability_model::encode_canonical(&document).is_err());
    }

    #[test]
    fn rejects_private_nix_selector_markers() {
        let mut projection = projection();
        projection["artifacts"][0]["_type"] = json!("aos-package-output-selector");
        let bytes = aos_contract::canonical::to_vec(&projection).unwrap();

        assert!(decode_package_projection(&bytes).is_err());
    }

    #[test]
    fn rejects_noncanonical_selector_order_before_resolution() {
        let mut projection = projection();
        projection["artifacts"] = json!([
            {"package": "self", "output": "out"},
            {"package": "dependency", "output": "bin"}
        ]);
        let bytes = aos_contract::canonical::to_vec(&projection).unwrap();

        let error = decode_package_projection(&bytes).unwrap_err();
        assert!(error.to_string().contains("canonically ordered"));
    }

    #[test]
    fn artifact_deduplication_uses_the_complete_semantic_identity() {
        let mut projection = projection();
        projection["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"package": "sibling", "output": "out"}));
        let bytes = aos_contract::canonical::to_vec(&projection).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        let document =
            resolve_package_projection(projection, payload.clone(), source, |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("self", "module") => Ok(artifact("module", "/nix/store/module")),
                    ("dependency", "bin") => Ok(artifact("shared", "/nix/store/dependency")),
                    ("sibling", "out") => {
                        let mut selected = artifact("shared", "/nix/store/sibling");
                        selected.closure = Sha256Digest::of_bytes(b"distinct closure");
                        Ok(selected)
                    }
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .unwrap();

        let shared_content = artifact("shared", "").content;
        assert_eq!(
            document
                .artifacts
                .iter()
                .filter(|artifact| artifact.content == shared_content)
                .count(),
            2
        );
    }

    #[test]
    fn retains_distinct_local_aliases_for_one_interface_document() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let interface = fixture.interfaces[0].clone();
        let identity = interface
            .interface_key()
            .expect("fixture interface identity should derive");
        let mut value = projection();
        value["interfaces"] = json!({
            "echo": identity,
            "echo-alias": identity,
        });
        value["interface_documents"] = json!([{
            "descriptor": identity.descriptor,
            "document": interface,
        }]);
        let bytes = aos_contract::canonical::to_vec(&value).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        let document =
            resolve_package_projection(projection, payload.clone(), source, |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("dependency", "bin") => {
                        Ok(artifact("dependency", "/nix/store/dependency-bin"))
                    }
                    ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .expect("distinct declaration aliases may retain one interface document");

        assert_eq!(document.interfaces.len(), 2);
        assert_eq!(
            document.interfaces[&LocalKey::new("echo").unwrap()],
            identity
        );
        assert_eq!(
            document.interfaces[&LocalKey::new("echo-alias").unwrap()],
            identity
        );
    }

    #[test]
    fn guarantee_prose_changes_signed_bytes_without_changing_semantic_identity() {
        fn resolve(description: &str) -> aos_ability_model::PackageDocument {
            let mut value = projection();
            value["guarantees"] = json!({
                "supervision": {
                    "name": "aos.service.supervision",
                    "version": 1,
                    "semantics": "The service remains supervised while requested.",
                    "description": description,
                }
            });
            let bytes = aos_contract::canonical::to_vec(&value).unwrap();
            let projection = decode_package_projection(&bytes).unwrap();
            let payload = artifact("payload", "/nix/store/payload");
            let source = artifact("source", "/nix/store/source.drv");

            resolve_package_projection(projection, payload.clone(), source, |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("dependency", "bin") => {
                        Ok(artifact("dependency", "/nix/store/dependency-bin"))
                    }
                    ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .unwrap()
        }

        let first = resolve("Keeps one requested service process supervised.");
        let second = resolve("Supervises the requested service process continuously.");

        assert_eq!(
            first.content_digest().unwrap(),
            second.content_digest().unwrap()
        );
        assert_ne!(
            aos_contract::canonical::to_vec(&first).unwrap(),
            aos_contract::canonical::to_vec(&second).unwrap()
        );
    }

    #[test]
    fn package_semantic_identity_uses_module_content_and_relative_path() {
        let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");
        let resolve = |projection| {
            resolve_package_projection(projection, payload.clone(), source.clone(), |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                    ("dependency", "bin") => {
                        Ok(artifact("dependency", "/nix/store/dependency-bin"))
                    }
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .unwrap()
        };
        let original = resolve(projection);

        let mut relocated = original.clone();
        relocated
            .package_module
            .as_mut()
            .unwrap()
            .artifact
            .store_path = "/nix/store/relocated-module".to_string();
        assert_eq!(
            original.content_digest().unwrap(),
            relocated.content_digest().unwrap()
        );

        let mut changed_closure = original.clone();
        changed_closure
            .package_module
            .as_mut()
            .unwrap()
            .artifact
            .closure = Sha256Digest::of_bytes("new closure");
        assert_ne!(
            original.content_digest().unwrap(),
            changed_closure.content_digest().unwrap()
        );

        let mut changed_nar = original.clone();
        changed_nar
            .package_module
            .as_mut()
            .unwrap()
            .artifact
            .nar_hash = Sha256Digest::of_bytes("new nar");
        assert_ne!(
            original.content_digest().unwrap(),
            changed_nar.content_digest().unwrap()
        );

        let mut changed_content = original.clone();
        changed_content
            .package_module
            .as_mut()
            .unwrap()
            .artifact
            .content = Sha256Digest::of_bytes("new module content");
        assert_ne!(
            original.content_digest().unwrap(),
            changed_content.content_digest().unwrap()
        );

        let mut changed_path = original.clone();
        changed_path.package_module.as_mut().unwrap().path =
            aos_ability_model::RelativePath::new("provider/module.nix").unwrap();
        assert_ne!(
            original.content_digest().unwrap(),
            changed_path.content_digest().unwrap()
        );
    }

    #[test]
    fn qualification_identity_uses_observer_semantics_without_store_locator() {
        let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");
        let mut document =
            resolve_package_projection(projection, payload.clone(), source, |selector| {
                match (selector.package.as_str(), selector.output.as_str()) {
                    ("self", "out") => Ok(payload.clone()),
                    ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                    ("dependency", "bin") => {
                        Ok(artifact("dependency", "/nix/store/dependency-bin"))
                    }
                    _ => unreachable!("fixture contains only declared selectors"),
                }
            })
            .unwrap();
        let observer = artifact("observer", "/nix/store/observer");
        document.qualification.implementations.insert(
            Sha256Digest::of_bytes("implementation"),
            aos_ability_model::ProviderQualification {
                conformance_families: vec![LocalKey::new("lifecycle").unwrap()],
                observer: aos_ability_model::HandlerDescriptor {
                    artifact: observer,
                    entry_point: "bin/observe".to_string(),
                    arguments: serde_json::from_value(json!({"kind": "boolean"})).unwrap(),
                    result: serde_json::from_value(json!({"kind": "boolean"})).unwrap(),
                },
            },
        );

        let semantic = document.content_digest().unwrap();
        let mut relocated = document.clone();
        relocated
            .qualification
            .implementations
            .values_mut()
            .next()
            .unwrap()
            .observer
            .artifact
            .store_path = "/nix/store/relocated-observer".to_string();
        assert_eq!(semantic, relocated.content_digest().unwrap());

        let mut changed = document;
        changed
            .qualification
            .implementations
            .values_mut()
            .next()
            .unwrap()
            .observer
            .artifact
            .closure = Sha256Digest::of_bytes("changed observer closure");
        assert_ne!(semantic, changed.content_digest().unwrap());
    }

    #[test]
    fn resolves_selectors_nested_in_portable_executable_values() {
        let selected = artifact("service", "/nix/store/service");
        let mut executable = json!({
            "artifact": {
                "_type": "aos-package-output-selector",
                "package": "self",
                "output": "out"
            },
            "entry_point": "bin/service",
            "arguments": ["--foreground"]
        });

        resolve_artifact_selectors(
            &mut executable,
            |selector| {
                assert_eq!(selector.package.as_str(), "self");
                assert_eq!(selector.output.as_str(), "out");
                Ok(selected.clone())
            },
            |_| unreachable!("fixture contains no configuration artifact selector"),
        )
        .unwrap();

        assert_eq!(
            executable["artifact"],
            serde_json::to_value(selected).unwrap()
        );
        assert_eq!(executable["entry_point"], "bin/service");
        assert_eq!(executable["arguments"], json!(["--foreground"]));
    }

    #[test]
    fn rejects_nonclosed_nested_selectors() {
        let mut executable = json!({
            "artifact": {
                "_type": "aos-package-output-selector",
                "package": "self",
                "output": "out",
                "store_path": "/nix/store/untrusted"
            },
            "entry_point": "bin/service",
            "arguments": []
        });

        assert!(
            resolve_artifact_selectors(
                &mut executable,
                |_| unreachable!("a malformed selector must fail before resolution"),
                |_| unreachable!("fixture contains no configuration artifact selector"),
            )
            .is_err()
        );
    }

    #[test]
    fn resolves_evaluated_configuration_artifact_selectors() {
        let selected = artifact("dbus-config", "/nix/store/dbus-system-conf");
        let mut reference = json!({
            "artifact": {
                "_type": "aos-config-artifact-selector",
                "name": "dbus-system-conf"
            },
            "path": "system.conf"
        });

        resolve_artifact_selectors(
            &mut reference,
            |_| unreachable!("fixture contains no package output selector"),
            |selector| {
                assert_eq!(selector.name.as_str(), "dbus-system-conf");
                Ok(selected.clone())
            },
        )
        .unwrap();

        assert_eq!(
            reference["artifact"],
            serde_json::to_value(selected).unwrap()
        );
        assert_eq!(reference["path"], "system.conf");
    }

    #[test]
    fn rejects_nonclosed_configuration_artifact_selectors() {
        let mut reference = json!({
            "artifact": {
                "_type": "aos-config-artifact-selector",
                "name": "dbus-system-conf",
                "store_path": "/nix/store/untrusted"
            },
            "path": "system.conf"
        });

        assert!(
            resolve_artifact_selectors(
                &mut reference,
                |_| unreachable!("fixture contains no package output selector"),
                |_| unreachable!("a malformed selector must fail before resolution"),
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_the_canonical_runtime_path_expression_for_later_typed_resolution() {
        let mut value = json!({
            "_type": "aos-runtime-path",
            "base": "/nix/store/service",
            "relative_path": "bin/daemon"
        });
        let original = value.clone();

        resolve_artifact_selectors(
            &mut value,
            |_| unreachable!("fixture contains no package selector"),
            |_| unreachable!("fixture contains no configuration selector"),
        )
        .unwrap();

        assert_eq!(value, original);
    }
}
