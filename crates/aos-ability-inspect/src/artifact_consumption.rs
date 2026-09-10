//! Checked decoding and focused queries for realized artifact consumption.
//!
//! The version-1 reader keeps each consumption mechanism distinct and accepts
//! only evidence produced from realized files or an observed invocation.

use std::collections::BTreeSet;

use aos_ability_model::document::PlatformIdentity;
use aos_ability_model::{
    ABILITY_LIMITS_V1, ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA, ArtifactConsumptionContract,
    ArtifactConsumptionEvidenceDocument, ArtifactConsumptionMechanism,
    ArtifactConsumptionObservation, ArtifactFileEvidence, ArtifactReference,
    ArtifactRetentionRequirement, BUILD_TOOL_EXECUTION_FEATURE, ELF_STARTUP_LINKAGE_FEATURE,
    HELPER_EXECUTION_FEATURE, IMMUTABLE_DATA_INPUT_FEATURE, PlanId, RUNTIME_PLUGIN_LOAD_FEATURE,
    RequiredFeature, VersionedDocument, decode_canonical,
};
use aos_contract::Sha256Digest;
use serde::Serialize;
use thiserror::Error;

use crate::{CheckedInspectionBundle, InspectionNode, InspectionView, InspectionViewError};

/// Maximum bytes accepted for one canonical artifact-consumption report.
pub const ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES: u64 = ABILITY_LIMITS_V1.max_document_bytes;

/// Selects one exact artifact-consumption relationship from checked evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArtifactConsumptionQuery {
    consumer: Option<String>,
    provider_content: Option<Sha256Digest>,
}

/// Carries a report that passed canonical decoding and semantic validation.
#[derive(Clone, Debug)]
pub struct CheckedArtifactConsumptionEvidence {
    document: ArtifactConsumptionEvidenceDocument,
}

/// Explains one checked consumer-to-provider relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConsumptionExplanation {
    /// Carries the schema of the checked source evidence.
    pub evidence_schema: String,
    /// Gives the stable local evidence identity.
    pub id: String,
    /// Identifies the mechanism established by the build gate.
    pub mechanism: ArtifactConsumptionMechanism,
    /// Identifies the build, host, and target platforms.
    pub platforms: aos_ability_model::ArtifactConsumptionPlatforms,
    /// Pins the exact consuming executable or produced file.
    pub consumer: ArtifactFileEvidence,
    /// Pins the exact library, executable, or data provider.
    pub provider: ArtifactFileEvidence,
    /// Records the checked mechanism-specific contract.
    pub contract: ArtifactConsumptionContract,
    /// Confirms that the consumer's realized closure retains the provider.
    pub provider_retained_by_consumer: bool,
    /// Confirms compatible consumer and provider ELF identities when applicable.
    pub provider_elf_compatible: Option<bool>,
    /// Confirms a compatible program interpreter ELF identity.
    pub loader_elf_compatible: Option<bool>,
    /// Confirms the embedded search order selects this exact provider first.
    pub search_resolves_exact_provider: Option<bool>,
    /// Confirms a syscall observation of the exact mechanism-specific provider access.
    pub provider_access_observed: Option<bool>,
    /// Classifies the authority carried by this portable report.
    pub provenance: ArtifactConsumptionProvenance,
    /// Binds both evidence artifacts to one semantically checked ability graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ability_graph: Option<ArtifactConsumptionGraphBinding>,
    /// States conclusions that this evidence mechanism cannot establish.
    pub limitations: Vec<ArtifactConsumptionLimitation>,
}

/// Identifies the checked ability graph that contains both evidence artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConsumptionGraphBinding {
    /// Identifies the canonical portable inspection bundle.
    pub bundle: Sha256Digest,
    /// Identifies the checked provider-binding plan reconstructed from the bundle.
    pub binding_plan: PlanId,
    /// Identifies the checked effect plan reconstructed from the bundle.
    pub effect_plan: PlanId,
    /// Identifies the exact semantically checked consumption edge.
    pub edge: Sha256Digest,
    /// Identifies the inspected mechanism retained by the checked edge.
    pub mechanism: ArtifactConsumptionMechanism,
    /// Places the consumption in its build or runtime phase.
    pub phase: ArtifactConsumptionPhase,
    /// States whether the provider belongs in the consumer runtime closure.
    pub retention: ArtifactRetentionRequirement,
    /// Retains the complete consumer artifact reference matched in the graph.
    pub consumer: ArtifactReference,
    /// Retains the complete provider artifact reference matched in the graph.
    pub provider: ArtifactReference,
}

/// Places an artifact-consumption relationship in its execution phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionPhase {
    /// A hermetic build action executes a tool while producing the consumer.
    Build,
    /// The runtime loader consumes a provider before the program starts.
    RuntimeStartup,
    /// A running program explicitly loads, executes, or reads the provider.
    RuntimeOperation,
}

/// Classifies where a checked artifact-consumption claim originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionProvenance {
    /// The report says a hermetic build gate inspected these realized outputs.
    ReportedRealizedBuildGate,
}

/// Names a conclusion deliberately excluded from artifact-consumption evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionLimitation {
    /// The report does not authenticate a signed publication envelope.
    NoPublicationAuthentication,
    /// The report does not observe a later live loader invocation.
    NoLiveLoaderEnforcement,
    /// The report does not authorize or establish runtime library rebinding.
    NoRuntimeRebinding,
    /// The report does not establish plugins or explicit runtime loads.
    NoPluginOrExplicitLoadEvidence,
    /// The report does not establish execution of a helper program.
    NoHelperExecutionEvidence,
    /// The report does not establish use of an artifact as a build tool.
    NoBuildToolExecutionEvidence,
    /// The report does not establish reads from an immutable data artifact.
    NoDataInputEvidence,
    /// The invocation does not establish continued state in a deployment after it exits.
    NoDeploymentRuntimeState,
}

/// Reports why artifact-consumption evidence or a query was rejected.
#[derive(Debug, Error)]
pub enum ArtifactConsumptionEvidenceError {
    /// Construction of the reader's fixed feature identity failed.
    #[error("artifact-consumption feature identity is invalid: {0}")]
    Feature(#[source] aos_ability_model::identity::IdentityError),
    /// Canonical, bounded model decoding failed.
    #[error("artifact-consumption evidence decoding failed: {0}")]
    Decode(#[source] aos_ability_model::document::DocumentError),
    /// The document did not declare exactly the version-1 mechanism feature.
    #[error("artifact-consumption evidence must require exactly its version-1 mechanism feature")]
    RequiredFeatures,
    /// The evidence mechanism does not agree with its feature declaration.
    #[error("artifact-consumption evidence mechanism and required feature disagree")]
    MechanismFeatureMismatch,
    /// The mechanism does not carry its required contract and observation shape.
    #[error("artifact-consumption evidence mechanism and payload shape disagree")]
    MechanismPayloadMismatch,
    /// A platform is not a valid ELF startup-linkage platform identity.
    #[error("artifact-consumption evidence has an unsupported platform relationship")]
    Platform,
    /// An artifact store path is not an absolute Nix store output.
    #[error("artifact-consumption evidence has an invalid {role} store path")]
    StorePath {
        /// Identifies the consumer or provider endpoint.
        role: &'static str,
    },
    /// A file path escapes or does not identify a file beneath its artifact.
    #[error("artifact-consumption evidence has an invalid {role} artifact-relative path")]
    ArtifactPath {
        /// Identifies the consumer or provider endpoint.
        role: &'static str,
    },
    /// A string or collection exceeds a version-1 semantic bound.
    #[error("artifact-consumption evidence exceeds the {field} bound")]
    Bound {
        /// Names the bounded field.
        field: &'static str,
    },
    /// The expected dynamic dependencies are not canonical and complete.
    #[error("artifact-consumption evidence has an invalid canonical DT_NEEDED contract")]
    Needed,
    /// The expected loader is not an exact absolute store path.
    #[error("artifact-consumption evidence has an invalid program interpreter")]
    Loader,
    /// The expected search path cannot select the exact provider artifact.
    #[error(
        "artifact-consumption evidence search path does not name the provider directory exactly"
    )]
    SearchPath,
    /// The expected symbol-version list is invalid or noncanonical.
    #[error("artifact-consumption evidence has an invalid canonical symbol-version contract")]
    Symbols,
    /// Facts inspected from the output do not equal the authored contract.
    #[error("artifact-consumption observation does not satisfy its linkage contract")]
    ObservationMismatch,
    /// The observed ELF machine does not match the exact target platform.
    #[error("artifact-consumption ELF machine does not match its target platform")]
    MachineMismatch,
    /// The closure observation did not match the mechanism's retention rule.
    #[error("artifact-consumption evidence does not satisfy its provider-retention contract")]
    ProviderRetentionMismatch,
    /// A query named another consumer file.
    #[error("artifact-consumption query does not match the checked consumer")]
    ConsumerMismatch,
    /// A query named another provider artifact.
    #[error("artifact-consumption query does not match the checked provider")]
    ProviderMismatch,
    /// The checked ability graph could not be projected.
    #[error("artifact-consumption ability graph projection failed: {0}")]
    AbilityGraph(#[source] InspectionViewError),
    /// The evidence consumer artifact is absent from the checked ability graph.
    #[error("artifact-consumption consumer is absent from the checked ability graph")]
    ConsumerAbsentFromAbilityGraph,
    /// The evidence provider artifact is absent from the checked ability graph.
    #[error("artifact-consumption provider is absent from the checked ability graph")]
    ProviderAbsentFromAbilityGraph,
    /// No checked graph edge connects the exact evidence endpoints and semantics.
    #[error("artifact-consumption exact edge is absent from the checked ability graph")]
    ConsumptionEdgeAbsentFromAbilityGraph,
    /// The checked evidence edge could not be assigned its exact identity.
    #[error("artifact-consumption evidence identity failed: {0}")]
    EvidenceIdentity(#[source] aos_ability_model::document::DocumentError),
}

impl ArtifactConsumptionQuery {
    /// Constructs a query for an optional exact consumer path and provider digest.
    #[must_use]
    pub fn new(consumer: Option<String>, provider_content: Option<Sha256Digest>) -> Self {
        Self {
            consumer,
            provider_content,
        }
    }
}

impl CheckedArtifactConsumptionEvidence {
    /// Decodes and checks one bounded canonical evidence document.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, noncanonical, unsupported, or
    /// internally inconsistent evidence.
    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactConsumptionEvidenceError> {
        let supported_features = [
            ELF_STARTUP_LINKAGE_FEATURE,
            RUNTIME_PLUGIN_LOAD_FEATURE,
            HELPER_EXECUTION_FEATURE,
            BUILD_TOOL_EXECUTION_FEATURE,
            IMMUTABLE_DATA_INPUT_FEATURE,
        ]
        .into_iter()
        .map(RequiredFeature::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(ArtifactConsumptionEvidenceError::Feature)?;
        let document = decode_canonical::<ArtifactConsumptionEvidenceDocument>(
            bytes,
            ABILITY_LIMITS_V1,
            &supported_features,
        )
        .map_err(ArtifactConsumptionEvidenceError::Decode)?;

        Self::check(document)
    }

    /// Checks a decoded evidence document's mechanism-specific semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when identities, paths, platform roles, ELF facts, or
    /// closure retention are inconsistent.
    pub fn check(
        document: ArtifactConsumptionEvidenceDocument,
    ) -> Result<Self, ArtifactConsumptionEvidenceError> {
        validate_features(&document)?;
        validate_platforms(&document.platforms)?;
        validate_artifact_file("consumer", &document.consumer)?;
        validate_artifact_file("provider", &document.provider)?;
        validate_contract_and_observation(&document)?;

        Ok(Self { document })
    }

    /// Returns the exact canonical source document after semantic checks.
    #[must_use]
    pub const fn document(&self) -> &ArtifactConsumptionEvidenceDocument {
        &self.document
    }

    /// Answers an exact consumer/provider query with the checked linkage facts.
    ///
    /// # Errors
    ///
    /// Returns an error if either supplied selector identifies another edge.
    pub fn query(
        &self,
        query: &ArtifactConsumptionQuery,
    ) -> Result<ArtifactConsumptionExplanation, ArtifactConsumptionEvidenceError> {
        let consumer = artifact_file_path(&self.document.consumer);
        if query
            .consumer
            .as_deref()
            .is_some_and(|expected| expected != consumer)
        {
            return Err(ArtifactConsumptionEvidenceError::ConsumerMismatch);
        }
        if query
            .provider_content
            .is_some_and(|expected| expected != self.document.provider.artifact.content)
        {
            return Err(ArtifactConsumptionEvidenceError::ProviderMismatch);
        }

        let (
            retained,
            provider_elf_compatible,
            loader_elf_compatible,
            search_resolves_exact_provider,
            provider_access_observed,
        ) = match &self.document.observation {
            ArtifactConsumptionObservation::ElfStartupLinkage(observation) => (
                observation.provider_retained_by_consumer,
                Some(observation.provider_elf_compatible),
                Some(observation.loader_elf_compatible),
                Some(observation.search_resolves_exact_provider),
                None,
            ),
            ArtifactConsumptionObservation::ObservedPath(observation) => (
                observation.provider_retained_by_consumer,
                None,
                None,
                None,
                Some(observation.provider_access_observed),
            ),
        };

        Ok(ArtifactConsumptionExplanation {
            evidence_schema: ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA.to_string(),
            id: self.document.id.as_str().to_string(),
            mechanism: self.document.mechanism,
            platforms: self.document.platforms.clone(),
            consumer: self.document.consumer.clone(),
            provider: self.document.provider.clone(),
            contract: self.document.contract.clone(),
            provider_retained_by_consumer: retained,
            provider_elf_compatible,
            loader_elf_compatible,
            search_resolves_exact_provider,
            provider_access_observed,
            provenance: ArtifactConsumptionProvenance::ReportedRealizedBuildGate,
            ability_graph: None,
            limitations: limitations(self.document.mechanism),
        })
    }

    /// Joins realized evidence to the exact artifact nodes in a checked ability graph.
    ///
    /// Matching compares the complete [`ArtifactReference`], including content,
    /// store path, NAR hash, and closure identity. A content-only coincidence is
    /// therefore insufficient.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails, the graph cannot be projected, or
    /// either exact evidence artifact is absent from the checked graph.
    pub fn query_with_bundle(
        &self,
        query: &ArtifactConsumptionQuery,
        bundle: &CheckedInspectionBundle,
    ) -> Result<ArtifactConsumptionExplanation, ArtifactConsumptionEvidenceError> {
        let mut explanation = self.query(query)?;
        let view = InspectionView::from_bundle(bundle)
            .map_err(ArtifactConsumptionEvidenceError::AbilityGraph)?;
        let mut graph_artifacts = view.nodes().iter().filter_map(|node| match node {
            InspectionNode::Artifact { reference, .. } => Some(reference),
            _ => None,
        });
        let consumer_present = graph_artifacts
            .clone()
            .any(|reference| reference == &self.document.consumer.artifact);
        if !consumer_present {
            return Err(ArtifactConsumptionEvidenceError::ConsumerAbsentFromAbilityGraph);
        }
        let provider_present =
            graph_artifacts.any(|reference| reference == &self.document.provider.artifact);
        if !provider_present {
            return Err(ArtifactConsumptionEvidenceError::ProviderAbsentFromAbilityGraph);
        }
        if !bundle
            .artifact_consumption_edges()
            .iter()
            .any(|edge| edge == &self.document)
        {
            return Err(ArtifactConsumptionEvidenceError::ConsumptionEdgeAbsentFromAbilityGraph);
        }

        explanation.ability_graph = Some(ArtifactConsumptionGraphBinding {
            bundle: bundle.digest(),
            binding_plan: view.binding_plan(),
            effect_plan: view.plan(),
            edge: self
                .document
                .content_digest()
                .map_err(ArtifactConsumptionEvidenceError::EvidenceIdentity)?,
            mechanism: self.document.mechanism,
            phase: consumption_phase(self.document.mechanism),
            retention: consumption_retention(&self.document.contract),
            consumer: self.document.consumer.artifact.clone(),
            provider: self.document.provider.artifact.clone(),
        });
        Ok(explanation)
    }
}

const fn consumption_phase(mechanism: ArtifactConsumptionMechanism) -> ArtifactConsumptionPhase {
    match mechanism {
        ArtifactConsumptionMechanism::BuildToolExecution => ArtifactConsumptionPhase::Build,
        ArtifactConsumptionMechanism::ElfStartupLinkage => ArtifactConsumptionPhase::RuntimeStartup,
        ArtifactConsumptionMechanism::RuntimePluginLoad
        | ArtifactConsumptionMechanism::HelperExecution
        | ArtifactConsumptionMechanism::ImmutableDataInput => {
            ArtifactConsumptionPhase::RuntimeOperation
        }
    }
}

const fn consumption_retention(
    contract: &ArtifactConsumptionContract,
) -> ArtifactRetentionRequirement {
    match contract {
        ArtifactConsumptionContract::ElfStartupLinkage(_) => ArtifactRetentionRequirement::Required,
        ArtifactConsumptionContract::ObservedPath(contract) => contract.retention,
    }
}

fn validate_features(
    document: &ArtifactConsumptionEvidenceDocument,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    let expected = feature_for(document.mechanism);
    if document.required_features.len() != 1 || document.required_features[0].as_str() != expected {
        return Err(ArtifactConsumptionEvidenceError::RequiredFeatures);
    }
    Ok(())
}

const fn feature_for(mechanism: ArtifactConsumptionMechanism) -> &'static str {
    match mechanism {
        ArtifactConsumptionMechanism::ElfStartupLinkage => ELF_STARTUP_LINKAGE_FEATURE,
        ArtifactConsumptionMechanism::RuntimePluginLoad => RUNTIME_PLUGIN_LOAD_FEATURE,
        ArtifactConsumptionMechanism::HelperExecution => HELPER_EXECUTION_FEATURE,
        ArtifactConsumptionMechanism::BuildToolExecution => BUILD_TOOL_EXECUTION_FEATURE,
        ArtifactConsumptionMechanism::ImmutableDataInput => IMMUTABLE_DATA_INPUT_FEATURE,
    }
}

fn limitations(mechanism: ArtifactConsumptionMechanism) -> Vec<ArtifactConsumptionLimitation> {
    use ArtifactConsumptionLimitation::{
        NoBuildToolExecutionEvidence, NoDataInputEvidence, NoDeploymentRuntimeState,
        NoHelperExecutionEvidence, NoLiveLoaderEnforcement, NoPluginOrExplicitLoadEvidence,
        NoPublicationAuthentication, NoRuntimeRebinding,
    };

    let mut limitations = vec![NoPublicationAuthentication, NoDeploymentRuntimeState];
    match mechanism {
        ArtifactConsumptionMechanism::ElfStartupLinkage => limitations.extend([
            NoLiveLoaderEnforcement,
            NoRuntimeRebinding,
            NoPluginOrExplicitLoadEvidence,
            NoHelperExecutionEvidence,
            NoBuildToolExecutionEvidence,
            NoDataInputEvidence,
        ]),
        ArtifactConsumptionMechanism::RuntimePluginLoad => limitations.extend([
            NoRuntimeRebinding,
            NoHelperExecutionEvidence,
            NoBuildToolExecutionEvidence,
            NoDataInputEvidence,
        ]),
        ArtifactConsumptionMechanism::HelperExecution => limitations.extend([
            NoLiveLoaderEnforcement,
            NoRuntimeRebinding,
            NoPluginOrExplicitLoadEvidence,
            NoBuildToolExecutionEvidence,
            NoDataInputEvidence,
        ]),
        ArtifactConsumptionMechanism::BuildToolExecution => limitations.extend([
            NoLiveLoaderEnforcement,
            NoRuntimeRebinding,
            NoPluginOrExplicitLoadEvidence,
            NoHelperExecutionEvidence,
            NoDataInputEvidence,
        ]),
        ArtifactConsumptionMechanism::ImmutableDataInput => limitations.extend([
            NoLiveLoaderEnforcement,
            NoRuntimeRebinding,
            NoPluginOrExplicitLoadEvidence,
            NoHelperExecutionEvidence,
            NoBuildToolExecutionEvidence,
        ]),
    }
    limitations
}

fn validate_platforms(
    platforms: &aos_ability_model::ArtifactConsumptionPlatforms,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    let local_key_bound = ABILITY_LIMITS_V1.max_string_bytes as usize;
    for platform in [&platforms.build, &platforms.host, &platforms.target] {
        if platform.system.as_str().len() > local_key_bound
            || platform.architecture.as_str().len() > local_key_bound
        {
            return Err(ArtifactConsumptionEvidenceError::Bound { field: "platform" });
        }
    }
    if platforms.host != platforms.target || platforms.target.system.as_str() != "linux" {
        return Err(ArtifactConsumptionEvidenceError::Platform);
    }
    match platforms.target.architecture.as_str() {
        "x86_64" | "aarch64" => Ok(()),
        _ => Err(ArtifactConsumptionEvidenceError::Platform),
    }
}

fn validate_artifact_file(
    role: &'static str,
    file: &ArtifactFileEvidence,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if !valid_store_path(&file.artifact.store_path) {
        return Err(ArtifactConsumptionEvidenceError::StorePath { role });
    }
    if !valid_artifact_path(&file.path) {
        return Err(ArtifactConsumptionEvidenceError::ArtifactPath { role });
    }
    let maximum = ABILITY_LIMITS_V1.max_string_bytes as usize;
    if file.artifact.store_path.len() > maximum
        || file.path.len() > maximum
        || artifact_file_path(file).len() > maximum
    {
        return Err(ArtifactConsumptionEvidenceError::Bound {
            field: "artifact path",
        });
    }
    Ok(())
}

fn validate_contract_and_observation(
    document: &ArtifactConsumptionEvidenceDocument,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    match (&document.contract, &document.observation) {
        (
            ArtifactConsumptionContract::ElfStartupLinkage(contract),
            ArtifactConsumptionObservation::ElfStartupLinkage(observation),
        ) if document.mechanism == ArtifactConsumptionMechanism::ElfStartupLinkage => {
            validate_elf_contract(document, contract)?;
            validate_elf_observation(document, contract, observation)
        }
        (
            ArtifactConsumptionContract::ObservedPath(contract),
            ArtifactConsumptionObservation::ObservedPath(observation),
        ) if document.mechanism != ArtifactConsumptionMechanism::ElfStartupLinkage => {
            validate_path_contract(contract)?;
            let required_retention = match document.mechanism {
                ArtifactConsumptionMechanism::BuildToolExecution => {
                    ArtifactRetentionRequirement::Forbidden
                }
                ArtifactConsumptionMechanism::RuntimePluginLoad
                | ArtifactConsumptionMechanism::HelperExecution
                | ArtifactConsumptionMechanism::ImmutableDataInput => {
                    ArtifactRetentionRequirement::Required
                }
                ArtifactConsumptionMechanism::ElfStartupLinkage => {
                    return Err(ArtifactConsumptionEvidenceError::MechanismPayloadMismatch);
                }
            };
            if contract.retention != required_retention {
                return Err(ArtifactConsumptionEvidenceError::ProviderRetentionMismatch);
            }
            if observation.arguments != contract.arguments
                || observation.exit_code != 0
                || observation.output_sha256 != contract.output_sha256
                || !observation.provider_access_observed
            {
                return Err(ArtifactConsumptionEvidenceError::ObservationMismatch);
            }
            let retention_matches = match contract.retention {
                ArtifactRetentionRequirement::Required => observation.provider_retained_by_consumer,
                ArtifactRetentionRequirement::Forbidden => {
                    !observation.provider_retained_by_consumer
                }
            };
            if !retention_matches {
                return Err(ArtifactConsumptionEvidenceError::ProviderRetentionMismatch);
            }
            Ok(())
        }
        _ => Err(ArtifactConsumptionEvidenceError::MechanismPayloadMismatch),
    }
}

fn validate_path_contract(
    contract: &aos_ability_model::ObservedPathConsumptionContract,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if contract.arguments.len() as u64 > ABILITY_LIMITS_V1.max_collection_items {
        return Err(ArtifactConsumptionEvidenceError::Bound {
            field: "invocation arguments",
        });
    }
    for argument in &contract.arguments {
        validate_argument(argument)?;
    }
    Ok(())
}

fn validate_argument(argument: &str) -> Result<(), ArtifactConsumptionEvidenceError> {
    if argument.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes || argument.contains('\0') {
        return Err(ArtifactConsumptionEvidenceError::Bound {
            field: "invocation argument",
        });
    }
    Ok(())
}

fn validate_elf_contract(
    document: &ArtifactConsumptionEvidenceDocument,
    contract: &aos_ability_model::ElfStartupLinkageContract,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    validate_string("ELF linkage", &contract.soname)?;
    if contract.soname.contains('/') || file_name(&document.provider.path) != contract.soname {
        return Err(ArtifactConsumptionEvidenceError::Needed);
    }
    if contract.needed.is_empty()
        || !is_sorted_unique(&contract.needed)
        || !contract
            .needed
            .iter()
            .any(|needed| needed == &contract.soname)
    {
        return Err(ArtifactConsumptionEvidenceError::Needed);
    }
    validate_string_list("DT_NEEDED", &contract.needed)?;

    validate_string("program interpreter", &contract.loader)?;
    if !valid_store_file_path(&contract.loader) {
        return Err(ArtifactConsumptionEvidenceError::Loader);
    }

    if contract.search_path.is_empty()
        || has_duplicate(&contract.search_path)
        || !contract
            .search_path
            .iter()
            .all(|path| valid_store_directory_path(path))
    {
        return Err(ArtifactConsumptionEvidenceError::SearchPath);
    }
    validate_string_list("ELF search path", &contract.search_path)?;
    let provider_directory = format!(
        "{}{}",
        document.provider.artifact.store_path,
        parent_path(&document.provider.path)
    );
    if !contract
        .search_path
        .iter()
        .any(|entry| entry == &provider_directory)
    {
        return Err(ArtifactConsumptionEvidenceError::SearchPath);
    }

    if contract.symbols.is_empty() || !is_sorted_unique(&contract.symbols) {
        return Err(ArtifactConsumptionEvidenceError::Symbols);
    }
    if contract.symbols.len() as u64 > ABILITY_LIMITS_V1.max_collection_items {
        return Err(ArtifactConsumptionEvidenceError::Bound {
            field: "ELF symbol-version collection",
        });
    }
    for symbol in &contract.symbols {
        if !valid_symbol_name(&symbol.name) || !valid_symbol_version(&symbol.version) {
            return Err(ArtifactConsumptionEvidenceError::Symbols);
        }
    }
    Ok(())
}

fn validate_elf_observation(
    document: &ArtifactConsumptionEvidenceDocument,
    contract: &aos_ability_model::ElfStartupLinkageContract,
    observation: &aos_ability_model::ElfStartupLinkageObservation,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if observation.soname != contract.soname
        || observation.needed != contract.needed
        || observation.search_path != contract.search_path
        || observation.search_path_kind != contract.search_path_kind
        || observation.loader != contract.loader
        || observation.symbols != contract.symbols
    {
        return Err(ArtifactConsumptionEvidenceError::ObservationMismatch);
    }
    let expected_machine = machine_for(&document.platforms.target)?;
    if observation.machine != expected_machine
        || observation.elf_class != "ELF64"
        || observation.data_encoding != "2's complement, little endian"
    {
        return Err(ArtifactConsumptionEvidenceError::MachineMismatch);
    }
    validate_string("ELF OS/ABI", &observation.os_abi)?;
    validate_string("ELF ABI version", &observation.abi_version)?;
    if !observation.provider_retained_by_consumer {
        return Err(ArtifactConsumptionEvidenceError::ProviderRetentionMismatch);
    }
    if !observation.provider_elf_compatible
        || !observation.loader_elf_compatible
        || !observation.search_resolves_exact_provider
    {
        return Err(ArtifactConsumptionEvidenceError::ObservationMismatch);
    }
    Ok(())
}

fn machine_for(
    platform: &PlatformIdentity,
) -> Result<&'static str, ArtifactConsumptionEvidenceError> {
    match platform.architecture.as_str() {
        "x86_64" => Ok("Advanced Micro Devices X86-64"),
        "aarch64" => Ok("AArch64"),
        _ => Err(ArtifactConsumptionEvidenceError::Platform),
    }
}

fn validate_string(
    field: &'static str,
    value: &str,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if value.is_empty()
        || value.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return Err(ArtifactConsumptionEvidenceError::Bound { field });
    }
    Ok(())
}

fn validate_string_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if values.len() as u64 > ABILITY_LIMITS_V1.max_collection_items {
        return Err(ArtifactConsumptionEvidenceError::Bound { field });
    }
    for value in values {
        validate_string(field, value)?;
    }
    Ok(())
}

fn valid_store_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, store_name)) = name.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && !store_name.is_empty()
        && store_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
}

fn valid_store_file_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((store_name, suffix)) = rest.split_once('/') else {
        return false;
    };
    valid_store_path(&format!("/nix/store/{store_name}"))
        && !suffix.is_empty()
        && suffix
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_store_directory_path(path: &str) -> bool {
    if valid_store_path(path) {
        return true;
    }

    valid_store_file_path(path)
}

fn valid_artifact_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_symbol_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn valid_symbol_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn artifact_file_path(file: &ArtifactFileEvidence) -> String {
    format!("{}{}", file.artifact.store_path, file.path)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn has_duplicate<T: Ord + Clone>(values: &[T]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        ArtifactConsumptionPlatforms, ElfSearchPathKind, ElfStartupLinkageContract,
        ElfStartupLinkageObservation, ElfSymbolVersion, LocalKey, encode_canonical,
    };
    use aos_ability_validate::test_support::plan_fixture;

    use super::*;
    use crate::InspectionBundle;

    const CONSUMER_STORE: &str = "/nix/store/00000000000000000000000000000000-consumer";
    const PROVIDER_STORE: &str = "/nix/store/11111111111111111111111111111111-provider";
    const LOADER: &str =
        "/nix/store/22222222222222222222222222222222-glibc/lib/ld-linux-x86-64.so.2";

    fn platform() -> PlatformIdentity {
        PlatformIdentity {
            system: LocalKey::new("linux").unwrap(),
            architecture: LocalKey::new("x86_64").unwrap(),
        }
    }

    fn artifact(store_path: &str, label: &str) -> aos_ability_model::ArtifactReference {
        aos_ability_model::ArtifactReference {
            content: Sha256Digest::of_bytes(format!("{label} content")),
            store_path: store_path.to_string(),
            nar_hash: Sha256Digest::of_bytes(format!("{label} nar")),
            closure: Sha256Digest::of_bytes(format!("{label} closure")),
        }
    }

    fn document() -> ArtifactConsumptionEvidenceDocument {
        let symbols = vec![ElfSymbolVersion {
            name: "aos_contract".to_string(),
            version: "AOS_CONTRACT_1".to_string(),
        }];
        let contract = ElfStartupLinkageContract {
            soname: "libaos-contract.so.1".to_string(),
            needed: vec!["libaos-contract.so.1".to_string()],
            search_path: vec![format!("{PROVIDER_STORE}/lib")],
            search_path_kind: ElfSearchPathKind::Runpath,
            loader: LOADER.to_string(),
            symbols: symbols.clone(),
        };

        ArtifactConsumptionEvidenceDocument {
            schema: ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new(ELF_STARTUP_LINKAGE_FEATURE).unwrap()],
            id: LocalKey::new("consumer-provider-linkage").unwrap(),
            mechanism: ArtifactConsumptionMechanism::ElfStartupLinkage,
            platforms: ArtifactConsumptionPlatforms {
                build: platform(),
                host: platform(),
                target: platform(),
            },
            consumer: ArtifactFileEvidence {
                artifact: artifact(CONSUMER_STORE, "consumer"),
                path: "/bin/consumer".to_string(),
                sha256: Sha256Digest::of_bytes("consumer file"),
            },
            provider: ArtifactFileEvidence {
                artifact: artifact(PROVIDER_STORE, "provider"),
                path: "/lib/libaos-contract.so.1".to_string(),
                sha256: Sha256Digest::of_bytes("provider file"),
            },
            observation: ArtifactConsumptionObservation::ElfStartupLinkage(
                ElfStartupLinkageObservation {
                    elf_class: "ELF64".to_string(),
                    data_encoding: "2's complement, little endian".to_string(),
                    machine: "Advanced Micro Devices X86-64".to_string(),
                    os_abi: "UNIX - System V".to_string(),
                    abi_version: "0".to_string(),
                    soname: contract.soname.clone(),
                    needed: contract.needed.clone(),
                    search_path: contract.search_path.clone(),
                    search_path_kind: contract.search_path_kind,
                    loader: contract.loader.clone(),
                    symbols,
                    provider_elf_compatible: true,
                    loader_elf_compatible: true,
                    search_resolves_exact_provider: true,
                    provider_retained_by_consumer: true,
                },
            ),
            contract: ArtifactConsumptionContract::ElfStartupLinkage(contract),
        }
    }

    fn observed_helper_document(arguments: Vec<String>) -> ArtifactConsumptionEvidenceDocument {
        let mut document = document();
        let output_sha256 = Sha256Digest::of_bytes("helper output");
        document.required_features = vec![RequiredFeature::new(HELPER_EXECUTION_FEATURE).unwrap()];
        document.mechanism = ArtifactConsumptionMechanism::HelperExecution;
        document.provider.path = "/bin/helper".to_string();
        document.contract = ArtifactConsumptionContract::ObservedPath(
            aos_ability_model::ObservedPathConsumptionContract {
                arguments: arguments.clone(),
                output_sha256,
                retention: ArtifactRetentionRequirement::Required,
            },
        );
        document.observation = ArtifactConsumptionObservation::ObservedPath(
            aos_ability_model::ObservedPathConsumptionObservation {
                arguments,
                exit_code: 0,
                output_sha256,
                provider_access_observed: true,
                provider_retained_by_consumer: true,
            },
        );
        document
    }

    fn bundle_with_artifacts(
        artifacts: Vec<ArtifactReference>,
        edges: Vec<ArtifactConsumptionEvidenceDocument>,
    ) -> CheckedInspectionBundle {
        let mut fixture = plan_fixture();
        fixture.effect_plan.artifacts.extend(artifacts);
        fixture.effect_plan.artifacts.sort_by(|left, right| {
            left.content
                .cmp(&right.content)
                .then_with(|| left.store_path.cmp(&right.store_path))
        });
        fixture.effect_plan.artifacts.dedup();
        fixture.refresh_commitments();

        let checked = fixture.validate().unwrap();
        InspectionBundle::from_checked(&checked)
            .unwrap()
            .with_artifact_consumption_edges(edges)
            .unwrap()
            .check(None)
            .unwrap()
    }

    #[test]
    fn checked_evidence_answers_exact_consumer_and_provider_query() {
        let document = document();
        let provider_content = document.provider.artifact.content;
        let bytes = encode_canonical(&document).unwrap();
        let checked = CheckedArtifactConsumptionEvidence::decode(&bytes).unwrap();

        let explanation = checked
            .query(&ArtifactConsumptionQuery::new(
                Some(format!("{CONSUMER_STORE}/bin/consumer")),
                Some(provider_content),
            ))
            .unwrap();

        assert!(matches!(
            explanation.contract,
            ArtifactConsumptionContract::ElfStartupLinkage(ref contract)
                if contract.soname == "libaos-contract.so.1"
        ));
        assert!(explanation.provider_retained_by_consumer);
        assert_eq!(
            explanation.provenance,
            ArtifactConsumptionProvenance::ReportedRealizedBuildGate
        );
        assert!(
            explanation
                .limitations
                .contains(&ArtifactConsumptionLimitation::NoLiveLoaderEnforcement)
        );
        assert!(
            explanation
                .limitations
                .contains(&ArtifactConsumptionLimitation::NoDataInputEvidence)
        );
    }

    #[test]
    fn checked_evidence_joins_both_exact_artifacts_to_one_checked_graph() {
        let document = document();
        let bundle = bundle_with_artifacts(
            vec![
                document.consumer.artifact.clone(),
                document.provider.artifact.clone(),
            ],
            vec![document.clone()],
        );
        let checked = CheckedArtifactConsumptionEvidence::check(document.clone()).unwrap();

        let explanation = checked
            .query_with_bundle(&ArtifactConsumptionQuery::default(), &bundle)
            .unwrap();
        let graph = explanation.ability_graph.unwrap();

        assert_eq!(graph.bundle, bundle.digest());
        assert_eq!(graph.effect_plan, bundle.plan().id());
        assert_eq!(graph.binding_plan, bundle.plan().binding_plan().id());
        assert_eq!(graph.consumer, document.consumer.artifact);
        assert_eq!(graph.provider, document.provider.artifact);
    }

    #[test]
    fn checked_evidence_rejects_graph_without_the_consumer_artifact() {
        let document = document();
        let mut fixture = plan_fixture();
        fixture
            .effect_plan
            .artifacts
            .push(document.provider.artifact.clone());
        fixture.effect_plan.artifacts.sort_by(|left, right| {
            left.content
                .cmp(&right.content)
                .then_with(|| left.store_path.cmp(&right.store_path))
        });
        fixture.effect_plan.artifacts.dedup();
        fixture.refresh_commitments();
        let checked_plan = fixture.validate().unwrap();
        let error = InspectionBundle::from_checked(&checked_plan)
            .unwrap()
            .with_artifact_consumption_edges(vec![document])
            .unwrap()
            .check(None)
            .unwrap_err();

        assert!(matches!(
            error,
            crate::InspectionBundleError::ArtifactConsumptionEdgeEndpoint
        ));
    }

    #[test]
    fn checked_evidence_does_not_join_on_content_digest_alone() {
        let document = document();
        let mut different_consumer_identity = document.consumer.artifact.clone();
        different_consumer_identity.nar_hash = Sha256Digest::of_bytes("different consumer NAR");
        let bundle = bundle_with_artifacts(
            vec![
                different_consumer_identity,
                document.provider.artifact.clone(),
            ],
            Vec::new(),
        );
        let checked = CheckedArtifactConsumptionEvidence::check(document).unwrap();

        assert!(matches!(
            checked.query_with_bundle(&ArtifactConsumptionQuery::default(), &bundle),
            Err(ArtifactConsumptionEvidenceError::ConsumerAbsentFromAbilityGraph)
        ));
    }

    #[test]
    fn checked_evidence_rejects_unrelated_edge_with_both_artifacts_present() {
        let document = document();
        let mut unrelated = observed_helper_document(vec![format!("{PROVIDER_STORE}/bin/helper")]);
        unrelated.id = LocalKey::new("unrelated-helper-edge").unwrap();
        let bundle = bundle_with_artifacts(
            vec![
                document.consumer.artifact.clone(),
                document.provider.artifact.clone(),
            ],
            vec![unrelated],
        );
        let checked = CheckedArtifactConsumptionEvidence::check(document).unwrap();

        assert!(matches!(
            checked.query_with_bundle(&ArtifactConsumptionQuery::default(), &bundle),
            Err(ArtifactConsumptionEvidenceError::ConsumptionEdgeAbsentFromAbilityGraph)
        ));
    }

    #[test]
    fn checked_evidence_rejects_contract_observation_disagreement() {
        let mut document = document();
        let ArtifactConsumptionObservation::ElfStartupLinkage(observation) =
            &mut document.observation
        else {
            panic!("ELF observation fixture");
        };
        observation.needed = vec!["libsubstituted.so.1".to_string()];
        let bytes = encode_canonical(&document).unwrap();

        assert!(matches!(
            CheckedArtifactConsumptionEvidence::decode(&bytes),
            Err(ArtifactConsumptionEvidenceError::ObservationMismatch)
        ));
    }

    #[test]
    fn checked_evidence_rejects_search_entries_outside_the_store() {
        let mut document = document();
        let ArtifactConsumptionContract::ElfStartupLinkage(contract) = &mut document.contract
        else {
            panic!("ELF contract fixture");
        };
        contract.search_path.insert(0, "/tmp/shadow".to_string());
        let search_path = contract.search_path.clone();
        let ArtifactConsumptionObservation::ElfStartupLinkage(observation) =
            &mut document.observation
        else {
            panic!("ELF observation fixture");
        };
        observation.search_path = search_path;

        assert!(matches!(
            CheckedArtifactConsumptionEvidence::check(document),
            Err(ArtifactConsumptionEvidenceError::SearchPath)
        ));
    }

    #[test]
    fn exact_query_rejects_another_provider() {
        let checked = CheckedArtifactConsumptionEvidence::check(document()).unwrap();
        let query =
            ArtifactConsumptionQuery::new(None, Some(Sha256Digest::of_bytes("another provider")));

        assert!(matches!(
            checked.query(&query),
            Err(ArtifactConsumptionEvidenceError::ProviderMismatch)
        ));
    }

    #[test]
    fn observed_helper_evidence_requires_access_output_and_retention() {
        let arguments = vec![format!("{PROVIDER_STORE}/bin/helper")];
        let mut document = observed_helper_document(arguments);

        let checked = CheckedArtifactConsumptionEvidence::check(document.clone()).unwrap();
        let explanation = checked.query(&ArtifactConsumptionQuery::default()).unwrap();
        assert_eq!(explanation.provider_access_observed, Some(true));
        assert!(
            !explanation
                .limitations
                .contains(&ArtifactConsumptionLimitation::NoHelperExecutionEvidence)
        );

        let mut invalid_retention = document.clone();
        let ArtifactConsumptionContract::ObservedPath(contract) = &mut invalid_retention.contract
        else {
            panic!("observed path contract fixture");
        };
        contract.retention = ArtifactRetentionRequirement::Forbidden;
        let ArtifactConsumptionObservation::ObservedPath(observation) =
            &mut invalid_retention.observation
        else {
            panic!("observed path fixture");
        };
        observation.provider_retained_by_consumer = false;
        assert!(matches!(
            CheckedArtifactConsumptionEvidence::check(invalid_retention),
            Err(ArtifactConsumptionEvidenceError::ProviderRetentionMismatch)
        ));

        let ArtifactConsumptionObservation::ObservedPath(observation) = &mut document.observation
        else {
            panic!("observed path fixture");
        };
        observation.provider_access_observed = false;
        assert!(matches!(
            CheckedArtifactConsumptionEvidence::check(document),
            Err(ArtifactConsumptionEvidenceError::ObservationMismatch)
        ));
    }

    #[test]
    fn observed_path_arguments_accept_empty_and_newline_values() {
        let arguments = vec![String::new(), "first line\nsecond line".to_string()];

        CheckedArtifactConsumptionEvidence::check(observed_helper_document(arguments)).unwrap();
    }

    #[test]
    fn observed_path_arguments_reject_nul_values() {
        let arguments = vec!["before\0after".to_string()];

        assert!(matches!(
            CheckedArtifactConsumptionEvidence::check(observed_helper_document(arguments)),
            Err(ArtifactConsumptionEvidenceError::Bound {
                field: "invocation argument"
            })
        ));
    }
}
