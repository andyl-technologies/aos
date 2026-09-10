//! Checked decoding and focused queries for realized artifact consumption.
//!
//! The version-1 reader accepts only ELF startup linkage. Its answer explains
//! why one exact executable retains and names one exact shared library. It
//! cannot answer questions about plugins, explicit `dlopen` calls, runtime
//! helpers, build tools, or data artifacts because those mechanisms require
//! different observations.

use std::collections::BTreeSet;

use aos_ability_model::document::PlatformIdentity;
use aos_ability_model::{
    ABILITY_LIMITS_V1, ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA, ArtifactConsumptionEvidenceDocument,
    ArtifactConsumptionMechanism, ArtifactFileEvidence, ELF_STARTUP_LINKAGE_FEATURE,
    ElfStartupLinkageContract, RequiredFeature, decode_canonical,
};
use aos_contract::Sha256Digest;
use serde::Serialize;
use thiserror::Error;

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
    /// Pins the exact consuming executable.
    pub consumer: ArtifactFileEvidence,
    /// Pins the exact shared-library provider.
    pub provider: ArtifactFileEvidence,
    /// Records the checked ELF relationship that explains the consumption.
    pub linkage: ElfStartupLinkageContract,
    /// Confirms that the consumer's realized closure retains the provider.
    pub provider_retained_by_consumer: bool,
    /// Confirms compatible consumer and provider ELF identities.
    pub provider_elf_compatible: bool,
    /// Confirms a compatible program interpreter ELF identity.
    pub loader_elf_compatible: bool,
    /// Confirms the embedded search order selects this exact provider first.
    pub search_resolves_exact_provider: bool,
    /// Classifies the authority carried by this portable report.
    pub provenance: ArtifactConsumptionProvenance,
    /// States conclusions that this evidence mechanism cannot establish.
    pub limitations: Vec<ArtifactConsumptionLimitation>,
}

/// Classifies where a checked artifact-consumption claim originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionProvenance {
    /// The report says a hermetic build gate inspected these realized outputs.
    ReportedRealizedBuildGate,
}

/// Names a conclusion deliberately excluded from ELF startup-linkage evidence.
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
    #[error("artifact-consumption evidence must require exactly '{ELF_STARTUP_LINKAGE_FEATURE}'")]
    RequiredFeatures,
    /// The evidence mechanism does not agree with its feature declaration.
    #[error("artifact-consumption evidence mechanism and required feature disagree")]
    MechanismFeatureMismatch,
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
    /// The closure observation did not establish exact provider retention.
    #[error("artifact-consumption evidence does not establish provider retention")]
    ProviderNotRetained,
    /// A query named another consumer file.
    #[error("artifact-consumption query does not match the checked consumer")]
    ConsumerMismatch,
    /// A query named another provider artifact.
    #[error("artifact-consumption query does not match the checked provider")]
    ProviderMismatch,
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
        let supported_features =
            BTreeSet::from([RequiredFeature::new(ELF_STARTUP_LINKAGE_FEATURE)
                .map_err(ArtifactConsumptionEvidenceError::Feature)?]);
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
        validate_contract(&document)?;
        validate_observation(&document)?;

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

        Ok(ArtifactConsumptionExplanation {
            evidence_schema: ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA.to_string(),
            id: self.document.id.as_str().to_string(),
            mechanism: self.document.mechanism,
            platforms: self.document.platforms.clone(),
            consumer: self.document.consumer.clone(),
            provider: self.document.provider.clone(),
            linkage: self.document.contract.clone(),
            provider_retained_by_consumer: self.document.observation.provider_retained_by_consumer,
            provider_elf_compatible: self.document.observation.provider_elf_compatible,
            loader_elf_compatible: self.document.observation.loader_elf_compatible,
            search_resolves_exact_provider: self
                .document
                .observation
                .search_resolves_exact_provider,
            provenance: ArtifactConsumptionProvenance::ReportedRealizedBuildGate,
            limitations: vec![
                ArtifactConsumptionLimitation::NoPublicationAuthentication,
                ArtifactConsumptionLimitation::NoLiveLoaderEnforcement,
                ArtifactConsumptionLimitation::NoRuntimeRebinding,
                ArtifactConsumptionLimitation::NoPluginOrExplicitLoadEvidence,
                ArtifactConsumptionLimitation::NoHelperExecutionEvidence,
                ArtifactConsumptionLimitation::NoBuildToolExecutionEvidence,
                ArtifactConsumptionLimitation::NoDataInputEvidence,
            ],
        })
    }
}

fn validate_features(
    document: &ArtifactConsumptionEvidenceDocument,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    if document.required_features.len() != 1
        || document.required_features[0].as_str() != ELF_STARTUP_LINKAGE_FEATURE
    {
        return Err(ArtifactConsumptionEvidenceError::RequiredFeatures);
    }
    if document.mechanism != ArtifactConsumptionMechanism::ElfStartupLinkage {
        return Err(ArtifactConsumptionEvidenceError::MechanismFeatureMismatch);
    }
    Ok(())
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

fn validate_contract(
    document: &ArtifactConsumptionEvidenceDocument,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    let contract = &document.contract;
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

fn validate_observation(
    document: &ArtifactConsumptionEvidenceDocument,
) -> Result<(), ArtifactConsumptionEvidenceError> {
    let observation = &document.observation;
    if observation.soname != document.contract.soname
        || observation.needed != document.contract.needed
        || observation.search_path != document.contract.search_path
        || observation.search_path_kind != document.contract.search_path_kind
        || observation.loader != document.contract.loader
        || observation.symbols != document.contract.symbols
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
        return Err(ArtifactConsumptionEvidenceError::ProviderNotRetained);
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
        ArtifactConsumptionPlatforms, ElfSearchPathKind, ElfStartupLinkageObservation,
        ElfSymbolVersion, LocalKey, encode_canonical,
    };

    use super::*;

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
            observation: ElfStartupLinkageObservation {
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
            contract,
        }
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

        assert_eq!(explanation.linkage.soname, "libaos-contract.so.1");
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
    fn checked_evidence_rejects_contract_observation_disagreement() {
        let mut document = document();
        document.observation.needed = vec!["libsubstituted.so.1".to_string()];
        let bytes = encode_canonical(&document).unwrap();

        assert!(matches!(
            CheckedArtifactConsumptionEvidence::decode(&bytes),
            Err(ArtifactConsumptionEvidenceError::ObservationMismatch)
        ));
    }

    #[test]
    fn checked_evidence_rejects_search_entries_outside_the_store() {
        let mut document = document();
        document
            .contract
            .search_path
            .insert(0, "/tmp/shadow".to_string());
        document.observation.search_path = document.contract.search_path.clone();

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
}
