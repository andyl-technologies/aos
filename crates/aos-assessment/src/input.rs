//! Frozen evaluation inputs, policies and exact retained evidence closure.
//!
//! `aos.scan-input/v1` contains semantic identities and explicit time, never SQL
//! operation IDs, elapsed durations, credentials or runtime location. A caller
//! supplies every referenced object before evaluation can begin.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::advisory::{AdvisoryRecordV1, AdvisorySnapshotV1};
use crate::definition::PackageScanDefinitionV1;
use crate::discovery::UpstreamObservationV1;
use crate::disposition::SecurityDispositionV1;
use crate::inventory::DiscoveryProvider;
use crate::scan_inventory::ScanInventoryV1;
use crate::time::Timestamp;
use crate::validation::{decode, digest, sorted, text};

/// Identifies the frozen semantic evaluation input format.
pub const SCAN_INPUT_V1: &str = "aos.scan-input/v1";

/// Identifies the evaluation-policy format.
pub const ASSESSMENT_POLICY_V1: &str = "aos.assessment-policy/v1";

/// Selects independently committed assessment profiles.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Preserves non-authoritative source license signals.
    LicenseSignals,
    /// Evaluates upstream release evidence and maintained-stream policy.
    Updates,
    /// Evaluates supported advisory claims and exact component inventories.
    Vulnerabilities,
}

/// Selects provider acquisition behavior without altering evaluation semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FreshnessMode {
    /// Reuses admitted evidence without implicit provider acquisition.
    Cached,
    /// Acquires only missing or expired observations within configured budgets.
    RefreshStale,
    /// Revalidates requested source queries without bypassing budgets.
    Refresh,
    /// Forbids provider network acquisition, preserving visible evidence gaps.
    Offline,
}

/// Binds the decision-relevant freshness and source requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentPolicyV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Maximum effective age of release/tag observations.
    pub upstream_max_age_seconds: u64,
    /// Maximum effective age of required advisory observations.
    pub advisory_max_age_seconds: u64,
    /// Additional required installed advisory sources, sorted and unique.
    pub required_advisory_sources: Vec<String>,
    /// Requires proven dependency coverage for a complete vulnerability result.
    pub require_dependency_coverage: bool,
}

impl AssessmentPolicyV1 {
    /// Validates bounded freshness and installed-source policy declarations.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema, invalid ages or source sets.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ASSESSMENT_POLICY_V1
            || !(1..=31_536_000).contains(&self.upstream_max_age_seconds)
            || !(1..=31_536_000).contains(&self.advisory_max_age_seconds)
            || self.required_advisory_sources.len() > 16
        {
            bail!("invalid assessment policy schema or bounds");
        }
        sorted(&self.required_advisory_sources, "required advisory sources")?;
        for provider in &self.required_advisory_sources {
            text(provider, 128, "required provider profile")?;
        }
        Ok(())
    }

    /// Computes the immutable evaluation-policy identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy or canonical bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(ASSESSMENT_POLICY_V1, self)
    }
}

/// Binds one portable component instance to its primary discovery evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamBinding {
    /// Exact instance within the portable inventory.
    pub component_ref: String,
    /// Immutable legacy-compatible normalized upstream observation.
    pub observation: UpstreamObservationV1,
    /// Exact retained response length, including legacy bounded page framing.
    pub response_byte_length: u64,
    /// Exact original page custody and any retained source-chain manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<crate::observation::SourceEvidenceRef>,
}

/// Retains a source-native first-observation identity independent of HTTP caches.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CandidateHistory {
    /// Installed upstream source profile.
    pub provider: String,
    /// Exact upstream project.
    pub project: String,
    /// Exact raw candidate identity.
    pub raw_id: String,
    /// Original admitted first-observed time, never reset by refresh.
    pub first_observed_at: Timestamp,
}

/// Freezes the complete identities consumed by deterministic evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanInputV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Exact normalized inventory identity.
    pub inventory_digest: Sha256Digest,
    /// Sorted exact subjects selected from the immutable inventory.
    pub subject_refs: Vec<String>,
    /// Independently requested profiles, sorted and unique.
    pub profiles: Vec<Profile>,
    /// Exact normalized observations, sorted and unique.
    pub observation_digests: Vec<Sha256Digest>,
    /// Required pinned snapshot when vulnerabilities are requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_snapshot_digest: Option<Sha256Digest>,
    /// Exact complete supplied statement set, including an explicit empty set.
    pub disposition_set_digest: Sha256Digest,
    /// Exact immutable evaluation policy.
    pub policy_digest: Sha256Digest,
    /// Exact durable candidate first-observation history.
    pub history_digest: Sha256Digest,
    /// Semantic engine/profile identity, independent of executable architecture.
    pub engine_digest: Sha256Digest,
    /// Explicit immutable evaluation time.
    pub evaluated_at: Timestamp,
}

impl ScanInputV1 {
    /// Validates the exact closed semantic-input structure.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema/engine, missing required snapshot,
    /// excessive references or duplicate/unordered profiles and observations.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCAN_INPUT_V1
            || self.engine_digest != engine_digest()
            || self.profiles.is_empty()
            || self.profiles.len() > 3
            || self.subject_refs.is_empty()
            || self.subject_refs.len() > 10_000
            || self.observation_digests.len() > 100_000
        {
            bail!("unsupported or invalid frozen scan input");
        }
        sorted(&self.profiles, "scan profiles")?;
        sorted(&self.subject_refs, "scan subject references")?;
        for subject in &self.subject_refs {
            text(subject, 128, "scan subject reference")?;
        }
        sorted(&self.observation_digests, "scan observation identities")?;
        if self.profiles.contains(&Profile::Vulnerabilities)
            && self.advisory_snapshot_digest.is_none()
        {
            bail!("vulnerability scan input lacks its exact advisory snapshot");
        }
        Ok(())
    }

    /// Computes the frozen semantic-input identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure or canonical bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(SCAN_INPUT_V1, self)
    }
}

/// Supplies the exact immutable objects needed to freeze and replay evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvaluationData {
    /// Complete portable subject/component/dependency inventory.
    pub inventory: ScanInventoryV1,
    /// Admitted package definitions referenced by the inventory.
    pub definitions: Vec<PackageScanDefinitionV1>,
    /// Component-keyed upstream observations.
    pub upstream: Vec<UpstreamBinding>,
    /// Complete supplied source/query snapshot for vulnerability evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_snapshot: Option<AdvisorySnapshotV1>,
    /// Exact normalized advisory revisions, not a mutable database lookup.
    pub advisories: Vec<AdvisoryRecordV1>,
    /// Complete supplied disposition set; admission authority is checked outside.
    pub dispositions: Vec<SecurityDispositionV1>,
    /// Independently retained first-observation history.
    pub history: Vec<CandidateHistory>,
    /// Exact evaluation policy.
    pub policy: AssessmentPolicyV1,
}

impl EvaluationData {
    /// Freezes an exact subject selector without changing retained inventory identity.
    ///
    /// # Errors
    /// Returns an error for invalid evidence, empty/unsorted/duplicate selectors,
    /// or a selected subject absent from the supplied immutable inventory.
    pub fn freeze_selected(
        &self,
        profiles: Vec<Profile>,
        subject_refs: Vec<String>,
        evaluated_at: Timestamp,
    ) -> Result<ScanInputV1> {
        let mut input = self.freeze(profiles, evaluated_at)?;
        let admitted = input
            .subject_refs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if subject_refs
            .iter()
            .any(|subject| !admitted.contains(subject.as_str()))
        {
            bail!("selected scan subject is absent from the immutable inventory");
        }
        input.subject_refs = subject_refs;
        input.validate()?;
        Ok(input)
    }

    /// Validates every referenced object and freezes its explicit identities.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/conflicting evidence, unbound metadata,
    /// inconsistent query origins/history, invalid graphs or resource bounds.
    pub fn freeze(&self, profiles: Vec<Profile>, evaluated_at: Timestamp) -> Result<ScanInputV1> {
        self.inventory.validate()?;
        self.policy.validate()?;
        if self.definitions.len() > 10_000
            || self.upstream.len() > 100_000
            || self.advisories.len() > 100_000
            || self.dispositions.len() > 100_000
            || self.history.len() > 100_000
        {
            bail!("frozen evaluation closure exceeds object budget");
        }
        let mut definitions = BTreeMap::new();
        for definition in &self.definitions {
            if definitions
                .insert(definition.digest()?, definition)
                .is_some()
            {
                bail!("duplicate scan definition object");
            }
        }
        let components = self
            .inventory
            .components
            .iter()
            .map(|component| (component.component_ref.as_str(), component))
            .collect::<BTreeMap<_, _>>();
        for component in &self.inventory.components {
            let definition = definitions
                .get(&component.scan_definition_digest)
                .context("component scan definition is missing")?;
            let declared = definition
                .components
                .iter()
                .find(|declared| declared.component_id == component.component_id)
                .context("component is absent from its exact scan definition")?;
            if declared.current != component.current || declared.security != component.security {
                bail!("component version/security differs from authenticated scan definition");
            }
        }
        for subject in &self.inventory.subjects {
            if !definitions.contains_key(&subject.scan_definition_digest) {
                bail!("subject scan definition is missing");
            }
        }
        validate_owners(&definitions)?;
        let mut observation_digests = BTreeSet::new();
        let mut bound_components = BTreeSet::new();
        sorted(&self.history, "candidate history")?;
        let mut history = BTreeMap::new();
        for entry in &self.history {
            text(&entry.provider, 128, "history provider")?;
            text(&entry.project, 1024, "history project")?;
            text(&entry.raw_id, 512, "history candidate")?;
            evaluated_at.elapsed_since(&entry.first_observed_at)?;
            if history
                .insert(
                    (&entry.provider, &entry.project, &entry.raw_id),
                    &entry.first_observed_at,
                )
                .is_some()
            {
                bail!("conflicting candidate first-observation history");
            }
        }
        for binding in &self.upstream {
            if binding.source_refs.len() > 128 {
                bail!("upstream source chain exceeds its custody reference ceiling");
            }
            sorted(&binding.source_refs, "upstream source custody references")?;
            if binding
                .source_refs
                .windows(2)
                .any(|pair| pair[0].digest == pair[1].digest)
            {
                bail!("upstream chain repeats a source custody identity");
            }
            for source in &binding.source_refs {
                if source.byte_length > 8 * 1024 * 1024
                    || source.origin != binding.observation.provider
                {
                    bail!("upstream source custody exceeds its exact provider/byte scope");
                }
            }
            if !binding.source_refs.is_empty()
                && !binding.source_refs.iter().any(|source| {
                    source.digest == binding.observation.response_digest
                        && source.byte_length == binding.response_byte_length
                })
            {
                bail!("upstream chain lacks its exact response custody");
            }
            if !bound_components.insert(&binding.component_ref) {
                bail!("duplicate upstream component binding");
            }
            let component = components
                .get(binding.component_ref.as_str())
                .context("upstream binding references missing component")?;
            let definition = definitions
                .get(&component.scan_definition_digest)
                .context("upstream definition is missing")?;
            let declared = definition
                .components
                .iter()
                .find(|declared| declared.component_id == component.component_id)
                .context("upstream component definition is missing")?;
            let expected = declared
                .discovery
                .primary
                .as_ref()
                .context("upstream observation has no declared primary")?;
            if provider_identity(expected)
                != (
                    binding.observation.provider.as_str(),
                    binding.observation.project.as_str(),
                )
            {
                bail!("upstream observation differs from the declared primary project");
            }
            binding.observation.validate()?;
            if binding.response_byte_length > 64 * 1024 * 1024 {
                bail!("upstream response custody exceeds per-task byte budget");
            }
            if binding.observation.retrieved_at_unix > evaluated_at.unix_seconds() {
                bail!("upstream observation is from the future");
            }
            for candidate in &binding.observation.candidates {
                let admitted = history
                    .get(&(
                        &binding.observation.provider,
                        &binding.observation.project,
                        &candidate.raw_id,
                    ))
                    .context("upstream candidate lacks retained history")?;
                if admitted.unix_seconds() != candidate.first_observed_at_unix {
                    bail!("upstream candidate resets admitted first-observation history");
                }
            }
            observation_digests.insert(Sha256Digest::of_canonical(
                "aos.component-upstream-observation/v1",
                binding,
            )?);
        }
        let records = self
            .advisories
            .iter()
            .map(|record| Ok((record.digest()?, record)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        if records.len() != self.advisories.len() {
            bail!("duplicate normalized advisory object");
        }
        let mut referenced = BTreeSet::new();
        let mut revisions = BTreeMap::new();
        if let Some(snapshot) = &self.advisory_snapshot {
            snapshot.validate()?;
            if let Some(catalog) = &snapshot.exploit_catalog {
                catalog.observation.is_fresh_at(&evaluated_at)?;
                observation_digests.insert(catalog.observation.digest()?);
            }
            for source in &snapshot.sources {
                source.observation.is_fresh_at(&evaluated_at)?;
                observation_digests.insert(source.observation.digest()?);
                for identity in &source.record_digests {
                    let record = records
                        .get(identity)
                        .context("snapshot advisory record is missing")?;
                    if record.provider != source.provider
                        || !source
                            .observation
                            .source_refs
                            .iter()
                            .any(|evidence| evidence.digest == record.source_digest)
                    {
                        bail!("advisory record differs from its admitted source evidence");
                    }
                    if revisions
                        .insert((&record.provider, &record.id), identity)
                        .is_some_and(|previous| previous != identity)
                    {
                        bail!("snapshot contains conflicting revisions of one source advisory");
                    }
                    referenced.insert(*identity);
                }
            }
        }
        if referenced.len() != records.len() {
            bail!("evaluation contains advisory records outside its pinned snapshot");
        }
        let mut dispositions = BTreeSet::new();
        for disposition in &self.dispositions {
            if !dispositions.insert(disposition.digest()?) {
                bail!("duplicate security disposition object");
            }
        }
        let input = ScanInputV1 {
            schema: SCAN_INPUT_V1.into(),
            inventory_digest: self.inventory.digest()?,
            subject_refs: self
                .inventory
                .subjects
                .iter()
                .map(|subject| subject.subject_ref.clone())
                .collect(),
            profiles,
            observation_digests: observation_digests.into_iter().collect(),
            advisory_snapshot_digest: self
                .advisory_snapshot
                .as_ref()
                .map(AdvisorySnapshotV1::digest)
                .transpose()?,
            disposition_set_digest: Sha256Digest::of_canonical(
                "aos.disposition-set/v1",
                &dispositions,
            )?,
            policy_digest: self.policy.digest()?,
            history_digest: Sha256Digest::of_canonical("aos.candidate-history/v1", &self.history)?,
            engine_digest: engine_digest(),
            evaluated_at,
        };
        input.validate()?;
        Ok(input)
    }

    /// Decodes a complete bounded evaluation closure without provider effects.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible/ambiguous JSON or document bounds.
    /// Call [`Self::freeze`] to validate exact semantic reference bindings.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        decode(bytes, "evaluation evidence closure")
    }
}

/// Returns the shared semantic engine identity for Native and Wasm builds.
#[must_use]
pub fn engine_digest() -> Sha256Digest {
    Sha256Digest::separated(
        "aos.assessment-engine/v1",
        "aos-assessment/1;osv-1.9.1;nvd-2.0;semver-2;numeric-1;coverage-1",
    )
}

/// Resolves a closed package provider declaration to its existing identity.
#[must_use]
pub fn provider_identity(provider: &DiscoveryProvider) -> (&str, &str) {
    match provider {
        DiscoveryProvider::GoReleases => ("go-releases", "go"),
        DiscoveryProvider::GithubReleases { repository, .. } => ("github-releases", repository),
        DiscoveryProvider::GithubTags { repository, .. } => ("github-tags", repository),
        DiscoveryProvider::Repology { project } => ("repology", project),
    }
}

fn validate_owners(definitions: &BTreeMap<Sha256Digest, &PackageScanDefinitionV1>) -> Result<()> {
    for definition in definitions.values() {
        let mut current = *definition;
        let mut visited = BTreeSet::new();
        for _ in 0..32 {
            let Some(owner) = &current.owner_ref else {
                break;
            };
            if !visited.insert(owner.definition_digest) {
                bail!("scan definition ownership cycle");
            }
            current = definitions
                .get(&owner.definition_digest)
                .context("scan owner definition is missing")?;
            if current.unit_id != owner.unit_id
                || current.members.binary_search(&owner.member_id).is_err()
            {
                bail!("scan owner unit differs from its exact definition");
            }
        }
        if current.owner_ref.is_some() {
            bail!("scan definition ownership exceeds depth limit");
        }
    }
    Ok(())
}
