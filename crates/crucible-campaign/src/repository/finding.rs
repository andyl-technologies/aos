//! Atomic finding publication and imported finding-owner validation.

use super::*;
use crate::{ExactCheckpointId, FindingExactPins, FindingKind, FindingSignature, FindingTarget};

/// Stable result of publishing or rediscovering one campaign finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingPublicationResult {
    /// Snapshot that owned the finding candidate.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot that first recorded this exact cluster update.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable finding record selected by the update.
    pub finding: FindingId,
    /// Whether the same occurrence and retention basis was already current.
    pub replayed: bool,
}

impl CampaignRepository {
    /// Publishes or extends one stable finding cluster atomically.
    ///
    /// The signature key selects at most one cluster. Rediscovery preserves the
    /// first observation, reproduction, and parent snapshot while unioning the
    /// occurrence and exact-pin sets. A minimized reproduction may be added but
    /// never replaced by a different artifact.
    ///
    /// # Errors
    ///
    /// Returns an error without writing when the expected snapshot is stale,
    /// the observation is not canonical in that snapshot, the signature's
    /// target/evidence is not owned by the observation, either reproduction is
    /// missing or inconsistent, an existing cluster conflicts, or bounds are
    /// exceeded. Storage failure after preflight may leave unreachable
    /// immutable objects before the final ref compare-and-swap.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_finding(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: BTreeSet<ExactCheckpointId>,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        self.publish_finding_with_retention(
            name,
            expected_snapshot,
            signature,
            observation,
            reproduction,
            minimized,
            FindingExactPins::from_untyped(exact_pins)?,
        )
    }

    /// Publishes a finding with role-tagged exact-checkpoint retention.
    ///
    /// Rediscovery unions each role independently. The first observation and
    /// original reproduction remain immutable, and a minimized reproduction
    /// may be added exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error under the same fail-closed and failure-atomic contract
    /// as [`Self::publish_finding`].
    #[allow(clippy::too_many_arguments)]
    pub fn publish_finding_with_retention(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;
        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        let observation_value = self.read_observation(observation.content_id())?;
        if self.merkle.get(
            current.snapshot.roots().observations,
            map_key_content(
                "observations.attempt",
                observation_value.attempt().content_id(),
            ),
        )? != Some(observation.content_id())
        {
            return Err(integrity("finding-observation-is-not-canonical"));
        }
        self.validate_finding_candidate_basis(
            &signature,
            &observation_value,
            reproduction,
            minimized,
        )?;

        let key = finding_signature_key(signature.cluster_key());
        let existing = self
            .merkle
            .get(current.snapshot.roots().findings, key)?
            .map(|id| self.read_finding(id))
            .transpose()?;
        let (
            representative,
            latest_occurrence,
            original_reproduction,
            first_seen,
            prior_occurrences,
            occurrences,
            occurrence_count,
            selected_minimized,
            pins,
        ) = if let Some(existing) = existing {
            if existing.signature() != &signature {
                return Err(integrity("finding-signature-key-collision"));
            }
            let occurrence_key = finding_occurrence_key(observation);
            let already_present = self.merkle.get(existing.occurrences(), occurrence_key)?
                == Some(observation.content_id());
            let occurrences = self.merkle.root_after_upserts(
                existing.occurrences(),
                &BTreeMap::from([(occurrence_key, observation.content_id())]),
            )?;
            let occurrence_count = if already_present {
                existing.occurrence_count()
            } else {
                existing
                    .occurrence_count()
                    .checked_add(1)
                    .ok_or_else(|| integrity("finding-occurrence-count"))?
            };
            let selected_minimized = match (existing.minimized(), minimized) {
                (Some(left), Some(right)) if left != right => {
                    return Err(CampaignRepositoryError::AlreadyExists);
                }
                (Some(value), _) | (None, Some(value)) => Some(value),
                (None, None) => None,
            };
            let pins = existing.exact_pin_retention().union(&exact_pins)?;
            (
                existing.observation(),
                if already_present {
                    existing.latest_occurrence()
                } else {
                    observation
                },
                existing.reproduction(),
                existing.first_seen_snapshot(),
                existing.occurrences(),
                occurrences,
                occurrence_count,
                selected_minimized,
                pins,
            )
        } else {
            let prior_occurrences = MerkleMap::empty_content_id()?;
            let occurrences = self.merkle.root_after_upserts(
                prior_occurrences,
                &BTreeMap::from([(
                    finding_occurrence_key(observation),
                    observation.content_id(),
                )]),
            )?;
            (
                observation,
                observation,
                reproduction,
                current_id,
                prior_occurrences,
                occurrences,
                1,
                minimized,
                exact_pins,
            )
        };

        let finding = Finding::new_with_retention(
            signature,
            representative,
            original_reproduction,
            first_seen,
            FindingOccurrenceSet::new(occurrences, occurrence_count, latest_occurrence)?,
            selected_minimized,
            pins,
        )?;
        let finding_id = finding.id()?;
        if self.merkle.get(current.snapshot.roots().findings, key)? == Some(finding_id.content_id())
        {
            return Ok(FindingPublicationResult {
                prior_snapshot: current_id,
                new_snapshot: current_id,
                finding: finding_id,
                replayed: true,
            });
        }

        let mut anchors = BTreeSet::from([
            current_content,
            current.snapshot.lineage().content_id(),
            current.snapshot.active_policy().content_id(),
        ]);
        anchors.extend(snapshot_roots(&current.snapshot));
        self.verify_campaign_closures_anchored_cached(
            finding
                .content_children()
                .into_iter()
                .filter_map(|(role, id)| (role != "occurrences").then_some(id)),
            &anchors,
            &mut ChoiceValidationCache::default(),
        )?;

        let published_occurrences = self
            .merkle
            .insert(
                prior_occurrences,
                finding_occurrence_key(latest_occurrence),
                latest_occurrence.content_id(),
            )?
            .content_id();
        if published_occurrences != occurrences {
            return Err(integrity("finding-occurrence-root-publication-mismatch"));
        }

        if self.put_finding(&finding)? != finding_id.content_id() {
            return Err(integrity("finding-publication-id-mismatch"));
        }
        let mut roots = current.snapshot.roots();
        roots.findings = self
            .merkle
            .insert(roots.findings, key, finding_id.content_id())?
            .content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let transition = self.put_fact(&CampaignFact::FindingPublished(finding_id))?;
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(FindingPublicationResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    finding: finding_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    fn validate_finding_candidate_basis(
        &self,
        signature: &FindingSignature,
        observation: &Observation,
        reproduction: ReproductionArtifactId,
        minimized: Option<ReproductionArtifactId>,
    ) -> Result<(), CampaignRepositoryError> {
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        if signature.kind() == FindingKind::PropertyViolation {
            let property = signature
                .property()
                .ok_or_else(|| integrity("finding-property-signature-has-no-property"))?;
            let properties =
                self.read_property_verdict_set(observation.properties().content_id())?;
            if properties
                .properties()
                .get(property)
                .map(|evidence| evidence.verdict())
                != Some(PropertyVerdict::Failed)
            {
                return Err(integrity("finding-property-is-not-a-failed-verdict"));
            }
        }
        let reproduction_id = reproduction;
        let reproduction = self.read_reproduction_artifact(reproduction_id.content_id())?;
        if reproduction.finding_fingerprint() != signature.fingerprint()
            || reproduction.scenario() != child.scenario()
            || reproduction.configuration_artifact() != observation.child_content()
        {
            return Err(integrity("finding-candidate-reproduction-basis-mismatch"));
        }
        if let Some(minimized) = minimized {
            let minimized_value = self.read_reproduction_artifact(minimized.content_id())?;
            if minimized_value.finding_fingerprint() != signature.fingerprint()
                || minimized_value.scenario() != child.scenario()
            {
                return Err(integrity("finding-candidate-minimized-basis-mismatch"));
            }
            let minimization = minimized_value
                .minimization()
                .ok_or_else(|| integrity("finding-candidate-minimized-has-no-retained-trace"))?;
            if minimization.original() != reproduction_id {
                return Err(integrity(
                    "finding-candidate-minimization-original-mismatch",
                ));
            }
        }
        match signature.target() {
            Some(FindingTarget::Configuration(configuration))
                if configuration != observation.child_content() =>
            {
                return Err(integrity("finding-candidate-configuration-target-mismatch"));
            }
            Some(FindingTarget::ChoiceOpportunity(opportunity))
                if !observation.discovered_choices().contains(&opportunity) =>
            {
                return Err(integrity("finding-candidate-choice-target-mismatch"));
            }
            _ => {}
        }
        let observation_children = observation
            .content_children()
            .into_iter()
            .map(|(_, id)| id)
            .collect::<BTreeSet<_>>();
        if !signature.causal_evidence().is_subset(&observation_children) {
            return Err(integrity(
                "finding-candidate-evidence-is-not-observation-owned",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_finding_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        finding_id: FindingId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("finding-transition-changed-campaign-basis"));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.pins != next.pins
            || prior.accounting != next.accounting
        {
            return Err(integrity("finding-transition-changed-unrelated-root"));
        }
        let finding = self.read_finding_cached(finding_id.content_id(), choice_cache)?;
        let representative = self.decode_observation(finding.observation().content_id())?;
        self.validate_finding_candidate_basis(
            finding.signature(),
            &representative,
            finding.reproduction(),
            finding.minimized(),
        )?;
        let latest = self.decode_observation(finding.latest_occurrence().content_id())?;
        if self.merkle.get(
            prior.observations,
            map_key_content("observations.attempt", latest.attempt().content_id()),
        )? != Some(finding.latest_occurrence().content_id())
        {
            return Err(integrity("finding-transition-occurrence-is-not-canonical"));
        }
        let prior_finding = self
            .merkle
            .get(
                prior.findings,
                finding_signature_key(finding.signature().cluster_key()),
            )?
            .map(|id| self.read_finding_cached(id, choice_cache))
            .transpose()?;
        if let Some(previous) = prior_finding {
            let latest_was_present = self.merkle.get(
                previous.occurrences(),
                finding_occurrence_key(finding.latest_occurrence()),
            )? == Some(finding.latest_occurrence().content_id());
            let expected_occurrences = self.merkle.root_after_upserts(
                previous.occurrences(),
                &BTreeMap::from([(
                    finding_occurrence_key(finding.latest_occurrence()),
                    finding.latest_occurrence().content_id(),
                )]),
            )?;
            let expected_count = previous
                .occurrence_count()
                .checked_add(u32::from(!latest_was_present))
                .ok_or_else(|| integrity("finding-occurrence-count"))?;
            if previous.signature() != finding.signature()
                || previous.observation() != finding.observation()
                || previous.reproduction() != finding.reproduction()
                || previous.first_seen_snapshot() != finding.first_seen_snapshot()
                || finding.occurrences() != expected_occurrences
                || finding.occurrence_count() != expected_count
                || !previous.exact_pins().is_subset(finding.exact_pins())
                || matches!(
                    (previous.minimized(), finding.minimized()),
                    (Some(left), Some(right)) if left != right
                )
                || matches!((previous.minimized(), finding.minimized()), (Some(_), None))
            {
                return Err(integrity(
                    "finding-transition-cluster-regressed-or-replaced",
                ));
            }
        } else {
            let expected_occurrences = self.merkle.root_after_upserts(
                MerkleMap::empty_content_id()?,
                &BTreeMap::from([(
                    finding_occurrence_key(finding.latest_occurrence()),
                    finding.latest_occurrence().content_id(),
                )]),
            )?;
            if finding.first_seen_snapshot().content_id() != parent.envelope.content_id()
                || finding.observation() != finding.latest_occurrence()
                || finding.occurrences() != expected_occurrences
                || finding.occurrence_count() != 1
            {
                return Err(integrity("finding-transition-first-publication-basis"));
            }
        }
        let expected_findings = self.merkle.root_after_upserts(
            prior.findings,
            &BTreeMap::from([(
                finding_signature_key(finding.signature().cluster_key()),
                finding_id.content_id(),
            )]),
        )?;
        if next.findings != expected_findings {
            return Err(integrity("finding-transition-findings-root"));
        }
        if next.findings == prior.findings {
            return Err(integrity("finding-transition-did-not-change-cluster"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("finding-transition-coordination-root"));
        }
        Ok(())
    }
}

pub(crate) fn finding_signature_key(signature: CampaignHash) -> CampaignHash {
    map_key_hash("findings.signature", signature)
}

pub(super) fn finding_occurrence_key(observation: ObservationId) -> CampaignHash {
    map_key_content("findings.occurrence", observation.content_id())
}
