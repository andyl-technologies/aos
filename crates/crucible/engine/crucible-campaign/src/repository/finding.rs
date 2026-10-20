//! Atomic finding publication and imported finding-owner validation.

use super::*;
use crate::{
    FindingCandidateBundleId, FindingExactPins, FindingKind, FindingSignature, FindingTarget,
};

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

pub(super) struct FindingPublicationInput<'a> {
    pub(super) name: &'a str,
    pub(super) expected_snapshot: CampaignSnapshotId,
    pub(super) signature: FindingSignature,
    pub(super) observation: ObservationId,
    pub(super) reproduction: ReproductionArtifactId,
    pub(super) minimized: Option<ReproductionArtifactId>,
    pub(super) exact_pins: FindingExactPins,
    pub(super) candidate_bundle: FindingCandidateBundleId,
}

impl CampaignRepository {
    pub(super) fn publish_finding_with_candidate_bundle(
        &self,
        input: FindingPublicationInput<'_>,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        let FindingPublicationInput {
            name,
            expected_snapshot,
            signature,
            observation,
            reproduction,
            minimized,
            exact_pins,
            candidate_bundle,
        } = input;
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
        let bundle = self.load_finding_candidate_bundle(candidate_bundle)?;
        if bundle.signature() != &signature
            || bundle.observation() != observation
            || bundle.reproduction() != reproduction
            || Some(bundle.minimized()) != minimized
            || bundle.exact_pins() != &exact_pins
        {
            return Err(integrity(
                "finding-candidate-bundle-publication-basis-mismatch",
            ));
        }
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
            selected_candidate_bundle,
            prior_candidate_occurrences,
            candidate_occurrence_upserts,
            candidate_occurrences,
            candidate_occurrence_count,
            latest_candidate_bundle,
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
            let selected_minimized = existing.minimized();
            let pins = existing.exact_pin_retention().union(&exact_pins)?;
            let prior_candidate_occurrences = existing.candidate_occurrences();
            let candidate_key = finding_candidate_occurrence_key(candidate_bundle);
            let candidate_already_present = self
                .merkle
                .get(prior_candidate_occurrences, candidate_key)?
                == Some(candidate_bundle.content_id());
            let candidate_occurrence_upserts =
                BTreeMap::from([(candidate_key, candidate_bundle.content_id())]);
            let candidate_occurrences = self
                .merkle
                .root_after_upserts(prior_candidate_occurrences, &candidate_occurrence_upserts)?;
            let candidate_occurrence_count = existing
                .candidate_occurrence_count()
                .checked_add(u32::from(!candidate_already_present))
                .ok_or_else(|| integrity("finding-candidate-occurrence-count"))?;
            let latest_candidate_bundle = if candidate_already_present {
                existing.latest_candidate_bundle()
            } else {
                candidate_bundle
            };
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
                existing.candidate_bundle(),
                prior_candidate_occurrences,
                candidate_occurrence_upserts,
                candidate_occurrences,
                candidate_occurrence_count,
                latest_candidate_bundle,
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
            let prior_candidate_occurrences = MerkleMap::empty_content_id()?;
            let candidate_occurrence_upserts = BTreeMap::from([(
                finding_candidate_occurrence_key(candidate_bundle),
                candidate_bundle.content_id(),
            )]);
            let candidate_occurrences = self
                .merkle
                .root_after_upserts(prior_candidate_occurrences, &candidate_occurrence_upserts)?;
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
                candidate_bundle,
                prior_candidate_occurrences,
                candidate_occurrence_upserts,
                candidate_occurrences,
                1,
                candidate_bundle,
            )
        };

        let occurrence_set =
            FindingOccurrenceSet::new(occurrences, occurrence_count, latest_occurrence)?;
        let finding = Finding::new_with_candidate_occurrences(
            Finding::basis(
                signature,
                representative,
                original_reproduction,
                first_seen,
                occurrence_set,
            ),
            selected_minimized,
            pins,
            selected_candidate_bundle,
            FindingCandidateOccurrenceSet::new(
                candidate_occurrences,
                candidate_occurrence_count,
                latest_candidate_bundle,
            )?,
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
                .filter_map(|(role, id)| {
                    (!matches!(role.as_str(), "occurrences" | "candidate-occurrences"))
                        .then_some(id)
                }),
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
        let mut published_candidate_occurrences = prior_candidate_occurrences;
        for (key, bundle) in &candidate_occurrence_upserts {
            published_candidate_occurrences = self
                .merkle
                .insert(published_candidate_occurrences, *key, *bundle)?
                .content_id();
        }
        if candidate_occurrences != published_candidate_occurrences {
            return Err(integrity(
                "finding-candidate-occurrence-root-publication-mismatch",
            ));
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
        let (next, budget_witness) = self.budgeted_successor(
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
            &budget_witness,
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

    pub(super) fn validate_finding_candidate_basis(
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
        let bundle = self.load_finding_candidate_bundle(finding.candidate_bundle())?;
        if bundle.signature() != finding.signature()
            || !exact_pins_contain(finding.exact_pin_retention(), bundle.exact_pins())
            || self.merkle.get(
                finding.occurrences(),
                finding_occurrence_key(bundle.observation()),
            )? != Some(bundle.observation().content_id())
        {
            return Err(integrity("finding-candidate-bundle-retention-mismatch"));
        }
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
            let previous_candidate_root = previous.candidate_occurrences();
            let latest_bundle = finding.latest_candidate_bundle();
            let candidate_key = finding_candidate_occurrence_key(latest_bundle);
            let candidate_was_present = self.merkle.get(previous_candidate_root, candidate_key)?
                == Some(latest_bundle.content_id());
            let candidate_upserts = BTreeMap::from([(candidate_key, latest_bundle.content_id())]);
            let expected_candidate_root = self
                .merkle
                .root_after_upserts(previous_candidate_root, &candidate_upserts)?;
            let expected_candidate_count = previous
                .candidate_occurrence_count()
                .checked_add(u32::from(!candidate_was_present))
                .ok_or_else(|| integrity("finding-candidate-occurrence-count"))?;
            if !candidate_was_present {
                let bundle = self.load_finding_candidate_bundle(latest_bundle)?;
                let observation = self.decode_observation(bundle.observation().content_id())?;
                if bundle.signature() != finding.signature()
                    || self.merkle.get(
                        finding.occurrences(),
                        finding_occurrence_key(bundle.observation()),
                    )? != Some(bundle.observation().content_id())
                    || self.merkle.get(
                        prior.observations,
                        map_key_content("observations.attempt", observation.attempt().content_id()),
                    )? != Some(bundle.observation().content_id())
                {
                    return Err(integrity("finding-transition-candidate-occurrence-basis"));
                }
            }
            if previous.signature() != finding.signature()
                || previous.observation() != finding.observation()
                || previous.reproduction() != finding.reproduction()
                || previous.first_seen_snapshot() != finding.first_seen_snapshot()
                || finding.occurrences() != expected_occurrences
                || finding.occurrence_count() != expected_count
                || finding.candidate_occurrences() != expected_candidate_root
                || finding.candidate_occurrence_count() != expected_candidate_count
                || candidate_was_present
                    && finding.latest_candidate_bundle() != previous.latest_candidate_bundle()
                || !previous.exact_pins().is_subset(finding.exact_pins())
                || matches!(
                    (previous.minimized(), finding.minimized()),
                    (Some(left), Some(right)) if left != right
                )
                || matches!((previous.minimized(), finding.minimized()), (Some(_), None))
                || previous.candidate_bundle() != finding.candidate_bundle()
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
            let bundle = finding.candidate_bundle();
            let expected_candidate_occurrences = self.merkle.root_after_upserts(
                MerkleMap::empty_content_id()?,
                &BTreeMap::from([(
                    finding_candidate_occurrence_key(bundle),
                    bundle.content_id(),
                )]),
            )?;
            if finding.first_seen_snapshot().content_id() != parent.envelope.content_id()
                || finding.observation() != finding.latest_occurrence()
                || finding.occurrences() != expected_occurrences
                || finding.occurrence_count() != 1
                || finding.candidate_occurrences() != expected_candidate_occurrences
                || finding.candidate_occurrence_count() != 1
                || finding.latest_candidate_bundle() != finding.candidate_bundle()
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

pub(crate) fn finding_candidate_occurrence_key(bundle: FindingCandidateBundleId) -> CampaignHash {
    map_key_content("findings.candidate-occurrence", bundle.content_id())
}

fn exact_pins_contain(retained: &FindingExactPins, requested: &FindingExactPins) -> bool {
    requested.pre_failure().is_subset(retained.pre_failure())
        && requested
            .measurement_boundary()
            .is_subset(retained.measurement_boundary())
        && requested.post_failure().is_subset(retained.post_failure())
        && requested.additional().is_subset(retained.additional())
}
