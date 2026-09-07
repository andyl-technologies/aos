//! Immutable finding-candidate publication and restart-safe validation.

use super::*;
use crate::{FindingCandidateBundle, FindingCandidateBundleId, FindingExactPins, FindingId};

impl CampaignRepository {
    /// Publishes one fully verified finding candidate handoff.
    ///
    /// The observation and both reproduction artifacts must already be durable.
    /// This operation validates their exact signature, scenario, configuration,
    /// fingerprint and complete-signature minimization evidence, plus the
    /// reachability of every retained checkpoint reference, before storing the
    /// acyclic bundle. Repeating the same operation returns the same content ID.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when any referenced object is
    /// missing, corrupt, or inconsistent with the bundle.
    pub fn publish_finding_candidate_bundle(
        &self,
        bundle: &FindingCandidateBundle,
    ) -> Result<FindingCandidateBundleId, CampaignRepositoryError> {
        self.validate_finding_candidate_bundle(bundle)?;
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::FindingCandidateBundle,
            crate::object::content_children(bundle.content_children())?,
            bundle.canonical_bytes(),
        )?)?;
        if content != bundle.id()?.content_id() {
            return Err(integrity(
                "finding-candidate-bundle-publication-id-mismatch",
            ));
        }
        self.verify_campaign_closure(content)?;
        FindingCandidateBundleId::from_content_id(content).map_err(Into::into)
    }

    /// Loads and authenticates one durable finding candidate handoff.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the bundle or any of its
    /// referenced observation, reproduction, evidence, or retention object is
    /// missing, corrupt, or inconsistent.
    pub fn load_finding_candidate_bundle(
        &self,
        id: FindingCandidateBundleId,
    ) -> Result<FindingCandidateBundle, CampaignRepositoryError> {
        let bundle = self.decode_finding_candidate_bundle(id.content_id())?;
        self.validate_finding_candidate_bundle(&bundle)?;
        Ok(bundle)
    }

    /// Incorporates one durable finding candidate into a campaign.
    ///
    /// The expected snapshot is the observation-owning campaign head reported
    /// to the worker. If the exact bundle was already incorporated and a later
    /// campaign transition advanced the head, this method recognizes its
    /// occurrence, minimized reproduction, and complete pin retention and
    /// returns an idempotent replay result. Any other stale head fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle is invalid, the campaign head is stale
    /// without the exact retained result, or ordinary finding publication fails.
    pub fn incorporate_finding_candidate_bundle(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        bundle: FindingCandidateBundleId,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        let bundle_id = bundle;
        let bundle = self.load_finding_candidate_bundle(bundle_id)?;
        let head = self.head(name)?;
        if let Some(replayed) = self.replayed_finding_candidate(&head, &bundle)? {
            return Ok(replayed);
        }
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }

        self.publish_finding_with_candidate_bundle(
            name,
            expected_snapshot,
            bundle.signature().clone(),
            bundle.observation(),
            bundle.reproduction(),
            Some(bundle.minimized()),
            bundle.exact_pins().clone(),
            Some(bundle_id),
        )
    }

    pub(super) fn decode_finding_candidate_bundle(
        &self,
        id: ContentId,
    ) -> Result<FindingCandidateBundle, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::FindingCandidateBundle)?;
        let bundle = FindingCandidateBundle::from_canonical_bytes(envelope.body())?;
        if bundle.id()?.content_id() != id {
            return Err(integrity("finding-candidate-bundle-envelope-shape"));
        }
        Ok(bundle)
    }

    pub(super) fn validate_finding_candidate_bundle(
        &self,
        bundle: &FindingCandidateBundle,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.read_observation(bundle.observation().content_id())?;
        self.validate_finding_candidate_basis(
            bundle.signature(),
            &observation,
            bundle.reproduction(),
            Some(bundle.minimized()),
        )?;
        let minimized = self.read_reproduction_artifact(bundle.minimized().content_id())?;
        let minimization = minimized
            .minimization()
            .ok_or_else(|| integrity("finding-candidate-minimized-has-no-retained-trace"))?;
        bundle
            .signature_minimization()
            .validate_against(bundle.signature(), minimization)?;
        for (_, child) in bundle.signature_minimization().content_children() {
            let handle = self.blobs.read(child, None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        for pin in bundle.exact_pins().all() {
            let handle = self.blobs.read(pin.content_id(), None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        Ok(())
    }

    fn replayed_finding_candidate(
        &self,
        head: &CampaignHead,
        bundle: &FindingCandidateBundle,
    ) -> Result<Option<FindingPublicationResult>, CampaignRepositoryError> {
        let key = finding_signature_key(bundle.signature().cluster_key());
        let Some(finding_id) = self.merkle.get(head.snapshot().roots().findings, key)? else {
            return Ok(None);
        };
        let finding = self.read_finding(finding_id)?;
        let occurrence = self.merkle.get(
            finding.occurrences(),
            finding_occurrence_key(bundle.observation()),
        )?;
        if finding.signature() != bundle.signature()
            || occurrence != Some(bundle.observation().content_id())
            || finding.minimized() != Some(bundle.minimized())
            || finding.candidate_bundle() != Some(bundle.id()?)
            || !exact_pins_contain(finding.exact_pin_retention(), bundle.exact_pins())
        {
            return Ok(None);
        }

        Ok(Some(FindingPublicationResult {
            prior_snapshot: head.snapshot_id(),
            new_snapshot: head.snapshot_id(),
            finding: FindingId::from_content_id(finding_id)?,
            replayed: true,
        }))
    }
}

fn exact_pins_contain(retained: &FindingExactPins, requested: &FindingExactPins) -> bool {
    requested.pre_failure().is_subset(retained.pre_failure())
        && requested
            .measurement_boundary()
            .is_subset(retained.measurement_boundary())
        && requested.post_failure().is_subset(retained.post_failure())
        && requested.additional().is_subset(retained.additional())
}
