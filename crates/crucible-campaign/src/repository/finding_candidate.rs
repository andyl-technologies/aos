//! Immutable finding-candidate publication and restart-safe validation.

use super::*;
use crate::{
    CampaignName, ConfigurationId, FindingCandidateBundle, FindingCandidateBundleId,
    FindingExactPins, FindingExactRetentionDisposition, FindingId, FindingTarget,
    FindingTriageReplayStorageDescription, FindingTriageReplayStorageObject,
    FindingTriageReplayStorageObjectRole, MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
    ScenarioArtifactId, ScenarioDefId,
};

const MAX_FINDING_EXACT_PIN_ROOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL: u64 = 64 * 1024 * 1024;

mod recovery;
mod replay_evidence;

pub(super) use recovery::FindingCandidateValidation;
pub use recovery::{
    AuthenticatedFindingCandidateIncorporation, AuthenticatedFindingExactCheckpoint,
    FindingExactCheckpointAuthenticationError, FindingExactCheckpointAuthenticator,
};
use recovery::{
    BoundFindingCandidateIncorporationAuthorization,
    finding_candidate_incorporation_operation_digest,
};

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
        self.publish_finding_candidate_bundle_inner(bundle, None)
    }

    /// Publishes one candidate after typed whole-inventory authentication.
    ///
    /// Current V6 retention is a daemon attestation: the trusted executor
    /// enumerates candidates while holding its operational inventory fences,
    /// and this method authenticates every listed root before storing the
    /// immutable attestation. Later cold loads validate the attested selection
    /// and retained roots without requiring weak, unselected candidates to
    /// survive normal garbage collection.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, limit, or integrity error when a dependency is
    /// absent or the typed authority rejects any checkpoint or basis binding.
    pub(crate) fn publish_finding_candidate_bundle_with_authenticator(
        &self,
        bundle: &FindingCandidateBundle,
        authenticator: &dyn FindingExactCheckpointAuthenticator,
    ) -> Result<FindingCandidateBundleId, CampaignRepositoryError> {
        self.publish_finding_candidate_bundle_inner(bundle, Some(authenticator))
    }

    fn import_finding_exact_pin_closures(
        &self,
        pins: &FindingExactPins,
        source: &dyn FindingExactCheckpointAuthenticator,
    ) -> Result<(), CampaignRepositoryError> {
        let mut pending = pins
            .all()
            .iter()
            .map(|checkpoint| checkpoint.content_id())
            .collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut manifest_bytes = 0_u64;

        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > MAX_CAMPAIGN_CLOSURE_OBJECTS {
                return Err(integrity("finding-exact-pin-closure-object-limit"));
            }
            if id.kind() != ObjectKind::ExactManifest && !is_opaque_campaign_leaf(id.kind()) {
                return Err(integrity("finding-exact-pin-closure-kind"));
            }

            if !self.blobs.contains(id)? {
                let handle = source
                    .read_finding_exact_checkpoint_object(id)
                    .map_err(|_| integrity("finding-exact-pin-closure-import-failed"))?;
                let receipt = self.blobs.put_if_absent(id, &handle)?;
                if receipt.id != id {
                    return Err(integrity("finding-exact-pin-closure-import-id-mismatch"));
                }
            }

            let handle = self.blobs.read(id, None)?;
            if is_opaque_campaign_leaf(id.kind()) {
                handle.copy_to(&mut std::io::sink())?;
                continue;
            }

            let length = handle.logical_length();
            manifest_bytes = manifest_bytes
                .checked_add(length)
                .ok_or_else(|| integrity("finding-exact-pin-closure-byte-limit"))?;
            if length > MAX_FINDING_EXACT_PIN_ROOT_BYTES
                || manifest_bytes > MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL
            {
                return Err(integrity("finding-exact-pin-closure-byte-limit"));
            }
            let bytes = handle.read_all(MAX_FINDING_EXACT_PIN_ROOT_BYTES)?;
            let envelope =
                ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
            if envelope.content_id(ObjectKind::ExactManifest) != id {
                return Err(integrity("finding-exact-pin-closure-envelope-id-mismatch"));
            }
            for child in envelope.children() {
                pending.push(child.id());
            }
        }

        Ok(())
    }

    fn publish_finding_candidate_bundle_inner(
        &self,
        bundle: &FindingCandidateBundle,
        authenticator: Option<&dyn FindingExactCheckpointAuthenticator>,
    ) -> Result<FindingCandidateBundleId, CampaignRepositoryError> {
        self.validate_finding_candidate_bundle(
            bundle,
            FindingCandidateValidation::Publication(authenticator),
        )?;
        if bundle.exact_retention().disposition() == FindingExactRetentionDisposition::Complete
            && let Some(authenticator) = authenticator
        {
            self.import_finding_exact_pin_closures(bundle.exact_pins(), authenticator)?;
        }
        let content = self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::FindingCandidateBundle,
            bundle.schema_version(),
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
        self.validate_finding_candidate_bundle(&bundle, FindingCandidateValidation::Load)?;
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
        self.incorporate_finding_candidate_bundle_inner(name, expected_snapshot, bundle, None)
    }

    pub(in crate::repository) fn incorporate_checked_executor_finding_candidate_bundle(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        bundle: FindingCandidateBundleId,
        observation: ObservationId,
        completion_context_digest: CampaignHash,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        let authorization = BoundFindingCandidateIncorporationAuthorization {
            context_digest: completion_context_digest,
            operation_digest: finding_candidate_incorporation_operation_digest(
                name,
                expected_snapshot,
                bundle,
                observation,
                completion_context_digest,
            ),
        };
        self.incorporate_finding_candidate_bundle_inner(
            name,
            expected_snapshot,
            bundle,
            Some(authorization),
        )
    }

    fn incorporate_finding_candidate_bundle_inner(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        bundle: FindingCandidateBundleId,
        authorization: Option<BoundFindingCandidateIncorporationAuthorization>,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        let bundle_id = bundle;
        let bundle = self.load_finding_candidate_bundle(bundle_id)?;
        if let Some(authorization) = &authorization {
            let expected_authorization = finding_candidate_incorporation_operation_digest(
                name,
                expected_snapshot,
                bundle_id,
                bundle.observation(),
                authorization.context_digest,
            );
            if authorization.operation_digest != expected_authorization {
                return Err(integrity(
                    "finding-candidate-incorporation-authorization-mismatch",
                ));
            }
        }
        let head = self.head(name)?;
        self.validate_finding_candidate_incorporation_ancestry(&head, expected_snapshot, &bundle)?;
        if let Some(replayed) = self.replayed_finding_candidate(&head, &bundle)? {
            return Ok(replayed);
        }
        if bundle.exact_retention().disposition() == FindingExactRetentionDisposition::Complete
            && authorization.is_none()
        {
            return Err(integrity(
                "complete-finding-exact-retention-requires-executor-attested-incorporation",
            ));
        }
        self.require_policy_bound_finding_candidate(expected_snapshot, &bundle)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }

        self.publish_finding_with_candidate_bundle(super::finding::FindingPublicationInput {
            name,
            expected_snapshot,
            signature: bundle.signature().clone(),
            observation: bundle.observation(),
            reproduction: bundle.reproduction(),
            minimized: Some(bundle.minimized()),
            exact_pins: bundle.exact_pins().clone(),
            candidate_bundle: bundle_id,
        })
    }

    fn require_policy_bound_finding_candidate(
        &self,
        snapshot: CampaignSnapshotId,
        bundle: &FindingCandidateBundle,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.read_observation(bundle.observation().content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let admission = self
            .merkle
            .get(
                loaded.snapshot.roots().accounting,
                attempt_execution_basis_key(observation.attempt()),
            )?
            .ok_or_else(|| integrity("finding-candidate-execution-basis-admission-is-missing"))?;
        let _admission = self.read_attempt_admission(admission)?;
        Ok(())
    }

    fn validate_finding_candidate_incorporation_ancestry(
        &self,
        head: &CampaignHead,
        expected_snapshot: CampaignSnapshotId,
        bundle: &FindingCandidateBundle,
    ) -> Result<(), CampaignRepositoryError> {
        let retention = bundle.exact_retention();
        let expected = self.read_snapshot(expected_snapshot.content_id())?;
        if expected.snapshot.lineage() != head.snapshot().lineage() {
            return Err(integrity(
                "finding-candidate-expected-snapshot-lineage-mismatch",
            ));
        }
        self.require_snapshot_ancestor(
            expected_snapshot,
            head.snapshot_id(),
            "finding-candidate-expected-snapshot-is-not-campaign-ancestor",
        )?;

        let source = self.read_snapshot(retention.snapshot().content_id())?;
        if source.snapshot.lineage() != expected.snapshot.lineage() {
            return Err(integrity(
                "finding-exact-retention-source-snapshot-lineage-mismatch",
            ));
        }
        self.require_snapshot_ancestor(
            retention.snapshot(),
            expected_snapshot,
            "finding-exact-retention-source-snapshot-is-not-assignment-ancestor",
        )
    }

    fn require_snapshot_ancestor(
        &self,
        ancestor: CampaignSnapshotId,
        descendant: CampaignSnapshotId,
        failure: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        let mut cursor = descendant;
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if cursor == ancestor {
                return Ok(());
            }
            let loaded = self.read_snapshot(cursor.content_id())?;
            let Some(parent) = loaded.snapshot.parent() else {
                return Err(integrity(failure));
            };
            cursor = parent;
        }
        Err(integrity("finding-candidate-incorporation-ancestry-limit"))
    }

    /// Authenticates that a campaign's current head retains one candidate.
    ///
    /// This read-only check is the handoff boundary for releasing an
    /// executor-owned pending-candidate GC root. It verifies the candidate and
    /// finding records, reads the named campaign's authoritative head, requires
    /// the finding's candidate occurrence set to contain `bundle`, and
    /// authenticates the complete current snapshot closure containing both
    /// records.
    ///
    /// The returned value is point-in-time evidence only. It neither pins that
    /// head nor authorizes a later unfenced assignment-ledger update. A caller
    /// releasing an operational candidate root must repeat this authentication
    /// immediately inside the GC/ledger-generation fence that covers the exact
    /// release compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when any record or descendant
    /// is missing or corrupt, the finding names another bundle, or the named
    /// finding and bundle are not both reachable from the current campaign
    /// head.
    pub fn authenticate_current_finding_candidate_incorporation(
        &self,
        campaign: &CampaignName,
        finding: FindingId,
        bundle: FindingCandidateBundleId,
    ) -> Result<AuthenticatedFindingCandidateIncorporation, CampaignRepositoryError> {
        self.load_finding_candidate_bundle(bundle)?;
        let finding_record = self.read_finding(finding.content_id())?;
        if !self.finding_retains_candidate_bundle(&finding_record, bundle)? {
            return Err(integrity(
                "finding-candidate-incorporation-occurrence-mismatch",
            ));
        }

        let snapshot = self.head(campaign.as_str())?.snapshot_id();
        let closure = self.authenticated_closure_ids([snapshot.content_id()])?;
        if !closure.contains(&finding.content_id()) || !closure.contains(&bundle.content_id()) {
            return Err(integrity(
                "finding-candidate-incorporation-not-retained-by-snapshot",
            ));
        }

        Ok(AuthenticatedFindingCandidateIncorporation {
            campaign: campaign.clone(),
            bundle,
            snapshot,
            finding,
        })
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

    pub(super) fn decode_finding_triage_replay_evidence(
        &self,
        id: ContentId,
    ) -> Result<FindingTriageReplayEvidence, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::FindingTriageReplayEvidence)?;
        let manifest = FindingTriageReplayEvidence::manifest_from_canonical_bytes(envelope.body())?;
        let payload_bytes = manifest.payload_bytes()?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_bytes).map_err(|_| {
            CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-allocation",
            }
        })?;
        for descriptor in manifest.chunks().iter().copied() {
            let chunk = self.require_record_kind(
                descriptor.content(),
                crate::CampaignRecordKind::FindingTriageReplayEvidenceChunk,
            )?;
            let bytes = FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
            if bytes.len() != descriptor.logical_bytes() as usize {
                return Err(integrity(
                    "finding-triage-replay-evidence-chunk-length-mismatch",
                ));
            }
            payload.extend_from_slice(&bytes);
        }
        let evidence = manifest.into_evidence(payload)?;
        if evidence.id()?.content_id() != id {
            return Err(integrity("finding-triage-replay-evidence-envelope-shape"));
        }
        Ok(evidence)
    }

    pub(super) fn validate_finding_triage_replay_evidence(
        &self,
        evidence: &FindingTriageReplayEvidence,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_finding_triage_replay_dependencies(
            evidence.reproduction(),
            evidence.observed_signature(),
        )
    }

    fn validate_finding_triage_replay_dependencies(
        &self,
        reproduction_id: crate::ReproductionArtifactId,
        observed_signature: &crate::FindingSignature,
    ) -> Result<(), CampaignRepositoryError> {
        let reproduction = self.read_reproduction_artifact(reproduction_id.content_id())?;
        if reproduction.finding_fingerprint() != observed_signature.fingerprint() {
            return Err(integrity(
                "finding-triage-replay-evidence-fingerprint-mismatch",
            ));
        }
        if matches!(
            observed_signature.target(),
            Some(FindingTarget::Configuration(configuration))
                if configuration != reproduction.configuration_artifact()
        ) {
            return Err(integrity(
                "finding-triage-replay-evidence-configuration-mismatch",
            ));
        }
        let mut children = vec![reproduction_id.content_id()];
        children.extend(
            crate::finding_candidate::signature_children("observed-signature", observed_signature)
                .into_iter()
                .map(|(_, child)| child),
        );
        for child in children {
            let handle = self.blobs.read(child, None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        Ok(())
    }

    pub(super) fn validate_finding_candidate_bundle(
        &self,
        bundle: &FindingCandidateBundle,
        validation: FindingCandidateValidation<'_>,
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
        self.validate_finding_exact_retention(bundle, &observation, &minimized, validation)?;
        if matches!(validation, FindingCandidateValidation::Load) {
            self.validate_finding_exact_pin_closures(bundle.exact_pins())?;
        }
        self.validate_finding_candidate_triage_evidence(bundle, minimization)?;
        for (_, child) in bundle.signature_minimization().content_children() {
            let handle = self.blobs.read(child, None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        let mut exact_pin_bytes = 0_u64;
        for pin in bundle.exact_pins().all() {
            let handle = if self.blobs.contains(pin.content_id())? {
                self.blobs.read(pin.content_id(), None)?
            } else if let FindingCandidateValidation::Publication(Some(authenticator)) = validation
            {
                authenticator
                    .read_finding_exact_checkpoint_object(pin.content_id())
                    .map_err(|_| integrity("finding-exact-pin-root-source-failed"))?
            } else {
                self.blobs.read(pin.content_id(), None)?
            };
            let length = handle.logical_length();
            exact_pin_bytes = exact_pin_bytes
                .checked_add(length)
                .ok_or_else(|| integrity("finding-candidate-exact-pin-byte-count-overflow"))?;
            if length > MAX_FINDING_EXACT_PIN_ROOT_BYTES
                || exact_pin_bytes > MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL
            {
                return Err(integrity("finding-candidate-exact-pin-byte-limit"));
            }
            handle.copy_to(&mut std::io::sink())?;
        }
        Ok(())
    }

    fn validate_finding_exact_pin_closures(
        &self,
        pins: &FindingExactPins,
    ) -> Result<(), CampaignRepositoryError> {
        let mut pending = pins
            .all()
            .iter()
            .map(|checkpoint| checkpoint.content_id())
            .collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut manifest_bytes = 0_u64;

        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > MAX_CAMPAIGN_CLOSURE_OBJECTS {
                return Err(integrity("finding-exact-pin-closure-object-limit"));
            }

            let handle = self.blobs.read(id, None)?;
            if is_opaque_campaign_leaf(id.kind()) {
                handle.copy_to(&mut std::io::sink())?;
                continue;
            }
            if id.kind() != ObjectKind::ExactManifest {
                return Err(integrity("finding-exact-pin-closure-kind"));
            }

            let length = handle.logical_length();
            manifest_bytes = manifest_bytes
                .checked_add(length)
                .ok_or_else(|| integrity("finding-exact-pin-closure-byte-limit"))?;
            if length > MAX_FINDING_EXACT_PIN_ROOT_BYTES
                || manifest_bytes > MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL
            {
                return Err(integrity("finding-exact-pin-closure-byte-limit"));
            }
            let bytes = handle.read_all(MAX_FINDING_EXACT_PIN_ROOT_BYTES)?;
            let envelope =
                ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
            if envelope.content_id(ObjectKind::ExactManifest) != id {
                return Err(integrity("finding-exact-pin-closure-envelope-id-mismatch"));
            }
            for child in envelope.children() {
                if child.id().kind() != ObjectKind::ExactManifest
                    && !is_opaque_campaign_leaf(child.id().kind())
                {
                    return Err(integrity("finding-exact-pin-closure-kind"));
                }
                pending.push(child.id());
            }
        }

        Ok(())
    }

    fn validate_finding_exact_retention(
        &self,
        bundle: &FindingCandidateBundle,
        observation: &Observation,
        minimized: &ReproductionArtifact,
        validation: FindingCandidateValidation<'_>,
    ) -> Result<(), CampaignRepositoryError> {
        let retention = bundle.exact_retention();
        let source = self.read_snapshot(retention.snapshot().content_id())?;
        let accounting = source.snapshot.roots().accounting;
        if self
            .merkle
            .get(accounting, attempt_index_key(observation.attempt()))?
            != Some(observation.attempt().content_id())
        {
            return Err(integrity(
                "finding-exact-retention-attempt-is-not-in-source-snapshot",
            ));
        }
        if self.merkle.get(
            accounting,
            attempt_execution_basis_key(observation.attempt()),
        )? != Some(retention.admission().content_id())
        {
            return Err(integrity(
                "finding-exact-retention-admission-is-not-selected-by-source-snapshot",
            ));
        }
        let source_lineage = self.read_lineage(source.snapshot.lineage().content_id())?;
        if source_lineage.scenario() != minimized.scenario() {
            return Err(integrity(
                "finding-exact-retention-source-snapshot-scenario-mismatch",
            ));
        }
        let admission = self.read_attempt_admission(retention.admission().content_id())?;
        let AttemptAdmissionRole::ExecutionBasis { .. } = admission.role() else {
            return Err(integrity(
                "finding-exact-retention-admission-is-not-execution-basis",
            ));
        };
        if admission.attempt() != observation.attempt() {
            return Err(integrity(
                "finding-exact-retention-admission-attempt-mismatch",
            ));
        }
        let policy_id = retention.policy();
        if admission.retention_policy() != policy_id {
            return Err(integrity(
                "finding-exact-retention-policy-admission-mismatch",
            ));
        }
        let policy = self.read_policy(policy_id.content_id())?;
        if policy.scenario() != minimized.scenario() {
            return Err(integrity(
                "finding-exact-retention-policy-scenario-mismatch",
            ));
        }

        let requested = policy.retention().exact_findings();
        match retention.disposition() {
            FindingExactRetentionDisposition::Disabled if requested => Err(integrity(
                "finding-exact-retention-disabled-by-requesting-policy",
            )),
            FindingExactRetentionDisposition::Complete
            | FindingExactRetentionDisposition::Incomplete(_)
                if !requested =>
            {
                Err(integrity(
                    "finding-exact-retention-enabled-by-disabled-policy",
                ))
            }
            FindingExactRetentionDisposition::Complete => {
                self.validate_authenticated_finding_exact_retention(bundle, observation, validation)
            }
            _ => Ok(()),
        }
    }

    fn validate_authenticated_finding_exact_retention(
        &self,
        bundle: &FindingCandidateBundle,
        observation: &Observation,
        validation: FindingCandidateValidation<'_>,
    ) -> Result<(), CampaignRepositoryError> {
        let evidence = bundle
            .exact_retention_evidence()
            .ok_or_else(|| integrity("finding-exact-retention-evidence-is-missing"))?;
        let original = self.read_reproduction_artifact(bundle.reproduction().content_id())?;
        let expected_measurement = match observation.stop() {
            crate::StopOutcome::ObservationReached(proof) => Some(proof.boundary().start_events()),
            _ => None,
        };
        if evidence.measurement_boundary_events() != expected_measurement {
            return Err(integrity(
                "finding-exact-retention-measurement-boundary-mismatch",
            ));
        }

        let declared = evidence
            .candidates()
            .iter()
            .map(|candidate| (candidate.checkpoint(), candidate.event_count()))
            .collect::<BTreeMap<_, _>>();
        if let FindingCandidateValidation::Publication(authenticator) = validation {
            let authenticator = authenticator
                .ok_or_else(|| integrity("finding-exact-checkpoint-authenticator-is-missing"))?;
            let mut remaining = MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL;
            for candidate in evidence.candidates() {
                let metadata = authenticator
                    .authenticate_finding_exact_checkpoint(
                        candidate.checkpoint(),
                        original.scenario(),
                        original.scenario_artifact(),
                        original.configuration(),
                        remaining,
                    )
                    .map_err(|error| match error {
                        FindingExactCheckpointAuthenticationError::LimitExceeded => {
                            integrity("finding-exact-retention-metadata-byte-limit")
                        }
                        FindingExactCheckpointAuthenticationError::AuthenticationFailed => {
                            integrity("finding-exact-retention-candidate-authentication-failed")
                        }
                    })?;
                if metadata.scenario() != original.scenario()
                    || metadata.configuration() != original.configuration()
                    || metadata.event_count() != candidate.event_count()
                {
                    return Err(integrity(
                        "finding-exact-retention-candidate-basis-mismatch",
                    ));
                }
                remaining = remaining
                    .checked_sub(metadata.metadata_bytes())
                    .ok_or_else(|| integrity("finding-exact-retention-metadata-byte-limit"))?;
            }
        }
        if declared.get(&evidence.captured_failure()) != Some(&evidence.failure_events()) {
            return Err(integrity(
                "finding-exact-retention-failure-boundary-mismatch",
            ));
        }
        let selected = select_authenticated_finding_pins(
            &declared,
            evidence.failure_events(),
            evidence.measurement_boundary_events(),
        )?;
        if &selected != evidence.selected() || &selected != bundle.exact_pins() {
            return Err(integrity("finding-exact-retention-selection-mismatch"));
        }
        Ok(())
    }

    fn validate_finding_candidate_triage_evidence(
        &self,
        bundle: &FindingCandidateBundle,
        minimization: &FindingMinimizationEvidence,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(evidence) = bundle.triage_evidence() else {
            return Ok(());
        };
        let selected_index = minimization
            .attempts()
            .iter()
            .position(|attempt| attempt.accepted())
            .map_or(0, |index| index + 1);
        let signatures = bundle.signature_minimization();
        let minimization_original = signatures
            .minimization_pass()
            .first()
            .and_then(Option::as_ref)
            .ok_or_else(|| integrity("finding-triage-minimization-original-is-missing"))?;
        let minimization_selected = signatures
            .minimization_pass()
            .get(selected_index)
            .and_then(Option::as_ref)
            .ok_or_else(|| integrity("finding-triage-minimization-selected-is-missing"))?;
        let verification_original = signatures
            .verification_pass()
            .first()
            .and_then(Option::as_ref)
            .ok_or_else(|| integrity("finding-triage-verification-original-is-missing"))?;
        let verification_selected = signatures
            .verification_pass()
            .get(selected_index)
            .and_then(Option::as_ref)
            .ok_or_else(|| integrity("finding-triage-verification-selected-is-missing"))?;
        for (id, reproduction, expected_signature) in [
            (
                evidence.minimization_original(),
                bundle.reproduction(),
                minimization_original,
            ),
            (
                evidence.minimization_selected(),
                bundle.minimized(),
                minimization_selected,
            ),
            (
                evidence.verification_original(),
                bundle.reproduction(),
                verification_original,
            ),
            (
                evidence.verification_selected(),
                bundle.minimized(),
                verification_selected,
            ),
        ] {
            let retained = self.load_finding_triage_replay_evidence(id)?;
            if retained.reproduction() != reproduction
                || retained.observed_signature() != expected_signature
            {
                return Err(integrity("finding-triage-replay-evidence-basis-mismatch"));
            }
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
            || !self.finding_retains_candidate_bundle(&finding, bundle.id()?)?
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

    pub(in crate::repository) fn finding_retains_candidate_bundle(
        &self,
        finding: &Finding,
        bundle: FindingCandidateBundleId,
    ) -> Result<bool, CampaignRepositoryError> {
        let Some(root) = finding.candidate_occurrences() else {
            return Ok(finding.candidate_bundle() == Some(bundle));
        };
        Ok(self
            .merkle
            .get(root, finding_candidate_occurrence_key(bundle))?
            == Some(bundle.content_id()))
    }
}

fn select_authenticated_finding_pins(
    candidates: &BTreeMap<crate::ExactCheckpointId, u64>,
    failure: u64,
    measurement: Option<u64>,
) -> Result<FindingExactPins, CampaignRepositoryError> {
    let greatest = |boundary: u64, strict: bool| {
        candidates
            .iter()
            .filter(|(_, events)| {
                if strict {
                    **events < boundary
                } else {
                    **events <= boundary
                }
            })
            .max_by(|(left_root, left_events), (right_root, right_events)| {
                left_events
                    .cmp(right_events)
                    .then_with(|| right_root.cmp(left_root))
            })
            .map(|(root, _)| *root)
    };
    let post = candidates
        .iter()
        .filter(|(_, events)| **events >= failure)
        .min_by(|(left_root, left_events), (right_root, right_events)| {
            left_events
                .cmp(right_events)
                .then_with(|| left_root.cmp(right_root))
        })
        .map(|(root, _)| *root);
    FindingExactPins::new(
        greatest(failure, true).into_iter().collect(),
        measurement
            .and_then(|boundary| greatest(boundary, false))
            .into_iter()
            .collect(),
        post.into_iter().collect(),
        BTreeSet::new(),
    )
    .map_err(Into::into)
}

fn exact_pins_contain(retained: &FindingExactPins, requested: &FindingExactPins) -> bool {
    requested.pre_failure().is_subset(retained.pre_failure())
        && requested
            .measurement_boundary()
            .is_subset(retained.measurement_boundary())
        && requested.post_failure().is_subset(retained.post_failure())
        && requested.additional().is_subset(retained.additional())
}
