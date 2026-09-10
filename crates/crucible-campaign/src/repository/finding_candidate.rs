//! Immutable finding-candidate publication and restart-safe validation.

use super::*;
use crate::{
    CampaignName, FindingCandidateBundle, FindingCandidateBundleId, FindingExactPins, FindingId,
    FindingTarget, FindingTriageReplayStorageDescription, FindingTriageReplayStorageObject,
    FindingTriageReplayStorageObjectRole, MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
};

/// Opaque proof that one snapshot directly retains a finding candidate bundle.
///
/// Values can be obtained only through
/// [`CampaignRepository::authenticate_current_finding_candidate_incorporation`],
/// which authenticates the named campaign's current authoritative head and the
/// finding's direct bundle reference before constructing the proof.
///
/// The proof records a point-in-time read. It does not pin the campaign head or
/// any immutable object and does not authorize a later unfenced root release.
/// A ledger owner must immediately reauthenticate the current head while
/// holding the operational GC/ledger-generation fence that covers its release
/// compare-and-swap.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedFindingCandidateIncorporation {
    campaign: CampaignName,
    bundle: FindingCandidateBundleId,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
}

impl AuthenticatedFindingCandidateIncorporation {
    /// Returns the campaign whose authoritative head retains the finding.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact candidate bundle retained by the finding.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the authenticated snapshot containing the finding closure.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the finding that directly retains the candidate bundle.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }
}

impl CampaignRepository {
    /// Publishes one transport-neutral native triage replay record.
    ///
    /// The referenced reproduction and every observed-signature dependency
    /// must already be durable. Repeating the operation returns the same ID.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when any referenced object
    /// is absent, corrupt, or inconsistent with the observed signature.
    pub fn publish_finding_triage_replay_evidence(
        &self,
        evidence: &FindingTriageReplayEvidence,
    ) -> Result<FindingTriageReplayEvidenceId, CampaignRepositoryError> {
        let plan = evidence.storage_plan()?;
        let expected_content = plan.root.content_id();
        self.validate_finding_triage_replay_evidence(evidence)?;

        // Rebuild and authenticate the complete deterministic plan before the
        // first durable write. The second pass publishes one bounded chunk at a
        // time, so maximum evidence does not require another full payload copy.
        for (index, descriptor) in plan.chunks.iter().copied().enumerate() {
            evidence.chunk_envelope(index, descriptor)?;
        }
        for (index, descriptor) in plan.chunks.iter().copied().enumerate() {
            let content = self.put_envelope(evidence.chunk_envelope(index, descriptor)?)?;
            if content != descriptor.content() {
                return Err(integrity(
                    "finding-triage-replay-evidence-chunk-publication-id-mismatch",
                ));
            }
        }
        let content = self.put_envelope(plan.root)?;
        if content != expected_content {
            return Err(integrity(
                "finding-triage-replay-evidence-publication-id-mismatch",
            ));
        }
        self.verify_campaign_closure(content)?;
        FindingTriageReplayEvidenceId::from_content_id(content).map_err(Into::into)
    }

    /// Loads and authenticates one native triage replay record.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the record or one of its
    /// referenced objects is absent, corrupt, or inconsistent.
    pub fn load_finding_triage_replay_evidence(
        &self,
        id: FindingTriageReplayEvidenceId,
    ) -> Result<FindingTriageReplayEvidence, CampaignRepositoryError> {
        let evidence = self.decode_finding_triage_replay_evidence(id.content_id())?;
        self.validate_finding_triage_replay_evidence(&evidence)?;
        Ok(evidence)
    }

    /// Describes the authenticated stored envelopes for one replay record.
    ///
    /// The returned order is always the root followed by payload chunks in
    /// logical order. Repeated content IDs remain distinct positions.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the root, a payload
    /// chunk, or a referenced logical dependency is absent or inconsistent.
    pub fn describe_finding_triage_replay_storage(
        &self,
        id: FindingTriageReplayEvidenceId,
    ) -> Result<FindingTriageReplayStorageDescription, CampaignRepositoryError> {
        let root = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::FindingTriageReplayEvidence,
        )?;
        let root_schema_version = root.schema_version();
        let mut objects = vec![FindingTriageReplayStorageObject::new(
            0,
            FindingTriageReplayStorageObjectRole::Root,
            id.content_id(),
            canonical_envelope_bytes(&root)?,
        )];

        let logical_payload_bytes = match root_schema_version {
            1 => {
                let evidence = FindingTriageReplayEvidence::from_canonical_bytes(root.body())?;
                self.validate_finding_triage_replay_dependencies(
                    evidence.reproduction(),
                    evidence.observed_signature(),
                )?;
                u64::try_from(evidence.payload().len()).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "finding-triage-replay-payload-bytes",
                    }
                })?
            }
            2 => {
                let manifest =
                    FindingTriageReplayEvidence::manifest_from_canonical_bytes(root.body())?;
                self.validate_finding_triage_replay_dependencies(
                    manifest.reproduction(),
                    manifest.observed_signature(),
                )?;
                for (index, descriptor) in manifest.chunks().iter().copied().enumerate() {
                    let chunk = self.require_record_kind(
                        descriptor.content(),
                        crate::CampaignRecordKind::FindingTriageReplayEvidenceChunk,
                    )?;
                    let payload =
                        FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
                    if payload.len() != descriptor.logical_bytes() as usize {
                        return Err(integrity(
                            "finding-triage-replay-evidence-chunk-length-mismatch",
                        ));
                    }
                    drop(payload);
                    let ordinal = u32::try_from(index + 1).map_err(|_| {
                        CampaignCodecError::LimitExceeded {
                            limit: "finding-triage-replay-storage-object-ordinal",
                        }
                    })?;
                    let chunk_index =
                        u32::try_from(index).map_err(|_| CampaignCodecError::LimitExceeded {
                            limit: "finding-triage-replay-storage-object-ordinal",
                        })?;
                    objects.push(FindingTriageReplayStorageObject::new(
                        ordinal,
                        FindingTriageReplayStorageObjectRole::PayloadChunk {
                            index: chunk_index,
                            logical_payload_bytes: descriptor.logical_bytes(),
                        },
                        descriptor.content(),
                        canonical_envelope_bytes(&chunk)?,
                    ));
                }
                u64::try_from(manifest.payload_bytes()?).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "finding-triage-replay-payload-bytes",
                    }
                })?
            }
            _ => {
                return Err(integrity("finding-triage-replay-evidence-envelope-version"));
            }
        };

        FindingTriageReplayStorageDescription::new(
            id,
            root_schema_version,
            logical_payload_bytes,
            objects,
        )
        .map_err(Into::into)
    }

    /// Reads one authenticated bounded range from a described stored envelope.
    ///
    /// `object_ordinal` addresses the root-then-payload order returned by
    /// [`Self::describe_finding_triage_replay_storage`]. The stored root layout
    /// is reauthenticated before the range is read, binding the ordinal and
    /// content identity to `id`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error for a zero-length, oversized,
    /// overflowing, out-of-bounds, or unknown range. Returns a store, codec, or
    /// integrity error when the authenticated layout cannot be read.
    pub fn read_finding_triage_replay_storage_range(
        &self,
        id: FindingTriageReplayEvidenceId,
        object_ordinal: u32,
        range: crucible_cas::content_store::ByteRange,
    ) -> Result<Vec<u8>, CampaignRepositoryError> {
        if range.length == 0 || range.length > MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-length",
            });
        }
        let end = range.offset.checked_add(range.length).ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-overflow",
            },
        )?;
        let object = self.resolve_finding_triage_replay_storage_object(id, object_ordinal)?;
        if end > object.stored_envelope_bytes() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-bounds",
            });
        }

        let source = self.blobs.read(object.content(), Some(range))?;
        if source.logical_length() != range.length {
            return Err(integrity(
                "finding-triage-replay-storage-range-length-mismatch",
            ));
        }
        source.read_all(range.length).map_err(Into::into)
    }

    fn resolve_finding_triage_replay_storage_object(
        &self,
        id: FindingTriageReplayEvidenceId,
        object_ordinal: u32,
    ) -> Result<FindingTriageReplayStorageObject, CampaignRepositoryError> {
        let root = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::FindingTriageReplayEvidence,
        )?;
        if object_ordinal == 0 {
            return Ok(FindingTriageReplayStorageObject::new(
                0,
                FindingTriageReplayStorageObjectRole::Root,
                id.content_id(),
                canonical_envelope_bytes(&root)?,
            ));
        }
        if root.schema_version() != 2 {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-object-ordinal",
            });
        }

        let manifest = FindingTriageReplayEvidence::manifest_from_canonical_bytes(root.body())?;
        let chunk_index =
            object_ordinal
                .checked_sub(1)
                .ok_or(CampaignRepositoryError::InvalidRequest {
                    reason: "finding-triage-replay-storage-object-ordinal",
                })?;
        let descriptor = manifest
            .chunks()
            .get(usize::try_from(chunk_index).map_err(|_| {
                CampaignRepositoryError::InvalidRequest {
                    reason: "finding-triage-replay-storage-object-ordinal",
                }
            })?)
            .copied()
            .ok_or(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-object-ordinal",
            })?;
        let chunk = self.require_record_kind(
            descriptor.content(),
            crate::CampaignRecordKind::FindingTriageReplayEvidenceChunk,
        )?;
        let logical_bytes = FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
        if logical_bytes.len() != descriptor.logical_bytes() as usize {
            return Err(integrity(
                "finding-triage-replay-evidence-chunk-length-mismatch",
            ));
        }

        Ok(FindingTriageReplayStorageObject::new(
            object_ordinal,
            FindingTriageReplayStorageObjectRole::PayloadChunk {
                index: chunk_index,
                logical_payload_bytes: descriptor.logical_bytes(),
            },
            descriptor.content(),
            canonical_envelope_bytes(&chunk)?,
        ))
    }

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
        let evidence = match envelope.schema_version() {
            1 => FindingTriageReplayEvidence::from_canonical_bytes(envelope.body())?,
            2 => {
                let manifest =
                    FindingTriageReplayEvidence::manifest_from_canonical_bytes(envelope.body())?;
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
                    let bytes =
                        FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
                    if bytes.len() != descriptor.logical_bytes() as usize {
                        return Err(integrity(
                            "finding-triage-replay-evidence-chunk-length-mismatch",
                        ));
                    }
                    payload.extend_from_slice(&bytes);
                }
                manifest.into_evidence(payload)?
            }
            _ => {
                return Err(integrity("finding-triage-replay-evidence-envelope-version"));
            }
        };
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
        self.validate_finding_candidate_triage_evidence(bundle, minimization)?;
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

fn canonical_envelope_bytes(envelope: &ObjectEnvelope) -> Result<u64, CampaignRepositoryError> {
    u64::try_from(envelope.canonical_bytes().len()).map_err(|_| {
        CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-envelope-bytes",
        }
        .into()
    })
}

fn exact_pins_contain(retained: &FindingExactPins, requested: &FindingExactPins) -> bool {
    requested.pre_failure().is_subset(retained.pre_failure())
        && requested
            .measurement_boundary()
            .is_subset(retained.measurement_boundary())
        && requested.post_failure().is_subset(retained.post_failure())
        && requested.additional().is_subset(retained.additional())
}
