//! Immutable finding-candidate publication and restart-safe validation.

use super::*;
use crate::{
    CampaignName, ConfigurationId, ExecutionId, FindingCandidateBundle, FindingCandidateBundleId,
    FindingExactPins, FindingExactRetentionDisposition, FindingId, FindingTarget,
    FindingTriageReplayStorageDescription, FindingTriageReplayStorageObject,
    FindingTriageReplayStorageObjectRole, ScenarioArtifactId, ScenarioDefId,
    MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
};
use ed25519_dalek::Signature;

const MAX_FINDING_EXACT_PIN_ROOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FINDING_EXACT_PIN_ROOT_BYTES_TOTAL: u64 = 64 * 1024 * 1024;

/// Strict authentication result for one production finding checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedFindingExactCheckpoint {
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    event_count: u64,
    metadata_bytes: u64,
}

impl AuthenticatedFindingExactCheckpoint {
    /// Builds one result after typed production-checkpoint validation succeeds.
    #[must_use]
    pub const fn new(
        scenario: ScenarioDefId,
        configuration: ConfigurationId,
        event_count: u64,
        metadata_bytes: u64,
    ) -> Self {
        Self {
            scenario,
            configuration,
            event_count,
            metadata_bytes,
        }
    }

    /// Returns the authenticated scenario identity.
    #[must_use]
    pub const fn scenario(self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the authenticated configuration identity.
    #[must_use]
    pub const fn configuration(self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the authenticated scheduler event boundary.
    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    /// Returns the root, manifest, and index bytes consumed by authentication.
    #[must_use]
    pub const fn metadata_bytes(self) -> u64 {
        self.metadata_bytes
    }
}

/// Stable failure class returned by a production-checkpoint authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingExactCheckpointAuthenticationError {
    /// The checkpoint metadata exceeds the caller's remaining byte budget.
    LimitExceeded,
    /// Typed structure, identity, or execution-model validation failed.
    AuthenticationFailed,
}

/// Authenticates production checkpoints through their owning typed codecs.
pub trait FindingExactCheckpointAuthenticator: Send + Sync {
    /// Authenticates one checkpoint against the exact finding basis.
    ///
    /// Implementations must reject before allocation when root, manifest,
    /// index, scheduler, or scenario-derived object limits are exceeded.
    ///
    /// # Errors
    ///
    /// Returns a stable limit or authentication failure without accepting a
    /// partial, unknown-field, or merely structurally plausible checkpoint.
    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: crate::ExactCheckpointId,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>;

    /// Opens one authenticated object named by a selected checkpoint closure.
    ///
    /// The repository calls this only for the selected root or for a child
    /// discovered from an authenticated exact-manifest envelope. Implementors
    /// may defer content authentication until the returned stream reaches EOF.
    ///
    /// # Errors
    ///
    /// Returns an authentication failure when the object is absent, corrupt,
    /// or unavailable from the owning checkpoint store.
    fn read_finding_exact_checkpoint_object(
        &self,
        _object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

/// Exact completed-execution context authenticated before restart incorporation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingCandidateRecoveryContext {
    campaign: CampaignName,
    expected_snapshot: CampaignSnapshotId,
    lineage: CampaignLineageId,
    attempt: AttemptId,
    execution_basis: CampaignHash,
    execution: ExecutionId,
    observation: ObservationId,
    bundle: FindingCandidateBundleId,
    prepared_result_digest: CampaignHash,
}

impl FindingCandidateRecoveryContext {
    /// Builds the full durable context covered by a recovery seal.
    #[must_use]
    // crucible-lint: allow rust-allow -- the durable authorization tuple is explicit.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        campaign: CampaignName,
        expected_snapshot: CampaignSnapshotId,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        execution_basis: CampaignHash,
        execution: ExecutionId,
        observation: ObservationId,
        bundle: FindingCandidateBundleId,
        prepared_result_digest: CampaignHash,
    ) -> Self {
        Self {
            campaign,
            expected_snapshot,
            lineage,
            attempt,
            execution_basis,
            execution,
            observation,
            bundle,
            prepared_result_digest,
        }
    }

    /// Returns the exact campaign authorized for incorporation.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact post-observation head authorized for incorporation.
    #[must_use]
    pub const fn expected_snapshot(&self) -> CampaignSnapshotId {
        self.expected_snapshot
    }

    /// Returns the completed campaign lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the completed semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the exact admitted execution-contract digest.
    #[must_use]
    pub const fn execution_basis(&self) -> CampaignHash {
        self.execution_basis
    }

    /// Returns the local execution incarnation that published the result.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the immutable completed observation.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the immutable finding-candidate bundle.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the digest of the complete prepared-result payload.
    #[must_use]
    pub const fn prepared_result_digest(&self) -> CampaignHash {
        self.prepared_result_digest
    }

    /// Encodes the domain-separated message covered by the process seal.
    #[must_use]
    pub fn seal_message(&self) -> Vec<u8> {
        let mut material = Vec::with_capacity(512);
        material
            .extend_from_slice(b"crucible.campaign.finding-candidate-recovery-process-seal.v1\0");
        for bytes in [
            self.campaign.as_str().as_bytes().to_vec(),
            self.expected_snapshot.to_text().into_bytes(),
            self.lineage.to_text().into_bytes(),
            self.attempt.to_text().into_bytes(),
            self.observation.to_text().into_bytes(),
            self.bundle.to_text().into_bytes(),
        ] {
            material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            material.extend_from_slice(&bytes);
        }
        material.extend_from_slice(&self.execution_basis.as_bytes());
        material.extend_from_slice(&self.execution.as_bytes());
        material.extend_from_slice(&self.prepared_result_digest.as_bytes());
        material
    }
}

/// Process-ephemeral signature over one authenticated recovery context.
///
/// The daemon creates this value only after reopening and comparing the V15
/// assignment state, prepared-result journal, and immutable candidate bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingCandidateRecoverySeal {
    signature: [u8; 64],
}

impl FindingCandidateRecoverySeal {
    /// Wraps one Ed25519 signature produced by the current recovery owner.
    #[must_use]
    pub const fn from_bytes(signature: [u8; 64]) -> Self {
        Self { signature }
    }

    pub(super) fn signature(self) -> Signature {
        Signature::from_bytes(&self.signature)
    }
}

/// Single-use authority for one exact finding-candidate incorporation.
///
/// The campaign repository creates this capability only after authenticated
/// recovery of a V15 completed ledger record and its full prepared-result
/// journal. It is bound to that recovery context and cannot be cloned or
/// constructed from public IDs. Checked live completion uses a separate
/// crate-private bound operation derived directly from the typed response.
pub struct FindingCandidateIncorporationAuthorization {
    bundle: FindingCandidateBundleId,
    observation: ObservationId,
    context_digest: CampaignHash,
    recovery_context: FindingCandidateRecoveryContext,
}

pub(super) struct BoundFindingCandidateIncorporationAuthorization {
    context_digest: CampaignHash,
    operation_digest: CampaignHash,
}

impl FindingCandidateIncorporationAuthorization {
    pub(super) fn for_authenticated_recovery(
        context_digest: CampaignHash,
        recovery_context: FindingCandidateRecoveryContext,
    ) -> Self {
        Self {
            bundle: recovery_context.bundle(),
            observation: recovery_context.observation(),
            context_digest,
            recovery_context,
        }
    }

    /// Returns the exact bundle authorized for incorporation.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the observation that the authorized bundle must name.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    pub(super) fn bind(
        self,
        campaign: &str,
        expected_snapshot: CampaignSnapshotId,
        bundle: FindingCandidateBundleId,
        observation: ObservationId,
    ) -> Option<BoundFindingCandidateIncorporationAuthorization> {
        if self.bundle != bundle || self.observation != observation {
            return None;
        }
        if self.recovery_context.campaign().as_str() != campaign
            || self.recovery_context.expected_snapshot() != expected_snapshot
        {
            return None;
        }
        let expected_context_digest = CampaignHash::derive(
            "crucible.campaign.finding-candidate-recovery-authorization.v1",
            &self.recovery_context.seal_message(),
        );
        if self.context_digest != expected_context_digest {
            return None;
        }
        Some(BoundFindingCandidateIncorporationAuthorization {
            context_digest: self.context_digest,
            operation_digest: finding_candidate_incorporation_operation_digest(
                campaign,
                expected_snapshot,
                bundle,
                observation,
                self.context_digest,
            ),
        })
    }
}

fn finding_candidate_incorporation_operation_digest(
    campaign: &str,
    expected_snapshot: CampaignSnapshotId,
    bundle: FindingCandidateBundleId,
    observation: ObservationId,
    context_digest: CampaignHash,
) -> CampaignHash {
    let mut material = Vec::with_capacity(768);
    for bytes in [
        campaign.as_bytes(),
        expected_snapshot.to_text().as_bytes(),
        bundle.to_text().as_bytes(),
        observation.to_text().as_bytes(),
    ] {
        material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(bytes);
    }
    material.extend_from_slice(&context_digest.as_bytes());
    CampaignHash::derive(
        "crucible.campaign.finding-candidate-incorporation-operation.v1",
        &material,
    )
}

#[derive(Clone, Copy)]
pub(super) enum FindingCandidateValidation<'a> {
    Publication(Option<&'a dyn FindingExactCheckpointAuthenticator>),
    Load,
}

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
        self.publish_finding_candidate_bundle_inner(bundle, None)
    }

    /// Publishes one candidate after typed whole-inventory authentication.
    ///
    /// Complete V5 retention is a daemon attestation: the trusted executor
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
    pub fn publish_finding_candidate_bundle_with_authenticator(
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
        if matches!(
            bundle
                .exact_retention()
                .map(|retention| retention.disposition()),
            Some(FindingExactRetentionDisposition::Complete)
        ) && let Some(authenticator) = authenticator
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

    pub(in crate::repository) fn incorporate_executor_finding_candidate_bundle(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        bundle: FindingCandidateBundleId,
        authorization: BoundFindingCandidateIncorporationAuthorization,
    ) -> Result<FindingPublicationResult, CampaignRepositoryError> {
        self.incorporate_finding_candidate_bundle_inner(
            name,
            expected_snapshot,
            bundle,
            Some(authorization),
        )
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
        if matches!(
            bundle
                .exact_retention()
                .map(|retention| retention.disposition()),
            Some(FindingExactRetentionDisposition::Complete)
        ) && authorization.is_none()
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
        let admission = self.read_attempt_admission(admission)?;
        if admission.schema_version()
            < crate::exploration::ATTEMPT_ADMISSION_RETENTION_SCHEMA_VERSION
        {
            return Ok(());
        }
        if bundle.schema_version() < 4 || bundle.exact_retention().is_none() {
            return Err(integrity(
                "policy-bound-finding-candidate-omits-exact-retention-evidence",
            ));
        }
        Ok(())
    }

    fn validate_finding_candidate_incorporation_ancestry(
        &self,
        head: &CampaignHead,
        expected_snapshot: CampaignSnapshotId,
        bundle: &FindingCandidateBundle,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(retention) = bundle.exact_retention() else {
            return Ok(());
        };
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
        let Some(retention) = bundle.exact_retention() else {
            return Ok(());
        };
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
        let AttemptAdmissionRole::ExecutionBasis { proposal, .. } = admission.role() else {
            return Err(integrity(
                "finding-exact-retention-admission-is-not-execution-basis",
            ));
        };
        if admission.attempt() != observation.attempt() {
            return Err(integrity(
                "finding-exact-retention-admission-attempt-mismatch",
            ));
        }
        let admitted_policy = match admission.retention_policy() {
            Some(policy) => Some(policy),
            None => proposal
                .map(|proposal| {
                    self.read_proposal(proposal.content_id())
                        .map(|p| p.policy())
                })
                .transpose()?,
        };
        let Some(policy_id) = retention.policy() else {
            if admitted_policy.is_some() {
                return Err(integrity(
                    "finding-exact-retention-omits-derivable-policy-basis",
                ));
            }
            return match retention.disposition() {
                FindingExactRetentionDisposition::Incomplete(
                    crate::FindingExactRetentionIncomplete::MissingAuthenticatedPolicyBasis,
                ) => Ok(()),
                _ => Err(integrity("finding-exact-retention-policy-basis-is-missing")),
            };
        };
        if admitted_policy != Some(policy_id) {
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
        if bundle.schema_version() < 5 {
            return Err(integrity(
                "complete-finding-exact-retention-requires-authenticated-evidence",
            ));
        }
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

fn canonical_envelope_bytes(envelope: &ObjectEnvelope) -> Result<u64, CampaignRepositoryError> {
    u64::try_from(envelope.canonical_bytes().len()).map_err(|_| {
        CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-envelope-bytes",
        }
        .into()
    })
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
