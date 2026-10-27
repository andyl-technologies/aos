//! Chunked finding-triage replay storage and log-segment ownership tests.

use super::*;
use crate::{
    FindingTriageReplayLogSegment, FindingTriageReplayStorageDescription,
    FindingTriageReplayStorageObject, FindingTriageReplayStorageObjectRole,
    MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES, MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
};

struct RedirectBlobReads {
    inner: Arc<MemoryBlobBackend>,
    redirects: BTreeMap<ContentId, Vec<u8>>,
}

impl ImmutableBlobBackend for RedirectBlobReads {
    fn name(&self) -> &str {
        "redirect-campaign-test"
    }

    fn capabilities(&self) -> crucible_store::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_store::content_store::ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        if range.is_none()
            && let Some(bytes) = self.redirects.get(&id)
        {
            return Ok(BlobHandle::from_bytes(bytes.clone()));
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<crucible_store::content_store::PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

/// Publishes the reproduction and builds the signature every test record uses.
fn triage_record_basis(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    label: &str,
) -> (ReproductionArtifactId, FindingSignature) {
    let fingerprint = CampaignHash::derive("test-finding", label.as_bytes());
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            fingerprint,
            crate::ReproductionPayload::new(1, label.as_bytes().to_vec(), Vec::new())
                .expect("reproduction payload"),
        )
        .expect("publish triage reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        format!("qemu.{label}"),
        Some(FindingTarget::Configuration(lineage.genesis_content())),
        BTreeSet::new(),
    )
    .expect("triage signature");
    (reproduction, signature)
}

/// Names `bytes` as one attempt-log trace leaf.
fn log_segment(bytes: &[u8]) -> FindingTriageReplayLogSegment {
    FindingTriageReplayLogSegment::new(
        ContentId::for_bytes(ObjectKind::Trace, 1, bytes),
        bytes.len() as u64,
    )
    .expect("log segment")
}

#[test]
fn triage_replay_chunk_storage_fails_closed_under_repository_adversaries() {
    use crate::finding_triage_evidence::{
        FindingTriageReplayChunkDescriptor, FindingTriageReplayManifest,
    };

    let (repository, lineage, _, blobs) = fixture_with_quota(128 * 1024 * 1024);
    let (reproduction, signature) =
        triage_record_basis(&repository, &lineage, "triage-chunk-authentication");

    // A maximum payload is one chunk that spans two storage ranges.
    let payload = vec![b'a'; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES];
    let evidence = FindingTriageReplayEvidence::new(reproduction, signature.clone(), 1, payload)
        .expect("replay evidence");
    let plan = evidence.storage_plan().expect("storage plan");
    assert_eq!(plan.chunks.len(), 1);
    let chunk = plan.chunks[0].content();
    let evidence_id = repository
        .publish_finding_triage_replay_evidence(&evidence)
        .expect("publish replay evidence");
    drop(evidence);

    let description = repository
        .describe_finding_triage_replay_storage(evidence_id)
        .expect("describe replay storage");
    assert_eq!(description.evidence(), evidence_id);
    assert_eq!(description.storage_schema_version(), 3);
    assert_eq!(
        description.logical_payload_bytes(),
        MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES as u64
    );
    assert_eq!(description.objects().len(), 2);
    assert_eq!(
        description.objects()[0].role(),
        FindingTriageReplayStorageObjectRole::Root
    );
    assert_eq!(description.objects()[1].content(), chunk);
    assert_eq!(
        description.objects()[1].role(),
        FindingTriageReplayStorageObjectRole::PayloadChunk {
            index: 0,
            logical_payload_bytes: MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES as u32,
        }
    );
    let encoded_description = description.canonical_bytes();
    assert_eq!(
        FindingTriageReplayStorageDescription::from_canonical_bytes(&encoded_description)
            .expect("decode storage description"),
        description
    );
    let mut noncanonical_description = encoded_description;
    noncanonical_description.push(0);
    assert!(
        FindingTriageReplayStorageDescription::from_canonical_bytes(&noncanonical_description)
            .is_err()
    );

    let chunk_bytes = blobs
        .read(chunk, None)
        .expect("read stored chunk")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy stored chunk");
    let root_bytes = blobs
        .read(evidence_id.content_id(), None)
        .expect("read stored replay root")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy stored replay root");
    description
        .authenticate_root_envelope(&root_bytes)
        .expect("authenticate manifest root and chunk descriptor");
    let misdescribed = FindingTriageReplayStorageDescription::new(
        description.evidence(),
        description.storage_schema_version(),
        description.logical_payload_bytes(),
        vec![
            description.objects()[0].clone(),
            FindingTriageReplayStorageObject::new(
                1,
                description.objects()[1].role(),
                evidence_id.content_id(),
                description.objects()[1].stored_envelope_bytes(),
            ),
        ],
    );
    assert!(
        misdescribed.is_err()
            || misdescribed.is_ok_and(|misdescribed| misdescribed
                .authenticate_root_envelope(&root_bytes)
                .is_err())
    );

    // Envelopes are consumed one at a time from any iterator.
    let reassembled = FindingTriageReplayEvidence::from_storage_envelopes(
        &description,
        [root_bytes.clone(), chunk_bytes.clone()],
    )
    .expect("reassemble stored envelopes");
    assert!(reassembled.payload().iter().all(|byte| *byte == b'a'));
    drop(reassembled);
    assert!(
        FindingTriageReplayEvidence::from_storage_envelopes(&description, [root_bytes.clone()])
            .is_err(),
        "a missing chunk envelope must be refused"
    );
    assert!(
        FindingTriageReplayEvidence::from_storage_envelopes(
            &description,
            [root_bytes.clone(), chunk_bytes.clone(), chunk_bytes.clone()],
        )
        .is_err(),
        "a surplus envelope must be refused"
    );
    assert!(
        FindingTriageReplayEvidence::from_storage_envelopes(
            &description,
            [chunk_bytes.clone(), root_bytes],
        )
        .is_err(),
        "reordered envelopes must be refused"
    );

    let first_segment = description
        .segment_range(1, chunk, 0)
        .expect("first canonical chunk segment");
    let final_segment = description
        .segment_range(1, chunk, 1)
        .expect("final canonical chunk segment");
    assert_eq!(
        first_segment.length,
        MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES
    );
    assert_eq!(
        first_segment.length + final_segment.length,
        description.objects()[1].stored_envelope_bytes()
    );
    assert!(
        description
            .segment_range(1, evidence_id.content_id(), 0)
            .is_err()
    );
    assert!(description.segment_range(1, chunk, 2).is_err());
    assert_eq!(
        repository
            .read_finding_triage_replay_storage_range(evidence_id, 1, first_segment)
            .expect("read bounded chunk range"),
        chunk_bytes[..usize::try_from(first_segment.length).expect("segment length")]
    );
    assert!(
        repository
            .read_finding_triage_replay_storage_range(
                evidence_id,
                2,
                crucible_store::content_store::ByteRange::new(0, 1).expect("unknown-object range"),
            )
            .is_err()
    );
    assert!(
        repository
            .read_finding_triage_replay_storage_range(
                evidence_id,
                1,
                crucible_store::content_store::ByteRange::new(
                    0,
                    MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES + 1,
                )
                .expect("oversized chunk range"),
            )
            .is_err()
    );

    let mut corrupt_bytes = chunk_bytes;
    corrupt_bytes[0] ^= 0xff;
    let corrupted = CampaignRepository::new(
        Arc::new(RedirectBlobReads {
            inner: blobs.clone(),
            redirects: BTreeMap::from([(chunk, corrupt_bytes)]),
        }),
        repository.refs.clone(),
    );
    assert!(
        corrupted
            .load_finding_triage_replay_evidence(evidence_id)
            .is_err()
    );

    assert!(
        FindingTriageReplayManifest::new(
            reproduction,
            signature,
            1,
            1,
            vec![FindingTriageReplayChunkDescriptor::new(
                evidence_id.content_id(),
                1,
            )],
            Vec::new(),
        )
        .is_err()
    );

    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire missing-chunk inventory fence");
    inventory
        .delete_candidate(chunk)
        .expect("delete referenced chunk");
    drop(inventory);
    assert!(matches!(
        repository.load_finding_triage_replay_evidence(evidence_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
}

#[test]
fn triage_replay_log_segments_are_owned_children_served_by_position() {
    let (repository, lineage, _, blobs) = fixture_with_quota(16 * 1024 * 1024);
    let (reproduction, signature) =
        triage_record_basis(&repository, &lineage, "triage-log-segments");
    let first_bytes = b"first attempt-log segment".to_vec();
    let second_bytes = b"second attempt-log segment".to_vec();
    let segments = vec![log_segment(&first_bytes), log_segment(&second_bytes)];
    let evidence = FindingTriageReplayEvidence::new_with_log_segments(
        reproduction,
        signature,
        4,
        b"segment-referencing replay payload".to_vec(),
        segments.clone(),
    )
    .expect("segment-naming replay evidence");

    // The record cannot be published before the segments it names.
    assert!(
        repository
            .publish_finding_triage_replay_evidence(&evidence)
            .is_err()
    );
    assert!(
        repository
            .publish_finding_triage_replay_log_segment(segments[0], &second_bytes)
            .is_err(),
        "a segment must derive its declared identity"
    );
    for (segment, bytes) in segments.iter().zip([&first_bytes, &second_bytes]) {
        repository
            .publish_finding_triage_replay_log_segment(*segment, bytes)
            .expect("publish log segment");
    }
    let evidence_id = repository
        .publish_finding_triage_replay_evidence(&evidence)
        .expect("publish replay evidence");

    assert_eq!(
        repository
            .read_finding_triage_replay_log_segment(evidence_id, 1)
            .expect("read second log segment"),
        second_bytes
    );
    assert!(matches!(
        repository.read_finding_triage_replay_log_segment(evidence_id, 2),
        Err(CampaignRepositoryError::InvalidRequest { .. })
    ));
    assert_eq!(
        repository
            .load_finding_triage_replay_evidence(evidence_id)
            .expect("load replay evidence")
            .log_segments(),
        segments.as_slice()
    );

    // Named segments are closure members, so collection keeps them.
    let retained = repository
        .authenticated_closure_ids([evidence_id.content_id()])
        .expect("authenticate replay closure");
    for segment in &segments {
        assert!(retained.contains(&segment.content()));
    }

    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire missing-segment inventory fence");
    inventory
        .delete_candidate(segments[0].content())
        .expect("delete named log segment");
    drop(inventory);
    assert!(
        repository
            .read_finding_triage_replay_log_segment(evidence_id, 0)
            .is_err()
    );
}

#[test]
fn maximum_triage_replay_evidence_survives_gc_and_restart() {
    let (repository, lineage, _, blobs) = fixture_with_quota(96 * 1024 * 1024);
    let (reproduction, signature) =
        triage_record_basis(&repository, &lineage, "maximum-triage-replay");
    let segment_bytes = b"maximum triage replay log segment".to_vec();
    let segment = log_segment(&segment_bytes);
    repository
        .publish_finding_triage_replay_log_segment(segment, &segment_bytes)
        .expect("publish maximum-triage log segment");
    let evidence = FindingTriageReplayEvidence::new_with_log_segments(
        reproduction,
        signature,
        1,
        vec![b'm'; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES],
        vec![segment],
    )
    .expect("maximum triage replay evidence");
    let plan = evidence
        .storage_plan()
        .expect("maximum triage storage plan");
    let chunk_ids = plan
        .chunks
        .iter()
        .map(|chunk| chunk.content())
        .collect::<Vec<_>>();
    assert_eq!(chunk_ids.len(), 1);
    let evidence_id = repository
        .publish_finding_triage_replay_evidence(&evidence)
        .expect("publish maximum triage replay evidence");
    for (content, expected_kind, expected_schema) in std::iter::once((
        evidence_id.content_id(),
        CampaignRecordKind::FindingTriageReplayEvidence,
        3,
    ))
    .chain(chunk_ids.iter().copied().map(|content| {
        (
            content,
            CampaignRecordKind::FindingTriageReplayEvidenceChunk,
            1,
        )
    })) {
        let stored = repository
            .read_envelope(content)
            .expect("read maximum triage stored envelope");
        assert_eq!(stored.record_kind(), expected_kind);
        assert_eq!(stored.schema_version(), expected_schema);
        let canonical = stored.canonical_bytes();
        assert_eq!(
            ObjectEnvelope::from_canonical_bytes(&canonical)
                .expect("round-trip maximum triage stored envelope"),
            stored
        );
    }
    drop(evidence);

    let loaded = repository
        .load_finding_triage_replay_evidence(evidence_id)
        .expect("load maximum triage replay evidence");
    assert_eq!(
        loaded.payload().len(),
        MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES
    );
    assert!(loaded.payload().iter().all(|byte| *byte == b'm'));
    drop(loaded);

    let orphan_bytes = b"unreachable beside maximum triage replay";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store maximum-triage GC candidate");
    let retained = repository
        .authenticated_closure_ids([evidence_id.content_id()])
        .expect("authenticate maximum triage replay closure");
    assert!(retained.contains(&evidence_id.content_id()));
    assert!(retained.contains(&segment.content()));
    for chunk in &chunk_ids {
        assert!(retained.contains(chunk));
    }

    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire maximum-triage GC fence");
    let mut candidates = Vec::new();
    inventory
        .visit_inventory(&mut |record| {
            if !retained.contains(&record.id()) {
                candidates.push(record.id());
            }
            Ok(())
        })
        .expect("inventory maximum-triage GC candidates");
    for candidate in candidates {
        inventory
            .delete_candidate(candidate)
            .expect("delete maximum-triage GC candidate");
    }
    drop(inventory);
    assert!(!blobs.contains(orphan).expect("orphan presence after GC"));
    assert!(
        blobs
            .contains(segment.content())
            .expect("segment presence after GC")
    );
    for chunk in &chunk_ids {
        assert!(blobs.contains(*chunk).expect("chunk presence after GC"));
    }

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let restarted_evidence = restarted
        .load_finding_triage_replay_evidence(evidence_id)
        .expect("load maximum triage replay evidence after restart");
    assert_eq!(
        restarted_evidence.payload().len(),
        MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES
    );
    assert!(
        restarted_evidence
            .payload()
            .iter()
            .all(|byte| *byte == b'm')
    );
    assert_eq!(
        restarted
            .read_finding_triage_replay_log_segment(evidence_id, 0)
            .expect("read log segment after restart"),
        segment_bytes
    );
}
