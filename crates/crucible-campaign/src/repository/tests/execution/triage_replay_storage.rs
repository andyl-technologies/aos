//! Chunked finding-triage replay storage tests.

use super::*;
use crate::{
    FindingTriageReplayStorageDescription, FindingTriageReplayStorageObject,
    FindingTriageReplayStorageObjectRole, MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES,
    MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
};

struct RedirectBlobReads {
    inner: Arc<MemoryBlobBackend>,
    redirects: BTreeMap<ContentId, Vec<u8>>,
}

impl ImmutableBlobBackend for RedirectBlobReads {
    fn name(&self) -> &str {
        "redirect-campaign-test"
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
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
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

#[test]
fn triage_replay_chunk_storage_fails_closed_under_repository_adversaries() {
    use crate::finding_triage_evidence::{
        FindingTriageReplayChunkDescriptor, FindingTriageReplayManifest,
    };

    const HALF_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

    let (repository, lineage, _, blobs) = fixture_with_quota(192 * 1024 * 1024);
    let fingerprint = CampaignHash::derive("test-finding", b"triage chunk authentication");
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            fingerprint,
            1,
            b"triage chunk reproduction".to_vec(),
        )
        .expect("publish triage chunk reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.triage-chunk-authentication".to_owned(),
        Some(FindingTarget::Configuration(lineage.genesis_content())),
        BTreeSet::new(),
    )
    .expect("triage chunk signature");

    let mut ordered_payload = vec![b'a'; HALF_PAYLOAD_BYTES];
    ordered_payload.extend(std::iter::repeat_n(b'b', HALF_PAYLOAD_BYTES));
    let ordered =
        FindingTriageReplayEvidence::new(reproduction, signature.clone(), 1, ordered_payload)
            .expect("ordered replay evidence");
    let ordered_plan = ordered.storage_plan().expect("ordered storage plan");
    assert_eq!(ordered_plan.chunks.len(), 2);
    let first_chunk = ordered_plan.chunks[0].content();
    let second_chunk = ordered_plan.chunks[1].content();
    assert_ne!(first_chunk, second_chunk);
    let ordered_id = repository
        .publish_finding_triage_replay_evidence(&ordered)
        .expect("publish ordered replay evidence");
    drop(ordered);
    let description = repository
        .describe_finding_triage_replay_storage(ordered_id)
        .expect("describe ordered replay storage");
    assert_eq!(description.evidence(), ordered_id);
    assert_eq!(description.storage_schema_version(), 2);
    assert_eq!(
        description.logical_payload_bytes(),
        2 * HALF_PAYLOAD_BYTES as u64
    );
    assert_eq!(description.objects().len(), 3);
    assert_eq!(
        description.objects()[0].role(),
        FindingTriageReplayStorageObjectRole::Root
    );
    assert_eq!(description.objects()[1].content(), first_chunk);
    assert_eq!(description.objects()[2].content(), second_chunk);
    assert_eq!(
        description.objects()[1].role(),
        FindingTriageReplayStorageObjectRole::PayloadChunk {
            index: 0,
            logical_payload_bytes: HALF_PAYLOAD_BYTES as u32,
        }
    );
    let encoded_description = description.canonical_bytes();
    assert_eq!(
        FindingTriageReplayStorageDescription::from_canonical_bytes(&encoded_description)
            .expect("decode ordered storage description"),
        description
    );
    let mut noncanonical_description = encoded_description;
    noncanonical_description.push(0);
    assert!(
        FindingTriageReplayStorageDescription::from_canonical_bytes(&noncanonical_description)
            .is_err()
    );

    let first_bytes = blobs
        .read(first_chunk, None)
        .expect("read first stored chunk")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy first stored chunk");
    let second_bytes = blobs
        .read(second_chunk, None)
        .expect("read second stored chunk")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy second stored chunk");
    let root_bytes = blobs
        .read(ordered_id.content_id(), None)
        .expect("read stored replay root")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy stored replay root");
    description
        .authenticate_root_envelope(&root_bytes)
        .expect("authenticate manifest root and chunk descriptors");
    let swapped_description = FindingTriageReplayStorageDescription::new(
        description.evidence(),
        description.storage_schema_version(),
        description.logical_payload_bytes(),
        vec![
            description.objects()[0].clone(),
            FindingTriageReplayStorageObject::new(
                1,
                description.objects()[1].role(),
                description.objects()[2].content(),
                description.objects()[2].stored_envelope_bytes(),
            ),
            FindingTriageReplayStorageObject::new(
                2,
                description.objects()[2].role(),
                description.objects()[1].content(),
                description.objects()[1].stored_envelope_bytes(),
            ),
        ],
    )
    .expect("structurally valid swapped description");
    assert!(
        swapped_description
            .authenticate_root_envelope(&root_bytes)
            .is_err()
    );
    let reassembled = FindingTriageReplayEvidence::from_storage_envelopes(
        &description,
        &[
            root_bytes.clone(),
            first_bytes.clone(),
            second_bytes.clone(),
        ],
    )
    .expect("reassemble ordered stored envelopes");
    assert_eq!(reassembled.payload().len(), 2 * HALF_PAYLOAD_BYTES);
    assert!(
        reassembled.payload()[..HALF_PAYLOAD_BYTES]
            .iter()
            .all(|byte| *byte == b'a')
    );
    assert!(
        reassembled.payload()[HALF_PAYLOAD_BYTES..]
            .iter()
            .all(|byte| *byte == b'b')
    );
    drop(reassembled);
    assert!(
        FindingTriageReplayEvidence::from_storage_envelopes(
            &description,
            &[root_bytes, second_bytes.clone(), first_bytes.clone()],
        )
        .is_err()
    );

    let first_segment = description
        .segment_range(1, first_chunk, 0)
        .expect("first canonical chunk segment");
    let final_segment = description
        .segment_range(1, first_chunk, 1)
        .expect("final canonical chunk segment");
    assert_eq!(
        first_segment.length,
        MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES
    );
    assert_eq!(
        first_segment.length + final_segment.length,
        description.objects()[1].stored_envelope_bytes()
    );
    assert!(description.segment_range(1, second_chunk, 0).is_err());
    assert!(description.segment_range(1, first_chunk, 2).is_err());
    assert_eq!(
        repository
            .read_finding_triage_replay_storage_range(ordered_id, 1, first_segment,)
            .expect("read bounded chunk range"),
        first_bytes[..usize::try_from(first_segment.length).expect("segment length")]
    );
    assert!(
        repository
            .read_finding_triage_replay_storage_range(
                ordered_id,
                3,
                crucible_cas::content_store::ByteRange::new(0, 1).expect("unknown-object range"),
            )
            .is_err()
    );
    assert!(
        repository
            .read_finding_triage_replay_storage_range(
                ordered_id,
                1,
                crucible_cas::content_store::ByteRange::new(
                    0,
                    MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES + 1,
                )
                .expect("oversized chunk range"),
            )
            .is_err()
    );
    let reordered = CampaignRepository::new(
        Arc::new(RedirectBlobReads {
            inner: blobs.clone(),
            redirects: BTreeMap::from([
                (first_chunk, second_bytes),
                (second_chunk, first_bytes.clone()),
            ]),
        }),
        repository.refs.clone(),
    );
    assert!(matches!(
        reordered.load_finding_triage_replay_evidence(ordered_id),
        Err(CampaignRepositoryError::Integrity {
            reason: "envelope-content-id-mismatch"
        })
    ));

    let mut corrupt_bytes = first_bytes;
    corrupt_bytes[0] ^= 0xff;
    let corrupted = CampaignRepository::new(
        Arc::new(RedirectBlobReads {
            inner: blobs.clone(),
            redirects: BTreeMap::from([(first_chunk, corrupt_bytes)]),
        }),
        repository.refs.clone(),
    );
    assert!(
        corrupted
            .load_finding_triage_replay_evidence(ordered_id)
            .is_err()
    );

    let inline = FindingTriageReplayEvidence::new(
        reproduction,
        signature.clone(),
        1,
        b"valid record of the wrong record kind".to_vec(),
    )
    .expect("inline replay evidence");
    let inline_id = repository
        .publish_finding_triage_replay_evidence(&inline)
        .expect("publish inline replay evidence");
    let inline_description = repository
        .describe_finding_triage_replay_storage(inline_id)
        .expect("describe inline replay storage");
    assert_eq!(inline_description.storage_schema_version(), 1);
    assert_eq!(inline_description.objects().len(), 1);
    assert_eq!(
        inline_description.objects()[0].content(),
        inline_id.content_id()
    );
    let inline_root_bytes = blobs
        .read(inline_id.content_id(), None)
        .expect("read inline storage root")
        .read_all(crate::codec::MAX_CANONICAL_BYTES as u64)
        .expect("copy inline storage root");
    inline_description
        .authenticate_root_envelope(&inline_root_bytes)
        .expect("authenticate inline root");
    assert_eq!(
        FindingTriageReplayEvidence::from_storage_envelopes(
            &inline_description,
            &[inline_root_bytes],
        )
        .expect("reassemble inline storage root"),
        inline
    );
    let wrong_kind_manifest = FindingTriageReplayManifest::new(
        reproduction,
        signature.clone(),
        1,
        1,
        vec![FindingTriageReplayChunkDescriptor::new(
            inline_id.content_id(),
            1,
        )],
    )
    .expect("structurally valid wrong-kind manifest");
    let wrong_kind_root = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::FindingTriageReplayEvidence,
        2,
        crate::object::content_children(wrong_kind_manifest.children())
            .expect("wrong-kind manifest children"),
        wrong_kind_manifest.canonical_bytes(),
    )
    .expect("wrong-kind root envelope");
    let wrong_kind_id = FindingTriageReplayEvidenceId::from_content_id(
        repository
            .put_envelope(wrong_kind_root)
            .expect("store wrong-kind root"),
    )
    .expect("wrong-kind root ID");
    assert!(matches!(
        repository.load_finding_triage_replay_evidence(wrong_kind_id),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-child-record-kind-mismatch"
        })
    ));

    let repeated = FindingTriageReplayEvidence::new(
        reproduction,
        signature,
        1,
        vec![b'r'; 2 * HALF_PAYLOAD_BYTES],
    )
    .expect("repeated-chunk replay evidence");
    let repeated_plan = repeated.storage_plan().expect("repeated storage plan");
    assert_eq!(repeated_plan.chunks.len(), 2);
    assert_eq!(
        repeated_plan.chunks[0].content(),
        repeated_plan.chunks[1].content()
    );
    let repeated_id = repository
        .publish_finding_triage_replay_evidence(&repeated)
        .expect("publish repeated-chunk evidence");
    let repeated_description = repository
        .describe_finding_triage_replay_storage(repeated_id)
        .expect("describe repeated-chunk storage");
    assert_eq!(repeated_description.objects().len(), 3);
    assert_eq!(
        repeated_description.objects()[1].content(),
        repeated_description.objects()[2].content()
    );
    assert_ne!(
        repeated_description.objects()[1].ordinal(),
        repeated_description.objects()[2].ordinal()
    );
    let repeated_range =
        crucible_cas::content_store::ByteRange::new(0, 64).expect("repeated-chunk bounded range");
    assert_eq!(
        repository
            .read_finding_triage_replay_storage_range(repeated_id, 1, repeated_range)
            .expect("read first repeated chunk position"),
        repository
            .read_finding_triage_replay_storage_range(repeated_id, 2, repeated_range)
            .expect("read second repeated chunk position")
    );
    assert_eq!(
        repository
            .load_finding_triage_replay_evidence(repeated_id)
            .expect("load repeated-chunk evidence"),
        repeated
    );

    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire missing-chunk inventory fence");
    inventory
        .delete_candidate(first_chunk)
        .expect("delete referenced chunk");
    drop(inventory);
    assert!(matches!(
        repository.load_finding_triage_replay_evidence(ordered_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
}

#[test]
fn maximum_triage_replay_evidence_survives_gc_and_restart() {
    let (repository, lineage, _, blobs) = fixture_with_quota(160 * 1024 * 1024);
    let fingerprint = CampaignHash::derive("test-finding", b"maximum triage replay evidence");
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            fingerprint,
            1,
            b"maximum triage replay reproduction".to_vec(),
        )
        .expect("publish maximum triage reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.maximum-triage-replay".to_owned(),
        Some(FindingTarget::Configuration(lineage.genesis_content())),
        BTreeSet::new(),
    )
    .expect("maximum triage signature");
    let evidence = FindingTriageReplayEvidence::new(
        reproduction,
        signature,
        1,
        vec![b'm'; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES],
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
    assert_eq!(chunk_ids.len(), 3);
    let evidence_id = repository
        .publish_finding_triage_replay_evidence(&evidence)
        .expect("publish maximum triage replay evidence");
    for (content, expected_kind, expected_schema) in std::iter::once((
        evidence_id.content_id(),
        CampaignRecordKind::FindingTriageReplayEvidence,
        2,
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
}
