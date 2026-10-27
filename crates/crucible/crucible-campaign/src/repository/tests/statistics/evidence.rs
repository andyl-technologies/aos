//! Chunked statistical evidence helpers and protocol regressions.
//!
//! Repository statistical tests collect evidence through the owner's manifest
//! and chunk API and verify it with the portable verifier. The protocol
//! regression splits one finished flight into several chunks and checks
//! ordering, completeness, tiling, and owner reproduction.

use super::*;

/// Complete chunked evidence collected from one statistical campaign head.
pub(super) struct CollectedEvidence {
    pub(super) manifest: crate::StatisticalEvidenceManifest,
    pub(super) chunks: Vec<crate::StatisticalEvidenceChunk>,
}

impl CollectedEvidence {
    pub(super) fn collect(
        repository: &CampaignRepository,
        campaign: &str,
        head: CampaignSnapshotId,
    ) -> Self {
        let manifest = repository
            .collect_statistical_evidence_manifest(campaign, head)
            .expect("collect statistical evidence manifest");
        let chunks = manifest
            .chunks()
            .iter()
            .map(|descriptor| {
                repository
                    .collect_statistical_evidence_chunk(campaign, head, descriptor)
                    .expect("collect statistical evidence chunk")
            })
            .collect();
        Self { manifest, chunks }
    }

    pub(super) fn items(&self) -> Vec<crate::StatisticalEvidenceItem> {
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.items().iter().cloned())
            .collect()
    }

    pub(super) fn draws(&self) -> Vec<crate::StatisticalDrawEvidence> {
        self.items()
            .into_iter()
            .filter_map(|item| match item {
                crate::StatisticalEvidenceItem::Draw(draw) => Some(draw),
                crate::StatisticalEvidenceItem::Transition(_) => None,
            })
            .collect()
    }

    pub(super) fn transitions(&self) -> Vec<crate::SmcTransitionEvidence> {
        self.items()
            .into_iter()
            .filter_map(|item| match item {
                crate::StatisticalEvidenceItem::Transition(transition) => Some(transition),
                crate::StatisticalEvidenceItem::Draw(_) => None,
            })
            .collect()
    }

    pub(super) fn verify(&self) -> Result<crate::StatisticalEvidenceReport, CampaignCodecError> {
        verify_chunks(&self.manifest, &self.chunks)
    }

    pub(super) fn root_lookups(&self) -> Vec<crate::StatisticalRootLookup> {
        self.chunks
            .iter()
            .flat_map(|chunk| {
                chunk
                    .required_root_lookups()
                    .expect("derive statistical evidence root lookups")
            })
            .collect()
    }

    /// Rebuilds the manifest around `chunks` under the same snapshot basis.
    fn manifest_for(
        &self,
        chunks: &[crate::StatisticalEvidenceChunk],
    ) -> crate::StatisticalEvidenceManifest {
        crate::StatisticalEvidenceManifest::new(
            self.manifest.snapshot().clone(),
            *self.manifest.planning_view(),
            self.manifest.policy().clone(),
            self.manifest.lineage().clone(),
            self.manifest.item_count(),
            chunks
                .iter()
                .map(crate::StatisticalEvidenceChunkDescriptor::of_chunk)
                .collect(),
        )
        .expect("rebuild statistical evidence manifest")
    }

    /// Verifies replacement items as one chunk under this evidence's basis.
    pub(super) fn verify_items(
        &self,
        items: Vec<crate::StatisticalEvidenceItem>,
    ) -> Result<crate::StatisticalEvidenceReport, CampaignCodecError> {
        let chunk = crate::StatisticalEvidenceChunk::new(0, 0, items)?;
        let manifest = self.manifest_for(std::slice::from_ref(&chunk));
        verify_chunks(&manifest, &[chunk])
    }
}

fn verify_chunks(
    manifest: &crate::StatisticalEvidenceManifest,
    chunks: &[crate::StatisticalEvidenceChunk],
) -> Result<crate::StatisticalEvidenceReport, CampaignCodecError> {
    let mut verifier = crate::StatisticalEvidenceVerifier::new(manifest)?;
    for chunk in chunks {
        verifier.push_chunk(chunk)?;
    }
    verifier.finish()
}

fn codec_reason(result: Result<impl std::fmt::Debug, CampaignCodecError>) -> &'static str {
    match result {
        Err(CampaignCodecError::InvalidValue { reason }) => reason,
        other => panic!("expected an invalid statistical evidence value: {other:?}"),
    }
}

/// Exercises the chunked evidence protocol on a complete two-draw flight.
pub(super) fn assert_chunked_evidence_protocol(
    repository: &CampaignRepository,
    campaign: &str,
    head: CampaignSnapshotId,
    report: &crate::StatisticalEstimateReport,
) {
    let expected = crate::StatisticalEvidenceReport::Finite(report.clone());

    // Both small draws share one transport-sized chunk.
    let evidence = CollectedEvidence::collect(repository, campaign, head);
    assert_eq!(evidence.manifest.item_count(), 2);
    assert_eq!(evidence.chunks.len(), 1);
    assert_eq!(
        evidence.verify().expect("verify one-chunk evidence"),
        expected
    );

    // A one-item limit packs one chunk per draw; the owner rebuilds each
    // chunk from its descriptor and the split manifest verifies identically.
    let one_item = crate::repository::statistics::ChunkLimits {
        max_bytes: crate::MAX_STATISTICAL_EVIDENCE_BYTES,
        max_items: 1,
    };
    let split_manifest = repository
        .pack_statistical_evidence_manifest(campaign, head, one_item)
        .expect("pack one-item evidence chunks");
    assert_eq!(split_manifest.chunks().len(), 2);
    let split_chunks = split_manifest
        .chunks()
        .iter()
        .map(|descriptor| {
            repository
                .collect_statistical_evidence_chunk(campaign, head, descriptor)
                .expect("rebuild split evidence chunk")
        })
        .collect::<Vec<_>>();
    for chunk in &split_chunks {
        assert_eq!(chunk.items().len(), 1);
        assert_eq!(
            crate::StatisticalEvidenceChunk::from_canonical_bytes(&chunk.canonical_bytes())
                .expect("round-trip split evidence chunk"),
            *chunk
        );
    }
    assert_eq!(
        crate::StatisticalEvidenceManifest::from_canonical_bytes(&split_manifest.canonical_bytes())
            .expect("round-trip split evidence manifest"),
        split_manifest
    );
    assert_eq!(
        verify_chunks(&split_manifest, &split_chunks).expect("verify split evidence"),
        expected
    );

    // A byte limit that admits only the larger draw also splits the flight.
    let largest_item = evidence
        .items()
        .iter()
        .map(|item| crate::codec::encode(item).len())
        .max()
        .expect("evidence has items");
    let byte_limited = crate::repository::statistics::ChunkLimits {
        max_bytes: 24 + largest_item,
        max_items: crate::MAX_STATISTICAL_EVIDENCE_ITEMS,
    };
    let byte_manifest = repository
        .pack_statistical_evidence_manifest(campaign, head, byte_limited)
        .expect("pack byte-limited evidence chunks");
    assert_eq!(byte_manifest.chunks(), split_manifest.chunks());

    // Chunks must arrive complete, in manifest order, and unaltered.
    let mut verifier =
        crate::StatisticalEvidenceVerifier::new(&split_manifest).expect("start verifier");
    assert_eq!(
        codec_reason(verifier.push_chunk(&split_chunks[1])),
        "statistical evidence chunk does not match its manifest"
    );
    let mut verifier =
        crate::StatisticalEvidenceVerifier::new(&split_manifest).expect("start verifier");
    verifier
        .push_chunk(&split_chunks[0])
        .expect("verify first chunk");
    assert_eq!(
        codec_reason(verifier.finish()),
        "statistical evidence chunk is missing"
    );
    let mut verifier =
        crate::StatisticalEvidenceVerifier::new(&split_manifest).expect("start verifier");
    for chunk in &split_chunks {
        verifier.push_chunk(chunk).expect("verify split chunk");
    }
    assert_eq!(
        codec_reason(verifier.push_chunk(&split_chunks[1])),
        "statistical evidence chunk is not in its manifest"
    );
    let reordered =
        crate::StatisticalEvidenceChunk::new(0, 0, vec![split_chunks[1].items()[0].clone()])
            .expect("reordered chunk");
    assert_eq!(
        codec_reason(verify_chunks(
            &split_manifest,
            &[reordered.clone(), split_chunks[1].clone()]
        )),
        "statistical evidence chunk does not match its manifest"
    );

    // Manifests must tile exactly the policy's item range.
    assert!(matches!(
        crate::StatisticalEvidenceManifest::new(
            split_manifest.snapshot().clone(),
            *split_manifest.planning_view(),
            split_manifest.policy().clone(),
            split_manifest.lineage().clone(),
            2,
            vec![split_manifest.chunks()[1]],
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "statistical evidence chunks do not tile the item range"
        })
    ));
    let truncated = crate::StatisticalEvidenceManifest::new(
        split_manifest.snapshot().clone(),
        *split_manifest.planning_view(),
        split_manifest.policy().clone(),
        split_manifest.lineage().clone(),
        1,
        vec![split_manifest.chunks()[0]],
    )
    .expect("structurally tiled truncated manifest");
    assert_eq!(
        codec_reason(crate::StatisticalEvidenceVerifier::new(&truncated).map(|_| ())),
        "statistical evidence item count disagrees with its policy"
    );

    // The owner refuses descriptors it cannot reproduce.
    let forged = crate::StatisticalEvidenceChunkDescriptor::of_chunk(&reordered);
    assert!(matches!(
        repository.collect_statistical_evidence_chunk(campaign, head, &forged),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical evidence chunk does not match its manifest"
        })
    ));
    let beyond = crate::StatisticalEvidenceChunkDescriptor::of_chunk(
        &crate::StatisticalEvidenceChunk::new(2, 2, vec![split_chunks[0].items()[0].clone()])
            .expect("chunk beyond the run"),
    );
    assert!(matches!(
        repository.collect_statistical_evidence_chunk(campaign, head, &beyond),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical evidence chunk is outside its run"
        })
    ));
}
