//! Capture, transcript ownership, and read-back regressions for finding export.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_campaign::{
    CampaignHash, CampaignLineageId, CampaignPolicyId, CampaignRecordKind, CampaignRoots,
    CampaignSnapshot, Finding, FindingCandidateBundleId, FindingCandidateOccurrenceSet,
    FindingExactPins, FindingKind, FindingOccurrenceSet, FindingSignature, MerkleMap,
    ObservationId, ReproductionArtifactId,
};
use crucible_store::content_store::{ContentId, MemoryBlobBackend, ObjectKind};

use super::*;
use crate::qemu_campaign_lifecycle::campaign_run::GuardedDefaultCampaignInvariantError;

struct CountingQueryClient {
    expected_request: QueryCampaignFindingsRequest,
    response: QueryCampaignFindingsResponse,
    cancellation: ExecutionCancellation,
    cancel_on_query: bool,
    query_transfers: AtomicUsize,
    object_transfers: AtomicUsize,
}

impl FindingExportClient for CountingQueryClient {
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError> {
        assert_eq!(request, &self.expected_request);
        self.query_transfers.fetch_add(1, Ordering::SeqCst);
        if self.cancel_on_query {
            self.cancellation.cancel();
        }
        Ok(self.response.clone())
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError> {
        self.object_transfers.fetch_add(1, Ordering::SeqCst);
        unreachable!("cancellation must prevent a finding-object transfer")
    }

    fn query_campaign_finding_occurrences(
        &self,
        _request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, CampaignClientError> {
        unreachable!("empty finding page has no occurrence transfer")
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        _request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, CampaignClientError> {
        unreachable!("empty finding page has no occurrence-object transfer")
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        _request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, CampaignClientError> {
        unreachable!("empty finding page has no triage-replay transfer")
    }
}

fn empty_query_fixture(
    cancellation: &ExecutionCancellation,
    cancel_on_query: bool,
) -> (
    CampaignPrincipal,
    CampaignName,
    CampaignSnapshotId,
    CountingQueryClient,
) {
    query_fixture(cancellation, cancel_on_query, false)
}

fn nonempty_query_fixture(
    cancellation: &ExecutionCancellation,
) -> (
    CampaignPrincipal,
    CampaignName,
    CampaignSnapshotId,
    CountingQueryClient,
) {
    query_fixture(cancellation, true, true)
}

fn query_fixture(
    cancellation: &ExecutionCancellation,
    cancel_on_query: bool,
    include_finding: bool,
) -> (
    CampaignPrincipal,
    CampaignName,
    CampaignSnapshotId,
    CountingQueryClient,
) {
    let backend = Arc::new(MemoryBlobBackend::new(
        "finding-export-cancellation",
        u64::MAX,
    ));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty campaign index");
    let finding = include_finding.then(|| finding_for_test(empty.content_id()));
    let findings_root = match finding.as_ref() {
        Some(finding) => map
            .insert(
                empty.content_id(),
                finding_signature_key_for_test(finding.signature().cluster_key()),
                finding.id().expect("finding ID").content_id(),
            )
            .expect("finding index")
            .content_id(),
        None => empty.content_id(),
    };
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: findings_root,
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let ledger = crucible_campaign::CampaignBudgetLedger::empty(empty.content_id())
        .expect("campaign budget ledger")
        .id()
        .expect("campaign budget ledger ID");
    let snapshot = CampaignSnapshot::genesis(
        CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignFact,
                CampaignRecordKind::Lineage.schema_version(),
                b"finding-export-lineage",
            )
            .encode()
        ))
        .expect("campaign lineage"),
        CampaignPolicyId::parse(&format!(
            "crucible.campaign.policy@{}",
            ContentId::for_bytes(
                ObjectKind::Policy,
                CampaignRecordKind::Policy.schema_version(),
                b"finding-export-policy",
            )
            .encode()
        ))
        .expect("campaign policy"),
        roots,
        ledger,
    )
    .expect("campaign snapshot");
    let snapshot_id = snapshot.id().expect("campaign snapshot ID");
    let principal = CampaignPrincipal::new("operator:export-test").expect("principal");
    let campaign = CampaignName::new("finding-export-test").expect("campaign");
    let request = QueryCampaignFindingsRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot_id,
        None,
        1,
    )
    .expect("finding query");
    let (page, proof) = map
        .scan_with_proof(findings_root, None, 1)
        .expect("finding proof");
    let response = QueryCampaignFindingsResponse::new(
        &request,
        snapshot,
        finding.into_iter().collect(),
        page.next_after(),
        proof,
    )
    .expect("finding response");
    let client = CountingQueryClient {
        expected_request: request,
        response,
        cancellation: cancellation.clone(),
        cancel_on_query,
        query_transfers: AtomicUsize::new(0),
        object_transfers: AtomicUsize::new(0),
    };
    (principal, campaign, snapshot_id, client)
}

fn finding_for_test(occurrence_root: ContentId) -> Finding {
    let observation = ObservationId::parse(&format!(
        "crucible.campaign.observation@{}",
        ContentId::for_bytes(
            ObjectKind::Observation,
            CampaignRecordKind::Observation.schema_version(),
            b"finding-export-observation",
        )
        .encode()
    ))
    .expect("observation ID");
    let first_seen = CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{}",
        ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"finding-export-first-seen"
        )
        .encode()
    ))
    .expect("first-seen snapshot");
    let candidate_bundle = FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@{}",
        ContentId::for_bytes(
            ObjectKind::Finding,
            CampaignRecordKind::FindingCandidateBundle.schema_version(),
            b"finding-export-candidate",
        )
        .encode()
    ))
    .expect("finding candidate bundle ID");
    Finding::new_with_candidate_occurrences(
        Finding::basis(
            FindingSignature::new(
                FindingKind::Timeout,
                CampaignHash::derive("finding-export-fingerprint", b"timeout"),
                None,
                String::from("finding-export.timeout"),
                None,
                BTreeSet::new(),
            )
            .expect("finding signature"),
            observation,
            ReproductionArtifactId::parse(&format!(
                "crucible.campaign.reproduction-artifact@{}",
                ContentId::for_bytes(ObjectKind::Finding, 3, b"finding-export-reproduction")
                    .encode()
            ))
            .expect("reproduction ID"),
            first_seen,
            FindingOccurrenceSet::new(occurrence_root, 1, observation)
                .expect("finding occurrence set"),
        ),
        None,
        FindingExactPins::default(),
        candidate_bundle,
        FindingCandidateOccurrenceSet::new(occurrence_root, 1, candidate_bundle)
            .expect("finding candidate occurrences"),
    )
    .expect("finding")
}

fn finding_signature_key_for_test(signature: CampaignHash) -> CampaignHash {
    let namespace = "findings.signature";
    let mut bytes = Vec::with_capacity(namespace.len() + 40);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&signature.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

fn storage(root: &Path) -> FindingExportStorage {
    FindingExportStorage {
        directory: root.join(FINDING_EXPORT_DIRECTORY),
        maximum_bytes: 1024 * 1024 * 1024,
    }
}

fn transcript_files(storage: &FindingExportStorage) -> Vec<String> {
    match fs::read_dir(&storage.directory) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .expect("transcript directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read transcript directory: {error}"),
    }
}

fn capture_empty_export(root: &Path) -> GuardedCampaignFindingExport {
    let cancellation = ExecutionCancellation::default();
    let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, false);
    capture_final_finding_export::<_, io::Error>(
        &client,
        &principal,
        &campaign,
        snapshot,
        &cancellation,
        &storage(root),
    )
    .expect("empty finding export")
}

fn read_all_frames(
    export: &GuardedCampaignFindingExport,
) -> Result<Vec<GuardedCampaignFindingExportFrame>, GuardedCampaignFindingExportReadError> {
    export.frames()?.collect()
}

#[test]
fn pre_canceled_export_attempts_no_transfer_and_creates_no_transcript() {
    let root = tempfile::tempdir().expect("run-state root");
    let cancellation = ExecutionCancellation::default();
    let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, false);
    cancellation.cancel();

    let result = capture_final_finding_export::<_, io::Error>(
        &client,
        &principal,
        &campaign,
        snapshot,
        &cancellation,
        &storage(root.path()),
    );

    assert!(matches!(
        result,
        Err(GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::FindingExportCanceled
        ))
    ));
    assert_eq!(client.query_transfers.load(Ordering::SeqCst), 0);
    assert!(transcript_files(&storage(root.path())).is_empty());
}

#[test]
fn empty_snapshot_export_streams_its_authenticated_query_page() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());

    let frames = read_all_frames(&export).expect("validated transcript");

    assert_eq!(export.findings(), 0);
    assert_eq!(export.frame_count(), 1);
    assert_eq!(
        export.transcript_bytes(),
        fs::metadata(export.transcript_path())
            .expect("transcript metadata")
            .len()
    );
    let [GuardedCampaignFindingExportFrame::FindingQuery(page)] = frames.as_slice() else {
        panic!("expected exactly one finding query frame, got {frames:?}");
    };
    assert_eq!(page.request().campaign(), export.campaign());
    assert_eq!(page.request().snapshot(), export.snapshot());
    assert!(page.response().entries().is_empty());
    assert_eq!(page.response().next_after(), None);
}

#[test]
fn transcript_is_removed_when_the_last_export_handle_drops() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());
    let path = export.transcript_path().to_path_buf();
    let clone = export.clone();
    assert_eq!(clone, export);

    drop(export);
    assert!(path.exists(), "a live clone keeps the transcript");
    let frames = clone.frames().expect("open transcript");
    drop(clone);
    assert!(path.exists(), "an open reader keeps the transcript");

    drop(frames);
    assert!(!path.exists(), "the last handle removes the transcript");
    assert!(transcript_files(&storage(root.path())).is_empty());
}

#[test]
fn cancellation_during_export_stops_after_current_transfer_without_a_partial_transcript() {
    let root = tempfile::tempdir().expect("run-state root");
    let cancellation = ExecutionCancellation::default();
    let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, true);

    let result = capture_final_finding_export::<_, io::Error>(
        &client,
        &principal,
        &campaign,
        snapshot,
        &cancellation,
        &storage(root.path()),
    );

    assert!(matches!(
        result,
        Err(GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::FindingExportCanceled
        ))
    ));
    assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
    assert!(transcript_files(&storage(root.path())).is_empty());
}

#[test]
fn cancellation_after_nonempty_query_prevents_pending_object_transfer() {
    let root = tempfile::tempdir().expect("run-state root");
    let cancellation = ExecutionCancellation::default();
    let (principal, campaign, snapshot, client) = nonempty_query_fixture(&cancellation);

    let result = capture_final_finding_export::<_, io::Error>(
        &client,
        &principal,
        &campaign,
        snapshot,
        &cancellation,
        &storage(root.path()),
    );

    assert!(matches!(
        result,
        Err(GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::FindingExportCanceled
        ))
    ));
    assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
    assert_eq!(client.object_transfers.load(Ordering::SeqCst), 0);
    assert!(transcript_files(&storage(root.path())).is_empty());
}

#[test]
fn export_exceeding_its_disk_quota_fails_closed_without_a_partial_transcript() {
    let root = tempfile::tempdir().expect("run-state root");
    let cancellation = ExecutionCancellation::default();
    let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, false);
    let storage = FindingExportStorage {
        maximum_bytes: 256,
        ..storage(root.path())
    };

    let result = capture_final_finding_export::<_, io::Error>(
        &client,
        &principal,
        &campaign,
        snapshot,
        &cancellation,
        &storage,
    );

    assert!(matches!(
        result,
        Err(GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::FindingExportLimit
        ))
    ));
    assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
    assert!(transcript_files(&storage).is_empty());
}

#[test]
fn altered_frame_byte_fails_read_back() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());
    let mut bytes = fs::read(export.transcript_path()).expect("transcript bytes");
    // The single frame's response ends just before the 41-byte trailer.
    let target = bytes.len() - 64;
    bytes[target] ^= 0x01;
    fs::write(export.transcript_path(), &bytes).expect("rewrite transcript");

    let result = read_all_frames(&export);

    assert!(result.is_err(), "an altered frame must not validate");
}

#[test]
fn altered_trailer_digest_fails_read_back() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());
    let mut bytes = fs::read(export.transcript_path()).expect("transcript bytes");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    fs::write(export.transcript_path(), &bytes).expect("rewrite transcript");

    let result = read_all_frames(&export);

    assert!(matches!(
        result,
        Err(GuardedCampaignFindingExportReadError::Malformed { .. })
    ));
}

#[test]
fn truncated_transcript_fails_read_back() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());
    let bytes = fs::read(export.transcript_path()).expect("transcript bytes");
    fs::write(export.transcript_path(), &bytes[..bytes.len() - 1]).expect("truncate transcript");

    let result = read_all_frames(&export);

    assert!(matches!(
        result,
        Err(GuardedCampaignFindingExportReadError::Malformed { .. })
    ));
}

#[test]
fn transcript_with_trailing_bytes_fails_read_back() {
    let root = tempfile::tempdir().expect("run-state root");
    let export = capture_empty_export(root.path());
    let mut bytes = fs::read(export.transcript_path()).expect("transcript bytes");
    bytes.push(0);
    fs::write(export.transcript_path(), &bytes).expect("extend transcript");

    let result = read_all_frames(&export);

    assert!(matches!(
        result,
        Err(GuardedCampaignFindingExportReadError::Malformed { .. })
    ));
}
