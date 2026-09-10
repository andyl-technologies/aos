//! Immutable final-snapshot finding proofs retained by a guarded campaign run.
//!
//! The guarded owner uses its checked [`CampaignClient`] while the ephemeral
//! repository is still live. The resulting transcript contains request-bound
//! Merkle responses only and can therefore be exported after repository teardown.

use crucible_campaign::{
    CampaignClient, CampaignClientError, CampaignFindingObjectKind,
    CampaignFindingOccurrenceObjectKind, CampaignFindingOccurrenceService, CampaignName,
    CampaignPrincipal, CampaignService, CampaignServiceFailureSource, CampaignSnapshotId,
    FindingId, GetCampaignFindingObjectRequest, GetCampaignFindingObjectResponse,
    GetCampaignFindingOccurrenceObjectRequest, GetCampaignFindingOccurrenceObjectResponse,
    QueryCampaignFindingOccurrencesRequest, QueryCampaignFindingOccurrencesResponse,
    QueryCampaignFindingsRequest, QueryCampaignFindingsResponse,
};
use std::time::{Duration, Instant};

use crate::ExecutionCancellation;

use super::GuardedDefaultCampaignRunError;

const MAX_FINDING_EXPORT_BYTES: usize = 512 * 1024 * 1024;
const MAX_FINDING_EXPORT_EXCHANGES: usize = 1_000_000;
const FINDING_EXPORT_DEADLINE: Duration = Duration::from_secs(300);

struct FindingExportBudget {
    deadline: Instant,
    bytes: usize,
    exchanges: usize,
}

struct FindingExportContext<'a, C> {
    client: &'a C,
    principal: &'a CampaignPrincipal,
    campaign: &'a CampaignName,
    snapshot: CampaignSnapshotId,
    cancellation: &'a ExecutionCancellation,
}

pub(super) trait FindingExportClient {
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError>;

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError>;

    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, CampaignClientError>;

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, CampaignClientError>;
}

impl<S> FindingExportClient for CampaignClient<S>
where
    S: CampaignService + CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError> {
        CampaignClient::query_campaign_findings(self, request)
    }

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError> {
        CampaignClient::get_campaign_finding_object(self, request)
    }

    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, CampaignClientError> {
        CampaignClient::query_campaign_finding_occurrences(self, request)
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, CampaignClientError> {
        CampaignClient::get_campaign_finding_occurrence_object(self, request)
    }
}

impl FindingExportBudget {
    fn new() -> Result<Self, super::GuardedDefaultCampaignInvariantError> {
        let deadline = finding_export_now()
            .checked_add(FINDING_EXPORT_DEADLINE)
            .ok_or(super::GuardedDefaultCampaignInvariantError::FindingExportDeadline)?;
        Ok(Self {
            deadline,
            bytes: 0,
            exchanges: 0,
        })
    }

    fn check(&self) -> Result<(), super::GuardedDefaultCampaignInvariantError> {
        if finding_export_now() >= self.deadline {
            return Err(super::GuardedDefaultCampaignInvariantError::FindingExportDeadline);
        }
        Ok(())
    }

    fn retain_exchange(
        &mut self,
        request_bytes: usize,
        response_bytes: usize,
    ) -> Result<(), super::GuardedDefaultCampaignInvariantError> {
        self.check()?;
        self.exchanges = self
            .exchanges
            .checked_add(1)
            .ok_or(super::GuardedDefaultCampaignInvariantError::FindingExportLimit)?;
        self.bytes = self
            .bytes
            .checked_add(request_bytes)
            .and_then(|bytes| bytes.checked_add(response_bytes))
            .ok_or(super::GuardedDefaultCampaignInvariantError::FindingExportLimit)?;
        if self.exchanges > MAX_FINDING_EXPORT_EXCHANGES || self.bytes > MAX_FINDING_EXPORT_BYTES {
            return Err(super::GuardedDefaultCampaignInvariantError::FindingExportLimit);
        }
        Ok(())
    }
}

// Monotonic time bounds only the operational proof transfer. It can reject an
// incomplete export, but never enters campaign state or modeled evidence.
// crucible-lint: allow clippy-disallowed-method -- this host-boundary deadline cannot influence modeled execution.
#[allow(clippy::disallowed_methods)]
fn finding_export_now() -> Instant {
    Instant::now()
}

/// One checked request and response for a representative finding dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingObjectProof {
    request: GetCampaignFindingObjectRequest,
    response: GetCampaignFindingObjectResponse,
}

impl GuardedCampaignFindingObjectProof {
    /// Returns the exact snapshot-bound request.
    #[must_use]
    pub const fn request(&self) -> &GetCampaignFindingObjectRequest {
        &self.request
    }

    /// Returns the client-validated response and Merkle proof.
    #[must_use]
    pub const fn response(&self) -> &GetCampaignFindingObjectResponse {
        &self.response
    }
}

/// One checked request and response for a candidate-bundle dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOccurrenceObjectProof {
    request: GetCampaignFindingOccurrenceObjectRequest,
    response: GetCampaignFindingOccurrenceObjectResponse,
}

impl GuardedCampaignFindingOccurrenceObjectProof {
    /// Returns the exact finding- and bundle-bound request.
    #[must_use]
    pub const fn request(&self) -> &GetCampaignFindingOccurrenceObjectRequest {
        &self.request
    }

    /// Returns the client-validated response and both Merkle proofs.
    #[must_use]
    pub const fn response(&self) -> &GetCampaignFindingOccurrenceObjectResponse {
        &self.response
    }
}

/// One limit-one occurrence page and every dependency named by its bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOccurrenceProof {
    request: QueryCampaignFindingOccurrencesRequest,
    response: QueryCampaignFindingOccurrencesResponse,
    objects: Vec<GuardedCampaignFindingOccurrenceObjectProof>,
}

/// One checked page in the complete final-snapshot finding query chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingQueryProof {
    request: QueryCampaignFindingsRequest,
    response: QueryCampaignFindingsResponse,
}

impl GuardedCampaignFindingQueryProof {
    /// Returns the exact snapshot-bound page request.
    #[must_use]
    pub const fn request(&self) -> &QueryCampaignFindingsRequest {
        &self.request
    }

    /// Returns the client-validated page and Merkle proof.
    #[must_use]
    pub const fn response(&self) -> &QueryCampaignFindingsResponse {
        &self.response
    }
}

impl GuardedCampaignFindingOccurrenceProof {
    /// Returns the exact request for this occurrence page.
    #[must_use]
    pub const fn request(&self) -> &QueryCampaignFindingOccurrencesRequest {
        &self.request
    }

    /// Returns the client-validated occurrence page.
    #[must_use]
    pub const fn response(&self) -> &QueryCampaignFindingOccurrencesResponse {
        &self.response
    }

    /// Returns every checked dependency response for the page's single bundle.
    #[must_use]
    pub fn objects(&self) -> &[GuardedCampaignFindingOccurrenceObjectProof] {
        &self.objects
    }
}

/// Complete final-snapshot proof material for one incorporated finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingProof {
    finding: FindingId,
    request: QueryCampaignFindingsRequest,
    response: QueryCampaignFindingsResponse,
    objects: Vec<GuardedCampaignFindingObjectProof>,
    occurrences: Vec<GuardedCampaignFindingOccurrenceProof>,
}

impl GuardedCampaignFindingProof {
    /// Returns the incorporated finding identity.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the exact query request whose page contains the finding.
    #[must_use]
    pub const fn request(&self) -> &QueryCampaignFindingsRequest {
        &self.request
    }

    /// Returns the client-validated query page containing the finding.
    #[must_use]
    pub const fn response(&self) -> &QueryCampaignFindingsResponse {
        &self.response
    }

    /// Returns checked representative observation and reproduction responses.
    #[must_use]
    pub fn objects(&self) -> &[GuardedCampaignFindingObjectProof] {
        &self.objects
    }

    /// Returns the complete limit-one occurrence page chain.
    #[must_use]
    pub fn occurrences(&self) -> &[GuardedCampaignFindingOccurrenceProof] {
        &self.occurrences
    }
}

/// Immutable proof transcript for every finding at one final campaign snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingExport {
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    query_pages: Vec<GuardedCampaignFindingQueryProof>,
    findings: Vec<GuardedCampaignFindingProof>,
}

impl GuardedCampaignFindingExport {
    /// Returns the campaign named by every retained request.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the immutable final snapshot authenticated by every response.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns every checked page, including the sole page for an empty snapshot.
    #[must_use]
    pub fn query_pages(&self) -> &[GuardedCampaignFindingQueryProof] {
        &self.query_pages
    }

    /// Returns all incorporated final finding identities and their proof material.
    #[must_use]
    pub fn findings(&self) -> &[GuardedCampaignFindingProof] {
        &self.findings
    }
}

pub(super) fn capture_final_finding_export<C, E>(
    client: &C,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    cancellation: &ExecutionCancellation,
) -> Result<GuardedCampaignFindingExport, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut budget = FindingExportBudget::new()?;
    let context = FindingExportContext {
        client,
        principal,
        campaign,
        snapshot,
        cancellation,
    };
    let mut query_pages = Vec::new();
    let mut findings = Vec::new();
    let mut after = None;
    loop {
        budget.check()?;
        let request = QueryCampaignFindingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            1,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(cancellation)?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        budget.retain_exchange(
            request.canonical_bytes().len(),
            response.canonical_bytes().len(),
        )?;
        let next_after = response.next_after();

        query_pages.push(GuardedCampaignFindingQueryProof {
            request: request.clone(),
            response: response.clone(),
        });

        if let Some(finding) = response.entries().first() {
            let finding_id = finding
                .id()
                .map_err(GuardedDefaultCampaignRunError::Codec)?;
            let objects = capture_finding_objects(
                &context,
                finding_id,
                finding.minimized().is_some(),
                &mut budget,
            )?;
            let occurrences = capture_finding_occurrences(&context, finding_id, &mut budget)?;
            findings.push(GuardedCampaignFindingProof {
                finding: finding_id,
                request,
                response,
                objects,
                occurrences,
            });
        }

        let Some(cursor) = next_after else {
            break;
        };
        after = Some(cursor);
    }

    check_cancellation(cancellation)?;
    Ok(GuardedCampaignFindingExport {
        campaign: campaign.clone(),
        snapshot,
        query_pages,
        findings,
    })
}

fn capture_finding_objects<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    has_minimized: bool,
    budget: &mut FindingExportBudget,
) -> Result<Vec<GuardedCampaignFindingObjectProof>, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut kinds = vec![
        CampaignFindingObjectKind::Observation,
        CampaignFindingObjectKind::Reproduction,
    ];
    if has_minimized {
        kinds.push(CampaignFindingObjectKind::MinimizedReproduction);
    }

    let mut objects = Vec::new();
    for kind in kinds {
        budget.check()?;
        let request = GetCampaignFindingObjectRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            kind,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .get_campaign_finding_object(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        budget.retain_exchange(
            request.canonical_bytes().len(),
            response.canonical_bytes().len(),
        )?;
        objects.push(GuardedCampaignFindingObjectProof { request, response });
    }
    Ok(objects)
}

fn capture_finding_occurrences<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    budget: &mut FindingExportBudget,
) -> Result<Vec<GuardedCampaignFindingOccurrenceProof>, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut pages = Vec::new();
    let mut after = None;
    loop {
        budget.check()?;
        let request = QueryCampaignFindingOccurrencesRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            after,
            1,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .query_campaign_finding_occurrences(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        budget.retain_exchange(
            request.canonical_bytes().len(),
            response.canonical_bytes().len(),
        )?;
        let next_after = response.next_after();
        let objects = match response.entries().first() {
            Some(occurrence) => {
                capture_occurrence_objects(context, finding, occurrence.bundle(), budget)?
            }
            None => Vec::new(),
        };
        pages.push(GuardedCampaignFindingOccurrenceProof {
            request,
            response,
            objects,
        });

        let Some(cursor) = next_after else {
            break;
        };
        after = Some(cursor);
    }
    Ok(pages)
}

fn capture_occurrence_objects<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    bundle: &crucible_campaign::FindingCandidateBundle,
    budget: &mut FindingExportBudget,
) -> Result<Vec<GuardedCampaignFindingOccurrenceObjectProof>, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut kinds = vec![
        CampaignFindingOccurrenceObjectKind::Observation,
        CampaignFindingOccurrenceObjectKind::Reproduction,
        CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
    ];
    if bundle.triage_evidence().is_some() {
        kinds.extend([
            CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence,
            CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence,
            CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence,
            CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence,
        ]);
    }
    let bundle = bundle.id().map_err(GuardedDefaultCampaignRunError::Codec)?;

    let mut objects = Vec::new();
    for kind in kinds {
        budget.check()?;
        let request = GetCampaignFindingOccurrenceObjectRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            bundle,
            kind,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        budget.retain_exchange(
            request.canonical_bytes().len(),
            response.canonical_bytes().len(),
        )?;
        objects.push(GuardedCampaignFindingOccurrenceObjectProof { request, response });
    }
    Ok(objects)
}

fn check_cancellation<E>(
    cancellation: &ExecutionCancellation,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    E: std::error::Error + 'static,
{
    if cancellation.is_canceled() {
        return Err(super::GuardedDefaultCampaignInvariantError::FindingExportCanceled.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible_campaign::{
        CampaignHash, CampaignLineageId, CampaignPolicyId, CampaignRoots, CampaignSnapshot,
        Finding, FindingKind, FindingOccurrenceSet, FindingSignature, MerkleMap, ObservationId,
        ReproductionArtifactId,
    };
    use crucible_cas::content_store::{ContentId, MemoryBlobBackend, ObjectKind};

    use super::*;

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
        let snapshot = CampaignSnapshot::genesis(
            CampaignLineageId::parse(&format!(
                "crucible.campaign.lineage@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"finding-export-lineage")
                    .encode()
            ))
            .expect("campaign lineage"),
            CampaignPolicyId::parse(&format!(
                "crucible.campaign.policy@{}",
                ContentId::for_bytes(ObjectKind::Policy, 1, b"finding-export-policy").encode()
            ))
            .expect("campaign policy"),
            roots,
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
            ContentId::for_bytes(ObjectKind::Observation, 1, b"finding-export-observation")
                .encode()
        ))
        .expect("observation ID");
        let first_seen = CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                2,
                b"finding-export-first-seen"
            )
            .encode()
        ))
        .expect("first-seen snapshot");
        Finding::new(
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
                ContentId::for_bytes(ObjectKind::Finding, 1, b"finding-export-reproduction")
                    .encode()
            ))
            .expect("reproduction ID"),
            first_seen,
            FindingOccurrenceSet::new(occurrence_root, 1, observation)
                .expect("finding occurrence set"),
            None,
            BTreeSet::new(),
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

    #[test]
    fn pre_canceled_export_attempts_no_transfer() {
        let cancellation = ExecutionCancellation::default();
        let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, false);
        cancellation.cancel();

        let result = capture_final_finding_export::<_, io::Error>(
            &client,
            &principal,
            &campaign,
            snapshot,
            &cancellation,
        );

        assert!(matches!(
            result,
            Err(GuardedDefaultCampaignRunError::Invariant(
                super::super::GuardedDefaultCampaignInvariantError::FindingExportCanceled
            ))
        ));
        assert_eq!(client.query_transfers.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_snapshot_export_retains_its_authenticated_query_page() {
        let cancellation = ExecutionCancellation::default();
        let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, false);

        let export = capture_final_finding_export::<_, io::Error>(
            &client,
            &principal,
            &campaign,
            snapshot,
            &cancellation,
        )
        .expect("empty finding export");

        assert_eq!(export.campaign(), &campaign);
        assert_eq!(export.snapshot(), snapshot);
        assert_eq!(export.query_pages().len(), 1);
        assert!(export.query_pages()[0].response().entries().is_empty());
        assert_eq!(export.query_pages()[0].response().next_after(), None);
        assert!(export.findings().is_empty());
        assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_during_export_stops_after_current_transfer_without_a_partial_result() {
        let cancellation = ExecutionCancellation::default();
        let (principal, campaign, snapshot, client) = empty_query_fixture(&cancellation, true);

        let result = capture_final_finding_export::<_, io::Error>(
            &client,
            &principal,
            &campaign,
            snapshot,
            &cancellation,
        );

        assert!(matches!(
            result,
            Err(GuardedDefaultCampaignRunError::Invariant(
                super::super::GuardedDefaultCampaignInvariantError::FindingExportCanceled
            ))
        ));
        assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_after_nonempty_query_prevents_pending_object_transfer() {
        let cancellation = ExecutionCancellation::default();
        let (principal, campaign, snapshot, client) = nonempty_query_fixture(&cancellation);

        let result = capture_final_finding_export::<_, io::Error>(
            &client,
            &principal,
            &campaign,
            snapshot,
            &cancellation,
        );

        assert!(matches!(
            result,
            Err(GuardedDefaultCampaignRunError::Invariant(
                super::super::GuardedDefaultCampaignInvariantError::FindingExportCanceled
            ))
        ));
        assert_eq!(client.query_transfers.load(Ordering::SeqCst), 1);
        assert_eq!(client.object_transfers.load(Ordering::SeqCst), 0);
    }
}
