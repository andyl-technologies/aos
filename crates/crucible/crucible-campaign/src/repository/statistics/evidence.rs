//! Owner collection of statistical evidence, one execution at a time.
//!
//! Every statistical item (a stage-zero draw or an SMC transition) is
//! collected from the pinned snapshot roots as one bounded execution closure.
//! Internal estimates feed those items straight into incremental replay. The
//! portable form packs the same items, in replay order, into chunks of at most
//! [`MAX_STATISTICAL_EVIDENCE_BYTES`] and [`MAX_STATISTICAL_EVIDENCE_ITEMS`]:
//! [`CampaignRepository::collect_statistical_evidence_manifest`] streams every
//! item once to replay it and derive the chunk digests, and
//! [`CampaignRepository::collect_statistical_evidence_chunk`] rebuilds one
//! named chunk deterministically, so a service can answer one chunk per
//! response without retaining the campaign's evidence.

use super::*;
use crate::statistics::statistical_evidence_item_count;
use crate::{
    MAX_STATISTICAL_EVIDENCE_BYTES, MAX_STATISTICAL_EVIDENCE_ITEMS, SmcTransitionEvidence,
    StatisticalChoiceEvidence, StatisticalDrawEvidence, StatisticalEvidenceChunk,
    StatisticalEvidenceChunkDescriptor, StatisticalEvidenceItem, StatisticalEvidenceManifest,
    StatisticalExecutionBasisEvidence, StatisticalExecutionEvidence,
    StatisticalOpportunityEvidence,
};

/// Canonical bytes of a chunk around its items: schema version, index, first
/// item, and the item-sequence length (`u32`, `u32`, `u64`, `u64`).
const CHUNK_HEADER_BYTES: usize = 24;

/// Bytes around one execution inside a chunk item: the item tag plus the
/// larger of the draw (`u64`) and transition (`u32`, `u32`) coordinates.
const CHUNK_ITEM_WRAPPER_BYTES: usize = 1 + std::mem::size_of::<u64>();

/// Largest execution closure that still fits alone in one chunk.
pub(super) const MAX_ITEM_EXECUTION_BYTES: usize =
    MAX_STATISTICAL_EVIDENCE_BYTES - CHUNK_HEADER_BYTES - CHUNK_ITEM_WRAPPER_BYTES;

/// Replay-order position of one statistical item in its snapshot.
#[derive(Clone, Copy)]
enum ItemCoordinate {
    Draw(u64),
    Transition { stage: u32, slot: u32 },
}

/// Enumerates every item of a complete run of `policy` in replay order.
fn item_coordinates(policy: &CampaignPolicy) -> impl Iterator<Item = ItemCoordinate> + '_ {
    let draws = policy
        .statistical_sampling_design()
        .into_iter()
        .flat_map(|design| design.draws().keys().copied().map(ItemCoordinate::Draw));
    let transitions = policy
        .sequential_monte_carlo_design()
        .into_iter()
        .flat_map(|design| {
            design.stages().keys().copied().flat_map(move |stage| {
                (0..design.particle_count())
                    .map(move |slot| ItemCoordinate::Transition { stage, slot })
            })
        });
    draws.chain(transitions)
}

/// Per-chunk packing limits.
///
/// Production manifests always use [`Self::TRANSPORT`]; tests pack the same
/// items under smaller limits to exercise multi-chunk manifests.
#[derive(Clone, Copy, Debug)]
pub(in crate::repository) struct ChunkLimits {
    /// Largest canonical chunk, including its header.
    pub(in crate::repository) max_bytes: usize,
    /// Largest number of items in one chunk.
    pub(in crate::repository) max_items: usize,
}

impl ChunkLimits {
    /// The portable transport bounds every verifier enforces.
    pub(in crate::repository) const TRANSPORT: Self = Self {
        max_bytes: MAX_STATISTICAL_EVIDENCE_BYTES,
        max_items: MAX_STATISTICAL_EVIDENCE_ITEMS,
    };
}

/// Greedy in-order packer that seals a chunk before it would overflow.
struct ChunkPacker {
    limits: ChunkLimits,
    next_index: u32,
    next_item: u64,
    items: Vec<StatisticalEvidenceItem>,
    item_bytes: usize,
    descriptors: Vec<StatisticalEvidenceChunkDescriptor>,
}

impl ChunkPacker {
    fn new(limits: ChunkLimits) -> Self {
        Self {
            limits,
            next_index: 0,
            next_item: 0,
            items: Vec::new(),
            item_bytes: 0,
            descriptors: Vec::new(),
        }
    }

    fn push(&mut self, item: StatisticalEvidenceItem) -> Result<(), CampaignRepositoryError> {
        let bytes = crate::codec::encode(&item).len();
        let fits = self
            .item_bytes
            .checked_add(bytes)
            .and_then(|total| total.checked_add(CHUNK_HEADER_BYTES))
            .is_some_and(|total| total <= self.limits.max_bytes);
        if !self.items.is_empty() && (!fits || self.items.len() >= self.limits.max_items) {
            self.seal()?;
        }
        self.item_bytes = self
            .item_bytes
            .checked_add(bytes)
            .ok_or_else(|| integrity("statistical evidence byte accounting overflows"))?;
        self.items.push(item);
        Ok(())
    }

    fn seal(&mut self) -> Result<(), CampaignRepositoryError> {
        let items = std::mem::take(&mut self.items);
        let count = u64::try_from(items.len())
            .map_err(|_| integrity("statistical evidence item count overflows"))?;
        let chunk = StatisticalEvidenceChunk::new(self.next_index, self.next_item, items)?;
        self.descriptors
            .push(StatisticalEvidenceChunkDescriptor::of_chunk(&chunk));
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| integrity("statistical evidence chunk count overflows"))?;
        self.next_item = self
            .next_item
            .checked_add(count)
            .ok_or_else(|| integrity("statistical evidence item count overflows"))?;
        self.item_bytes = 0;
        Ok(())
    }

    fn finish(
        mut self,
    ) -> Result<Vec<StatisticalEvidenceChunkDescriptor>, CampaignRepositoryError> {
        if !self.items.is_empty() {
            self.seal()?;
        }
        Ok(self.descriptors)
    }
}

/// Owner-side replay matching the policy's statistical kind.
enum OwnerReplay<'a> {
    Finite(FiniteEvidenceReplay<'a>),
    SequentialMonteCarlo(Box<SmcEvidenceReplay<'a>>),
}

impl OwnerReplay<'_> {
    fn push(&mut self, item: &StatisticalEvidenceItem) -> Result<(), CampaignRepositoryError> {
        match (self, item) {
            (Self::Finite(replay), StatisticalEvidenceItem::Draw(draw)) => replay.push(draw)?,
            (Self::SequentialMonteCarlo(replay), StatisticalEvidenceItem::Draw(draw)) => {
                replay.push_initial_draw(draw)?;
            }
            (Self::SequentialMonteCarlo(replay), StatisticalEvidenceItem::Transition(item)) => {
                replay.push_transition(item)?;
            }
            (Self::Finite(_), StatisticalEvidenceItem::Transition(_)) => {
                return Err(integrity("finite statistical policy has an SMC transition"));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<(), CampaignRepositoryError> {
        match self {
            Self::Finite(replay) => replay.finish().map(|_| ()),
            Self::SequentialMonteCarlo(replay) => replay.finish().map(|_| ()),
        }
        .map_err(Into::into)
    }
}

impl CampaignRepository {
    /// Collects the manifest of complete owner-authenticated statistical evidence.
    ///
    /// Every draw and transition is read from the pinned roots in replay order,
    /// replayed by the same verifier that checked clients use, and packed into
    /// chunks whose digests the manifest records. Only one chunk of items is
    /// held at a time. Fetch each chunk with
    /// [`Self::collect_statistical_evidence_chunk`].
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or incomplete snapshot, a non-statistical
    /// policy, invalid root membership, a malformed record closure, semantic
    /// replay failure, an execution closure too large for one chunk, or a
    /// manifest larger than the transport bound.
    pub fn collect_statistical_evidence_manifest(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<StatisticalEvidenceManifest, CampaignRepositoryError> {
        self.pack_statistical_evidence_manifest(name, expected_snapshot, ChunkLimits::TRANSPORT)
    }

    /// Collects the evidence manifest, packing chunks under `limits`.
    ///
    /// Limits only choose chunk boundaries; any tiling within the transport
    /// bounds verifies to the same report.
    pub(in crate::repository) fn pack_statistical_evidence_manifest(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        limits: ChunkLimits,
    ) -> Result<StatisticalEvidenceManifest, CampaignRepositoryError> {
        let snapshot = self.load_statistical_snapshot(name, expected_snapshot)?;
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        let is_smc = policy.sequential_monte_carlo_design().is_some();
        statistical_report_design(&policy, is_smc)?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let planning_view = snapshot.snapshot.planning_view();
        let basis = EvidenceBasis::new(&snapshot.snapshot, &planning_view, &policy, &lineage);

        let mut replay = if is_smc {
            OwnerReplay::SequentialMonteCarlo(Box::new(SmcEvidenceReplay::new(basis)?))
        } else {
            OwnerReplay::Finite(FiniteEvidenceReplay::new(basis, false)?)
        };
        let mut packer = ChunkPacker::new(limits);
        for coordinate in item_coordinates(&policy) {
            let item = self.collect_statistical_evidence_item(&snapshot, coordinate)?;
            replay.push(&item)?;
            packer.push(item)?;
        }
        replay.finish()?;

        StatisticalEvidenceManifest::new(
            snapshot.snapshot.clone(),
            planning_view,
            policy.clone(),
            lineage.clone(),
            statistical_evidence_item_count(&policy)?,
            packer.finish()?,
        )
        .map_err(Into::into)
    }

    /// Rebuilds one chunk named by a manifest descriptor.
    ///
    /// The items are reread from the same pinned snapshot, so the result must
    /// reproduce the descriptor's digest exactly.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, a descriptor outside the run's
    /// item range, a record-closure failure, or a chunk that does not
    /// reproduce the descriptor.
    pub fn collect_statistical_evidence_chunk(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        descriptor: &StatisticalEvidenceChunkDescriptor,
    ) -> Result<StatisticalEvidenceChunk, CampaignRepositoryError> {
        let snapshot = self.load_statistical_snapshot(name, expected_snapshot)?;
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        statistical_report_design(&policy, policy.sequential_monte_carlo_design().is_some())?;

        let first = usize::try_from(descriptor.first_item())
            .map_err(|_| integrity("statistical evidence chunk is outside its run"))?;
        let count = usize::try_from(descriptor.item_count())
            .map_err(|_| integrity("statistical evidence chunk is outside its run"))?;
        let item_end = descriptor
            .first_item()
            .checked_add(u64::from(descriptor.item_count()))
            .ok_or_else(|| integrity("statistical evidence chunk is outside its run"))?;
        if count == 0 || item_end > statistical_evidence_item_count(&policy)? {
            return Err(integrity("statistical evidence chunk is outside its run"));
        }

        let mut items = Vec::with_capacity(count);
        for coordinate in item_coordinates(&policy).skip(first).take(count) {
            items.push(self.collect_statistical_evidence_item(&snapshot, coordinate)?);
        }
        let chunk =
            StatisticalEvidenceChunk::new(descriptor.index(), descriptor.first_item(), items)?;
        if StatisticalEvidenceChunkDescriptor::of_chunk(&chunk) != *descriptor {
            return Err(integrity(
                "statistical evidence chunk does not match its manifest",
            ));
        }
        Ok(chunk)
    }

    fn collect_statistical_evidence_item(
        &self,
        snapshot: &LoadedSnapshot,
        coordinate: ItemCoordinate,
    ) -> Result<StatisticalEvidenceItem, CampaignRepositoryError> {
        match coordinate {
            ItemCoordinate::Draw(coordinate) => self
                .collect_statistical_draw_evidence(snapshot, coordinate)
                .map(StatisticalEvidenceItem::Draw),
            ItemCoordinate::Transition { stage, slot } => self
                .collect_smc_transition_evidence(snapshot, stage, slot)
                .map(StatisticalEvidenceItem::Transition),
        }
    }

    /// Collects one stage-zero draw small enough to fit alone in a chunk.
    pub(super) fn collect_statistical_draw_evidence(
        &self,
        snapshot: &LoadedSnapshot,
        coordinate: u64,
    ) -> Result<StatisticalDrawEvidence, CampaignRepositoryError> {
        let request_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().exploration,
                statistical_draw_request_key(coordinate),
            )?
            .ok_or_else(|| integrity("statistical-report-draw-request-is-missing"))?;
        let proposal_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                statistical_draw_proposal_key(coordinate),
            )?
            .ok_or_else(|| integrity("statistical-report-draw-proposal-is-missing"))?;
        let execution = self.collect_statistical_execution_evidence(
            snapshot,
            request_content,
            proposal_content,
            MAX_ITEM_EXECUTION_BYTES,
        )?;
        Ok(StatisticalDrawEvidence::new(coordinate, execution))
    }

    /// Collects one SMC transition small enough to fit alone in a chunk.
    pub(super) fn collect_smc_transition_evidence(
        &self,
        snapshot: &LoadedSnapshot,
        stage: u32,
        slot: u32,
    ) -> Result<SmcTransitionEvidence, CampaignRepositoryError> {
        let request_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().exploration,
                smc_transition_request_key(stage, slot),
            )?
            .ok_or_else(|| integrity("SMC evidence transition request is missing"))?;
        let proposal_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                smc_transition_proposal_key(stage, slot),
            )?
            .ok_or_else(|| integrity("SMC evidence transition proposal is missing"))?;
        let execution = self.collect_statistical_execution_evidence(
            snapshot,
            request_content,
            proposal_content,
            MAX_ITEM_EXECUTION_BYTES,
        )?;
        Ok(SmcTransitionEvidence::new(stage, slot, execution))
    }

    fn collect_statistical_execution_evidence(
        &self,
        snapshot: &LoadedSnapshot,
        request_content: ContentId,
        proposal_content: ContentId,
        maximum_bytes: usize,
    ) -> Result<StatisticalExecutionEvidence, CampaignRepositoryError> {
        let mut charged_bytes = std::mem::size_of::<u64>();
        let request = self.read_branch_request(request_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&request).len(),
            maximum_bytes,
        )?;
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&parent).len(),
            maximum_bytes,
        )?;
        let request_opportunity =
            self.collect_statistical_opportunity_evidence(request.opportunity())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&request_opportunity).len(),
            maximum_bytes,
        )?;
        let proposal = self.read_proposal(proposal_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&proposal).len(),
            maximum_bytes,
        )?;

        let proposal_admission_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            .ok_or_else(|| integrity("statistical evidence proposal admission is missing"))?;
        let proposal_admission = self.read_attempt_admission(proposal_admission_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&proposal_admission).len(),
            maximum_bytes,
        )?;
        let attempt_id = proposal_admission.attempt();
        let attempt = self.read_attempt(attempt_id.content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&attempt).len(),
            maximum_bytes,
        )?;
        let AttemptStart::Branch { selection, .. } = attempt.start() else {
            return Err(integrity("statistical evidence attempt is not a branch"));
        };
        let selection = self.resolve_selection(selection)?;
        let choice = StatisticalChoiceEvidence::new(
            selection.selection().clone(),
            StatisticalOpportunityEvidence::new(
                selection.opportunity().clone(),
                selection.declaration().clone(),
                selection.domain().clone(),
            ),
        );
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&choice).len(),
            maximum_bytes,
        )?;
        let path = self.read_branch_path(attempt.path().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&path).len(),
            maximum_bytes,
        )?;

        let observation_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", attempt_id.content_id()),
            )?
            .ok_or_else(|| integrity("statistical-report-draw-observation-is-missing"))?;
        let observation = self.read_observation(observation_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&observation).len(),
            maximum_bytes,
        )?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&child).len(),
            maximum_bytes,
        )?;
        let mut discovered_opportunities = Vec::new();
        self.for_each_discovered_choice(&observation, |opportunity| {
            let opportunity = self.collect_statistical_opportunity_evidence(opportunity)?;
            charge_statistical_execution_evidence(
                &mut charged_bytes,
                crate::codec::encode(&opportunity).len(),
                maximum_bytes,
            )?;
            discovered_opportunities.push(opportunity);
            Ok(())
        })?;

        let basis_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    attempt_id.content_id(),
                ),
            )?
            .ok_or_else(|| integrity("statistical evidence execution basis is missing"))?;
        let basis_admission = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(basis_proposal),
            ..
        } = basis_admission.role()
        else {
            return Err(integrity(
                "statistical evidence execution basis has no proposal",
            ));
        };
        let basis_proposal = self.read_proposal(basis_proposal.content_id())?;
        let basis_request = self.read_branch_request(basis_proposal.request().content_id())?;
        let execution_basis =
            StatisticalExecutionBasisEvidence::new(basis_admission, basis_proposal, basis_request);
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&execution_basis).len(),
            maximum_bytes,
        )?;

        let evidence = StatisticalExecutionEvidence::new(
            request,
            parent,
            request_opportunity,
            proposal,
            proposal_admission,
            execution_basis,
            attempt,
            choice,
            path,
            observation,
            child,
            discovered_opportunities,
        );
        debug_assert_eq!(charged_bytes, crate::codec::encode(&evidence).len());
        Ok(evidence)
    }

    fn collect_statistical_opportunity_evidence(
        &self,
        opportunity: ChoiceOpportunityId,
    ) -> Result<StatisticalOpportunityEvidence, CampaignRepositoryError> {
        let (opportunity, declaration, domain) =
            self.load_choice_opportunity_dependencies(opportunity)?;
        Ok(StatisticalOpportunityEvidence::new(
            opportunity,
            declaration,
            domain,
        ))
    }
}

fn charge_statistical_execution_evidence(
    charged_bytes: &mut usize,
    additional_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), CampaignRepositoryError> {
    *charged_bytes = charged_bytes
        .checked_add(additional_bytes)
        .ok_or_else(|| integrity("statistical execution evidence byte accounting overflows"))?;
    if *charged_bytes > maximum_bytes {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "statistical-evidence-bytes",
        }
        .into());
    }
    Ok(())
}
