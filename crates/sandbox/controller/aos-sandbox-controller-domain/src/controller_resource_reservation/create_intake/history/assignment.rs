//! Plans the first immutable assignment under the same held J/Source/Cache.
//!
//! This new Controller phase12 is a paid logical declaration, not InputsReady,
//! an Ownership lease, a signing challenge or permission to send Prepare. It
//! preserves the original accepted Create, enrolled Node, Spec, child capacity
//! and compiler proposal while the actual Root later independently verifies B.

use super::*;
use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, FeatureRef, IncarnationId, NodeId,
    ProjectId, SandboxId, AssignmentEpoch, DesiredGeneration, NamespaceGeneration,
};
use aos_sandbox_model::model::SandboxAncestry;
use aos_sandbox_protocol::policy_data::{
    PublisherPolicyDataError, RetainedPublisherCompilerOriginV3,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    assignment_planned::AssignmentPlannedBodyDataV1,
    cache_held::CacheHeldReceiptDataV1,
};
use aos_sandbox_cache::CacheHeldPreRootCutV1;
use sha2::{Digest as _, Sha256};

type AssignmentResult<T> = Result<T, AssignmentPlannedErrorV1>;

#[derive(Debug, thiserror::Error)]
pub(super) enum AssignmentPlannedErrorV1 {
    #[error(transparent)]
    History(#[from] HistoryProductionErrorV1),
    #[error(transparent)]
    Resource(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Framing(#[from] HistoryErrorV1),
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("assignment proposal model failed: {0}")]
    Model(#[source] Box<dyn StdError + Send + Sync>),
    #[error("an immutable assignment, prepared publication or pending binding already exists")]
    AlreadyAssigned,
    #[error("original assignment proposal is closed")]
    Closed,
}

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct AssignmentPlannedOriginalV1 {
    q04: Option<Result<crate::policy_compiler::create_q04::Q04CutIdentityV1, ResourceReservationErrorV1>>,
    original_clock: Option<RawPairedClockSample>,
    cutoff: Option<u64>,
    record_ceiling: Option<usize>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    node: Option<Result<NodeId, ResourceReservationErrorV1>>,
    incarnation: Option<std::io::Result<[u8; 16]>>,
    origin_shape: Option<Result<usize, PublisherPolicyDataError>>,
    origin: Option<Result<
        (
            RetainedPublisherCompilerOriginV3,
            aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1
        ),
        PublisherPolicyDataError
    >>,
    tree: Option<Result<crate::hierarchy::protected_journal::CreateStorageEmptyTreeDataV1,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1>>,
    publication: Option<Result<bool, crate::publication::AuthorityPublicationError>>,
    authority: Option<Result<bool, crate::runtime_authority::RuntimeAuthorityError>>,
    manifest: Option<AssignmentResult<CanonicalAssignmentManifestV1>>,
    body: Vec<u8>,
    encoding: Option<Result<(), HistoryErrorV1>>,
    pair: OriginalHistoryPairV1,
    pair_entered: bool,
    primary: Option<AssignmentResult<()>>,
    complete: bool,
}

impl AssignmentPlannedOriginalV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn completed_q04_identity_v1(&self)
        -> Result<&crate::policy_compiler::create_q04::Q04CutIdentityV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.q04.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn retain_q04_association_once(
        &mut self,
        q04: Result<crate::policy_compiler::create_q04::Q04CutIdentityV1, ResourceReservationErrorV1>,
        parent: &ProjectPreparationReservationAttemptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.q04.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.q04 = Some(q04.and_then(|identity| {
            if !parent.matches_create_continuation_identity(&identity) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(identity)
        }));
        if matches!(self.q04, Some(Ok(_))) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    // Only the joined original Ready scope invokes this closed producer. The
    // actual Cache pre-Root borrower remains alive through the Native append.
    pub(in crate::controller_resource_reservation::create_intake) fn produce_once(
        &mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut CacheHeldPreRootCutV1<'_, '_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.primary.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.primary = Some(self.produce_inner(parent, intake, histories, controller, source, profile, cache));
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Some(original), Some(cutoff)) = (self.original_clock, self.cutoff) {
                self.pair.finish_posts_once(intake, controller, source.journal(), profile,
                    original, cutoff, HistoryRoleV1::Controller);
            }
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(
        &mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut CacheHeldPreRootCutV1<'_, '_>,
    ) -> AssignmentResult<()> {
        retained(&self.q04)?;
        let accepted = parent.create_storage_original_identity_v1()?;
        self.cutoff = Some(accepted.original_cutoff);
        self.original_clock = Some(intake.create_storage_j_data_v1()?.clock);
        let lane = intake.create_lane()?;
        let source_receipt = histories.source_held_data_v1(lane)?;
        let cache_receipt = cache.held_receipt_data_v1().map_err(|_| AssignmentPlannedErrorV1::Closed)?;
        cache_receipt.compare_source(lane, source_receipt)?;
        let before = histories.controller_position_v1()?;
        self.funding = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            let (_, origin_bytes) = parent.create_storage_policy_sources_v1()?;
            parent.create_storage_assignment_proposal_inputs_v1()?;
            self.origin_shape = Some(RetainedPublisherCompilerOriginV3::borrow_policy_output_bytes_v3(origin_bytes)
                .map(<[u8]>::len));
            let policy_bytes = *self.origin_shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let record_bound = first_assignment_record_bound_v1();
            self.record_ceiling = Some(record_bound);
            let mut demand = pair_fixed_demand(record_bound)?;
            demand = demand.checked_add(controller.create_storage_semantic_append_demand_v1()?)?;
            demand = demand.checked_add(source.journal().create_storage_semantic_append_demand_v1()?)?;
            demand = demand.checked_add(aos_sandbox_ledger_replay::replay::tree_lineage::start_assignment::
                create_storage_tree_model_demand_v1(source.journal().historical_read_view_v1().rows_data_v2())
                .map_err(crate::JournalError::from)?)?;
            demand = demand.checked_add(policy_model_demand(policy_bytes)?)?;
            let construction = crate::policy_compiler::assignment_manifest_construction_receiving_bytes_v2()
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            demand = demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction))?;
            let feature_cells = 3 * (4 * aos_sandbox_model::model::MAX_ASSIGNMENT_REQUIRED_FEATURES + 1);
            let descriptor_cells = 3 * 14;
            let manifest_models = feature_cells * (std::mem::size_of::<FeatureRef>() + 255)
                + descriptor_cells * (std::mem::size_of::<ObjectDescriptor>() + 255);
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(manifest_models).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::MetadataEntries, u64::try_from(feature_cells + descriptor_cells).map_err(|_| ResourceReservationErrorV1::Conflict)?))?;
            let origin_memory = origin_bytes.len().checked_mul(4)
                .and_then(|n| n.checked_add(32 * std::mem::size_of::<Vec<u8>>()))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(origin_memory).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::MetadataEntries, 32))?;
            intake.reserve_create_capture_complete(Owner::AssignmentPlanned, demand)?;
            // All earlier C/S and Cache name samples are completely positive
            // and their fresh Files disposed. Reuse the same 21-FD peak while
            // retaining old fourteen and new three Source ancestor Vec backings;
            // three existing eight-slot memory recipes conservatively cover 17.
            let names = crate::journal::create_storage_name_peak_demand_v1()?;
            let names = names.with(D::MemoryBytes, names.get(D::MemoryBytes).checked_mul(3)
                .ok_or(ResourceReservationErrorV1::Conflict)?);
            intake.reserve_create_capture_complete(Owner::HistoryNames, names)?;
            // Entry, Native final crossing and independent after each read two
            // exact producer properties. Earlier retained rows remain charged.
            intake.extend_create_capture_observers_once(profile, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal(), profile, HistoryRoleV1::Controller)?;
        self.node = Some(intake.create_storage_node_v1());
        self.incarnation = Some(crate::policy_compiler::fresh_root_nonce());
        let (_, origin_bytes) = parent.create_storage_policy_sources_v1()?;
        self.origin = Some(RetainedPublisherCompilerOriginV3::from_record_bytes_with_policy_v3(origin_bytes));
        let (origin, _) = retained(&self.origin)?;
        if origin.project().into_bytes() != accepted.project || origin.original_target().into_bytes() != accepted.sandbox {
            return Err(AssignmentPlannedErrorV1::Closed);
        }
        self.tree = Some(crate::hierarchy::protected_journal::create_storage_empty_tree_data_v1(
            source.journal(), ProjectId::from_bytes(accepted.project)));
        let q04 = retained(&self.q04)?;
        if retained(&self.tree)?.tree_head != q04.ancestry() || !parent.matches_create_continuation_identity(q04) {
            return Err(AssignmentPlannedErrorV1::Closed);
        }
        let sandbox = SandboxId::from_bytes(accepted.sandbox);
        self.publication = Some(crate::publication::assignment_subject_present_v1(controller, sandbox));
        self.authority = Some(crate::runtime_authority::assignment_subject_present_v1(controller, sandbox));
        if *retained(&self.publication)? || *retained(&self.authority)? {
            return Err(AssignmentPlannedErrorV1::AlreadyAssigned);
        }
        self.manifest = Some((|| {
            let (spec, reservations) = parent.create_storage_assignment_proposal_inputs_v1()?;
            let (origin, policy) = retained(&self.origin)?;
            let policy = policy.policy();
            let policy_data = crate::policy_compiler::assignment_manifest_policy_data_v2(policy, spec.spec())
                .map_err(model)?;
            let ancestry = SandboxAncestry::new(sandbox, Vec::new()).map_err(model)?;
            let [policy_descriptor, _, _, _] = origin.output_descriptors().map_err(model)?;
            let placement = crate::policy_compiler::AssignmentManifestPlacementDataV2 {
                sandbox,
                project: ProjectId::from_bytes(accepted.project),
                ancestry,
                incarnation: IncarnationId::from_bytes(*retained(&self.incarnation)?),
                node: *retained(&self.node)?,
                epoch: AssignmentEpoch::new(1),
                desired_generation: DesiredGeneration::new(1),
                namespace_generation: NamespaceGeneration::new(1),
            };
            crate::policy_compiler::materialize_assignment_manifest_v2(
                placement, spec.spec(), spec.descriptor(), policy_data, policy_descriptor, reservations,
            ).map_err(model)
        })());
        let manifest = retained(&self.manifest)?;
        let source_body = source_receipt.body(lane)?;
        let source_envelope = RecordEnvelopeV1::decode(source_receipt.record,
            KeyV1::new(lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
        let cache_envelope = RecordEnvelopeV1::decode(cache_receipt.record,
            KeyV1::new(lane, OwnerV1::Cache, 1)?, PhaseV1::new(OwnerV1::Cache, 1)?)?;
        let tree = retained(&self.tree)?;
        let body = AssignmentPlannedBodyDataV1 { association: source_body.association(),
            source_held: source_envelope.checksum(), cache_held: cache_envelope.checksum(),
            input_origin: Sha256::digest(origin_bytes).into(), tree_head: *tree.tree_head.as_bytes(),
            lineage_head: *tree.lineage_head.as_bytes(), manifest: manifest.canonical_bytes() };
        let length = body.encoded_bytes()?;
        if self.record_ceiling.is_none_or(|ceiling| length.checked_add(RECORD_OVERHEAD_BYTES).is_none_or(|record| record > ceiling)) {
            return Err(AssignmentPlannedErrorV1::Closed);
        }
        self.body.try_reserve_exact(length)?;
        self.body.resize(length, 0);
        self.encoding = Some(body.encode_into(&mut self.body));
        retained(&self.encoding)?;
        let binding = AssignmentAppendBindingV1 { lane, prior_record: &histories.intent.record,
            prior_head: histories.intent.head, body: &self.body, manifest,
            source: source_receipt, cache: cache_receipt };
        // Both borrowed receipts originate from the genuine still-live Source
        // and Cache owners, never from a caller-decoded receipt constructor.
        let original = intake.create_storage_j_data_v1()?.clock;
        self.pair_entered = true;
        self.pair.produce_once(parent, intake, controller, source.journal(), profile,
            HistoryRoleV1::Controller, lane, source_body.seed, original, accepted.original_cutoff,
            Some((before.next, before.end)), &self.body, Some(HistorySuccessorBindingV1::Assignment(&binding)))?;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn planned_manifest_v1(
        &self,
    ) -> Result<&CanonicalAssignmentManifestV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.manifest.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool { self.q04.is_some() || self.primary.is_some() }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.q04).or_else(|| cause(&self.origin_shape)).or_else(|| cause(&self.funding)).or_else(|| self.pair.primary_failure())
            .or_else(|| cause(&self.node)).or_else(|| cause(&self.incarnation))
            .or_else(|| cause(&self.origin))
            .or_else(|| cause(&self.tree)).or_else(|| cause(&self.publication))
            .or_else(|| cause(&self.authority)).or_else(|| cause(&self.manifest))
            .or_else(|| cause(&self.encoding))
            .or_else(|| (!self.pair_entered).then(|| cause(&self.primary)).flatten())
            .or_else(|| self.pair.post_failure()).or_else(|| cause(&self.primary))
    }
}

// Constructed only inside the original producer while the typed pre-Root Cache
// borrow is live. Its receipt lifetime also keeps that actual Cache borrowed.
pub(super) struct AssignmentAppendBindingV1<'held> {
    lane: [u8; 16],
    prior_record: &'held [u8],
    prior_head: [u8; HEAD_BYTES],
    body: &'held [u8],
    manifest: &'held CanonicalAssignmentManifestV1,
    source: SourceHeldReceiptDataV1<'held>,
    cache: CacheHeldReceiptDataV1<'held>,
}

impl AssignmentAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        Ok(RecordEnvelopeV1::decode(self.prior_record, KeyV1::new(self.lane, OwnerV1::Controller, 1)?,
            PhaseV1::new(OwnerV1::Controller, 1)?)?.checksum())
    }

    pub(super) fn require_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        journal.ensure_healthy()?;
        self.require_state_successor(parent, intake, state, transaction)
    }

    pub(super) fn require_state_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        let closed = || JournalError::ProtectedBoundary;
        parent.require_create_continuation_state(state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let intent_key = KeyV1::new(self.lane, OwnerV1::Controller, 1).map_err(|_| closed())?;
        let head_key = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        let mut count = 0;
        for ((namespace, key), value) in state {
            if *namespace != crate::RecordNamespace::CreateStorageHistory { continue; }
            count += 1;
            if !((key.as_slice() == intent_key.encode() && value == self.prior_record)
                || (key.as_slice() == head_key.encode() && value.as_slice() == self.prior_head)) {
                return Err(closed());
            }
        }
        if count != 2 { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 2).map_err(|_| closed())?;
        let phase = PhaseV1::new(OwnerV1::Controller, 12).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != head_key.encode() {
            return Err(closed());
        }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key, phase).map_err(|_| closed())?;
        let body = AssignmentPlannedBodyDataV1::decode(envelope.body()).map_err(|_| closed())?;
        let accepted = parent.create_storage_original_identity_v1().map_err(native_error)?;
        let source_body = self.source.body(self.lane).map_err(|_| closed())?;
        self.cache.compare_source(self.lane, self.source).map_err(|_| closed())?;
        let cache_record = RecordEnvelopeV1::decode(self.cache.record,
            KeyV1::new(self.lane, OwnerV1::Cache, 1).map_err(|_| closed())?,
            PhaseV1::new(OwnerV1::Cache, 1).map_err(|_| closed())?).map_err(|_| closed())?;
        if envelope.body() != self.body || body.manifest != self.manifest.canonical_bytes()
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || envelope.coordinates().correlation != source_body.seed
            || body.association != source_body.association() || body.cache_held != cache_record.checksum()
            || self.manifest.manifest().sandbox().into_bytes() != accepted.sandbox
            || self.manifest.manifest().project().into_bytes() != accepted.project {
            return Err(closed());
        }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, head_key)
            .and_then(|latest| latest.check_record(head_key, envelope)).map_err(|_| closed())
    }
}

fn model(error: impl StdError + Send + Sync + 'static) -> AssignmentPlannedErrorV1 {
    AssignmentPlannedErrorV1::Model(Box::new(error))
}

// The closed first-assignment recipe has zero ancestry edges, generation one,
// at most ten source descriptors from the already-validated AOSPCO03 Policy,
// four top-level descriptors and Core's existing 64-feature maximum. Media and
// feature namespaces are each syntactically bounded to 255 bytes. These are
// CBOR upper widths from the SAME existing Core encoder, not a new wire cap.
fn first_assignment_record_bound_v1() -> usize {
    let descriptor = 1 + (2 + 255) + 1 + (2 + 32) + 9;
    let feature = 1 + (2 + 255) + 5 + 5;
    let canonical = 1 + 1 + 4 * (1 + 16) + 1 + 3
        + 14 * descriptor + 1 + (2 + 32)
        + 1 + aos_sandbox_model::ResourceDimension::COUNT * 9
        + 2 + aos_sandbox_model::model::MAX_ASSIGNMENT_REQUIRED_FEATURES * feature;
    aos_sandbox_protocol::domain_ledger::create_storage_history::assignment_planned::ASSIGNMENT_PLANNED_FIXED_BYTES_V1
        + RECORD_OVERHEAD_BYTES + canonical
}

fn policy_model_demand(bytes: usize) -> Result<ResourceVector, ResourceReservationErrorV1> {
    // Canonical CBOR is completely checked before typed Vec reservation. Every
    // advertised child therefore consumes a real canonical item, even when the
    // typed child later rejects its shape. A one-byte item is a conservative
    // lower bound here; this is carrier pricing, never a whole Policy per byte.
    let width = std::mem::size_of::<aos_sandbox_model::Grant>()
        .max(std::mem::size_of::<aos_sandbox_model::Selector>())
        .max(std::mem::size_of::<FeatureRef>())
        .max(std::mem::size_of::<ObjectDescriptor>())
        .max(std::mem::size_of::<aos_sandbox_model::model::PolicyViewAction>())
        .max(std::mem::size_of::<aos_sandbox_model::model::ExplanationReason>())
        .max(std::mem::size_of::<aos_sandbox_model::model::Limit>());
    // Keep the actual model already checked by the origin validator. Four
    // carrier lanes conservatively cover that one decode, validation/set clones
    // and the live manifest's selected feature/descriptor collections.
    let cells = bytes.checked_add(8).and_then(|n| n.checked_mul(4))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let memory = cells.checked_mul(width).and_then(|n| n.checked_add(bytes.checked_mul(32)?))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| ResourceReservationErrorV1::Conflict)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entered_model_allocation_cause_precedes_independent_native_post_failure() {
        let mut original = AssignmentPlannedOriginalV1::default();
        let actual = Vec::<u8>::new().try_reserve_exact(usize::MAX).unwrap_err();
        original.primary = Some(Err(AssignmentPlannedErrorV1::Allocation(actual)));
        original.pair.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(2))));

        let error = original.failure().unwrap().downcast_ref::<AssignmentPlannedErrorV1>().unwrap();
        assert!(matches!(error, AssignmentPlannedErrorV1::Allocation(_)));
        let first = error as *const AssignmentPlannedErrorV1;
        assert!(original.pair.post_failure().is_some());
        assert_eq!(first, original.failure().unwrap().downcast_ref::<AssignmentPlannedErrorV1>().unwrap()
            as *const AssignmentPlannedErrorV1);
    }
}

impl AssignmentPlannedOriginalV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn bundle_head_v1(&self)
        -> Result<[u8; HEAD_BYTES], ResourceReservationErrorV1>
    {
        self.planned_manifest_v1()?;
        Ok(self.pair.head)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn bundle_record_v1(&self)
        -> Result<&[u8], ResourceReservationErrorV1>
    {
        self.planned_manifest_v1()?;
        Ok(&self.pair.record)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn bundle_origin_v1(
        &self
    ) -> Result<
        (
            &RetainedPublisherCompilerOriginV3,
            &aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1
        ),
        ResourceReservationErrorV1
    > {
        self.planned_manifest_v1()?;
        self.origin.as_ref().and_then(|result| result.as_ref().ok())
            .map(|(origin, policy)| (origin, policy))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}
