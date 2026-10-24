//! Stores genuine Complete four-owner completions before scheduling/native ACK.
//!
//! Thirteen predeclared write-once slots retain real exact-input reports and the
//! complete plan/audit/report/root closure. Lost Put or CAS replies reconcile
//! those same immutable bodies; durable bytes never replace live native proof.
//!
//! The root stores full references and original outcome fields:
//!
//! ```text
//! {"format":"crucible.packet-complete-collecting-result","version":1,
//!  "purpose":"conformance-collection","plan":<ContentRef>,
//!  "refused_audit":<ContentRef>,"original_report":<ContentRef>,
//!  "case":<original case>,"objects":[<three CAS identities>],
//!  "activation":<ActivationView>,"route":<NodeRoute>,
//!  "request":<OperationRequest>,"outcome":<OperationOutcome>}
//! ```

use crucible_engine::node_admission::{ConformancePlanEvidence, InstalledConformancePlan};
use crucible_engine::node_contract::{
    ConformanceResultPublisher, NodeRoute, OperationOutcome, OperationRequest, OperationToken,
    OriginalCompletedOperation, OriginalRuntimeWitness, PublicationStatus, RuntimeError,
};
use crucible_node_format::{ContentRef, Id, canonical};
use crucible_store::content_store::{
    ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use serde::Serialize;
use std::{mem::size_of, rc::Rc, sync::Arc};

use super::super::connected::PacketConnectedCaseKind;
use super::super::result_publication::{placement::PreparedPacketPlacement, serialize_content_ids};
use super::execution::schedule;
use super::{InstalledPacketCompleteCollectionAuthority, PacketCompleteExecutionScene};
use crate::node_qualification::production_conformance::publication::OriginalExactPublicationReport;

const SLOTS: usize = 13;
const MAXIMUM_EACH: usize = 64 * 1024 * 1024;
const MAXIMUM_TOTAL: usize = 512 * 1024 * 1024;

/// Binds durable Complete result storage to the actual pre-Child execution scene.
pub struct PacketCompletePublicationRequest {
    /// Retains the original Complete four-owner authority, never a World2 substitute.
    pub authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    /// Retains the same opaque collecting plan as the execution actor.
    pub plan: Rc<InstalledConformancePlan>,
    /// Retains the genuine source/oracle scene installed before native launch.
    pub scene: Rc<PacketCompleteExecutionScene>,
    /// Retains independently managed durable immutable storage through cleanup.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains durable write-once root storage through deliberate report release.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Names thirteen distinct result slots in the fixed original grant order.
    pub references: [RefName; 13],
    /// Bounds each complete report/serialization/placement request to 64 MiB.
    pub maximum_each_bytes: usize,
    /// Bounds the aggregate independent placement reservations to 512 MiB.
    pub maximum_total_bytes: usize,
}

struct Placement {
    operation: Id,
    node: Id,
    case: String,
    reference: RefName,
    report: OriginalExactPublicationReport,
    prepared: Option<PreparedPacketPlacement>,
    attempted: bool,
}

/// Publishes actual Complete results durably before their original consumed ACK.
///
/// Construction reserves independent finite storage without backend effects.
/// The original scene and its native oracle remain authoritative at every read
/// and write boundary. The caller retains this publisher and its namespace
/// through failures and original native reclamation; daemon GC is separate.
#[must_use = "retain complete result bodies and durable namespace through native cleanup"]
pub struct StoredPacketCompleteResultPublisher {
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    scene: Rc<PacketCompleteExecutionScene>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    maximum_each: usize,
    placements: Vec<Placement>,
}

impl StoredPacketCompleteResultPublisher {
    // The concrete holder conjoins this before preparing its actor. This view
    // quote grants no storage/backend permission and never calls a serializer.
    pub(crate) fn counter_scratch_data() -> Result<usize, RuntimeError> {
        use std::mem::size_of_val;
        let terms = [
            OriginalExactPublicationReport::counter_scratch_data()?,
            size_of::<Self>(),
            size_of::<PacketCompletePublicationRequest>(),
            size_of::<Result<Self, RuntimeError>>(),
            size_of::<&mut Self>(),
            size_of::<Placement>(),
            size_of::<Vec<Placement>>(),
            size_of::<PreparedPacketPlacement>(),
            size_of::<Option<PreparedPacketPlacement>>(),
            size_of::<Result<PreparedPacketPlacement, RuntimeError>>(),
            size_of::<CompleteResultRoot<'static>>(),
            size_of::<[ContentId; 3]>(),
            size_of::<[Vec<u8>; 4]>(),
            size_of::<[RefName; SLOTS]>(),
            size_of::<std::array::IntoIter<RefName, SLOTS>>(),
            size_of::<std::slice::Iter<'static, Placement>>(),
            size_of::<ConformancePlanEvidence<'static>>(),
            size_of::<OriginalCompletedOperation<'static>>(),
            size_of::<&OriginalCompletedOperation<'static>>(),
            size_of::<OriginalRuntimeWitness<'static>>(),
            size_of::<Result<OriginalRuntimeWitness<'static>, RuntimeError>>(),
            size_of::<Result<PublicationStatus, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<super::retained::Counter>(),
            InstalledConformancePlan::original_runtime_constructor_data_counter_scratch_data(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Reserves the fixed original publication slots before execution.
    ///
    /// # Errors
    /// Refuses a foreign scene/plan/oracle, missing unique before-retirement
    /// cases, duplicate reference names or complete requested-storage excess.
    pub fn new(request: PacketCompletePublicationRequest) -> Result<Self, RuntimeError> {
        request
            .scene
            .authenticate_publication_owner(&request.authority, &request.plan)?;
        let future = request
            .maximum_each_bytes
            .checked_mul(SLOTS)
            .ok_or(RuntimeError::ResourceLimit)?;
        if request.maximum_each_bytes == 0
            || request.maximum_each_bytes > MAXIMUM_EACH
            || request.maximum_total_bytes == 0
            || request.maximum_total_bytes > MAXIMUM_TOTAL
            || future > request.maximum_total_bytes
            || request.references.iter().enumerate().any(|(index, name)| {
                !name.as_str().starts_with("node-packet-collecting-results/")
                    || request.references[..index].contains(name)
            })
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let oracle = request.scene.publication_oracle();
        let selected = oracle.execution_schedule();
        schedule::authenticate(oracle, request.authority.world())
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mut counter = super::retained::Counter::new(request.maximum_total_bytes);
        counter
            .add(Self::counter_scratch_data()?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(future)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(size_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                SLOTS
                    .checked_mul(size_of::<Placement>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for (index, reference) in request.references.iter().enumerate() {
            let grant = &selected.grants[index];
            let mut cases = selected.cases.iter().filter(|case| {
                case.node == grant.node
                    && case.operation.as_ref() == Some(&grant.operation)
                    && case.kind == PacketConnectedCaseKind::BeforeRetirement
            });
            let case = cases.next().ok_or(RuntimeError::ForeignAuthority)?;
            if cases.next().is_some() {
                return Err(RuntimeError::ForeignAuthority);
            }
            counter
                .charge(&grant.operation)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&grant.node)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&case.id)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .add(reference.retained_requested_storage_data())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        let mut placements = Vec::new();
        placements
            .try_reserve_exact(SLOTS)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for (index, reference) in request.references.into_iter().enumerate() {
            let grant = &selected.grants[index];
            let case = selected
                .cases
                .iter()
                .find(|case| {
                    case.node == grant.node
                        && case.operation.as_ref() == Some(&grant.operation)
                        && case.kind == PacketConnectedCaseKind::BeforeRetirement
                })
                .ok_or(RuntimeError::ForeignAuthority)?;
            placements.push(Placement {
                operation: grant.operation.clone(),
                node: grant.node.clone(),
                case: case.id.clone(),
                reference,
                report: OriginalExactPublicationReport::new(),
                prepared: None,
                attempted: false,
            });
        }
        request
            .scene
            .authenticate_publication_owner(&request.authority, &request.plan)?;
        Ok(Self {
            authority: request.authority,
            plan: request.plan,
            scene: request.scene,
            blobs: request.blobs,
            refs: request.refs,
            maximum_each: request.maximum_each_bytes,
            placements,
        })
    }

    pub(super) fn collect_original(
        &mut self,
        runtime: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        let index = self
            .placements
            .iter()
            .position(|slot| {
                &slot.operation == token.operation() && slot.node == token.route().node
            })
            .ok_or(RuntimeError::ForeignAuthority)?;
        let oracle = self.scene.publication_oracle();
        let case = oracle
            .expected_completion(&self.placements[index].case)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let plan = self.authority.witness_plan();
        self.placements[index]
            .report
            .collect(runtime, token, &case, self.maximum_each, |witness| {
                oracle.authenticate_original_runtime(plan, &case.case, &case.oracle, witness)
            })
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.current()
    }

    fn current(&self) -> Result<(), RuntimeError> {
        self.scene
            .authenticate_publication_owner(&self.authority, &self.plan)?;
        self.scene
            .live()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn authenticate(
        &self,
        index: usize,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        let slot = self
            .placements
            .get(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if original.acknowledged()
            || &slot.operation != original.admission().token().operation()
            || slot.node != original.admission().token().route().node
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (reference, bytes) = slot
            .report
            .original()
            .ok_or(RuntimeError::ForeignAuthority)?;
        reference
            .verify(bytes)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.scene
            .publication_oracle()
            .authenticate_original_result(&slot.case, original, reference)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.current()
    }

    fn prepare(
        &self,
        index: usize,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<PreparedPacketPlacement, RuntimeError> {
        self.authenticate(index, original)?;
        let slot = self
            .placements
            .get(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let (report_ref, report_bytes) = slot
            .report
            .original()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let plan = self.plan.evidence();
        let objects = [
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.plan_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.refused_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, report_bytes),
        ];
        let root = CompleteResultRoot {
            format: "crucible.packet-complete-collecting-result",
            version: 1,
            purpose: "conformance-collection",
            plan: plan.plan_ref,
            refused_audit: plan.refused_ref,
            original_report: report_ref,
            case: &slot.case,
            objects: &objects,
            activation: super::super::scope::activation_view(
                original.admission().activation().record(),
            ),
            route: original.admission().token().route(),
            request: original.admission().request(),
            outcome: original.outcome(),
        };
        let report_storage = slot
            .report
            .requested_storage(self.maximum_each)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let serialization =
            InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                &root,
                self.maximum_each,
            )?;
        let raw = plan
            .plan_bytes
            .len()
            .checked_add(plan.refused_bytes.len())
            .and_then(|bytes| bytes.checked_add(report_bytes.len()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let root_length = super::super::scope::encoded_size(&root, self.maximum_each)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // Four body owners can coexist in the defining placement implementation:
        // retained originals, prepared handles, backend return handles, readback.
        raw.checked_add(root_length)
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(serialization))
            .and_then(|bytes| bytes.checked_add(report_storage))
            .filter(|bytes| *bytes <= self.maximum_each)
            .ok_or(RuntimeError::ResourceLimit)?;
        let root_bytes = canonical::canonical_json(
            &serde_json::to_value(&root).map_err(|_| RuntimeError::ResourceLimit)?,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        PreparedPacketPlacement::prepare(
            Arc::clone(&self.blobs),
            Arc::clone(&self.refs),
            slot.reference.clone(),
            [
                plan.plan_bytes.to_vec(),
                plan.refused_bytes.to_vec(),
                report_bytes.to_vec(),
                root_bytes,
            ],
            self.maximum_each,
        )
    }
}

impl ConformanceResultPublisher for StoredPacketCompleteResultPublisher {
    fn publish_original(
        &mut self,
        plan: ConformancePlanEvidence<'_>,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        let retained = self.plan.evidence();
        if plan.plan_ref != retained.plan_ref
            || plan.plan_bytes != retained.plan_bytes
            || plan.refused_ref != retained.refused_ref
            || plan.refused_bytes != retained.refused_bytes
            || plan.world != retained.world
            || plan.sources != retained.sources
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let index = self
            .placements
            .iter()
            .position(|slot| {
                &slot.operation == original.admission().token().operation()
                    && slot.node == original.admission().token().route().node
            })
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate(index, original)?;
        if self.placements[index].prepared.is_none() {
            self.placements[index].prepared = Some(self.prepare(index, original)?);
        }
        let prepared = self.placements[index]
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?;
        if self.placements[index].attempted {
            let status = prepared.reconcile(|| self.current())?;
            if status != PublicationStatus::NotCommitted {
                return Ok(status);
            }
        }
        self.placements[index].attempted = true;
        self.placements[index]
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?
            .publish(|| self.current())
    }
}

#[derive(Serialize)]
struct CompleteResultRoot<'a> {
    format: &'static str,
    version: u16,
    purpose: &'static str,
    plan: &'a ContentRef,
    refused_audit: &'a ContentRef,
    original_report: &'a ContentRef,
    case: &'a str,
    #[serde(serialize_with = "serialize_content_ids")]
    objects: &'a [ContentId; 3],
    activation: super::super::scope::ActivationView<'a>,
    route: &'a NodeRoute,
    request: &'a OperationRequest,
    outcome: &'a OperationOutcome,
}
