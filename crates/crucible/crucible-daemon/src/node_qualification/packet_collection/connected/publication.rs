//! Durably places original connected plan/audit/report roots before source ACK.
//!
//! The storage helper retains uncertain original writes and reconciles only the
//! same immutable closure. Neither a parsed report nor a reopened root supplies
//! native authority; actual original runtime and source journal bindings remain
//! mandatory before every backend action.

use super::super::result_publication::{placement::PreparedPacketPlacement, serialize_content_ids};
use super::{InstalledPacketConnectedCollectionAuthority, PacketConnectedCaseKind};
use crate::node_qualification::CaseVerdict;
use crucible_engine::{
    node_admission::{
        AdmissionRequest, ConformanceAdmissionAuthority, ConformancePlanEvidence,
        InstalledConformancePlan, ScenarioRequirements,
    },
    node_contract::{
        ConformanceResultPublisher, NodeRoute, OperationOutcome, OperationRequest,
        OriginalCompletedOperation, PublicationStatus, RuntimeError,
    },
};
use crucible_node_format::{ContentRef, Id, NodeBinding, NodeDescriptor, OwnerBinding, canonical};
use crucible_store::content_store::{
    ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use serde::Serialize;
use std::{collections::BTreeSet, rc::Rc, sync::Arc};

/// Supplies all original write-once result placements before native birth.
pub struct PacketConnectedPublicationRequest {
    /// Retains the same concrete whole-scene source authority and native oracle.
    pub authority: Rc<InstalledPacketConnectedCollectionAuthority>,
    /// Retains the same opaque original plan used by the collecting runtime.
    pub plan: Rc<InstalledConformancePlan>,
    /// Owns the complete native-three/host-one requirements.
    pub requirements: ScenarioRequirements,
    /// Retains the real immutable durable store across audit and cleanup.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains the actual durable write-once placement namespace.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Owns one distinct original reference per predeclared exact grant.
    pub references: Vec<RefName>,
    /// Bounds each complete root/report/handle/readback construction peak.
    pub maximum_each_bytes: usize,
    /// Bounds the sum of all original future placement ceilings.
    pub maximum_total_bytes: usize,
}

struct Placement {
    node: Id,
    operation: Id,
    before: String,
    reference: RefName,
    prepared: Option<PreparedPacketPlacement>,
    attempted: bool,
}

/// Retains bounded original connected publications under genuine source custody.
///
/// Durable result roots are collecting-purpose evidence. They do not preserve,
/// restore, qualify or transfer a native world or accepted class.
pub struct StoredPacketConnectedResultPublisher {
    authority: Rc<InstalledPacketConnectedCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    maximum_each_bytes: usize,
    placements: Vec<Placement>,
}

impl StoredPacketConnectedResultPublisher {
    /// Reserves every complete original placement before any native effect.
    ///
    /// # Errors
    /// Refuses a changed full plan/scenario, duplicate or missing slots, absent
    /// original before-ACK cases or unavailable finite body/pointer credit.
    pub fn new(request: PacketConnectedPublicationRequest) -> Result<Self, RuntimeError> {
        let schedule = request.authority.schedule();
        if request.maximum_each_bytes == 0
            || request.maximum_each_bytes > 64 * 1024 * 1024
            || request.maximum_total_bytes == 0
            || request.maximum_total_bytes > 512 * 1024 * 1024
            || schedule.grants.len() != request.references.len()
            || request.references.is_empty()
            || request.references.len() > 64
            || request
                .maximum_each_bytes
                .checked_mul(request.references.len())
                .is_none_or(|bytes| bytes > request.maximum_total_bytes)
            || request.references.iter().collect::<BTreeSet<_>>().len() != request.references.len()
            || request.references.iter().any(|reference| {
                !reference
                    .as_str()
                    .starts_with("node-packet-collecting-results/connected/")
            })
            || request
                .plan
                .authenticate_authority(request.authority.as_ref())
                .is_err()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        request
            .authority
            .current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let selected = [
            request.authority.participant(0),
            request.authority.participant(1),
            request.authority.participant(2),
        ];
        let [source0, source1, source2] = selected;
        let selected = [
            source0
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .installation(),
            source1
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .installation(),
            source2
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .installation(),
        ];
        let host = request.authority.host_source().selection();
        super::super::scope::encoded_size(
            &(
                (
                    &selected[0].descriptor,
                    &selected[0].binding,
                    &selected[0].owner,
                ),
                (
                    &selected[1].descriptor,
                    &selected[1].binding,
                    &selected[1].owner,
                ),
                (
                    &selected[2].descriptor,
                    &selected[2].binding,
                    &selected[2].owner,
                ),
                host,
                &request.requirements,
                schedule,
                request
                    .references
                    .iter()
                    .map(RefName::as_str)
                    .collect::<Vec<_>>(),
            ),
            request.maximum_total_bytes,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut descriptors = Vec::new();
        let mut bindings = Vec::new();
        let mut owners = Vec::new();
        let mut placements = Vec::new();
        descriptors
            .try_reserve_exact(4)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        bindings
            .try_reserve_exact(4)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        owners
            .try_reserve_exact(4)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        placements
            .try_reserve_exact(schedule.grants.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for selected in selected {
            descriptors.push(selected.descriptor.clone());
            bindings.push(selected.binding.clone());
            owners.push(selected.owner.clone());
        }
        descriptors.push(host.descriptor.clone());
        bindings.push(host.binding.clone());
        owners.push(host.owner.clone());
        request
            .authority
            .authenticate_collection_world(
                request.plan.evidence(),
                AdmissionRequest {
                    world: request.authority.world(),
                    descriptors: &descriptors,
                    bindings: &bindings,
                    owners: &owners,
                    requirements: &request.requirements,
                },
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        for (grant, reference) in schedule.grants.iter().zip(request.references) {
            let mut cases = schedule.cases.iter().filter(|case| {
                case.node == grant.node
                    && case.operation.as_ref() == Some(&grant.operation)
                    && case.kind == PacketConnectedCaseKind::BeforeRetirement
            });
            let before = cases.next().ok_or(RuntimeError::ForeignAuthority)?;
            if cases.next().is_some() {
                return Err(RuntimeError::ForeignAuthority);
            }
            placements.push(Placement {
                node: grant.node.clone(),
                operation: grant.operation.clone(),
                before: before.id.clone(),
                reference,
                prepared: None,
                attempted: false,
            });
        }
        Ok(Self {
            authority: request.authority,
            plan: request.plan,
            requirements: request.requirements,
            descriptors,
            bindings,
            owners,
            blobs: request.blobs,
            refs: request.refs,
            maximum_each_bytes: request.maximum_each_bytes,
            placements,
        })
    }

    fn current(&self) -> Result<(), RuntimeError> {
        self.plan
            .reauthenticate()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.authority
            .authenticate_collection_current_scope(
                self.plan.evidence(),
                AdmissionRequest {
                    world: self.authority.world(),
                    descriptors: &self.descriptors,
                    bindings: &self.bindings,
                    owners: &self.owners,
                    requirements: &self.requirements,
                },
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.authority
            .host_source()
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.authority
            .roster()
            .current_native()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.authority
            .host_source()
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn index(&self, original: &OriginalCompletedOperation<'_>) -> Result<usize, RuntimeError> {
        let token = original.admission().token();
        self.placements
            .iter()
            .position(|slot| {
                slot.node == token.route().node && &slot.operation == token.operation()
            })
            .ok_or(RuntimeError::ForeignAuthority)
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
        let expected = self
            .authority
            .expected_completion(&slot.before)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if expected.acknowledged
            || original.acknowledged()
            || &expected.request != original.admission().request()
            || &expected.outcome != original.outcome()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authority
            .with_original_report(&slot.before, |reference, bytes, verdict| {
                if verdict != Some(CaseVerdict::Passed) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                reference
                    .verify(bytes)
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
                self.authority
                    .oracle()
                    .authenticate_original_result(&slot.before, original, reference)
                    .map_err(|_| RuntimeError::ForeignAuthority)
            })?;
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
        self.authority
            .with_original_report(&slot.before, |report_ref, report_bytes, verdict| {
                if verdict != Some(CaseVerdict::Passed) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let plan = self.plan.evidence();
                let objects = [
                    ContentId::for_bytes(ObjectKind::Trace, 1, plan.plan_bytes),
                    ContentId::for_bytes(ObjectKind::Trace, 1, plan.refused_bytes),
                    ContentId::for_bytes(ObjectKind::Trace, 1, report_bytes),
                ];
                let root = ResultRoot {
                    format: "crucible.packet-connected-collecting-result",
                    version: 4,
                    purpose: "conformance-collection",
                    plan: plan.plan_ref,
                    refused_audit: plan.refused_ref,
                    original_report: report_ref,
                    case: &slot.before,
                    objects: &objects,
                    activation: super::super::scope::activation_view(
                        original.admission().activation().record(),
                    ),
                    route: original.admission().token().route(),
                    request: original.admission().request(),
                    outcome: original.outcome(),
                };
                let raw = plan
                    .plan_bytes
                    .len()
                    .checked_add(plan.refused_bytes.len())
                    .and_then(|bytes| bytes.checked_add(report_bytes.len()))
                    .and_then(|bytes| bytes.checked_mul(4))
                    .ok_or(RuntimeError::ResourceLimit)?;
                let root_bytes = super::super::scope::encoded_size(&root, self.maximum_each_bytes)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                if root_bytes
                    .checked_mul(6)
                    .and_then(|bytes| raw.checked_add(bytes))
                    .is_none_or(|bytes| bytes > self.maximum_each_bytes)
                {
                    return Err(RuntimeError::ResourceLimit);
                }
                let root_bytes = canonical::canonical_json(
                    &serde_json::to_value(&root).map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
                PreparedPacketPlacement::prepare(
                    self.blobs.clone(),
                    self.refs.clone(),
                    slot.reference.clone(),
                    [
                        plan.plan_bytes.to_vec(),
                        plan.refused_bytes.to_vec(),
                        report_bytes.to_vec(),
                        root_bytes,
                    ],
                    self.maximum_each_bytes,
                )
            })
    }
}

impl ConformanceResultPublisher for StoredPacketConnectedResultPublisher {
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
        let index = self.index(original)?;
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
struct ResultRoot<'a> {
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
