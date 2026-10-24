//! Stores all 27 whole-world original packet result roots before consumed ACK.
//!
//! Each source-fixed grant has one preallocated write-once reference and one
//! original prepared closure. The same immutable plan/audit/report/root bodies
//! survive uncertain Put/CAS replies and publication callbacks. Reconciliation
//! cannot replace a token, submit Begin, enroll a report or qualify a class.

use std::{collections::BTreeSet, rc::Rc, sync::Arc};

use crucible_engine::{
    node_adapters::cnp::CnpSemanticSource,
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

use super::{
    InstalledPacketWorldCollectionAuthority,
    result_publication::{placement::PreparedPacketPlacement, serialize_content_ids},
};
use crate::node_qualification::CaseVerdict;

/// Supplies complete durable result placement configuration before Child.
pub struct PacketWorldPublicationRequest {
    /// Retains the SAME installed whole-world source authority and native oracles.
    pub authority: Rc<InstalledPacketWorldCollectionAuthority>,
    /// Retains the SAME opaque complete Refused plan used by the original actor.
    pub plan: Rc<InstalledConformancePlan>,
    /// Owns complete source-authenticated scenario demands for the full world.
    pub requirements: ScenarioRequirements,
    /// Retains the independent durable immutable store through audit and cleanup.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains the independent durable write-once reference backend.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Names 27 distinct original write-once slots in window/member order.
    pub references: [RefName; 27],
    /// Bounds each complete visible four-body/root construction peak to 64 MiB.
    pub maximum_each_bytes: usize,
    /// Bounds the sum of all original placement ceilings to 512 MiB.
    pub maximum_total_bytes: usize,
}

struct OriginalPlacement {
    operation: Id,
    node: Id,
    before: String,
    reference: RefName,
    prepared: Option<PreparedPacketPlacement>,
    attempted: bool,
}

/// Owns all original full-world result placements beneath the same native custody.
///
/// The independently retained store namespace is a fixture lifetime obligation;
/// ordinary daemon GC and restore are separate. Reopened bytes confer no native,
/// accepted-class or original runtime authority. Every call requires the current
/// exact plan/world/native roster and an opaque source-verified original token.
pub struct StoredPacketWorldResultPublisher {
    authority: Rc<InstalledPacketWorldCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    maximum_each_bytes: usize,
    originals: Vec<OriginalPlacement>,
}

impl StoredPacketWorldResultPublisher {
    /// Reserves all exact original result placements without backend/native effects.
    ///
    /// # Errors
    /// Refuses a foreign plan/scenario, duplicate placement names, missing original
    /// source grants, exhausted complete-roster/body credit or unavailable finite
    /// allocation. No report or readiness is authenticated by construction.
    pub fn new(request: PacketWorldPublicationRequest) -> Result<Self, RuntimeError> {
        if request.maximum_each_bytes == 0
            || request.maximum_each_bytes > 64 * 1024 * 1024
            || request.maximum_total_bytes == 0
            || request.maximum_total_bytes > 512 * 1024 * 1024
            || request
                .maximum_each_bytes
                .checked_mul(27)
                .is_none_or(|extent| extent > request.maximum_total_bytes)
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
        super::scope::encoded_size(
            &(
                &request.requirements,
                request.references.each_ref().map(RefName::as_str),
            ),
            request.maximum_total_bytes,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let scenario = super::scope::encoded_program(&request.requirements)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        request
            .authority
            .world()
            .scenario_ref
            .verify(&scenario)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if request
            .references
            .iter()
            .any(|name| !name.as_str().starts_with("node-packet-collecting-results/"))
            || request.references.iter().collect::<BTreeSet<_>>().len() != 27
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let selections = [
            request.authority.source(0),
            request.authority.source(1),
            request.authority.source(2),
        ];
        let [source0, source1, source2] = selections;
        let selected =
            [source0, source1, source2].map(|source| source.map(|source| source.installation()));
        let [selected0, selected1, selected2] = selected;
        let selected = [
            selected0.map_err(|_| RuntimeError::ForeignAuthority)?,
            selected1.map_err(|_| RuntimeError::ForeignAuthority)?,
            selected2.map_err(|_| RuntimeError::ForeignAuthority)?,
        ];
        super::scope::encoded_size(
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
            ),
            request.maximum_total_bytes,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        // Count every later grant/case clone before constructing the original
        // placement roster. The same grants were independently source-sealed
        // during pre-Child population installation.
        super::scope::encoded_size(&request.authority.grants(), request.maximum_total_bytes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut descriptors = Vec::new();
        let mut bindings = Vec::new();
        let mut owners = Vec::new();
        let mut originals = Vec::new();
        descriptors
            .try_reserve_exact(3)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        bindings
            .try_reserve_exact(3)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        owners
            .try_reserve_exact(3)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        originals
            .try_reserve_exact(27)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for selected in selected {
            descriptors.push(selected.descriptor.clone());
            bindings.push(selected.binding.clone());
            owners.push(selected.owner.clone());
        }
        for (index, reference) in request.references.into_iter().enumerate() {
            let grant = request
                .authority
                .grant(index)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            request
                .authority
                .oracle(index % 3)
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .template_oracle(&grant.before)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            originals.push(OriginalPlacement {
                operation: grant.operation.clone(),
                node: descriptors[index % 3].id.clone(),
                before: grant.before.clone(),
                reference,
                prepared: None,
                attempted: false,
            });
        }
        request
            .plan
            .reauthenticate()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        request
            .authority
            .current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
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
            originals,
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
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn index(&self, original: &OriginalCompletedOperation<'_>) -> Result<usize, RuntimeError> {
        let token = original.admission().token();
        self.originals
            .iter()
            .position(|slot| {
                &slot.operation == token.operation() && slot.node == token.route().node
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
            .originals
            .get(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let oracle = self
            .authority
            .oracle(index % 3)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let expected = oracle
            .expected_completion(&slot.before)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if expected.acknowledged
            || original.acknowledged()
            || &expected.request != original.admission().request()
            || &expected.outcome != original.outcome()
            || original.admission().inputs().is_some()
            || original.staged_inputs()?.is_some()
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
                oracle
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
            .originals
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
                let root = WorldResultRoot {
                    format: "crucible.packet-collecting-result",
                    version: 2,
                    purpose: "conformance-collection",
                    plan: plan.plan_ref,
                    refused_audit: plan.refused_ref,
                    original_report: report_ref,
                    case: &slot.before,
                    objects: &objects,
                    activation: super::scope::activation_view(
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
                let root_bytes = super::scope::encoded_size(&root, self.maximum_each_bytes)
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

impl ConformanceResultPublisher for StoredPacketWorldResultPublisher {
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
        if self.originals[index].prepared.is_none() {
            let prepared = self.prepare(index, original)?;
            self.originals[index].prepared = Some(prepared);
        }
        let prepared = self.originals[index]
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?;
        if self.originals[index].attempted {
            let status = prepared.reconcile(|| self.current())?;
            if status != PublicationStatus::NotCommitted {
                return Ok(status);
            }
        }
        // Install the original effect frontier before storage. Err/unwind keeps
        // the same complete prepared bodies, reference and attempt in this slot.
        self.originals[index].attempted = true;
        self.originals[index]
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?
            .publish(|| self.current())
    }
}

#[derive(Serialize)]
struct WorldResultRoot<'a> {
    format: &'static str,
    version: u16,
    purpose: &'static str,
    plan: &'a ContentRef,
    refused_audit: &'a ContentRef,
    original_report: &'a ContentRef,
    case: &'a str,
    #[serde(serialize_with = "serialize_content_ids")]
    objects: &'a [ContentId; 3],
    activation: super::scope::ActivationView<'a>,
    route: &'a NodeRoute,
    request: &'a OperationRequest,
    outcome: &'a OperationOutcome,
}
