//! Stores a source-authenticated original packet result before consumed ACK.
//!
//! The plan, refused audit and runner-origin report are separate raw immutable
//! objects. One collecting-purpose root binds their complete closure and original
//! admission. Reopening bytes never supplies native, accepted-class or restore
//! authority; the actual original source and runtime witness remain mandatory.

use std::{rc::Rc, sync::Arc};

use crucible::node_adapters::cnp::CnpSemanticSource;
use crucible::node_admission::{
    AdmissionRequest, ConformanceAdmissionAuthority, ConformancePlanEvidence,
    InstalledConformancePlan, ScenarioRequirements,
};
use crucible::node_contract::{
    ConformanceResultPublisher, NodeRoute, OperationOutcome, OperationRequest,
    OriginalCompletedOperation, PublicationStatus, RuntimeError,
};
use crucible_cas::content_store::{
    ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use crucible_node_contract::{ContentRef, canonical};
use serde::Serialize;

use super::InstalledPacketCollectionAuthority;
use crate::node_qualification::CaseVerdict;

mod placement;

/// Owns one finite original packet publication and its actual durable backends.
///
/// This publisher is for an independently managed fixture store. Its write-once
/// ref and complete objects must remain retained by that store's owner; ordinary
/// daemon GC integration is separate. It cannot publish another native operation,
/// install a report, authenticate an accepted class or restore any world.
pub struct StoredPacketResultPublisher {
    authority: Rc<InstalledPacketCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    before_case: String,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    maximum_bytes: usize,
    prepared: Option<placement::PreparedPacketPlacement>,
    attempted: bool,
}

impl StoredPacketResultPublisher {
    /// Retains the same original collecting scope and one write-once result slot.
    ///
    /// Construction performs no placement, native effect or readiness callback.
    /// The source-specific host invocation must retain these exact stores and
    /// publishers through original owner cleanup and deliberate report retention.
    ///
    /// # Errors
    /// Refuses foreign plan/requirements, unknown template, changed original
    /// source or zero/greater-than64-MiB aggregate storage credit.
    // crucible-lint: allow rust-allow -- Original plan, source, template, complete requirements and both durable backends form one installation tuple.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Rc<InstalledPacketCollectionAuthority>,
        plan: InstalledConformancePlan,
        requirements: ScenarioRequirements,
        before_case: String,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        maximum_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        Self::with_shared_plan(
            authority,
            Rc::new(plan),
            requirements,
            before_case,
            blobs,
            refs,
            reference,
            maximum_bytes,
        )
    }

    /// Retains the same opaque plan shared by the original host executor.
    ///
    /// Sharing retains the original installed authority; it supplies no decoded
    /// constructor, replacement plan or ordinary qualification.
    ///
    /// # Errors
    /// Refuses the same original scope, credit and store conditions as `new`.
    // crucible-lint: allow rust-allow -- The same original source, shared opaque plan and complete placement tuple are retained together.
    #[allow(clippy::too_many_arguments)]
    pub fn with_shared_plan(
        authority: Rc<InstalledPacketCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        requirements: ScenarioRequirements,
        before_case: String,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        maximum_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        if maximum_bytes == 0
            || maximum_bytes > 64 * 1024 * 1024
            || plan.authenticate_authority(authority.as_ref()).is_err()
            || !reference
                .as_str()
                .starts_with("node-packet-collecting-results/")
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        super::scope::encoded_size(&(&requirements, &before_case), maximum_bytes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scenario = canonical::canonical_json(
            &serde_json::to_value(&requirements).map_err(|_| RuntimeError::ForeignAuthority)?,
        )
        .map_err(|_| RuntimeError::ForeignAuthority)?;
        authority
            .world
            .scenario_ref
            .verify(&scenario)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        authority
            .oracle
            .template_oracle(&before_case)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        authority
            .current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        plan.reauthenticate()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(Self {
            authority,
            plan,
            requirements,
            before_case,
            blobs,
            refs,
            reference,
            maximum_bytes,
            prepared: None,
            attempted: false,
        })
    }

    fn current(&self) -> Result<(), RuntimeError> {
        self.plan
            .reauthenticate()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.authority
            .current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let selection = self.authority.source.installation();
        // This final hook reads the installed complete scope directly; its
        // source implementation performs the original native-handle read last.
        self.authority
            .authenticate_collection_current_scope(
                self.plan.evidence(),
                AdmissionRequest {
                    world: &self.authority.world,
                    descriptors: std::slice::from_ref(&selection.descriptor),
                    bindings: std::slice::from_ref(&selection.binding),
                    owners: std::slice::from_ref(&selection.owner),
                    requirements: &self.requirements,
                },
            )
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn prepare(
        &self,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<placement::PreparedPacketPlacement, RuntimeError> {
        self.current()?;
        let expected = self
            .authority
            .oracle
            .expected_completion(&self.before_case)
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
        let reports = self
            .authority
            .reports
            .try_borrow()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let (report_ref, report_bytes, verdict) = reports
            .original_report(&self.before_case)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if verdict != Some(CaseVerdict::Passed) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authority
            .oracle
            .authenticate_original_result(&self.before_case, original, report_ref)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        report_ref
            .verify(report_bytes)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let plan = self.plan.evidence();
        plan.plan_ref
            .verify(plan.plan_bytes)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        plan.refused_ref
            .verify(plan.refused_bytes)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let objects = [
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.plan_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.refused_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, report_bytes),
        ];
        let activation = original.admission().activation().record();
        let root = ResultRoot {
            format: "crucible.packet-collecting-result",
            version: 1,
            purpose: "conformance-collection",
            plan: plan.plan_ref,
            refused_audit: plan.refused_ref,
            original_report: report_ref,
            case: &self.before_case,
            objects: &objects,
            activation: super::scope::activation_view(activation),
            route: original.admission().token().route(),
            request: original.admission().request(),
            outcome: original.outcome(),
        };
        // Credit raw bodies, prepared and returned handles, and readbacks,
        // and canonical root temporaries, BEFORE cloning/canonical allocation.
        let raw = plan
            .plan_bytes
            .len()
            .checked_add(plan.refused_bytes.len())
            .and_then(|sum| sum.checked_add(report_bytes.len()))
            .and_then(|sum| sum.checked_mul(4))
            .ok_or(RuntimeError::ResourceLimit)?;
        let root_bytes = super::scope::encoded_size(&root, self.maximum_bytes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if root_bytes
            .checked_mul(6)
            .and_then(|size| raw.checked_add(size))
            .is_none_or(|size| size > self.maximum_bytes)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&root).map_err(|_| RuntimeError::ResourceLimit)?,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        placement::PreparedPacketPlacement::prepare(
            self.blobs.clone(),
            self.refs.clone(),
            self.reference.clone(),
            [
                plan.plan_bytes.to_vec(),
                plan.refused_bytes.to_vec(),
                report_bytes.to_vec(),
                bytes,
            ],
            self.maximum_bytes,
        )
    }
}

impl ConformanceResultPublisher for StoredPacketResultPublisher {
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
        // Reauthenticate the actual permission/outcome on EVERY call, including
        // retries. A historical prepared body cannot substitute a new operation.
        let expected = self
            .authority
            .oracle
            .expected_completion(&self.before_case)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if &expected.request != original.admission().request()
            || &expected.outcome != original.outcome()
            || original.acknowledged()
            || original.admission().inputs().is_some()
            || original.staged_inputs()?.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        {
            let reports = self
                .authority
                .reports
                .try_borrow()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            let (reference, bytes, verdict) = reports
                .original_report(&self.before_case)
                .ok_or(RuntimeError::ForeignAuthority)?;
            if verdict != Some(CaseVerdict::Passed) {
                return Err(RuntimeError::ForeignAuthority);
            }
            reference
                .verify(bytes)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            self.authority
                .oracle
                .authenticate_original_result(&self.before_case, original, reference)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        if self.prepared.is_none() {
            self.prepared = Some(self.prepare(original)?);
        }
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?;
        if self.attempted {
            let status = prepared.reconcile(|| self.current())?;
            if status != PublicationStatus::NotCommitted {
                return Ok(status);
            }
        }
        // Unwind keeps the exact prepared bodies and sticky original attempt;
        // subsequent reconciliation cannot allocate a replacement result root.
        self.attempted = true;
        prepared.publish(|| self.current())
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
    activation: super::scope::ActivationView<'a>,
    route: &'a NodeRoute,
    request: &'a OperationRequest,
    outcome: &'a OperationOutcome,
}

// This borrowed data encoding preserves every domain-separated CAS identity
// field without adding serialization to live handles or allocating ID strings
// ahead of the complete root precredit.
fn serialize_content_ids<S: serde::Serializer>(
    objects: &[ContentId; 3],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct ContentIdentity {
        kind: &'static str,
        schema_version: u32,
        digest: [u8; 32],
    }

    objects
        .map(|object| ContentIdentity {
            kind: object.kind().as_str(),
            schema_version: object.schema_version(),
            digest: object.digest(),
        })
        .serialize(serializer)
}
