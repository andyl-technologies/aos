//! Stores Source-fenced restored Producer results before common scheduling ACK.
//!
//! The separately registered target publisher owns one append-only placement per
//! global Window action slot. Canonical Source reports remain opaque bytes here;
//! only the genuine synchronous publication scope can invoke storage effects.
//! The durable root binds the report to the actual common completion:
//!
//! ```text
//! {format,version,purpose,plan,refused_audit,restored_report,slot,objects,
//!  activation,route,request,outcome}
//! ```

use crucible_engine::node_adapters::cnp::OriginalRestoredProducerOutcomeProjection;
use crucible_engine::node_admission::{
    CompleteOriginalRestorationWindow, InstalledConformancePlan,
    OriginalRestoredProducerPublisherConstructionScope,
};
use crucible_engine::node_contract::{
    NodeRoute, NodeRuntime, OperationOutcome, OperationRequest,
    OriginalRestoredProducerPublicationConstructionData, OriginalRestoredProducerPublicationScope,
    OriginalRestoredProducerResultPublisher, PublicationStatus, RuntimeError,
};
use crucible_node_format::{ContentRef, canonical};
use crucible_store::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend,
    DirectoryRefNameConstructionData, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    cell::OnceCell,
    mem::{align_of, size_of, size_of_val},
    rc::{Rc, Weak},
    sync::Arc,
};

use super::super::result_publication::placement::PreparedPacketPlacement;

const NAMESPACE: &str = "node-packet-collecting-results/restored-producer-v1/";
const MAXIMUM_CLOSURE: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Placement {
    started: bool,
    report: Option<ContentRef>,
    bodies: [Option<Vec<u8>>; 4],
    root_value: Option<Value>,
    root_reference: Option<ContentRef>,
    committed: bool,
    prepared: Option<PreparedPacketPlacement>,
    attempted: bool,
}

/// Retains independently owned Directory inputs for target result publication.
///
/// The registered holder takes this complete bank before any fallible quote.
/// The name roster declares the finite funded lifecycle capacity; it creates no
/// operation or publication rights and cannot exceed the real Runtime/Source
/// limits checked by the Window before Prepare.
pub struct PacketRestoredProducerPublicationInputs {
    /// Retains the actual immutable Directory store through native cleanup.
    pub blobs: Arc<DirectoryBlobBackend>,
    /// Retains the actual durable write-once Directory ref store.
    pub refs: Arc<DirectoryRefBackend>,
    /// Owns unique names in global Window action-slot order.
    pub references: Vec<RefName>,
}

/// Owns finite target result slots beside the actual fresh restoration capsule.
///
/// This type has no original-execution publisher implementation. Its caller
/// retains it through every failed action, native retirement and cleanup. A DATA
/// quote or a write-once name never supplies a completed-operation scope.
pub(crate) struct StoredPacketRestoredProducerResultPublisher {
    plan: Rc<InstalledConformancePlan>,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    references: Vec<RefName>,
    placements: Vec<Placement>,
    construction: OnceCell<OriginalRestoredProducerPublicationConstructionData>,
    root_encoded: OnceCell<usize>,
    window: OnceCell<Weak<CompleteOriginalRestorationWindow>>,
    maximum: usize,
}

fn add(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right).ok_or(RuntimeError::ResourceLimit)
}

fn mul(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_mul(right).ok_or(RuntimeError::ResourceLimit)
}

impl StoredPacketRestoredProducerResultPublisher {
    /// Retains original inputs without invoking a backend or allocating slots.
    pub(super) fn retain(
        plan: Rc<InstalledConformancePlan>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
        references: Vec<RefName>,
        maximum: usize,
    ) -> Self {
        Self {
            plan,
            blobs,
            refs,
            references,
            placements: Vec::new(),
            construction: OnceCell::new(),
            root_encoded: OnceCell::new(),
            window: OnceCell::new(),
            maximum,
        }
    }

    /// Quotes the same closed root and real Directory callbacks before Prepare.
    ///
    /// The registered holder supplies this actual Source projection and the
    /// exact funded lifecycle capacity, checked against the actual Runtime and
    /// Source limits by the Window. Neither number creates rights.
    ///
    /// # Errors
    /// Refuses empty/changed input geometry, foreign names, unsupported Directory
    /// instrumentation, overflow, or a complete row above the installed policy.
    pub(super) fn construction_data(
        &mut self,
        projection: &OriginalRestoredProducerOutcomeProjection<'_>,
        report_encoded: usize,
        outcome_encoded: usize,
        projection_scratch: usize,
        slots: usize,
    ) -> Result<&OriginalRestoredProducerPublicationConstructionData, RuntimeError> {
        if slots == 0 || self.references.len() != slots {
            return Err(RuntimeError::OutstandingObligations);
        }
        for (index, name) in self.references.iter().enumerate() {
            if !name.as_str().starts_with(NAMESPACE) || self.references[..index].contains(name) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let plan = self.plan.evidence();
        let objects = ResultObjects::Prospective;
        let report = projection.report_ref_data();
        let route = projection.route_data();
        let request = projection.request_data();
        let root = ResultRoot {
            format: "crucible.packet-restored-producer-result",
            version: 1,
            purpose: "conformance-collection",
            plan: plan.plan_ref,
            refused_audit: plan.refused_ref,
            restored_report: &report,
            slot: usize::MAX,
            objects,
            activation: super::super::scope::activation_view(projection.target_data()),
            route: &route,
            request: &request,
            outcome: projection.outcome_data(),
        };
        let root_encoded = super::super::scope::encoded_size(&root, self.maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let serialization =
            InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                &root,
                self.maximum,
            )?;
        let lengths = [
            plan.plan_bytes.len(),
            plan.refused_bytes.len(),
            report_encoded,
            root_encoded,
        ];
        let raw = lengths
            .iter()
            .try_fold(0usize, |total, bytes| add(total, *bytes))?;
        if raw == 0 || mul(raw, 4)? > MAXIMUM_CLOSURE {
            return Err(RuntimeError::ResourceLimit);
        }
        // Retained originals, prepared Vecs, known in-memory Arc sources, plus
        // conversion/readback overlap are separate banks. Keep every root DOM
        // through errors. No Source-owned report or Outcome allowance is reused.
        let mut per_slot = add(mul(raw, 4)?, serialization)?;
        for length in lengths {
            per_slot = add(
                per_slot,
                BlobHandle::from_bytes_retained_requested_storage_data(length)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        // Report and durable-root references each retain four independent Strings.
        let full_reference =
            "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
        per_slot = add(per_slot, mul(full_reference, 2)?)?;
        let name_copies = self
            .references
            .iter()
            .try_fold(0usize, |total, name| add(total, name.as_str().len()))?;
        let placement_slots = mul(size_of::<Placement>(), slots)?;
        let action_slots = mul(
            size_of::<std::cell::RefCell<RestoredProducerAction>>(),
            slots,
        )?;
        let retained = add(
            add(mul(per_slot, slots)?, add(placement_slots, action_slots)?)?,
            name_copies,
        )?;
        let mut directory_peak = 0usize;
        let mut directory_scratch = 0usize;
        let mut descriptors = 0usize;
        for reference in &self.references {
            for pair in [[lengths[0], lengths[1]], [lengths[2], lengths[3]]] {
                let data = self
                    .blobs
                    .original_two_object_publication_construction_data(
                        &self.refs,
                        [DirectoryRefNameConstructionData::original(reference); 2],
                        pair,
                        pair,
                        self.maximum,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                directory_peak = directory_peak.max(data.requested_bytes_data());
                directory_scratch = directory_scratch.max(data.counter_scratch_bytes_data());
                descriptors =
                    descriptors.max(data.maximum_simultaneous_transient_descriptors_data());
            }
        }
        let scratch = add(
            add(Self::counter_scratch_data()?, projection_scratch)?,
            directory_scratch,
        )?;
        let row = OriginalRestoredProducerPublicationConstructionData::new_data(
            retained,
            directory_peak,
            scratch,
            descriptors,
            report_encoded,
            outcome_encoded,
            slots,
            self.maximum,
        )?;
        match (self.construction.get(), self.root_encoded.get()) {
            (Some(saved), Some(encoded)) if saved == &row && encoded == &root_encoded => {}
            (None, None) => {
                self.root_encoded
                    .set(root_encoded)
                    .map_err(|_| RuntimeError::DuplicateOperation)?;
                self.construction
                    .set(row)
                    .map_err(|_| RuntimeError::DuplicateOperation)?;
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        // This fixed row and original input bank can be retained before whole
        // admission. Slot allocation requires the separate ColdAdmitted callback.
        self.construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Allocates slots once under the actual admitted pre-Prepare scope.
    ///
    /// # Errors
    /// Refuses another candidate, Window, row or capacity, a spent constructor,
    /// allocation failure, or a changed final currentness fence.
    pub(super) fn initialize_admitted_data(
        &mut self,
        scope: &OriginalRestoredProducerPublisherConstructionScope<'_>,
        window: &Rc<CompleteOriginalRestorationWindow>,
    ) -> Result<(), RuntimeError> {
        scope.authenticate_current_data()?;
        let row = self
            .construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !scope.is_original_window_data(window)
            || !scope.original_publisher_data((self as *const Self).cast())
            || scope.construction_data() != row
            || scope.funded_capacity_data() != self.references.len()
            || self.window.get().is_some()
            || !self.placements.is_empty()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // This once destination is set before reserve. Even an allocation
        // failure leaves the same input bank, spent phase and partial capacity.
        self.window
            .set(Rc::downgrade(window))
            .map_err(|_| RuntimeError::DuplicateOperation)?;
        self.placements
            .try_reserve_exact(scope.funded_capacity_data())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.placements
            .resize_with(scope.funded_capacity_data(), Placement::default);
        scope.authenticate_current_data()
    }

    fn authenticate(
        &self,
        scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<(), RuntimeError> {
        scope.authenticate_current_data()?;
        if !scope.original_publisher_data((self as *const Self).cast()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let window = self
            .window
            .get()
            .and_then(Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !scope.is_original_window_data(&window) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let expected = self.plan.evidence();
        let actual = scope.plan_data();
        if expected.plan_ref != actual.plan_ref
            || expected.plan_bytes != actual.plan_bytes
            || expected.refused_ref != actual.refused_ref
            || expected.refused_bytes != actual.refused_bytes
            || expected.world != actual.world
            || expected.sources != actual.sources
            || scope.original_operation_data().acknowledged()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        match scope.original_operation_data().admission().request() {
            OperationRequest::ExactRun {
                boundary_policy: crucible_engine::node_contract::ExactBoundaryPolicy::HorizonPark,
                ..
            }
            | OperationRequest::BoundarySettle { .. } => {}
            _ => return Err(RuntimeError::UnsupportedFacet),
        }
        let row = self
            .construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (report, bytes) = scope.report_data();
        if scope.slot_data() >= row.maximum_slots_data()
            || bytes.len() > row.maximum_report_encoded_bytes_data()
            || report.media_type != "application/json"
        {
            return Err(RuntimeError::ResourceLimit);
        }
        // The nonconstructible scope and its live Source fence validate this
        // exact report/ref pair. No arbitrary bytes are parsed or reissued here.
        let slot = self
            .placements
            .get(scope.slot_data())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if let Some(saved) = &slot.report {
            if saved != report || slot.bodies[2].as_deref() != Some(bytes) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        scope.authenticate_current_data()
    }

    fn prepare(
        &mut self,
        scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate(scope)?;
        let index = scope.slot_data();
        let slot = self
            .placements
            .get_mut(index)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if slot.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Spend the slot before any report/root copy. A failed partial cannot be
        // replaced by a later operation, even when its first bank is still None.
        slot.started = true;
        let (report, bytes) = scope.report_data();
        slot.report = Some(report.clone());
        slot.bodies[2] = Some(bytes.to_vec());
        let plan = self.plan.evidence();
        slot.bodies[0] = Some(plan.plan_bytes.to_vec());
        slot.bodies[1] = Some(plan.refused_bytes.to_vec());
        let objects = [
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.plan_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, plan.refused_bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, bytes),
        ];
        let original = scope.original_operation_data();
        let root = ResultRoot {
            format: "crucible.packet-restored-producer-result",
            version: 1,
            purpose: "conformance-collection",
            plan: plan.plan_ref,
            refused_audit: plan.refused_ref,
            restored_report: report,
            slot: index,
            objects: ResultObjects::Actual(&objects),
            activation: super::super::scope::activation_view(scope.world_data().record()),
            route: original.admission().token().route(),
            request: original.admission().request(),
            outcome: original.outcome(),
        };
        let outcome_encoded = super::super::scope::encoded_size(original.outcome(), self.maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if outcome_encoded
            > self
                .construction
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .maximum_outcome_encoded_bytes_data()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let encoded = super::super::scope::encoded_size(&root, self.maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if encoded
            > *self
                .root_encoded
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        slot.root_value =
            Some(serde_json::to_value(&root).map_err(|_| RuntimeError::ResourceLimit)?);
        slot.bodies[3] = Some(
            canonical::canonical_json(
                slot.root_value
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?,
        );
        slot.root_reference = Some(
            canonical::content_ref(
                slot.bodies[3]
                    .as_deref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                "application/json",
            )
            .map_err(|_| RuntimeError::ResourceLimit)?,
        );
        scope.authenticate_current_data()?;
        let bodies = [
            slot.bodies[0]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            slot.bodies[1]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            slot.bodies[2]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            slot.bodies[3]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
        ];
        let blobs: Arc<dyn ImmutableBlobBackend> = self.blobs.clone();
        let refs: Arc<dyn MutableRefBackend> = self.refs.clone();
        slot.prepared = Some(PreparedPacketPlacement::prepare(
            blobs,
            refs,
            self.references[index].clone(),
            bodies,
            MAXIMUM_CLOSURE,
        )?);
        scope.authenticate_current_data()
    }
}

impl OriginalRestoredProducerResultPublisher for StoredPacketRestoredProducerResultPublisher {
    fn committed_root_data(
        &self,
        scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        StoredPacketRestoredProducerResultPublisher::committed_root_data(self, scope)
    }

    fn publish_original_restored_producer(
        &mut self,
        scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        self.authenticate(scope)?;
        let index = scope.slot_data();
        if !self.placements[index].started {
            self.prepare(scope)?;
        }
        if self.placements[index].prepared.is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        if self.placements[index].attempted {
            let prepared = self.placements[index]
                .prepared
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let currency = PublicationCurrency {
                publisher: self,
                scope,
            };
            let status = prepared.reconcile(|| currency.authenticate())?;
            if status == PublicationStatus::Committed {
                self.placements[index].committed = true;
            }
            if status != PublicationStatus::NotCommitted {
                return Ok(status);
            }
        }
        self.placements[index].attempted = true;
        let prepared = self.placements[index]
            .prepared
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let currency = PublicationCurrency {
            publisher: self,
            scope,
        };
        let status = prepared.publish(|| currency.authenticate())?;
        if status == PublicationStatus::Committed {
            self.placements[index].committed = true;
        }
        Ok(status)
    }
}

#[derive(Serialize)]
struct ResultRoot<
    'a,
    F: Serialize + ?Sized,
    R: Serialize + ?Sized,
    Q: Serialize + ?Sized,
    O: Serialize + ?Sized,
> {
    format: &'static str,
    version: u16,
    purpose: &'static str,
    plan: &'a ContentRef,
    refused_audit: &'a ContentRef,
    restored_report: &'a F,
    slot: usize,
    objects: ResultObjects<'a>,
    activation: super::super::scope::ActivationView<'a>,
    route: &'a R,
    request: &'a Q,
    outcome: &'a O,
}

// This exact structural identity shape matches the existing placement root
// serializer. Its prospective digest uses the largest decimal u8 spelling.
#[derive(Clone, Copy, Serialize)]
struct ResultContentIdentity {
    kind: &'static str,
    schema_version: u32,
    digest: [u8; 32],
}

impl ResultContentIdentity {
    fn actual(object: ContentId) -> Self {
        Self {
            kind: object.kind().as_str(),
            schema_version: object.schema_version(),
            digest: object.digest(),
        }
    }
}

enum ResultObjects<'a> {
    Prospective,
    Actual(&'a [ContentId; 3]),
}

impl Serialize for ResultObjects<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Actual(objects) => (**objects)
                .map(ResultContentIdentity::actual as fn(ContentId) -> ResultContentIdentity)
                .serialize(serializer),
            Self::Prospective => [ResultContentIdentity {
                kind: ObjectKind::Trace.as_str(),
                schema_version: 1,
                digest: [255; 32],
            }; 3]
                .serialize(serializer),
        }
    }
}

struct PublicationCurrency<'a, 's> {
    publisher: &'a StoredPacketRestoredProducerResultPublisher,
    scope: &'a OriginalRestoredProducerPublicationScope<'s>,
}

impl PublicationCurrency<'_, '_> {
    fn authenticate(&self) -> Result<(), RuntimeError> {
        self.publisher.authenticate(self.scope)
    }
}

impl StoredPacketRestoredProducerResultPublisher {
    /// Names fixed publisher, placement, serializer and owner-observation views.
    ///
    /// # Errors
    /// Refuses checked fixed-layout arithmetic overflow.
    pub(super) fn counter_scratch_data() -> Result<usize, RuntimeError> {
        type ActualRoot =
            ResultRoot<'static, ContentRef, NodeRoute, OperationRequest, OperationOutcome>;
        let terms = [
            Self::placement_counter_scratch_data(),
            RestoredProducerAction::counter_scratch_data()?,
            BlobHandle::from_bytes_retained_counter_scratch_data(),
            NodeRuntime::original_json_value_counter_scratch_data(),
            InstalledConformancePlan::original_runtime_constructor_data_counter_scratch_data(),
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<&mut Self>(),
            size_of::<PacketRestoredProducerPublicationInputs>(),
            size_of::<&OriginalRestoredProducerPublisherConstructionScope<'static>>(),
            size_of::<Placement>(),
            size_of::<Vec<Placement>>(),
            size_of::<Vec<RefName>>(),
            size_of::<std::slice::Iter<'static, RefName>>(),
            size_of::<std::slice::Iter<'static, Placement>>(),
            size_of::<std::iter::Enumerate<std::slice::Iter<'static, RefName>>>(),
            size_of::<[Option<Vec<u8>>; 4]>(),
            size_of::<[Vec<u8>; 4]>(),
            size_of::<[usize; 4]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<std::array::IntoIter<usize, 4>>(),
            size_of::<[[usize; 2]; 2]>(),
            size_of::<std::array::IntoIter<[usize; 2], 2>>(),
            size_of::<[DirectoryRefNameConstructionData<'static>; 2]>(),
            size_of::<crucible_store::content_store::DirectoryPublicationConstructionStorageData>(),
            size_of::<
                Result<
                    crucible_store::content_store::DirectoryPublicationConstructionStorageData,
                    crucible_store::content_store::StoreError,
                >,
            >(),
            size_of::<OriginalRestoredProducerPublicationConstructionData>(),
            size_of::<Result<OriginalRestoredProducerPublicationConstructionData, RuntimeError>>(),
            size_of::<Option<&OriginalRestoredProducerPublicationConstructionData>>(),
            size_of::<Result<&OriginalRestoredProducerPublicationConstructionData, RuntimeError>>(),
            size_of::<Result<(), OriginalRestoredProducerPublicationConstructionData>>(),
            size_of::<ActualRoot>(),
            size_of::<ResultObjects<'static>>(),
            size_of::<ResultContentIdentity>(),
            size_of::<[ResultContentIdentity; 3]>(),
            size_of::<std::array::IntoIter<ResultContentIdentity, 3>>(),
            size_of::<[ContentId; 3]>(),
            size_of::<&[ContentId; 3]>(),
            size_of::<std::array::IntoIter<ContentId, 3>>(),
            size_of::<fn(ContentId) -> ResultContentIdentity>(),
            size_of::<&OriginalRestoredProducerOutcomeProjection<'static>>(),
            size_of::<crucible_engine::node_admission::ConformancePlanEvidence<'static>>() * 2,
            size_of::<PublicationCurrency<'static, 'static>>(),
            size_of::<&PublicationCurrency<'static, 'static>>(),
            size_of::<&OriginalRestoredProducerPublicationScope<'static>>(),
            size_of::<(&ContentRef, &[u8])>(),
            size_of::<Option<ContentRef>>(),
            size_of::<Option<&ContentRef>>(),
            size_of::<Option<Vec<u8>>>(),
            size_of::<Option<&Vec<u8>>>(),
            size_of::<Result<&Vec<u8>, RuntimeError>>(),
            size_of::<Option<&[u8]>>(),
            size_of::<Option<Value>>(),
            size_of::<Option<&Value>>(),
            size_of::<Result<&Value, RuntimeError>>(),
            size_of::<Result<Value, serde_json::Error>>(),
            size_of::<Result<Value, RuntimeError>>(),
            size_of::<Result<ContentRef, crucible_node_format::ContractError>>(),
            size_of::<Result<ContentRef, RuntimeError>>(),
            size_of::<crucible_node_format::HashRef>(),
            size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>(),
            size_of::<Option<&ContentRef>>(),
            size_of::<Result<&ContentRef, RuntimeError>>(),
            size_of::<(&ContentRef, &[u8])>(),
            size_of::<Result<(&ContentRef, &[u8]), RuntimeError>>(),
            size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>(),
            size_of::<Result<Vec<u8>, RuntimeError>>(),
            size_of::<Option<PreparedPacketPlacement>>(),
            size_of::<Option<&PreparedPacketPlacement>>(),
            size_of::<Result<&PreparedPacketPlacement, RuntimeError>>(),
            size_of::<Result<PreparedPacketPlacement, RuntimeError>>(),
            size_of::<Option<&Placement>>(),
            size_of::<Option<&mut Placement>>(),
            size_of::<Result<&Placement, RuntimeError>>(),
            size_of::<Result<&mut Placement, RuntimeError>>(),
            size_of::<std::collections::TryReserveError>(),
            size_of::<Result<(), std::collections::TryReserveError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<PublicationStatus, RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<usize, crucible_store::content_store::StoreError>>(),
            size_of::<Result<usize, crate::node_qualification::QualificationError>>(),
            size_of::<Option<usize>>(),
            size_of::<Option<&usize>>(),
            size_of::<Result<&usize, RuntimeError>>(),
            size_of::<Result<(), usize>>(),
            size_of::<Weak<CompleteOriginalRestorationWindow>>(),
            size_of::<Option<&Weak<CompleteOriginalRestorationWindow>>>(),
            size_of::<Option<Rc<CompleteOriginalRestorationWindow>>>(),
            size_of::<Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError>>(),
            size_of::<Result<(), Weak<CompleteOriginalRestorationWindow>>>(),
            size_of::<Arc<dyn ImmutableBlobBackend>>(),
            size_of::<Arc<dyn MutableRefBackend>>(),
            size_of::<super::retained::Counter>(),
            size_of::<bool>(),
        ];
        terms
            .iter()
            .try_fold(size_of_val(&terms), |total, bytes| add(total, *bytes))
    }

    fn placement_counter_scratch_data() -> usize {
        PreparedPacketPlacement::retained_counter_scratch_data()
    }

    // The same plan is retained by the registered target holder and observed
    // independently by Core. This raw walk grants no plan or Source authority.
    /// Observes every actual retained partial without invoking a backend.
    ///
    /// # Errors
    /// Refuses unsupported owner geometry or the counter's remaining ceiling.
    pub(super) fn charge_retained_storage_data(
        &self,
        counter: &mut super::retained::Counter,
    ) -> Result<(), RuntimeError> {
        let failure = |_| RuntimeError::ResourceLimit;
        counter.rc(&self.plan).map_err(failure)?;
        if counter
            .shared_header(
                Arc::as_ptr(&self.blobs).cast(),
                size_of::<DirectoryBlobBackend>(),
                align_of::<DirectoryBlobBackend>(),
            )
            .map_err(failure)?
        {
            counter
                .add(
                    self.blobs
                        .retained_configuration_requested_storage_data()
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .map_err(failure)?;
        }
        if counter
            .shared_header(
                Arc::as_ptr(&self.refs).cast(),
                size_of::<DirectoryRefBackend>(),
                align_of::<DirectoryRefBackend>(),
            )
            .map_err(failure)?
        {
            counter
                .add(self.refs.retained_configuration_requested_storage_data())
                .map_err(failure)?;
        }
        counter
            .add(mul(self.references.capacity(), size_of::<RefName>())?)
            .map_err(failure)?;
        for name in &self.references {
            counter
                .add(name.retained_requested_storage_data())
                .map_err(failure)?;
        }
        counter
            .add(mul(self.placements.capacity(), size_of::<Placement>())?)
            .map_err(failure)?;
        for slot in &self.placements {
            counter.charge(&slot.report).map_err(failure)?;
            counter.charge(&slot.root_reference).map_err(failure)?;
            counter.charge(&slot.bodies).map_err(failure)?;
            if let Some(value) = &slot.root_value {
                counter
                    .add(NodeRuntime::original_json_value_requested_storage_data(
                        value,
                        counter.remaining(),
                    )?)
                    .map_err(failure)?;
            }
            if let Some(prepared) = &slot.prepared {
                prepared
                    .charge_retained_storage_data(counter)
                    .map_err(failure)?;
            }
        }
        if let Some(window) = self.window.get() {
            counter.weak(window).map_err(failure)?;
        }
        Ok(())
    }
}

impl StoredPacketRestoredProducerResultPublisher {
    /// Compares the exact retained target plan allocation without issuing rights.
    ///
    /// # Errors
    /// Refuses another original plan, including equal historical plan bytes.
    pub(super) fn authenticate_plan_data(
        &self,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        if !self.plan.is_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl StoredPacketRestoredProducerResultPublisher {
    // The selected Core adapter may inspect this only under the same real
    // Source callback. The returned tuple is borrowed DATA; only that adapter's
    // current operation/scheduling fence can authorize a later consumption ACK.
    /// Lends the root only after this exact placement durably committed.
    ///
    /// # Errors
    /// Refuses changed live scope, another operation or an uncertain root.
    pub(super) fn committed_root_data(
        &self,
        scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        self.authenticate(scope)?;
        let slot = self
            .placements
            .get(scope.slot_data())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !slot.committed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let reference = slot
            .root_reference
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let bytes = slot.bodies[3]
            .as_deref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok((reference, bytes))
    }
}

impl StoredPacketRestoredProducerResultPublisher {
    pub(super) fn funded_capacity_data(&self) -> usize {
        self.references.len()
    }
}

impl StoredPacketRestoredProducerResultPublisher {
    pub(super) fn maximum_requested_data(&self) -> usize {
        self.maximum
    }
}

mod action;
pub(super) use action::RestoredProducerAction;
