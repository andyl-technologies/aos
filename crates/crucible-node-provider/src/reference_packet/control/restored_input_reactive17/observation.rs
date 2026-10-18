//! Produces a new native checkpoint from the actual signed Observe17 original.
//!
//! Its inventory is unchanged, but the model proof embeds the new signed
//! original and therefore receives a new full reference.
//!
//! The native action scope authenticates its Source MAC, latest checkpoint and
//! separately funded current Boot/index/Rc occurrence before this producer.
//! It never strips the signed extension or re-enters a legacy Observe permit.

use super::*;
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, encode_original_precharged_serialization_into,
};
use crate::reference_packet::service::ack_emitter::NativeObservation17SpentAction;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::reference_packet::service::restored_input_reactive17::observation_geometry::{
    self as geometry, Observation17OriginalData,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata, requested_metadata_backing_storage_data,
    serialization_storage::OriginalSerializationStorageProjection,
};
use std::{
    mem::{align_of, size_of},
    rc::Rc,
};

type Projection = OriginalSerializationStorageProjection;

#[path = "observation/geometry.rs"]
mod projection_geometry;

#[path = "observation/retained.rs"]
mod retained;
pub(crate) use retained::NativeObservation17PublishedProductionData;

#[path = "observation/capture_current17.rs"]
mod capture_current17;
pub(crate) use capture_current17::capture17_checkpoint_counter_scratch_data;

/// Keeps every newly initialized proof owner in the original native attempt.
#[derive(Serialize)]
pub(crate) struct NativeObservation17ProductionAttempt {
    model_bytes: Vec<u8>,
    model_reference: Option<ContentRef>,
    receipt: Option<PacketNative5Record>,
    restored: Option<PacketNativeRestoredRecord>,
    restored_bytes: Vec<u8>,
    restored_reference: Option<ContentRef>,
    body: Option<Map<String, Value>>,
    evidence: Vec<(ContentRef, Vec<u8>)>,
    started: bool,
    complete: bool,
}

/// Binds prospective storage to this exact actual Control/original occurrence.
pub(crate) struct NativeObservation17ProducerStorageData<'original> {
    owner: Rc<()>,
    original: &'original Envelope,
    row: PacketNativeStartupAllocationRow,
    model: NativeSerializationStorageData,
    restored: NativeSerializationStorageData,
    terminal: NativeSerializationStorageData,
}

/// Retains a complete borrowed-model comparison in the same spent action slot.
#[derive(Serialize)]
pub(crate) struct NativeObservation17CheckpointAttempt {
    model_bytes: Vec<u8>,
    receipt: Option<PacketNative5Record>,
    restored: Option<PacketNativeRestoredRecord>,
    restored_bytes: Vec<u8>,
    validated: bool,
}

/// Prices the defining native current-check before any comparison DTO exists.
pub(crate) struct NativeObservation17CheckpointStorageData<'previous> {
    owner: Rc<()>,
    previous: &'previous Envelope,
    row: PacketNativeStartupAllocationRow,
    model: NativeSerializationStorageData,
    restored: NativeSerializationStorageData,
}

#[derive(Serialize)]
struct BorrowedReactiveObservation17<'a, I: Serialize> {
    schema: &'static str,
    native_pid: U64,
    original: &'a Envelope,
    inventory: I,
    grant: Option<()>,
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(exhausted)
    })
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native signed Observe17 defining producer storage")
}

fn quote_row(
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(u64::try_from(retained).map_err(|_| exhausted())?),
        maximum_simultaneous_transient_bytes: U64::new(
            u64::try_from(transient).map_err(|_| exhausted())?,
        ),
        declared_counter_scratch_bytes: U64::new(u64::try_from(scratch).map_err(|_| exhausted())?),
    };
    if usize::try_from(row.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

fn reference_projection(value: &mut Projection) -> Result<(), ProviderError> {
    value.add_object()?;
    for key in ["hash", "length", "media_type"] {
        value.add_field(key)?;
    }
    value.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        value.add_field(key)?;
    }
    value.add_string("blake3-256")?;
    value.add_string("cnp.blob.v1")?;
    value.add_unescaped_ascii_extent(64)?;
    value.add_unescaped_ascii_extent(20)?;
    value.add_string("application/json")
}

const UNKNOWN_MESSAGE: &str = "original signed Observe17 remains unresolved";

fn unknown_projection(maximum: usize) -> Result<NativeSerializationStorageData, ProviderError> {
    let mut value = Projection::new(maximum)?;
    value.add_object()?;
    for key in ["status", "operation_state", "error", "extensions"] {
        value.add_field(key)?;
    }
    value.add_string("error")?;
    value.add_value(&OperationState::Unknown)?;
    value.add_object()?;
    for key in ["code", "message", "effect", "retryable", "details"] {
        value.add_field(key)?;
    }
    value.add_string("OUTCOME_UNKNOWN")?;
    value.add_string(UNKNOWN_MESSAGE)?;
    value.add_value(&EffectCertainty::Unknown)?;
    value.add_value(&false)?;
    value.add_object()?;
    value.add_object()?;
    value.finish(maximum)
}

// The pinned BTree has at least two children per internal level. A single
// insertion can split one node per level and introduce one new root. The
// maximum internal layout is charged for each newly requested node; existing
// empty-node or spare capacity is never reused as prospective credit.
fn insertion_node_bound(entries: usize) -> Result<usize, ProviderError> {
    let values = entries.checked_add(1).ok_or_else(exhausted)?;
    let height = values.checked_ilog2().unwrap_or(0) as usize;
    height.checked_add(2).ok_or_else(exhausted)
}

impl PacketControl {
    fn observation17_receipt_backing_data(
        &self,
        original: &Envelope,
        scope: &crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope,
    ) -> Result<usize, ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let mut fields = MetadataObserver::new();
        fields.observe(original)?;
        fields.observe(&binding.authority.session_id)?;
        fields.observe(&binding.authority.incarnation_id)?;
        fields.observe(&binding.compatibility.node_id)?;
        fields.observe(&binding.compatibility.capture_owner.id)?;
        fields.observe(&binding.authority.input_epoch)?;
        fields.observe(&self.selection.world)?;
        fields.observe(&self.complete_capture_profile)?;
        fields.observe(&self.complete_storage)?;
        // This exhaustive complete scope subset bounds each independently
        // copied restoration reference and digest in the actual wrapper.
        fields.observe(&scope.restoration)?;
        // binding_hash is newly computed by OwnerBinding::identity().
        add(
            requested_metadata_backing_storage_data(&fields.finish())?,
            "blake3-256".len() + "cnp.owner-binding.v1".len() + 64,
        )
    }

    fn observation17_model_storage_data(
        &self,
        original: &Envelope,
        maximum: usize,
    ) -> Result<NativeSerializationStorageData, ProviderError> {
        let NativeProgram::Connected(program) = &self.program else {
            return Err(refused());
        };
        let inventory =
            program.borrow_original_observation17_inventory_data(&mut MetadataObserver::new())?;
        let mut projection = Projection::new(maximum)?;
        geometry::model_header(
            &mut projection,
            U64::new(u64::from(self.capture_creator)),
            &Observation17OriginalData::Actual(original),
        )?;
        inventory.project_observation17_inventory_data(&mut projection)?;
        projection.add_value(&Option::<()>::None)?;
        let mut storage = projection.finish(maximum)?;
        storage.serializer_temporary_requested_bytes =
            inventory.observation17_formatter_storage_data()?;
        if storage.requested_total()? > maximum {
            return Err(exhausted());
        }
        Ok(storage)
    }

    /// Rejoins one genuine published owner's immutable cached checkpoint pair.
    ///
    /// This custody fence allocates no canonical/hash banks and grants no model
    /// currency. The independent funded current comparer rehashes the cached
    /// request identity and both complete output banks before producer effects.
    ///
    /// # Errors
    /// Refuses a foreign/fenced Control, changed complete reply, malformed exact
    /// Observe pair, lost content or routing correspondence.
    pub(crate) fn authenticate_observation17_checkpoint_cache_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || original.method != Method::Observe
        {
            return Err(refused());
        }
        original.matches_response(terminal)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let (identity, cached) = self.originals.get(id).ok_or_else(refused)?;
        let [model, restored] = cached.evidence.as_slice() else {
            return Err(refused());
        };
        if cached.body != terminal.body
            || cached.body.get("status").and_then(Value::as_str) != Some("completed")
            || cached.body.get("operation_state").and_then(Value::as_str) != Some("completed")
            || identity.algorithm != "blake3-256"
            || identity.domain != "cnp.request.v1"
            || identity.digest.len() != 64
            || !identity.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.content.get(&model.0) != Some(&model.1)
            || self.content.get(&restored.0) != Some(&restored.1)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Compares immutable first-proof ancestry without borrowing Control banks.
    ///
    /// The live lender supplies its actual first original/terminal; the private
    /// native scope separately compares the complete retained first/World scope.
    ///
    /// # Errors
    /// Refuses lost first custody or another complete first-proof reference.
    pub(crate) fn authenticate_observation17_ancestry_data(
        &self,
        first_original: &Envelope,
        first_terminal: &Envelope,
        request: &PacketRestoredInputReactive17Request,
    ) -> Result<(), ProviderError> {
        self.authenticate_observation17_checkpoint_cache_data(first_original, first_terminal)?;
        let id = first_original.request_id.0.as_ref().ok_or_else(refused)?;
        let (_, reply) = self.originals.get(id).ok_or_else(refused)?;
        let [_, restored] = reply.evidence.as_slice() else {
            return Err(refused());
        };
        if request.first_observation != restored.0 {
            return Err(refused());
        }
        Ok(())
    }

    // A repeated model hash across observations is legitimate. Pair ownership
    // instead requires the exact original and BOTH complete output references.
    fn authenticate_observation17_cached_pair_data(
        &self,
        previous: &Envelope,
        request: &PacketRestoredInputReactive17Request,
    ) -> Result<(), ProviderError> {
        self.authenticate_current_checkpoint17_fields_data(
            previous,
            capture_current17::CheckpointFields17::observation_data(request),
        )
    }

    /// Borrows only the actual completed producer's identical cached reply.
    ///
    /// The native scope supplies the privately retained completed production;
    /// this cache correspondence creates no publication/currentness permission.
    ///
    /// # Errors
    /// Refuses a foreign/fenced Control, lost cache or another complete proof.
    pub(crate) fn borrow_observation17_produced_reply_data<'a>(
        &'a self,
        original: &Envelope,
        production: &NativeObservation17PublishedProductionData<'_>,
    ) -> Result<&'a PacketControlReply, ProviderError> {
        if self.capture_creator != std::process::id() || self.fenced || !self.immediate {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let (_, reply) = self.originals.get(id).ok_or_else(refused)?;
        let [model, restored] = reply.evidence.as_slice() else {
            return Err(refused());
        };
        let expected_model = production.model_data();
        let expected_restored = production.restored_data();
        if &reply.body != production.body_data()
            || &model.0 != expected_model.0
            || model.1.as_slice() != expected_model.1
            || &restored.0 != expected_restored.0
            || restored.1.as_slice() != expected_restored.1
            || self.content.get(&model.0) != Some(&model.1)
            || self.content.get(&restored.0) != Some(&restored.1)
        {
            return Err(refused());
        }
        Ok(reply)
    }

    /// Quotes exact current-proof comparison from the actual native model.
    ///
    /// The defining Boot lender supplies the actual latest published original;
    /// neither a decoded envelope nor a cache search creates that lender. This
    /// quote performs no DOM/model decode and issues no row permission.
    ///
    /// # Errors
    /// Refuses changed actual cache pair, unsupported model/current scope,
    /// checked geometry overflow or a complete independent short bound.
    pub(crate) fn quote_observation17_checkpoint_data<'previous>(
        &self,
        previous: &'previous Envelope,
        request: &PacketRestoredInputReactive17Request,
        maximum: usize,
    ) -> Result<NativeObservation17CheckpointStorageData<'previous>, ProviderError> {
        self.quote_current_checkpoint17_fields_data(
            previous,
            capture_current17::CheckpointFields17::observation_data(request),
            maximum,
        )
    }

    /// Compares the actual current model with the exact retained checkpoint pair.
    ///
    /// The genuine caller has already spent both this independent row and its
    /// output row. It retains the destination in the same Boot/index/Rc before
    /// entering, then separately fences the actual latest published-original
    /// lender. Complete model equality is recomputed without replay or DTOs.
    ///
    /// # Errors
    /// Refuses reentry, changed Control/original/cache custody, failed retained
    /// serialization, stale complete model or changed restoration receipt.
    pub(crate) fn authenticate_observation17_checkpoint_into_data(
        &self,
        previous: &Envelope,
        request: &PacketRestoredInputReactive17Request,
        storage: &NativeObservation17CheckpointStorageData<'_>,
        destination: &mut Option<NativeObservation17CheckpointAttempt>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current_checkpoint17_into_data(
            previous,
            capture_current17::CheckpointFields17::observation_data(request),
            storage,
            destination,
        )
    }

    fn authenticate_observation17_fields_data(
        &self,
        original: &Envelope,
        observe: &ObserveRequest,
        request: &PacketRestoredInputReactive17Request,
    ) -> Result<(), ProviderError> {
        // The private spent action supplies actual immutable birth/Source-MAC
        // provenance. This structural prequote performs no legacy serializer,
        // canonical identity, model clone or row-funded work before debit.
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = self.selection.realization.owners.as_slice() else {
            return Err(refused());
        };
        if request.command != PacketRestoredInputReactive17Command::Observe
            || original.message != crate::envelope::MessageKind::Request
            || original.method != Method::Observe
            || original.extensions.len() != 1
            || !original
                .extensions
                .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
            || original.operation_id.0.is_some()
            || original.request_id.0.is_none()
            || original.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || original.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || original.execution_owner_id.0.as_ref() != Some(&owner.id)
            || original.capture_owner_id.0.is_some()
            || observe.binding_hash != request.scope.target.binding_hash
            || observe.owner_generation != binding.authority.owner_generation
            || observe.after_observation_sequence != U64::new(0)
            || observe.maximum_items != U64::new(1)
            || !observe.extensions.is_empty()
            || self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.complete_restored_hold.is_none()
            || self.original_physical_gate_held()?
            || self.complete_restored_evidence.is_none()
            || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.current_operation.is_some()
            || self.active.as_ref().is_none_or(|active| {
                active.activation_id != request.scope.target.activation
                    || active.world_generation != request.scope.target.generation
                    || active.world_binding_hash != request.scope.target.world
            })
            || !matches!(self.program, NativeProgram::Connected(_))
        {
            return Err(refused());
        }
        Ok(())
    }

    fn project_observation17_restored_data(
        &self,
        original: &Envelope,
        current_record: &ContentRef,
        maximum: usize,
    ) -> Result<NativeSerializationStorageData, ProviderError> {
        let current = self.content.get(current_record).ok_or_else(refused)?;
        let mut value = Projection::new(maximum)?;
        geometry::restored_from_current_bytes(
            &mut value,
            current,
            &Observation17OriginalData::Actual(original),
        )?;
        let mut storage = value.finish(maximum)?;
        // The defining restoration digest is the wrapper's only Bytes field.
        // The future original already owns its signed extension as JSON Values.
        storage.serializer_temporary_requested_bytes =
            add(storage.serializer_temporary_requested_bytes, 43)?;
        if storage.requested_total()? > maximum {
            return Err(exhausted());
        }
        Ok(storage)
    }

    fn project_observation17_terminal_data(
        &self,
        original: &Envelope,
        maximum: usize,
    ) -> Result<NativeSerializationStorageData, ProviderError> {
        let mut value = Projection::new(maximum)?;
        value.add_object()?;
        for key in [
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ] {
            value.add_field(key)?;
        }
        value.add_string("CNP/1")?;
        value.add_value(&crate::envelope::MessageKind::Response)?;
        value.add_value(&original.session_id)?;
        value.add_value(&original.incarnation_id)?;
        value.add_value(&original.node_id)?;
        value.add_value(&original.execution_owner_id)?;
        value.add_value(&original.capture_owner_id)?;
        value.add_value(&original.request_id)?;
        value.add_value(&original.operation_id)?;
        value.add_unescaped_ascii_extent(20)?;
        value.add_value(&Method::Observe)?;
        value.add_object()?;
        for key in ["status", "operation_state", "result", "extensions"] {
            value.add_field(key)?;
        }
        value.add_string("completed")?;
        value.add_value(&OperationState::Completed)?;
        self.project_observation17_result_data(&mut value, original)?;
        value.add_object()?;
        value.add_object()?;
        let mut storage = value.finish(maximum)?;
        storage.serializer_temporary_requested_bytes = 20;
        if storage.requested_total()? > maximum {
            return Err(exhausted());
        }
        Ok(storage)
    }

    /// Quotes actual signed-original proof producers before copying their banks.
    ///
    /// Pure original/row correspondence is not an action permission. The same
    /// private native action must independently debit this complete prospective
    /// demand and authenticate current lineage before invoking the producer.
    ///
    /// # Errors
    /// Refuses another live Control/original, unsupported active state, changed
    /// closed Observe fields, malformed geometry, overflow or a short bound.
    pub(crate) fn quote_observation17_producer_data<'original>(
        &self,
        original: &'original Envelope,
        observe: &ObserveRequest,
        request: &PacketRestoredInputReactive17Request,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeObservation17ProducerStorageData<'original>, ProviderError> {
        self.authenticate_observation17_fields_data(original, observe, request)?;
        let model = self.observation17_model_storage_data(original, maximum)?;
        let restored =
            self.project_observation17_restored_data(original, &request.current_record, maximum)?;
        let terminal = self.project_observation17_terminal_data(original, maximum)?;
        if model.maximum_encoded_bytes > maximum_frame
            || restored.maximum_encoded_bytes > maximum_frame
            || terminal.maximum_encoded_bytes > maximum_frame
        {
            return Err(exhausted());
        }

        // These defining copied fields have independent future owners. Current
        // allocation census grants no credit and unused selection manifests do
        // not contribute to this receipt's prospective demand.
        let copied_receipt = self.observation17_receipt_backing_data(original, &request.scope)?;
        let original_nodes = tree_storage_data(
            0,
            insertion_node_bound(self.originals.len())?,
            size_of::<Id>() + size_of::<(HashRef, PacketControlReply)>(),
            align_of::<(Id, (HashRef, PacketControlReply))>(),
        )?;
        let content_nodes = sum(&[
            tree_storage_data(
                0,
                insertion_node_bound(self.content.len())?,
                size_of::<ContentRef>() + size_of::<Vec<u8>>(),
                align_of::<(ContentRef, Vec<u8>)>(),
            )?,
            tree_storage_data(
                0,
                insertion_node_bound(add(self.content.len(), 1)?)?,
                size_of::<ContentRef>() + size_of::<Vec<u8>>(),
                align_of::<(ContentRef, Vec<u8>)>(),
            )?,
        ])?;
        let mut trees = MetadataObserver::new();
        trees.vector::<(ContentRef, Vec<u8>)>(2)?;
        trees.vector::<(ContentRef, Vec<u8>)>(2)?;
        let unknown = unknown_projection(maximum)?;
        let mut reference = Projection::new(maximum)?;
        reference_projection(&mut reference)?;
        let reference = reference.finish(maximum)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let retained = sum(&[
            size_of::<NativeObservation17ProductionAttempt>(),
            size_of::<NativeObservation17ProducerStorageData<'static>>(),
            requested_metadata_backing_storage_data(&trees.finish())?,
            original_nodes,
            content_nodes,
            id.as_str().len(),
            "blake3-256".len() + "cnp.request.v1".len() + 64,
            // Actual model/wrapper banks coexist in the producer, verified
            // content store, retained produced reply and immutable reply cache.
            multiply(4, model.maximum_encoded_bytes)?,
            multiply(4, restored.maximum_encoded_bytes)?,
            multiply(2, copied_receipt)?,
            multiply(2, size_of::<PacketNative5Record>())?,
            multiply(2, "source-owned.packet-receipt/5".len())?,
            "source-owned.packet-restored-native/12".len(),
            size_of::<PacketNativeRestoredRecord>(),
            // Attempt refs (2), verified-content keys (2), both receipts'
            // model refs (2), retained proof pairs (2) and cached proof pairs
            // (2) are ten independently initialized full-reference owners.
            multiply(10, reference.retained_value_backing_bytes)?,
            // Production body, Control cache, ingress prepared_reply and the
            // ingress's complete terminal clone own four independent banks.
            // Complete terminal backing also bounds its native routing leaves;
            // none of these clones borrows the raw ingress DOM allowance.
            multiply(4, terminal.retained_value_backing_bytes)?,
            unknown.retained_value_backing_bytes,
        ])?;
        let transient = sum(&[
            model.requested_total()?,
            restored.requested_total()?,
            terminal.requested_total()?,
            unknown.requested_total()?,
            // observation17_body_data owns its one-element typed result until
            // the independently priced result and complete-body DOMs exist.
            size_of::<ObserveResult>(),
            size_of::<ObservationBatch>(),
            copied_receipt,
            reference.retained_value_backing_bytes,
            "blake3-256".len() + "source-owned.packet-connected-inventory/4".len() + 64,
            // The full closed model tree independently bounds the separate
            // inventory-only canonical hash phase without running a formatter.
            model.requested_total()?,
            projection_geometry::original_work_data(original, maximum)?.requested_total()?,
            reference.requested_total()?,
            // The defining actual OwnerBinding identity is independently
            // serialized by request comparison, receipt and terminal batch.
            multiply(
                3,
                projection_geometry::owner_binding_work_data(
                    self.selection
                        .realization
                        .owner_bindings
                        .first()
                        .ok_or_else(refused)?,
                    maximum,
                )?
                .requested_total()?,
            )?,
        ])?;
        Ok(NativeObservation17ProducerStorageData {
            owner: Rc::clone(&self.capture_identity),
            original,
            row: quote_row(
                retained,
                transient,
                observation17_producer_counter_scratch_data(),
                maximum,
            )?,
            model,
            restored,
            terminal,
        })
    }

    /// Produces and caches a new proof under one genuine spent native17 action.
    ///
    /// Every independent owner is retained before its next fallible operation.
    /// The complete original remains signed throughout; no synthetic Observe or
    /// legacy permission is constructed. This operation changes only custody,
    /// content and the once ledger, never the native simulated model.
    ///
    /// # Errors
    /// Refuses a foreign/reused action, changed quote or current fields, full
    /// content/original quotas, failed retained serialization or cache insertion.
    /// The same attempt and Unknown cache remain after any partial failure.
    pub(crate) fn produce_observation17_into_data(
        &mut self,
        action: &NativeObservation17SpentAction<'_, '_>,
        original: &Envelope,
        observe: &ObserveRequest,
        request: &PacketRestoredInputReactive17Request,
        destination: &mut Option<NativeObservation17ProductionAttempt>,
    ) -> Result<&PacketControlReply, ProviderError> {
        action.authenticate_control_data(self, original)?;
        self.authenticate_observation17_fields_data(original, observe, request)?;
        let storage = action.storage_data();
        storage.authenticate_data(self, original)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if destination.is_some()
            || self.originals.contains_key(id)
            || self.originals.len() >= ORIGINALS
            || self.content.len().saturating_add(2) > OBJECTS
            || self.content_bytes.saturating_add(sum(&[
                storage.model.maximum_encoded_bytes,
                storage.restored.maximum_encoded_bytes,
            ])?) > CONTENT_BYTES
        {
            return Err(exhausted());
        }
        action.begin_control_data(self, original)?;
        let outcome = (|| -> Result<(), ProviderError> {
            *destination = Some(NativeObservation17ProductionAttempt {
                model_bytes: Vec::new(),
                model_reference: None,
                receipt: None,
                restored: None,
                restored_bytes: Vec::new(),
                restored_reference: None,
                body: None,
                evidence: Vec::new(),
                started: true,
                complete: false,
            });
            let attempt = destination.as_mut().ok_or_else(refused)?;
            let identity = original.request_hash(crate::envelope::RequestOrigin::Controller)?;
            self.originals.insert(
                id.clone(),
                (
                    identity,
                    PacketControlReply {
                        body: object(ResponseShape::Error {
                            operation_state: OperationState::Unknown,
                            error: ErrorRecord {
                                code: "OUTCOME_UNKNOWN".into(),
                                message: UNKNOWN_MESSAGE.into(),
                                effect: EffectCertainty::Unknown,
                                retryable: false,
                                details: Map::new(),
                            },
                            extensions: Extensions::new(),
                        })?,
                        evidence: Vec::new(),
                    },
                ),
            );
            attempt
                .model_bytes
                .try_reserve_exact(storage.model.maximum_encoded_bytes)
                .map_err(|_| exhausted())?;
            let NativeProgram::Connected(program) = &self.program else {
                return Err(refused());
            };
            let inventory = program
                .borrow_original_observation17_inventory_data(&mut MetadataObserver::new())?;
            encode_original_precharged_serialization_into(
                &BorrowedReactiveObservation17 {
                    schema: "source-owned.packet-native/4",
                    native_pid: U64::new(u64::from(self.capture_creator)),
                    original,
                    inventory,
                    grant: None,
                },
                &storage.model,
                &mut attempt.model_bytes,
            )?;
            attempt.model_reference = Some(reference(&attempt.model_bytes)?);
            let model = attempt.model_reference.as_ref().ok_or_else(refused)?;
            self.install_content(model.clone(), &attempt.model_bytes)?;
            attempt.receipt = Some(self.original_complete_receipt_data(original, model.clone())?);
            attempt.restored = Some(
                self.complete_restored_evidence
                    .as_ref()
                    .ok_or_else(refused)?
                    .wrap(attempt.receipt.as_ref().ok_or_else(refused)?.clone(), false)?,
            );
            attempt
                .restored_bytes
                .try_reserve_exact(storage.restored.maximum_encoded_bytes)
                .map_err(|_| exhausted())?;
            encode_original_precharged_serialization_into(
                attempt.restored.as_ref().ok_or_else(refused)?,
                &storage.restored,
                &mut attempt.restored_bytes,
            )?;
            attempt.restored_reference = Some(reference(&attempt.restored_bytes)?);
            let restored = attempt.restored_reference.as_ref().ok_or_else(refused)?;
            self.install_content(restored.clone(), &attempt.restored_bytes)?;
            attempt.body = Some(self.observation17_body_data(original, restored)?);
            attempt
                .evidence
                .try_reserve_exact(2)
                .map_err(|_| exhausted())?;
            attempt
                .evidence
                .push((model.clone(), attempt.model_bytes.clone()));
            attempt
                .evidence
                .push((restored.clone(), attempt.restored_bytes.clone()));
            // Both complete proof banks already live in the actual attempt before
            // any reply-cache clone or subsequent Endpoint publication can fail.
            let reply = PacketControlReply {
                body: attempt.body.as_ref().ok_or_else(refused)?.clone(),
                evidence: attempt.evidence.clone(),
            };
            self.originals.get_mut(id).ok_or_else(refused)?.1 = reply;
            attempt.complete = true;
            action.authenticate_control_data(self, original)?;
            Ok(())
        })();
        if outcome.is_err() {
            // Once the action is spent, partial content/cache/attempt custody
            // remains observable and no later control action may proceed.
            self.fenced = true;
        }
        outcome?;
        Ok(&self.originals.get(id).ok_or_else(refused)?.1)
    }

    fn observation17_body_data(
        &self,
        original: &Envelope,
        measurement: &ContentRef,
    ) -> Result<Map<String, Value>, ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = self.selection.realization.owners.as_slice() else {
            return Err(refused());
        };
        let active = self.active.as_ref().ok_or_else(refused)?;
        let result = ObserveResult {
            observations: vec![ObservationBatch {
                schema_version: 1,
                execution_owner_id: owner.id.clone(),
                owner_binding_hash: self.selection.realization.owner_bindings[0].identity()?,
                world_binding_hash: self.selection.world.clone(),
                activation_id: active.activation_id.clone(),
                world_generation: active.world_generation,
                owner_generation: binding.authority.owner_generation,
                operation_id: original.request_id.0.as_ref().ok_or_else(refused)?.clone(),
                grant_id: None,
                first_sequence: U64::new(0),
                last_sequence: U64::new(0),
                events: Vec::new(),
                visibility: Visibility::Staged,
                measurement_ref: measurement.clone(),
                extensions: Extensions::new(),
            }],
            next_sequence: U64::new(1),
            complete: true,
            // The separately priced full-model phase dominates this exact
            // inventory-only hash. It uses the Observe guard; the old Capture
            // helper correctly refuses models with retained outputs.
            inventory_hash: match &self.program {
                NativeProgram::Connected(program) => canonical::json_hash(
                    "source-owned.packet-connected-inventory/4",
                    &program.borrow_original_observation17_inventory_data(
                        &mut MetadataObserver::new(),
                    )?,
                )?,
                _ => return Err(refused()),
            },
        };
        object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(result)?,
            extensions: Extensions::new(),
        })
    }
}

impl NativeObservation17CheckpointStorageData<'_> {
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }
}

impl NativeObservation17ProducerStorageData<'_> {
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }

    /// Reconciles the selected actual connection's exact two-proof suffix.
    ///
    /// # Errors
    /// Refuses a changed original/cut, another selected family, insufficient
    /// real transport/literal bank or any independent geometry upper.
    pub(crate) fn prefix_storage_data<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
        first: u64,
        original: &Envelope,
        maximum: usize,
    ) -> Result<crate::connection::OriginalPacketPrefixProjectionStorageData<2>, ProviderError>
    {
        if !std::ptr::eq(self.original, original) {
            return Err(refused());
        }
        let objects = [
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: self.model.maximum_encoded_bytes,
                media_type: "application/json",
            },
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: self.restored.maximum_encoded_bytes,
                media_type: "application/json",
            },
        ];
        let original_projection = projection_geometry::original_work_data(original, maximum)?;
        connection.quote_original_restored_observation17_prefix_projection_storage_data(
            first,
            original,
            crate::connection::OriginalPacketPrefixProjectionInput {
                terminal: &self.terminal,
                original: &original_projection,
                objects: &objects,
                maximum_requested_bytes: maximum,
            },
        )
    }

    pub(crate) fn authenticate_data(
        &self,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.owner, &control.capture_identity)
            || !std::ptr::eq(self.original, original)
        {
            return Err(refused());
        }
        Ok(())
    }
}

pub(crate) fn observation17_producer_counter_scratch_data() -> usize {
    capture_current17::field_counter_scratch_data()
        + size_of::<NativeObservation17ProductionAttempt>()
        + size_of::<NativeObservation17ProducerStorageData<'static>>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<Projection>()
        + 6 * size_of::<NativeSerializationStorageData>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<[usize; 14]>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<NativeObservation17CheckpointAttempt>()
        + size_of::<NativeObservation17CheckpointStorageData<'static>>()
        + size_of::<ObserveResult>()
        + size_of::<ObservationBatch>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, (HashRef, PacketControlReply)>>()
        + size_of::<Result<ContentRef, ProviderError>>()
        + size_of::<Result<HashRef, crucible_node_contract::ContractError>>()
        + crate::reference_packet::service::restored_input_reactive17::restored_observation17_output_counter_scratch_data()
}
