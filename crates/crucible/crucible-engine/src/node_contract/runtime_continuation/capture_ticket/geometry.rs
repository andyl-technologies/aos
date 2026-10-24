//! Seals the admitted source plan to the same original runtime before effects.

use super::*;
use crate::node_contract::PreparedCompleteOriginalCapturePreflight;
use crate::node_state::{CompleteOriginalCaptureGeometry, CompleteOriginalOwnerCaptureGeometry};

/// Retains one pre-effect capture plan under the original runtime authority.
///
/// Its private constructor is used only by the complete archive writer after
/// source-factory admission. Parsed plans and equal portable activation records
/// cannot create or transfer this seal to another runtime.
pub struct PreparedCompleteOriginalCaptureGeometry {
    original: OriginalSchedulingSource,
    collecting_plan: Option<crate::node_admission::InstalledConformancePlan>,
    activation: WorldActivation,
    capture_id: Id,
    runtime_object: ContentRef,
    runtime_storage: usize,
    limits: NativeCaptureLimits,
    plan: CompleteOriginalCaptureGeometry,
    preflight: Option<PreparedCompleteOriginalCapturePreflight>,
    allocation_budget: Option<crate::node_state::CompleteCaptureAllocationBudget>,
}

impl PreparedCompleteOriginalCaptureGeometry {
    pub(super) fn authenticate(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        capture_id: &Id,
        object: &InputPayload,
        limits: NativeCaptureLimits,
    ) -> Result<(), RuntimeError> {
        if let Some(budget) = &self.allocation_budget {
            budget.authenticate(limits.maximum_total_record_bytes)?;
        }
        match (&self.collecting_plan, runtime.collecting.as_ref()) {
            (None, None) => {}
            (Some(plan), Some(graph)) if plan.same_original(graph.plan()) => {}
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        self.original.authenticate_runtime_authority(
            &self.activation.record().world_binding_hash,
            &runtime.authority,
        )?;
        if !Rc::ptr_eq(&self.activation.authority, &activation.authority)
            || self.activation.record() != activation.record()
            || &self.capture_id != capture_id
            || self.runtime_object != object.reference
            || self.limits.maximum_record_bytes != limits.maximum_record_bytes
            || self.limits.maximum_total_record_bytes != limits.maximum_total_record_bytes
            || self.limits.maximum_objects != limits.maximum_objects
            || self.limits.maximum_artifact_bytes != limits.maximum_artifact_bytes
            || self.limits.maximum_total_artifact_bytes != limits.maximum_total_artifact_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if storage::payload(object)? > self.runtime_storage {
            return Err(RuntimeError::ResourceLimit);
        }
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }

    pub(super) fn reloan_owner(
        &self,
        runtime: &mut crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        index: usize,
    ) -> Result<(), super::super::RuntimePollFailure> {
        if let Some(preflight) = &self.preflight {
            preflight.reloan_owner(runtime, activation, source, runtime_object, index)?;
        }
        Ok(())
    }

    pub(super) fn authenticate_host_family17_data(
        &self,
        restored: bool,
    ) -> Result<(), RuntimeError> {
        match &self.preflight {
            Some(preflight) => preflight.authenticate_host_family17_data(restored),
            None if !restored => Ok(()),
            None => Err(RuntimeError::UnsupportedFacet),
        }
    }

    pub(super) fn take_prepared_host(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        object: &InputPayload,
    ) -> Result<super::host_preparation::family::PreparedHostCaptureFamily, RuntimeError> {
        self.preflight
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .take_prepared_host(runtime, activation, object)
    }

    fn owned_seal_storage(&self) -> Result<usize, RuntimeError> {
        let mut seal_storage = self
            .plan
            .owners
            .capacity()
            .checked_mul(std::mem::size_of::<CompleteOriginalOwnerCaptureGeometry>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for row in &self.plan.owners {
            seal_storage = storage::add(
                seal_storage,
                crate::node_contract::NodeRuntime::capture_owner_geometry_storage(row)?,
            )?;
        }
        seal_storage = storage::add(seal_storage, self.capture_id.allocated_capacity())?;
        seal_storage = storage::add(
            seal_storage,
            crate::node_contract::NodeRuntime::capture_reference_storage(&self.runtime_object)?,
        )?;
        if let Some(preflight) = &self.preflight {
            seal_storage = storage::add(seal_storage, preflight.capture_owned_storage()?)?;
        }
        Ok(seal_storage)
    }

    pub(super) fn authenticate_attempt_construction(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        capture_id: &Id,
        source: &OriginalLineageRuntimeRecord,
        object: &InputPayload,
    ) -> Result<(), RuntimeError> {
        self.authenticate(runtime, activation, capture_id, object, self.limits)?;
        let requested = attempt_precharge::requested(
            graph,
            activation,
            capture_id,
            source,
            object,
            self.limits.maximum_total_record_bytes,
        )?;
        let mut peak = storage::add(requested, runtime.retained_original_capture_buffer_bytes()?)?;
        peak = storage::add(peak, self.runtime_storage)?;
        for row in &self.plan.owners {
            peak = storage::add(peak, row.maximum_retained_bytes)?;
            peak = storage::add(peak, row.maximum_transient_bytes)?;
        }
        peak = storage::add(peak, self.owned_seal_storage()?)?;
        if peak > self.limits.maximum_total_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    pub(super) fn authenticate_prepared_attempt_storage(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        attempt: &OriginalLineageCaptureAttempt,
    ) -> Result<(), RuntimeError> {
        self.authenticate(
            runtime,
            &attempt.activation,
            &attempt.capture_id,
            &attempt.runtime_object,
            attempt.limits,
        )?;
        let selected_peak = self.plan.owners.iter().try_fold(0usize, |total, row| {
            storage::add(
                storage::add(total, row.maximum_retained_bytes)?,
                row.maximum_transient_bytes,
            )
        })?;
        let seal_storage = self.owned_seal_storage()?;
        let actual_attempt = storage::add(storage::attempt(attempt)?, seal_storage)?;
        let prior_attempts = runtime.retained_original_capture_buffer_bytes()?;
        let peak = storage::add(
            storage::add(actual_attempt, prior_attempts)?,
            storage::add(self.runtime_storage, selected_peak)?,
        )?;
        if peak > self.limits.maximum_total_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    pub(super) fn authenticate_owner_key(
        &self,
        index: usize,
        key: &crate::node_contract::NativeStateKey,
    ) -> Result<(), RuntimeError> {
        let expected = self
            .preflight
            .as_ref()
            .map(|preflight| {
                preflight
                    .owners()
                    .get(index)
                    .map(|owner| &owner.key)
                    .ok_or(RuntimeError::InvalidReceipt)
            })
            .transpose()?;
        authenticate_closed_original_key(key, expected)
    }

    pub(super) fn owner(
        &self,
        index: usize,
    ) -> Result<&CompleteOriginalOwnerCaptureGeometry, RuntimeError> {
        self.plan
            .owners
            .get(index)
            .ok_or(RuntimeError::InvalidReceipt)
    }
}

impl crate::node_contract::NodeRuntime {
    pub(crate) fn capture_requested_attempt_storage(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        capture_id: &Id,
        source: &OriginalLineageRuntimeRecord,
        object: &InputPayload,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.validate_activation(activation)?;
        attempt_precharge::requested(graph, activation, capture_id, source, object, maximum)
    }

    pub(crate) fn capture_registered_attempt_storage(&self) -> Result<usize, RuntimeError> {
        self.retained_original_capture_buffer_bytes()
    }

    pub(crate) fn capture_original_payload_storage(&self) -> Result<usize, RuntimeError> {
        self.original_lineage_capture_objects()
            .try_fold(0usize, |bytes, object| {
                storage::add(bytes, storage::payload(object)?)
            })
    }

    pub(crate) fn prepare_complete_capture_geometry(
        &self,
        activation: &WorldActivation,
        capture_id: &Id,
        runtime_object: &InputPayload,
        plan: CompleteOriginalCaptureGeometry,
        limits: NativeCaptureLimits,
    ) -> Result<PreparedCompleteOriginalCaptureGeometry, RuntimeError> {
        let original = self.scheduling_origin()?.source();
        original.authenticate_runtime_authority(
            &activation.record().world_binding_hash,
            &self.authority,
        )?;
        self.validate_activation(activation)?;
        capture_id
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let selected_record = plan
            .owners
            .iter()
            .map(|row| row.maximum_record_bytes)
            .max()
            .ok_or(RuntimeError::ResourceLimit)?;
        if selected_record != limits.maximum_record_bytes
            || runtime_object.bytes.len() > selected_record
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let selected_peak = plan
            .owners
            .iter()
            .try_fold(0usize, |total, row| {
                total
                    .checked_add(row.maximum_retained_bytes)?
                    .checked_add(row.maximum_transient_bytes)
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        // Core metadata copies and the original runtime object coexist with
        // every preallocated owner bank and the selected temporary extents.
        let retained_buffers = self.retained_original_capture_buffer_bytes()?;
        let runtime_storage = storage::payload(runtime_object)?;
        let peak = selected_record
            .checked_mul(42)
            .and_then(|bytes| bytes.checked_add(runtime_storage))
            .and_then(|bytes| bytes.checked_add(selected_peak))
            .and_then(|bytes| bytes.checked_add(retained_buffers))
            .ok_or(RuntimeError::ResourceLimit)?;
        if peak > limits.maximum_total_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        // Logical and actual owning-storage admission precedes hashing, even
        // when a reference is invalid. This source streams canonical::hash;
        // it does not allocate canonical::frame's optional payload copy.
        runtime_object
            .reference
            .verify(&runtime_object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(PreparedCompleteOriginalCaptureGeometry {
            original,
            collecting_plan: self
                .collecting
                .as_ref()
                .map(|graph| graph.plan().retained()),
            activation: activation.clone(),
            capture_id: capture_id.clone(),
            runtime_object: runtime_object.reference.clone(),
            runtime_storage,
            limits,
            plan,
            preflight: None,
            allocation_budget: None,
        })
    }

    pub(crate) fn prepare_complete_capture_geometry_with_preflight(
        &self,
        activation: &WorldActivation,
        capture_id: &Id,
        runtime_object: &InputPayload,
        plan: CompleteOriginalCaptureGeometry,
        limits: NativeCaptureLimits,
        preparation: (
            PreparedCompleteOriginalCapturePreflight,
            crate::node_state::CompleteCaptureAllocationBudget,
        ),
    ) -> Result<PreparedCompleteOriginalCaptureGeometry, RuntimeError> {
        let (preflight, allocation_budget) = preparation;
        allocation_budget.authenticate(limits.maximum_total_record_bytes)?;
        preflight.authenticate_runtime(self, activation, runtime_object)?;
        if plan.owners.len() != preflight.owners().len()
            || plan
                .owners
                .iter()
                .zip(preflight.owners())
                .any(|(row, original)| row != &original.geometry)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut geometry = self.prepare_complete_capture_geometry(
            activation,
            capture_id,
            runtime_object,
            plan,
            limits,
        )?;
        geometry.preflight = Some(preflight);
        geometry.allocation_budget = Some(allocation_budget);
        Ok(geometry)
    }

    pub(in crate::node_contract) fn charge_original_capture_activation_backings(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), RuntimeError> {
        for attempt in self.original_capture_attempts.values() {
            let facts = attempt
                .activation
                .retained_requested_storage_data(counter.maximum())?;
            // The attempt visitor already counts this independent record clone.
            // Its actual shared authority/preparation roots remain Core owners.
            counter.views(
                0,
                facts
                    .shared_allocations()
                    .map(|row| (row.identity(), row.requested_bytes())),
            )?;
        }
        Ok(())
    }

    pub(in crate::node_contract) fn retained_original_capture_buffer_bytes(
        &self,
    ) -> Result<usize, RuntimeError> {
        let mut total = 0usize;
        if let Some(history) = &self.original_capture_history {
            history.authenticate_target(&self.authority)?;
            total = storage::add(total, history.capture_owned_storage()?)?;
        }
        for (key, attempt) in &self.original_capture_attempts {
            if attempt.process != std::process::id() || attempt.thread != thread::current().id() {
                return Err(RuntimeError::ForeignAuthority);
            }
            attempt.original.authenticate_runtime_authority(
                &attempt.activation.record().world_binding_hash,
                &self.authority,
            )?;
            total = storage::add(total, key.allocated_capacity())?;
            total = storage::add(total, storage::attempt(attempt)?)?;
        }
        // Registry keys are separate from attempt.capture_id. The conservative
        // typed node bound includes one root even for an emptied map; accounting
        // observes lifetime storage and never removes an attempt or refunds IDs.
        let nodes = self
            .original_capture_attempts
            .len()
            .checked_add(1)
            .and_then(|count| {
                count.checked_mul(
                    crate::node_contract::NodeRuntime::capture_map_node_storage::<
                        Id,
                        Rc<OriginalLineageCaptureAttempt>,
                    >(),
                )
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        total = storage::add(
            total,
            std::mem::size_of_val(&self.original_capture_attempts),
        )?;
        storage::add(total, nodes)
    }
}

// Returned buffers remain in their preallocated world-owned slot on refusal.
// Logical record bounds govern framing; retained credits govern actual Vec
// capacity, including independent equal-hash buffers and unused allocation.
pub(super) fn charge_retained_capture_objects(
    captured: &super::super::InstalledOriginalLineageCapture,
    selected: NativeCaptureLimits,
    remaining: &mut NativeCaptureLimits,
) -> Result<(), RuntimeError> {
    let objects = std::iter::once(captured.native.state())
        .chain(captured.native.evidence())
        .chain(std::iter::once(&captured.journal));
    let mut count = 0usize;
    for object in objects {
        if object.bytes.len() > selected.maximum_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        count = count.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    }
    let capacity = storage::captured(captured)?;
    if count > selected.maximum_objects || capacity > selected.maximum_total_record_bytes {
        return Err(RuntimeError::ResourceLimit);
    }
    let objects = remaining
        .maximum_objects
        .checked_sub(count)
        .ok_or(RuntimeError::ResourceLimit)?;
    let bytes = remaining
        .maximum_total_record_bytes
        .checked_sub(capacity)
        .ok_or(RuntimeError::ResourceLimit)?;
    // Finite logical and allocated-capacity credit precedes digest validation.
    // canonical::hash streams this source's payload. Failure retains the
    // caller's original slot and credit.
    for object in std::iter::once(captured.native.state())
        .chain(captured.native.evidence())
        .chain(std::iter::once(&captured.journal))
    {
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    remaining.maximum_objects = objects;
    remaining.maximum_total_record_bytes = bytes;
    Ok(())
}

// Applies the same closed-shape conjunction to data from the actual callback.
// Original identity remains in the separately authenticated geometry/preflight.
fn authenticate_closed_original_key(
    key: &crate::node_contract::NativeStateKey,
    expected: Option<&crate::node_contract::NativeStateKey>,
) -> Result<(), RuntimeError> {
    if !key.schema.extensions.is_empty() || expected.is_some_and(|original| original != key) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod closed_original_key_controls {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn closed_key_rejects_nested_extensions_and_another_original_selection() {
        // These are inert key values, not native/source/capture authority.
        let key = crate::node_contract::NativeStateKey {
            implementation: Id::new("implementation").unwrap(),
            profile: Id::new("profile").unwrap(),
            schema: crucible_node_format::SchemaRef {
                id: Id::new("schema").unwrap(),
                version: 5,
                definition: canonical::content_ref(b"closed", "text/plain").unwrap(),
                extensions: Default::default(),
            },
        };
        assert_eq!(authenticate_closed_original_key(&key, Some(&key)), Ok(()));

        let mut foreign = key.clone();
        foreign.profile = Id::new("another-profile").unwrap();
        assert_eq!(
            authenticate_closed_original_key(&foreign, Some(&key)),
            Err(RuntimeError::InvalidReceipt)
        );

        let mut extended = key.clone();
        extended
            .schema
            .extensions
            .insert("unexpected".into(), serde_json::json!({"nested":[1,2,3]}));
        assert_eq!(
            authenticate_closed_original_key(&extended, Some(&extended)),
            Err(RuntimeError::InvalidReceipt)
        );
    }
}
