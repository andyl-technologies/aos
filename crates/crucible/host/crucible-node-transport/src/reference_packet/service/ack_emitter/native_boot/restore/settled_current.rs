//! Borrows the actual current Commit owner without recursive imported heaps.
//!
//! Every operational field stays represented. Mapping and physical Hold are
//! encoded once by closed outer graph roles after real pointer correspondence;
//! their immutable ancestry is validated through the signed bounded DAG.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct CommitHistory<'a>(&'a NativeCompleteRestoreAttempt);

impl NativeCompleteRestoreAttempt {
    pub(in crate::reference_packet::service) fn borrowed_restored_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.ensure_origin()?;
        Ok(CommitHistory(self))
    }
}

impl Serialize for CommitHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.ensure_origin().map_err(serde::ser::Error::custom)?;
        let NativeCompleteRestoreAttempt {
            creator,
            thread: _,
            original,
            launch,
            mapping: _,
            host_authority,
            kernel_binding,
            policy_binding,
            request,
            proof,
            context,
            capture_request,
            pending_control,
            prepared_model,
            physical_hold,
            gate_evidence,
            gate_data,
            receipt_body,
            receipt_result,
            receipt_started,
            completed_response,
            response_body,
            requested_model_bytes,
            verified,
            installation_started,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCurrentCommit17", 26)?;
        fields.serialize_field("schema", "source-private.native-current-restore-commit/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("launch", &launch.as_ref().map(crate::protocol_snapshot::restored_settled17::current_launch::BorrowedCurrentLaunch17))?;
        fields.serialize_field("mapping_role", "native-archived-protocol-mapping")?;
        fields.serialize_field("host_authority", host_authority)?;
        fields.serialize_field("kernel_binding", kernel_binding)?;
        fields.serialize_field("policy_binding", policy_binding)?;
        fields.serialize_field("request", request)?;
        fields.serialize_field("proof", proof)?;
        fields.serialize_field("context", context)?;
        fields.serialize_field("capture_request", capture_request)?;
        fields.serialize_field(
            "pending_control",
            &pending_control
                .as_ref()
                .map(|control| control.borrowed_settled_history_data()),
        )?;
        if let Some(model) = prepared_model {
            let hold = physical_hold.as_ref().ok_or_else(|| {
                serde::ser::Error::custom("current Commit model has no same hold")
            })?;
            fields.serialize_field(
                "prepared_model",
                &Some(
                    model
                        .borrowed_settled_model_data(hold)
                        .map_err(serde::ser::Error::custom)?,
                ),
            )?;
        } else {
            fields.serialize_field("prepared_model", &Option::<()>::None)?;
        }
        fields.serialize_field(
            "physical_hold_role",
            &physical_hold
                .as_ref()
                .map(|_| "native-complete-restore-physical-hold"),
        )?;
        fields.serialize_field(
            "gate_evidence",
            &gate_evidence.as_ref().map(|(reference, body)| {
                (reference, BorrowedCompactBytes::new(body), body.capacity())
            }),
        )?;
        fields.serialize_field("gate_data", gate_data)?;
        fields.serialize_field(
            "receipt_body",
            &(
                BorrowedCompactBytes::new(receipt_body),
                receipt_body.capacity(),
            ),
        )?;
        fields.serialize_field("receipt_result", receipt_result)?;
        fields.serialize_field("receipt_started", receipt_started)?;
        fields.serialize_field("completed_response", completed_response)?;
        fields.serialize_field(
            "response_body",
            &(
                BorrowedCompactBytes::new(response_body),
                response_body.capacity(),
            ),
        )?;
        fields.serialize_field("requested_model_bytes", requested_model_bytes)?;
        fields.serialize_field("verified", verified)?;
        fields.serialize_field("installation_started", installation_started)?;
        fields.end()
    }
}

impl NativeCompleteRestoreAttempt {
    /// Appends every actual current Commit field under the aggregate pass.
    ///
    /// # Errors
    /// Refuses foreign or borrowed owners, a mismatched model Hold or exhausted banks.
    pub(in crate::reference_packet::service) fn observe_current_settled17_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;
        self.ensure_origin()?;
        let Self {
            creator,
            thread: _,
            original,
            launch,
            mapping,
            host_authority,
            kernel_binding,
            policy_binding,
            request,
            proof,
            context,
            capture_request,
            pending_control,
            prepared_model,
            physical_hold,
            gate_evidence,
            gate_data,
            receipt_body,
            receipt_result,
            receipt_started,
            completed_response,
            response_body,
            requested_model_bytes,
            verified,
            installation_started,
        } = self;
        observer.observe(creator)?;
        observer.observe(original)?;
        if let Some(value) = launch {
            crate::protocol_snapshot::restored_settled17::current_launch::observe_native_launch17(
                value, observer,
            )?;
        }
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ArchivedMapping,
            mapping.as_ref(),
        )?;
        observer.observe(host_authority)?;
        observer.observe(kernel_binding)?;
        observer.observe(policy_binding)?;
        if let Some(value) = request {
            value.observe_current(observer)?;
        }
        if let Some(value) = proof {
            value.observe_current(observer)?;
        }
        if let Some(value) = context {
            value.observe_current(observer)?;
        }
        observer.observe(capture_request)?;
        if let Some(value) = pending_control {
            value.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(value) = prepared_model {
            let hold = physical_hold.as_ref().ok_or(ProviderError::Correlation(
                "current Commit model has no same Hold",
            ))?;
            value.observe_settled_history_metadata_data(hold, observer)?;
        }
        if let Some(hold) = physical_hold {
            observer.shared_original(
                crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredPhysicalHold,
                hold.as_ref(),
            )?;
        }
        if let Some((reference, body)) = gate_evidence {
            observer.observe(reference)?;
            observer.observe(body)?;
        }
        if let Some(value) = gate_data {
            value.observe_current(observer)?;
        }
        observer.observe(receipt_body)?;
        if let Some(value) = receipt_result {
            value.observe_current(observer)?;
        }
        observer.observe(receipt_started)?;
        observer.observe(completed_response)?;
        observer.observe(response_body)?;
        observer.observe(requested_model_bytes)?;
        observer.observe(verified)?;
        observer.observe(installation_started)
    }
}
