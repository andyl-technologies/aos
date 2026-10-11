//! Canonical kernel-owned response fragments and bounded original input echoes.
//!
//! The native payload classification is preserved. An unknown original-request
//! echo contains input custody only; it cannot establish a native fragment,
//! callback result, completion or execution authority.
//!
//! This modeled Query frame observes the original row without carrying bytes
//! for a device callback:
//!
//! ```json
//! {"execute":"x-crucible-kvm-response-bytes","arguments":{
//!   "operation":"query","record-index":2,"generation":3,
//!   "expected-invocation":4,"operation-id":0,"expected-sequence":0}}
//! ```

mod completion;
mod payload;
pub use completion::{QmpKvmCompletionSummary, QmpKvmCompletionTransaction};
mod wire;

pub use wire::{QmpKvmResponseBytesObservation, QmpKvmResponseBytesPayloadKind};

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream, exchange_component,
};

/// Selects observational Query or one original kernel callback completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmResponseBytesOperation {
    /// Observes the current native fragment without consumption or dispatch.
    Query,
    /// Completes the source-retained handler reply under its original identity.
    Complete,
}

/// Correlates the closed native byte namespace with its original RUN row.
///
/// Complete carries no caller-provided response bytes: the actual stopped
/// handler and kernel own them. Exact native last-operation recovery must retain
/// this request before dispatch and cannot admit another original prematurely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmResponseBytesRequest {
    /// Selects current observation or original completion.
    pub operation: QmpKvmResponseBytesOperation,
    /// Identifies the original lifetime RUN-return row.
    pub record_index: u32,
    /// Identifies the original closed clock generation.
    pub generation: u64,
    /// Identifies the originally reserved kernel invocation.
    pub expected_invocation: u64,
    /// Identifies the original consecutive completion; zero for Query.
    pub operation_id: u64,
    /// Identifies the original fragment; zero for Query.
    pub expected_sequence: u64,
}

/// Retains one bounded checked native fragment or distinctly classified echo.
///
/// Compatibility fields describe compiled userspace, not the running kernel or
/// devices. These observations never establish a common grant or continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpKvmResponseBytesState {
    observed: QmpKvmResponseBytesObservation,
    bytes: Vec<u8>,
}

impl QmpKvmResponseBytesState {
    /// Borrows the unchanged classification and original scalar facts.
    pub fn observed(&self) -> &QmpKvmResponseBytesObservation {
        &self.observed
    }

    /// Borrows canonical native bytes or explicitly classified original input.
    ///
    /// Callers must inspect [`QmpKvmResponseBytesPayloadKind`] before treating
    /// these bytes as native output or current response geometry.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies bounded retained facts only when all host copy credit is available.
    ///
    /// # Errors
    /// Returns unavailable host allocation credit without altering the original
    /// native result or its byte custody.
    pub(crate) fn try_copy(&self) -> Result<Self, QmpError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.bytes.len())
            .map_err(|_| malformed("retained native byte copy credit is unavailable"))?;
        bytes.extend_from_slice(&self.bytes);
        let observed = QmpKvmResponseBytesObservation {
            schema_version: self.observed.schema_version,
            payload_kind: self.observed.payload_kind,
            components: self.observed.components,
            kernel_capability: self.observed.kernel_capability,
            native_abi_size: self.observed.native_abi_size,
            maximum_data_bytes: self.observed.maximum_data_bytes,
            clock_edition: self.observed.clock_edition,
            clock_components: self.observed.clock_components,
            qemu_build_id: copy_string(&self.observed.qemu_build_id)?,
            qemu_source_hash: copy_string(&self.observed.qemu_source_hash)?,
            record_index: self.observed.record_index,
            vcpu_index: self.observed.vcpu_index,
            native_vcpu_id: self.observed.native_vcpu_id,
            generation: self.observed.generation,
            invocation: self.observed.invocation,
            operation_id: self.observed.operation_id,
            expected_sequence: self.observed.expected_sequence,
            expected_revision: self.observed.expected_revision,
            pending_sequence: self.observed.pending_sequence,
            consumed_sequence: self.observed.consumed_sequence,
            revision: self.observed.revision,
            native_phase: self.observed.native_phase,
            callback_result: self.observed.callback_result,
            native_errno: self.observed.native_errno,
            reason: self.observed.reason,
            address: self.observed.address,
            data_offset: self.observed.data_offset,
            length: self.observed.length,
            count: self.observed.count,
            size: self.observed.size,
            direction: self.observed.direction,
            data_length: self.observed.data_length,
            data_base64: copy_string(&self.observed.data_base64)?,
            result_known: self.observed.result_known,
            uncertain_effects: self.observed.uncertain_effects,
            opaque_effects: self.observed.opaque_effects,
            kernel_source_qualified: self.observed.kernel_source_qualified,
            device_closure: self.observed.device_closure,
            input_custody: self.observed.input_custody,
            output_custody: self.observed.output_custody,
            profile_qualified: self.observed.profile_qualified,
        };
        Ok(Self { observed, bytes })
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Observes or completes the source-owned canonical response-byte original.
    ///
    /// The owning process controller must reserve original request, reply and
    /// history credit before Complete. A well-formed unknown input echo remains
    /// distinct from native-result facts and retains uncertainty.
    ///
    /// # Errors
    /// Refuses invalid original scope, unsupported component/schema/source
    /// identities, malformed geometry or encoding, false native results and
    /// whole-node capability promotion. Ambiguity fences the ID-less channel.
    pub fn control_native_kvm_response_bytes(
        &mut self,
        request: &QmpKvmResponseBytesRequest,
    ) -> Result<QmpKvmResponseBytesState, QmpError> {
        validate_request(request)?;
        exchange_component(self, QmpCommand::KvmResponseBytes { request }, |value| {
            parse_response(request, value)
        })
    }
}

fn malformed(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmResponseBytes,
        response: reason.into(),
    }
}

fn validate_request(request: &QmpKvmResponseBytesRequest) -> Result<(), QmpError> {
    let original =
        request.record_index < 65_536 && request.generation > 0 && request.expected_invocation > 0;
    let operation = match request.operation {
        QmpKvmResponseBytesOperation::Query => {
            request.operation_id == 0 && request.expected_sequence == 0
        }
        QmpKvmResponseBytesOperation::Complete => {
            request.operation_id > 0
                && request.expected_sequence > 0
                && request.expected_sequence < u64::MAX
        }
    };
    if !original || !operation {
        return Err(malformed(
            "canonical bytes require their bounded original scope",
        ));
    }
    Ok(())
}

fn parse_response(
    request: &QmpKvmResponseBytesRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmResponseBytesState, QmpError> {
    parse_response_into(request, value, Vec::new())
}

fn parse_response_into(
    request: &QmpKvmResponseBytesRequest,
    value: &serde_json::Value,
    buffer: Vec<u8>,
) -> Result<QmpKvmResponseBytesState, QmpError> {
    // Bound native strings before allocating their owned copies. Deserializing
    // the borrowed Value also avoids cloning unrelated untrusted reply fields.
    if value
        .get("data-base64")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|encoded| encoded.len() > 5464)
    {
        return Err(malformed(
            "canonical byte payload exceeds its native capacity",
        ));
    }
    if ["qemu-build-id", "qemu-source-hash"]
        .into_iter()
        .any(|field| {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_none_or(|identity| identity.len() != 64)
        })
        || value
            .get("payload-kind")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|kind| kind.len() > 16)
    {
        return Err(malformed(
            "canonical native identities exceed their closed schema",
        ));
    }
    let observed = QmpKvmResponseBytesObservation::deserialize(value)
        .map_err(|_| malformed("canonical bytes require their closed edition-one schema"))?;
    wire::validate(request, &observed)?;
    let bytes = payload::decode_into(&observed.data_base64, buffer)?;
    payload::validate(&observed, &bytes)?;
    Ok(QmpKvmResponseBytesState { observed, bytes })
}

#[cfg(test)]
#[path = "response_bytes_tests.rs"]
mod tests;

fn copy_string(value: &str) -> Result<String, QmpError> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| malformed("retained native fact copy credit is unavailable"))?;
    copied.push_str(value);
    Ok(copied)
}
