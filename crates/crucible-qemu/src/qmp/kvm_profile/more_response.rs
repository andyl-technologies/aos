//! Original paused callbacks for authenticated native More fragments.
//!
//! This namespace handles a fragment produced by one original kernel completion,
//! not another RUN. Its per-CPU native result cache is distinct from the initial
//! callback's lifetime RUN-row cache. An owning controller retains its result
//! before admitting another callback or completion that can replace that cache.
//!
//! This modeled request correlates a checked native More fragment; it carries no
//! execution permission:
//!
//! ```json
//! {"execute":"x-crucible-kvm-response-service","arguments":{
//!   "operation":"poll","vcpu-index":0,"completion-id":1,"exit-sequence":6}}
//! {"return":{"schema-version":1,"vcpu-index":0,"kernel-vcpu-id":0,
//!   "completion-id":1,"exit-sequence":6,"service-id":7,"submitted":true,
//!   "completed":true,"result-known":true,"callback-result":0,
//!   "uncertain-effects":false,"opaque-effects":false,"device-closure":false,
//!   "input-custody":false,"output-custody":false,"profile-qualified":false}}
//! ```

mod transaction;
pub use transaction::QmpKvmMoreResponseTransaction;

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream, exchange_component,
};

/// Selects one original More callback or retained-result observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmMoreResponseOperation {
    /// Admits the original More callback into its enrolled paused CPU slot.
    Submit,
    /// Observes or collects the original result without repeating its callback.
    Poll,
}

/// Correlates a callback with the original native completion and More fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmMoreResponseRequest {
    /// Selects the original submission or result observation.
    pub operation: QmpKvmMoreResponseOperation,
    /// Identifies the original immutable QEMU roster position.
    pub vcpu_index: u32,
    /// Identifies the original known kernel completion producing More.
    pub completion_id: u64,
    /// Identifies the exact native More fragment from that completion.
    pub exit_sequence: u64,
}

/// Retains original More callback facts without whole-node authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmMoreResponseObservation {
    /// Identifies the independent paused-service schema, exactly one.
    pub schema_version: u32,
    /// Identifies the original immutable QEMU roster position.
    pub vcpu_index: u32,
    /// Identifies the original native CPU; BSP zero is valid.
    pub kernel_vcpu_id: u64,
    /// Identifies the original known completion that produced More.
    pub completion_id: u64,
    /// Identifies the resulting original More fragment.
    pub exit_sequence: u64,
    /// Identifies the admitted original paused callback slot.
    pub service_id: u64,
    /// Records actual admission of the original callback slot.
    pub submitted: bool,
    /// Records the retained actual handler return.
    pub completed: bool,
    /// Records collection of that original return from the paused CPU slot.
    pub result_known: bool,
    /// Retains the signed original handler result; zero before completion.
    pub callback_result: i32,
    /// Retains the original effect uncertainty.
    pub uncertain_effects: bool,
    /// Retains the original native owner opacity.
    pub opaque_effects: bool,
    /// Remains false because this mechanism does not close devices or DMA.
    pub device_closure: bool,
    /// Remains false because no common input cut is authenticated here.
    pub input_custody: bool,
    /// Remains false because no common output custody is established here.
    pub output_custody: bool,
    /// Remains false because these callback facts cannot qualify a node.
    pub profile_qualified: bool,
}

/// Retains a checked original More callback reply without execution permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmMoreResponseState {
    observed: QmpKvmMoreResponseObservation,
}

impl QmpKvmMoreResponseState {
    /// Borrows the unchanged original callback facts.
    pub fn observed(&self) -> &QmpKvmMoreResponseObservation {
        &self.observed
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Submits or observes one original More callback without another guest RUN.
    ///
    /// An owning controller must retain the actual native completion and bytes
    /// before Submit, and preserve the collected result before another original
    /// can replace the per-CPU source cache.
    ///
    /// # Errors
    /// Refuses invalid original scope, native or transport failure, malformed or
    /// foreign facts, unsupported schema and false closure promotion. Ambiguity
    /// fences the ID-less channel before any further operation.
    pub fn control_native_kvm_more_response(
        &mut self,
        request: &QmpKvmMoreResponseRequest,
    ) -> Result<QmpKvmMoreResponseState, QmpError> {
        validate_request(request)?;
        exchange_component(self, QmpCommand::KvmMoreResponse { request }, |value| {
            parse_response(request, value)
        })
    }
}

fn malformed(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmMoreResponse,
        response: reason.into(),
    }
}

fn validate_request(request: &QmpKvmMoreResponseRequest) -> Result<(), QmpError> {
    if request.vcpu_index >= 4096 || request.completion_id == 0 || request.exit_sequence == 0 {
        return Err(malformed(
            "More callback requires its bounded original native fragment",
        ));
    }
    Ok(())
}

fn parse_response(
    request: &QmpKvmMoreResponseRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmMoreResponseState, QmpError> {
    let observed = QmpKvmMoreResponseObservation::deserialize(value)
        .map_err(|_| malformed("More callback requires its closed edition-one schema"))?;
    if observed.schema_version != 1
        || observed.vcpu_index != request.vcpu_index
        || observed.completion_id != request.completion_id
        || observed.exit_sequence != request.exit_sequence
        || observed.device_closure
        || observed.input_custody
        || observed.output_custody
        || observed.profile_qualified
        || observed.result_known && !observed.completed
        || observed.completed && !observed.submitted
        || !observed.completed && observed.callback_result != 0
        || observed.submitted && observed.service_id == 0
        || !observed.submitted && observed.service_id != 0
        || request.operation == QmpKvmMoreResponseOperation::Submit && !observed.submitted
    {
        return Err(malformed(
            "More callback changed its original scope or actual result",
        ));
    }
    Ok(QmpKvmMoreResponseState { observed })
}

#[cfg(test)]
#[path = "more_response_tests.rs"]
mod tests;
