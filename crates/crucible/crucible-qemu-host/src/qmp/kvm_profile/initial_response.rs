//! Original first-response callback submission and retained-result polling.
//!
//! The source lifetime RUN row owns this result independently of later More
//! fragments. These typed observations neither admit guest execution nor close
//! devices, input/output or native continuation state.
//!
//! This modeled wire example carries correlation and retained callback facts,
//! without execution permission:
//!
//! ```json
//! {"execute":"x-crucible-kvm-initial-response","arguments":{
//!   "operation":"poll","record-index":2,"generation":3,"expected-invocation":4}}
//! {"return":{"schema-version":1,"record-index":2,"generation":3,
//!   "expected-invocation":4,"vcpu-index":0,"native-vcpu-id":0,
//!   "exit-sequence":5,"service-id":6,"submitted":true,"completed":true,
//!   "result-known":true,"callback-result":0,"uncertain-effects":false,
//!   "opaque-effects":false,"device-closure":false,"input-custody":false,
//!   "output-custody":false,"profile-qualified":false}}
//! ```

mod transaction;

pub use transaction::QmpKvmInitialResponseTransaction;

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream, exchange_component,
};

/// Selects the original initial callback or its retained result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmInitialResponseOperation {
    /// Submits the first original callback into its enrolled paused CPU slot.
    Submit,
    /// Collects or recovers its retained result without another submission.
    Poll,
}

/// Correlates a callback operation with its original lifetime RUN-return row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmInitialResponseRequest {
    /// Selects original callback submission or retained-result observation.
    pub operation: QmpKvmInitialResponseOperation,
    /// Identifies its actual source-owned lifetime return row.
    pub record_index: u32,
    /// Identifies the original retained window generation.
    pub generation: u64,
    /// Identifies the originally reserved kernel RUN invocation.
    pub expected_invocation: u64,
}

/// Copies the actual source callback journal without whole-node authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmInitialResponseObservation {
    /// Identifies the independent initial callback edition, exactly one.
    pub schema_version: u32,
    /// Identifies the original lifetime return row.
    pub record_index: u32,
    /// Identifies the original retained window generation.
    pub generation: u64,
    /// Identifies the originally reserved kernel RUN invocation.
    pub expected_invocation: u64,
    /// Identifies the original immutable QEMU CPU roster position.
    pub vcpu_index: u32,
    /// Identifies the original native CPU; BSP zero is valid.
    pub native_vcpu_id: u64,
    /// Identifies the original first response fragment, not a later More.
    pub exit_sequence: u64,
    /// Identifies the admitted original paused callback slot.
    pub service_id: u64,
    /// Records actual admission of the original callback slot.
    pub submitted: bool,
    /// Records that the original actual handler returned a retained result.
    pub completed: bool,
    /// Records collection of the same original result from its paused CPU slot.
    pub result_known: bool,
    /// Retains the signed original handler result; zero until completion.
    pub callback_result: i32,
    /// Retains original native or transport uncertainty.
    pub uncertain_effects: bool,
    /// Retains the original owner opacity.
    pub opaque_effects: bool,
    /// Remains false because this mechanism does not close devices or DMA.
    pub device_closure: bool,
    /// Remains false because no original common input cut is authenticated here.
    pub input_custody: bool,
    /// Remains false because no output-publication custody is established here.
    pub output_custody: bool,
    /// Remains false because these callback facts cannot qualify a node.
    pub profile_qualified: bool,
}

/// Retains a checked original callback reply without execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmInitialResponseState {
    observed: QmpKvmInitialResponseObservation,
}

impl QmpKvmInitialResponseState {
    /// Borrows the retained original callback facts without advancing the source.
    pub fn observed(&self) -> &QmpKvmInitialResponseObservation {
        &self.observed
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Submits or observes one original first callback at its source-owned cut.
    ///
    /// The owning controller must retain the actual request before transport.
    /// Recovery uses Poll and never silently repeats Submit. Ambiguous exchanges
    /// fence this ID-less channel before any further original observation.
    ///
    /// # Errors
    /// Refuses invalid scope, native command failure, malformed or foreign facts,
    /// unsupported schema or closure promotion. A framed native refusal remains
    /// usable; other exchange failures require authenticated same-child reconnect.
    pub fn control_native_kvm_initial_response(
        &mut self,
        request: &QmpKvmInitialResponseRequest,
    ) -> Result<QmpKvmInitialResponseState, QmpError> {
        validate_request(request)?;
        exchange_component(self, QmpCommand::KvmInitialResponse { request }, |value| {
            parse_response(request, value)
        })
    }
}

fn malformed(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmInitialResponse,
        response: reason.into(),
    }
}

fn validate_request(request: &QmpKvmInitialResponseRequest) -> Result<(), QmpError> {
    if request.record_index >= 65_536 || request.generation == 0 || request.expected_invocation == 0
    {
        return Err(malformed(
            "initial callback requires its bounded original RUN row",
        ));
    }
    Ok(())
}

fn parse_response(
    request: &QmpKvmInitialResponseRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmInitialResponseState, QmpError> {
    let observed: QmpKvmInitialResponseObservation = serde_json::from_value(value.clone())
        .map_err(|_| malformed("initial callback requires its closed edition-one schema"))?;
    if observed.schema_version != 1
        || observed.record_index != request.record_index
        || observed.generation != request.generation
        || observed.expected_invocation != request.expected_invocation
        || observed.vcpu_index >= 4096
        || observed.device_closure
        || observed.input_custody
        || observed.output_custody
        || observed.profile_qualified
        || observed.result_known && !observed.completed
        || observed.completed && !observed.submitted
        || !observed.completed && observed.callback_result != 0
        || observed.submitted && (observed.exit_sequence == 0 || observed.service_id == 0)
        || !observed.submitted && (observed.exit_sequence != 0 || observed.service_id != 0)
        || request.operation == QmpKvmInitialResponseOperation::Submit && !observed.submitted
    {
        return Err(malformed(
            "initial callback changed its original scope or actual result",
        ));
    }
    Ok(QmpKvmInitialResponseState { observed })
}

#[cfg(test)]
#[path = "initial_response_tests.rs"]
mod tests;
