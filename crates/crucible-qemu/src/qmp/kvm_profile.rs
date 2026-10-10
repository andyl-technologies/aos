//! Native accelerator observation, separated from deterministic SIM control.
//!
//! Standard `query-kvm` proves only what the connected emulator reports about
//! its accelerator. It grants no clock, native pause, custody or capture claim.

mod exchange;
mod initial_response;
mod original_inventory;
mod original_return;
mod original_window;
mod userspace;
mod v3;

pub use initial_response::{
    QmpKvmInitialResponseObservation, QmpKvmInitialResponseOperation, QmpKvmInitialResponseRequest,
    QmpKvmInitialResponseState, QmpKvmInitialResponseTransaction,
};

pub use original_inventory::{
    QmpKvmOriginalReturnIdentity, QmpKvmOriginalReturnsObservation, QmpKvmOriginalReturnsRequest,
    QmpKvmOriginalReturnsState,
};
pub use original_return::{
    QmpKvmOriginalAckTransaction, QmpKvmOriginalReturnObservation, QmpKvmOriginalReturnOperation,
    QmpKvmOriginalReturnRequest, QmpKvmOriginalReturnState,
};

pub use original_window::{
    QmpKvmOriginalWindowObservation, QmpKvmOriginalWindowOperation, QmpKvmOriginalWindowRequest,
    QmpKvmOriginalWindowState, QmpKvmOriginalWindowTransaction,
};
pub use userspace::{
    QmpKvmUserspaceComponentState, QmpKvmUserspaceExitPhase, QmpKvmUserspaceExitRecord,
    QmpKvmUserspaceInventory,
};
pub use v3::QmpKvmClockV3ComponentState;

use exchange::exchange_component;
use serde::{Deserialize, Serialize};

use super::{QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream};

/// Observes standard QEMU native KVM acceleration status without profile authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QmpKvmAccelerationState {
    /// Reports that this QEMU build contains native KVM acceleration support.
    pub present: bool,
    /// Reports that this actual machine is using KVM rather than TCG or SIM.
    pub enabled: bool,
}

/// Selects one operation in the experimental native clock component ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmClockOperation {
    /// Opens one consecutive generation at the retained frozen coordinate.
    Begin,
    /// Freezes projection and waits within the supplied native run-owner allowance.
    Freeze,
    /// Observes the actual kernel domain without changing its state.
    Query,
    /// Advances an acknowledged frozen domain to an explicit boundary.
    Step,
}

/// Encodes a component transaction rather than a CNP node execution grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmClockRequest {
    /// Selects the native component operation.
    pub operation: QmpKvmClockOperation,
    /// Identifies the original retained window generation, except for read-only query.
    pub window_generation: u64,
    /// Supplies the begin or frozen step coordinate in nanoseconds.
    pub start_ns: u64,
    /// Supplies the immutable begin ceiling in nanoseconds.
    pub end_ns: u64,
    /// Bounds native run-owner waiting; freeze accepts at most five seconds.
    pub stop_budget_ns: u64,
}

/// Reports actual partial kernel mediation without complete node authority.
///
/// Each component command checks its own fixed schema and coverage bitmap.
/// `native_owners_stopped` excludes pending device, interrupt and exit custody.
/// A successful response must therefore retain `profile_qualified == false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmClockComponentState {
    /// Identifies the command-specific fixed component response schema.
    pub schema_version: u32,
    /// Identifies the retained actual kernel window generation.
    pub window_generation: u64,
    /// Reports the actual projected or frozen logical coordinate.
    pub current_ns: u64,
    /// Reports the actual retained begin coordinate.
    pub start_ns: u64,
    /// Reports the actual immutable begin ceiling.
    pub end_ns: u64,
    /// Multiplies elapsed host nanoseconds in the admitted rational projection.
    pub numerator: u32,
    /// Divides elapsed host nanoseconds in the admitted rational projection.
    pub denominator: u32,
    /// Reports the command-specific exact partial native coverage bitmap.
    pub kernel_components: u32,
    /// Counts owners inside KVM_RUN, including counted completion reentry.
    ///
    /// Outstanding userspace MMIO/PIO disposition after return is not counted.
    pub run_owners: u32,
    /// Reports whether native execution admission is open for the component.
    pub active: bool,
    /// Reports only kernel RUN owners closed, excluding other state domains.
    pub native_owners_stopped: bool,
    /// Remains false while clocks, timers, interrupts and device custody are incomplete.
    pub profile_qualified: bool,
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Queries actual acceleration without inferring clock or stopping guarantees.
    ///
    /// The caller must authenticate the child executable and QMP peer separately.
    /// This read-only command does not enable KVM, change deterministic launch
    /// admission or authorize a native run window.
    ///
    /// # Errors
    /// Reports the bounded QMP transport/command failure or an invalid closed
    /// response, including a claim that absent KVM support is enabled.
    pub fn query_native_kvm_acceleration(&mut self) -> Result<QmpKvmAccelerationState, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryKvm)?;
        parse_acceleration(&response.value)
    }
    /// Executes a bounded experimental native clock component transaction.
    ///
    /// This command requires an authenticated source-patched QEMU child with the
    /// component configured before vCPU creation. Neither successful control nor
    /// the returned native run-owner count authorizes a CNP node or publication.
    /// Stock QEMU, SIM and unpatched host kernels must refuse the operation.
    ///
    /// # Errors
    /// Rejects invalid request bounds, bounded transport failures, native refusal,
    /// incoherent responses and any claim of complete profile qualification.
    pub fn control_native_kvm_clock_component(
        &mut self,
        request: &QmpKvmClockRequest,
    ) -> Result<QmpKvmClockComponentState, QmpError> {
        validate_clock_request(request)?;
        let response = self.send_command_return(QmpCommand::KvmClockComponent { request })?;
        parse_clock_component(request, &response.value)
    }
}

fn parse_acceleration(value: &serde_json::Value) -> Result<QmpKvmAccelerationState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryKvm,
        response: "query-kvm must contain exactly coherent present/enabled booleans".to_owned(),
    };
    let state: QmpKvmAccelerationState =
        serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    if state.enabled && !state.present {
        return Err(malformed());
    }
    Ok(state)
}

fn malformed_component_for(command: QmpCommandKind, reason: &str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command,
        response: reason.to_owned(),
    }
}

fn validate_clock_request(request: &QmpKvmClockRequest) -> Result<(), QmpError> {
    validate_clock_request_for(request, QmpCommandKind::KvmClockComponent)
}

fn validate_clock_request_for(
    request: &QmpKvmClockRequest,
    command: QmpCommandKind,
) -> Result<(), QmpError> {
    let malformed = |reason| malformed_component_for(command, reason);
    if request.start_ns > i64::MAX as u64 || request.end_ns > i64::MAX as u64 {
        return Err(malformed(
            "native component coordinate exceeds the QEMU timeline",
        ));
    }
    match request.operation {
        QmpKvmClockOperation::Begin
            if request.window_generation == 0 || request.end_ns <= request.start_ns =>
        {
            Err(malformed(
                "native begin needs a generation and increasing ceiling",
            ))
        }
        QmpKvmClockOperation::Freeze
            if request.stop_budget_ns == 0 || request.stop_budget_ns > 5_000_000_000 =>
        {
            Err(malformed(
                "native freeze allowance must be within five seconds",
            ))
        }
        _ => Ok(()),
    }
}

fn parse_clock_component(
    request: &QmpKvmClockRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmClockComponentState, QmpError> {
    parse_clock_component_edition(request, value, QmpCommandKind::KvmClockComponent, 1, 7)
}

fn parse_clock_component_edition(
    request: &QmpKvmClockRequest,
    value: &serde_json::Value,
    command: QmpCommandKind,
    schema_version: u32,
    kernel_components: u32,
) -> Result<QmpKvmClockComponentState, QmpError> {
    let malformed = |reason| malformed_component_for(command, reason);
    let state: QmpKvmClockComponentState = serde_json::from_value(value.clone())
        .map_err(|_| malformed("native component response does not match its closed schema"))?;
    if state.schema_version != schema_version
        || state.kernel_components != kernel_components
        || state.numerator == 0
        || state.denominator == 0
        || state.profile_qualified
        || state.current_ns > i64::MAX as u64
        || state.start_ns > i64::MAX as u64
        || state.end_ns > i64::MAX as u64
        || (state.native_owners_stopped && (state.active || state.run_owners != 0))
        || (state.active && (state.current_ns < state.start_ns || state.current_ns > state.end_ns))
    {
        return Err(malformed(
            "native component coverage, clock or ownership is incoherent",
        ));
    }
    if request.operation != QmpKvmClockOperation::Query
        && state.window_generation != request.window_generation
    {
        return Err(malformed(
            "native response changed the original window generation",
        ));
    }
    match request.operation {
        QmpKvmClockOperation::Begin
            if !state.active
                || state.start_ns != request.start_ns
                || state.end_ns != request.end_ns =>
        {
            return Err(malformed("native begin changed its immutable bounds"));
        }
        QmpKvmClockOperation::Freeze if state.active || !state.native_owners_stopped => {
            return Err(malformed(
                "native freeze did not acknowledge its actual RUN owners",
            ));
        }
        QmpKvmClockOperation::Step
            if state.active
                || !state.native_owners_stopped
                || state.current_ns != request.start_ns =>
        {
            return Err(malformed("native frozen step was not applied exactly"));
        }
        _ => {}
    }
    Ok(state)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These kvm profile tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stock_acceleration_observation_grants_no_extra_guarantees() {
        assert_eq!(
            parse_acceleration(&json!({"present":true,"enabled":false})).unwrap(),
            QmpKvmAccelerationState {
                present: true,
                enabled: false
            }
        );
        assert!(parse_acceleration(&json!({"present":false,"enabled":true})).is_err());
        assert!(
            parse_acceleration(&json!({"present":true,"enabled":true,"controller-clock":true}))
                .is_err()
        );
        assert!(parse_acceleration(&json!({"present":true,"enabled":"true"})).is_err());
    }

    #[test]
    fn native_namespace_encodes_one_closed_read_only_standard_command() {
        assert_eq!(QmpCommand::QueryKvm.kind(), QmpCommandKind::QueryKvm);
        assert_eq!(
            QmpCommand::QueryKvm.request(),
            json!({"execute":"query-kvm"})
        );
    }
    fn component_response() -> serde_json::Value {
        json!({
            "schema-version": 1, "window-generation": 9,
            "current-ns": 20, "start-ns": 10, "end-ns": 30,
            "numerator": 1, "denominator": 1, "kernel-components": 7,
            "run-owners": 0, "active": false,
            "native-owners-stopped": true, "profile-qualified": false,
        })
    }

    #[test]
    fn partial_native_closure_cannot_claim_complete_profile_or_changed_generation() {
        let request = QmpKvmClockRequest {
            operation: QmpKvmClockOperation::Freeze,
            window_generation: 9,
            start_ns: 0,
            end_ns: 0,
            stop_budget_ns: 1_000_000,
        };
        let response = component_response();
        assert!(parse_clock_component(&request, &response).is_ok());

        for (field, replacement) in [
            ("profile-qualified", json!(true)),
            ("window-generation", json!(10)),
            ("run-owners", json!(1)),
            ("active", json!(true)),
            ("kernel-components", json!(15)),
        ] {
            let mut forged = response.clone();
            forged[field] = replacement;
            assert!(parse_clock_component(&request, &forged).is_err(), "{field}");
        }
    }

    #[test]
    fn native_begin_and_step_bind_the_original_coordinate() {
        let begin = QmpKvmClockRequest {
            operation: QmpKvmClockOperation::Begin,
            window_generation: 9,
            start_ns: 10,
            end_ns: 30,
            stop_budget_ns: 0,
        };
        let mut response = component_response();
        response["active"] = json!(true);
        response["native-owners-stopped"] = json!(false);
        assert!(parse_clock_component(&begin, &response).is_ok());
        response["end-ns"] = json!(31);
        assert!(parse_clock_component(&begin, &response).is_err());

        let step = QmpKvmClockRequest {
            operation: QmpKvmClockOperation::Step,
            start_ns: 40,
            ..begin
        };
        response = component_response();
        assert!(parse_clock_component(&step, &response).is_err());
        response["current-ns"] = json!(40);
        assert!(parse_clock_component(&step, &response).is_ok());
    }

    #[test]
    fn native_control_rejects_unbounded_or_unrepresentable_requests_before_io() {
        let mut request = QmpKvmClockRequest {
            operation: QmpKvmClockOperation::Freeze,
            window_generation: 1,
            start_ns: 0,
            end_ns: 0,
            stop_budget_ns: 0,
        };
        assert!(validate_clock_request(&request).is_err());
        request.stop_budget_ns = 5_000_000_001;
        assert!(validate_clock_request(&request).is_err());
        request.stop_budget_ns = 5_000_000_000;
        assert!(validate_clock_request(&request).is_ok());
        request.start_ns = u64::MAX;
        assert!(validate_clock_request(&request).is_err());
    }
}
