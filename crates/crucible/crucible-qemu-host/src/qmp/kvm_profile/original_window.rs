//! Original native window transactions without whole-node execution authority.
//!
//! A command opens or observes the kernel/CPU component only. Its original
//! request survives transport uncertainty, and reconciliation uses Query rather
//! than repeating Begin. Neither a stopped roster nor a frozen clock closes
//! input, devices, DMA or output publication.

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream, exchange_component,
};

const MAXIMUM_RETURNS: u32 = 65_536;
const MAXIMUM_VCPUS: u32 = 4096;
const MAXIMUM_STOP_BUDGET_NS: u64 = 5_000_000_000;

/// Selects one original source-owned window transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmOriginalWindowOperation {
    /// Opens the next generation at an already authenticated native clock cut.
    Begin,
    /// Seals entry and requests bounded original CPU/kernel stopping.
    Close,
    /// Observes the retained generation without guest entry or device drain.
    Query,
}

/// Encodes the existing original-window component namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalWindowRequest {
    /// Selects the component operation, never an ordinary QMP cont/stop pair.
    pub operation: QmpKvmOriginalWindowOperation,
    /// Identifies the actual original native window; Begin requires a successor.
    pub generation: u64,
    /// Supplies the exact Begin coordinate, otherwise zero.
    pub start_ns: u64,
    /// Supplies the exact immutable Begin ceiling, otherwise zero.
    pub end_ns: u64,
    /// Supplies the positive bounded Close allowance, otherwise zero.
    pub stop_budget_ns: u64,
}

/// Reports partial original kernel/CPU custody, without a common stop receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalWindowObservation {
    /// Selects the original-window response edition, exactly one.
    pub schema_version: u32,
    /// Selects kernel clock edition two on ARM or three on x86.
    pub clock_edition: u32,
    /// Reports the exact partial source coverage, respectively 228 or 159.
    pub clock_components: u32,
    /// Retains the original source window generation.
    pub generation: u64,
    /// Reports Empty=0, Running=1, Closing=2, Closed=3 or Unknown=4.
    pub phase: u32,
    /// Reports the original kernel clock sample in nanoseconds.
    pub current_ns: u64,
    /// Reports whether the actual kernel clock execution gate remains open.
    pub clock_active: bool,
    /// Counts actual original owners still inside native KVM_RUN.
    pub kernel_run_owners: u32,
    /// Reports actual frozen clock acknowledgment and zero KVM_RUN owners.
    pub clock_closed: bool,
    /// Reports the actual work-locked stopped cut of every original fixed CPU.
    pub original_cpus_stopped: bool,
    /// Counts source-owned lifetime return records, including unresolved rows.
    pub retained_returns: u32,
    /// Remains false because the component does not close original input roots.
    pub input_custody_known: bool,
    /// Remains false because device and DMA custody are not qualified here.
    pub device_custody_known: bool,
    /// Remains false because output publication custody is not qualified here.
    pub publication_custody_known: bool,
    /// Remains false because this component does not qualify a runnable node.
    pub profile_qualified: bool,
}

/// Retains a checked observation from an independently authenticated QMP peer.
///
/// Construction proves closed schema and request correlation only. It is not
/// native execution authority, a Ready attestation or a whole-world stop seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmOriginalWindowState {
    observed: QmpKvmOriginalWindowObservation,
}

impl QmpKvmOriginalWindowState {
    /// Borrows the partial observation and its explicit missing custody facts.
    pub fn observed(&self) -> &QmpKvmOriginalWindowObservation {
        &self.observed
    }
}

/// Retains one original component request across uncertain transport delivery.
///
/// This value does not own a native process or confer common-node authority.
/// The enclosing installed adapter must retain its authentic peer, operation,
/// input/output inventory and supervisor. A request is sent at most once through
/// this value; reconciliation observes the same generation without repeating
/// Begin or Close. Historical uncertainty remains sticky after a later Query.
#[derive(Debug)]
pub struct QmpKvmOriginalWindowTransaction {
    original: QmpKvmOriginalWindowRequest,
    sent: bool,
    uncertain_effects: bool,
    observation: Option<QmpKvmOriginalWindowState>,
}

impl QmpKvmOriginalWindowTransaction {
    /// Retains checked original Begin or Close bytes before transport effects.
    ///
    /// # Errors
    /// Refuses invalid coordinates, allowance or an observational Query request.
    pub fn prepare(request: QmpKvmOriginalWindowRequest) -> Result<Self, QmpError> {
        validate_original_window_request(&request)?;
        if request.operation == QmpKvmOriginalWindowOperation::Query {
            return Err(malformed_window(
                "Query is not an original mutation transaction",
            ));
        }
        Ok(Self {
            original: request,
            sent: false,
            uncertain_effects: false,
            observation: None,
        })
    }

    /// Borrows the unchanged original native request, including exact ceiling.
    pub fn original(&self) -> &QmpKvmOriginalWindowRequest {
        &self.original
    }

    /// Reports retained transport/native uncertainty; Query never clears it.
    pub fn uncertain_effects(&self) -> bool {
        self.uncertain_effects
    }

    /// Borrows the latest checked partial observation, if one was received.
    pub fn observation(&self) -> Option<&QmpKvmOriginalWindowState> {
        self.observation.as_ref()
    }

    /// Sends the retained original command once, before observing its outcome.
    ///
    /// The sent flag is recorded before the first transport call. Any error
    /// conservatively retains uncertainty, including QMP refusal after possible
    /// native mutation. Reusing this value cannot redispatch the mutation.
    ///
    /// # Errors
    /// Refuses repeated dispatch before I/O or returns actual native/transport
    /// failure. The caller retains this value and its owning native scope.
    pub fn dispatch_once<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmOriginalWindowState, QmpError> {
        if self.sent {
            return Err(malformed_window(
                "original window transaction was already sent",
            ));
        }
        self.sent = true;
        let result = client.control_native_kvm_original_window(&self.original);
        self.retain_result(result)
    }

    /// Observes the same original generation without redispatching its mutation.
    ///
    /// A received Query cannot recover missing input/output or kernel return
    /// custody and does not erase the original ambiguous delivery history.
    ///
    /// # Errors
    /// Refuses before original dispatch or returns actual native/transport
    /// failure while retaining the unchanged original request and uncertainty.
    /// An ambiguous original exchange fences its stream. Recovery then requires
    /// a replacement peer independently authenticated to the same owning child;
    /// a fresh socket or matching generation label alone supplies no authority.
    pub fn reconcile<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
    ) -> Result<QmpKvmOriginalWindowState, QmpError> {
        if !self.sent {
            return Err(malformed_window("original window transaction was not sent"));
        }
        let query = QmpKvmOriginalWindowRequest {
            operation: QmpKvmOriginalWindowOperation::Query,
            generation: self.original.generation,
            start_ns: 0,
            end_ns: 0,
            stop_budget_ns: 0,
        };
        let result = client.control_native_kvm_original_window(&query);
        self.retain_result(result)
    }

    fn retain_result(
        &mut self,
        result: Result<QmpKvmOriginalWindowState, QmpError>,
    ) -> Result<QmpKvmOriginalWindowState, QmpError> {
        match result {
            Ok(state) => {
                self.uncertain_effects |= state.observed.phase == 4;
                self.observation = Some(state);
                Ok(state)
            }
            Err(error) => {
                self.uncertain_effects = true;
                Err(error)
            }
        }
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Sends one original-window component command to the retained native peer.
    ///
    /// The caller authenticates installed source, executable, kernel and peer
    /// independently. Begin is not an idempotent retry: a lost reply requires
    /// Query of the same original generation, while keeping the original
    /// request and all resulting return/output custody.
    ///
    /// # Errors
    /// Refuses invalid geometry before I/O, native refusal, transport failure,
    /// changed generation/edition, impossible stopped facts or any whole-node
    /// qualification claim. A failure after sending does not imply no effects.
    pub fn control_native_kvm_original_window(
        &mut self,
        request: &QmpKvmOriginalWindowRequest,
    ) -> Result<QmpKvmOriginalWindowState, QmpError> {
        validate_original_window_request(request)?;
        exchange_component(self, QmpCommand::KvmOriginalWindow { request }, |value| {
            parse_original_window(request, value)
        })
    }
}

fn malformed_window(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmOriginalWindow,
        response: reason.to_owned(),
    }
}

fn validate_original_window_request(request: &QmpKvmOriginalWindowRequest) -> Result<(), QmpError> {
    let valid = match request.operation {
        QmpKvmOriginalWindowOperation::Begin => {
            request.generation != 0
                && request.start_ns < request.end_ns
                && request.end_ns <= i64::MAX as u64
                && request.stop_budget_ns == 0
        }
        QmpKvmOriginalWindowOperation::Close => {
            request.start_ns == 0
                && request.end_ns == 0
                && request.stop_budget_ns != 0
                && request.stop_budget_ns <= MAXIMUM_STOP_BUDGET_NS
        }
        QmpKvmOriginalWindowOperation::Query => {
            request.start_ns == 0 && request.end_ns == 0 && request.stop_budget_ns == 0
        }
    };
    if !valid {
        return Err(malformed_window("invalid original native window request"));
    }
    Ok(())
}

fn parse_original_window(
    request: &QmpKvmOriginalWindowRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmOriginalWindowState, QmpError> {
    let malformed = || malformed_window("inconsistent or qualified original native window");
    let observed: QmpKvmOriginalWindowObservation =
        serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    if observed.schema_version != 1
        || !matches!(
            (observed.clock_edition, observed.clock_components),
            (2, 228) | (3, 159)
        )
        || observed.generation != request.generation
        || observed.phase > 4
        || observed.current_ns > i64::MAX as u64
        || observed.kernel_run_owners > MAXIMUM_VCPUS
        || observed.retained_returns > MAXIMUM_RETURNS
        || observed.input_custody_known
        || observed.device_custody_known
        || observed.publication_custody_known
        || observed.profile_qualified
        || (observed.clock_closed && (observed.clock_active || observed.kernel_run_owners != 0))
        || (observed.original_cpus_stopped && observed.kernel_run_owners != 0)
        || (observed.phase == 0 && observed.generation != 0)
        || (observed.phase == 3 && (!observed.clock_closed || !observed.original_cpus_stopped))
    {
        return Err(malformed());
    }
    if request.operation == QmpKvmOriginalWindowOperation::Begin
        && (observed.phase != 1
            || !observed.clock_active
            || observed.clock_closed
            || observed.current_ns < request.start_ns
            || observed.current_ns > request.end_ns)
    {
        return Err(malformed());
    }
    Ok(QmpKvmOriginalWindowState { observed })
}

#[cfg(test)]
#[path = "original_window_tests.rs"]
mod tests;
