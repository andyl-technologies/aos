//! Correlated reset completion for one exact stopped selectable request.
//!
//! An empty command acknowledgement admits the operation. Only the dedicated
//! terminal event proves that the retained request was abandoned after reset;
//! the ordinary `RESET` event is deliberately insufficient.

use super::*;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;

const COMPLETED_EVENT: &str = "CRUCIBLE_SELECTABLE_RESET_COMPLETED";
const FAILED_EVENT: &str = "CRUCIBLE_SELECTABLE_RESET_FAILED";

/// Authenticated command acknowledgement and correlated terminal reset event.
///
/// This observation permits reconciliation of the caller's exact pending
/// request. It does not prove a fresh RAM sample or guest continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpSelectableResetComplete {
    correlation: u64,
    observation_generation: u64,
}

impl QmpSelectableResetComplete {
    /// Returns the caller correlation echoed by the terminal event.
    #[must_use]
    pub const fn correlation(self) -> u64 {
        self.correlation
    }

    /// Returns the fresh native reset-observation generation.
    #[must_use]
    pub const fn observation_generation(self) -> u64 {
        self.observation_generation
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn reset_selectable_under_original(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        original: &HostOperationGuard,
    ) -> Result<QmpSelectableResetComplete, QmpError> {
        self.ensure_usable()?;
        original
            .wait_slice()
            .map_err(|error| QmpError::OperationalSupervision {
                operation: QmpCommandKind::SelectableReset.wire_name(),
                message: error.to_string(),
            })?;
        let correlation =
            self.selectable_reset_correlation
                .checked_add(1)
                .ok_or(QmpError::InvalidBound {
                    operation: "selectable reset correlation overflow",
                })?;
        let encoded = pending.request().encode().map_err(|error| QmpError::Json {
            operation: "encode exact selectable reset request",
            message: error.to_string(),
        })?;
        if encoded.len() > crucible_protocol::selectable_transport::SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES {
            return Err(QmpError::InvalidBound { operation: "selectable reset request exceeds its public protocol bound" });
        }
        let mut request_hex = String::with_capacity(encoded.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in encoded {
            request_hex.push(char::from(HEX[usize::from(byte >> 4)]));
            request_hex.push(char::from(HEX[usize::from(byte & 15)]));
        }

        // Consume correlations even on refusal. A reconnect cannot bypass the
        // native VM-wide highwater, and an uncertain request is never retried.
        self.selectable_reset_correlation = correlation;
        let response = self.exchange_under(
            QmpCommand::SelectableReset {
                pending,
                request_hex: &request_hex,
                correlation,
            },
            original,
        )?;
        let completion = response.selectable_reset.ok_or(QmpError::InvalidBound {
            operation: "selectable reset omitted its terminal observation",
        })?;
        self.selectable_reset_observation = completion.observation_generation;
        Ok(completion)
    }

    pub(super) fn read_selectable_reset_response(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        correlation: u64,
        deadline: &QmpOperationDeadline<'_>,
    ) -> Result<QmpCommandReturn, QmpError> {
        let command = QmpCommandKind::SelectableReset;
        let mut acknowledgement = None;
        let mut completion = None;
        let mut events = 0usize;
        loop {
            let response = self.read_json_line(command.wire_name(), deadline)?;
            if let Some(event) = response.get("event") {
                if response.get("return").is_some() || response.get("error").is_some() {
                    return Err(malformed(&response));
                }
                events = events.saturating_add(1);
                if events > self.io_timeout_policy.max_async_events_per_command {
                    return Err(QmpError::AsyncEventLimitExceeded {
                        command,
                        limit: self.io_timeout_policy.max_async_events_per_command,
                    });
                }
                match event.as_str() {
                    Some(COMPLETED_EVENT) => {
                        if completion.is_some() {
                            return Err(malformed(&response));
                        }
                        let data =
                            event_data(&response, pending, correlation, "observation-generation")?;
                        let generation = data
                            .get("observation-generation")
                            .and_then(Value::as_u64)
                            .filter(|value| *value > self.selectable_reset_observation)
                            .ok_or_else(|| malformed(&response))?;
                        completion = Some(QmpSelectableResetComplete {
                            correlation,
                            observation_generation: generation,
                        });
                    }
                    Some(FAILED_EVENT) => {
                        let data = event_data(&response, pending, correlation, "status")?;
                        let status = data
                            .get("status")
                            .and_then(Value::as_i64)
                            .filter(|value| *value < 0)
                            .ok_or_else(|| malformed(&response))?;
                        return Err(QmpError::SelectableResetFailed { status });
                    }
                    Some(_) => {}
                    None => return Err(malformed(&response)),
                }
            } else if let Some(value) = response.get("return") {
                if response.get("error").is_some()
                    || acknowledgement.is_some()
                    || !value.as_object().is_some_and(|value| value.is_empty())
                {
                    return Err(malformed(&response));
                }
                acknowledgement = Some(value.clone());
            } else if let Some(error) = response.get("error") {
                // A command rejection is certain only before an effect has
                // been acknowledged or observed. Keep the actual typed cause.
                if acknowledgement.is_some() || completion.is_some() {
                    self.poisoned = true;
                    self.stream.get_mut().poison_qmp_stream();
                }
                return Err(command_error(command, error));
            } else {
                return Err(malformed(&response));
            }
            if let (Some(value), Some(observation)) = (&acknowledgement, completion) {
                return Ok(QmpCommandReturn {
                    command,
                    value: value.clone(),
                    selectable_reset: Some(observation),
                });
            }
        }
    }
}

fn event_data<'a>(
    response: &'a Value,
    pending: &SelectablePlanPendingRequest,
    correlation: u64,
    outcome: &str,
) -> Result<&'a serde_json::Map<String, Value>, QmpError> {
    let data = response
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(response))?;
    let fields = [
        "schema-version",
        "correlation",
        "request-sequence",
        "raw-icount",
        "trap-tick-ps",
        "vcpu-index",
        outcome,
    ];
    if data.len() != fields.len()
        || fields.iter().any(|name| !data.contains_key(*name))
        || data.get("schema-version").and_then(Value::as_u64) != Some(1)
        || data.get("correlation").and_then(Value::as_u64) != Some(correlation)
        || data.get("request-sequence").and_then(Value::as_u64)
            != Some(pending.request().sequence())
        || data.get("raw-icount").and_then(Value::as_u64) != Some(pending.raw_icount())
        || data.get("trap-tick-ps").and_then(Value::as_u64) != Some(pending.trap_tick_ps())
        || data.get("vcpu-index").and_then(Value::as_u64) != Some(u64::from(pending.vcpu_index()))
    {
        return Err(malformed(response));
    }
    Ok(data)
}

fn malformed(response: &Value) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::SelectableReset,
        response: response.to_string(),
    }
}

#[cfg(test)]
mod tests;
