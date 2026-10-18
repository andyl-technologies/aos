//! Read-only runstate evidence under the caller's live Transfer original.

use super::*;

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(crate) fn is_stopped_for_transfer(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<bool, QmpError> {
        original
            .verify_operation_class(HostOperationClass::Transfer)
            .map_err(|source| QmpError::OperationalSupervision {
                operation: "receiving stopped runstate",
                message: source.to_string(),
            })?;
        let response = self.exchange_under(QmpCommand::QueryStatus, original)?;
        let running = response.value.get("running").and_then(Value::as_bool);
        let status = response
            .value
            .get("status")
            .and_then(Value::as_str)
            .and_then(QmpRunStateKind::from_wire);
        match (running, status) {
            (Some(running), Some(status)) if running == (status == QmpRunStateKind::Running) => {
                Ok(!running && status == QmpRunStateKind::Paused)
            }
            _ => Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryStatus,
                response: response.value.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
