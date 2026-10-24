//! Component-only QMP exchange fencing after an ambiguous reply boundary.
//!
//! These new native namespaces use the existing ID-less QMP channel. An I/O,
//! framing or schema error permanently fences that stream so a delayed original
//! reply cannot be mistaken for a subsequent Query. A fully received native
//! command refusal has a known boundary and keeps the stream usable. Replacement
//! peer authentication remains the owning installed adapter's responsibility.

use super::{QmpClient, QmpCommand, QmpError, QmpTimeoutStream};

pub(super) fn exchange_component<S: QmpTimeoutStream, T>(
    client: &mut QmpClient<S>,
    command: QmpCommand<'_>,
    parse: impl FnOnce(&serde_json::Value) -> Result<T, QmpError>,
) -> Result<T, QmpError> {
    let result = client
        .send_command_return(command)
        .and_then(|response| parse(&response.value));
    if result
        .as_ref()
        .is_err_and(|error| !matches!(error, QmpError::Command { .. }))
    {
        client.poisoned = true;
        client.stream.get_mut().poison_qmp_stream();
    }
    result
}
