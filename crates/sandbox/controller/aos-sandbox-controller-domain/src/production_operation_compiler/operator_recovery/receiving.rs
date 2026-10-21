//! Memory controls for the actual borrowed recovery target interfaces.

use crate::journal::historical_observation::HistoricalObservationV1;

/// Prices the additional target-observer interfaces before target decoding.
///
/// The longest target path retains ten distinct borrowed-observer arguments:
/// current target, target decoder, resolver, recovered resource, Repair receipt
/// validator, Controller verifier, terminal verifier, terminal rows, archived
/// pending rows, and recovered admission. Each names its construction, ABI and
/// caller plane. The existing model and credential invoices remain separate.
///
/// This quote excludes the shared observer getter/status quote and the complete
/// failed-Create planner quote, which their actual receiving owners supply.
pub(crate) fn recovery_target_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    let target_arguments = size_of::<HistoricalObservationV1<'_>>()
        .checked_mul(10)?
        .checked_mul(3)?;
    let projection =
        crate::controller_service::public_projection::projection_observation_control_bytes_v2()?;
    let runtime = crate::runtime_authority::current_observation_control_bytes_v2()?;
    let runtime_geometry =
        crate::runtime_authority::current_publication_geometry_control_bytes_v2()?;
    let controller_history = crate::journal::controller_q04_history_observation_control_bytes_v2()?;

    target_arguments
        .checked_add(projection)?
        .checked_add(runtime)?
        .checked_add(runtime_geometry)?
        .checked_add(controller_history)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
