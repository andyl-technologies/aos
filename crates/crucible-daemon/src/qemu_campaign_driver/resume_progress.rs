//! Bounded host progress notice after a restored guest reaches its first marker.

use std::io::Write;

use crucible::{ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload};

use crate::AttemptExecutionContext;

/// Emits one restored-guest marker notice from a completed scheduler quantum.
pub(super) fn report_first_restored_guest_marker(
    context: &AttemptExecutionContext,
    replaying_selected_boundary: bool,
    entries: &[SchedulerEventLogEntry],
    completed_quanta: u64,
    already_reported: bool,
) -> bool {
    if already_reported || context.resume_checkpoint().is_none() || replaying_selected_boundary {
        return already_reported;
    }
    let Some(basis) = context.runtime_basis() else {
        return false;
    };
    let Some((marker, retired_icount)) = entries.iter().find_map(|entry| match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            marker,
            retired_icount,
            ..
        }) => Some((marker, retired_icount)),
        _ => None,
    }) else {
        return false;
    };

    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-EXACT-RESUME-PROGRESS-V1 attempt={:?} execution={:?} quanta={} marker={} icount={}",
        basis.key().attempt(),
        basis.execution(),
        completed_quanta,
        marker.name,
        retired_icount.retired,
    );
    true
}
