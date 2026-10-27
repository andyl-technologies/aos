//! Diagnostic rows a hot-fork child world writes about its resources.
//!
//! Each row is a single stderr line that flight diagnostics match by prefix:
//!
//! ```text
//! CRUCIBLE-HOT-FORK-CHILD-MEMORY-V1 private_dirty_bytes=.. budget=.. regions=..
//! CRUCIBLE-HOT-FORK-CHILD-OVER-BUDGET-V1 private_dirty_bytes=.. budget=.. excess=..
//! CRUCIBLE-HOT-FORK-INSTALL-QUARANTINE-V1 source=retained-until-exit error=..
//! ```

use crate::SourceMemoryRegions;
use crucible_control_api::LifecycleApiError;

/// Writes a child world's measured private dirty bytes against its budget.
///
/// The budget is a prediction made when the source was measured, so every
/// child checks it before shutdown. Exceeding it, or failing to measure,
/// writes a row of its own; neither stops the child.
pub(super) fn note_child_memory(
    measured: Result<SourceMemoryRegions, LifecycleApiError>,
    budget: Option<u64>,
) {
    use std::io::Write as _;

    let mut stderr = std::io::stderr().lock();
    let regions = match measured {
        Ok(regions) => regions,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "CRUCIBLE-HOT-FORK-CHILD-MEMORY-V1 decision=unmeasured budget={budget:?} error=\"{error}\""
            );
            return;
        }
    };
    let dirty = regions.private_dirty_bytes;
    let _ = writeln!(
        stderr,
        "CRUCIBLE-HOT-FORK-CHILD-MEMORY-V1 private_dirty_bytes={dirty} budget={budget:?} regions={regions:?}"
    );
    if let Some(budget) = budget
        && dirty > budget
    {
        let _ = writeln!(
            stderr,
            "CRUCIBLE-HOT-FORK-CHILD-OVER-BUDGET-V1 private_dirty_bytes={dirty} budget={budget} excess={}",
            dirty - budget
        );
    }
}

/// Names why a source stays checked out after a refused child install.
///
/// A refused install may leave forked children whose exit is unproven, so it
/// keeps the source lease for the process lifetime instead of returning it.
/// Shutdown then cannot retire that source; this row is the reason it names.
pub(super) fn note_install_quarantine(error: &LifecycleApiError) {
    use std::io::Write as _;

    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-INSTALL-QUARANTINE-V1 source=retained-until-exit error={error}"
    );
}
