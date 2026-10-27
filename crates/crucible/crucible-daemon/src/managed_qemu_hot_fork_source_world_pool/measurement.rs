//! Source-world memory measurement rows and the child reservation they imply.
//!
//! Binding measures each retained source world once. The measurement row
//! shows how its memory splits by QEMU region class, and the child profile
//! derived here is what each forked child reserves while leased.

use crucible_daemon::vm_lifecycle::ProductionVmHotForkSourceWorldResourceUsage;

use crate::{
    HotCheckpointResourceProfile, HotCheckpointResourceProfileError, QemuHotForkSourceWorldKey,
};

/// Returns the retained profile a measured source world occupies as a template.
pub(super) fn source_resources(
    usage: ProductionVmHotForkSourceWorldResourceUsage,
) -> Result<HotCheckpointResourceProfile, HotCheckpointResourceProfileError> {
    HotCheckpointResourceProfile::new(
        usage.template_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
}

/// Returns the reservation one child forked from a measured source makes.
///
/// A forked child shares the source's pages; the new memory it holds is what
/// it dirties, so the child charges its dirty bound as both its bytes and its
/// private dirties, plus the source's process, vCPU, descriptor, and overlay
/// counts.
pub(super) fn child_resources(
    usage: ProductionVmHotForkSourceWorldResourceUsage,
) -> Result<HotCheckpointResourceProfile, HotCheckpointResourceProfileError> {
    HotCheckpointResourceProfile::new(
        usage.expected_private_dirty_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
}

/// Writes one source world's measured memory profile by QEMU region class.
pub(super) fn note_source_measurement(
    key: &QemuHotForkSourceWorldKey,
    usage: ProductionVmHotForkSourceWorldResourceUsage,
) {
    use std::io::Write as _;

    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-SOURCE-MEASUREMENT-V1 configuration={:?} processes={} template_bytes={} expected_private_dirty_bytes={} regions={:?}",
        key.configuration(),
        usage.process_count(),
        usage.template_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.regions(),
    );
}
