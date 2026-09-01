//! Teardown selection for the two loaded-QEMU coverage runs.

use crate::QemuLaunchPluginSwitch;

/// Selects which independent shutdown transport one coverage run proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoadedTeardownTrigger {
    /// Requests shutdown through the mapped shared-memory transport.
    SharedShutdown,
    /// Requests shutdown through the control protocol.
    ControlQuit,
}

/// Selects the teardown transport assigned to one coverage mode.
pub(super) const fn teardown_trigger_for_coverage(
    coverage: QemuLaunchPluginSwitch,
) -> LoadedTeardownTrigger {
    match coverage {
        QemuLaunchPluginSwitch::Off => LoadedTeardownTrigger::SharedShutdown,
        QemuLaunchPluginSwitch::On => LoadedTeardownTrigger::ControlQuit,
    }
}
