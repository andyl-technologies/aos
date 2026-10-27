//! Selects actual native copy staging boundaries for fault and lock witnesses.

/// Selects the actual fixed native copy or recovery command.
pub(crate) use super::io::initializer_faults::CopyBoundary;
/// Observes actual receipt retention without exposing native descriptors.
pub(crate) use super::io::initializer_faults::CopyRetentionProbe;
use super::io::initializer_faults::{self, Hook};
use std::{path::PathBuf, sync::mpsc};

/// Interrupts the chosen actual installation before or after its rename.
///
/// # Panics
/// Panics if this control already has a registered test hook.
pub(crate) fn fault(control: PathBuf, root: PathBuf, boundary: CopyBoundary, after: bool) {
    initializer_faults::register(
        control,
        Hook::CopyFault {
            root,
            boundary,
            after,
        },
    );
}

/// Blocks an actual submitted command while retaining its original descriptors.
///
/// # Panics
/// Panics if this control already has a registered test hook.
pub(crate) fn gate(
    control: PathBuf,
    root: PathBuf,
    boundary: CopyBoundary,
    arrived: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
) -> mpsc::Receiver<CopyRetentionProbe> {
    let (observed, observations) = mpsc::channel();
    initializer_faults::register(
        control,
        Hook::CopyGate {
            root,
            boundary,
            observed,
            arrived,
            release,
        },
    );
    observations
}

/// Fails the actual explicit durability command for a staged record's temporary.
///
/// # Panics
/// Panics if this control already has a registered test hook.
pub(crate) fn file_sync(control: PathBuf, root: PathBuf, boundary: CopyBoundary) {
    initializer_faults::register(control, Hook::CopyFileSync { root, boundary });
}

/// Fails one indexed explicit directory sync in the actual native program.
///
/// # Panics
/// Panics for a zero ordinal or an already registered test hook.
pub(crate) fn directory_sync(control: PathBuf, root: PathBuf, ordinal: usize) {
    assert!(ordinal != 0);
    initializer_faults::register(
        control,
        Hook::CopyDirectorySync {
            root,
            remaining: ordinal,
        },
    );
}

/// Records every actual explicit directory durability command without effects.
///
/// # Panics
/// Panics if this control already has a registered test hook.
pub(crate) fn trace_directories(control: PathBuf, root: PathBuf) -> mpsc::Receiver<PathBuf> {
    let (observed, observations) = mpsc::channel();
    initializer_faults::register(control, Hook::CopyDirectoryTrace { root, observed });
    observations
}

/// Removes only this test's nonconsuming directory observer.
///
/// # Panics
/// Panics when the exact directory observer is absent.
pub(crate) fn finish_trace(control: &std::path::Path) {
    initializer_faults::clear(control);
}

/// Requires the actual submitted command to have consumed its precise hook.
///
/// # Panics
/// Panics when an armed hook remains unconsumed.
pub(crate) fn assert_consumed(control: &std::path::Path) {
    initializer_faults::assert_consumed(control);
}
