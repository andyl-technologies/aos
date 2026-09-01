//! Process arguments, diagnostics, and console collection for the live gate.

use std::error::Error;
use std::process::ExitCode;

use crucible::{ObservableEventPayload, SimulationBackend};
use crucible_qemu::QemuNodeSet;

/// Converts the gate result into the example's process status and diagnostic.
pub(super) fn entry(run: impl FnOnce() -> Result<(), String>) -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-fault-hardware: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drains guest console observations into the retained output buffer.
pub(super) fn collect_console(nodes: &mut QemuNodeSet, output: &mut Vec<u8>) -> Result<(), String> {
    let events = SimulationBackend::drain_observable_events(nodes)
        .map_err(|error| format!("drain live guest observations: {error}"))?;
    for event in events {
        if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
            output.extend_from_slice(bytes);
        }
    }
    Ok(())
}

/// Reports whether a byte buffer contains the exact byte substring.
pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Takes one required positional argument or returns the usage diagnostic.
pub(super) fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

pub(super) fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY")
}

/// Renders an error and every available source in causal order.
pub(super) fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        message.push_str(": ");
        message.push_str(&current.to_string());
        source = current.source();
    }
    message
}
