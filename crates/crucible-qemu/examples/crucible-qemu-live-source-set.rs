//! Runs real native VMState source prepare/abort and resumed-save transactions.
//!
//! ```text
//! crucible-qemu-live-source-set QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY
//! ```
//!
//! Firmware executes bounded busy windows; the kernel argument supplies launch
//! identity material but is not booted. This flight does not fork a guest.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-source-set: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_source_set_gate};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [qemu, plugin, kernel, firmware, directory] = args.as_slice() else {
        return Err("expected QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY".into());
    };
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, directory)
        .with_firmware_boot();
    let report = run_qemu_live_source_set_gate(&config)?;
    println!("PASS");
    println!("gate=gate:qemu-native-source-set-lifecycle");
    println!(
        "retained_transactions={}",
        report.template_generations.len()
    );
    println!("restored_vmstate_saves={}", report.restored_vmstate_saves);
    println!("suffix_icount={}", report.suffix_icount);
    println!("whole_world_child_handoff=false");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crucible-qemu-live-source-set requires Linux");
    ExitCode::FAILURE
}
