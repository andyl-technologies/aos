//! Runs the production loaded-QEMU basic-block coverage gate.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use crucible_qemu::{LoadedQemuCoverageGateConfig, run_loaded_qemu_coverage_gate};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-coverage: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let program = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("crucible-qemu-live-coverage"));
    let qemu = required_arg(&mut args, &program, "QEMU")?;
    let plugin = required_arg(&mut args, &program, "PLUGIN")?;
    let trace_plugin = required_arg(&mut args, &program, "TRACE_PLUGIN")?;
    let kernel = required_arg(&mut args, &program, "KERNEL")?;
    let root_image = required_arg(&mut args, &program, "ROOT_IMAGE")?;
    let off_directory = required_arg(&mut args, &program, "COVERAGE_OFF_DIRECTORY")?;
    let on_directory = required_arg(&mut args, &program, "COVERAGE_ON_DIRECTORY")?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let config = LoadedQemuCoverageGateConfig::new(
        qemu,
        plugin,
        trace_plugin,
        kernel,
        root_image,
        off_directory,
        on_directory,
    );
    let report = run_loaded_qemu_coverage_gate(&config).map_err(|error| error.to_string())?;
    println!("PASS");
    println!("gate=gate:basic-block-coverage");
    println!("loaded_qemu_callback_evidence=present");
    println!("guest_instrumentation=none");
    println!("guest_post_io_reached=true");
    println!("completed_icount={}", report.completed_icount);
    println!(
        "coverage_observation_count={}",
        report.coverage_observation_count
    );
    println!(
        "guest_coverage_observation_count={}",
        report.guest_coverage_observation_count
    );
    println!("canonical_event_log_match=true");
    println!(
        "canonical_event_log_fingerprint={}",
        report.canonical_event_log_fingerprint.to_hex()
    );
    println!(
        "coverage_off_plugin={}",
        report.coverage_off_plugin_argument
    );
    println!("coverage_on_plugin={}", report.coverage_on_plugin_argument);
    println!("coverage_on_off_fingerprint_match=true");
    println!("independent_trace_fingerprint_match=true");
    println!("run_control_silent={}", report.run_control_silent);
    println!("plugin_quit_consumed={}", report.plugin_quit_consumed);
    println!("orderly_child_exit={}", report.orderly_child_exit);
    println!("trace_components=instruction-stream,all-vcpu-registers,rr-cursor,ram,device-io");
    println!(
        "independent_trace_fingerprint={}",
        report.independent_trace_fingerprint.to_hex()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
    _label: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!(
        "usage: {program} QEMU PLUGIN TRACE_PLUGIN KERNEL ROOT_IMAGE COVERAGE_OFF_DIRECTORY COVERAGE_ON_DIRECTORY"
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-coverage requires Linux");
}
