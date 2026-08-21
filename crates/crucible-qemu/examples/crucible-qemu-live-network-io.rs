//! Runs the certifying loaded-QEMU guest network exchange.
//!
//! Positional arguments are
//! `QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY`. Optional tuning:
//!
//! ```text
//! CRUCIBLE_NETWORK_IO_BUSY_CEILING
//! CRUCIBLE_NETWORK_IO_TIMEOUT_SECS
//! CRUCIBLE_NETWORK_IO_SECOND_RUN_LOAD
//! ```

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crucible_qemu::{
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_PROBE_PAYLOAD, QemuLiveNetworkIoGateConfig,
    run_qemu_live_network_io_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-network-io: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-network-io"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let initrd = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let config =
        QemuLiveNetworkIoGateConfig::new(qemu, plugin, kernel, firmware, initrd, run_directory)
            .with_completion_timeout(Duration::from_secs(env_u64(
                "CRUCIBLE_NETWORK_IO_TIMEOUT_SECS",
                120,
            )?))
            .with_second_run_host_load(env_flag("CRUCIBLE_NETWORK_IO_SECOND_RUN_LOAD", true)?);
    let config = match env_opt_u64("CRUCIBLE_NETWORK_IO_BUSY_CEILING")? {
        Some(ceiling) => config.with_busy_ceiling_icount(ceiling),
        None => config,
    };
    let report = run_qemu_live_network_io_gate(&config).map_err(|error| error_chain(&error))?;
    let probe = report.reference.tx_frames.iter().find(|frame| {
        frame
            .payload
            .windows(LIVE_NETWORK_PROBE_PAYLOAD.len())
            .any(|window| window == LIVE_NETWORK_PROBE_PAYLOAD)
    });
    let acknowledgement = report.reference.tx_frames.iter().find(|frame| {
        frame
            .payload
            .windows(LIVE_NETWORK_ACK_PAYLOAD.len())
            .any(|window| window == LIVE_NETWORK_ACK_PAYLOAD)
    });
    let reply_latency_icount = probe
        .map(|frame| frame.emit_icount)
        .zip(report.reference.reply_delivery_icount)
        .and_then(|(probe_icount, reply_icount)| reply_icount.checked_sub(probe_icount));

    println!("PASS");
    println!("gate=gate:live-network-io");
    println!("certification=guest-tx-router-reply-guest-rx-ack");
    println!("network_backend=hostless-qemu-hubport");
    println!("network_ring=SLOT_NET_ROUTER");
    println!("host_traffic_injector=false");
    println!("probe_emit_icount={}", observation_icount(probe));
    println!(
        "reply_delivery_icount={}",
        option_u64(report.reference.reply_delivery_icount)
    );
    println!("reply_latency_icount={}", option_u64(reply_latency_icount));
    println!("ack_emit_icount={}", observation_icount(acknowledgement));
    println!("acknowledgement_seen={}", report.acknowledgement_seen);
    println!(
        "boot_backpressure_retained={}",
        report.boot_backpressure_retained
    );
    println!(
        "canonical_backpressure_retry_delivered={}",
        report.canonical_backpressure_retry_delivered
    );
    println!(
        "deterministic_under_host_load={}",
        report.deterministic_under_host_load
    );
    println!(
        "hostile_probe_emit_icount={}",
        option_u64(report.hostile_probe_emit_icount)
    );
    println!(
        "absolute_probe_origin_equal={}",
        report.absolute_probe_origin_equal
    );
    println!(
        "hostile_acknowledgement_offset_icount={}",
        option_u64(report.hostile_acknowledgement_offset_icount)
    );
    println!(
        "acknowledgement_offset_equal={}",
        report.acknowledgement_offset_equal
    );
    println!("determinism_scope=router-delivery-and-frame-order");
    println!("host_load_applied={}", report.host_load_applied);
    println!("delayed_reply_applied={}", report.delayed_reply_applied);
    println!("orderly_child_exit={}", report.orderly_child_exit);
    Ok(())
}

#[cfg(target_os = "linux")]
fn observation_icount(observation: Option<&crucible_qemu::LiveNetworkTxObservation>) -> String {
    observation.map_or_else(
        || String::from("none"),
        |observation| observation.emit_icount.to_string(),
    )
}

#[cfg(target_os = "linux")]
fn option_u64(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("none"), |value| value.to_string())
}

#[cfg(target_os = "linux")]
fn env_u64(key: &str, fallback: u64) -> Result<u64, String> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| format!("environment variable {key} is not a u64: {error}")),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} is not valid UTF-8"))
        }
    }
}

#[cfg(target_os = "linux")]
fn env_opt_u64(key: &str) -> Result<Option<u64>, String> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|error| format!("environment variable {key} is not a u64: {error}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} is not valid UTF-8"))
        }
    }
}

#[cfg(target_os = "linux")]
fn env_flag(key: &str, fallback: bool) -> Result<bool, String> {
    match env::var(key) {
        Ok(value) => match value.trim() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(format!(
                "environment variable {key} is not a boolean: {other}"
            )),
        },
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} is not valid UTF-8"))
        }
    }
}

#[cfg(target_os = "linux")]
fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        message.push_str(": ");
        message.push_str(&current.to_string());
        source = current.source();
    }
    message
}

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-network-io requires Linux");
}
