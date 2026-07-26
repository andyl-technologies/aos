//! Runs the production loaded-QEMU Rust-plugin install lifecycle gate.
//!
//! Boots the patched QEMU binary once with the real Rust control plugin loaded
//! through the fixed inherited descriptors and drives the full install
//! lifecycle: handshake, `SCM_RIGHTS` handover, shared-memory map, `SetupAck`,
//! boot-barrier release, one exact-icount quantum, run-control silence, control
//! `Quit` teardown, and natural child exit. Prints machine-checkable evidence
//! the phase2 gate asserts.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use crucible_qemu::{
    LivePluginInstallGateConfig, QemuLaunchAppRandomConfig, QemuLaunchPluginSwitch,
    run_live_plugin_install_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-plugin-install: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-plugin-install"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let root_image = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    let kernel_cmdline = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut config =
        LivePluginInstallGateConfig::new(qemu, plugin, kernel, root_image, run_directory);
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    if let Some(kernel_cmdline) = kernel_cmdline {
        let kernel_cmdline = kernel_cmdline
            .into_string()
            .map_err(|_| String::from("kernel command line is not valid UTF-8"))?;
        config = config.with_kernel_cmdline(kernel_cmdline);
    }
    let whitebox = env_switch("CRUCIBLE_LIVE_PLUGIN_WHITEBOX")?;
    let fingerprint = env_switch("CRUCIBLE_LIVE_PLUGIN_FINGERPRINT")?;
    config = config.with_whitebox(whitebox).with_fingerprint(fingerprint);
    if let Some(app_random) = app_random_env()? {
        config = config.with_app_random(app_random);
    }
    let report = run_live_plugin_install_gate(&config).map_err(|error| error_chain(&error))?;
    println!("PASS");
    println!("gate=gate:plugin-install-lifecycle");
    println!("plugin_loaded=rust-control-cdylib");
    println!("time_authority=rust-plugin");
    println!(
        "handshake_proto_version={}",
        report.negotiated_proto_version
    );
    println!("handshake_abi_version={}", report.negotiated_abi_version);
    println!("handshake_slot={}", report.negotiated_slot);
    println!("handshake_node_count={}", report.negotiated_node_count);
    println!("setup_ack_ready={}", report.setup_ack_ready);
    println!("shmem_region_len={}", report.shmem_region_len);
    println!(
        "boot_barrier_ceiling_enforced={}",
        report.boot_barrier_ceiling_enforced
    );
    println!("completed_icount={}", report.completed_icount);
    println!(
        "execution_fingerprint={}",
        report.execution_fingerprint.hash.to_hex()
    );
    println!("run_control_silent={}", report.run_control_silent);
    println!("plugin_quit_consumed={}", report.plugin_quit_consumed);
    println!("orderly_child_exit={}", report.orderly_child_exit);
    println!(
        "time_authority_is_rust_plugin={}",
        report.time_authority_is_rust_plugin
    );
    println!("whitebox={whitebox}");
    println!(
        "whitebox_setup_region={}",
        report
            .whitebox_setup_region
            .as_deref()
            .unwrap_or("not-required")
    );
    println!("whitebox_marker_count={}", report.whitebox_marker_count);
    println!(
        "whitebox_marker_icount={}",
        report
            .whitebox_marker_icount
            .map_or_else(|| "not-observed".to_owned(), |icount| icount.to_string())
    );
    println!(
        "whitebox_marker_point={}",
        report
            .whitebox_marker_point
            .as_deref()
            .unwrap_or("not-observed")
    );
    println!(
        "app_random_decision_count={}",
        report.app_random_decision_count
    );
    println!(
        "app_random_request_id={}",
        report
            .app_random_request_id
            .map_or_else(|| "not-observed".to_owned(), |value| value.to_string())
    );
    println!(
        "app_random_value={}",
        report
            .app_random_value
            .map_or_else(|| "not-observed".to_owned(), |value| value.to_string())
    );
    println!(
        "app_random_width_bits={}",
        report
            .app_random_width_bits
            .map_or_else(|| "not-observed".to_owned(), |value| value.to_string())
    );
    println!("fingerprint={fingerprint}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn app_random_env() -> Result<Option<QemuLaunchAppRandomConfig>, String> {
    let seed = env::var("CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_SEED");
    let cap = env::var("CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_CAP");
    let node = env::var("CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_NODE");
    match (seed, cap, node) {
        (
            Err(env::VarError::NotPresent),
            Err(env::VarError::NotPresent),
            Err(env::VarError::NotPresent),
        ) => Ok(None),
        (Ok(seed), Ok(cap), Ok(node)) => {
            let root_seed = seed.parse::<u64>().map_err(|_error| {
                String::from("CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_SEED must be a u64")
            })?;
            let draw_cap = cap.parse::<u64>().map_err(|_error| {
                String::from("CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_CAP must be a u64")
            })?;
            Ok(Some(QemuLaunchAppRandomConfig::new(
                root_seed, draw_cap, node,
            )))
        }
        _ => Err(String::from(
            "live app-random requires seed, cap, and node environment variables together",
        )),
    }
}

#[cfg(target_os = "linux")]
fn env_switch(name: &str) -> Result<QemuLaunchPluginSwitch, String> {
    let switch = match env::var(name).as_deref() {
        Ok("on") => QemuLaunchPluginSwitch::On,
        Ok("off") | Err(env::VarError::NotPresent) => QemuLaunchPluginSwitch::Off,
        Ok(value) => {
            return Err(format!("{name} must be `on` or `off`, got `{value}`"));
        }
        Err(env::VarError::NotUnicode(_value)) => {
            return Err(format!("{name} is not valid UTF-8"));
        }
    };
    Ok(switch)
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
    format!(
        "usage: {program} QEMU PLUGIN KERNEL ROOT_IMAGE RUN_DIRECTORY [INITRD [KERNEL_CMDLINE]]"
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-plugin-install requires Linux");
}
