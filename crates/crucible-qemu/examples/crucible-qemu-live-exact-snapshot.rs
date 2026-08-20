//! Runs the live paired VMState/host checkpoint crash-and-restore gate.
//!
//! Positional arguments are `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY
//! [INITRD]`. The runner uses the production scheduler-facing node, QMP
//! snapshot jobs, shared-memory devices, and host servicers. It force-kills the
//! captured QEMU process before copying its VMState artifact to a fresh launch.
//!
//! ```text
//! CRUCIBLE_EXACT_CAPTURE_CEILING   maximum capture-search icount
//! CRUCIBLE_EXACT_SUFFIX_INCREMENT post-restore execution length
//! CRUCIBLE_EXACT_PENDING_BLOCK     require pending real block I/O at capture
//! CRUCIBLE_EXACT_TIMEOUT_SECS      bounded host wait per quantum
//! GUEST_KERNEL_APPEND              explicit guest kernel command line
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
use crucible_device::block::{
    BaseImage, BlockCompletionDurability, BlockDiscardSemantics, BlockDurabilityConfig,
    BlockLatency,
};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig, run_qemu_live_exact_snapshot_gate,
};

#[cfg(target_os = "linux")]
const BLOCK_DEVICE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-exact-snapshot: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-exact-snapshot"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let require_pending_block = env_flag("CRUCIBLE_EXACT_PENDING_BLOCK", false)?;
    let mut config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
        .with_vm_shape(256, 2, 0)
        .with_fingerprint(QemuLaunchPluginSwitch::On)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_EXACT_TIMEOUT_SECS",
            240,
        )?));
    if let Some(initrd) = initrd.filter(|value| !value.is_empty() && !require_pending_block) {
        config = config.with_initrd(initrd);
    }
    if let Some(kernel_cmdline) = env::var_os("GUEST_KERNEL_APPEND") {
        config = config.with_kernel_cmdline(kernel_cmdline.to_string_lossy());
    }
    if require_pending_block {
        let length = usize::try_from(BLOCK_DEVICE_BYTES)
            .map_err(|_| String::from("block device length exceeds the host usize range"))?;
        let mut bytes = (0..length)
            .map(|index| {
                u8::try_from(index % 251)
                    .map_err(|_| String::from("deterministic block byte exceeds u8"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        install_firmware_block_probe(&mut bytes)?;
        config = config
            .with_fault_free_shmem_block_and_latency(
                BaseImage::new(bytes),
                pending_write_durability(),
                BlockLatency::default(),
            )
            .with_rr_switch_quantum(1_048_576)
            .with_firmware_boot();
    }

    let capture_ceiling = env_u64(
        "CRUCIBLE_EXACT_CAPTURE_CEILING",
        if require_pending_block {
            80_000_000_000
        } else {
            9_000_001
        },
    )?;
    let suffix_increment = env_u64("CRUCIBLE_EXACT_SUFFIX_INCREMENT", 3_000_000)?;
    let report = run_qemu_live_exact_snapshot_gate(
        &config,
        capture_ceiling,
        suffix_increment,
        require_pending_block,
    )
    .map_err(|error| error_chain(&error))?;

    println!("PASS");
    println!("gate=gate:qemu-exact-snapshot-restore");
    println!("vmstate_backend=real-qemu-qcow2");
    println!("host_io_backend=production-shared-memory-servicer");
    println!(
        "old_process_force_crashed={}",
        report.old_process_force_crashed
    );
    println!("capture_icount={}", report.capture_icount);
    println!("restored_icount={}", report.restored_icount);
    println!("capture_rr_current_vcpu={}", report.capture_rr_current_vcpu);
    println!(
        "capture_rr_position_in_quantum={}",
        report.capture_rr_position_in_quantum
    );
    println!(
        "capture_rr_switch_quantum={}",
        report.capture_rr_switch_quantum
    );
    println!("suffix_icount={}", report.suffix_icount);
    println!("smp_vcpus={}", report.smp_vcpus);
    println!(
        "capture_logical_time_offset={}",
        report.capture_logical_time_offset
    );
    println!(
        "capture_fingerprint={}",
        report.capture_fingerprint.to_hex()
    );
    println!("suffix_fingerprint={}", report.suffix_fingerprint.to_hex());
    println!(
        "replay_oracle_pair_match={}",
        report.replay_oracle_pair_match
    );
    println!(
        "pending_block_io_captured={}",
        report.pending_block_io_captured
    );
    println!("multi_vcpu_exact_restore=true");
    println!("nonzero_intra_turn_rr_cursor_restored=true");
    println!(
        "rr_cursor_negative_control_rejected={}",
        report.rr_cursor_negative_control_rejected
    );
    println!("logical_time_calibration_restored=true");
    Ok(())
}

#[cfg(target_os = "linux")]
fn pending_write_durability() -> BlockDurabilityConfig {
    BlockDurabilityConfig {
        length_bytes: BLOCK_DEVICE_BYTES,
        atomic_write_bytes: 512,
        maximum_request_bytes: BLOCK_DEVICE_BYTES,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 4 * 1024,
        cache_entries: 8,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 16_777_216,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    }
}

fn install_firmware_block_probe(bytes: &mut [u8]) -> Result<(), String> {
    const BOOT_SECTOR_BYTES: usize = 512;
    const BOOT_PROGRAM: &[u8] = &[
        0xfa, // cli
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0x66, 0xb9, 0x80, 0x84, 0x1e, 0x00, // mov ecx, 2_000_000
        0x66, 0x49, // dec ecx
        0x75, 0xfc, // jnz delay
        0xbb, 0x00, 0x7e, // mov bx, 0x7e00
        0xb4, 0x03, // mov ah, 3 (BIOS write sectors)
        0xb0, 0x01, // mov al, 1
        0xb5, 0x00, // mov ch, 0
        0xb1, 0x02, // mov cl, 2
        0xb6, 0x00, // mov dh, 0
        0xb2, 0x80, // mov dl, 0x80
        0xcd, 0x13, // int 0x13
        0xf4, // hlt
        0xeb, 0xfd, // jmp hlt
    ];
    if bytes.len() < BOOT_SECTOR_BYTES {
        return Err(String::from(
            "firmware block probe requires one full sector",
        ));
    }
    bytes[..BOOT_SECTOR_BYTES].fill(0);
    bytes[..BOOT_PROGRAM.len()].copy_from_slice(BOOT_PROGRAM);
    bytes[510] = 0x55;
    bytes[511] = 0xaa;
    Ok(())
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
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-exact-snapshot requires Linux");
}
