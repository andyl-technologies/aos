//! Exercises the combined production process/storage owner in a disposable VM.
//!
//! A real QEMU and its image helper launch through the sealed cgroup and quota
//! contract. The flight checks installed limits and child credentials, signals
//! sticky cancellation, reaps the process, and reuses the single project slot.
//! Invoke only with dedicated empty cgroup-v2 and ext4 project-quota roots:
//!
//! ```text
//! crucible-qemu-host-owner-flight QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, QemuGuardedFreshNodeLaunch,
    QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, launch_qemu_live_node_guarded,
};

const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const DISK_BYTES: u64 = 1024 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-host-owner-flight: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let [qemu, plugin, kernel, firmware, cgroup_root, run_root] = arguments.as_slice() else {
        return Err("expected QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT".into());
    };
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        run_root,
        "host-flight",
        20000,
        1,
        65534,
        65534,
        64,
        4096,
        Duration::from_secs(15),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host.clone())?;
    if LinuxQemuAttemptHostFactory::open(host).is_ok() {
        return Err("second allocator acquired the same resource namespace".into());
    }
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_vm_shape(128, 1, 0)
        .with_completion_timeout(Duration::from_secs(30));

    // There is only one project ID. The second successful launch therefore
    // requires complete release of the first process and storage authorities.
    for _ in 0..2 {
        let mut owner = factory.begin(1, MEMORY_BYTES, DISK_BYTES)?;
        let attempt_root = owner.run_directory()?.to_owned();
        let mut directory =
            owner.prepare_generation_run_directory(config.resource_requirements())?;
        if let Err(mut error) =
            directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)
        {
            if let Some(child) = error.take_unreaped_child() {
                owner.retain_failed_child(child);
            }
            return Err(error.into());
        }
        let launch_config = config.clone().with_run_directory(directory.path());
        let mut node = match launch_qemu_live_node_guarded(
            &launch_config,
            QemuGuardedFreshNodeLaunch::new(
                &directory,
                owner.process_contract()?,
                QemuLiveNodeIdentity::new("node", "router", "crash-detector"),
            ),
        ) {
            Ok(node) => node,
            Err(mut error) => {
                if let Some(child) = error.take_unreaped_child() {
                    owner.retain_failed_child(child);
                }
                return Err(error.into());
            }
        };
        let process = PathBuf::from(format!("/proc/{}", node.process_id()));
        let group = verify_child(&process, cgroup_root)?;
        owner.check_operational_boundary()?;
        owner.cancellation_signal()?.signal()?;
        if owner.check_operational_boundary().is_ok() || owner.process_contract().is_ok() {
            return Err("cancelled owner continued lending launch authority".into());
        }
        node.shutdown_child()?;
        if !node.child_reaped() {
            return Err("cancelled QEMU was not reaped".into());
        }
        drop(node);
        drop(directory);
        owner.finish()?;
        owner.finish()?;
        require_absent(&process)?;
        require_absent(&group)?;
        require_absent(&attempt_root)?;
    }
    println!("real_guarded_qemu_launches=2");
    println!("exclusive_resource_namespace=true");
    println!("child_credentials_unprivileged=true");
    println!("cpu_memory_task_limits_installed=true");
    println!("sticky_cancellation_closes_launch_authority=true");
    println!("process_reaped_before_storage_release=true");
    println!("single_project_slot_reused=true");
    println!("PASS");
    Ok(())
}

fn verify_child(process: &Path, cgroup_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let status = fs::read_to_string(process.join("status"))?;
    for key in ["Uid:", "Gid:"] {
        let line = status
            .lines()
            .find(|line| line.starts_with(key))
            .ok_or("missing credentials")?;
        let ids = line.split_whitespace().skip(1).collect::<Vec<_>>();
        if ids != ["65534"; 4] {
            return Err(format!("unexpected child credentials: {line}").into());
        }
    }
    let membership = fs::read_to_string(process.join("cgroup"))?;
    let relative = membership
        .trim()
        .strip_prefix("0::/")
        .ok_or("not unified cgroup membership")?;
    let group = Path::new("/sys/fs/cgroup").join(relative);
    if group.parent() != Some(cgroup_root) {
        return Err(format!("child escaped dedicated cgroup root: {}", group.display()).into());
    }
    for (file, expected) in [
        ("cpu.max", "100000 100000"),
        ("memory.max", "536870912"),
        ("memory.swap.max", "0"),
        ("pids.max", "64"),
    ] {
        if fs::read_to_string(group.join(file))?.trim() != expected {
            return Err(format!("unexpected installed {file} limit").into());
        }
    }
    Ok(group)
}

fn require_absent(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(format!("cleanup retained {}", path.display()).into()),
    }
}
