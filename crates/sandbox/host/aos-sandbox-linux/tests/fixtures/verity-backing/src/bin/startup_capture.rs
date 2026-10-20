//! Qualifies one-shot startup capture across two distinct sealed executables.
//!
//! The VM seals separate copies of this probe on ext4. The launcher executes
//! the worker so the claimant must measure both `/proc/self/exe` and its direct
//! parent's executable before it can retain the initial descriptor table.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::process::Command;

    use aos_sandbox_linux::startup_fd_table::{
        StartupFdCaptureHardLimitsV1, claim_initial_process_fd_table_once,
    };

    let mut arguments = env::args_os();
    let _program = arguments.next();
    let mode = arguments.next().ok_or("missing startup-capture mode")?;

    if mode == "launch" {
        let worker = arguments.next().ok_or("missing worker executable")?;
        if arguments.next().is_some() {
            return Err("unexpected launcher argument".into());
        }

        let status = Command::new(worker).arg("capture").status()?;
        if !status.success() {
            return Err(format!("startup capture worker failed: {status}").into());
        }
        return Ok(());
    }

    if mode != "capture" || arguments.next().is_some() {
        return Err("invalid startup-capture mode".into());
    }

    // SAFETY: this single-threaded entry point has not constructed an I/O
    // owner for any inherited descriptor or changed the activation table.
    let claimed = unsafe {
        claim_initial_process_fd_table_once(StartupFdCaptureHardLimitsV1::mount_manager())?
    };
    claimed.revalidate()?;

    let execution = claimed.execution();
    let launcher = claimed.launcher();
    if execution.process.parent_pid() != launcher.process.pid()
        || execution.executable.fs_verity_sha256 == [0; 32]
        || execution.executable.fs_verity_sha256 != launcher.executable.fs_verity_sha256
        || (execution.executable.device, execution.executable.inode)
            == (launcher.executable.device, launcher.executable.inode)
    {
        return Err("startup executable identity did not match the sealed pair".into());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
