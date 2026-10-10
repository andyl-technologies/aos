// SPDX-License-Identifier: Apache-2.0
//! Dispatches managed Sim measurements to the original admitted native worker.

use std::error::Error;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

/// Runs one Sim trial through the original admitted native worker.
///
/// # Errors
///
/// Refuses missing kernel-runner authority, failed native execution, and absent
/// or ambiguous authenticated measurement output.
pub fn run(workload: &str, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let runner = std::env::var_os("CRUCIBLE_TCG_NATIVE_RUNNER").ok_or(
        "managed Sim requires the packaged native runner in its isolated quota/UFFD kernel",
    )?;
    let cpu_index = if workload == "linux" { 7 } else { 6 };
    let cpu: usize = arguments
        .get(cpu_index)
        .ok_or("missing trial CPU")?
        .parse()?;
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err("trial CPU exceeds the kernel affinity inventory".into());
    }
    let mut command = Command::new(runner);
    // The worker and its admitted children inherit the same requested core as
    // ordinary controls. This does not change their full-vector CPU admission.
    // SAFETY: the child hook uses only a fixed CPU mask and async-signal-safe
    // sched_setaffinity before exec; no borrowed host resources are mutated.
    unsafe {
        command.pre_exec(move || {
            let mut mask: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut mask);
            if libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command
        .args([
            "--ignored", "--exact",
            "packaged_qemu_executor::tests::paging_native::performance::managed_tcg_performance_trial",
            "--nocapture", "--test-threads=1",
        ])
        .env("CRUCIBLE_TCG_PERFORMANCE_WORKLOAD", workload)
        .env("CRUCIBLE_TCG_PERFORMANCE_ARGUMENTS", serde_json::to_string(arguments)?)
        .stdin(Stdio::null())
        .output()?;
    std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;
    if !output.status.success() {
        std::io::Write::write_all(&mut std::io::stderr(), &output.stdout)?;
        return Err("the admitted native performance worker refused or failed its trial".into());
    }
    let transcript = std::str::from_utf8(&output.stdout)?;
    let mut samples = transcript
        .lines()
        .filter_map(|line| line.strip_prefix("TCG_MANAGED_SAMPLE="));
    let sample = samples
        .next()
        .ok_or("native worker returned no authenticated measurement")?;
    if samples.next().is_some() {
        return Err("native worker returned multiple trial measurements".into());
    }
    let decoded: serde_json::Value = serde_json::from_str(sample)?;
    if decoded["managed_owner"] != true || decoded["accepted_assignment"] != true {
        return Err("measurement did not retain its actual accepted native owner".into());
    }
    println!("{sample}");
    Ok(())
}
