//! Exercises the actual Linux pure-worker owner inside its disposable VM.
//!
//! The source-built probe tests kernel enforcement, not Source or bank issuance.
//! Every attempt must return only after waited reap, empty group and disk cleanup.

use sha2::{Digest, Sha256};
use std::error::Error;
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crucible_host_resources::{
    LinuxPureWorkerAttempt, LinuxPureWorkerConfiguration, LinuxPureWorkerFactory,
    LinuxPureWorkerFailure, LinuxPureWorkerLimits, LinuxPureWorkerOutcome, LinuxPureWorkerProgram,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn check(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}

fn measure(mut file: std::fs::File) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

fn limits() -> LinuxPureWorkerLimits {
    LinuxPureWorkerLimits {
        memory_bytes: 32 * 1024 * 1024,
        address_space_bytes: 256 * 1024 * 1024,
        cpu_seconds: 2,
        descriptors: 32,
        disk_bytes: 1024 * 1024,
        inodes: 32,
        input_bytes: 1024,
        elements: 1024,
        bank_bytes: 1024,
        diagnostic_bytes: 256,
        stdout_bytes: 2048,
        stderr_bytes: 2048,
        wall_seconds: 15,
    }
}

fn wait(attempt: &mut LinuxPureWorkerAttempt) -> Result<LinuxPureWorkerOutcome> {
    let started = Instant::now();
    loop {
        if let Some(outcome) = attempt.take_outcome()? {
            return Ok(outcome);
        }
        check(
            started.elapsed() < Duration::from_secs(25),
            "owner did not complete cleanup",
        )?;
        thread::sleep(Duration::from_millis(10));
    }
}

fn clean(configuration: &LinuxPureWorkerConfiguration) -> Result<()> {
    check(
        std::fs::read_dir(&configuration.run_root)?.next().is_none(),
        "quota directory remains",
    )?;
    check(
        !configuration.cgroup_root.join("pure-worker").exists(),
        "cgroup remains",
    )
}

fn run(factory: &LinuxPureWorkerFactory, mode: &str) -> Result<LinuxPureWorkerOutcome> {
    let mut attempt = factory.reserve(limits())?;
    attempt.prepare_input()?;
    let prepared = attempt.direct_buffer_census()?;
    check(
        prepared.program_path_bytes > 0
            && prepared.namespace_path_bytes > 0
            && prepared.attempt_path_bytes > 0
            && prepared.output_capacity_bytes == 0,
        "prepared direct buffer census does not describe actual retained paths",
    )?;
    attempt.write_all(mode.as_bytes())?;
    attempt.start()?;
    wait(&mut attempt)
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    check(
        arguments.len() >= 5,
        "helper worker group run roots are required",
    )?;
    let configuration = LinuxPureWorkerConfiguration {
        cgroup_root: PathBuf::from(&arguments[2]),
        run_root: PathBuf::from(&arguments[3]),
        project_id: 23025,
        child_user_id: 23025,
        child_group_id: 23025,
    };
    let roots: Vec<_> = arguments[4..].iter().map(PathBuf::from).collect();
    let worker_digest = measure(std::fs::File::open(&arguments[1])?)?;
    // For this OS-only fixture the probe's actual ELF identifies its algorithm.
    // Production binds the separate reviewed DeriveSourceBirth algorithm ID.
    let program = LinuxPureWorkerProgram::open(
        arguments[0].as_ref(),
        arguments[1].as_ref(),
        &roots,
        worker_digest,
        worker_digest,
    )?;
    check(
        measure(program.worker_file().try_clone()?)? == worker_digest,
        "opened worker differs from measured probe",
    )?;
    let _actual_launcher_digest = measure(program.launcher_file().try_clone()?)?;
    program.verify_current()?;
    let program_identity = program.identity();

    let mut unavailable = configuration.clone();
    unavailable.cgroup_root.push("not-delegated");
    check(
        LinuxPureWorkerFactory::open(unavailable, program.clone()).is_err(),
        "missing delegation was accepted",
    )?;
    let factory = LinuxPureWorkerFactory::open(configuration.clone(), program)?;
    check(
        factory.program_identity() == program_identity,
        "factory changed installation",
    )?;

    for mode in [
        "success",
        "network",
        "clone",
        "filesystem",
        "descriptors",
        "address-space",
    ] {
        let outcome = run(&factory, mode)?;
        check(
            outcome.failure.is_none() && outcome.status.is_some_and(|s| s.success()),
            "positive denial probe failed",
        )?;
        let expected = format!(
            "PASS:{mode}:{}\n",
            outcome
                .child_id
                .ok_or_else(|| io::Error::other("missing std child pid"))?
        );
        check(
            outcome.stdout == expected.as_bytes(),
            "helper changed PID or probe did not pass",
        )?;
        check(
            outcome.stderr.is_empty(),
            "successful probe emitted diagnostics",
        )?;
        clean(&configuration)?;
    }

    let cpu = run(&factory, "cpu")?;
    check(
        cpu.stdout == b"CPU:started\n"
            && cpu.memory_oom_kills == Some(0)
            && cpu.failure == Some(LinuxPureWorkerFailure::ChildExit)
            && cpu.status.is_some_and(|status| {
                matches!(status.signal(), Some(libc::SIGKILL) | Some(libc::SIGXCPU))
            }),
        "CPU probe did not die from the enforced resource signal",
    )?;
    clean(&configuration)?;
    let memory = run(&factory, "memory")?;
    check(
        memory.stdout == b"MEMORY:started\nMEMORY:mapped\n"
            && memory.failure == Some(LinuxPureWorkerFailure::ChildExit)
            && memory
                .status
                .is_some_and(|status| status.signal() == Some(libc::SIGKILL))
            && memory.memory_oom_kills.is_some_and(|count| count > 0),
        "memory probe lacks actual waited kill and same-cgroup OOM evidence",
    )?;
    clean(&configuration)?;
    let output = run(&factory, "output")?;
    check(
        (output.failure == Some(LinuxPureWorkerFailure::StdoutLimit) && output.status.is_some())
            || (output.failure == Some(LinuxPureWorkerFailure::ChildExit)
                && output
                    .status
                    .is_some_and(|status| status.signal() == Some(libc::SIGXFSZ))),
        "disk output cap was not enforced",
    )?;
    check(
        output.stdout.len() <= limits().stdout_bytes,
        "retained output exceeded cap",
    )?;
    clean(&configuration)?;

    let mut cancelled = factory.reserve(limits())?;
    cancelled.prepare_input()?;
    cancelled.write_all(b"cancel")?;
    cancelled.start()?;
    let started = Instant::now();
    while cancelled.child_id().is_none() {
        check(
            started.elapsed() < Duration::from_secs(5),
            "std spawn did not return",
        )?;
        thread::sleep(Duration::from_millis(1));
    }
    cancelled.cancel();
    let cancelled_outcome = wait(&mut cancelled)?;
    check(
        cancelled_outcome.failure == Some(LinuxPureWorkerFailure::Cancelled),
        "cancellation was not sticky",
    )?;
    check(
        cancelled_outcome.status.is_some(),
        "cancel returned without original-child wait",
    )?;
    clean(&configuration)?;

    let mut overflow = factory.reserve(limits())?;
    overflow.prepare_input()?;
    check(
        overflow.write_all(&[0; 1025]).is_err(),
        "input cap was ignored",
    )?;
    check(
        matches!(
            overflow.take_input_error(),
            Some(crucible_host_resources::LinuxPureWorkerError::InputLimit)
        ),
        "actual export cause was lost",
    )?;
    check(
        overflow.take_input_error().is_none(),
        "export cause was duplicated",
    )?;
    let failed = wait(&mut overflow)?;
    check(
        failed.failure == Some(LinuxPureWorkerFailure::InputExport) && failed.child_id.is_none(),
        "failed export launched a child",
    )?;
    clean(&configuration)?;

    let mut success = factory.reserve(limits())?;
    let identity = success.identity();
    success.prepare_input()?;
    success.write_all(b"success")?;
    success.start()?;
    let started = Instant::now();
    let completion = loop {
        if let Some(completion) = success.take_completion()? {
            break completion;
        }
        check(
            started.elapsed() < Duration::from_secs(25),
            "sealed completion did not arrive",
        )?;
        thread::sleep(Duration::from_millis(10));
    };
    completion.verify_original(&identity, &program_identity)?;
    let observed = completion.direct_buffer_census()?;
    check(
        observed.attempt_path_bytes == 0
            && observed.output_capacity_bytes
                >= completion.outcome().stdout.len() + completion.outcome().stderr.len(),
        "completion census lost moved output buffers or retained a deleted path",
    )?;
    let foreign = factory.reserve(limits())?;
    check(
        completion
            .verify_original(&foreign.identity(), &program_identity)
            .is_err(),
        "foreign attempt accepted completion",
    )?;
    drop(foreign);
    success.cancel();
    check(
        completion
            .verify_original(&identity, &program_identity)
            .is_err(),
        "post-completion cancellation revived acceptance",
    )?;
    check(
        success.take_completion().is_err(),
        "completion was transferred twice",
    )?;

    println!("PASS");
    println!("same_pid_kernel_profile_and_waited_cleanup=true");
    println!("memory_cpu_network_clone_fd_filesystem_output_cancel_refusal=true");
    println!("sealed_same_original_completion_and_sticky_cancel=true");
    Ok(())
}
