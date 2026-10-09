//! Runs real managed-worker containment checks inside a systemd VM.
//!
//! This test executable accepts trusted fixture runner and native executable
//! paths. It exercises the production provider against the VM's actual manager
//! and kernel cgroup controllers; it is not installed in the public tools.

use std::{
    error::Error,
    path::{Path, PathBuf},
    time::Duration,
};

use dispatch_runtime::WorkerFailureCause;
use dispatch_runtime::providers::{
    ExecutionProvider, WorkerConnection, WorkerLaunch,
    systemd::{ManagerScope, SystemdProfile, SystemdProvider, WorkerLimits},
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> ProbeResult<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("expected fixture runner and native executable paths".into());
    }

    run(PathBuf::from(&arguments[0]), PathBuf::from(&arguments[1])).await
}

fn profile() -> ProbeResult<SystemdProfile> {
    Ok(SystemdProfile::new(
        "vm",
        "dispatch-owner.service",
        ManagerScope::System,
        WorkerLimits {
            cpu_weight: 250,
            cpu_quota_percent: 150,
            memory_high_bytes: 64 * 1024 * 1024,
            memory_max_bytes: 96 * 1024 * 1024,
            tasks_max: 16,
            lifetime_seconds: 120,
            startup_timeout_seconds: 15,
            cleanup_timeout_seconds: 5,
        },
    )?)
}

fn launch(runner: &Path, native: &Path, generation: u64) -> WorkerLaunch {
    WorkerLaunch {
        runner: runner.to_owned(),
        native_backend: native.to_owned(),
        native_arguments: Vec::new(),
        session_generation: generation,
        worker_generation: 1,
        max_frame_bytes: 65536,
    }
}

async fn line(connection: &mut WorkerConnection) -> ProbeResult<Option<Value>> {
    // One byte-at-a-time reads avoid consuming a later response when the
    // temporary buffered reader is dropped between fixture commands.
    let mut bytes = Vec::new();
    let mut reader = BufReader::with_capacity(1, &mut connection.reader);
    let count = tokio::time::timeout(
        Duration::from_secs(20),
        reader.read_until(b'\n', &mut bytes),
    )
    .await??;
    if count == 0 {
        return Ok(None);
    }

    Ok(Some(serde_json::from_slice(&bytes)?))
}

async fn required_line(connection: &mut WorkerConnection) -> ProbeResult<Value> {
    line(connection)
        .await?
        .ok_or_else(|| "fixture connection ended unexpectedly".into())
}

async fn command(connection: &mut WorkerConnection, command: &str) -> ProbeResult<()> {
    connection.control.begin_job().await?;
    connection.writer.write_all(command.as_bytes()).await?;
    connection.writer.write_all(b"\n").await?;
    connection.writer.flush().await?;
    Ok(())
}

fn group(info: &Value) -> ProbeResult<PathBuf> {
    let native = info["cgroup"].as_str().ok_or("missing native cgroup")?;
    let runner = info["runner_cgroup"]
        .as_str()
        .ok_or("missing runner cgroup")?;
    if native != runner {
        return Err("runner and native descendant escaped their shared worker boundary".into());
    }

    Ok(Path::new("/sys/fs/cgroup").join(native.trim_start_matches('/')))
}

async fn assert_file(path: impl AsRef<Path>, expected: &str) -> ProbeResult<()> {
    let actual = tokio::fs::read_to_string(path.as_ref()).await?;
    if actual.trim() != expected {
        return Err(format!(
            "{}: expected {expected:?}, got {actual:?}",
            path.as_ref().display()
        )
        .into());
    }

    Ok(())
}

async fn assert_stopped(info: &Value) -> ProbeResult<()> {
    for field in ["pid", "runner_pid"] {
        let pid = info[field].as_u64().ok_or("missing process id")?;
        let path = format!("/proc/{pid}/stat");
        for _ in 0..100 {
            match tokio::fs::read_to_string(&path).await {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(stat)
                    if stat
                        .split(')')
                        .nth(1)
                        .is_some_and(|state| state.starts_with(" Z ")) =>
                {
                    break;
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => return Err(error.into()),
            }
        }

        if let Ok(stat) = tokio::fs::read_to_string(&path).await
            && !stat
                .split(')')
                .nth(1)
                .is_some_and(|state| state.starts_with(" Z "))
        {
            return Err(format!("process {pid} remains live after confirmed stop").into());
        }
    }

    Ok(())
}

async fn local_oom_events(directory: &Path) -> ProbeResult<u64> {
    let events = tokio::fs::read_to_string(directory.join("memory.events.local")).await?;
    for line in events.lines() {
        if let Some(count) = line.strip_prefix("oom ") {
            return Ok(count.parse()?);
        }
    }

    Err("missing local OOM event counter".into())
}

async fn run(runner: PathBuf, native: PathBuf) -> ProbeResult<()> {
    let first_provider = SystemdProvider::connect(profile()?).await?;
    let second_provider = SystemdProvider::connect(profile()?).await?;
    let grant = first_provider.grant();
    if !grant.independent_memory || !grant.aggregate_accounting || !grant.owner_cleanup {
        return Err("managed provider did not grant enforced containment".into());
    }

    let mut first = first_provider.launch(launch(&runner, &native, 1)).await?;
    let mut second = second_provider.launch(launch(&runner, &native, 2)).await?;
    let first_info = required_line(&mut first).await?;
    let second_info = required_line(&mut second).await?;
    let first_group = group(&first_info)?;
    let second_group = group(&second_info)?;
    if first_group.parent() != second_group.parent() || first_group == second_group {
        return Err(
            "sessions did not share one aggregate parent with separate worker leaves".into(),
        );
    }

    for directory in [&first_group, &second_group] {
        assert_file(directory.join("memory.max"), "100663296").await?;
        assert_file(directory.join("memory.high"), "67108864").await?;
        assert_file(directory.join("pids.max"), "16").await?;
        assert_file(directory.join("cpu.weight"), "250").await?;
        let cpu = tokio::fs::read_to_string(directory.join("cpu.max")).await?;
        let values: Vec<u64> = cpu
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        if values.len() != 2 || values[0] * 100 != values[1] * 150 {
            return Err("worker CPU ceiling differs from the granted profile".into());
        }
    }

    let solver_parent = first_group.parent().ok_or("missing solver parent")?;
    let application_parent = solver_parent.parent().ok_or("missing application parent")?;
    assert_file(solver_parent.join("memory.max"), "402653184").await?;
    assert_file(application_parent.join("memory.max"), "536870912").await?;
    assert_file(application_parent.join("cpu.weight"), "400").await?;

    command(&mut first, "tasks").await?;
    let tasks = required_line(&mut first).await?;
    if tasks["limited"] != true
        || tasks["pids_current"]
            .as_u64()
            .is_none_or(|count| count > 16)
    {
        return Err("kernel task limit did not constrain native thread creation".into());
    }

    first.control.stop().await?;
    assert_stopped(&first_info).await?;
    command(&mut second, "hello").await?;
    required_line(&mut second).await?;

    let mut memory = first_provider.launch(launch(&runner, &native, 3)).await?;
    let memory_info = required_line(&mut memory).await?;
    group(&memory_info)?;
    command(&mut memory, "memory").await?;
    if let Some(result) = line(&mut memory).await?
        && result["native_exit"].as_i64() != Some(-9)
    {
        return Err("over-limit allocation did not terminate the native process".into());
    }
    let report = memory
        .control
        .failure_report()
        .await
        .ok_or("missing leaf OOM attribution")?;
    if !matches!(report.cause, WorkerFailureCause::WorkerMemoryLimit) {
        return Err(format!("leaf OOM was not attributed: {report:?}").into());
    }
    memory.control.stop().await?;
    assert_stopped(&memory_info).await?;
    command(&mut second, "hello").await?;
    required_line(&mut second).await?;

    // Each held allocation fits its leaf ceiling. Their combined resident
    // usage must nevertheless reach the solver parent's enforced ceiling.
    // Local events distinguish ancestor OOM from descendant leaf OOM events.
    let ancestor_oom_before = local_oom_events(solver_parent).await?;
    let mut held_workers = Vec::new();
    for generation in 4..10 {
        let mut worker = first_provider
            .launch(launch(&runner, &native, generation))
            .await?;
        let info = required_line(&mut worker).await?;
        command(&mut worker, "hold").await?;
        let _ = line(&mut worker).await?;
        held_workers.push((worker, info));
    }
    if local_oom_events(solver_parent).await? <= ancestor_oom_before {
        return Err("aggregate memory usage bypassed the solver parent ceiling".into());
    }
    let mut attributed_ancestor = false;
    for (worker, info) in held_workers {
        if let Some(report) = worker.control.failure_report().await
            && matches!(report.cause, WorkerFailureCause::AncestorMemoryLimit { ref unit } if unit == "dispatch-vm-solver.slice")
        {
            attributed_ancestor = true;
        }
        worker.control.stop().await?;
        assert_stopped(&info).await?;
    }
    if !attributed_ancestor {
        return Err("ancestor OOM had no attributed victim in the worker leaves".into());
    }

    // Losing the owner must independently stop surviving workers, even while
    // this test process keeps a connection and control handle alive.
    let status = tokio::process::Command::new(
        std::env::var_os("DISPATCH_SYSTEMCTL").ok_or("missing trusted systemctl path")?,
    )
    .args(["stop", "dispatch-owner.service"])
    .status()
    .await?;
    if !status.success() {
        return Err("owner service stop failed".into());
    }
    if line(&mut second).await?.is_some() {
        return Err("owner loss left its worker connected".into());
    }
    second.control.stop().await?;
    assert_stopped(&second_info).await?;

    println!("Dispatch systemd containment passed");
    Ok(())
}
