//! Exact planned gate execution with sanitized subprocesses and bounded logs.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use aos_maintain::PACKAGE_UPDATE_GATE_RESULTS_V1;
use aos_maintain::plan::{GateSpec, PackageUpdatePlanV1};
use aos_maintain::run::{GateResult, GateResultsV1, PackageUpdateRunV1};
use aos_maintain::workflow::{ActorClass, GateOutcome, RunState};

use super::state::{self, StateStore};

const MAX_GATE_LOG_BYTES: usize = 8 * 1024 * 1024;

/// Runs the immutable quick gate plan and records every result.
///
/// # Errors
///
/// Returns an error when candidate identity changed, an exact gate cannot be
/// spawned or observed, or durable evidence cannot be stored.
pub(super) fn quick(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
) -> Result<GateResultsV1> {
    if run.state == RunState::QuickGated {
        return verified_existing(store, run, "quick");
    }
    if run.state != RunState::PolicyValid {
        bail!("run is not at the quick validation boundary");
    }
    let materialization = store
        .read_materialization(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("quick gates require materialization evidence"))?;
    if let Some(record) = store.read_gate_results(run.run_id.as_str(), "quick")? {
        if record.candidate_digest != materialization.patch_digest {
            bail!("stored quick gates bind a different candidate patch");
        }
        if record.all_succeeded() {
            store.transition(
                run,
                RunState::QuickGated,
                ActorClass::Controller,
                state::now_unix()?,
            )?;
        }
        return Ok(record);
    }

    let mut results = Vec::with_capacity(plan.quick_gates.len());
    let mut logs = Vec::with_capacity(plan.quick_gates.len());
    for gate in &plan.quick_gates {
        let (result, log) = execute_gate(Path::new(&run.worktree), gate)?;
        results.push(result);
        logs.push((gate.id.clone(), log));
    }
    let record = GateResultsV1 {
        schema: PACKAGE_UPDATE_GATE_RESULTS_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: plan.plan_id.clone(),
        phase: "quick".to_string(),
        candidate_digest: materialization.patch_digest,
        results,
        completed_at_unix: state::now_unix()?,
    };
    record.validate()?;
    store.write_gate_results(&record, &logs)?;
    if record.all_succeeded() {
        store.transition(
            run,
            RunState::QuickGated,
            ActorClass::Controller,
            state::now_unix()?,
        )?;
    }
    Ok(record)
}

fn execute_gate(root: &Path, gate: &GateSpec) -> Result<(GateResult, Vec<u8>)> {
    let executable = std::env::current_exe().context("resolving frozen controller executable")?;
    let started = Instant::now();
    let mut command = Command::new(executable);
    command
        .args(&gate.argv[1..])
        .current_dir(root)
        .env_clear()
        .env("AOS_ROOT", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "NIX_REMOTE",
        "NIX_CONFIG",
        "NIX_SSL_CERT_FILE",
        "SSL_CERT_FILE",
        "XDG_CACHE_HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning planned gate {}", gate.id))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("planned gate stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("planned gate stderr was not captured"))?;
    let stdout_reader = std::thread::spawn(move || bounded_read(stdout));
    let stderr_reader = std::thread::spawn(move || bounded_read(stderr));
    let status = child.wait().context("waiting for planned gate")?;
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("planned gate stdout reader panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("planned gate stderr reader panicked"))??;
    let mut log = Vec::with_capacity(
        stdout
            .len()
            .saturating_add(stderr.len())
            .min(MAX_GATE_LOG_BYTES),
    );
    append_log(&mut log, b"stdout:\n", &stdout);
    append_log(&mut log, b"\nstderr:\n", &stderr);
    if stdout_truncated || stderr_truncated {
        append_log(&mut log, b"\n", b"[output truncated by aos maintain]\n");
    }
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let result = GateResult {
        gate_id: gate.id.clone(),
        argv: gate.argv.clone(),
        outcome: if status.success() {
            GateOutcome::Success
        } else {
            GateOutcome::Failure
        },
        exit_code: status.code(),
        log_digest: aos_contract::Sha256Digest::separated("aos.package-update-gate-log/v1", &log),
        log_bytes: u64::try_from(log.len()).context("gate log length overflow")?,
        elapsed_ms,
    };
    Ok((result, log))
}

fn bounded_read(mut reader: impl std::io::Read) -> Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_GATE_LOG_BYTES.saturating_sub(retained.len());
        let accepted = remaining.min(count);
        retained.extend_from_slice(&buffer[..accepted]);
        truncated |= accepted < count;
    }
    Ok((retained, truncated))
}

fn append_log(output: &mut Vec<u8>, label: &[u8], bytes: &[u8]) {
    let remaining = MAX_GATE_LOG_BYTES.saturating_sub(output.len());
    output.extend_from_slice(&label[..label.len().min(remaining)]);
    let remaining = MAX_GATE_LOG_BYTES.saturating_sub(output.len());
    output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn verified_existing(
    store: &StateStore,
    run: &PackageUpdateRunV1,
    phase: &str,
) -> Result<GateResultsV1> {
    let record = store
        .read_gate_results(run.run_id.as_str(), phase)?
        .ok_or_else(|| anyhow::anyhow!("run state has no matching gate evidence"))?;
    if !record.all_succeeded() {
        bail!("run state claims successful gates but retained results failed");
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_drains_but_retains_only_the_limit() -> Result<()> {
        let bytes = vec![b'x'; MAX_GATE_LOG_BYTES + 17];
        let (retained, truncated) = bounded_read(bytes.as_slice())?;
        assert_eq!(retained.len(), MAX_GATE_LOG_BYTES);
        assert!(truncated);
        Ok(())
    }
}
