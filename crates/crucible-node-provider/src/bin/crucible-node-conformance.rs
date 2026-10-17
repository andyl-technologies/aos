//! Runs bounded independent public CNP/1 protocol probes against installed peers.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

fn main() {
    match execute() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("node protocol conformance failed: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(target_os = "linux")]
fn execute() -> Result<bool, Box<dyn std::error::Error>> {
    use crucible_node_provider::conformance::{MAX_PLAN_BYTES, ProbePlan, UnixProbeConnector, run};

    let mut arguments = std::env::args_os().skip(1).peekable();
    if arguments
        .peek()
        .is_some_and(|argument| argument == "--help")
    {
        println!(
            "crucible-node-conformance SOCKET EXPECTED_EXECUTABLE PLAN REPORT [PRIVATE_BINDINGS]\n\
                  Runs public CNP/1 protocol probes with a 3-second per-exchange deadline.\n\
                  Checks actual peer UID and executable bytes. Reports protocol behavior only;\n\
                  successful probes do not qualify CPU fidelity or complete native state capture."
        );
        return Ok(true);
    }
    let socket = PathBuf::from(arguments.next().ok_or("expected provider socket path")?);
    let executable = PathBuf::from(
        arguments
            .next()
            .ok_or("expected installed executable path")?,
    );
    let plan_path = PathBuf::from(arguments.next().ok_or("expected portable plan path")?);
    let report_path = PathBuf::from(arguments.next().ok_or("expected report output path")?);
    let private_bindings = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("unexpected conformance argument".into());
    }
    let plan = ProbePlan::decode(&read_bounded(&plan_path, MAX_PLAN_BYTES)?)?;
    let bindings: BTreeMap<String, serde_json::Value> = match private_bindings {
        Some(path) => serde_json::from_value(crucible_node_contract::canonical::parse_json(
            &read_bounded(&path, MAX_PLAN_BYTES)?,
            MAX_PLAN_BYTES,
        )?)?,
        None => BTreeMap::new(),
    };
    let mut connector = UnixProbeConnector::new(
        socket,
        rustix::process::geteuid().as_raw(),
        &executable,
        Duration::from_secs(3),
    )?;
    let mut report = run(&plan, &mut connector, bindings)?;
    report.harness_executable = Some(crucible_node_provider::conformance::measure_executable(
        &std::env::current_exe()?,
    )?);
    let bytes = report.canonical_bytes()?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report_path)?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!(
        "{} protocol cases; {} required checks missing; {}",
        report.results.len(),
        report.missing_checks.len(),
        if report.passed() { "passed" } else { "failed" }
    );
    Ok(report.passed())
}

#[cfg(target_os = "linux")]
fn read_bounded(
    path: &std::path::Path,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("conformance input exceeds the finite byte allowance".into());
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn execute() -> Result<bool, Box<dyn std::error::Error>> {
    Err("local executable/peer measurement requires the Linux conformance runner".into())
}
