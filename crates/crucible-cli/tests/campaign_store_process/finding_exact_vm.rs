//! Fresh-process, packaged-QEMU verification of a portable retained finding.

use super::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::sync::mpsc::Receiver;

use sha2::{Digest, Sha256};

#[test]
#[ignore]
fn midpoint_socket_denies_other_uid() -> Result<(), Box<dyn Error>> {
    let socket = std::env::var_os("CRUCIBLE_MIDPOINT_SOCKET_PROBE")
        .ok_or("socket identity probe requires a socket path")?;
    let error = UnixStream::connect(socket).expect_err("another uid opened private GDB relay");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn packaged_finding_bundle_replays_without_source_owner() -> Result<(), Box<dyn Error>> {
    with_copied_bundle(
        midpoint_debug::FindingScenario::MarkerOnly,
        inspect_exact_read_only,
    )
}

#[test]
fn packaged_finding_bundle_fork_write_is_noncanonical() -> Result<(), Box<dyn Error>> {
    with_copied_bundle(
        midpoint_debug::FindingScenario::MarkerOnly,
        inspect_noncanonical_fork,
    )
}

#[test]
fn packaged_finding_bundle_retains_selected_fault_and_guest_response() -> Result<(), Box<dyn Error>>
{
    with_copied_bundle(
        midpoint_debug::FindingScenario::CpuServiceFault,
        inspect_signal_rich_bundle,
    )
}

fn with_copied_bundle(
    scenario: midpoint_debug::FindingScenario,
    inspect: impl FnOnce(&Path, &Path, &Value) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    midpoint_debug::run_public_campaign_debug_flight_with_stopped_finding(
        scenario,
        |fixture, snapshot, finding| {
            grant_export_reads(&fixture.peer_policy)?;
            let source_bundle = fixture._temporary.path().join("exported-finding");
            let exported = run_json(
                command(&[
                    "--format",
                    "jsonl",
                    "campaign",
                    "finding-bundle",
                    "export",
                    CAMPAIGN,
                ])
                .args(["--snapshot", snapshot, "--finding", finding])
                .arg("--source-state")
                .arg(&fixture.state)
                .arg("--source-policy")
                .arg(&fixture.peer_policy)
                .arg("--source-store")
                .arg(&fixture.store)
                .arg("--output")
                .arg(&source_bundle),
                "export retained finding as executable archive",
            )?;
            assert_eq!(
                exported["schema"],
                "crucible.cli.campaign-finding-bundle-export.v2"
            );
            assert_eq!(exported["native_signature_verified"], true);
            assert_eq!(exported["snapshot"], snapshot);
            assert_eq!(exported["finding"], finding);

            let investigator = TempDir::new()?;
            let bundle = investigator.path().join("finding-bundle");
            copy_bundle(&source_bundle, &bundle)?;

            // Only the copied bundle and the immutable package closure survive
            // the handoff. A stale source path must be unusable by the verifier.
            fs::remove_dir_all(fixture._temporary.path())?;
            inspect(&bundle, investigator.path(), &exported["minimization"])
        },
    )
}

fn inspect_exact_read_only(
    bundle: &Path,
    working_directory: &Path,
    export_minimization: &Value,
) -> Result<(), Box<dyn Error>> {
    assert_localized_minimization(export_minimization)?;
    let pristine_bundle = bundle_fingerprints(bundle)?;
    let verified = run_json(
        &mut verify_command(bundle, working_directory)?,
        "verify exact finding in a fresh packaged process",
    )?;
    assert_eq!(
        verified["schema"],
        "crucible.cli.campaign-finding-bundle-verification.v2"
    );
    assert_eq!(verified["native_signature_verified"], true);
    assert_eq!(verified["model_replay"]["authenticated"], true);
    assert_eq!(verified["minimization"], *export_minimization);
    assert_eq!(verified["exact_replay"]["role"], "verification-original");
    assert_eq!(verified["exact_replay"]["reproduced"], true);
    assert!(json_u64(&verified["exact_replay"], "completed_quanta")? > 0);
    assert!(json_u64(&verified["exact_replay"], "frontier_ticks")? > 0);

    inspect_read_only_midpoint(bundle, working_directory, false)?;
    for packet in ["G00", "M0,1:00", "c"] {
        reject_midpoint_mutation(bundle, working_directory, packet)?;
    }
    assert_eq!(
        bundle_fingerprints(bundle)?,
        pristine_bundle,
        "midpoint inspection changed the handed-off bundle"
    );

    let ledger = bundle.join("ledger");
    let original_ledger = fs::read(&ledger)?;
    corrupt_file(&ledger)?;
    reject_bundle(bundle, working_directory, "altered ledger")?;
    fs::write(ledger, original_ledger)?;

    let object = archive_manifest_object(bundle)?;
    assert!(
        object.is_file(),
        "export omitted its archive manifest object"
    );
    fs::remove_file(object)?;
    reject_bundle(bundle, working_directory, "missing archive object")?;

    println!("finding_bundle_fresh_process_exact_qemu=true");
    println!("finding_bundle_source_owner_absent=true");
    println!("finding_bundle_signature_and_terminal_reproduced=true");
    println!("finding_bundle_live_midpoint_read_only=true");
    println!("finding_bundle_mutation_rejected_and_checkpoint_unchanged=true");
    println!("finding_bundle_tamper_rejected=true");
    Ok(())
}

fn inspect_signal_rich_bundle(
    bundle: &Path,
    working_directory: &Path,
    _export_minimization: &Value,
) -> Result<(), Box<dyn Error>> {
    let pristine_bundle = bundle_fingerprints(bundle)?;
    let verified = run_json(
        &mut verify_command(bundle, working_directory)?,
        "verify selected-fault finding in a fresh packaged process",
    )?;
    assert_eq!(verified["native_signature_verified"], true);
    assert_eq!(verified["model_replay"]["authenticated"], true);
    assert_eq!(verified["exact_replay"]["role"], "verification-original");
    assert_eq!(verified["exact_replay"]["reproduced"], true);
    assert!(json_u64(&verified["exact_replay"], "completed_quanta")? > 0);
    assert!(json_u64(&verified["exact_replay"], "frontier_ticks")? > 0);

    inspect_read_only_midpoint(bundle, working_directory, true)?;
    assert_eq!(
        bundle_fingerprints(bundle)?,
        pristine_bundle,
        "signal-rich inspection changed the handed-off bundle"
    );
    println!("finding_bundle_selected_fault_and_guest_response=true");
    println!("finding_bundle_signal_archive_unchanged=true");
    Ok(())
}

fn inspect_noncanonical_fork(
    bundle: &Path,
    working_directory: &Path,
    _export_minimization: &Value,
) -> Result<(), Box<dyn Error>> {
    let pristine_bundle = bundle_fingerprints(bundle)?;
    let (mut process, report, mut stream) = MidpointProcess::start_fork(bundle, working_directory)?;
    assert_eq!(
        report["schema"],
        "crucible.cli.campaign-finding-bundle-fork-write.v1"
    );
    assert_eq!(report["read_only"], false);
    assert_eq!(report["branch_classification"], "non-canonical");
    assert_eq!(report["selection_sequence"], "fast,q7");
    assert_eq!(report["canonical_session_unchanged"], true);
    assert_eq!(report["archive_manifest_unchanged"], true);
    assert_eq!(report["checkpoint_unchanged"], true);
    assert!(report["checkpoint"].as_str().is_some());
    assert!(report["archive_manifest"].as_str().is_some());

    let original = report["canonical_register_hex"]
        .as_str()
        .ok_or("fork proof omitted canonical register")?;
    let branch = report["branch_register_hex"]
        .as_str()
        .ok_or("fork proof omitted branch register")?;
    assert_eq!(original.len(), branch.len());
    assert!(original.len() >= 2 && original.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(branch.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(original, branch, "branch write did not change the register");
    let branch_id = report["branch"]
        .as_str()
        .ok_or("fork proof omitted branch identity")?;
    assert_eq!(branch_id.len(), 64);
    assert!(branch_id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    assert_socket_denies_other_uid(&process.socket)?;
    let qemu_pids = packaged_qemu_pids()?;
    assert_eq!(
        qemu_pids.len(),
        2,
        "fork did not keep two distinct QEMUs live"
    );
    let observed_branch = rsp_request(&mut stream, "p0")?;
    assert!(
        observed_branch.eq_ignore_ascii_case(branch),
        "live branch register differs from the write proof"
    );
    drop(stream);
    let (status, stderr) = process.finish()?;
    assert!(
        status.success(),
        "noncanonical fork exited unsuccessfully: {stderr}"
    );
    assert!(!process.socket.exists(), "fork relay socket survived exit");
    assert_no_packaged_qemu()?;
    assert_eq!(
        bundle_fingerprints(bundle)?,
        pristine_bundle,
        "fork write modified the handed-off bundle"
    );

    println!("finding_bundle_fork_source_owner_absent=true");
    println!("finding_bundle_two_live_packaged_qemu=true");
    println!("finding_bundle_noncanonical_register_write=true");
    println!("finding_bundle_canonical_checkpoint_and_bundle_unchanged=true");
    println!("finding_bundle_fork_qemu_teardown=true");
    Ok(())
}

fn grant_export_reads(policy: &Path) -> Result<(), Box<dyn Error>> {
    {
        let mut file = fs::OpenOptions::new().append(true).open(policy)?;
        for operation in [
            "query-campaign-finding-occurrences",
            "get-campaign-finding-occurrence-object",
            "get-campaign-finding-triage-replay-segment",
        ] {
            writeln!(
                file,
                "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = {operation:?}\ncampaign = \"*\""
            )?;
        }
    }

    let policy = UnixPeerCampaignPolicy::from_toml_bytes(&fs::read(policy)?)?;
    let principal = CampaignPrincipal::new(PRINCIPAL)?;
    let campaign = CampaignName::new(CAMPAIGN)?;
    let request = CampaignHash::derive("finding-exact-vm-export-grants", b"ledger");
    for operation in [
        CampaignServiceOperation::QueryCampaignFindings,
        CampaignServiceOperation::QueryCampaignFindingOccurrences,
        CampaignServiceOperation::GetCampaignFindingObject,
        CampaignServiceOperation::GetCampaignFindingOccurrenceObject,
        CampaignServiceOperation::GetCampaignFindingTriageReplaySegment,
    ] {
        policy.authorize(&principal, operation, &campaign, request)?;
    }
    Ok(())
}

fn assert_localized_minimization(report: &Value) -> Result<(), Box<dyn Error>> {
    let retained = report["retained"]
        .as_object()
        .ok_or("finding bundle has no retained minimization outcome")?;
    let original = retained["original_reproduction"]
        .as_str()
        .ok_or("minimization omitted original reproduction")?;
    let minimized = retained["minimized_reproduction"]
        .as_str()
        .ok_or("minimization omitted selected reproduction")?;
    assert_ne!(original, minimized);
    assert!(json_u64(&report["retained"], "policy_schema")? > 0);

    let original_decisions = json_u64(&report["retained"], "original_schedule_decisions")?;
    let minimized_decisions = json_u64(&report["retained"], "minimized_schedule_decisions")?;
    let original_selections = json_u64(&report["retained"], "original_selections")?;
    let minimized_selections = json_u64(&report["retained"], "minimized_selections")?;
    assert!(original_selections > 0);
    assert!(minimized_selections <= original_selections);
    let attempts = retained["attempts"]
        .as_array()
        .ok_or("minimization omitted candidate history")?;
    match report["disposition"].as_str() {
        Some("candidate-accepted") => {
            assert_eq!(retained["schedule_reduced"], true);
            assert!(minimized_decisions < original_decisions);
            assert!(
                attempts.iter().any(|attempt| attempt["accepted"] == true),
                "accepted minimization has no accepted candidate"
            );
        }
        Some("no-reduction") => {
            assert_eq!(retained["schedule_reduced"], false);
            assert_eq!(minimized_decisions, original_decisions);
            assert!(
                report["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
            );
            assert!(attempts.iter().all(|attempt| attempt["accepted"] == false));
            if original_decisions > 0 {
                assert!(
                    attempts.iter().any(|attempt| {
                        matches!(
                            attempt["outcome"].as_str(),
                            Some("no-fingerprint" | "different-fingerprint")
                        )
                    }),
                    "no-reduction trace did not localize a rejected candidate"
                );
            }
        }
        _ => return Err("finding bundle has no localized minimization disposition".into()),
    }
    Ok(())
}

fn verify_command(bundle: &Path, working_directory: &Path) -> Result<Command, Box<dyn Error>> {
    let mut process = packaged_command(working_directory)?;
    process
        .args(["campaign", "finding-bundle", "verify"])
        .arg(bundle)
        .arg("--exact");
    Ok(process)
}

fn packaged_command(working_directory: &Path) -> Result<Command, Box<dyn Error>> {
    let binary = std::env::var_os("CRUCIBLE_EXACT_BUNDLE_BINARY")
        .ok_or("CRUCIBLE_EXACT_BUNDLE_BINARY is required for the packaged gate")?;
    let deployment = std::env::var_os("CRUCIBLE_FLIGHT_DEPLOYMENT")
        .ok_or("CRUCIBLE_FLIGHT_DEPLOYMENT is required for the packaged gate")?;
    let mut process = Command::new(binary);
    process
        .current_dir(working_directory)
        .env_remove("CRUCIBLE_QEMU")
        .env_remove("CRUCIBLE_PLUGIN")
        .env_remove("CRUCIBLE_EXACT_BUNDLE_BINARY")
        .env_remove("CRUCIBLE_PROCESS_FLIGHT_BINARY")
        .env_remove("CRUCIBLE_FLIGHT_DEPLOYMENT")
        .env_remove("CRUCIBLE_FLIGHT_QEMU")
        .env_remove("CRUCIBLE_FLIGHT_PLUGIN")
        .env_remove("CRUCIBLE_DEBUG_GATEWAY")
        .env_remove("CRUCIBLE_KERNEL")
        .env_remove("CRUCIBLE_INITRD")
        .env_remove("CRUCIBLE_ROOT_IMAGE")
        .env_remove("CRUCIBLE_RUN_STATE_ROOT")
        .env_remove("CRUCIBLE_NATIVE_GUEST_ARCHITECTURE")
        .args(["--format", "jsonl", "--campaign-deployment"])
        .arg(deployment);
    Ok(process)
}

struct MidpointProcess {
    child: Child,
    lines: Receiver<String>,
    socket: PathBuf,
}

impl MidpointProcess {
    fn start(
        bundle: &Path,
        working_directory: &Path,
    ) -> Result<(Self, Value, UnixStream), Box<dyn Error>> {
        let mut command = packaged_command(working_directory)?;
        command
            .args(["campaign", "finding-bundle", "midpoint"])
            .arg(bundle)
            .args(["--node", "choice-node"]);
        Self::start_command(command, working_directory)
    }

    fn start_fork(
        bundle: &Path,
        working_directory: &Path,
    ) -> Result<(Self, Value, UnixStream), Box<dyn Error>> {
        let mut command = packaged_command(working_directory)?;
        command
            .args(["campaign", "finding-bundle", "fork-write"])
            .arg(bundle)
            .args([
                "--node",
                "choice-node",
                "--register",
                "0",
                "--xor-mask",
                "1",
                "--serve",
            ]);
        Self::start_command(command, working_directory)
    }

    fn start_command(
        mut command: Command,
        working_directory: &Path,
    ) -> Result<(Self, Value, UnixStream), Box<dyn Error>> {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or("midpoint stdout was unavailable")?;
        let (sender, lines) = std_mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut process = Self {
            child,
            lines,
            socket: PathBuf::new(),
        };
        let report: Value = serde_json::from_str(&process.next_line()?)?;
        let readiness = process.next_line()?;
        let socket = readiness
            .strip_prefix("crucible: private GDB relay listening at ")
            .ok_or_else(|| format!("midpoint did not open its local relay: {readiness}"))?
            .into();
        let metadata = fs::symlink_metadata(&socket)?;
        assert!(
            metadata.file_type().is_socket(),
            "relay is not a Unix socket"
        );
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), fs::metadata(working_directory)?.uid());
        process.socket = socket;
        let mut stream = UnixStream::connect(&process.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        let initial_stop = read_rsp_packet(&mut stream)?;
        assert!(
            initial_stop.starts_with('T') || initial_stop.starts_with('S'),
            "midpoint relay omitted its initial QEMU stop: {initial_stop}"
        );
        Ok((process, report, stream))
    }

    fn next_line(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.lines.recv_timeout(Duration::from_secs(60))?)
    }

    fn finish(&mut self) -> Result<(ExitStatus, String), Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                self.child.kill()?;
                return Err("midpoint relay did not exit after GDB disconnect".into());
            }
            thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .ok_or("midpoint stderr was unavailable")?
            .read_to_string(&mut stderr)?;
        Ok((status, stderr))
    }
}

impl Drop for MidpointProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn inspect_read_only_midpoint(
    bundle: &Path,
    working_directory: &Path,
    signal_rich: bool,
) -> Result<(), Box<dyn Error>> {
    let (mut process, report, mut stream) = MidpointProcess::start(bundle, working_directory)?;
    assert_socket_denies_other_uid(&process.socket)?;
    assert_eq!(
        report["schema"],
        "crucible.cli.campaign-finding-bundle-midpoint.v1"
    );
    assert_eq!(report["read_only"], true);
    assert_eq!(report["branch_classification"], "no-branch");
    assert_eq!(report["selection_sequence"], "fast,q7");
    assert_eq!(report["selections"], serde_json::json!(["fast", "q7"]));
    assert!(
        report["failure_detail"]
            .as_str()
            .ok_or("midpoint failure detail is missing")?
            .contains("selected-fast-q7")
    );
    assert!(json_u64(&report, "restore_bytes")? > 0);
    assert!(json_u64(&report, "causal_entries")? > 0);
    let events = report["events"]
        .as_array()
        .ok_or("midpoint event log is missing")?;
    assert!(!events.is_empty());
    for (sequence, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"].as_u64(), Some(sequence as u64));
    }
    assert!(json_u64(&report["metrics"], "payload_schema")? > 0);
    assert!(report["metrics"]["payload_hex"].as_str().is_some());
    assert!(report["metrics"]["evidence"].as_array().is_some());
    if signal_rich {
        assert_selected_cpu_fault_and_guest_response(&report)?;
    } else {
        assert!(report["signal_effects"].is_null());
    }

    let stop = rsp_request(&mut stream, "?")?;
    assert!(
        !stop.starts_with('E'),
        "midpoint stop request failed: {stop}"
    );
    let registers = rsp_request(&mut stream, "g")?;
    assert!(
        registers.len() > 32
            && registers
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'x')
    );
    let instruction_pointer = rsp_request(&mut stream, "p10")?;
    assert_eq!(instruction_pointer.len(), 16);
    let mut rip_bytes = [0_u8; 8];
    for (index, byte) in rip_bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&instruction_pointer[index * 2..index * 2 + 2], 16)?;
    }
    let instruction = rsp_request(
        &mut stream,
        &format!("m{:x},1", u64::from_le_bytes(rip_bytes)),
    )?;
    assert_eq!(instruction.len(), 2);
    assert!(instruction.bytes().all(|byte| byte.is_ascii_hexdigit()));

    drop(stream);
    let (status, stderr) = process.finish()?;
    assert!(
        status.success(),
        "read-only midpoint exited unsuccessfully: {stderr}"
    );
    assert!(
        !process.socket.exists(),
        "private relay socket survived exit"
    );
    assert_no_packaged_qemu()?;
    Ok(())
}

fn assert_selected_cpu_fault_and_guest_response(report: &Value) -> Result<(), Box<dyn Error>> {
    let work_items = report["signal_effects"]["work_items"]
        .as_array()
        .ok_or("copied finding omitted its resolved signal-effect trace")?;
    let effect = work_items
        .iter()
        .flat_map(|item| item["records"].as_array().into_iter().flatten())
        .find(|record| {
            record["binding"] == midpoint_debug::signal::BINDING
                && record["effect"] == "CpuService"
                && record["action_kind"] == "upsert_persistent"
        })
        .ok_or("copied finding has no committed QEMU CPU-service fault")?;
    assert_eq!(effect["capability"], "qemu.cpu.service.v1");
    assert_eq!(effect["phase"], "run");
    assert!(
        effect["coordinate"]["retired_instructions"]
            .as_u64()
            .is_some()
    );
    let fault_time = json_u64(&effect["coordinate"], "virtual_nanos")?;

    let guest_marker = report["events"]
        .as_array()
        .ok_or("copied finding omitted its guest event log")?
        .iter()
        .find(|event| {
            event["event_payload"]["kind"] == "guest_marker"
                && event.to_string().contains("selected-fast-q7")
        })
        .ok_or("selected fault has no retained guest response marker")?;
    let guest_time = json_u64(&guest_marker["at"]["virtual_time"], "ticks")?;
    assert!(
        fault_time <= guest_time,
        "fault was applied after the guest response"
    );
    assert!(
        report["failure_detail"].as_str().is_some_and(
            |detail| detail.contains("inner guest marker marker=selected-fast-q7 matched")
        ),
        "finding did not explain the selected guest response"
    );
    Ok(())
}

fn reject_midpoint_mutation(
    bundle: &Path,
    working_directory: &Path,
    packet: &str,
) -> Result<(), Box<dyn Error>> {
    let (mut process, report, mut stream) = MidpointProcess::start(bundle, working_directory)?;
    assert_eq!(report["branch_classification"], "no-branch");
    write_rsp_packet(&mut stream, packet)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let (status, stderr) = process.finish()?;
    assert!(
        !status.success(),
        "RSP {packet} unexpectedly changed read-only QEMU"
    );
    assert!(
        stderr.contains("read-only") || stderr.contains("state-changing"),
        "RSP {packet} failed for an unrelated reason: {stderr}"
    );
    assert!(
        !process.socket.exists(),
        "private relay socket survived denial"
    );
    assert_no_packaged_qemu()?;
    Ok(())
}

fn assert_no_packaged_qemu() -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if packaged_qemu_pids()?.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("packaged QEMU remained alive after midpoint relay exit".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn packaged_qemu_pids() -> Result<BTreeSet<u32>, Box<dyn Error>> {
    let packaged_qemu = fs::canonicalize(
        std::env::var_os("CRUCIBLE_FLIGHT_QEMU")
            .ok_or("CRUCIBLE_FLIGHT_QEMU is required for the packaged gate")?,
    )?;
    let packaged_qemu_command = packaged_qemu.to_string_lossy().into_owned().into_bytes();
    let mut pids = BTreeSet::new();
    for entry in fs::read_dir("/proc")?.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let process = entry.path();
        let executable = fs::read_link(process.join("exe")).ok();
        let command = fs::read(process.join("cmdline")).ok();
        if executable.as_deref() == Some(packaged_qemu.as_path())
            || command.as_deref().is_some_and(|bytes| {
                bytes.split(|byte| *byte == 0).next() == Some(packaged_qemu_command.as_slice())
            })
        {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

fn assert_socket_denies_other_uid(socket: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "finding_exact_vm::midpoint_socket_denies_other_uid",
        ])
        .env("CRUCIBLE_MIDPOINT_SOCKET_PROBE", socket)
        .uid(65534)
        .gid(65534)
        .output()?;
    assert!(
        output.status.success(),
        "another uid socket probe failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn rsp_request(stream: &mut UnixStream, packet: &str) -> Result<String, Box<dyn Error>> {
    write_rsp_packet(stream, packet)?;
    read_rsp_packet(stream)
}

fn read_rsp_packet(stream: &mut UnixStream) -> Result<String, Box<dyn Error>> {
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'$' {
            break;
        }
        if byte[0] != b'+' {
            return Err(format!("unexpected GDB response prefix: {:02x}", byte[0]).into());
        }
    }
    let mut response = Vec::new();
    loop {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'#' {
            break;
        }
        response.push(byte[0]);
        if response.len() > 65_536 {
            return Err("GDB response exceeds test bound".into());
        }
    }
    let mut checksum = [0_u8; 2];
    stream.read_exact(&mut checksum)?;
    let expected = u8::from_str_radix(std::str::from_utf8(&checksum)?, 16)?;
    let actual = response
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    assert_eq!(actual, expected, "GDB response checksum mismatch");
    stream.write_all(b"+")?;
    Ok(String::from_utf8(response)?)
}

fn write_rsp_packet(stream: &mut UnixStream, packet: &str) -> Result<(), Box<dyn Error>> {
    let checksum = packet
        .bytes()
        .fold(0_u8, |sum, byte| sum.wrapping_add(byte));
    stream.write_all(format!("${packet}#{checksum:02x}").as_bytes())?;
    Ok(())
}

fn bundle_fingerprints(bundle: &Path) -> Result<BTreeMap<PathBuf, [u8; 32]>, Box<dyn Error>> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<PathBuf, [u8; 32]>,
    ) -> Result<(), Box<dyn Error>> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file() {
                let mut source = fs::File::open(&path)?;
                let mut digest = Sha256::new();
                let mut chunk = [0_u8; 65_536];
                loop {
                    let length = source.read(&mut chunk)?;
                    if length == 0 {
                        break;
                    }
                    digest.update(&chunk[..length]);
                }
                files.insert(
                    path.strip_prefix(root)?.to_path_buf(),
                    digest.finalize().into(),
                );
            } else {
                return Err("finding bundle contains a nonregular entry".into());
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    visit(bundle, bundle, &mut files)?;
    Ok(files)
}

fn reject_bundle(
    bundle: &Path,
    working_directory: &Path,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let output = verify_command(bundle, working_directory)?.output()?;
    assert!(
        !output.status.success(),
        "{label} unexpectedly verified: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

fn copy_bundle(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_bundle(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            return Err("finding bundle contains a nonregular entry".into());
        }
    }
    Ok(())
}

fn archive_manifest_object(bundle: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let manifest = fs::read_to_string(bundle.join("manifest"))?;
    let archive = manifest
        .lines()
        .find_map(|line| line.strip_prefix("archive_manifest="))
        .ok_or("finding bundle manifest omitted archive identity")?;
    let id = crucible_campaign::CampaignArchiveManifestId::parse(archive)?.content_id();
    let encoded = id.encode();
    let digest = encoded
        .rsplit('.')
        .next()
        .filter(|part| part.len() >= 2)
        .ok_or("archive manifest has an invalid content digest")?;
    Ok(bundle
        .join("archive")
        .join("objects")
        .join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest))
}

fn corrupt_file(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut bytes = fs::read(path)?;
    let first = bytes
        .first_mut()
        .ok_or("cannot corrupt an empty evidence file")?;
    *first ^= 1;
    fs::write(path, bytes)?;
    Ok(())
}
