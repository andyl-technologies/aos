//! Real local-QEMU process flight for the campaign-backed default `run` path.

#![cfg(target_os = "linux")]
// crucible-lint: allow clippy-disallowed-method -- this boundary test intentionally launches the shipped CLI process.
// crucible-lint: allow panic-shortcut -- assertions localize failures in one hermetic VM flight.
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use crucible_harness::reproduction::content_address_bytes;
use crucible_session::engine::{
    Action, ContentAddressedBlobRef, ContentHash, EventGraph, EventId, Icount, NodeId, Plan,
    Predicate, Properties, ReadyPoint, ScenarioDefForm, Seed, SimDuration, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};
use serde_json::Value;
use tempfile::TempDir;

const LIVE_QEMU_EVENT_STREAM_MEDIA_TYPE: &str =
    "application/vnd.crucible.live-qemu-event-stream.v1+bytes";
const LIVE_QEMU_FINGERPRINT_STREAM_MEDIA_TYPE: &str =
    "application/vnd.crucible.live-qemu-fingerprint-stream.v1+bytes";
const CAMPAIGN_REPLAY_CLOSURE_MEDIA_TYPE: &str =
    "application/vnd.crucible.campaign-replay-closure.v1+binary";

#[test]
#[ignore = "requires the packaged patched-QEMU, plugin, kernel, and root image VM fixture"]
fn public_default_run_executes_through_an_authenticated_campaign() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path();
    let run_state = root.join("run-state");
    let artifact_dir = root.join("artifacts");
    fs::create_dir(&run_state)?;
    fs::set_permissions(&run_state, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&artifact_dir)?;

    let scenario_path = write_scenario(root, Action::Pass)?;

    let output = command()
        .args(["--backend", "qemu", "--qemu"])
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
        .args(["--format", "jsonl", "--artifact-dir"])
        .arg(&artifact_dir)
        .arg("run")
        .arg(&scenario_path)
        .arg("--watch")
        .arg("--campaign-deployment")
        .arg(required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?)
        .env("CRUCIBLE_RUN_STATE_ROOT", &run_state)
        .output()?;
    require_success(&output, "campaign-backed default run")?;

    let entries = String::from_utf8(output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    let states = entries
        .iter()
        .filter(|entry| entry["kind"] == "run_state_update")
        .map(|entry| entry["summary"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(states, ["created", "running", "completed"]);
    let watch_summaries = entries
        .iter()
        .filter(|entry| entry["kind"] == "run_watch_status")
        .filter_map(|entry| entry["summary"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(watch_summaries.len(), 4);
    assert!(watch_summaries[0].starts_with("state=created\tfrontier_ticks=0\tquanta=0"));
    assert!(watch_summaries[1].starts_with("state=running\tfrontier_ticks=0\tquanta=0"));
    assert!(watch_summaries[2].starts_with("state=running\t"));
    assert!(watch_summaries[2].contains("\tobservation=crucible.campaign.observation@"));
    assert!(watch_summaries[3].starts_with("state=completed\t"));
    assert!(watch_summaries[3].contains("\toutcome=passed\t"));
    assert!(watch_summaries[3].ends_with("\tobservation=none"));
    let watch_frontiers = watch_summaries
        .iter()
        .map(|summary| {
            summary_field(summary, "frontier_ticks")
                .unwrap_or_default()
                .parse::<u64>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let watch_quanta = watch_summaries
        .iter()
        .map(|summary| {
            summary_field(summary, "quanta")
                .unwrap_or_default()
                .parse::<u64>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(watch_frontiers.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(watch_quanta.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(watch_frontiers[2], watch_frontiers[3]);
    assert_eq!(watch_quanta[2], watch_quanta[3]);
    assert!(watch_quanta[2] > 0);
    let watch_campaigns = watch_summaries
        .iter()
        .filter_map(|summary| {
            summary
                .split('\t')
                .find_map(|field| field.strip_prefix("campaign="))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(watch_campaigns.len(), 1);
    assert!(
        watch_campaigns
            .first()
            .is_some_and(|campaign| campaign.starts_with("legacy-run-"))
    );
    assert!(watch_summaries.iter().all(|summary| {
        summary.contains("\towner=campaign\t")
            && summary.contains("\tsnapshot=crucible.campaign.snapshot@")
    }));
    let incorporated_observation = summary_field(watch_summaries[2], "observation")
        .ok_or("campaign watch frame omitted its incorporated observation")?;
    let incorporated_entry = entries
        .iter()
        .find(|entry| {
            entry["kind"] == "authenticated_observation"
                && entry["summary"]
                    .as_str()
                    .is_some_and(|summary| summary.contains(incorporated_observation))
        })
        .ok_or("campaign watch observation was absent from authenticated output")?;
    assert_eq!(
        incorporated_entry["virtual_time"].as_u64(),
        Some(watch_frontiers[2])
    );
    let completed_entry = entries
        .iter()
        .find(|entry| entry["kind"] == "campaign_completed")
        .ok_or("campaign completion entry was absent")?;
    let completed_summary = completed_entry["summary"]
        .as_str()
        .ok_or("campaign completion summary was not text")?;
    assert_eq!(
        summary_field(watch_summaries[3], "campaign"),
        summary_field(completed_summary, "campaign")
    );
    assert_eq!(
        summary_field(watch_summaries[3], "snapshot"),
        summary_field(completed_summary, "snapshot")
    );
    assert_eq!(
        summary_field(watch_summaries[2], "observation"),
        summary_field(completed_summary, "observation")
    );
    assert_eq!(
        summary_field(watch_summaries[3], "frontier_ticks"),
        summary_field(completed_summary, "frontier_ticks")
    );
    assert_eq!(
        summary_field(watch_summaries[3], "quanta"),
        summary_field(completed_summary, "quanta")
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry["kind"] == "run_stream_event")
    );
    assert!(entries.iter().any(|entry| {
        entry["kind"] == "authenticated_observation"
            && entry["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("stop=terminal-success"))
    }));
    assert!(entries.iter().any(|entry| {
        entry["kind"] == "campaign_completed"
            && entry["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("defaults=0"))
    }));
    assert!(entries.iter().any(|entry| {
        entry["kind"] == "live_backend_execution"
            && entry["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("operation=run-campaign-default-path"))
    }));

    println!("\nlegacy_default_run_campaign=true");
    Ok(())
}

fn summary_field<'a>(summary: &'a str, name: &str) -> Option<&'a str> {
    summary
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
}

#[test]
#[ignore = "requires the packaged patched-QEMU, plugin, kernel, and root image VM fixture"]
fn guarded_campaign_failure_artifact_replays_live_evidence() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path();
    let run_state = root.join("run-state");
    let replay_state = root.join("replay-state");
    let legacy_replay_state = root.join("legacy-replay-state");
    let artifact_dir = root.join("artifacts");
    fs::create_dir(&run_state)?;
    fs::create_dir(&replay_state)?;
    fs::create_dir(&legacy_replay_state)?;
    fs::set_permissions(&run_state, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&replay_state, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&legacy_replay_state, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&artifact_dir)?;
    let scenario_path = write_scenario(root, Action::fail("guarded campaign flight failure"))?;

    let deployment = required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?;
    let failure =
        guarded_run_command(&scenario_path, &artifact_dir, &run_state, &deployment)?.output()?;
    assert_eq!(
        failure.status.code(),
        Some(1),
        "guarded failure should exit 1; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&failure.stdout),
        String::from_utf8_lossy(&failure.stderr),
    );
    let failure_stdout = String::from_utf8(failure.stdout)?;
    assert!(failure_stdout.contains("authenticated_observation"));
    assert!(failure_stdout.contains("stop=scenario-failure:"));

    let artifact_path = single_reproduction_artifact(&artifact_dir)?;
    let artifact_text = fs::read_to_string(&artifact_path)?;
    require_embedded_component(
        &artifact_text,
        "live_qemu_event_stream",
        LIVE_QEMU_EVENT_STREAM_MEDIA_TYPE,
    )?;
    require_embedded_component(
        &artifact_text,
        "live_qemu_fingerprint_stream",
        LIVE_QEMU_FINGERPRINT_STREAM_MEDIA_TYPE,
    )?;
    require_embedded_component(
        &artifact_text,
        "campaign_replay_closure",
        CAMPAIGN_REPLAY_CLOSURE_MEDIA_TYPE,
    )?;

    let replay = command()
        .args(["--backend", "qemu", "--qemu"])
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
        .arg("--campaign-deployment")
        .arg(&deployment)
        .args(["--format", "jsonl", "replay"])
        .arg(&artifact_path)
        .env("CRUCIBLE_RUN_STATE_ROOT", &replay_state)
        .output()?;
    require_success(&replay, "live replay of guarded campaign failure")?;
    let replay_stdout = String::from_utf8(replay.stdout)?;
    assert!(replay_stdout.contains("replay_live_qemu"));
    assert!(replay_stdout.contains("validation=passed"));
    assert!(replay_stdout.contains("owner=campaign"));
    assert!(replay_stdout.contains("reproduced_status=failed"));

    // Recast the same real execution into the historical session-owned `run`
    // shape: producer `run`, with no campaign choice closure. Its selection-free
    // schedule must now enter the campaign replay owner and reproduce exactly.
    let legacy_artifact = legacy_run_artifact_from_campaign(&artifact_text)?;
    assert!(legacy_artifact.contains("70726f64756365720972756e0a"));
    assert!(!legacy_artifact.contains("campaign_replay_closure"));
    let legacy_artifact_path = root.join("legacy-run.crucible");
    fs::write(&legacy_artifact_path, legacy_artifact)?;
    let legacy_replay = command()
        .args(["--backend", "qemu", "--qemu"])
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
        .arg("--campaign-deployment")
        .arg(&deployment)
        .args(["--format", "jsonl", "replay"])
        .arg(&legacy_artifact_path)
        .env("CRUCIBLE_RUN_STATE_ROOT", &legacy_replay_state)
        .output()?;
    require_success(
        &legacy_replay,
        "campaign replay of a selection-free legacy run artifact",
    )?;
    let legacy_replay_stdout = String::from_utf8(legacy_replay.stdout)?;
    assert!(legacy_replay_stdout.contains("replay_live_qemu"));
    assert!(legacy_replay_stdout.contains("validation=passed"));
    assert!(legacy_replay_stdout.contains("owner=campaign"));
    assert!(legacy_replay_stdout.contains("reproduced_status=failed"));

    println!("\nlegacy_guarded_failure_replay=true");
    Ok(())
}

#[test]
#[ignore = "requires the packaged patched-QEMU, plugin, kernel, and root image VM fixture"]
fn guarded_campaign_rejects_insufficient_capacity_before_guest_launch() -> Result<(), Box<dyn Error>>
{
    let temporary = TempDir::new()?;
    let root = temporary.path();
    let run_state = root.join("run-state");
    let artifact_dir = root.join("artifacts");
    fs::create_dir(&run_state)?;
    fs::set_permissions(&run_state, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&artifact_dir)?;
    let scenario_path = write_scenario(root, Action::Pass)?;

    let authored = fs::read_to_string(required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?)?;
    let constrained = authored.replace(
        "maximum_resident_bytes = 536870912",
        "maximum_resident_bytes = 67108864",
    );
    if constrained == authored {
        return Err("flight deployment has an unexpected resident-memory ceiling".into());
    }
    let deployment = root.join("constrained-executor.toml");
    fs::write(&deployment, constrained)?;
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600))?;

    let rejected =
        guarded_run_command(&scenario_path, &artifact_dir, &run_state, &deployment)?.output()?;
    assert!(!rejected.status.success());
    let stderr = String::from_utf8(rejected.stderr)?;
    assert!(stderr.contains("fresh QEMU scenario requires 134217728 resident bytes"));
    assert!(
        fs::read_dir(required_path("CRUCIBLE_FLIGHT_RUN_ROOT")?)?
            .next()
            .is_none()
    );

    println!("\nlegacy_guarded_prelaunch_capacity_refusal=true");
    Ok(())
}

fn write_scenario(root: &std::path::Path, terminal: Action) -> Result<PathBuf, Box<dyn Error>> {
    let kernel = required_path("CRUCIBLE_KERNEL")?;
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    let world = World::from_nodes_and_links(
        vec![WorldNode {
            id: NodeId {
                name: String::from("node"),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::from("console=ttyS0"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                &fs::read(&kernel)?,
            ))),
            root_image: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                &fs::read(&root_image)?,
            ))),
            initrd: None,
        }],
        Vec::new(),
    )?;
    let graph = EventGraph::builder()
        .event("begin-flight")
        .entrypoint()
        .action(Action::Group(Vec::new()))
        .event("complete-flight")
        .when(Predicate::After {
            of: EventId::from_name("begin-flight"),
            duration: SimDuration { nanos: 2_000_000 },
        })
        .action(terminal)
        .build_for_world(&world)?;
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::from_event_graph_for_world(&world, graph)?,
        &Properties::empty(),
        Seed::from_u64(0x1e6a_caca),
    )?;
    let scenario_path = root.join("scenario.toml");
    fs::write(&scenario_path, scenario.to_canonical_toml()?)?;
    Ok(scenario_path)
}

fn guarded_run_command(
    scenario: &std::path::Path,
    artifact_dir: &std::path::Path,
    run_state: &std::path::Path,
    deployment: &std::path::Path,
) -> Result<Command, Box<dyn Error>> {
    let mut command = command();
    command
        .args(["--backend", "qemu", "--qemu"])
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
        .args(["--format", "jsonl", "--artifact-dir"])
        .arg(artifact_dir)
        .arg("run")
        .arg(scenario)
        .arg("--campaign-deployment")
        .arg(deployment)
        .env("CRUCIBLE_RUN_STATE_ROOT", run_state);
    Ok(command)
}

fn single_reproduction_artifact(root: &std::path::Path) -> Result<PathBuf, Box<dyn Error>> {
    let paths = fs::read_dir(root)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            (name.starts_with("repro-failed-") && name.ends_with(".crucible")).then_some(path)
        })
        .collect::<Vec<_>>();
    match paths.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(format!("expected one failure artifact, found {}", paths.len()).into()),
    }
}

fn legacy_run_artifact_from_campaign(artifact: &str) -> Result<String, Box<dyn Error>> {
    let mut rows = artifact
        .lines()
        .map(|line| line.split('\t').map(str::to_owned).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let campaign_closure_digest = rows
        .iter()
        .find(|fields| {
            fields.first().is_some_and(|field| field == "component")
                && fields
                    .get(1)
                    .is_some_and(|field| field == "campaign_replay_closure")
        })
        .and_then(|fields| fields.get(3))
        .cloned()
        .ok_or("campaign artifact omitted its replay closure")?;
    rows.retain(|fields| {
        let is_closure_component = fields.first().is_some_and(|field| field == "component")
            && fields
                .get(1)
                .is_some_and(|field| field == "campaign_replay_closure");
        let is_closure_payload = fields.first().is_some_and(|field| field == "payload")
            && fields
                .get(1)
                .is_some_and(|field| field == &campaign_closure_digest);

        !(is_closure_component || is_closure_payload)
    });

    let contract_index = rows
        .iter()
        .position(|fields| {
            fields.first().is_some_and(|field| field == "component")
                && fields
                    .get(1)
                    .is_some_and(|field| field == "live_qemu_replay_contract")
        })
        .ok_or("campaign artifact omitted its live-QEMU replay contract")?;
    let contract_digest = rows[contract_index]
        .get(3)
        .cloned()
        .ok_or("live-QEMU contract component omitted its digest")?;
    let payload_index = rows
        .iter()
        .position(|fields| {
            fields.first().is_some_and(|field| field == "payload")
                && fields.get(1).is_some_and(|field| field == &contract_digest)
        })
        .ok_or("campaign artifact omitted its live-QEMU contract payload")?;
    let contract_bytes = decode_hex(
        rows[payload_index]
            .get(2)
            .ok_or("live-QEMU contract payload omitted its bytes")?,
    )?;
    let contract = String::from_utf8(contract_bytes)?;
    let rewritten = contract.replacen("producer\tcampaign-run\n", "producer\trun\n", 1);
    if rewritten == contract {
        return Err("live-QEMU contract did not name the campaign-run producer".into());
    }
    let rewritten = rewritten.into_bytes();
    let rewritten_digest = content_address_bytes(&rewritten);

    rows[contract_index][3] = rewritten_digest.clone();
    rows[contract_index][4] = format!("cas:{rewritten_digest}");
    rows[contract_index][6] = rewritten.len().to_string();
    rows[payload_index][1] = rewritten_digest;
    rows[payload_index][2] = encode_hex(&rewritten);

    Ok(format!(
        "{}\n",
        rows.into_iter()
            .map(|fields| fields.join("\t"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = encoded.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex payload has an odd length".into());
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex payload contains a non-hexadecimal byte".into()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn require_embedded_component(
    artifact: &str,
    kind: &str,
    media_type: &str,
) -> Result<(), Box<dyn Error>> {
    let component = artifact
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|fields| fields.len() == 7 && fields[0] == "component" && fields[1] == kind)
        .ok_or_else(|| format!("reproduction artifact has no `{kind}` component"))?;
    if component[5] != media_type || component[4] != format!("cas:{}", component[3]) {
        return Err(format!("reproduction artifact has an invalid `{kind}` component row").into());
    }

    let declared_size = component[6].parse::<usize>()?;
    let payload = artifact
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|fields| fields.len() == 3 && fields[0] == "payload" && fields[1] == component[3])
        .ok_or_else(|| format!("reproduction artifact has no payload for `{kind}`"))?;
    let payload_hex = payload[2];
    if declared_size == 0
        || payload_hex.len() != declared_size.saturating_mul(2)
        || !payload_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("reproduction artifact has an invalid `{kind}` payload row").into());
    }

    Ok(())
}

fn command() -> Command {
    let binary = std::env::var_os("CRUCIBLE_PROCESS_FLIGHT_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_crucible").into());
    Command::new(binary)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

fn require_success(output: &Output, operation: &str) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{operation} failed with {}; stdout=`{}` stderr=`{}`",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}
