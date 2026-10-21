//! Exercises the actual funded endpoint and reads its actor-owned foundation state.
//!
//! ```text
//! crucible-funded-source-templates-flight POLICY.json OPERATIONAL.json INSTALLATION.json EXPECTED.json templates|births|failure
//! ```
//!
//! Each ordinary process installs its original reservation synchronously before
//! any actor/thread. This test-support consumer is built separately from the
//! default-feature CLI package. It issues no Ready or full preservation claim.

use crucible_daemon::{
    node_control::{
        NodeControlDaemon, NodeControlRequest, NodeControlResult, NodeDaemonPolicy,
        NodeOperationalDeployment, NodeOperationalDeploymentPolicy, request_node_control,
    },
    node_observed_executor::{
        CompleteSceneServiceFactory, FundedTemplateObserver, FundedTemplatePhase,
    },
    node_qualification::InstalledCompleteSceneManifest,
};
use crucible_node_format::{ContentRef, canonical};
use std::{
    error::Error,
    io::Read,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

type Failure = Box<dyn Error>;

fn main() -> Result<(), Failure> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 5 {
        return Err(
            "expected POLICY OPERATIONAL INSTALLATION EXPECTED templates|births|failure".into(),
        );
    }
    let expected_phase = match arguments[4].to_str() {
        Some("templates") => FundedTemplatePhase::TemplatesRetained,
        Some("births") => FundedTemplatePhase::PrivateBirthsRetained,
        Some("failure") => FundedTemplatePhase::AttemptFailed,
        _ => return Err("expected templates, births or failure".into()),
    };
    // The same public defining entry precedes daemon startup and the client thread.
    let operational =
        NodeOperationalDeploymentPolicy::from_json(&read(Path::new(&arguments[1]), 65_536)?)?;
    let mut original = None;
    NodeOperationalDeployment::install_before_actors_into(&mut original, operational)?;
    let policy = NodeDaemonPolicy::from_json(&read(Path::new(&arguments[0]), 65_536)?)?;
    let socket = policy.socket.clone();
    let namespace = policy.state_directory.join("complete-scene");
    let expected: ContentRef = serde_json::from_value(canonical::parse_json(
        &read(Path::new(&arguments[3]), 65_536)?,
        65_536,
    )?)?;
    let pin = InstalledCompleteSceneManifest::new(arguments[2].clone().into(), expected)?;
    let factory = CompleteSceneServiceFactory::with_operational_deployment(
        pin,
        original.take().ok_or("original deployment absent")?,
    );
    let mut daemon = NodeControlDaemon::start_with_vendor_installation(policy, Box::new(factory))?;
    let observer = daemon
        .funded_template_observer()
        .ok_or("actual actor observer absent")?;
    let snapshot = observer.snapshot()?;
    if snapshot.phase() != FundedTemplatePhase::Unattempted || snapshot.retained_worlds() != 1 {
        return Err("startup did not retain the actual unattempted world debit".into());
    }
    let stopping = Arc::new(AtomicBool::new(false));
    let client_stopping = Arc::clone(&stopping);
    let client_observer = observer.clone();
    let client = thread::Builder::new()
        .name("funded-template-control".into())
        .spawn(move || {
            let stop = StopOnDrop(client_stopping);
            let outcome = (|| -> Result<(), String> {
                for attempt in 0..2 {
                    let request = NodeControlRequest::complete_scene_prepare(if attempt == 0 {
                        "fixture/first"
                    } else {
                        "fixture/spent"
                    })
                    .map_err(|e| e.to_string())?;
                    let reply =
                        request_node_control(&socket, &request).map_err(|e| e.to_string())?;
                    if !matches!(reply.result, NodeControlResult::Refused { .. }) {
                        return Err(
                            "foundation was incorrectly exposed as complete-scene success".into(),
                        );
                    }
                    await_phase(&client_observer, expected_phase)?;
                    let snapshot = client_observer.snapshot().map_err(|e| e.to_string())?;
                    if snapshot.retained_worlds() != 1 {
                        return Err("first attempt or retry discarded original world credit".into());
                    }
                }
                Ok(())
            })();
            drop(stop);
            outcome
        })?;
    let served = daemon.serve(&stopping);
    let controls = client.join().map_err(|_| "ordinary client panicked")?;
    served?;
    controls.map_err(std::io::Error::other)?;
    let final_snapshot = observer.snapshot()?;
    if final_snapshot.phase() != FundedTemplatePhase::Reclaimed
        || final_snapshot.retained_worlds() != 0
    {
        return Err("normal stopping returned before actual capsule reclamation".into());
    }
    match std::fs::symlink_metadata(&namespace) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("normal stopping did not prove namespace absence".into()),
    }
    println!("consumer_pid={}", std::process::id());
    println!("PASS");
    println!("actual_command_twice_and_retained_world_credit=true");
    println!("terminal_namespace_absent_and_world_credit_released=true");
    if expected_phase == FundedTemplatePhase::PrivateBirthsRetained {
        println!("actual_three_worker_results_and_private_births_retained=true");
    }
    Ok(())
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn await_phase(
    observer: &FundedTemplateObserver,
    phase: FundedTemplatePhase,
) -> Result<(), String> {
    // The public exchange keeps its own deadline. The birth flight also waits
    // for three confined jobs; the foundation flight needs only publication.
    let deadline = Instant::now()
        + if phase == FundedTemplatePhase::PrivateBirthsRetained {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(1)
        };
    loop {
        let snapshot = observer.snapshot().map_err(|e| e.to_string())?;
        let observed = snapshot.phase();
        if observed == phase
            || (phase == FundedTemplatePhase::TemplatesRetained
                && matches!(
                    observed,
                    FundedTemplatePhase::PrivateBirthsRetained
                        | FundedTemplatePhase::DerivationFailed
                ))
        {
            return Ok(());
        }
        if matches!(
            observed,
            FundedTemplatePhase::AttemptFailed | FundedTemplatePhase::DerivationFailed
        ) {
            return Err(format!(
                "funded preparation failed at {observed:?}: {}",
                snapshot
                    .failure_reason()
                    .unwrap_or("retained cause unavailable"),
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "actor did not publish {phase:?}; retained phase is {observed:?}"
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, Failure> {
    if !path.is_absolute() {
        return Err("local control inputs must be absolute paths".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("local control input exceeds its fixed bound".into());
    }
    Ok(bytes)
}
