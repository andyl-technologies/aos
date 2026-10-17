//! Checks authentic ordinary collection without manufacturing behavioral acceptance.

use super::*;
use crate::node_observed_executor::factory::{
    Gem5BehavioralCase, Gem5BehavioralRequest, Gem5BehavioralRun,
};
use crate::node_qualification::{QualificationClaim, RequirementDisposition};
use crate::node_scenario::NodeRunConfiguration;

fn source_run(directory: &std::path::Path) -> Gem5BehavioralRun {
    let companion =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = catalog(directory, &companion);
    let (mut selections, script, base, script_path, base_path) = authored(directory);
    selections[1].kind = InstalledNodeKind::Gem5Closed {
        isa: super::super::super::control::InstalledGem5Isa::X86_64,
    };
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(script_path, script),
            InstalledIoArtifact::path(base_path, base),
        ])
        .unwrap();
    let scenario = catalog.scenario(&selections).unwrap();
    Gem5BehavioralRun::reserve(
        &catalog,
        Gem5BehavioralRequest {
            selections,
            scenario,
            configuration: configuration(),
            execution: crucible_campaign::ExecutionId::from_bytes([119; 16]).unwrap(),
            blobs: Arc::new(DirectoryBlobBackend::new(
                "ordinary-gem5",
                directory.join("cas"),
            )),
            refs: Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
            case: Gem5BehavioralCase::LcgOutput,
        },
    )
    .unwrap()
}

fn configuration() -> NodeRunConfiguration {
    NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: 2_000_000_000.into(),
        maximum_rounds: 64.into(),
    }
}

fn save_original_cases(directory: &std::path::Path, run: &Gem5BehavioralRun) {
    let objects = directory.join("original-case-bodies");
    std::fs::create_dir_all(&objects).unwrap();
    let mut inventory = Vec::new();
    for (ordinal, (reference, body)) in run.original_case_objects().enumerate() {
        reference.verify(body).unwrap();
        let name = format!("{ordinal:06}.body");
        std::fs::write(objects.join(&name), body).unwrap();
        inventory.push((name, reference));
    }
    save(directory, "original-case-inventory", &inventory);
}

#[test]
#[ignore = "requires authentic source-installed RF assets; reserves only and starts no Child"]
fn missing_actual_cases_cannot_become_accepted_report() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = source_run(directory.path());
    let report = run.report().unwrap();
    let (reference, bytes) = report.original();
    reference.verify(bytes).unwrap();
    let claim: QualificationClaim = serde_json::from_slice(bytes).unwrap();
    assert!(!claim.requirements.is_empty());
    assert!(
        claim
            .requirements
            .iter()
            .all(|row| row.disposition == RequirementDisposition::NotExecuted
                && row.cases.is_empty())
    );
    let decision: serde_json::Value = serde_json::from_slice(&report.evaluate().unwrap()).unwrap();
    assert!(decision["decision"].get("refused").is_some());
}

#[test]
#[ignore = "starts one authentic source-built native four-owner ordinary run; retains originals on refusal"]
fn actual_ordinary_four_owner_source_oracle_and_ack_witness() {
    let directory = tempfile::Builder::new()
        .prefix("gem5-ordinary-behavioral-")
        .tempdir_in("/tmp")
        .unwrap()
        .keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("ordinary original run: {}", directory.display());
    let companion =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = catalog(&directory, &companion);
    let (mut selections, script, base, script_path, base_path) = authored(&directory);
    selections[1].kind = InstalledNodeKind::Gem5Closed {
        isa: super::super::super::control::InstalledGem5Isa::X86_64,
    };
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(script_path, script),
            InstalledIoArtifact::path(base_path, base),
        ])
        .unwrap();
    let scenario = catalog.scenario(&selections).unwrap();
    let mut run = Gem5BehavioralRun::reserve(
        &catalog,
        Gem5BehavioralRequest {
            selections,
            scenario: scenario.clone(),
            configuration: configuration(),
            execution: crucible_campaign::ExecutionId::from_bytes([121; 16]).unwrap(),
            blobs: Arc::new(DirectoryBlobBackend::new(
                "ordinary-gem5",
                directory.join("cas"),
            )),
            refs: Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
            case: Gem5BehavioralCase::LcgOutput,
        },
    )
    .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.prepare(&catalog).unwrap();
        run.start().unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut finished = false;
        for _ in 0..600_000 {
            match run.poll(&mut context) {
                Poll::Ready(Ok(true)) => {
                    finished = true;
                    break;
                }
                Poll::Ready(Err(error)) => {
                    if let Ok(diagnostic) = run.retained_error_diagnostic() {
                        save(&directory, "original-refusal-site", &diagnostic);
                    }
                    panic!("{error}");
                }
                _ => std::thread::park_timeout(Duration::from_millis(1)),
            }
        }
        assert!(finished, "actual original finite poll credit exhausted");
        run.retain_common_witness().unwrap();
        let (runtime, scheduler) = run.common_witness().unwrap();
        save(&directory, "ordinary-runtime", runtime);
        save(&directory, "ordinary-scheduler", scheduler);
        save_original_cases(&directory, &run);
        let report = Arc::new(run.report().unwrap());
        let (_, bytes) = report.original();
        std::fs::write(directory.join("original-qualification.json"), bytes).unwrap();
        std::fs::write(
            directory.join("original-acceptance-audit.json"),
            report.evaluate().unwrap(),
        )
        .unwrap();
        assert!(
            report.install(&mut catalog, &scenario).is_err(),
            "uncovered requirements cannot grant accepted enrollment"
        );
    }));
    if result.is_err() {
        // Historical bodies remain useful even when a later semantic case refuses.
        // Export failure leaves the same complete owning stack parked below.
        let exported = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            save_original_cases(&directory, &run);
        }));
        if exported.is_err() {
            eprintln!("original refused-case export failed; originals remain held");
        }
        eprintln!("refused original run retained at {}", directory.display());
        // The same stack owns all originals; refusal never silently drops custody.
        loop {
            std::thread::park();
        }
    }
    drop(run);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if catalog.custody().reserved_worlds() == 0 {
            return;
        }
        let _ = catalog.custody().poll_reclamation(&mut context);
        std::thread::park_timeout(Duration::from_millis(1));
    }
    panic!("original successful run remains under authentic custody");
}
