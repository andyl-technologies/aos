//! Actual model-aware source-death UART custody and independent fresh certification.

// crucible-lint: allow rust-allow -- invalid actual native fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and validation failures are test-only.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use crucible_node_contract::{Id, Phase, Position, U64};
use crucible_node_provider::{
    ProviderError,
    gem5::{
        ArmRootCustodySlot, ArmRootExactAuthority, ArmRootLaunch, ArmRootNativeCustody,
        ArmRootNativeProcess, ArmRootRestoreTarget, ArmRootRunOutcome, Gem5ExactRange, Gem5Run,
    },
};

struct Supervisor(Arc<Mutex<Vec<ArmRootNativeCustody>>>);

impl ArmRootCustodySlot for Supervisor {
    fn retain(self: Box<Self>, custody: ArmRootNativeCustody) {
        self.0.lock().unwrap().push(custody);
    }
}

fn private(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn retire(supervisor: &Arc<Mutex<Vec<ArmRootNativeCustody>>>) -> Result<(), ProviderError> {
    let mut capsules = supervisor.lock().unwrap();
    for capsule in &mut *capsules {
        capsule.begin_quarantine()?;
        while !capsule.poll_reclamation()? {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(capsule.poll_reclamation()?);
    }
    capsules.clear();
    Ok(())
}

fn run(
    process: &mut ArmRootNativeProcess,
    authority: &ArmRootExactAuthority,
    name: &str,
) -> Result<ArmRootRunOutcome, ProviderError> {
    process.run_exact(
        authority,
        Gem5Run {
            kind: "run".to_owned(),
            operation: Id::new(name)?,
            exclusive_tick: 2_000_000_000u64.into(),
            maximum_events: 262_144u64.into(),
            exact_range: Some(Gem5ExactRange {
                start: process.logical_position(),
                limit: Position::new(2_000_000_000u64.into(), 0.into(), Phase::BoundaryControl),
                maximum_microsteps: authority.maximum_microsteps(),
            }),
        },
    )
}

fn suffix(
    process: &mut ArmRootNativeProcess,
    authority: &ArmRootExactAuthority,
) -> Result<Vec<Vec<u8>>, ProviderError> {
    let mut records = Vec::new();
    for number in 0..3 {
        let prefix = run(process, authority, &format!("suffix-{number}"))?;
        let completed = prefix
            .completion()
            .ok_or(ProviderError::Frame("actual source UART suffix refused"))?;
        if completed.output.len() != 1 || completed.publications.len() != 1 {
            return Err(ProviderError::Correlation(
                "actual suffix did not reach original serial byte",
            ));
        }
        records.push(crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&completed.publications)
                .map_err(|_| ProviderError::Frame("actual UART encoding"))?,
        )?);
        process.acknowledge(&completed.operation)?;
    }
    Ok(records)
}

fn retire_complete(
    supervisor: &Arc<Mutex<Vec<ArmRootNativeCustody>>>,
) -> Result<(), ProviderError> {
    let complete = supervisor.lock().unwrap().iter().all(|capsule| {
        let ledger = capsule.host_ledger();
        ledger.prepared().is_some()
            && ledger.boundary().is_some()
            && ledger.operations().count() >= 4
            && ledger.pending().is_none()
            && ledger.unresolved().is_none()
            && ledger.unresolved_capture().is_none()
    });
    retire(supervisor)?;
    if !complete {
        return Err(ProviderError::Correlation(
            "actual retirement omitted original host continuation",
        ));
    }
    Ok(())
}

#[test]
#[ignore = "executes installed ARM Linux and genuine source-gone twin reconstructions"]
fn actual_root_serial_source_gone_twins_require_fresh_certificates() {
    let root = root_native_support::evidence_root("crucible-arm-root-cold").unwrap();
    let supervisor = Arc::new(Mutex::new(Vec::new()));
    let result = (|| -> Result<(), ProviderError> {
        let source = root.join("source");
        private(&source);
        let resources = source.join("resources");
        private(&resources);
        let images = source.join("images");
        private(&images);
        let temporary = source.join("temporary");
        private(&temporary);
        let launch = ArmRootLaunch::installed(
            Id::new("root-node")?,
            Id::new("original")?,
            1.into(),
            resources,
            images,
            temporary,
            Duration::from_secs(180),
        )?;
        let mut process =
            ArmRootNativeProcess::spawn(launch, Box::new(Supervisor(supervisor.clone())))?;
        let initial = root.join("initial");
        private(&initial);
        let image = process.capture(Id::new("initial")?, &initial)?;
        let certificate = process.qualify_capture(&image, &root)?;
        let authority = process.qualify_exact(&image, &certificate)?;
        process.initial_prepared_session(&authority)?;
        let held = run(&mut process, &authority, "original-held-byte")?;
        let original = held
            .completion()
            .ok_or(ProviderError::Frame("actual first serial prefix refused"))?;
        if original.output != vec![91]
            || original.publications.len() != 1
            || original.publications[0].causal_parent != U64::new(0)
        {
            return Err(ProviderError::Correlation(
                "actual root serial birth/parent differs",
            ));
        }
        let archive = root.join("archive");
        private(&archive);
        let saved = process.capture(Id::new("held")?, &archive)?;
        let current = process.qualify_capture(&saved, &root)?;
        current.verify_image(&saved)?;
        assert_eq!(
            process
                .run_exact(&authority, original.original.clone())?
                .bytes(),
            held.bytes()
        );
        process.acknowledge(&original.operation)?;
        let expected = suffix(&mut process, &authority)?;
        drop(process);
        retire_complete(&supervisor)?;
        fs::remove_dir_all(&source)?;
        fs::remove_dir_all(&initial)?;
        if source.exists() {
            return Err(ProviderError::Correlation(
                "original ARM source namespace survived",
            ));
        }
        let mut branches = Vec::new();
        for name in ["branch-a", "branch-b"] {
            let branch = root.join(name);
            private(&branch);
            let resources = branch.join("resources");
            private(&resources);
            let images = branch.join("images");
            private(&images);
            let temporary = branch.join("temporary");
            private(&temporary);
            let restored = ArmRootNativeProcess::restore(
                &saved,
                ArmRootRestoreTarget {
                    incarnation: Id::new(name)?,
                    generation: 2.into(),
                    resource_root: resources,
                    image_root: images,
                    temporary_root: temporary,
                    timeout: Duration::from_secs(180),
                },
                Box::new(Supervisor(supervisor.clone())),
            )?;
            branches.push((branch, restored));
        }
        // Both native owners coexist before either is independently recertified.
        for (branch, process) in &mut branches {
            let fresh = branch.join("fresh");
            private(&fresh);
            let image = process.capture(Id::new("fresh-held")?, &fresh)?;
            let certificate = process.qualify_capture(&image, &root)?;
            let authority = process.qualify_exact(&image, &certificate)?;
            if process.initial_prepared_session(&authority).is_ok() {
                return Err(ProviderError::Correlation(
                    "restored zero/history minted original preparation",
                ));
            }
            process.restored_prepared_session(&authority, saved.capture_id())?;
            assert_eq!(
                process
                    .run_exact(&authority, original.original.clone())?
                    .bytes(),
                held.bytes()
            );
            process.acknowledge(&original.operation)?;
            assert_eq!(suffix(process, &authority)?, expected);
        }
        drop(branches);
        retire_complete(&supervisor)?;
        println!(
            "authentic Root UART source-gone/two-fresh closure, held originals, suffix, ACK, all groups PASS; evidence {}",
            root.display()
        );
        Ok(())
    })();
    let cleanup = retire(&supervisor);
    cleanup.unwrap();
    if let Err(error) = result {
        panic!(
            "actual cold Root gate failed: {error}; evidence {}",
            root.display()
        );
    }
}

#[path = "support/root_native.rs"]
mod root_native_support;
