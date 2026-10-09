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
        ArmRootArchiveImport, ArmRootArchiveSourceVerifier, ArmRootCapturedImage,
        ArmRootCustodySlot, ArmRootExactAuthority, ArmRootLaunch, ArmRootNativeCustody,
        ArmRootNativeProcess, ArmRootRestoreTarget, ArmRootRunOutcome, Gem5CapturedArtifactRole,
        Gem5ExactRange, Gem5Run,
    },
};

struct Supervisor(Arc<Mutex<Vec<ArmRootNativeCustody>>>);

impl ArmRootCustodySlot for Supervisor {
    fn retain(self: Box<Self>, custody: ArmRootNativeCustody) {
        self.0.lock().unwrap().push(custody);
    }
}

/// Authenticates the exact export retained from the actual owning source in this witness.
/// This fixture is not an installed public source verifier or an authority factory.
struct OriginalExport(ArmRootArchiveImport);

impl ArmRootArchiveSourceVerifier for OriginalExport {
    fn verify_archive(&self, actual: &ArmRootArchiveImport) -> Result<(), ProviderError> {
        let original = &self.0;
        if actual.capture != original.capture
            || actual.source != original.source
            || actual.source_supplementary_files_root != original.source_supplementary_files_root
            || actual.boundary != original.boundary
            || actual.original_outcomes != original.original_outcomes
            || actual.control_history != original.control_history
            || actual.pending != original.pending
            || actual.last_acknowledged != original.last_acknowledged
            || actual.artifacts.len() != original.artifacts.len()
            || actual
                .artifacts
                .iter()
                .zip(&original.artifacts)
                .any(|(left, right)| {
                    left.role != right.role
                        || left.relative != right.relative
                        || left.artifact.content != right.artifact.content
                })
        {
            return Err(ProviderError::Correlation(
                "actual owning export was substituted",
            ));
        }
        Ok(())
    }
}

fn materialize(
    original: &ArmRootArchiveImport,
    root: &Path,
) -> Result<ArmRootArchiveImport, ProviderError> {
    let images = root.join("historical-images");
    let resources = root.join("historical-resources");
    private(&images);
    private(&resources);
    let mut copy = original.clone();
    for file in &mut copy.artifacts {
        let base = if file.role == Gem5CapturedArtifactRole::Image {
            &images
        } else {
            &resources
        };
        let target = base.join(&file.relative);
        let mut current = base.clone();
        for part in file.relative.parent().unwrap().components() {
            current.push(part);
            if !current.exists() {
                private(&current);
            }
        }
        let metadata = fs::symlink_metadata(&file.artifact.path)?;
        if !metadata.is_file() || metadata.len() != file.artifact.content.length.get() {
            return Err(ProviderError::Correlation(
                "original artifact was changed before copying",
            ));
        }
        fs::copy(&file.artifact.path, &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        file.artifact.path = target;
    }
    Ok(copy)
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
fn actual_root_archive_import_preserves_raw_history_after_entire_source_is_gone() {
    let root = root_native_support::evidence_root("crucible-arm-root-archive-import").unwrap();
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
        let first = process.run_exact(
            &authority,
            Gem5Run {
                kind: "run".to_owned(),
                operation: Id::new("actual-ack-prefix")?,
                exclusive_tick: 2_000_000_000u64.into(),
                maximum_events: 1.into(),
                exact_range: Some(Gem5ExactRange {
                    start: process.logical_position(),
                    limit: Position::new(2_000_000_000u64.into(), 0.into(), Phase::BoundaryControl),
                    maximum_microsteps: authority.maximum_microsteps(),
                }),
            },
        )?;
        let first = first
            .completion()
            .ok_or(ProviderError::Frame("initial mechanical prefix refused"))?;
        process.acknowledge(&first.operation)?;
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
        let original_export = saved.archive_record()?;
        let verifier = OriginalExport(original_export.clone());
        let mut imports = Vec::new();
        for name in ["branch-a", "branch-b"] {
            let branch = root.join(name);
            private(&branch);
            imports.push((branch.clone(), materialize(&original_export, &branch)?));
        }
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
        fs::remove_dir_all(&archive)?;
        drop(saved);
        assert!(
            verifier
                .0
                .artifacts
                .iter()
                .all(|file| !file.artifact.path.exists())
        );
        if source.exists() {
            return Err(ProviderError::Correlation(
                "original ARM source namespace survived",
            ));
        }
        let mut branches = Vec::new();
        for (branch, imported) in imports {
            let name = branch.file_name().unwrap().to_str().unwrap();
            let saved =
                ArmRootCapturedImage::import_authenticated_arm_archive(imported, &verifier)?;
            assert_eq!(saved.control_history(), &original_export.control_history);
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
            process.restored_prepared_session(&authority, &original_export.capture)?;
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
            "authentic Root independent archive import, raw Ready/control/admin ACK history, source-gone/two-fresh closure, held originals, suffix, all groups PASS; evidence {}",
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
