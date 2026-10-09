//! Model-only historical import tests; no simulated data qualifies a live owner.

#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{Phase, Position, canonical};
use serde_json::json;
use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (TestRoot, Gem5ArchiveImport) {
    let root = std::env::temp_dir().join(format!(
        "gem5-archive-model-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut artifacts = Vec::new();
    for (role, name) in [
        (Gem5CapturedArtifactRole::Image, "owner.dmtcp"),
        (Gem5CapturedArtifactRole::Resource, "native-owner.py"),
        (Gem5CapturedArtifactRole::Resource, "native-owner-model.py"),
        (Gem5CapturedArtifactRole::Resource, "guest.elf"),
    ] {
        let path = root.join(name);
        fs::write(&path, name.as_bytes()).unwrap();
        artifacts.push(Gem5ArchiveArtifact {
            role,
            relative: PathBuf::from(name),
            artifact: Gem5LaunchArtifact {
                path,
                content: canonical::content_ref(name.as_bytes(), "application/octet-stream")
                    .unwrap(),
            },
        });
    }
    let asset = artifacts[1].artifact.clone();
    let source = Gem5Launch {
        executable: asset.clone(),
        owner_script: asset.clone(),
        model_script: artifacts[2].artifact.clone(),
        guest: artifacts[3].artifact.clone(),
        guest_isa: "x86_64".into(),
        owner: Id::new("owner").unwrap(),
        incarnation: Id::new("source").unwrap(),
        generation: U64::new(1),
        resource_root: PathBuf::from("/saved/source/root"),
        timeout: Duration::from_secs(1),
        process_images: Some(super::super::super::Gem5ProcessImageTools {
            launcher: asset.clone(),
            restarter: asset.clone(),
            reconstruction_executable: asset.clone(),
            resource_helper: asset,
            image_root: root.clone(),
            temporary_root: root.clone(),
        }),
    };
    let boundary = Gem5Boundary {
        tick: U64::new(0),
        logical_position: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        ordinal: U64::new(0),
        tick_ordinal: U64::new(0),
        has_next_event: true,
        next_tick: U64::new(1),
        next_priority: 0,
        inventory: json!({"native_tick":"0","complete":false}),
    };
    (
        TestRoot(root),
        Gem5ArchiveImport {
            capture: Id::new("original-capture").unwrap(),
            source,
            boundary,
            completed: Vec::new(),
            pending: None,
            last_acknowledged: None,
            artifacts,
        },
    )
}

struct Reject(Cell<usize>);
impl Gem5ArchiveSourceVerifier for Reject {
    fn verify_archive(&self, _: &Gem5ArchiveImport) -> Result<(), ProviderError> {
        self.0.set(self.0.get() + 1);
        Err(ProviderError::Correlation("model signature unavailable"))
    }
}

#[test]
fn complete_syntax_and_content_cannot_import_unsigned_original_state() {
    let (_root, source) = fixture();
    let verifier = Reject(Cell::new(0));
    assert!(Gem5CapturedImage::import_authenticated_archive(source, &verifier).is_err());
    assert_eq!(verifier.0.get(), 1);
}

#[test]
fn unsafe_geometry_omitted_guest_and_orphan_ack_refuse_before_verification() {
    let (_root, original) = fixture();
    let mut unsafe_name = original.clone();
    unsafe_name.artifacts[0].relative = PathBuf::from("../owner.dmtcp");
    let mut omitted = original.clone();
    omitted.artifacts.pop();
    let mut orphan = original;
    orphan.last_acknowledged = Some(Id::new("missing-prefix").unwrap());
    let verifier = Reject(Cell::new(0));
    for source in [unsafe_name, omitted, orphan] {
        assert!(Gem5CapturedImage::import_authenticated_archive(source, &verifier).is_err());
    }
    assert_eq!(verifier.0.get(), 0);
}

#[test]
fn installed_verification_cannot_seal_artifacts_changed_during_its_io() {
    struct Change;
    impl Gem5ArchiveSourceVerifier for Change {
        fn verify_archive(&self, source: &Gem5ArchiveImport) -> Result<(), ProviderError> {
            fs::write(&source.artifacts[0].artifact.path, b"changed")?;
            Ok(())
        }
    }
    let (_root, source) = fixture();
    assert!(Gem5CapturedImage::import_authenticated_archive(source, &Change).is_err());
}

#[test]
fn oversized_historical_observer_refuses_before_installed_validation() {
    let (_root, mut source) = fixture();
    source.boundary.inventory = json!({"native_tick":"0", "oversized":
        "x".repeat(super::super::super::GEM5_NATIVE_FRAME_BYTES)});
    let verifier = Reject(Cell::new(0));
    assert!(matches!(
        Gem5CapturedImage::import_authenticated_archive(source, &verifier),
        Err(ProviderError::ResourceExhausted(_))
    ));
    assert_eq!(verifier.0.get(), 0);
}
