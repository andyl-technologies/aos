//! Exercises genuine creator events, exact staging and genesis probe proposals.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::store::{ChunkRequirement, ContentValidator, MetaUpload, TokioClock, TokioLocalFs};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use terrane_core::bucket::{BucketCapabilities, StoreProfile};
use terrane_core::chunking::ChunkProfile;
use terrane_core::gc::publication::{Activation, BackendRegistration};

pub(in super::super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, _: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        Ok(())
    }

    fn chunk_requirements(
        &self,
        _: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        Ok(Vec::new())
    }
}

pub(in super::super) struct Fixture {
    pub(in super::super) parent: PathBuf,
    pub(in super::super) root: PathBuf,
    pub(in super::super) control: PathBuf,
    pub(in super::super) owner: u32,
}

impl Fixture {
    pub(in super::super) fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let parent = std::env::temp_dir().join(format!(
            "terrane-fresh-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let owner = std::fs::symlink_metadata(&parent).unwrap().uid();
        Self {
            root: parent.join("payload"),
            control: parent.join("control"),
            parent,
            owner,
        }
    }

    pub(in super::super) fn config(&self) -> FileBucketConfig {
        FileBucketConfig {
            root: self.root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: self.owner,
                control: Some(self.control.clone()),
            }),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([0; 32]),
            locality: Default::default(),
        }
    }

    pub(in super::super) fn request(&self) -> NativePublicationInitialization {
        crate::store::native_initialization_request(
            &self.root,
            &self.control,
            self.owner,
            StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: [0; 32],
            },
            7,
        )
        .unwrap()
    }

    pub(in super::super) async fn staged(&self) -> NativePendingRoot {
        match TokioLocalFs
            .initialize_publication(self.request())
            .await
            .unwrap()
        {
            NativePublicationInitializationOutcome::Fresh(receipt) => *receipt,
            NativePublicationInitializationOutcome::Existing => {
                panic!("genuine absent root was not created")
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.parent).unwrap();
    }
}

#[tokio::test]
async fn fresh_native_creator_stages_pending_before_selected_activation() {
    let fixture = Fixture::new();
    let receipt = fixture.staged().await;
    let registration = std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap();
    let registration = BackendRegistration::decode(&registration).unwrap();
    assert_eq!(registration.activation, Activation::Pending);
    assert_eq!(registration.binding, receipt.binding);
    assert!(matches!(
        std::fs::symlink_metadata(fixture.control.join("publication/commits/0")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    receipt
        .staged
        .transaction
        .check_snapshot(&receipt.staged.snapshot_bytes)
        .unwrap();
    assert_eq!(
        std::fs::read(fixture.root.join("publication/PORTABLE")).unwrap(),
        receipt.staged.transaction.snapshot.encode().unwrap()
    );

    activate(&TokioLocalFs, receipt).await.unwrap();
    let registration = BackendRegistration::decode(
        &std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap(),
    )
    .unwrap();
    assert_eq!(registration.activation, Activation::Active);
    assert!(registration.genesis.is_some());
    let bucket = FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    assert_eq!(bucket.root(), fixture.root);
}

#[tokio::test]
async fn fresh_creation_race_returns_existing_without_repairing_winner() {
    let fixture = Fixture::new();
    let (left, right) = tokio::join!(
        TokioLocalFs.initialize_publication(fixture.request()),
        TokioLocalFs.initialize_publication(fixture.request())
    );
    let receipt = match (left.unwrap(), right.unwrap()) {
        (
            NativePublicationInitializationOutcome::Fresh(receipt),
            NativePublicationInitializationOutcome::Existing,
        )
        | (
            NativePublicationInitializationOutcome::Existing,
            NativePublicationInitializationOutcome::Fresh(receipt),
        ) => *receipt,
        _ => panic!("exactly one genuine creator must win"),
    };
    let pending = std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap();
    assert_eq!(pending, receipt.pending);
    activate(&TokioLocalFs, receipt).await.unwrap();
}

#[tokio::test]
async fn fresh_probe_preparation_checks_whole_cap_before_any_staging() {
    let fixture = Fixture::new();
    let receipt = fixture.staged().await;
    let NativePendingRoot {
        request,
        directories,
        exclusions,
        binding,
        pending,
        staged,
        names,
        reads,
        ..
    } = receipt;
    let directories = Arc::new(Mutex::new(directories));
    let mut frame =
        bootstrap::restore_frame(request.operator_uid, exclusions, names, reads).unwrap();
    bootstrap::finish(
        &TokioLocalFs,
        &request,
        &binding,
        &pending,
        &staged,
        &mut frame,
        &directories,
    )
    .await
    .unwrap();
    let original = std::fs::read(fixture.root.join("CAPABILITIES")).unwrap();
    let mut replacement = BucketCapabilities::decode(&original).unwrap();
    replacement.probed_at += 1;
    let replacement = replacement.encode().unwrap();
    let mut stale = original.clone();
    stale.push(0);

    let error = bootstrap::prepare_capability_change(
        &TokioLocalFs,
        &request,
        &staged,
        &mut frame,
        &directories,
        &stale,
        &replacement,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(
        std::fs::read(fixture.root.join("CAPABILITIES")).unwrap(),
        original
    );
    assert!(matches!(
        std::fs::symlink_metadata(fixture.control.join("publication/commits/1")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    let proposal = bootstrap::prepare_capability_change(
        &TokioLocalFs,
        &request,
        &staged,
        &mut frame,
        &directories,
        &original,
        &replacement,
    )
    .await
    .unwrap();
    assert_eq!(proposal.expected, Some(original));
    assert_eq!(proposal.new, Some(replacement));
    assert_eq!(proposal.key, "CAPABILITIES");
}

#[tokio::test]
async fn unavailable_native_initialization_hook_refuses_before_any_effect() {
    let fixture = Fixture::new();
    let fs = super::test_fs::ProbeFs::default();
    let error = FileBucket::open(fixture.config(), fs.clone(), TokioClock, Validator)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(fs.ordinary_effects(), 0);
    for path in [&fixture.root, &fixture.control] {
        assert!(
            matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
}

#[tokio::test]
async fn fresh_activation_requires_real_create_new_and_binding_range_probes() {
    for wrong_range in [false, true] {
        let fixture = Fixture::new();
        let receipt = fixture.staged().await;
        let fs = super::test_fs::ProbeFs::default();
        if wrong_range {
            fs.wrong_range();
        } else {
            fs.noop_probe();
        }
        let error = activate(&fs, receipt).await.err().unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
        assert_eq!(fs.ordinary_effects(), 0);
        assert!(
            matches!(std::fs::symlink_metadata(fixture.control.join("publication/commits/1")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
}

#[tokio::test]
async fn interrupted_creator_before_pending_does_not_authorize_existing_root() {
    let fixture = Fixture::new();
    super::io::initializer_faults::register(
        fixture.control.clone(),
        super::io::initializer_faults::Hook::BeforeRegistration,
    );
    TokioLocalFs
        .initialize_publication(fixture.request())
        .await
        .err()
        .unwrap();
    assert!(fixture.root.is_dir());
    assert!(fixture.control.is_dir());
    assert!(
        matches!(std::fs::symlink_metadata(fixture.control.join("backend-registration.cbor")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    );

    FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(std::fs::symlink_metadata(fixture.control.join("publication/commits/0")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        matches!(std::fs::symlink_metadata(fixture.control.join("backend-registration.cbor")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_running_creator_retains_actual_directories_and_exclusion_through_staging() {
    use super::io::initializer_faults::{Hook, register};
    let fixture = Fixture::new();
    let (observed, observations) = std::sync::mpsc::channel();
    let (arrived, arrivals) = std::sync::mpsc::channel();
    let (release, releases) = std::sync::mpsc::channel();
    register(
        fixture.control.clone(),
        Hook::Running {
            observed,
            arrived,
            release: releases,
        },
    );
    let request = fixture.request();
    let creator = tokio::spawn(async move { TokioLocalFs.initialize_publication(request).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || arrivals.recv().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let directories = observations
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();

    creator.abort();
    assert!(creator.await.err().unwrap().is_cancelled());
    assert!(directories.upgrade().is_some());
    let path = fixture
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    use std::os::unix::fs::OpenOptionsExt;
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    let named = std::fs::symlink_metadata(&path).unwrap();
    let opened = contender.metadata().unwrap();
    assert_eq!((named.dev(), named.ino()), (opened.dev(), opened.ino()));
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(contender);

    release.send(()).unwrap();
    let guard = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        TokioLocalFs.lock_existing_exclusive(&path),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(directories.upgrade().is_none());
    let pending = BackendRegistration::decode(
        &std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap(),
    )
    .unwrap();
    assert_eq!(pending.activation, Activation::Pending);
    let pointer = terrane_core::gc::publication::PortableCurrent::decode(
        &std::fs::read(fixture.root.join("publication/PORTABLE")).unwrap(),
    )
    .unwrap();
    pointer
        .check_snapshot(&std::fs::read(fixture.root.join(&pointer.key)).unwrap())
        .unwrap();
    drop(guard);

    FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
}

#[test]
fn fresh_creator_enforces_actual_descriptor_modes_under_restrictive_umask() {
    const MASK: &str = "TERRANE_FRESH_CREATOR_TEST_MASK";
    let Some(mask) = std::env::var_os(MASK) else {
        let name = concat!(
            module_path!(),
            "::fresh_creator_enforces_actual_descriptor_modes_under_restrictive_umask"
        );
        let (_, test) = name.split_once("::").unwrap();
        for mask in ["0300", "0777"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--test-threads=1", "--nocapture"])
                .env(MASK, mask)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let mask = u32::from_str_radix(mask.to_str().unwrap(), 8).unwrap();
    let fixture = Fixture::new();
    let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
    let result = fixture.request().execute_inline();
    rustix::process::umask(previous);
    match result {
        Ok(NativePublicationInitializationOutcome::Fresh(receipt)) => {
            for directory in [&fixture.root, &fixture.control] {
                let metadata = std::fs::symlink_metadata(directory).unwrap();
                assert_eq!(metadata.uid(), fixture.owner);
                assert_eq!(metadata.mode() & 0o7777, 0o700);
            }
            assert_eq!(
                receipt.pending,
                std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap()
            );
        }
        Err(error) if mask == 0o777 => {
            assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
            assert!(
                matches!(std::fs::symlink_metadata(fixture.control.join("backend-registration.cbor")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            );
            std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        _ => panic!("unexpected genuine creator outcome under mask{mask:04o}"),
    }
}

#[tokio::test]
async fn native_creator_requires_actual_effective_uid_before_creating_any_name() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    assert_eq!(request.operator_uid, rustix::process::geteuid().as_raw());
    request.operator_uid ^= 1;

    let error = TokioLocalFs
        .initialize_publication(request)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    for path in [&fixture.root, &fixture.control] {
        assert!(
            matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }

    // The same genuine configured creator remains eligible after the refusal.
    let receipt = fixture.staged().await;
    activate(&TokioLocalFs, receipt).await.unwrap();
}
