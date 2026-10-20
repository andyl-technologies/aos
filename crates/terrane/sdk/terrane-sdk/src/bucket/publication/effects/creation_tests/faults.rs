//! Exercises real durability, retained-name and cancellation fault boundaries.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::super::super::TestGatePhase;
use super::support::*;
use crate::store::{ContentStore, EffectFault, StoreErrorKind, TokioClock};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use terrane_format::bucket::BucketCapabilities;
use terrane_format::gc::{CreationJournal, JournalState};

async fn held(
    select: Select,
    fixture: &Fixture,
    pack: &crate::pack::SealedPack,
    phase: TestGatePhase,
) -> (
    tokio::task::JoinHandle<Result<terrane_format::identity::Identity, crate::store::StoreFailure>>,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (arrived, arrival) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture
        .fs
        .arm(select, 1, Action::Hold(phase, arrived, released));
    let bucket = fixture.bucket.clone();
    let bytes = pack.bytes().to_vec();
    let task = tokio::spawn(async move {
        use crate::store::{ContentUpload, MetaUpload};
        bucket
            .put(ContentUpload::Meta(
                MetaUpload::new(terrane_format::identity::IdentityKind::Pack, &bytes).unwrap(),
            ))
            .await
    });
    (task, arrival, release)
}

async fn arrived(arrival: mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
}

/// Proves durable Pending precedes the first actual artifact ancestor mutation.
///
/// # Panics
/// Panics on wrong ordering, absent hook consumption or false closed acknowledgment.
pub(super) async fn pending_order_and_closed_results() {
    let fixture = fixture().await;
    let pack = pack().await;
    let key = pack.header().id().pack_key();
    let path = journal(&fixture.control, &key);
    assert!(
        fixture
            .bucket
            .root()
            .join("objects/index/1/MANIFEST")
            .exists()
    );
    let pack_directory = fixture.bucket.root().join("objects/pack");
    let (task, arrival, release) = held(
        Select::Exact(Kind::DirectoryCreate(pack_directory.clone())),
        &fixture,
        &pack,
        TestGatePhase::BeforeChecks,
    )
    .await;
    arrived(arrival).await;
    assert!(!pack_directory.exists());
    let nonce = fixture.fs.nonces()[0];
    assert_eq!(
        tokio::fs::read(&path).await.unwrap(),
        pending_bytes(&key, nonce)
    );
    let effects = fixture.fs.effects();
    let qualified = effects
        .iter()
        .position(|kind| *kind == Kind::Pending(path.clone()))
        .unwrap();
    let first_mutation = effects
        .iter()
        .position(|kind| *kind == Kind::DirectoryCreate(pack_directory.clone()))
        .unwrap();
    assert!(qualified < first_mutation);
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
    fixture.fs.assert_consumed();
    assert_committed(&fixture, &key, pack.bytes()).await;

    for phase in 0..3 {
        let fixture = super::support::fixture().await;
        let pack = super::support::pack().await;
        let key = pack.header().id().pack_key();
        let target = journal(&fixture.control, &key);
        let kind = match phase {
            0 => Kind::Pending(target.clone()),
            1 => Kind::Seal(fixture.bucket.root().join(&key)),
            _ => Kind::Commit(target.clone()),
        };
        fixture.fs.arm(Select::Exact(kind), 1, Action::Noop);
        assert!(matches!(
            put(&fixture.bucket, &pack).await.unwrap_err().kind(),
            StoreErrorKind::Unsupported
        ));
        fixture.fs.assert_consumed();
        assert!(inventory(fixture.bucket.root()).await.is_empty());
        assert!(!fixture.fs.effects().iter().any(|kind| matches!(kind, Kind::Rename(path) if path.starts_with(fixture.control.join("publication/commits")))));
        assert!(matches!(
            CreationJournal::decode(&tokio::fs::read(&target).await.unwrap())
                .unwrap()
                .state,
            JournalState::Pending
        ));
        if phase == 0 {
            assert!(!fixture.bucket.root().join("objects/pack").exists());
        }
        assert!(
            !fixture
                .bucket
                .root()
                .join(pack.header().id().index_key())
                .exists()
        );
    }
}

/// Proves exact copied payload bytes carry no source creation-journal authority.
///
/// # Panics
/// Panics if payload copying/activation or journal separation fails.
pub(super) async fn copied_payload_has_no_creation_authority() {
    let source = fixture().await;
    let pack = pack().await;
    put(&source.bucket, &pack).await.unwrap();
    let mut config = source.config.clone();
    config.root = source.bucket.root().with_extension("copy");
    let source_image = image(source.bucket.root()).await;
    tokio::fs::create_dir(&config.root).await.unwrap();
    for (relative, bytes) in &source_image {
        let path = config.root.join(relative);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(path, bytes).await.unwrap();
    }
    assert_eq!(image(&config.root).await, source_image);
    let destination_control = control(&config.root);
    let fs = ProbeFs::default();
    let copied = crate::bucket::FileBucket::initialize_portable_copy(
        config.clone(),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert!(!destination_control.join(".terrane-creation").exists());
    fs.clear();
    put(&copied, &pack).await.unwrap();
    assert!(!destination_control.join(".terrane-creation").exists());
    assert!(
        !fs.effects()
            .iter()
            .any(|kind| matches!(kind, Kind::Pending(_) | Kind::Seal(_) | Kind::Commit(_)))
    );
    assert_eq!(
        tokio::fs::read(copied.root().join(pack.header().id().pack_key()))
            .await
            .unwrap(),
        pack.bytes()
    );
    assert_eq!(
        tokio::fs::read(copied.root().join(pack.header().id().index_key()))
            .await
            .unwrap(),
        pack.index_object()
    );
}

/// Refuses repeated secure-incarnation output before artifact or journal effects.
///
/// # Panics
/// Panics on nonce reuse, mutation or an unconsumed collision fixture.
pub(super) async fn fresh_nonce_collision_refuses_without_artifact_mutation() {
    for previous_member in 0..2 {
        let fixture = fixture().await;
        let pack = pack().await;
        unselected(&fixture, &pack).await;
        let keys = [
            pack.header().id().pack_key(),
            pack.header().id().index_key(),
        ];
        let old = CreationJournal::decode(
            &tokio::fs::read(journal(&fixture.control, &keys[previous_member]))
                .await
                .unwrap(),
        )
        .unwrap();
        tokio::fs::remove_file(fixture.bucket.root().join(&keys[0]))
            .await
            .unwrap();
        let before_root = image(fixture.bucket.root()).await;
        let before_control = image(&fixture.control).await;
        fixture.fs.clear();
        fixture.fs.repeat_nonce(old.nonce);

        assert!(matches!(
            put(&fixture.bucket, &pack).await.unwrap_err().kind(),
            StoreErrorKind::Unsupported
        ));
        assert_current_repair(&fixture);
        assert_eq!(fixture.fs.nonces(), vec![old.nonce]);
        assert_eq!(image(fixture.bucket.root()).await, before_root);
        assert_eq!(image(&fixture.control).await, before_control);
    }
}

/// Exercises owned, malformed, misplaced, colliding and unsafe valid-baseline cases.
///
/// # Panics
/// Panics on unexpected error classes, mutations or weakened pair-wide refusal.
pub(super) async fn owned_and_invalid_preimages() {
    for member in 0..2 {
        for present in [true, false] {
            let fixture = fixture().await;
            let pack = pack().await;
            unselected(&fixture, &pack).await;
            let keys = [
                pack.header().id().pack_key(),
                pack.header().id().index_key(),
            ];
            let path = journal(&fixture.control, &keys[member]);
            let baseline = CreationJournal::decode(&tokio::fs::read(&path).await.unwrap()).unwrap();
            tokio::fs::write(path, owned(&baseline)).await.unwrap();
            if !present {
                for key in &keys {
                    tokio::fs::remove_file(fixture.bucket.root().join(key))
                        .await
                        .unwrap();
                }
            }
            let root = image(fixture.bucket.root()).await;
            let control = image(&fixture.control).await;
            fixture.fs.clear();
            assert!(matches!(
                put(&fixture.bucket, &pack).await.unwrap_err().kind(),
                StoreErrorKind::Unsupported
            ));
            assert_current_repair(&fixture);
            assert_eq!(image(fixture.bucket.root()).await, root);
            assert_eq!(image(&fixture.control).await, control);
        }
    }
    for case in 0..5 {
        let fixture = fixture().await;
        let pack = pack().await;
        unselected(&fixture, &pack).await;
        let pack_key = pack.header().id().pack_key();
        let index_key = pack.header().id().index_key();
        let path = journal(&fixture.control, &pack_key);
        match case {
            0 => tokio::fs::write(&path, b"not canonical journal")
                .await
                .unwrap(),
            1 => {
                let other = tokio::fs::read(journal(&fixture.control, &index_key))
                    .await
                    .unwrap();
                tokio::fs::write(&path, other).await.unwrap();
            }
            2 => {
                let target = fixture.bucket.root().join(&pack_key);
                let mut bytes = tokio::fs::read(&target).await.unwrap();
                bytes[crate::pack::HEADER_SIZE + 1] ^= 1;
                tokio::fs::write(target, bytes).await.unwrap();
            }
            3 => {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                    .await
                    .unwrap();
            }
            _ => {
                let retained = path.with_extension("original");
                tokio::fs::rename(&path, &retained).await.unwrap();
                std::os::unix::fs::symlink(&retained, &path).unwrap();
            }
        }
        let root = image(fixture.bucket.root()).await;
        let control = image(&fixture.control).await;
        fixture.fs.clear();
        let error = put(&fixture.bucket, &pack).await.unwrap_err();
        if case >= 3 {
            assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
        } else {
            assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
        }
        assert_current_repair(&fixture);
        assert_eq!(image(fixture.bucket.root()).await, root);
        assert_eq!(image(&fixture.control).await, control);
    }
}

async fn replace_same_bytes(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let held = std::fs::File::open(path).unwrap();
    let old = held.metadata().unwrap();
    let bytes = tokio::fs::read(path).await.unwrap();
    let temporary = path.with_extension("replacement");
    tokio::fs::write(&temporary, &bytes).await.unwrap();
    tokio::fs::set_permissions(&temporary, old.permissions())
        .await
        .unwrap();
    tokio::fs::rename(temporary, path).await.unwrap();
    let new = std::fs::symlink_metadata(path).unwrap();
    assert_ne!((old.dev(), old.ino()), (new.dev(), new.ino()));
    assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
}

/// Rejects same-byte and changed-byte replacements at actual retained handoffs.
///
/// # Panics
/// Panics on lost identity checks, writes after refusal or unconsumed real gates.
pub(super) async fn retained_handoff_replacements() {
    for case in 0..7 {
        let fixture = fixture().await;
        let pack = pack().await;
        let key = pack.header().id().pack_key();
        let pending_path = journal(&fixture.control, &key);
        let (kind, phase) = if case == 0 {
            (
                Kind::Pending(pending_path.clone()),
                TestGatePhase::AfterOpen,
            )
        } else {
            (
                Kind::Seal(fixture.bucket.root().join(&key)),
                TestGatePhase::AfterOpen,
            )
        };
        let (task, arrival, release) = held(Select::Exact(kind), &fixture, &pack, phase).await;
        arrived(arrival).await;
        match case {
            0 => replace_same_bytes(&pending_path).await,
            1 => replace_same_bytes(&fixture.bucket.root().join(&key)).await,
            2 => {
                let path = fixture.bucket.root().join(&key);
                let mut bytes = tokio::fs::read(&path).await.unwrap();
                bytes[crate::pack::HEADER_SIZE + 1] ^= 1;
                tokio::fs::write(path, bytes).await.unwrap();
            }
            3 => replace_same_bytes(&fixture.control.join("backend-registration.cbor")).await,
            4 => {
                let key = terrane_format::bucket::BucketKey::parse("CAPABILITIES").unwrap();
                replace_same_bytes(&fixture.bucket.root().join(key.lock_name())).await;
            }
            5 => {
                let parent = fixture
                    .bucket
                    .root()
                    .join(&key)
                    .parent()
                    .unwrap()
                    .to_owned();
                let previous = parent.with_extension("old-parent");
                tokio::fs::rename(&parent, &previous).await.unwrap();
                tokio::fs::create_dir(&parent).await.unwrap();
                tokio::fs::copy(
                    previous.join(Path::new(&key).file_name().unwrap()),
                    parent.join(Path::new(&key).file_name().unwrap()),
                )
                .await
                .unwrap();
            }
            _ => {
                use std::os::unix::fs::DirBuilderExt;
                let original = image(&fixture.control).await;
                let previous = fixture.control.with_extension("old-control");
                tokio::fs::rename(&fixture.control, previous).await.unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&fixture.control)
                    .unwrap();
                for (relative, bytes) in original {
                    let path = fixture.control.join(relative);
                    tokio::fs::create_dir_all(path.parent().unwrap())
                        .await
                        .unwrap();
                    tokio::fs::write(&path, bytes).await.unwrap();
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        .await
                        .unwrap();
                }
            }
        }
        let before_root = image(fixture.bucket.root()).await;
        let before_control = image(&fixture.control).await;
        let count = fixture.fs.effects().len();
        release.send(()).unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err().kind(),
            StoreErrorKind::Unavailable { .. }
        ));
        fixture.fs.assert_consumed();
        assert_eq!(fixture.fs.effects().len(), count);
        assert_eq!(image(fixture.bucket.root()).await, before_root);
        assert_eq!(image(&fixture.control).await, before_control);
        assert!(!fixture.fs.native_errors().is_empty());
    }
}

struct SyncCase {
    select: Select,
    fault: EffectFault,
    expected: &'static str,
    visible_committed: bool,
}

fn sync_case(select: Select, fault: EffectFault, visible_committed: bool) -> SyncCase {
    let expected = match &fault {
        EffectFault::BeforeFileSync | EffectFault::AfterFileSync => "file sync",
        EffectFault::BeforeRename | EffectFault::AfterRename => "rename",
        EffectFault::BeforeDirectorySyncAt(_)
        | EffectFault::AfterDirectorySyncAt(_)
        | EffectFault::BeforeCommittedDirectorySyncAt(_)
        | EffectFault::AfterCommittedDirectorySyncAt(_) => "directory sync",
        EffectFault::UnavailableRead(_) => "exact read failure",
        _ => panic!("matrix requires an actual qualified boundary"),
    };
    SyncCase {
        select,
        fault,
        expected,
        visible_committed,
    }
}

/// Exercises actual staging, Pending, seal and commitment file/directory boundaries.
///
/// # Panics
/// Panics if a real selected fault does not fire or a failed version advances catalog.
pub(super) async fn durability_fault_matrix() {
    for number in 0..59 {
        let fixture = fixture().await;
        let pack = pack().await;
        let key = pack.header().id().pack_key();
        let pending = journal(&fixture.control, &key);
        let control_directory = fixture.control.join(".terrane-creation");
        let artifact_parent = fixture
            .bucket
            .root()
            .join(&key)
            .parent()
            .unwrap()
            .to_owned();
        let artifact_directories = [
            fixture.bucket.root().to_owned(),
            fixture.bucket.root().join("objects"),
            fixture.bucket.root().join("objects/pack"),
            artifact_parent.clone(),
        ];
        let controls = [fixture.control.clone(), control_directory.clone()];
        let case = match number {
            0 => sync_case(
                Select::WritesBelow(control_directory.clone()),
                EffectFault::BeforeFileSync,
                false,
            ),
            1 => sync_case(
                Select::WritesBelow(control_directory.clone()),
                EffectFault::AfterFileSync,
                false,
            ),
            2 => sync_case(
                Select::Exact(Kind::FileSync),
                EffectFault::BeforeFileSync,
                false,
            ),
            3 => sync_case(
                Select::Exact(Kind::Rename(pending.clone())),
                EffectFault::BeforeRename,
                false,
            ),
            4 => sync_case(
                Select::Exact(Kind::Rename(pending.clone())),
                EffectFault::AfterRename,
                false,
            ),
            5 => sync_case(
                Select::WritesBelow(control_directory.clone()),
                EffectFault::BeforeDirectorySyncAt(control_directory.clone()),
                false,
            ),
            6 => sync_case(
                Select::Exact(Kind::Rename(pending.clone())),
                EffectFault::AfterDirectorySyncAt(control_directory.clone()),
                false,
            ),
            7 | 8 => sync_case(
                Select::Exact(Kind::Pending(pending.clone())),
                if number == 7 {
                    EffectFault::BeforeFileSync
                } else {
                    EffectFault::AfterFileSync
                },
                false,
            ),
            9..=12 => sync_case(
                Select::Exact(Kind::Pending(pending.clone())),
                if number < 11 {
                    EffectFault::BeforeDirectorySyncAt(controls[number - 9].clone())
                } else {
                    EffectFault::AfterDirectorySyncAt(controls[number - 11].clone())
                },
                false,
            ),
            13 | 14 => sync_case(
                Select::WritesBelow(artifact_parent.clone()),
                if number == 13 {
                    EffectFault::BeforeFileSync
                } else {
                    EffectFault::BeforeDirectorySyncAt(artifact_parent.clone())
                },
                false,
            ),
            15 | 16 => sync_case(
                Select::Exact(Kind::Seal(fixture.bucket.root().join(&key))),
                if number == 15 {
                    EffectFault::BeforeFileSync
                } else {
                    EffectFault::AfterFileSync
                },
                false,
            ),
            17..=20 => sync_case(
                Select::Exact(Kind::Seal(fixture.bucket.root().join(&key))),
                EffectFault::BeforeDirectorySyncAt(artifact_directories[number - 17].clone()),
                false,
            ),
            21 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::BeforeFileSync,
                false,
            ),
            22 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::BeforeRename,
                false,
            ),
            23 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::AfterRename,
                true,
            ),
            24 | 25 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::BeforeDirectorySyncAt(controls[number - 24].clone()),
                false,
            ),
            26 | 27 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::BeforeCommittedDirectorySyncAt(controls[number - 26].clone()),
                true,
            ),
            28 | 29 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::AfterCommittedDirectorySyncAt(controls[number - 28].clone()),
                true,
            ),
            30 => sync_case(
                Select::Exact(Kind::FileSync),
                EffectFault::AfterFileSync,
                false,
            ),
            31 | 32 => sync_case(
                Select::Exact(Kind::Rename(pending.clone())),
                if number == 31 {
                    EffectFault::BeforeFileSync
                } else {
                    EffectFault::AfterFileSync
                },
                false,
            ),
            33 => sync_case(
                Select::WritesBelow(control_directory.clone()),
                EffectFault::AfterDirectorySyncAt(control_directory.clone()),
                false,
            ),
            34 => sync_case(
                Select::Exact(Kind::Rename(pending.clone())),
                EffectFault::BeforeDirectorySyncAt(control_directory.clone()),
                false,
            ),
            35 => sync_case(
                Select::Exact(Kind::Pending(pending.clone())),
                EffectFault::UnavailableRead(pending.clone()),
                false,
            ),
            36..=39 => sync_case(
                Select::Exact(Kind::Seal(fixture.bucket.root().join(&key))),
                EffectFault::AfterDirectorySyncAt(artifact_directories[number - 36].clone()),
                false,
            ),
            40 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::AfterFileSync,
                false,
            ),
            41 | 42 => sync_case(
                Select::Exact(Kind::Commit(pending.clone())),
                EffectFault::AfterDirectorySyncAt(controls[number - 41].clone()),
                false,
            ),
            43 => sync_case(
                Select::WritesBelow(artifact_parent.clone()),
                EffectFault::AfterFileSync,
                false,
            ),
            44 => sync_case(
                Select::WritesBelow(artifact_parent.clone()),
                EffectFault::AfterDirectorySyncAt(artifact_parent.clone()),
                false,
            ),
            45 | 46 => sync_case(
                Select::Exact(Kind::Rename(fixture.bucket.root().join(&key))),
                if number == 45 {
                    EffectFault::BeforeFileSync
                } else {
                    EffectFault::AfterFileSync
                },
                false,
            ),
            47 | 48 => sync_case(
                Select::Exact(Kind::Rename(fixture.bucket.root().join(&key))),
                if number == 47 {
                    EffectFault::BeforeRename
                } else {
                    EffectFault::AfterRename
                },
                false,
            ),
            49 | 50 => sync_case(
                Select::Exact(Kind::Rename(fixture.bucket.root().join(&key))),
                if number == 49 {
                    EffectFault::BeforeDirectorySyncAt(artifact_parent.clone())
                } else {
                    EffectFault::AfterDirectorySyncAt(artifact_parent.clone())
                },
                false,
            ),
            51 | 52 => sync_case(
                Select::Exact(Kind::DirectoryCreate(control_directory.clone())),
                if number == 51 {
                    EffectFault::BeforeDirectorySyncAt(fixture.control.clone())
                } else {
                    EffectFault::AfterDirectorySyncAt(fixture.control.clone())
                },
                false,
            ),
            53 | 54 => sync_case(
                Select::Exact(Kind::Directory(fixture.bucket.root().to_owned())),
                if number == 53 {
                    EffectFault::BeforeDirectorySyncAt(fixture.bucket.root().to_owned())
                } else {
                    EffectFault::AfterDirectorySyncAt(fixture.bucket.root().to_owned())
                },
                false,
            ),
            _ => {
                let directory = (number - 55) / 2 + 2;
                sync_case(
                    Select::Exact(Kind::DirectoryCreate(
                        artifact_directories[directory].clone(),
                    )),
                    if number % 2 == 1 {
                        EffectFault::BeforeDirectorySyncAt(
                            artifact_directories[directory - 1].clone(),
                        )
                    } else {
                        EffectFault::AfterDirectorySyncAt(
                            artifact_directories[directory - 1].clone(),
                        )
                    },
                    false,
                )
            }
        };
        fixture.fs.arm(case.select, 1, Action::Fault(case.fault));
        assert!(matches!(
            put(&fixture.bucket, &pack).await.unwrap_err().kind(),
            StoreErrorKind::Unavailable { .. }
        ));
        fixture.fs.assert_consumed();
        assert!(
            fixture
                .fs
                .native_errors()
                .iter()
                .any(|error| error.contains(case.expected)),
            "actual fault {number} did not fire: {:?}",
            fixture.fs.native_errors()
        );
        assert!(inventory(fixture.bucket.root()).await.is_empty());
        assert!(
            !fixture
                .bucket
                .root()
                .join(pack.header().id().index_key())
                .exists()
        );
        if pending.exists() {
            let record =
                CreationJournal::decode(&tokio::fs::read(&pending).await.unwrap()).unwrap();
            assert_eq!(
                matches!(record.state, JournalState::Committed { .. }),
                case.visible_committed
            );
        } else {
            assert!(!case.visible_committed);
        }
        if number <= 12 || (30..=35).contains(&number) || (51..=54).contains(&number) {
            assert!(!fixture.bucket.root().join("objects/pack").exists());
        }
    }
    let fixture = fixture().await;
    let pack = pack().await;
    let path = journal(&fixture.control, &pack.header().id().pack_key());
    fixture.fs.arm(
        Select::Exact(Kind::Commit(path.clone())),
        1,
        Action::Swallow(EffectFault::BeforeCommittedDirectorySyncAt(
            fixture.control.join(".terrane-creation"),
        )),
    );
    assert!(matches!(
        put(&fixture.bucket, &pack).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    fixture.fs.assert_consumed();
    assert!(
        fixture
            .fs
            .native_errors()
            .iter()
            .any(|error| error.contains("directory sync failure"))
    );
    assert!(matches!(
        CreationJournal::decode(&tokio::fs::read(path).await.unwrap())
            .unwrap()
            .state,
        JournalState::Committed { .. }
    ));
    assert!(inventory(fixture.bucket.root()).await.is_empty());
}

/// Retains actual namespace exclusion after cancellation through physical completion.
///
/// # Panics
/// Panics on premature independent progress, missing actual gate or failed release.
pub(super) async fn cancellation_retains_exclusion() {
    for boundary in 0..3 {
        let fixture = fixture().await;
        let first = pack().await;
        let key = first.header().id().pack_key();
        let path = journal(&fixture.control, &key);
        let kind = match boundary {
            0 => Kind::Pending(path),
            1 => Kind::Seal(fixture.bucket.root().join(&key)),
            _ => Kind::Commit(path),
        };
        let (task, arrival, release) = held(
            Select::Exact(kind),
            &fixture,
            &first,
            TestGatePhase::AfterOpen,
        )
        .await;
        arrived(arrival).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let next = pack().await;
        let bucket = fixture.bucket.clone();
        let (lock_attempt, attempted) = mpsc::channel();
        fixture.fs.observe_next_lock_attempt(lock_attempt);
        let mut competitor = tokio::spawn(async move { put(&bucket, &next).await });
        arrived(attempted).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut competitor)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(30), competitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fixture.fs.assert_consumed();
        assert_eq!(inventory(fixture.bucket.root()).await.len(), 1);
    }
}

/// Refuses read-only writes and unavailable actual retention without physical mutation.
///
/// # Panics
/// Panics if refusal changes any source/control/artifact bytes or submits effects.
pub(super) async fn readonly_and_retention() {
    let fixture = fixture().await;
    let pack = pack().await;
    let root = image(fixture.bucket.root()).await;
    let controls = image(&fixture.control).await;
    fixture.fs.deny_retention();
    assert!(matches!(
        put(&fixture.bucket, &pack).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(fixture.fs.effects().is_empty());
    assert_eq!(fixture.fs.ordinary_writes(), 0);
    assert_eq!(image(fixture.bucket.root()).await, root);
    assert_eq!(image(&fixture.control).await, controls);

    let fixture = super::support::fixture().await;
    let cap_path = fixture.bucket.root().join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&tokio::fs::read(&cap_path).await.unwrap()).unwrap();
    capabilities.layout_version = 1;
    capabilities.publication_protocol = None;
    capabilities.ref_names = None;
    tokio::fs::write(&cap_path, capabilities.encode().unwrap())
        .await
        .unwrap();
    let readonly = crate::bucket::FileBucket::open_legacy_read_only(
        fixture.config.clone(),
        fixture.fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    fixture.fs.clear();
    let root = image(fixture.bucket.root()).await;
    let controls = image(&fixture.control).await;
    let pack = super::support::pack().await;
    assert!(matches!(
        put(&readonly, &pack).await.unwrap_err().kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(fixture.fs.effects().is_empty());
    assert_eq!(fixture.fs.ordinary_writes(), 0);
    assert_eq!(image(fixture.bucket.root()).await, root);
    assert_eq!(image(&fixture.control).await, controls);
}
