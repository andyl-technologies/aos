//! Exercises cancellation at the real kernel/state publication boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::{self, File};
use std::future::{Future, poll_fn};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use terrane::host::publication::{
    FsPublicationState, PublicationClaim, PublicationRecipe, PublicationState, Publisher,
};
use terrane::store::TokioLocalFs;
use terrane_core::chunking::ChunkProfile;
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};

use super::{
    NativePublicationWorker, NativePublisher, NativePublisherConfig, NativeRetirementPolicy,
    NativeWipePolicy, WorkerGate,
};

fn fixture(name: &str) -> [PathBuf; 4] {
    let root =
        PathBuf::from(std::env::var_os("TERRANE_PUBLISH_VM_ROOT").expect("disk-backed VM fixture"));
    let root = root.join(name);
    fs::create_dir(&root).unwrap();
    for name in ["chunks", "objects", "quarantine"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o2770)).unwrap();
    }
    fs::create_dir(root.join("state")).unwrap();
    let paths = [
        root.join("sealed"),
        root.join("staging"),
        root.join("pending-delete"),
        root.join("state/publication"),
    ];
    for path in &paths {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    paths
}

fn configuration(root: &Path, wipe: NativeWipePolicy) -> NativePublisherConfig {
    NativePublisherConfig {
        domain: "public".into(),
        layout_root: root.to_owned(),
        wipe,
        retirement: NativeRetirementPolicy::new(Duration::from_millis(10)).unwrap(),
        content_uid: rustix::process::geteuid().as_raw(),
        content_gid: rustix::process::getegid().as_raw(),
    }
}

fn claim() -> PublicationClaim {
    let bytes = b"cancel-safe";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Inline {
            chunk: Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap(),
        },
        &ChunkProfile::cdc_1m([0; 32]),
    )
    .unwrap()
}

fn source(path: &Path) -> File {
    let path = path.join("input");
    fs::write(&path, b"cancel-safe").unwrap();
    File::open(path).unwrap()
}

#[test]
#[ignore = "requires explicitly provisioned disk-backed verity-enabled ext4 in the AOS VM"]
fn canceled_waiter_retains_owner_through_actual_binding_durability() {
    let paths = fixture("worker-cancellation");
    let stale = paths[3].join(".binding-incomplete");
    fs::write(&stale, b"unfinished metadata").unwrap();
    let (arrived_sender, arrived) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = WorkerGate {
        arrived: arrived_sender,
        release: Mutex::new(released),
    };
    let (worker, owner) = NativePublicationWorker::start_thread(
        configuration(paths[0].parent().unwrap(), NativeWipePolicy::None),
        Some(gate),
    )
    .unwrap();
    assert!(
        !stale.exists(),
        "successful start must finish actual state recovery"
    );

    let claim = claim();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let request = worker.publish(claim.clone(), source(paths[0].parent().unwrap()));
        let mut request = std::pin::pin!(request);
        poll_fn(|context| {
            assert!(request.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        arrived.recv_timeout(Duration::from_secs(20)).unwrap();
        // Leaving this scope drops the actual request future while the owned
        // publisher has already sealed, linked and synchronized its inode.
    });
    drop(worker);
    drop(runtime);

    assert!(
        NativePublisher::open("public".into(), &paths[0], &paths[1], &paths[2]).is_err(),
        "canceling every client must not release the active publisher exclusion"
    );
    release.send(()).unwrap();
    owner.join().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = FsPublicationState::new(TokioLocalFs, paths[3].clone());
    assert!(runtime.block_on(state.binding(&claim)).unwrap().is_some());
    let native = NativePublisher::open("public".into(), &paths[0], &paths[1], &paths[2]).unwrap();
    let mut publisher = Publisher::new(native, state);
    let adopted = runtime.block_on(publisher.adopt(&claim)).unwrap();
    assert_eq!(adopted.into_handle().metadata().unwrap().len(), 11);
}

#[test]
#[ignore = "requires explicitly provisioned disk-backed verity-enabled ext4 in the AOS VM"]
fn startup_reports_actual_private_state_recovery_failure() {
    let paths = fixture("worker-startup-failure");
    fs::create_dir(paths[3].join(".binding-invalid-directory")).unwrap();
    assert!(
        NativePublicationWorker::start(configuration(
            paths[0].parent().unwrap(),
            NativeWipePolicy::None
        ))
        .is_err()
    );
}

#[test]
fn unsupported_wipe_policy_is_refused_before_directory_effects() {
    let missing = Path::new("/unprovisioned-terrane-publisher");
    for policy in [
        NativeWipePolicy::Zero,
        NativeWipePolicy::Discard,
        NativeWipePolicy::Volatile,
    ] {
        let error = NativePublicationWorker::start(configuration(missing, policy))
            .err()
            .expect("unsupported policy must refuse");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}

#[test]
#[ignore = "requires explicitly provisioned disk-backed verity-enabled ext4 in the AOS VM"]
fn pending_restart_rebuilds_lease_and_requires_canonical_adoption() {
    use super::{NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation};

    let paths = fixture("worker-pending-restart");
    let root = paths[0].parent().unwrap();
    let make_config = || {
        let mut config = configuration(root, NativeWipePolicy::None);
        config.retirement = NativeRetirementPolicy::new(Duration::from_secs(30)).unwrap();
        config
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let claim = claim();
    let key = NativeBodyKey::Sealed {
        descriptor: claim.descriptor().clone(),
    };
    let context = NativeCommandContext {
        domain: "public".into(),
        cache_incarnation: [1; 16],
    };
    let (worker, owner) = NativePublicationWorker::start_thread(make_config(), None).unwrap();

    let old_token = runtime.block_on(async {
        worker
            .execute(context.clone(), NativeOperation::Drain)
            .await
            .unwrap();
        worker
            .execute(context.clone(), NativeOperation::Resume)
            .await
            .unwrap();
        let result = worker
            .execute(
                context.clone(),
                NativeOperation::Publish {
                    claim: claim.clone(),
                    source: source(root),
                },
            )
            .await
            .unwrap();
        let NativeCommandResult::Published {
            object,
            incarnation,
        } = result
        else {
            panic!("native published result")
        };
        drop(object);
        let token = *incarnation.bytes();
        worker
            .execute(
                context.clone(),
                NativeOperation::Retire {
                    key: key.clone(),
                    incarnation: token,
                },
            )
            .await
            .unwrap();
        let error = worker
            .execute(
                context.clone(),
                NativeOperation::FinishRetirement {
                    key: key.clone(),
                    incarnation: token,
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        token
    });
    drop(worker);
    owner.join().unwrap();

    // Simulate losing embedded deadline state while the pending inode survives.
    for entry in fs::read_dir(&paths[3]).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b"retirement-")
        {
            fs::remove_file(entry.path()).unwrap();
        }
    }
    File::open(&paths[3]).unwrap().sync_all().unwrap();
    let (worker, owner) = NativePublicationWorker::start_thread(make_config(), None).unwrap();
    let context = NativeCommandContext {
        domain: "public".into(),
        cache_incarnation: [2; 16],
    };
    runtime.block_on(async {
        worker
            .execute(context.clone(), NativeOperation::Drain)
            .await
            .unwrap();
        let result = worker
            .execute(
                context.clone(),
                NativeOperation::InspectPending { key: key.clone() },
            )
            .await
            .unwrap();
        let NativeCommandResult::Pending { incarnation } = result else {
            panic!("no FD or binding in pending result")
        };
        let token = *incarnation.bytes();
        assert_ne!(token, old_token);
        let error = worker
            .execute(
                context.clone(),
                NativeOperation::FinishRetirement {
                    key: key.clone(),
                    incarnation: token,
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::WouldBlock,
            "lost state must not mean expired"
        );
        worker
            .execute(
                context.clone(),
                NativeOperation::Restore {
                    key: key.clone(),
                    incarnation: token,
                },
            )
            .await
            .unwrap();
        let result = worker
            .execute(
                context.clone(),
                NativeOperation::Adopt {
                    claim: claim.clone(),
                },
            )
            .await
            .unwrap();
        let NativeCommandResult::Published {
            object,
            incarnation,
        } = result
        else {
            panic!("canonical adoption must mint backing")
        };
        assert_eq!(object.into_handle().metadata().unwrap().len(), 11);
        assert_eq!(
            *incarnation.bytes(),
            token,
            "same actual inode retains its lifecycle token"
        );
        worker
            .execute(context.clone(), NativeOperation::Resume)
            .await
            .unwrap();
        let error = worker
            .execute(
                context.clone(),
                NativeOperation::Retire {
                    key: key.clone(),
                    incarnation: old_token,
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        worker
            .execute(
                context,
                NativeOperation::Retire {
                    key,
                    incarnation: token,
                },
            )
            .await
            .unwrap();
    });
    drop(worker);
    owner.join().unwrap();
}
