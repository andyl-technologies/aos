//! Exercises cancellation at the real kernel/state publication boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::{self, File};
use std::future::{Future, poll_fn};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use terrane::host::publication::{FsPublicationState, PublicationClaim, PublicationRecipe, PublicationState, Publisher};
use terrane::store::TokioLocalFs;
use terrane_core::chunking::ChunkProfile;
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};

use super::{NativePublicationWorker, NativePublisher, WorkerGate};

fn fixture(name: &str) -> [PathBuf; 4] {
    let root = PathBuf::from(std::env::var_os("TERRANE_PUBLISH_VM_ROOT").expect("disk-backed VM fixture"));
    let root = root.join(name);
    fs::create_dir(&root).unwrap();
    let paths = [root.join("sealed"), root.join("staging"), root.join("pending"), root.join("state")];
    for path in &paths {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    paths
}

fn claim() -> PublicationClaim {
    let bytes = b"cancel-safe";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    PublicationClaim::new("public".into(), PublicationRecipe::Inline {
        chunk: Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap(),
    }, &ChunkProfile::cdc_1m([0; 32])).unwrap()
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
    let gate = WorkerGate { arrived: arrived_sender, release: Mutex::new(released) };
    let (worker, owner) = NativePublicationWorker::start_thread("public".into(),
        &paths[0], &paths[1], &paths[2], &paths[3], Some(gate)).unwrap();
    assert!(!stale.exists(), "successful start must finish actual state recovery");

    let claim = claim();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let request = worker.publish(claim.clone(), source(paths[0].parent().unwrap()));
        let mut request = std::pin::pin!(request);
        poll_fn(|context| {
            assert!(request.as_mut().poll(context).is_pending());
            Poll::Ready(())
        }).await;
        arrived.recv_timeout(Duration::from_secs(20)).unwrap();
        // Leaving this scope drops the actual request future while the owned
        // publisher has already sealed, linked and synchronized its inode.
    });
    drop(worker);
    drop(runtime);

    assert!(NativePublisher::open("public".into(), &paths[0], &paths[1], &paths[2]).is_err(),
        "canceling every client must not release the active publisher exclusion");
    release.send(()).unwrap();
    owner.join().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
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
    assert!(NativePublicationWorker::start("public".into(), &paths[0], &paths[1],
        &paths[2], &paths[3]).is_err());
}
