//! Exercises cancellation at the real kernel/state publication boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::{self, File};
use std::future::{Future, poll_fn};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::publication::{
    AdoptionFailure, FsPublicationState, PublicationClaim, PublicationRecipe, PublicationState,
    Publisher,
};
use terrane_sdk::store::TokioLocalFs;

use super::{
    NativePublicationWorker, NativePublisher, NativePublisherConfig, NativeRetirementPolicy,
    NativeWipePolicy, WorkerGate,
};

#[path = "worker_tests/bound.rs"]
mod bound;

#[path = "worker_tests/encoded_quarantine.rs"]
mod encoded_quarantine;

fn fixture(name: &str) -> [PathBuf; 4] {
    let root =
        PathBuf::from(std::env::var_os("TERRANE_PUBLISH_VM_ROOT").expect("disk-backed VM fixture"));
    let root = root.join(name);
    let paths = [
        root.join("sealed"),
        root.join("staging"),
        root.join("pending-delete"),
        root.join("state/publication"),
    ];
    let project = crate::host_quota::NativeProject::inspect(&File::open(&root).unwrap()).unwrap();
    assert!((64101..=64108).contains(&project.project_id));
    assert!(project.inherit);
    for path in &paths {
        let actual = crate::host_quota::NativeProject::inspect(&File::open(path).unwrap()).unwrap();
        assert_eq!(actual.project_id, project.project_id);
        assert_eq!(actual.device, project.device);
        assert!(actual.inherit);
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }
    paths
}

fn configuration(root: &Path, wipe: NativeWipePolicy) -> NativePublisherConfig {
    NativePublisherConfig {
        domain: "public".into(),
        profile: ChunkProfile::cdc_1m([0; 32]),
        layout_root: root.to_owned(),
        wipe,
        retirement: NativeRetirementPolicy::new(Duration::from_millis(10)).unwrap(),
        content_uid: 840,
        content_gid: 845,
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

fn canceled_waiter_retains_owner_through_actual_binding_durability(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    let paths = fixture("worker-cancellation");
    let stale = paths[3].join(format!(".binding-{}", "ab".repeat(16)));
    fs::write(&stale, b"unfinished metadata").unwrap();
    let lease_scratch = paths[3].join(format!(".binding-retirement-{}", "cd".repeat(16)));
    fs::write(&lease_scratch, b"incomplete lease").unwrap();
    let (arrived_sender, arrived) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = WorkerGate {
        arrived: arrived_sender,
        release: Mutex::new(released),
    };
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        configuration(paths[0].parent().unwrap(), NativeWipePolicy::None),
        Some(gate),
        None,
    )
    .unwrap();
    assert!(
        !stale.exists(),
        "successful start must finish actual state recovery"
    );
    assert!(!lease_scratch.exists());

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
        NativePublisher::open(
            Arc::clone(&confinement),
            "public".into(),
            &paths[0],
            &paths[1],
            &paths[2]
        )
        .is_err(),
        "canceling every client must not release the active publisher exclusion"
    );
    let owner = super::NativePublicationOwner(Some(owner));
    let (finished, completion) = mpsc::sync_channel(1);
    let joining = std::thread::spawn(move || finished.send(owner.join()).unwrap());
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    release.send(()).unwrap();
    completion
        .recv_timeout(Duration::from_secs(20))
        .unwrap()
        .unwrap();
    joining.join().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = FsPublicationState::new(TokioLocalFs, paths[3].clone());
    assert!(runtime.block_on(state.binding(&claim)).unwrap().is_some());
    let native = NativePublisher::open(
        Arc::clone(&confinement),
        "public".into(),
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .unwrap();
    let mut publisher = Publisher::new(native, state);
    let adopted = runtime.block_on(publisher.adopt(&claim)).unwrap();
    assert_eq!(adopted.into_handle().metadata().unwrap().len(), 11);
}

fn startup_reports_actual_private_state_recovery_failure(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    let paths = fixture("worker-startup-failure");
    let malformed = paths[3].join(".binding-not-a-generated-name");
    let valid = paths[3].join(format!(".binding-{}", "ef".repeat(16)));
    fs::write(&malformed, b"unknown must survive").unwrap();
    fs::write(&valid, b"generated scratch must survive failed preflight").unwrap();
    let invalid_directory = paths[3].join(".binding-invalid-directory");
    fs::create_dir(&invalid_directory).unwrap();
    assert!(
        NativePublicationWorker::start(
            configuration(paths[0].parent().unwrap(), NativeWipePolicy::None),
            Arc::clone(&confinement),
        )
        .is_err()
    );
    assert_eq!(fs::read(malformed).unwrap(), b"unknown must survive");
    assert_eq!(
        fs::read(valid).unwrap(),
        b"generated scratch must survive failed preflight"
    );
    assert!(invalid_directory.is_dir());

    let native = NativePublisher::open(
        confinement,
        "public".into(),
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .expect("failed startup must finish teardown before returning its error");
    drop(native);
}

fn unsupported_wipe_policy_is_refused_before_directory_effects(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    let missing = Path::new("/unprovisioned-terrane-publisher");
    for policy in [
        NativeWipePolicy::Zero,
        NativeWipePolicy::Discard,
        NativeWipePolicy::Volatile,
    ] {
        let error = NativePublicationWorker::start(
            configuration(missing, policy),
            Arc::clone(&confinement),
        )
        .err()
        .expect("unsupported policy must refuse");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}

fn pending_restart_rebuilds_lease_and_requires_canonical_adoption(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
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
    let (worker, owner) =
        NativePublicationWorker::start_thread(Arc::clone(&confinement), make_config(), None, None)
            .unwrap();

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
    let (worker, owner) =
        NativePublicationWorker::start_thread(Arc::clone(&confinement), make_config(), None, None)
            .unwrap();
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

fn shared_directory(path: &Path) {
    let metadata = fs::metadata(path).expect("external supervisor provisioned shared directory");
    assert!(metadata.is_dir());
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
        (840, 845, 0o2770)
    );
}

fn shared_file(path: &Path, bytes: &[u8]) {
    let metadata =
        fs::metadata(path).expect("external supervisor provisioned immutable fixture bytes");
    assert!(metadata.is_file());
    assert_eq!((metadata.uid(), metadata.gid()), (840, 845));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

fn pack_fixture(root: &Path, id: [u8; 16]) -> (PathBuf, PathBuf, String, String, Vec<u8>) {
    use terrane_format::pack_format::{HEADER_SIZE, Header, PackView, Record, encode_pack};
    let bytes = b"pack-payload";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    let mut body = vec![0];
    body.extend_from_slice(bytes);
    let record = Record {
        hash: identity.digest().try_into().unwrap(),
        offset: HEADER_SIZE as u64,
        body_len: body.len() as u32,
        plaintext_len: bytes.len() as u32,
        codec: 0,
        kind: 0,
        dictionary_id: 0,
    };
    let pack = encode_pack(Header::new(id, false, false), &body, &[record]).unwrap();
    let index = PackView::decode(&pack).unwrap().index_object();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let id_hex = hex(&id);
    shared_directory(&root.join("objects/pack"));
    let shard = root.join("objects/pack").join(&id_hex[..2]);
    shared_directory(&shard);
    let pack_path = shard.join(format!("{id_hex}.pack"));
    let index_path = shard.join(format!("{id_hex}.idx"));
    shared_file(&pack_path, &pack);
    shared_file(&index_path, &index);
    let pack_pending = hex(TERRANE_V1
        .calculate(IdentityKind::Pack, &pack)
        .unwrap()
        .digest());
    let index_pending = hex(TERRANE_V1
        .calculate(IdentityKind::Index, &index)
        .unwrap()
        .digest());
    (pack_path, index_path, pack_pending, index_pending, pack)
}

fn pack_pair_reconciles_actual_partial_rename_without_replacing_collision(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    use super::{NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation};
    use std::io::Read;

    let paths = fixture("worker-pack-partial-rename");
    let root = paths[0].parent().unwrap();
    let id = [0x31; 16];
    let key = NativeBodyKey::Pack { pack_id: id };
    let (pack, index, pack_name, index_name, expected) = pack_fixture(root, id);
    let collision = paths[2].join(&index_name);
    fs::write(&collision, b"unrelated pending inode").unwrap();
    let context = NativeCommandContext {
        domain: "public".into(),
        cache_incarnation: [3; 16],
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        configuration(root, NativeWipePolicy::None),
        None,
        None,
    )
    .unwrap();
    runtime.block_on(async {
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
                NativeOperation::InspectBody {
                    key: key.clone(),
                    claim: None,
                },
            )
            .await
            .unwrap();
        let NativeCommandResult::Inspected { body, incarnation } = result else {
            panic!("unsealed custody result")
        };
        drop(body);
        let error = worker
            .execute(
                context.clone(),
                NativeOperation::Retire {
                    key: key.clone(),
                    incarnation: *incarnation.bytes(),
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    });
    assert!(!pack.exists());
    assert!(index.exists());
    assert!(paths[2].join(pack_name).exists());
    assert_eq!(fs::read(&collision).unwrap(), b"unrelated pending inode");
    drop(worker);
    owner.join().unwrap();

    fs::remove_file(&collision).unwrap();
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        configuration(root, NativeWipePolicy::None),
        None,
        None,
    )
    .unwrap();
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
            panic!("lifecycle-only pair result")
        };
        assert!(
            !index.exists(),
            "recovery reconciles canonical index into the pending unit"
        );
        worker
            .execute(
                context.clone(),
                NativeOperation::Restore {
                    key: key.clone(),
                    incarnation: *incarnation.bytes(),
                },
            )
            .await
            .unwrap();
        let result = worker
            .execute(
                context.clone(),
                NativeOperation::InspectBody { key, claim: None },
            )
            .await
            .unwrap();
        let NativeCommandResult::Inspected { body, .. } = result else {
            panic!("unsealed body, no serving proof")
        };
        let mut actual = Vec::new();
        body.into_handle().read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
    });
    assert!(pack.exists() && index.exists());
    drop(worker);
    owner.join().unwrap();
    encoded_quarantine::exercise(confinement, root, &pack, &index);
}

fn failed_second_unlink_recovers_orphan_index_without_pack_authority(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    use super::{NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation};

    let paths = fixture("worker-pack-partial-unlink");
    let root = paths[0].parent().unwrap();
    let id = [0x42; 16];
    let key = NativeBodyKey::Pack { pack_id: id };
    let (pack, index, pack_name, index_name, _) = pack_fixture(root, id);
    let survivor = root.join("index-survivor");
    assert_eq!(
        fs::metadata(&index).unwrap().ino(),
        fs::metadata(&survivor)
            .expect("supervisor retained the real index hardlink")
            .ino(),
    );
    let make_config = || {
        let mut config = configuration(root, NativeWipePolicy::None);
        config.retirement = NativeRetirementPolicy::new(Duration::from_millis(1)).unwrap();
        config
    };
    let (arrived_sender, arrived) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = WorkerGate {
        arrived: arrived_sender,
        release: Mutex::new(released),
    };
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        make_config(),
        None,
        Some(gate),
    )
    .unwrap();
    let context = NativeCommandContext {
        domain: "public".into(),
        cache_incarnation: [4; 16],
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let token = runtime.block_on(async {
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
                NativeOperation::InspectBody {
                    key: key.clone(),
                    claim: None,
                },
            )
            .await
            .unwrap();
        let NativeCommandResult::Inspected { body, incarnation } = result else {
            panic!("actual pair custody")
        };
        drop(body);
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
        token
    });
    std::thread::sleep(Duration::from_millis(30));
    let requester = worker.clone();
    let request_context = context.clone();
    let request_key = key.clone();
    let waiting = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(requester.execute(
            request_context,
            NativeOperation::FinishRetirement {
                key: request_key,
                incarnation: token,
            },
        ))
    });
    arrived.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(
        !paths[2].join(pack_name).exists(),
        "first actual unlink and fsync completed"
    );
    let index_pending = paths[2].join(index_name);
    fs::remove_file(&index_pending).unwrap();
    fs::create_dir(&index_pending).unwrap();
    release.send(()).unwrap();
    assert!(
        waiting.join().unwrap().is_err(),
        "the second actual unlink must fail on a directory"
    );
    assert!(
        NativePublisher::open(
            Arc::clone(&confinement),
            "public".into(),
            &paths[0],
            &paths[1],
            &paths[2]
        )
        .is_err(),
        "failure retains publisher custody"
    );
    fs::remove_dir(&index_pending).unwrap();
    // The supervisor supplied the retained real index before confinement.
    // Moving that existing link needs directory authority, not CAP_FOWNER or
    // a forbidden non-owner hardlink operation in the publisher process.
    fs::rename(&survivor, &index_pending).unwrap();
    File::open(root).unwrap().sync_all().unwrap();
    File::open(&paths[2]).unwrap().sync_all().unwrap();
    drop(worker);
    owner.join().unwrap();

    let (worker, owner) =
        NativePublicationWorker::start_thread(Arc::clone(&confinement), make_config(), None, None)
            .unwrap();
    let token = runtime.block_on(async {
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
            panic!("orphan grants no FD or binding")
        };
        let token = *incarnation.bytes();
        let error = worker
            .execute(
                context.clone(),
                NativeOperation::Restore {
                    key: key.clone(),
                    incarnation: token,
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::NotFound,
            "index cannot establish missing pack bytes"
        );
        token
    });
    std::thread::sleep(Duration::from_millis(30));
    runtime
        .block_on(worker.execute(
            context,
            NativeOperation::FinishRetirement {
                key,
                incarnation: token,
            },
        ))
        .unwrap();
    assert!(!pack.exists() && !index.exists() && !index_pending.exists());
    drop(worker);
    owner.join().unwrap();
    assert!(!survivor.exists());
}

fn prepared_roots_defer_staging_effects_and_retain_actual_exclusion(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    let paths = fixture("worker-prepared-roots");
    let root = paths[0].parent().unwrap();
    let previous = paths[1].join("previous-publisher");
    fs::create_dir(&previous).unwrap();
    fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
    let unfinished = previous.join("unfinished");
    fs::write(&unfinished, b"unserved staging").unwrap();

    let prepared = configuration(root, NativeWipePolicy::None)
        .prepare(Arc::clone(&confinement))
        .unwrap();
    assert_eq!(prepared.configuration().domain, "public");
    assert!(unfinished.exists(), "preflight does not perform cleanup");
    assert_eq!(fs::read_dir(&paths[1]).unwrap().count(), 1);
    assert!(
        NativePublisher::open(
            Arc::clone(&confinement),
            "public".into(),
            &paths[0],
            &paths[1],
            &paths[2]
        )
        .is_err()
    );
    let error = configuration(root, NativeWipePolicy::Zero)
        .prepare(Arc::clone(&confinement))
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(
        unfinished.exists(),
        "later unsupported domain cannot trigger earlier effects"
    );

    let (worker, owner) =
        NativePublicationWorker::start_prepared_thread(prepared, None, None).unwrap();
    assert!(!previous.exists());
    let directories: Vec<_> = fs::read_dir(&paths[1])
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(directories.len(), 1);
    assert!(directories[0].file_type().unwrap().is_dir());
    assert_eq!(
        directories[0].metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::read_dir(directories[0].path()).unwrap().count(), 0);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        use super::{NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation};
        let expected = claim();
        worker
            .publish(expected.clone(), source(root))
            .await
            .unwrap();
        let context = NativeCommandContext {
            domain: "public".into(),
            cache_incarnation: [17; 16],
        };
        worker
            .execute(context.clone(), NativeOperation::Drain)
            .await
            .unwrap();
        let result = worker
            .execute(context.clone(), NativeOperation::Inventory { cursor: None })
            .await
            .unwrap();
        let NativeCommandResult::Inventory { keys, next_cursor } = result else {
            panic!("inventory grants no native body authority")
        };
        assert_eq!(
            keys,
            vec![NativeBodyKey::Sealed {
                descriptor: expected.descriptor().clone()
            }]
        );
        assert!(next_cursor.is_none());

        // An independently matched native binding is supported; unknown fields
        // and physical orphans remain nonReady rather than becoming ignored
        // state. These controlled writes are ordinary publisher-owned state,
        // not writable handles to a sealed content inode.
        let state = FsPublicationState::new(TokioLocalFs, paths[3].clone());
        let record = state.binding_record_path(&expected);
        let original = fs::read(&record).unwrap();
        let mut malformed = original.clone();
        malformed.extend_from_slice(b"\nunknown_fixture_field = 1\n");
        fs::write(&record, malformed).unwrap();
        File::open(&record).unwrap().sync_all().unwrap();
        assert!(
            worker
                .execute(context.clone(), NativeOperation::Inventory { cursor: None })
                .await
                .is_err()
        );
        let conflicting = format!(
            "version = 1\ndomain = \"public\"\ndescriptor = {:?}\nverity_algorithm = 1\nverity_digest = {:?}\n",
            expected.descriptor().encode(),
            vec![0u8; 32],
        );
        fs::write(&record, conflicting.as_bytes()).unwrap();
        File::open(&record).unwrap().sync_all().unwrap();
        let digest: String = expected
            .descriptor()
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let canonical = paths[0].join(&digest[..2]).join(&digest);
        let retained = File::open(&canonical).unwrap();
        let inode = retained.metadata().unwrap();
        let measurement = crate::verity::measure(&retained).unwrap();
        let plaintext = fs::read(&canonical).unwrap();

        let result = worker
            .execute(context.clone(), NativeOperation::Inventory { cursor: None })
            .await
            .unwrap();
        let NativeCommandResult::Inventory { keys, next_cursor } = result else {
            panic!("conflicting inventory cannot grant a body or binding")
        };
        assert_eq!(
            keys,
            vec![NativeBodyKey::Sealed {
                descriptor: expected.descriptor().clone()
            }]
        );
        assert!(next_cursor.is_none());
        assert_eq!(fs::read(&record).unwrap(), conflicting.as_bytes());
        assert_eq!(fs::metadata(&canonical).unwrap().ino(), inode.ino());
        assert_eq!(fs::read(&canonical).unwrap(), plaintext);

        let error = worker
            .execute(
                context.clone(),
                NativeOperation::Adopt {
                    claim: expected.clone(),
                },
            )
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<AdoptionFailure>()),
            Some(AdoptionFailure::RecordedBindingMismatch)
        ));
        assert!(!canonical.exists());
        assert!(!record.exists());
        let quarantine = root.join("quarantine").join(&digest);
        let actual = fs::metadata(&quarantine).unwrap();
        assert_eq!((actual.dev(), actual.ino()), (inode.dev(), inode.ino()));
        assert_eq!(fs::read(&quarantine).unwrap(), plaintext);
        assert_eq!(crate::verity::measure(&retained).unwrap(), measurement);

        // A fresh ordinary publication restores a genuine valid record for the
        // remaining malformed/orphan inventory controls; no old binding is copied.
        worker
            .execute(context.clone(), NativeOperation::Resume)
            .await
            .unwrap();
        worker
            .publish(expected.clone(), source(root))
            .await
            .unwrap();
        worker
            .execute(context.clone(), NativeOperation::Drain)
            .await
            .unwrap();
        bound::exercise(&worker, &context, root).await;
        for name in [
            "retirement-unknown.toml".to_owned(),
            ".binding-incomplete".to_owned(),
            format!("{}-{}.toml", "00".repeat(32), "11".repeat(32)),
        ] {
            let orphan = paths[3].join(name);
            fs::write(&orphan, b"unreconciled").unwrap();
            assert!(
                worker
                    .execute(context.clone(), NativeOperation::Inventory { cursor: None })
                    .await
                    .is_err()
            );
            fs::remove_file(orphan).unwrap();
        }
        File::open(&paths[3]).unwrap().sync_all().unwrap();
        assert!(
            worker
                .execute(
                    context,
                    NativeOperation::Inventory {
                        cursor: Some(vec![0; 32])
                    }
                )
                .await
                .is_err()
        );
    });
    drop(worker);
    owner.join().unwrap();
}

fn staged_writer_retains_root_exclusion_after_adapter_drop(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    use terrane_sdk::host::publication::PublicationKernel;

    let paths = fixture("worker-staged-root-retention");
    let root = paths[0].parent().unwrap();
    let mut native = NativePublisher::open(
        Arc::clone(&confinement),
        "public".into(),
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .unwrap();
    let staged = native.stage(&claim(), source(root)).unwrap();
    drop(native);

    assert!(
        NativePublisher::open(
            Arc::clone(&confinement),
            "public".into(),
            &paths[0],
            &paths[1],
            &paths[2]
        )
        .is_err(),
        "a live staged writer keeps the actual staging-root flock"
    );
    drop(staged);
    let _native = NativePublisher::open(
        Arc::clone(&confinement),
        "public".into(),
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .unwrap();
    let directories: Vec<_> = fs::read_dir(&paths[1])
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(directories.len(), 1);
    assert_eq!(fs::read_dir(directories[0].path()).unwrap().count(), 0);
}

fn actual_binding_path_failure_rolls_back_before_backing_acknowledgment(
    confinement: Arc<crate::quota_confinement::Installed>,
) {
    let paths = fixture("worker-binding-path-failure");
    let root = paths[0].parent().unwrap();
    let (arrived_sender, arrived) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let gate = WorkerGate {
        arrived: arrived_sender,
        release: Mutex::new(released),
    };
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        configuration(root, NativeWipePolicy::None),
        Some(gate),
        None,
    )
    .unwrap();
    let requester = worker.clone();
    let input = source(root);
    let expected = claim();
    let pending_claim = expected.clone();
    let waiting = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(requester.publish(pending_claim, input))
    });
    arrived.recv_timeout(Duration::from_secs(20)).unwrap();
    let digest: String = expected
        .descriptor()
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let canonical = paths[0].join(&digest[..2]).join(&digest);
    assert!(
        canonical.exists(),
        "the actual canonical link and parent sync precede state binding"
    );
    let actual = File::open(&canonical).unwrap();
    crate::verity::measure(&actual).unwrap();

    // Force a real LocalFs metadata/open failure after the publication effects.
    // The fixture hook supplies no Result, acknowledgment or success receipt.
    let saved_state = root.join("saved-publication-state");
    fs::rename(&paths[3], &saved_state).unwrap();
    fs::write(&paths[3], b"not a directory").unwrap();
    release.send(()).unwrap();
    assert!(waiting.join().unwrap().is_err());
    assert!(
        !canonical.exists(),
        "failed real binding cannot acknowledge a backing inode"
    );
    assert_eq!(
        actual.metadata().unwrap().nlink(),
        0,
        "rollback removes canonical and private staging aliases"
    );
    drop(actual);
    assert!(
        NativePublisher::open(
            Arc::clone(&confinement),
            "public".into(),
            &paths[0],
            &paths[1],
            &paths[2]
        )
        .is_err(),
        "the physical owner still retains its exclusions"
    );
    drop(worker);
    owner.join().unwrap();

    fs::remove_file(&paths[3]).unwrap();
    fs::rename(saved_state, &paths[3]).unwrap();
    let (worker, owner) = NativePublicationWorker::start_thread(
        Arc::clone(&confinement),
        configuration(root, NativeWipePolicy::None),
        None,
        None,
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime
        .block_on(worker.publish(expected.clone(), source(root)))
        .unwrap();
    assert_eq!(
        result.into_handle().metadata().unwrap().len(),
        expected.plaintext_size()
    );
    let state = FsPublicationState::new(TokioLocalFs, paths[3].clone());
    let binding_path = state.binding_record_path(&expected);
    let record = fs::read_to_string(&binding_path).unwrap();
    let prefix = record.split_once("verity_digest =").unwrap().0;
    fs::write(
        &binding_path,
        format!("{prefix}verity_digest = {:?}\n", [0u8; 32]),
    )
    .unwrap();

    assert!(runtime.block_on(worker.adopt(expected.clone())).is_err());
    assert!(!canonical.exists());
    assert!(
        !binding_path.exists(),
        "exact stale binding removed only after quarantine"
    );
    assert!(root.join("quarantine").join(&digest).exists());
    runtime
        .block_on(worker.publish(expected.clone(), source(root)))
        .unwrap();
    assert!(canonical.exists());

    drop(worker);
    owner.join().unwrap();
    let state = FsPublicationState::new(TokioLocalFs, paths[3].clone());
    assert!(
        runtime
            .block_on(state.binding(&expected))
            .unwrap()
            .is_some()
    );
}

/// Runs one explicitly selected non-production native conformance scenario.
///
/// # Errors
/// Refuses a changed process receipt or an unknown fixture selector.
///
/// # Panics
/// Panics when actual kernel, custody, durability or recovery assertions fail.
pub(super) fn run(
    selector: &str,
    confinement: Arc<crate::quota_confinement::Installed>,
) -> io::Result<()> {
    confinement.check_current()?;
    match selector {
        "canceled_waiter_retains_owner_through_actual_binding_durability" => {
            canceled_waiter_retains_owner_through_actual_binding_durability(confinement)
        }
        "startup_reports_actual_private_state_recovery_failure" => {
            startup_reports_actual_private_state_recovery_failure(confinement)
        }
        "unsupported_wipe_policy_is_refused_before_directory_effects" => {
            unsupported_wipe_policy_is_refused_before_directory_effects(confinement)
        }
        "pending_restart_rebuilds_lease_and_requires_canonical_adoption" => {
            pending_restart_rebuilds_lease_and_requires_canonical_adoption(confinement)
        }
        "pack_pair_reconciles_actual_partial_rename_without_replacing_collision" => {
            pack_pair_reconciles_actual_partial_rename_without_replacing_collision(confinement)
        }
        "failed_second_unlink_recovers_orphan_index_without_pack_authority" => {
            failed_second_unlink_recovers_orphan_index_without_pack_authority(confinement)
        }
        "prepared_roots_defer_staging_effects_and_retain_actual_exclusion" => {
            prepared_roots_defer_staging_effects_and_retain_actual_exclusion(confinement)
        }
        "staged_writer_retains_root_exclusion_after_adapter_drop" => {
            staged_writer_retains_root_exclusion_after_adapter_drop(confinement)
        }
        "actual_binding_path_failure_rolls_back_before_backing_acknowledgment" => {
            actual_binding_path_failure_rolls_back_before_backing_acknowledgment(confinement)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown native publication fixture",
            ));
        }
    }
    Ok(())
}
