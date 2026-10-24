//! Checks original encoded chunk and pack/index quarantine under actual custody.

use super::{NativeWipePolicy, configuration};
use crate::publisher_io::{
    NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation,
    NativePublicationWorker,
};
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};

/// Exercises actual collision refusal and moves the original native allocations.
///
/// # Panics
/// Panics if original native custody, no-replace moves or token revocation fail.
pub(super) fn exercise(
    confinement: Arc<crate::quota_confinement::Installed>,
    root: &Path,
    pack: &Path,
    index: &Path,
) {
    let descriptor = Descriptor::from_wire(
        &TERRANE_V1,
        TERRANE_V1.algorithm(),
        TERRANE_V1.domain(IdentityKind::Chunk).unwrap(),
        &[0x51; 32],
        16,
    )
    .unwrap();
    let chunk = root
        .join("chunks/51")
        .join(format!("{}.0", "51".repeat(32)));
    // This deliberately unverified chunk has no HOST-14 content authority.
    // Its real UID, project and original inode suffice only for quarantine.
    assert!(
        descriptor
            .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, b"unverified-chunk")
            .is_err()
    );
    let units = [
        (
            NativeBodyKey::Pack {
                pack_id: [0x31; 16],
            },
            vec![pack.to_owned(), index.to_owned()],
        ),
        (
            NativeBodyKey::Chunk {
                descriptor,
                codec: 0,
            },
            vec![chunk],
        ),
    ];
    let originals: Vec<_> = units
        .iter()
        .map(|(_, paths)| {
            paths
                .iter()
                .map(|path| {
                    let metadata = fs::metadata(path).unwrap();
                    assert_eq!(
                        (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
                        (840, 845, 0o640)
                    );
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.blocks(),
                        fs::read(path).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let context = NativeCommandContext {
        domain: "public".into(),
        cache_incarnation: [7; 16],
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
        for (key, paths) in &units {
            let token = inspect(&worker, &context, key).await;
            let mut wrong = token;
            wrong[0] ^= 1;
            assert_eq!(
                worker
                    .execute(
                        context.clone(),
                        NativeOperation::Quarantine {
                            key: key.clone(),
                            incarnation: wrong,
                        }
                    )
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );

            // Collision on the final pack member must precede either rename.
            let last = paths.last().unwrap();
            let collision = destination(root, last, &token);
            fs::write(&collision, b"earlier encoded quarantine").unwrap();
            let previous = fs::metadata(&collision).unwrap().ino();
            assert_eq!(
                worker
                    .execute(
                        context.clone(),
                        NativeOperation::Quarantine {
                            key: key.clone(),
                            incarnation: token,
                        }
                    )
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::AlreadyExists
            );
            assert!(paths.iter().all(|path| path.exists()));
            assert_eq!(fs::metadata(&collision).unwrap().ino(), previous);
            assert_eq!(fs::read(&collision).unwrap(), b"earlier encoded quarantine");
            assert!(
                worker
                    .execute(
                        context.clone(),
                        NativeOperation::Retire {
                            key: key.clone(),
                            incarnation: token,
                        }
                    )
                    .await
                    .is_err()
            );
            fs::remove_file(collision).unwrap();
        }
    });
    drop(worker);
    owner.join().unwrap();

    // A failed exchange requires a new actual owner and fresh native inspection.
    let (worker, owner) = NativePublicationWorker::start_thread(
        confinement,
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
        for ((key, paths), originals) in units.iter().zip(&originals) {
            let token = inspect(&worker, &context, key).await;
            assert!(matches!(
                worker
                    .execute(
                        context.clone(),
                        NativeOperation::Quarantine {
                            key: key.clone(),
                            incarnation: token,
                        }
                    )
                    .await
                    .unwrap(),
                NativeCommandResult::Complete
            ));
            for (path, original) in paths.iter().zip(originals) {
                assert!(!path.exists());
                let target = destination(root, path, &token);
                let metadata = fs::metadata(&target).unwrap();
                assert_eq!(
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.blocks(),
                        metadata.nlink()
                    ),
                    (original.0, original.1, original.2, 1)
                );
                assert_eq!(fs::read(target).unwrap(), original.3);
            }
            for operation in [
                NativeOperation::Quarantine {
                    key: key.clone(),
                    incarnation: token,
                },
                NativeOperation::Restore {
                    key: key.clone(),
                    incarnation: token,
                },
                NativeOperation::FinishRetirement {
                    key: key.clone(),
                    incarnation: token,
                },
            ] {
                assert_eq!(
                    worker
                        .execute(context.clone(), operation)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        }
    });
    drop(worker);
    owner.join().unwrap();
    File::open(root.join("quarantine"))
        .unwrap()
        .sync_all()
        .unwrap();
    println!(
        "PASS exact original encoded chunk and pack/index quarantine preserves every inode and byte, refuses collisions before pair mutation and revokes old lifecycle tokens"
    );
}

async fn inspect(
    worker: &NativePublicationWorker,
    context: &NativeCommandContext,
    key: &NativeBodyKey,
) -> [u8; 32] {
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
        panic!("encoded inspection must return only original unverified custody")
    };
    drop(body);
    *incarnation.bytes()
}

fn destination(root: &Path, canonical: &Path, token: &[u8; 32]) -> PathBuf {
    root.join("quarantine").join(format!(
        "encoded.{}.{}",
        canonical.file_name().unwrap().to_str().unwrap(),
        token
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}
