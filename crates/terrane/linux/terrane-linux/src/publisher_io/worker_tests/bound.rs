//! Checks bound writable candidates through actual inventory, quarantine and adoption.

use crate::publisher_io::{
    NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation,
    NativePublicationWorker,
};
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    host::publication::{AdoptionFailure, FsPublicationState, PublicationClaim, PublicationRecipe},
    store::TokioLocalFs,
};

/// Exercises real replacement, names-only inventory and native seal refusal.
///
/// # Panics
/// Panics if kernel custody, unchanged records, original-inode quarantine or
/// independent adoption of the genuine restored sealed inode fails.
pub(super) async fn exercise(
    worker: &NativePublicationWorker,
    context: &NativeCommandContext,
    root: &Path,
) {
    let plaintext = b"bound-unsealed";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, plaintext).unwrap();
    let claim = PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Inline {
            chunk: descriptor.clone(),
        },
        &ChunkProfile::cdc_1m([0; 32]),
    )
    .unwrap();
    let input = root.join("bound-unsealed-input");
    fs::write(&input, plaintext).unwrap();
    worker
        .execute(context.clone(), NativeOperation::Resume)
        .await
        .unwrap();
    let sealed = worker
        .publish(claim.clone(), File::open(&input).unwrap())
        .await
        .unwrap()
        .into_handle();
    worker
        .execute(context.clone(), NativeOperation::Drain)
        .await
        .unwrap();

    let digest: String = descriptor
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let canonical = root.join("sealed").join(&digest[..2]).join(&digest);
    let saved = root.join("replaced-bound-sealed");
    let state = FsPublicationState::new(TokioLocalFs, root.join("state/publication"));
    let record = state.binding_record_path(&claim);
    let record_inode = fs::metadata(&record).unwrap().ino();
    let record_bytes = fs::read(&record).unwrap();
    let measurement = crate::verity::measure(&sealed).unwrap();
    rename(&canonical, &saved);
    fs::write(&canonical, plaintext).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o600)).unwrap();
    let unsealed = File::open(&canonical).unwrap();
    unsealed.sync_all().unwrap();
    File::open(canonical.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    let inode = unsealed.metadata().unwrap();
    assert_ne!(inode.ino(), sealed.metadata().unwrap().ino());
    assert_eq!(
        crate::verity::measure(&unsealed)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENODATA)
    );

    let result = worker
        .execute(context.clone(), NativeOperation::Inventory { cursor: None })
        .await
        .unwrap();
    let NativeCommandResult::Inventory { keys, next_cursor } = result else {
        panic!("unsealed inventory cannot grant a body or binding")
    };
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&NativeBodyKey::Sealed {
        descriptor: descriptor.clone(),
    }));
    assert!(next_cursor.is_none());
    assert_eq!(fs::metadata(&canonical).unwrap().ino(), inode.ino());
    assert_eq!(fs::metadata(&record).unwrap().ino(), record_inode);
    assert_eq!(fs::read(&record).unwrap(), record_bytes);

    let error = worker
        .execute(
            context.clone(),
            NativeOperation::Adopt {
                claim: claim.clone(),
            },
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.get_ref().and_then(|cause| cause.downcast_ref::<AdoptionFailure>()),
        Some(AdoptionFailure::KernelSeal(cause)) if cause.raw_os_error() == Some(libc::ENODATA)
    ));
    assert!(!canonical.exists());
    let quarantine = root.join("quarantine").join(&digest);
    let actual = fs::metadata(&quarantine).unwrap();
    assert_eq!((actual.dev(), actual.ino()), (inode.dev(), inode.ino()));
    assert_eq!(fs::read(&quarantine).unwrap(), plaintext);
    assert_eq!(fs::metadata(&record).unwrap().ino(), record_inode);
    assert_eq!(fs::read(&record).unwrap(), record_bytes);

    let observation = worker
        .execute(
            context.clone(),
            NativeOperation::InspectQuarantine {
                incarnation: None,
                key: NativeBodyKey::Sealed {
                    descriptor: descriptor.clone(),
                },
            },
        )
        .await
        .unwrap();
    let NativeCommandResult::Quarantined { body } = observation else {
        panic!("quarantine inspection cannot grant a publication or lifecycle token")
    };
    let file = body.into_handle();
    let observed = file.metadata().unwrap();
    assert_eq!((observed.dev(), observed.ino()), (inode.dev(), inode.ino()));
    assert_eq!(observed.mode() & 0o7777, 0o600);
    assert!(!rustix::fs::fcntl_getfl(&file).unwrap().intersects(
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH
    ));
    assert_eq!(
        crate::host_quota::NativeProject::inspect(&file)
            .unwrap()
            .project_id,
        crate::host_quota::NativeProject::inspect(&unsealed)
            .unwrap()
            .project_id
    );
    assert_eq!(
        crate::verity::measure(&file).unwrap_err().raw_os_error(),
        Some(libc::ENODATA)
    );
    assert_eq!(fs::metadata(&quarantine).unwrap().ino(), inode.ino());
    assert!(!canonical.exists());
    assert_eq!(fs::read(&record).unwrap(), record_bytes);
    println!(
        "PASS actual original unsealed quarantine inode inspected read-only without seal or lifecycle authority"
    );

    // Restore the genuine previously published inode, then require actual
    // adoption rather than copying a binding or declaring inventory Ready.
    rename(&saved, &canonical);
    let adopted = worker
        .execute(
            context.clone(),
            NativeOperation::Adopt {
                claim: claim.clone(),
            },
        )
        .await
        .unwrap();
    let NativeCommandResult::Published { incarnation, .. } = adopted else {
        panic!("actual adoption must retain the original canonical incarnation")
    };
    assert_eq!(
        fs::metadata(&canonical).unwrap().ino(),
        sealed.metadata().unwrap().ino()
    );
    assert_eq!(crate::verity::measure(&sealed).unwrap(), measurement);
    assert_eq!(fs::read(&record).unwrap(), record_bytes);

    let key = NativeBodyKey::Sealed {
        descriptor: descriptor.clone(),
    };
    let mut token = *incarnation.bytes();
    let mut original = sealed.metadata().unwrap().ino();
    let mut retained = Vec::new();
    for round in 0..2 {
        let tagged = root
            .join("quarantine")
            .join(crate::publisher_io::quarantine_name(
                &descriptor,
                Some(&token),
            ));
        if round == 0 {
            fs::write(&tagged, b"earlier quarantine entry").unwrap();
            let existing = fs::metadata(&tagged).unwrap().ino();
            let error = worker
                .execute(
                    context.clone(),
                    NativeOperation::Quarantine {
                        key: key.clone(),
                        incarnation: token,
                    },
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            assert_eq!(fs::metadata(&tagged).unwrap().ino(), existing);
            assert_eq!(fs::read(&tagged).unwrap(), b"earlier quarantine entry");
            assert_eq!(fs::metadata(&canonical).unwrap().ino(), original);
            fs::remove_file(&tagged).unwrap();
            File::open(root.join("quarantine"))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        let mut wrong = token;
        wrong[0] ^= 1;
        assert_eq!(
            worker
                .execute(
                    context.clone(),
                    NativeOperation::Quarantine {
                        key: key.clone(),
                        incarnation: wrong
                    }
                )
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::metadata(&canonical).unwrap().ino(), original);
        assert!(matches!(
            worker
                .execute(
                    context.clone(),
                    NativeOperation::Quarantine {
                        key: key.clone(),
                        incarnation: token
                    }
                )
                .await
                .unwrap(),
            NativeCommandResult::Complete
        ));
        assert!(!canonical.exists());
        assert_eq!(fs::metadata(&tagged).unwrap().ino(), original);
        assert_eq!(fs::metadata(&quarantine).unwrap().ino(), inode.ino());

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
        let inspected = worker
            .execute(
                context.clone(),
                NativeOperation::InspectQuarantine {
                    key: key.clone(),
                    incarnation: Some(token),
                },
            )
            .await
            .unwrap();
        let NativeCommandResult::Quarantined { body } = inspected else {
            panic!("tagged quarantine cannot return backing or lifecycle authority")
        };
        let opaque = body.into_handle();
        assert_eq!(opaque.metadata().unwrap().ino(), original);
        assert_eq!(opaque.metadata().unwrap().mode() & 0o7777, 0o400);
        retained.push((tagged, original));

        if round == 0 {
            worker
                .execute(context.clone(), NativeOperation::Resume)
                .await
                .unwrap();
            let replacement = worker
                .execute(
                    context.clone(),
                    NativeOperation::Publish {
                        claim: claim.clone(),
                        source: File::open(&input).unwrap(),
                    },
                )
                .await
                .unwrap();
            let NativeCommandResult::Published {
                object,
                incarnation,
            } = replacement
            else {
                panic!("replacement must be independently published and sealed")
            };
            let replacement = object.into_handle();
            original = replacement.metadata().unwrap().ino();
            token = *incarnation.bytes();
            assert_ne!(original, sealed.metadata().unwrap().ino());
            assert_eq!(crate::verity::measure(&replacement).unwrap(), measurement);
        }
    }
    assert_ne!(retained[0].0, retained[1].0);
    for (path, original) in retained {
        assert_eq!(fs::metadata(path).unwrap().ino(), original);
    }
    assert_eq!(fs::read(&record).unwrap(), record_bytes);
    println!(
        "PASS exact retained sealed incarnations quarantined without replacement; repeated hashes preserved and old lifecycle tokens revoked"
    );
}

fn rename(source: &Path, target: &Path) {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .unwrap();
    for path in [source.parent().unwrap(), target.parent().unwrap()] {
        File::open(path).unwrap().sync_all().unwrap();
    }
}
