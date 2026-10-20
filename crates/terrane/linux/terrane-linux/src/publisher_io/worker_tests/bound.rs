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
        .publish(claim.clone(), File::open(input).unwrap())
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
    assert!(keys.contains(&NativeBodyKey::Sealed { descriptor }));
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

    // Restore the genuine previously published inode, then require actual
    // adoption rather than copying a binding or declaring inventory Ready.
    rename(&saved, &canonical);
    worker
        .execute(context.clone(), NativeOperation::Adopt { claim })
        .await
        .unwrap();
    assert_eq!(
        fs::metadata(&canonical).unwrap().ino(),
        sealed.metadata().unwrap().ino()
    );
    assert_eq!(crate::verity::measure(&sealed).unwrap(), measurement);
    assert_eq!(fs::read(&record).unwrap(), record_bytes);
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
