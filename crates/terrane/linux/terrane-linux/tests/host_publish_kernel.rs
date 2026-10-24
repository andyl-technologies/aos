//! Requires a real disk-backed ext4 filesystem with the verity feature enabled.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::publisher_io::NativePublisher;
use terrane_linux::verity;
use terrane_sdk::host::publication::{
    FsPublicationState, PublicationClaim, PublicationRecipe, PublicationState, Publisher,
    VerityBinding,
};

#[derive(Default)]
struct State {
    bindings: BTreeMap<Vec<u8>, VerityBinding>,
    fail: bool,
}

#[async_trait::async_trait]
impl PublicationState for State {
    async fn binding(&self, claim: &PublicationClaim) -> io::Result<Option<VerityBinding>> {
        Ok(self.bindings.get(claim.descriptor().digest()).cloned())
    }

    async fn record(
        &mut self,
        claim: &PublicationClaim,
        binding: &VerityBinding,
    ) -> io::Result<()> {
        if self.fail {
            return Err(io::Error::other("injected binding failure"));
        }
        self.bindings
            .insert(claim.descriptor().digest().to_vec(), binding.clone());
        Ok(())
    }
}

fn claim(domain: &str, bytes: &[u8]) -> PublicationClaim {
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    PublicationClaim::new(
        domain.into(),
        PublicationRecipe::Inline {
            chunk: Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap(),
        },
        &ChunkProfile::cdc_1m([0; 32]),
    )
    .unwrap()
}

fn directories(root: &Path, name: &str) -> [PathBuf; 3] {
    let expected =
        terrane_linux::host_quota::NativeProject::inspect(&File::open(root).unwrap()).unwrap();
    assert_eq!(expected.project_id, 64109);
    assert!(expected.inherit);
    let base = root.join(name);
    fs::create_dir(&base).unwrap();
    fs::create_dir(base.join("quarantine")).unwrap();
    let paths = [
        base.join("sealed"),
        base.join("staging"),
        base.join("pending"),
    ];
    for path in &paths {
        fs::create_dir(path).unwrap();
        let actual =
            terrane_linux::host_quota::NativeProject::inspect(&File::open(path).unwrap()).unwrap();
        assert_eq!(actual.project_id, expected.project_id);
        assert_eq!(actual.device, expected.device);
        assert!(actual.inherit);
    }
    fs::set_permissions(&paths[1], fs::Permissions::from_mode(0o700)).unwrap();
    paths
}

fn adapter(
    confinement: &Arc<terrane_linux::quota_confinement::Installed>,
    domain: &str,
    paths: &[PathBuf; 3],
) -> NativePublisher {
    NativePublisher::open(
        Arc::clone(confinement),
        domain.into(),
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .unwrap()
}

fn assert_empty_private_staging(root: &Path) {
    let publishers: Vec<_> = fs::read_dir(root).unwrap().map(Result::unwrap).collect();
    assert_eq!(
        publishers.len(),
        1,
        "staging holds the publisher-ID directory"
    );
    let publisher = &publishers[0];
    assert!(publisher.file_type().unwrap().is_dir());
    assert_eq!(publisher.metadata().unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::read_dir(publisher.path()).unwrap().count(), 0);
}

fn source(root: &Path, bytes: &[u8]) -> File {
    let path = root.join("input");
    fs::write(&path, bytes).unwrap();
    File::open(path).unwrap()
}

/// Runs the non-production genuine-kernel publication sequence fixture.
///
/// # Errors
/// Rejects a receipt belonging to a different process or changed confinement.
///
/// # Panics
/// Panics when actual sealing, durability, adoption or isolation assertions fail.
pub fn run(confinement: Arc<terrane_linux::quota_confinement::Installed>) -> io::Result<()> {
    confinement.check_current()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let root =
            PathBuf::from(std::env::var_os("TERRANE_PUBLISH_VM_ROOT").expect("VM fixture root"))
                .join("kernel-sequence");
        let paths = directories(&root, "public");
        let claim = claim("public", b"immutable content");
        let state_path = root.join("publication-state");
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut publisher = Publisher::new(
            adapter(&confinement, "public", &paths),
            FsPublicationState::new(terrane_sdk::store::TokioLocalFs, state_path.clone()),
        );
        let published = publisher
            .publish(&claim, source(&root, b"immutable content"))
            .await
            .unwrap();
        let measured = published.binding().clone();
        let mut handle = published.into_handle();
        let original = handle.metadata().unwrap();
        assert_eq!(verity::measure(&handle).unwrap(), measured);
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"immutable content");

        let hex: String = claim
            .descriptor()
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let canonical = paths[0].join(&hex[..2]).join(&hex);
        // Owner-controlled mode bits do not defeat the genuine kernel seal.
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(OpenOptions::new().write(true).open(&canonical).is_err());
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o400)).unwrap();

        let second = publisher
            .publish(&claim, source(&root, b"immutable content"))
            .await
            .unwrap()
            .into_handle();
        assert_eq!(second.metadata().unwrap().ino(), original.ino());
        assert_empty_private_staging(&paths[1]);

        let (native, _) = publisher.into_parts();
        drop(native);
        // Simulate total embedded-state loss while preserving the sealed inode.
        fs::remove_dir_all(&state_path).unwrap();
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut publisher = Publisher::new(
            adapter(&confinement, "public", &paths),
            FsPublicationState::new(terrane_sdk::store::TokioLocalFs, state_path.clone()),
        );
        let adopted = publisher.adopt(&claim).await.unwrap();
        assert_eq!(adopted.binding(), &measured);
        assert_eq!(
            adopted.into_handle().metadata().unwrap().ino(),
            original.ino()
        );

        let (mut native, state) = publisher.into_parts();
        native.retire(&claim).unwrap();
        assert!(!canonical.exists());
        native.restore(&claim).unwrap();
        let mut publisher = Publisher::new(native, state);
        assert_eq!(
            publisher
                .adopt(&claim)
                .await
                .unwrap()
                .into_handle()
                .metadata()
                .unwrap()
                .ino(),
            original.ino()
        );

        let (mut native, _) = publisher.into_parts();
        let quarantine = File::open(paths[0].parent().unwrap().join("quarantine")).unwrap();
        let unrelated = File::open(root.join("input")).unwrap();
        assert!(
            native
                .quarantine_rejected(&claim, &unrelated, &quarantine)
                .is_err()
        );
        assert_eq!(fs::metadata(&canonical).unwrap().ino(), original.ino());

        let mut state = State::default();
        state.bindings.insert(
            claim.descriptor().digest().to_vec(),
            VerityBinding {
                algorithm: 1,
                digest: vec![0; 32],
            },
        );
        let mut publisher = Publisher::new(native, state);
        assert!(publisher.adopt(&claim).await.is_err());
        assert!(!canonical.exists());
        assert!(
            paths[0]
                .parent()
                .unwrap()
                .join("quarantine")
                .join(&hex)
                .exists()
        );
        drop(publisher);

        let other_paths = directories(&root, "private");
        let other_claim = self::claim("private:other", b"immutable content");
        let mut other = Publisher::new(
            adapter(&confinement, "private:other", &other_paths),
            State::default(),
        );
        let private = other
            .publish(&other_claim, source(&root, b"immutable content"))
            .await
            .unwrap()
            .into_handle();
        assert_ne!(private.metadata().unwrap().ino(), original.ino());
        assert!(other.adopt(&claim).await.is_err());

        let failure_paths = directories(&root, "failure");
        let mut failure = Publisher::new(
            adapter(&confinement, "public", &failure_paths),
            State {
                fail: true,
                ..State::default()
            },
        );
        assert!(
            failure
                .publish(&claim, source(&root, b"immutable content"))
                .await
                .is_err()
        );
        assert!(!failure_paths[0].join(&hex[..2]).join(&hex).exists());
        assert_empty_private_staging(&failure_paths[1]);

        let unsealed_paths = directories(&root, "unsealed");
        fs::create_dir(unsealed_paths[0].join(&hex[..2])).unwrap();
        let unsealed = unsealed_paths[0].join(&hex[..2]).join(&hex);
        fs::write(&unsealed, b"immutable content").unwrap();
        fs::set_permissions(&unsealed, fs::Permissions::from_mode(0o400)).unwrap();
        let mut unsealed_publisher = Publisher::new(
            adapter(&confinement, "public", &unsealed_paths),
            State::default(),
        );
        let rejected_inode = fs::metadata(&unsealed).unwrap().ino();
        assert!(
            unsealed_publisher
                .publish(&claim, source(&root, b"immutable content"))
                .await
                .is_err()
        );
        assert!(!unsealed.exists());
        let quarantined = unsealed_paths[0]
            .parent()
            .unwrap()
            .join("quarantine")
            .join(&hex);
        assert_eq!(fs::metadata(&quarantined).unwrap().ino(), rejected_inode);
        assert_eq!(fs::read(&quarantined).unwrap(), b"immutable content");
        let retried = unsealed_publisher
            .publish(&claim, source(&root, b"immutable content"))
            .await
            .unwrap();
        assert_ne!(
            retried.into_handle().metadata().unwrap().ino(),
            rejected_inode
        );

        let wrong_size = Descriptor::from_wire(
            &TERRANE_V1,
            claim.descriptor().algorithm(),
            claim.descriptor().domain(),
            claim.descriptor().digest(),
            claim.plaintext_size() + 1,
        )
        .unwrap();
        let wrong_claim = PublicationClaim::new(
            "public".into(),
            PublicationRecipe::Inline { chunk: wrong_size },
            &ChunkProfile::cdc_1m([0; 32]),
        )
        .unwrap();
        assert!(unsealed_publisher.adopt(&wrong_claim).await.is_err());
        assert!(
            unsealed.exists(),
            "bad request metadata must not quarantine a valid canonical inode"
        );
    });
    Ok(())
}
