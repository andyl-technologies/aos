//! Establishes genuine selected Guard and protected registration for native lease tests.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::{FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{GuardConfig, RegistrationView};
use crate::store::native_publication_effects::collection::test_fs::{TestClock, TestFs};
use crate::store::{Clock, MetaUpload, NativeEffectClock};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
#[cfg(not(feature = "send"))]
use std::rc::Rc as Arc;
#[cfg(feature = "send")]
use std::sync::Arc;
use terrane_core::bucket::BucketKey;
use terrane_core::chunking::ChunkProfile;
use terrane_core::gc::publication::PublicationState;
use terrane_core::refs::Locality;

/// Refuses unrelated content upload in the lease-only fixture.
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, _: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        unreachable!("Collector lease qualification uploads no content")
    }
}

/// Names the real native bucket used by both runtime lanes.
pub(super) type Bucket = FileBucket<TestFs, NativeEffectClock, Validator>;
/// Names the actual Guard with its genuinely retained injected clock.
pub(super) type ConcreteGuard = Guard<Bucket, NativeEffectClock>;

/// Retains trusted setup, the actual namespace and its protected registration.
pub(super) struct Fixture {
    pub(super) parent: PathBuf,
    pub(super) config: FileBucketConfig,
    pub(super) guard: Arc<ConcreteGuard>,
    pub(super) authority: OriginalAuthority,
    pub(super) clock: TestClock,
    pub(super) fs: TestFs,
}

impl Fixture {
    /// Initializes real protected namespace and selected Guard state.
    pub(super) async fn new() -> Self {
        let fs = TestFs::default();
        let entropy = fs.random_bytes(16).await.unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-gc-lease-{suffix}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let owner = std::fs::symlink_metadata(&parent).unwrap().uid();
        let config = FileBucketConfig {
            root: parent.join("bucket"),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: Some(parent.join("publication")),
            }),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([0; 32]),
            locality: Locality::default(),
        };
        let clock = TestClock::new(100);
        let bucket = FileBucket::open(
            config.clone(),
            fs.clone(),
            clock.retain_native_clock().unwrap(),
            Validator,
        )
        .await
        .unwrap();
        let guard = Arc::new(Guard::new(
            bucket,
            clock.retain_native_clock().unwrap(),
            Vec::new(),
            configuration(),
        ));
        let control = parent.join("original");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&control)
            .unwrap();
        fs.write_new(&control.join("retention.lock"), b"")
            .await
            .unwrap();
        fs.set_permissions_and_sync(
            &control.join("retention.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .unwrap();
        let root = std::fs::symlink_metadata(&config.root).unwrap();
        let lock = std::fs::symlink_metadata(
            config
                .root
                .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name()),
        )
        .unwrap();
        let view = RegistrationView {
            id: &[7; 32],
            root: &config.root,
            domain: "public",
            root_identity: (root.dev(), root.ino()),
            coordination_identity: (lock.dev(), lock.ino()),
            control: &control,
        };
        let bytes = registration(&view);
        fs.write_new(&control.join("registration.cbor"), &bytes)
            .await
            .unwrap();
        fs.set_permissions_and_sync(
            &control.join("registration.cbor"),
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .unwrap();
        fs.sync_directory(&control).await.unwrap();
        let authority = guard
            .bind_original_authority(
                &DomainNamespace {
                    root: config.root.clone(),
                    domain: "public".into(),
                },
                &control,
                view,
            )
            .await
            .unwrap();
        let single = SingleHeld::acquire(guard.store()).await.unwrap();
        let held = single.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        crate::selected_bridge::native_guard::install_initial_guard(
            Arc::clone(&guard),
            &authority,
            &held,
            &observed,
        )
        .await
        .unwrap();
        drop(observed);
        drop(single);
        fs.reset();
        Self {
            parent,
            config,
            guard,
            authority,
            clock,
            fs,
        }
    }

    /// Reopens the actual existing namespace through the production path.
    pub(super) async fn reopen(&self) -> Arc<ConcreteGuard> {
        let bucket = FileBucket::open(
            self.config.clone(),
            self.fs.clone(),
            self.clock.retain_native_clock().unwrap(),
            Validator,
        )
        .await
        .unwrap();
        Arc::new(Guard::new(
            bucket,
            self.clock.retain_native_clock().unwrap(),
            Vec::new(),
            configuration(),
        ))
    }

    #[cfg(feature = "tokio")]
    /// Reads the fresh complete selected state under real exclusion.
    pub(super) async fn selected(&self) -> (PublicationState, Option<GcLease>) {
        selection(self.guard.store()).await
    }

    /// Borrows the explicitly configured trusted maintenance authority.
    pub(super) fn collector(
        &self,
    ) -> Collector<'_, TestFs, NativeEffectClock, Validator, NativeEffectClock> {
        Collector::new(self.guard.as_ref(), &self.authority)
    }

    #[cfg(feature = "tokio")]
    /// Returns the protected selected commit name in this fixture.
    pub(super) fn slot(&self, revision: u64) -> PathBuf {
        self.parent
            .join("publication")
            .join(format!("publication/commits/{revision}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.parent).unwrap();
    }
}

/// Supplies ordinary trusted Guard configuration without actor token grants.
pub(super) fn configuration() -> GuardConfig {
    GuardConfig {
        store_name: "local".into(),
        private_domain: "private:test".into(),
        home: Locality::default(),
        initial_acl: Vec::new(),
        min_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
        policy_authority: None,
    }
}

// Writes ordinary trusted setup data; bind_original_authority independently
// checks these bytes, physical identities, protected paths and real exclusions.
fn registration(view: &RegistrationView<'_>) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    use terrane_core::cbor;
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 9);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, view.id);
    cbor::write_bytes(&mut bytes, view.root.as_os_str().as_bytes());
    cbor::write_text(&mut bytes, view.domain);
    for number in [
        view.root_identity.0,
        view.root_identity.1,
        view.coordination_identity.0,
        view.coordination_identity.1,
    ] {
        cbor::write_uint(&mut bytes, number);
    }
    cbor::write_bytes(&mut bytes, view.control.as_os_str().as_bytes());
    bytes
}

/// Resolves the actual whole selected lease under one real held namespace.
pub(super) async fn selection(bucket: &Bucket) -> (PublicationState, Option<GcLease>) {
    let single = SingleHeld::acquire(bucket).await.unwrap();
    let held = single.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let lease = observed
        .logical()
        .get("gc/lease")
        .unwrap()
        .as_deref()
        .map(GcLease::decode)
        .transpose()
        .unwrap();
    (observed.state().clone(), lease)
}
