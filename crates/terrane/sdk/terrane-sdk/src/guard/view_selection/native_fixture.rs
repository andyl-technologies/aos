//! Installs one actual current3 Guard before genuine Legacy or Recorded authoring.

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;
use crate::domain::DomainNamespace;
use crate::guard::{Guard, GuardConfig};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Retains the real metadata validator and canonical local repository factories.
pub(crate) type Native = Repository<
    crate::bucket::FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
    TokioClock,
    TokioLocalFs,
>;

/// Opens a fresh native namespace with an explicit genuine Guard selection.
///
/// # Errors
/// Preserves native backend, retention initialization and registered setup failures.
///
pub(crate) async fn fixture(active: bool) -> Result<Native> {
    let nonce = TokioLocalFs.random_bytes(16).await?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("terrane-active-completion-{suffix}"));
    let administrative = root.with_file_name(format!("terrane-recorded-operator-{suffix}"));
    TokioLocalFs.create_dir_new(&administrative).await?;
    TokioLocalFs
        .set_permissions_and_sync(&administrative, std::fs::Permissions::from_mode(0o700))
        .await?;
    let operator = TokioLocalFs.symlink_metadata(&administrative).await?;
    let configuration = crate::bucket::FileBucketConfig {
        root: root.clone(),
        publication_control: Some(crate::bucket::FileBucketPublicationConfig {
            operator_uid: operator.uid(),
            control: None,
        }),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: terrane_format::chunking::ChunkProfile::cdc_1m([0; 32]),
        locality: terrane_format::refs::Locality::default(),
    };
    let profile = configuration.chunk_profile.clone();
    let store = crate::bucket::FileBucket::open(
        configuration,
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile),
    )
    .await?;
    let keys = vec![terrane_format::auth::IssuerKey {
        issuer: "test".into(),
        key_id: "key".into(),
        public_key: [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ],
        retirement: None,
    }];
    let config = GuardConfig {
        store_name: "local".into(),
        private_domain: "private:test".into(),
        home: terrane_format::refs::Locality::default(),
        initial_acl: vec![("writer".into(), 31)],
        min_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: Box::new(terrane_format::chunking::ChunkProfile::cdc_1m([0; 32])),
        policy_authority: None,
    };
    let guard = if active {
        Guard::new_active(store, TokioClock, keys, config)
    } else {
        Guard::new_active(store, TokioClock, keys, config).with_legacy_authoring()?
    };
    let timing = CommitTiming::new(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(10),
    )?;
    let coordinator = Coordinator::new(guard, timing, TokioLocalFs);
    let control = root.with_file_name(format!("terrane-active-original-{suffix}"));
    TokioLocalFs.create_dir_new(&control).await?;
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await?;
    let owner = TokioLocalFs.symlink_metadata(&root).await?.uid();
    let namespace = DomainNamespace {
        root,
        domain: "public".into(),
    };
    Ok(Repository::initialize_native_retention(coordinator, &namespace, &control, owner).await?)
}

/// Reads the actual selected immutable current Guard snapshot under native exclusion.
///
/// # Errors
/// Preserves unavailable native controls and missing or malformed current snapshots.
///
/// # Panics
/// Panics when the actual selected snapshot is not the installed current3/attribute2 profile.
pub(crate) async fn current_snapshot(repository: &Native) -> Result<Vec<u8>> {
    let holder = crate::bucket::held::SingleHeld::acquire(repository.coordinator().store()).await?;
    let held = holder.destination();
    let observed = held.observe_publication().await?;
    let bytes = held
        .selected_guard_snapshot(&observed)
        .await?
        .ok_or("actual configured current Guard")?;
    let snapshot = terrane_format::gc::publication::evidence::GuardSnapshot::decode(&bytes)?;
    assert_eq!(snapshot.registries.property_revision, 3);
    assert_eq!(snapshot.registries.attribute_revision, 2);
    assert!(snapshot.registries.later_properties.is_empty());
    observed.revalidate().await?;
    Ok(bytes)
}
