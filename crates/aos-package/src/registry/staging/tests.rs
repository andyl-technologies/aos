//! Tests exact destination snapshots, publication retries, and authoring isolation.

use super::*;
use aos_cache::backend::AuthOptions;
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    author: PathBuf,
    workspace: PathBuf,
    origin: PathBuf,
    store: LocalStageStore,
}

#[test]
fn stage_lock_releases_ownership_despite_a_retained_descriptor() {
    let temporary = TempDir::new().unwrap();
    git2::Repository::init(temporary.path()).unwrap();
    let store = LocalStageStore::open(temporary.path()).unwrap();
    let lock = store.lock().unwrap();
    let inherited = lock.file.try_clone().unwrap();

    assert!(store.lock().is_err());
    drop(lock);

    let next = store.lock().unwrap();
    assert!(store.lock().is_err());
    drop(next);
    drop(inherited);
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap();
        let author = temporary.path().join("author");
        let workspace = temporary.path().join("workspace");
        let origin = temporary.path().join("origin");
        let mut options = git2::RepositoryInitOptions::new();
        options
            .object_format(git2::ObjectFormat::Sha256)
            .initial_head("refs/heads/dplecki/test");
        let repository = git2::Repository::init_opts(&author, &options).unwrap();
        fs::write(
            author.join("registry.toml"),
            "[registry]\nname = \"example\"\n",
        )
        .unwrap();
        let mut index = repository.index().unwrap();
        index.add_path(Path::new("registry.toml")).unwrap();
        index.write().unwrap();
        let tree = repository.find_tree(index.write_tree().unwrap()).unwrap();
        let signature = git2::Signature::new(
            "Maintainer",
            "maintainer@example.com",
            &git2::Time::new(1_700_000_000, 0),
        )
        .unwrap();
        let commit = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "initial catalog",
                &tree,
                &[],
            )
            .unwrap();
        repository
            .reference("refs/heads/public-custom", commit, false, "bootstrap")
            .unwrap();
        drop(tree);
        drop(index);
        drop(repository);
        let prepared = git2::build::RepoBuilder::new()
            .clone_local(git2::build::CloneLocal::NoLinks)
            .clone(author.to_str().unwrap(), &workspace)
            .unwrap();
        let key = temporary.path().join("signing-key");
        fs::write(
            &key,
            crate::sshkey::Ed25519Keypair::from_seed([47; 32]).to_openssh_private_key("example"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let payload = aos_registry_surface::tag::render_tag_payload(
            "1.0.0",
            &commit.to_string(),
            "commit",
            "candidate",
            1_700_000_000,
        )
        .unwrap();
        let armor =
            crate::security::sign_payload_signature(&key, "git", payload.as_bytes()).unwrap();
        let tag = prepared
            .odb()
            .unwrap()
            .write(
                git2::ObjectType::Tag,
                format!("{payload}{armor}\n").as_bytes(),
            )
            .unwrap();
        prepared
            .reference("refs/tags/1.0.0", tag, false, "candidate")
            .unwrap();
        crate::registry::objectstore::ensure_loose_completeness(&workspace).unwrap();
        crate::registry::objectstore::refresh_server_info(&workspace).unwrap();
        fs::create_dir_all(origin.join("info")).unwrap();
        fs::write(origin.join("HEAD"), "ref: refs/heads/public-custom\n").unwrap();
        fs::write(
            origin.join("info/refs"),
            format!("{commit}\trefs/heads/public-custom\n{commit}\trefs/heads/preserved\n"),
        )
        .unwrap();
        fs::create_dir_all(origin.join("channels/public-custom")).unwrap();
        fs::write(
            origin.join("channels/public-custom/00"),
            b"unchanged channel frontier",
        )
        .unwrap();
        let store = LocalStageStore::open(&author).unwrap();
        Self {
            _temporary: temporary,
            author,
            workspace,
            origin,
            store,
        }
    }

    fn destinations(&self) -> Vec<String> {
        vec![self.origin.to_str().unwrap().into()]
    }

    async fn capture(&self) -> StageRecord {
        self.store
            .capture(
                "candidate",
                "example",
                "1.0.0",
                "dplecki/test",
                &self.workspace,
                None,
                None,
                &self.destinations(),
                &AuthOptions::default(),
                None,
                &[],
            )
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn capture_preserves_destination_default_refs_and_channel_frontiers() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.origin.join("HEAD")).unwrap();
    let record = fixture.capture().await;

    let head = record
        .revision
        .publication
        .iter()
        .find(|pointer| pointer.path == "HEAD")
        .unwrap();
    assert_eq!(head.bytes, before);
    let refs = record
        .revision
        .publication
        .iter()
        .find(|pointer| pointer.path == "info/refs")
        .unwrap();
    let refs = std::str::from_utf8(&refs.bytes).unwrap();
    assert!(refs.contains("refs/heads/preserved"));
    assert!(refs.contains("refs/heads/public-custom"));
    assert!(refs.contains("refs/tags/1.0.0"));
    assert!(!refs.contains("refs/heads/dplecki/test"));
    assert!(
        !record
            .revision
            .publication
            .iter()
            .any(|pointer| pointer.path.starts_with("channels/"))
    );
    assert_eq!(fs::read(fixture.origin.join("HEAD")).unwrap(), before);
    assert_eq!(
        fs::read(fixture.origin.join("channels/public-custom/00")).unwrap(),
        b"unchanged channel frontier"
    );
}

#[tokio::test]
async fn empty_destinations_never_create_ready_or_released_records() {
    let fixture = Fixture::new();
    let record = fixture.capture().await;

    assert!(
        fixture
            .store
            .upload("candidate", 1, &[], &AuthOptions::default())
            .await
            .is_err()
    );
    assert!(
        fixture
            .store
            .publish("candidate", 1, &[], &AuthOptions::default())
            .await
            .is_err()
    );
    assert_eq!(fixture.store.show("candidate").unwrap(), record);
}

#[tokio::test]
async fn missing_predecessor_rejects_before_freezing_or_writing_pointers() {
    let fixture = Fixture::new();
    fixture.capture().await;
    fixture
        .store
        .upload(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    let listing = fs::read(fixture.origin.join("info/refs")).unwrap();
    fs::remove_file(fixture.origin.join("HEAD")).unwrap();

    let error = fixture
        .store
        .publish(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("disappeared"));
    assert_eq!(
        fixture.store.show("candidate").unwrap().state,
        StageState::Ready
    );
    assert_eq!(fs::read(fixture.origin.join("info/refs")).unwrap(), listing);
    assert!(!fixture.origin.join("HEAD").exists());
}

#[tokio::test]
async fn finalization_and_retry_import_exact_tag_without_moving_author_workspace() {
    let fixture = Fixture::new();
    let before_head = fs::read(fixture.author.join(".git/HEAD")).unwrap();
    let before_index = fs::read(fixture.author.join(".git/index")).unwrap();
    let before_tree = fs::read(fixture.author.join("registry.toml")).unwrap();
    fixture.capture().await;
    let file_destination = vec![
        url::Url::from_directory_path(&fixture.origin)
            .unwrap()
            .to_string(),
    ];
    fixture
        .store
        .upload("candidate", 1, &file_destination, &AuthOptions::default())
        .await
        .unwrap();
    let released = fixture
        .store
        .publish(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    let repeated = fixture
        .store
        .publish("candidate", 1, &file_destination, &AuthOptions::default())
        .await
        .unwrap();

    assert_eq!(released, repeated);
    assert_eq!(released.state, StageState::Released);
    let author = git2::Repository::open(&fixture.author).unwrap();
    let workspace = git2::Repository::open(&fixture.workspace).unwrap();
    assert_eq!(
        author.find_reference("refs/tags/1.0.0").unwrap().target(),
        workspace
            .find_reference("refs/tags/1.0.0")
            .unwrap()
            .target()
    );
    assert_eq!(
        fs::read(fixture.author.join(".git/HEAD")).unwrap(),
        before_head
    );
    assert_eq!(
        fs::read(fixture.author.join(".git/index")).unwrap(),
        before_index
    );
    assert_eq!(
        fs::read(fixture.author.join("registry.toml")).unwrap(),
        before_tree
    );
    assert_eq!(
        fs::read(fixture.origin.join("channels/public-custom/00")).unwrap(),
        b"unchanged channel frontier"
    );
}

#[tokio::test]
async fn absent_bootstrap_and_destination_drift_fail_closed() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.origin.join("HEAD")).unwrap();
    assert!(
        fixture
            .store
            .capture(
                "candidate",
                "example",
                "1.0.0",
                "dplecki/test",
                &fixture.workspace,
                None,
                None,
                &fixture.destinations(),
                &AuthOptions::default(),
                None,
                &[]
            )
            .await
            .is_err()
    );
    assert!(fixture.store.find("candidate").unwrap().is_none());
    fs::write(
        fixture.origin.join("HEAD"),
        "ref: refs/heads/public-custom\n",
    )
    .unwrap();
    fixture.capture().await;
    let other = fixture._temporary.path().join("other");
    fs::create_dir(&other).unwrap();

    assert!(
        fixture
            .store
            .upload(
                "candidate",
                1,
                &[other.to_str().unwrap().into()],
                &AuthOptions::default(),
            )
            .await
            .is_err()
    );
    assert_eq!(
        fixture.store.show("candidate").unwrap().state,
        StageState::Draft
    );
}

#[test]
fn read_only_open_leaves_absent_candidate_storage_absent() {
    let fixture = Fixture::new();
    fs::remove_dir_all(&fixture.store.root).unwrap();

    let store = LocalStageStore::open_read_only(&fixture.author).unwrap();

    assert!(store.list().unwrap().is_empty());
    assert!(!store.root.exists());
}

#[tokio::test]
async fn frozen_partial_publication_resumes_the_exact_revision() {
    let fixture = Fixture::new();
    let captured = fixture.capture().await;
    fixture
        .store
        .upload(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    // Simulate interruption after the publisher froze this exact ready revision.
    let mut frozen = fixture.store.show("candidate").unwrap();
    frozen.state = StageState::Releasing;
    fixture.store.write_record(&frozen).unwrap();
    let listing = captured
        .revision
        .publication
        .iter()
        .find(|pointer| pointer.path == "info/refs")
        .unwrap();
    fs::write(fixture.origin.join("info/refs"), &listing.bytes).unwrap();

    let rejected = fixture
        .store
        .capture(
            "candidate",
            "example",
            "1.0.0",
            "dplecki/test",
            &fixture.workspace,
            Some(1),
            None,
            &fixture.destinations(),
            &AuthOptions::default(),
            None,
            &[],
        )
        .await;
    assert!(rejected.is_err());
    assert_eq!(
        fixture.store.show("candidate").unwrap().state,
        StageState::Releasing
    );

    let released = fixture
        .store
        .publish(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(released.state, StageState::Released);
    assert_eq!(released.revision, captured.revision);
}

#[tokio::test]
async fn changed_advertisement_conflicts_before_any_pointer_effect() {
    let fixture = Fixture::new();
    fixture.capture().await;
    fixture
        .store
        .upload(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    let changed = format!(
        "{}{}\trefs/heads/concurrent\n",
        fs::read_to_string(fixture.origin.join("info/refs")).unwrap(),
        "ab".repeat(32)
    );
    fs::write(fixture.origin.join("info/refs"), &changed).unwrap();
    let head_before = fs::read(fixture.origin.join("HEAD")).unwrap();

    assert!(
        fixture
            .store
            .publish(
                "candidate",
                1,
                &fixture.destinations(),
                &AuthOptions::default()
            )
            .await
            .is_err()
    );

    assert_eq!(
        fixture.store.show("candidate").unwrap().state,
        StageState::Ready
    );
    assert_eq!(
        fs::read_to_string(fixture.origin.join("info/refs")).unwrap(),
        changed
    );
    assert_eq!(fs::read(fixture.origin.join("HEAD")).unwrap(), head_before);
}

#[tokio::test]
async fn lightweight_candidate_tag_cannot_be_captured_as_a_release() {
    let fixture = Fixture::new();
    let repository = git2::Repository::open(&fixture.workspace).unwrap();
    let commit = repository.head().unwrap().peel_to_commit().unwrap().id();
    repository
        .reference("refs/tags/1.0.0", commit, true, "invalid candidate")
        .unwrap();
    crate::registry::objectstore::refresh_server_info(&fixture.workspace).unwrap();

    assert!(
        fixture
            .store
            .capture(
                "candidate",
                "example",
                "1.0.0",
                "dplecki/test",
                &fixture.workspace,
                None,
                None,
                &fixture.destinations(),
                &AuthOptions::default(),
                None,
                &[]
            )
            .await
            .is_err()
    );
    assert!(fixture.store.find("candidate").unwrap().is_none());
}

#[tokio::test]
async fn completed_release_retry_preserves_a_newer_publication() {
    let fixture = Fixture::new();
    fixture.capture().await;
    fixture
        .store
        .upload(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();
    let first = fixture
        .store
        .publish(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();

    let repository = git2::Repository::open(&fixture.workspace).unwrap();
    let commit = repository.head().unwrap().peel_to_commit().unwrap().id();
    let payload = aos_registry_surface::tag::render_tag_payload(
        "1.0.1",
        &commit.to_string(),
        "commit",
        "next candidate",
        1_700_000_001,
    )
    .unwrap();
    let key = fixture._temporary.path().join("signing-key");
    let armor = crate::security::sign_payload_signature(&key, "git", payload.as_bytes()).unwrap();
    let tag = repository
        .odb()
        .unwrap()
        .write(
            git2::ObjectType::Tag,
            format!("{payload}{armor}\n").as_bytes(),
        )
        .unwrap();
    repository
        .reference("refs/tags/1.0.1", tag, false, "next candidate")
        .unwrap();
    crate::registry::objectstore::refresh_server_info(&fixture.workspace).unwrap();
    fixture
        .store
        .capture(
            "next",
            "example",
            "1.0.1",
            "dplecki/test",
            &fixture.workspace,
            None,
            None,
            &fixture.destinations(),
            &AuthOptions::default(),
            None,
            &[],
        )
        .await
        .unwrap();
    fixture
        .store
        .upload("next", 1, &fixture.destinations(), &AuthOptions::default())
        .await
        .unwrap();
    fixture
        .store
        .publish("next", 1, &fixture.destinations(), &AuthOptions::default())
        .await
        .unwrap();
    let newer_listing = fs::read(fixture.origin.join("info/refs")).unwrap();
    assert!(
        std::str::from_utf8(&newer_listing)
            .unwrap()
            .contains("refs/tags/1.0.1")
    );

    let repeated = fixture
        .store
        .publish(
            "candidate",
            1,
            &fixture.destinations(),
            &AuthOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(repeated, first);
    assert_eq!(
        fs::read(fixture.origin.join("info/refs")).unwrap(),
        newer_listing
    );
    assert_eq!(
        fixture.store.show("next").unwrap().state,
        StageState::Released
    );
}
