//! End-to-end release staging, publication, and command ownership contracts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, ensure};
use aos_registry_client::registry::{keys, state};
use aos_registry_authoring::registry::{staging::LocalStageStore};
use aos_registry_client::sshkey::Ed25519Keypair;
use aos_release_format::RELEASE_JOURNAL_ENTRY;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::state::{JournalEntry, ReleaseState};
use serde_json::Value;
use tempfile::TempDir;

const REGISTRY: &str = "staging-fixture";
const VERSION: &str = "1.0.0";
const STAGE: &str = "candidate-one";

struct Fixture {
    temporary: TempDir,
    home: PathBuf,
    registry: PathBuf,
    origin: PathBuf,
    key: PathBuf,
    trust_key: String,
}

struct Consumer {
    home: PathBuf,
    config: PathBuf,
}

impl Consumer {
    fn new(fixture: &Fixture) -> Result<Self> {
        let home = fixture.temporary.path().join("consumer");
        fs::create_dir_all(&home)?;
        let url = format!("file://{}", fixture.origin.display());
        let added = isolated_command(env!("CARGO_BIN_EXE_apm"), &home)
            .args([
                "registry",
                "add",
                &url,
                "--name",
                REGISTRY,
                "--trust-key",
                &fixture.trust_key,
            ])
            .output()?;
        require_success(&added, &["apm", "registry", "add"])?;
        let config = home
            .join(".config/apm/registries.d")
            .join(format!("{REGISTRY}.toml"));
        let consumer = Self { home, config };
        consumer.update()?;
        Ok(consumer)
    }

    fn state(&self) -> Result<aos_registry_format::consumer::RegistryState> {
        state::load_state(&self.config)?.context("consumer state was not persisted")
    }

    fn update(&self) -> Result<()> {
        let updated = isolated_command(env!("CARGO_BIN_EXE_apm"), &self.home)
            .args(["update", "--registry", REGISTRY])
            .output()?;
        require_success(&updated, &["apm", "update"])
    }
}

impl Fixture {
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let home = temporary.path().join("maintainer");
        fs::create_dir_all(&home)?;

        let keypair = Ed25519Keypair::from_seed([71; 32]);
        let key = home.join("initial.key");
        fs::write(&key, keypair.to_openssh_private_key("staging fixture"))?;
        restrict_private_key(&key)?;

        let trust_key = keypair.trust_key_line(REGISTRY);
        let registry = home.join(".local/share/apm/registries").join(REGISTRY);
        let origin = temporary.path().join("origin");
        let fixture = Self {
            temporary,
            home,
            registry,
            origin,
            key,
            trust_key,
        };

        fixture.apr(&[
            "create",
            REGISTRY,
            "--trust-key",
            &fixture.trust_key,
            "--key",
            path_text(&fixture.key)?,
        ])?;
        git_output(&fixture.registry, &["config", "user.name", "Registry Test"])?;
        git_output(
            &fixture.registry,
            &["config", "user.email", "registry@example.com"],
        )?;
        let upload_url = format!("file://{}", fixture.origin.display());
        fixture.apr(&[
            "origin",
            "upload",
            "--registry",
            REGISTRY,
            "--upload-url",
            &upload_url,
        ])?;
        git_output(
            &fixture.registry,
            &["switch", "-c", "dplecki/staging-fixture"],
        )?;
        Ok(fixture)
    }

    fn apr(&self, arguments: &[&str]) -> Result<Output> {
        let output = self.apr_output(arguments)?;
        require_success(&output, arguments)?;
        Ok(output)
    }

    fn apr_output(&self, arguments: &[&str]) -> Result<Output> {
        isolated_command(env!("CARGO_BIN_EXE_apr"), &self.home)
            .args(arguments)
            .output()
            .with_context(|| format!("running apr {}", arguments.join(" ")))
    }

    fn release_stage(&self, revision: Option<u64>, resume: bool) -> Result<Output> {
        self.release_stage_named(VERSION, STAGE, revision, resume)
    }

    fn release_stage_named(
        &self,
        version: &str,
        stage: &str,
        revision: Option<u64>,
        resume: bool,
    ) -> Result<Output> {
        let upload_url = format!("file://{}", self.origin.display());
        self.release_stage_to(version, stage, revision, resume, &[upload_url])
    }

    fn release_stage_to(
        &self,
        version: &str,
        stage: &str,
        revision: Option<u64>,
        resume: bool,
        destinations: &[String],
    ) -> Result<Output> {
        let revision_text = revision.map(|value| value.to_string());
        let mut arguments = vec![
            "release",
            version,
            "--stage",
            stage,
            "--registry",
            REGISTRY,
            "--key",
            path_text(&self.key)?,
        ];
        for destination in destinations {
            arguments.extend(["--upload-url", destination.as_str()]);
        }
        if let Some(revision) = revision_text.as_deref() {
            arguments.extend(["--stage-revision", revision]);
        }
        if resume {
            arguments.push("--resume");
        }
        self.apr_output(&arguments)
    }

    fn show_stage(&self) -> Result<Value> {
        self.show_stage_named(STAGE)
    }

    fn show_stage_named(&self, stage: &str) -> Result<Value> {
        let output = self.apr(&["--json", "stage", "show", stage, "--registry", REGISTRY])?;
        serde_json::from_slice(&output.stdout).context("parsing stage show JSON")
    }

    fn publish_stage(&self, revision: u64) -> Result<Output> {
        self.publish_stage_named(VERSION, STAGE, revision)
    }

    fn publish_stage_named(&self, version: &str, stage: &str, revision: u64) -> Result<Output> {
        let revision = revision.to_string();
        let upload_url = format!("file://{}", self.origin.display());
        self.apr_output(&[
            "release",
            version,
            "--from-stage",
            stage,
            "--stage-revision",
            &revision,
            "--registry",
            REGISTRY,
            "--key",
            path_text(&self.key)?,
            "--upload-url",
            &upload_url,
        ])
    }

    fn commit_note(&self, content: &str) -> Result<()> {
        fs::write(self.registry.join("candidate-note.txt"), content)?;
        self.apr(&[
            "commit",
            "candidate-note.txt",
            "--message",
            "change candidate contents",
            "--registry",
            REGISTRY,
            "--key",
            path_text(&self.key)?,
        ])?;
        Ok(())
    }

    fn promote_and_upload(
        &self,
        version: &str,
        initialize: bool,
        partitions: Option<&str>,
    ) -> Result<()> {
        let mut arguments = vec![
            "channel",
            if initialize { "init" } else { "advance" },
            "defaultchannel",
            version,
            "--registry",
            REGISTRY,
            "--key",
            path_text(&self.key)?,
        ];
        if let Some(partitions) = partitions {
            arguments.extend(["--partitions", partitions]);
        } else if !initialize {
            arguments.extend(["--count", "256"]);
        }
        self.apr(&arguments)?;

        // The static-origin CLI exposes the checked-out frontier as symbolic
        // HEAD. Restore the authoring branch after this explicit promotion.
        git_output(&self.registry, &["switch", "defaultchannel"])?;
        let upload_url = format!("file://{}", self.origin.display());
        let upload = self.apr(&[
            "origin",
            "upload",
            "--registry",
            REGISTRY,
            "--upload-url",
            &upload_url,
        ]);
        git_output(&self.registry, &["switch", "dplecki/staging-fixture"])?;
        upload?;
        Ok(())
    }

    fn assert_unpublished(&self) -> Result<()> {
        assert!(
            git_output(&self.registry, &["tag", "--list"])?
                .trim()
                .is_empty(),
            "staging must not create a public release or channel tag"
        );
        assert!(advertised_release(&self.origin, VERSION)?.is_none());
        assert!(!self.origin.join("refs/heads/defaultchannel").exists());
        assert!(!self.origin.join("channels/defaultchannel").exists());
        Ok(())
    }
}

#[test]
fn staging_rejects_channel_changes_before_creating_candidate() -> Result<()> {
    let fixture = Fixture::new()?;
    for promotion_arguments in [
        vec!["--channel", "defaultchannel"],
        vec!["--init-channel"],
        vec!["--count", "1"],
        vec!["--partitions", "00"],
    ] {
        let mut arguments = vec![
            "release",
            VERSION,
            "--stage",
            STAGE,
            "--registry",
            REGISTRY,
            "--key",
            path_text(&fixture.key)?,
        ];
        arguments.extend(promotion_arguments);
        let rejected = fixture.apr_output(&arguments)?;
        assert!(
            !rejected.status.success(),
            "channel changes must be rejected during staging: {}",
            output_text(&rejected)
        );
        assert!(
            !fixture
                .registry
                .join(".git/apr/stages/records/candidate-one.json")
                .exists()
        );
        fixture.assert_unpublished()?;
    }
    Ok(())
}

#[test]
fn interrupted_upload_resumes_without_publication() -> Result<()> {
    let fixture = Fixture::new()?;
    let interrupted_origin = fixture.temporary.path().join("origin-interrupted");
    copy_directory(&fixture.origin, &interrupted_origin)?;
    let original_permissions = directory_permissions(&interrupted_origin)?;
    for (directory, permissions) in &original_permissions {
        let mut read_only = permissions.clone();
        read_only.set_readonly(true);
        fs::set_permissions(directory, read_only)?;
    }
    fixture.commit_note("immutable bytes retained across upload interruption\n")?;
    let destinations = [
        format!("file://{}", fixture.origin.display()),
        format!("file://{}", interrupted_origin.display()),
    ];
    let initial_refs = fs::read(fixture.origin.join("info/refs"))?;
    let initial_file_count = file_count(&fixture.origin)?;

    // Required mirrors transfer one phase at a time. The first mirror completes
    // its immutable inventory before the second rejects creation of new files.
    let interrupted_result = fixture.release_stage_to(VERSION, STAGE, None, false, &destinations);
    for (directory, permissions) in original_permissions {
        fs::set_permissions(directory, permissions)?;
    }
    let interrupted = interrupted_result?;
    assert!(
        !interrupted.status.success(),
        "immutable writes must fail on the read-only mirror"
    );
    assert!(
        file_count(&fixture.origin)? > initial_file_count,
        "immutable Git bytes should have uploaded before the interruption: {}",
        output_text(&interrupted)
    );
    fixture.assert_unpublished()?;
    assert_eq!(fs::read(fixture.origin.join("info/refs"))?, initial_refs);
    assert_eq!(
        fs::read(interrupted_origin.join("info/refs"))?,
        initial_refs
    );
    assert!(!interrupted_origin.join("refs/tags/1.0.0").exists());
    let revision = stage_revision(&fixture.show_stage()?)?;

    let resumed = fixture.release_stage_to(VERSION, STAGE, Some(revision), true, &destinations)?;
    require_success(&resumed, &["release", "--stage", "--resume"])?;
    fixture.assert_unpublished()?;

    let completed = fixture.show_stage()?;
    let resumed_revision = stage_revision(&completed)?;
    let repeated =
        fixture.release_stage_to(VERSION, STAGE, Some(resumed_revision), true, &destinations)?;
    require_success(&repeated, &["release", "--stage", "--resume"])?;
    assert_eq!(stage_revision(&fixture.show_stage()?)?, resumed_revision);
    fixture.assert_unpublished()?;
    assert!(!interrupted_origin.join("refs/tags/1.0.0").exists());
    Ok(())
}

#[test]
fn interrupted_publication_keeps_exact_revision_frozen_for_retry() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.commit_note("candidate retained across publication interruption\n")?;
    let staged = fixture.release_stage(None, false)?;
    require_success(&staged, &["release", "--stage"])?;
    let revision = stage_revision(&fixture.show_stage()?)?;

    let retained_refs = fs::read(fixture.origin.join("info/refs"))?;
    let publication_lock = fixture
        .origin
        .join("info")
        .join(aos_transfer::protocol::conditional::lock_file_name("refs"));
    // A competing writer allows predecessor reads, then interrupts the first
    // conditional pointer write after the candidate has been frozen.
    fs::write(&publication_lock, "held by the publication fixture")?;
    let interrupted = fixture.publish_stage(revision)?;
    assert!(
        !interrupted.status.success(),
        "publication must stop while another writer holds its pointer lock"
    );
    assert_eq!(fixture.show_stage()?["state"], "releasing");
    fixture.assert_unpublished()?;
    assert_eq!(fs::read(fixture.origin.join("info/refs"))?, retained_refs);

    let replacement = fixture.release_stage(Some(revision), false)?;
    assert!(
        !replacement.status.success(),
        "a publication attempt freezes its reviewed candidate"
    );
    fs::remove_file(&publication_lock)?;
    let retried = fixture.publish_stage(revision)?;
    require_success(&retried, &["release", "--from-stage", "--stage-revision"])?;
    assert_eq!(fixture.show_stage()?["state"], "released");
    assert_eq!(stage_revision(&fixture.show_stage()?)?, revision);
    assert!(advertised_release(&fixture.origin, VERSION)?.is_some());
    assert!(!fixture.origin.join("channels/defaultchannel").exists());
    Ok(())
}

#[test]
fn changed_candidate_rejects_stale_finalize_and_publishes_exact_revision() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.commit_note("first candidate\n")?;
    let staged = fixture.release_stage(None, false)?;
    require_success(&staged, &["release", "--stage"])?;
    let first_revision = stage_revision(&fixture.show_stage()?)?;
    fixture.assert_unpublished()?;

    fixture.commit_note("reviewed second candidate\n")?;
    let updated = fixture.release_stage(Some(first_revision), false)?;
    require_success(&updated, &["release", "--stage", "--stage-revision"])?;
    let revision = stage_revision(&fixture.show_stage()?)?;
    assert!(revision > first_revision);

    let stale = fixture.publish_stage(first_revision)?;
    assert!(
        !stale.status.success(),
        "stale finalization must fail: {}",
        output_text(&stale)
    );
    fixture.assert_unpublished()?;

    let published = fixture.publish_stage(revision)?;
    require_success(&published, &["release", "--from-stage"])?;
    let workspace = LocalStageStore::open(&fixture.registry)?.workspace(STAGE, revision)?;
    let release_commit = git_output(&workspace, &["rev-parse", "1.0.0^{commit}"])?;
    let release_tag = git_output(&workspace, &["rev-parse", "1.0.0^{tag}"])?;
    assert_eq!(
        git_output(&workspace, &["show", "1.0.0:candidate-note.txt"])?,
        "reviewed second candidate"
    );
    assert_eq!(
        advertised_release(&fixture.origin, VERSION)?,
        Some((release_tag.clone(), release_commit.clone()))
    );
    assert!(!fixture.origin.join("refs/heads/defaultchannel").exists());
    assert!(!fixture.origin.join("channels/defaultchannel").exists());
    fixture.promote_and_upload(VERSION, true, None)?;

    let consumer = Consumer::new(&fixture)?;
    let state = consumer.state()?;
    assert_eq!(state.selected_channel.as_deref(), Some("defaultchannel"));
    assert_eq!(state.last_commit.as_deref(), Some(release_commit.as_str()));

    let promoted_refs = fs::read(fixture.origin.join("info/refs"))?;
    let promoted_head = fs::read(fixture.origin.join("HEAD"))?;
    let promoted_partition = fs::read(fixture.origin.join("channels/defaultchannel/00"))?;
    let published_again = fixture.publish_stage(revision)?;
    require_success(
        &published_again,
        &["release", "--from-stage", "--stage-revision"],
    )?;
    assert_eq!(fs::read(fixture.origin.join("info/refs"))?, promoted_refs);
    assert_eq!(fs::read(fixture.origin.join("HEAD"))?, promoted_head);
    assert_eq!(
        fs::read(fixture.origin.join("channels/defaultchannel/00"))?,
        promoted_partition
    );

    let released_update = fixture.release_stage(Some(revision), false)?;
    assert!(
        !released_update.status.success(),
        "released candidates must be immutable"
    );
    let discarded = fixture.apr_output(&[
        "stage",
        "discard",
        STAGE,
        "--stage-revision",
        &revision.to_string(),
        "--registry",
        REGISTRY,
    ])?;
    assert!(
        !discarded.status.success(),
        "a released candidate cannot be discarded"
    );
    assert_eq!(
        advertised_release(&fixture.origin, VERSION)?,
        Some((release_tag, release_commit))
    );
    Ok(())
}

#[test]
fn sequential_staged_releases_preserve_history_and_promote_partitions_separately() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.commit_note("first retained release\n")?;
    let first = fixture.release_stage(None, false)?;
    require_success(&first, &["release", "--stage"])?;
    let first_revision = stage_revision(&fixture.show_stage()?)?;
    let published = fixture.publish_stage(first_revision)?;
    require_success(&published, &["release", "--from-stage"])?;
    fixture.promote_and_upload(VERSION, true, None)?;
    let consumer = Consumer::new(&fixture)?;
    let mut first_state = consumer.state()?;
    assert_eq!(first_state.floor.as_deref(), Some("1.0.0"));
    first_state.bucket = Some(0);
    state::save_state(&consumer.config, &first_state)?;

    let first_tag = advertised_release(&fixture.origin, VERSION)?
        .context("first signed release was not advertised")?;
    let first_partitions: Vec<Vec<u8>> = (0..=255_u8)
        .map(|bucket| {
            fs::read(
                fixture
                    .origin
                    .join(aos_registry_client::registry::channel::partition_path(
                        "defaultchannel",
                        bucket,
                    )),
            )
        })
        .collect::<std::io::Result<_>>()?;

    fixture.commit_note("second retained release\n")?;
    let second = fixture.release_stage_named("1.1.0", "candidate-two", None, false)?;
    require_success(&second, &["release", "1.1.0", "--stage"])?;
    let second_revision = stage_revision(&fixture.show_stage_named("candidate-two")?)?;
    assert_eq!(
        advertised_release(&fixture.origin, VERSION)?,
        Some(first_tag.clone())
    );
    assert!(advertised_release(&fixture.origin, "1.1.0")?.is_none());

    let published = fixture.publish_stage_named("1.1.0", "candidate-two", second_revision)?;
    require_success(&published, &["release", "1.1.0", "--from-stage"])?;
    let second_tag = advertised_release(&fixture.origin, "1.1.0")?
        .context("second signed release was not advertised")?;
    assert_eq!(
        advertised_release(&fixture.origin, VERSION)?,
        Some(first_tag.clone())
    );
    for (bucket, expected) in first_partitions.iter().enumerate() {
        assert_eq!(
            fs::read(
                fixture
                    .origin
                    .join(format!("channels/defaultchannel/{bucket:02x}"))
            )?,
            *expected
        );
    }

    fixture.promote_and_upload("1.1.0", false, Some("00"))?;
    consumer.update()?;
    let second_state = consumer.state()?;
    assert_eq!(second_state.floor.as_deref(), Some("1.1.0"));
    assert_eq!(
        second_state.selected_channel.as_deref(),
        Some("defaultchannel")
    );
    assert!(second_state.tuf_targets_version > first_state.tuf_targets_version);
    assert!(second_state.tuf_snapshot_version > first_state.tuf_snapshot_version);
    let second_workspace =
        LocalStageStore::open(&fixture.registry)?.workspace("candidate-two", second_revision)?;
    let second_commit = git_output(&second_workspace, &["rev-parse", "1.1.0^{commit}"])?;
    assert_eq!(
        second_state.last_commit.as_deref(),
        Some(second_commit.as_str())
    );

    assert_ne!(
        fs::read(fixture.origin.join("channels/defaultchannel/00"))?,
        first_partitions[0]
    );
    for (bucket, expected) in first_partitions.iter().enumerate().skip(1) {
        assert_eq!(
            fs::read(
                fixture
                    .origin
                    .join(format!("channels/defaultchannel/{bucket:02x}"))
            )?,
            *expected
        );
    }
    assert_eq!(
        advertised_release(&fixture.origin, VERSION)?,
        Some(first_tag)
    );
    assert_eq!(
        advertised_release(&fixture.origin, "1.1.0")?,
        Some(second_tag)
    );
    Ok(())
}

#[test]
fn discarded_candidate_cannot_be_finalized() -> Result<()> {
    let fixture = Fixture::new()?;
    let staged = fixture.release_stage(None, false)?;
    require_success(&staged, &["release", "--stage"])?;
    let revision = stage_revision(&fixture.show_stage()?)?;
    fixture.apr(&[
        "stage",
        "discard",
        STAGE,
        "--stage-revision",
        &revision.to_string(),
        "--registry",
        REGISTRY,
    ])?;
    assert!(!fixture.publish_stage(revision)?.status.success());
    fixture.assert_unpublished()?;
    Ok(())
}

#[test]
fn default_key_retirement_is_atomic_and_explicit_revocation_retains_release() -> Result<()> {
    let fixture = Fixture::new()?;
    let next_keypair = Ed25519Keypair::from_seed([72; 32]);
    let next_key = fixture.home.join("next.key");
    fs::write(
        &next_key,
        next_keypair.to_openssh_private_key("next fixture key"),
    )?;
    restrict_private_key(&next_key)?;
    let next_trust = next_keypair.trust_key_line(REGISTRY);
    fixture.apr(&[
        "keys",
        "add",
        "next",
        &next_trust,
        "--key",
        path_text(&fixture.key)?,
        "--registry",
        REGISTRY,
    ])?;
    fixture.apr(&[
        "release",
        VERSION,
        "--registry",
        REGISTRY,
        "--key",
        path_text(&fixture.key)?,
    ])?;

    let head = git_output(&fixture.registry, &["rev-parse", "HEAD"])?;
    let release = git_output(&fixture.registry, &["rev-parse", "1.0.0^{tag}"])?;
    let roster = fs::read(fixture.registry.join("keys.toml"))?;
    let index = fs::read(fixture.registry.join(".git/index"))?;
    let rejected = fixture.apr_output(&[
        "keys",
        "retire",
        "initial",
        "--vouched-by",
        "next",
        "--key",
        path_text(&next_key)?,
        "--registry",
        REGISTRY,
    ])?;
    assert!(
        !rejected.status.success(),
        "default retirement must refuse release rewrites"
    );
    assert_eq!(git_output(&fixture.registry, &["rev-parse", "HEAD"])?, head);
    assert_eq!(
        git_output(&fixture.registry, &["rev-parse", "1.0.0^{tag}"])?,
        release
    );
    assert_eq!(fs::read(fixture.registry.join("keys.toml"))?, roster);
    assert_eq!(fs::read(fixture.registry.join(".git/index"))?, index);
    assert!(git_output(&fixture.registry, &["status", "--porcelain"])?.is_empty());

    fixture.apr(&[
        "keys",
        "retire",
        "initial",
        "--vouched-by",
        "next",
        "--key",
        path_text(&next_key)?,
        "--no-resign",
        "--registry",
        REGISTRY,
    ])?;
    let roster = keys::load_keys_toml(&fixture.registry)?.context("registry roster missing")?;
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.active[0].id, "next");
    assert_eq!(roster.revoked.len(), 1);
    assert_eq!(roster.revoked[0].id, "initial");
    assert_eq!(
        git_output(&fixture.registry, &["rev-parse", "1.0.0^{tag}"])?,
        release
    );
    Ok(())
}

#[test]
fn release_journal_status_runs_offline_under_maintenance() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let journal = temporary.path().join("journal.jsonl");
    let entry = JournalEntry {
        schema_version: RELEASE_JOURNAL_ENTRY.to_owned(),
        sequence: 1,
        previous_entry_digest: None,
        plan_digest: Sha256Digest::of_bytes(b"offline release fixture"),
        manifest_digest: None,
        prior_state: None,
        new_state: ReleaseState::Planned,
        destination: None,
        operation_ids: Vec::new(),
        evidence: Vec::new(),
        recorded_at: "2026-10-01T00:00:00Z".to_owned(),
    };
    let mut bytes = canonical::to_vec(&entry)?;
    bytes.push(b'\n');
    fs::write(&journal, bytes)?;

    let output = isolated_command(env!("CARGO_BIN_EXE_aos"), temporary.path())
        .env("PATH", temporary.path().join("no-executables"))
        .args([
            "--json",
            "maintain",
            "release",
            "step",
            "status",
            "--journal",
            path_text(&journal)?,
        ])
        .output()?;
    require_success(&output, &["aos", "maintain", "release", "step", "status"])?;
    let status: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(status["state"], "planned");
    assert_eq!(status["sequence"], 1);

    let removed = isolated_command(env!("CARGO_BIN_EXE_aos"), temporary.path())
        .args(["release", "--help"])
        .output()?;
    assert!(
        !removed.status.success(),
        "the former top-level release command must be rejected"
    );
    Ok(())
}

fn advertised_release(origin: &Path, version: &str) -> Result<Option<(String, String)>> {
    let advertisement = fs::read_to_string(origin.join("info/refs"))?;
    let references = aos_registry_format::refs::parse_info_refs(&advertisement)?;
    match (
        references.tags.get(version),
        references.peeled_tags.get(version),
    ) {
        (None, None) => Ok(None),
        (Some(tag), Some(commit)) => Ok(Some((tag.to_string(), commit.to_string()))),
        _ => anyhow::bail!("release advertisement must bind both signed tag and peeled commit"),
    }
}

fn isolated_command(binary: &str, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("APM_SYSTEM_CONFIG_DIR", home.join("system-config"))
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME");
    command
}

fn require_success(output: &Output, arguments: &[&str]) -> Result<()> {
    ensure!(
        output.status.success(),
        "{} failed: {}",
        arguments.join(" "),
        output_text(output)
    );
    Ok(())
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn git_output(registry: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(registry)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()?;
    require_success(&output, arguments)?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("fixture path is not UTF-8")
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn stage_revision(document: &Value) -> Result<u64> {
    let stage = document.get("stage").unwrap_or(document);
    stage["revision"]["revision"]
        .as_u64()
        .or_else(|| stage["revision"].as_u64())
        .with_context(|| format!("stage show did not expose a revision: {document}"))
}

fn file_count(directory: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        count += if path.is_dir() { file_count(&path)? } else { 1 };
    }
    Ok(count)
}

fn directory_permissions(directory: &Path) -> Result<Vec<(PathBuf, fs::Permissions)>> {
    let mut permissions = vec![(directory.to_owned(), fs::metadata(directory)?.permissions())];
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            permissions.extend(directory_permissions(&entry.path())?);
        }
    }
    Ok(permissions)
}

fn restrict_private_key(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
