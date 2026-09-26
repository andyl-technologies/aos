//! Process-loss fixtures for campaign repository publication boundaries.

use super::*;

use std::path::Path;

use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

const CHILD_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_DAEMON_FAULT_CHILD";
const ROOT_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_DAEMON_FAULT_ROOT";
const TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
const SNAPSHOT_PUBLICATION_TRIGGER: &str =
    "crucible.destructive-recovery.daemon-during-snapshot-publication";
const TEST_NAME: &str = "repository::tests::destructive_recovery::daemon_fault_during_snapshot_publication_recovers_complete_ref";
const FAULT_EXIT_CODE: i32 = 86;
const CAMPAIGN: &str = "daemon-snapshot-publication-fault";

#[test]
fn daemon_fault_during_snapshot_publication_recovers_complete_ref() {
    if std::env::var_os(CHILD_ENVIRONMENT).is_some() {
        run_faulting_publication();
        panic!("daemon snapshot publication fault returned without terminating the process");
    }

    let temporary = tempfile::tempdir().expect("persistent daemon fault fixture");
    let repository = persistent_repository(temporary.path());
    let (repository, lineage, policy) = initialize_fixture(repository);
    let prior = repository
        .create_funded(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create persistent campaign");
    drop(repository);

    let child = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg(TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_ENVIRONMENT, "1")
        .env(ROOT_ENVIRONMENT, temporary.path())
        .env(TRIGGER_ENVIRONMENT, SNAPSHOT_PUBLICATION_TRIGGER)
        .output()
        .expect("run daemon snapshot fault child");
    assert_eq!(
        child.status.code(),
        Some(FAULT_EXIT_CODE),
        "fault child did not terminate during snapshot publication:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );

    let repository = persistent_repository(temporary.path());
    let post_fault = repository.head(CAMPAIGN).expect("head after daemon fault");
    assert_eq!(post_fault, prior);
    repository
        .validate_complete_head(post_fault.snapshot_id().content_id())
        .expect("complete pre-fault head");

    let resume = command(
        "daemon-snapshot-publication-fault-resume",
        prior.snapshot_id(),
        CampaignControlAction::Resume,
    );
    let recovered = repository
        .apply_control(CAMPAIGN, &resume)
        .expect("repeat interrupted snapshot publication");
    assert_eq!(recovered.prior_snapshot, prior.snapshot_id());
    assert_ne!(recovered.new_snapshot, prior.snapshot_id());
    repository
        .validate_complete_head(recovered.new_snapshot.content_id())
        .expect("complete recovered head");
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("recovered head")
            .snapshot_id(),
        recovered.new_snapshot,
    );

    let replay = repository
        .apply_control(CAMPAIGN, &resume)
        .expect("replay recovered control command");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, recovered.new_snapshot);
}

fn run_faulting_publication() {
    let root = std::env::var_os(ROOT_ENVIRONMENT)
        .map(std::path::PathBuf::from)
        .expect("daemon fault fixture root");
    let repository = persistent_repository(&root);
    let prior = repository.head(CAMPAIGN).expect("pre-fault campaign head");
    let resume = command(
        "daemon-snapshot-publication-fault-resume",
        prior.snapshot_id(),
        CampaignControlAction::Resume,
    );

    let _ = repository.apply_control(CAMPAIGN, &resume);
}

fn persistent_repository(root: &Path) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "daemon-fault-fixture",
            root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(root.join("authority"))),
    )
}
