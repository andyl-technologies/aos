//! Actual private SQLite initialization, restart, CAS and failure regressions.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::sync::{Arc, Barrier};

use aos_hub_core::storage_authority::{
    lease::{LeaseCohort, LeaseEffect, LeasePurpose, LeaseTimingProfile},
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId,
    SetStorageAuthorityAdmission, StorageAuthorityAdmissionState, StorageAuthorityAliasSpec,
    StorageAuthorityCredentialMember, StorageAuthorityHost,
};

use super::*;

// Test publications use the shared canonical JSON digest contract; no fixture
// digest represents real provider qualification or operator authorization.
fn canonical_digest(value: &impl serde::Serialize) -> Result<String> {
    use sha2::Digest as _;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        value,
    )?)))
}

const EXECUTOR: &str = "qualified-executor";

pub(crate) fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}
pub(crate) fn clock(value: i64) -> LeaseClock {
    LeaseClock {
        observed_at: value,
        uncertainty: 2,
    }
}

pub(crate) fn profile() -> LeaseTimingProfile {
    // Fixture-only example; these values are not a qualified deployment default.
    LeaseTimingProfile {
        profile_id: "fixture-reviewed-clock".into(),
        review_digest: "9".repeat(64),
        maximum_lifetime: integer(30),
        maximum_clock_uncertainty: integer(2),
    }
}

pub(crate) fn publication() -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: "permanent-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("objects.example.invalid".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 9_007_199_254_740_993,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 9_007_199_254_740_995,
        binding_write_revision: 9_007_199_254_740_997,
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: 9_007_199_254_741_001,
            secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
            credential_fingerprint: "4".repeat(64),
        })
        .collect();
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials,
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = canonical_digest(&admission).unwrap();
    let publication = StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    };
    publication
        .validate(&publication.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    publication
}

pub(crate) fn next_publication(
    previous: &StorageAuthorityPublication,
    state: StorageAuthorityAdmissionState,
) -> StorageAuthorityPublication {
    let mut next = publication();
    next.generation = previous.generation + 1;
    next.admission.expected_generation = previous.generation;
    next.admission.expected_digest = Some(previous.digest.clone());
    next.admission.state = state;
    if state != StorageAuthorityAdmissionState::Admitted {
        next.aliases.clear();
        next.associations.clear();
        next.attestation = None;
        next.admission.attestation_id = None;
        next.admission.association_ids.clear();
    }
    next.digest = canonical_digest(&next.admission).unwrap();
    next.validate(&next.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    next
}

pub(crate) fn cohort(publication: &StorageAuthorityPublication) -> LeaseCohort {
    LeaseCohort::from_publication(
        publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding/objects",
        vec![LeaseEffect::Put, LeaseEffect::MultipartComplete],
    )
    .unwrap()
}

pub(crate) struct Fixture {
    _directory: tempfile::TempDir,
    pub(crate) path: PathBuf,
    pub(crate) boundary: HubDataBoundary,
    pub(crate) marker: IssuerInstallation,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let issuer = directory.path().join("issuer");
        let hub = directory.path().join("hub");
        fs::create_dir(&issuer).unwrap();
        fs::create_dir(&hub).unwrap();
        fs::set_permissions(&issuer, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            path: issuer.join("authority.sqlite"),
            boundary: HubDataBoundary {
                hub_root: hub,
                hub_sqlite_file: None,
            },
            marker: IssuerInstallation {
                format_version: 1,
                authority: publication().authority,
                issuer_resource_id: "permanent-issuer-resource-one".into(),
                runtime_identity: "separate-issuer-runtime-one".into(),
                executor_identity: EXECUTOR.into(),
            },
            _directory: directory,
        }
    }

    pub(crate) fn initialize(&self) -> AuthorityJournal {
        AuthorityJournal::initialize_fresh(
            &self.path,
            &self.boundary,
            self.marker.clone(),
            publication(),
            BoundedLeaseRevocationPolicy {
                timing_profile: profile(),
            },
            clock(100),
        )
        .unwrap()
    }

    pub(crate) fn reopen(&self) -> Result<AuthorityJournal> {
        AuthorityJournal::open_existing(&self.path, &self.boundary, self.marker.clone())
    }
}

fn issuance(adapter: &AuthorityJournal) -> IssuerTransition {
    let state = adapter.load().unwrap();
    state
        .journal
        .prepare_issue(
            &state.publication,
            cohort(&state.publication),
            "fixture-issuer-key",
            120,
            clock(100),
        )
        .unwrap()
        .transition()
        .clone()
}

#[test]
fn serving_never_bootstraps_missing_or_empty_files_and_initialization_never_overwrites() {
    let fixture = Fixture::new();
    assert!(fixture.reopen().is_err());
    assert!(!fixture.path.exists());

    fs::write(&fixture.path, []).unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fixture.reopen().is_err());
    assert_eq!(fs::metadata(&fixture.path).unwrap().len(), 0);
    assert!(AuthorityJournal::initialize_fresh(
        &fixture.path,
        &fixture.boundary,
        fixture.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
}

#[test]
fn private_installation_reopens_exact_state_without_hub_sql_or_default_bindings() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let before = adapter.load().unwrap();
    drop(adapter);

    let after = fixture.reopen().unwrap().load().unwrap();
    assert_eq!(after, before);
    assert_eq!(
        after.publication.associations[0].binding_id,
        9_007_199_254_740_993
    );
    assert_eq!(
        fs::metadata(&fixture.path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(fs::read_dir(&fixture.boundary.hub_root).unwrap().count(), 0);
    assert!(!PathBuf::from(format!("{}-wal", fixture.path.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", fixture.path.display())).exists());
}

#[tokio::test]
async fn issuance_acknowledges_committed_retention_and_cas_survives_restart() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let transition = issuance(&adapter);
    adapter.commit_lease(transition.clone()).await.unwrap();
    drop(adapter);

    let adapter = fixture.reopen().unwrap();
    assert_eq!(adapter.load().unwrap().journal, transition.next);
    assert!(adapter.commit_lease(transition).await.is_err());
    assert_eq!(adapter.load().unwrap().journal.last_sequence.get(), 1);
    assert_eq!(
        adapter.load().unwrap().journal.largest_issued_expiry.get(),
        120
    );
}

#[tokio::test]
async fn publication_denial_and_receipt_commit_atomically_preserving_issuance_history() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    adapter.commit_lease(issuance(&adapter)).await.unwrap();
    let before = adapter.load().unwrap();
    let denied = next_publication(&before.publication, StorageAuthorityAdmissionState::Blocked);
    let transition = before
        .journal
        .prepare_publication(&denied, clock(101))
        .unwrap();
    let receipt = adapter
        .commit_publication(transition.clone(), denied.clone(), clock(101))
        .await
        .unwrap();
    drop(adapter);

    let adapter = fixture.reopen().unwrap();
    assert_eq!(adapter.load().unwrap().publication, denied);
    assert_eq!(adapter.load().unwrap().journal, transition.next);
    assert_eq!(adapter.receipt(integer(2)).unwrap(), Some(receipt));
    assert!(adapter.receipt(integer(1)).unwrap().is_some());
    assert_eq!(adapter.load().unwrap().journal.last_sequence.get(), 1);
    assert_eq!(
        adapter.load().unwrap().journal.largest_issued_expiry.get(),
        120
    );
    assert!(adapter
        .commit_lease(issuance_from_snapshot(&before))
        .await
        .is_err());
}

fn issuance_from_snapshot(state: &IssuerLiveState) -> IssuerTransition {
    state
        .journal
        .prepare_issue(
            &state.publication,
            cohort(&state.publication),
            "fixture-issuer-key",
            121,
            clock(101),
        )
        .unwrap()
        .transition()
        .clone()
}

#[test]
fn concurrent_real_connections_allow_exactly_one_expected_journal_cas() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let expected = issuance(&adapter);
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let adapter = adapter.clone();
            let transition = expected.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                sqlite::commit_lease(&adapter, transition, || {}).is_ok()
            })
        })
        .collect();
    let succeeded = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|succeeded| *succeeded)
        .count();
    assert_eq!(succeeded, 1);
    assert_eq!(
        fixture.reopen().unwrap().load().unwrap().journal,
        expected.next
    );
}

#[tokio::test]
async fn discarded_acknowledgment_retains_commit_after_reopen() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let transition = issuance(&adapter);
    // The storage operation commits; the caller discards its acknowledgement.
    let _discarded = adapter.commit_lease(transition.clone()).await;
    drop(adapter);

    assert_eq!(
        fixture.reopen().unwrap().load().unwrap().journal,
        transition.next
    );
}

#[tokio::test]
async fn cancellation_after_transaction_start_cannot_undo_background_commit() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let transition = issuance(&adapter);
    let expected = transition.next.clone();
    let (started, observed_start) = tokio::sync::oneshot::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let worker = adapter.clone();
    let operation = tokio::spawn(async move {
        worker
            .commit_lease_inner(transition, move || {
                started.send(()).unwrap();
                wait_release.recv().unwrap();
            })
            .await
    });
    observed_start.await.unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if fixture.reopen().unwrap().load().unwrap().journal == expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(fixture.reopen().unwrap().load().unwrap().journal, expected);
}

#[tokio::test]
async fn journal_history_publication_and_clock_cannot_be_rewritten_by_lease_cas() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let expected = adapter.load().unwrap().journal;
    for altered in 0..4 {
        let mut next = expected.clone();
        match altered {
            0 => next.publication_digest = "f".repeat(64),
            1 => next.clock_floor = integer(99),
            2 => next.last_sequence = integer(5),
            _ => next.authority.guard_namespace_id = "changed-domain".into(),
        }
        assert!(adapter
            .commit_lease(IssuerTransition {
                expected: expected.clone(),
                next
            })
            .await
            .is_err());
    }
    assert_eq!(fixture.reopen().unwrap().load().unwrap().journal, expected);
}

#[test]
fn marker_binds_version_full_authority_resource_runtime_and_executor_identity() {
    let fixture = Fixture::new();
    fixture.initialize();
    for altered in 0..5 {
        let mut marker = fixture.marker.clone();
        match altered {
            0 => marker.format_version = 2,
            1 => marker.authority.qualification_digest = "f".repeat(64),
            2 => marker.issuer_resource_id = "changed-resource".into(),
            3 => marker.runtime_identity = "changed-runtime".into(),
            _ => marker.executor_identity = "changed-executor".into(),
        }
        assert!(AuthorityJournal::open_existing(&fixture.path, &fixture.boundary, marker).is_err());
    }
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert!(connection
        .execute("DELETE FROM installation_marker", [])
        .is_err());
    assert!(connection
        .execute("UPDATE installation_marker SET marker = '{}'", [])
        .is_err());
    assert!(connection
        .execute(
            "INSERT OR REPLACE INTO installation_marker SELECT * FROM installation_marker",
            []
        )
        .is_err());
    assert!(connection
        .execute(
            "INSERT OR REPLACE INTO publication_receipts SELECT * FROM publication_receipts",
            []
        )
        .is_err());
}

#[test]
fn malformed_marker_schema_state_and_header_fail_closed() {
    for altered in 0..4 {
        let fixture = Fixture::new();
        fixture.initialize();
        if altered == 3 {
            fs::write(&fixture.path, b"corrupt sqlite header").unwrap();
        } else {
            let connection = rusqlite::Connection::open(&fixture.path).unwrap();
            match altered {
                0 => {
                    connection.execute_batch("DROP TRIGGER marker_no_update; UPDATE installation_marker SET marker = '{}' ").unwrap();
                }
                1 => {
                    connection.execute_batch("PRAGMA user_version = 3").unwrap();
                }
                _ => {
                    connection
                        .execute(
                            "UPDATE authority_state SET journal = ?1",
                            [b"{\"unknown\":1}".as_slice()],
                        )
                        .unwrap();
                }
            }
        }
        assert!(fixture.reopen().is_err());
    }
}

#[test]
fn insecure_file_parent_links_sidecars_and_hub_paths_are_refused() {
    for altered in 0..7 {
        let fixture = Fixture::new();
        fixture.initialize();
        match altered {
            0 => fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => fs::set_permissions(
                fixture.path.parent().unwrap(),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap(),
            2 => {
                fs::hard_link(&fixture.path, fixture.path.with_extension("link")).unwrap();
            }
            3 => {
                let actual = fixture.path.with_extension("actual");
                fs::rename(&fixture.path, &actual).unwrap();
                symlink(&actual, &fixture.path).unwrap();
            }
            4 => {
                symlink(
                    &fixture.path,
                    PathBuf::from(format!("{}-journal", fixture.path.display())),
                )
                .unwrap();
            }
            5 => {
                fs::write(PathBuf::from(format!("{}-wal", fixture.path.display())), []).unwrap();
            }
            _ => {
                fs::write(PathBuf::from(format!("{}-shm", fixture.path.display())), []).unwrap();
            }
        }
        assert!(fixture.reopen().is_err());
    }
    let fixture = Fixture::new();
    let mut boundary = fixture.boundary.clone();
    boundary.hub_root = fixture.path.parent().unwrap().to_owned();
    assert!(AuthorityJournal::initialize_fresh(
        &fixture.path,
        &boundary,
        fixture.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
    boundary = fixture.boundary.clone();
    boundary.hub_sqlite_file = Some(fixture.path.clone());
    assert!(AuthorityJournal::initialize_fresh(
        &fixture.path,
        &boundary,
        fixture.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
}

#[test]
fn opened_adapter_refuses_replaced_inode_and_canonical_encoding_remains_lossless() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    let mut journal = adapter.load().unwrap().journal;
    journal.last_sequence = integer(9_007_199_254_740_993);
    journal.largest_issued_expiry = integer(9_007_199_254_740_995);
    let bytes = serde_json::to_vec(&journal).unwrap();
    assert!(std::str::from_utf8(&bytes)
        .unwrap()
        .contains("\"last_sequence\":\"9007199254740993\""));
    connection
        .execute("UPDATE authority_state SET journal = ?1", [bytes])
        .unwrap();
    assert_eq!(fixture.reopen().unwrap().load().unwrap().journal, journal);
    drop(connection);

    let replacement = fixture.path.with_extension("replacement");
    fs::copy(&fixture.path, &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &fixture.path).unwrap();
    assert!(adapter.load().is_err());
}

#[test]
fn publication_failure_before_commit_rolls_back_state_and_new_receipt_together() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let before = adapter.load().unwrap();
    let denied = next_publication(&before.publication, StorageAuthorityAdmissionState::Blocked);
    let transition = before
        .journal
        .prepare_publication(&denied, clock(101))
        .unwrap();

    let result = sqlite::commit_publication(&adapter, transition, denied, clock(101), || {
        anyhow::bail!("fixture failure after all SQL writes before commit")
    });
    assert!(result.is_err());
    assert_eq!(fixture.reopen().unwrap().load().unwrap(), before);
    assert!(adapter.receipt(integer(2)).unwrap().is_none());
    assert!(adapter.receipt(integer(1)).unwrap().is_some());
}

#[tokio::test]
async fn denied_gap_keeps_exact_live_history_and_never_bootstraps_a_missing_file() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    adapter.commit_lease(issuance(&adapter)).await.unwrap();
    let before = adapter.load().unwrap();
    let mut denied = next_publication(&before.publication, StorageAuthorityAdmissionState::Blocked);
    denied.admission.expected_generation = 4;
    denied.admission.expected_digest = Some("9".repeat(64));
    denied.generation = 5;
    denied.digest = canonical_digest(&denied.admission).unwrap();
    let denial = StorageAuthorityDeniedTransition {
        publication: denied.clone(),
        expected_remote: Some(
            aos_hub_core::storage_authority::StorageAuthorityRemoteWatermark {
                authority_id: fixture.marker.authority.authority_id.clone(),
                guard_namespace_id: fixture.marker.authority.guard_namespace_id.clone(),
                generation: 1,
                digest: before.publication.digest.clone(),
            },
        ),
    };
    let transition = before
        .journal
        .prepare_denied_gap(&denial, clock(101))
        .unwrap();
    adapter
        .commit_denial(transition.clone(), denial, clock(101))
        .await
        .unwrap();

    let state = fixture.reopen().unwrap().load().unwrap();
    assert_eq!(state.publication, denied);
    assert_eq!(state.journal, transition.next);
    assert_eq!(state.journal.last_sequence.get(), 1);
    assert_eq!(state.journal.largest_issued_expiry.get(), 120);
    assert!(adapter.receipt(integer(1)).unwrap().is_some());
    assert!(adapter.receipt(integer(5)).unwrap().is_some());
    assert!(adapter.receipt(integer(2)).unwrap().is_none());
}

#[tokio::test]
async fn concurrent_issuance_and_denial_share_one_real_sqlite_gate() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let before = adapter.load().unwrap();
    let issue = issuance(&adapter);
    let denied = next_publication(&before.publication, StorageAuthorityAdmissionState::Blocked);
    let transition = before
        .journal
        .prepare_publication(&denied, clock(101))
        .unwrap();
    let (issue_result, deny_result) = tokio::join!(
        adapter.commit_lease(issue),
        adapter.commit_publication(transition, denied, clock(101))
    );
    assert_ne!(issue_result.is_ok(), deny_result.is_ok());
    let state = fixture.reopen().unwrap().load().unwrap();
    if issue_result.is_ok() {
        assert_eq!(
            state.journal.state,
            StorageAuthorityAdmissionState::Admitted
        );
        assert_eq!(state.journal.last_sequence.get(), 1);
        assert!(adapter.receipt(integer(2)).unwrap().is_none());
    } else {
        assert_eq!(state.journal.state, StorageAuthorityAdmissionState::Blocked);
        assert_eq!(state.journal.last_sequence.get(), 0);
        assert!(adapter.receipt(integer(2)).unwrap().is_some());
    }
}

#[test]
fn initialization_refuses_noninitial_history_and_serving_refuses_foreign_hub_sql() {
    let fixture = Fixture::new();
    let later = next_publication(&publication(), StorageAuthorityAdmissionState::Blocked);
    assert!(AuthorityJournal::initialize_fresh(
        &fixture.path,
        &fixture.boundary,
        fixture.marker.clone(),
        later,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
    assert!(!fixture.path.exists());

    // A normal SQLite database is never adopted as an issuer installation.
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    connection
        .execute("CREATE TABLE hub_rows (id INTEGER)", [])
        .unwrap();
    drop(connection);
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fixture.reopen().is_err());
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'installation_marker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn commit_acknowledgment_refuses_file_replacement_during_transaction() {
    let fixture = Fixture::new();
    let adapter = fixture.initialize();
    let transition = issuance(&adapter);
    let (started, observed_start) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let worker = adapter.clone();
    let operation = std::thread::spawn(move || {
        sqlite::commit_lease(&worker, transition, || {
            started.send(()).unwrap();
            wait_release.recv().unwrap();
        })
    });
    observed_start.recv().unwrap();

    let retained_file = fixture._directory.path().join("retained.sqlite");
    fs::rename(&fixture.path, &retained_file).unwrap();
    fs::copy(&retained_file, &fixture.path).unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    release.send(()).unwrap();
    assert!(operation.join().unwrap().is_err());
    assert!(adapter.load().is_err());
}

#[test]
fn journal_directory_cannot_be_shared_with_another_installation_or_foreign_file() {
    let fixture = Fixture::new();
    fixture.initialize();
    let other = fixture.path.parent().unwrap().join("other.sqlite");
    assert!(AuthorityJournal::initialize_fresh(
        &other,
        &fixture.boundary,
        fixture.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
    assert!(!other.exists());
    let sidecar_name = fixture.path.with_file_name("authority.sqlite-journal");
    assert!(AuthorityJournal::initialize_fresh(
        &sidecar_name,
        &fixture.boundary,
        fixture.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
    fs::write(&other, b"foreign file").unwrap();
    assert!(fixture.reopen().is_err());
}

#[test]
fn opened_adapter_refuses_ancestor_replacement_by_symlink_with_identical_inodes() {
    let mut fixture = Fixture::new();
    let ancestor = fixture._directory.path().join("ancestor");
    fs::create_dir(&ancestor).unwrap();
    let parent = ancestor.join("issuer");
    fs::rename(fixture.path.parent().unwrap(), &parent).unwrap();
    fixture.path = parent.join("authority.sqlite");
    let adapter = fixture.initialize();
    adapter.load().unwrap();
    let file_before = fs::metadata(&fixture.path).unwrap();

    let moved = fixture._directory.path().join("moved-ancestor");
    fs::rename(&ancestor, &moved).unwrap();
    symlink(&moved, &ancestor).unwrap();
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        fs::metadata(&fixture.path).unwrap().ino(),
        file_before.ino()
    );
    assert!(adapter.load().is_err());
    assert!(fixture.reopen().is_err());
}
