//! Real format 3 transactions, exact replay and format 2 refusal regressions.

use super::*;
use crate::authority_journal::tests::{clock, cohort, integer, profile, publication, Fixture};
use crate::authority_journal::AuthorityJournal;
use aos_hub_core::storage_authority::lease::BoundedLeaseRevocationPolicy;

pub(crate) fn policy() -> ClockRecoveryPolicy {
    ClockRecoveryPolicy {
        version: 1,
        reviewer_key_id: "independent-recovery-reviewer".into(),
        reviewer_public_key: hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[37; 32])
                .verifying_key()
                .to_bytes(),
        ),
        resource_qualification_digest: "6".repeat(64),
        clock_qualification_digest: "7".repeat(64),
        maximum_review_seconds: integer(30),
        clock_uncertainty: integer(0),
        clock_commit_latency: integer(1),
    }
}

fn initialize(file: &Fixture) -> AuthorityJournal {
    AuthorityJournal::initialize_recoverable(
        &file.path,
        &file.boundary,
        file.marker.clone(),
        publication(),
        BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock(100),
        policy(),
    )
    .unwrap()
}

#[tokio::test]
async fn exact_positive_replay_consumes_one_successor_and_preserves_issuer_history() {
    let file = Fixture::new();
    let journal = initialize(&file);
    let old = journal.begin_clock_observation_session().unwrap();
    old.retain_ceiling(clock(110)).unwrap();
    assert!(journal.inspect_clock_session(&policy()).is_err());
    let initial = journal.load().unwrap();
    let issuance = initial
        .journal
        .prepare_issue(
            &initial.publication,
            cohort(&initial.publication),
            "fixture-issuer-key",
            120,
            clock(110),
        )
        .unwrap()
        .transition()
        .clone();
    journal.commit_lease(issuance).await.unwrap();
    drop(old);

    let original = journal.load().unwrap();
    assert!(journal.begin_clock_observation_session().is_err());
    let plan = journal.inspect_clock_session(&policy()).unwrap();
    assert_eq!(plan.expected_floor.get(), 110);
    assert_eq!(plan.expected_ceiling.get(), 112);
    assert_eq!(plan.expected_head.journal.last_sequence.get(), 1);
    assert_eq!(plan.expected_head.journal.largest_issued_expiry.get(), 120);
    let review = ClockRecoveryReview::sign(plan.clone(), &policy(), &[37; 32]).unwrap();

    // Simulate loss of the acknowledgment after the real EXTRA commit. No
    // exported receipt or session consumption occurred. Exact retry recovers the
    // retained positive, never a replacement observation or nominated successor.
    let lost = crate::authority_journal::sqlite::recovery::resolve(
        &journal,
        &policy(),
        &review,
        sample().unwrap(),
    )
    .unwrap();
    assert!(journal.begin_clock_observation_session().is_err());
    let replayed = journal.resolve_clock_session(&policy(), &review).unwrap();
    assert_eq!(replayed, lost);
    assert_eq!(journal.load().unwrap(), original);
    assert_eq!(
        journal.receipt(integer(1)).unwrap(),
        Some(
            crate::authority_journal::IssuerPublicationReceipt::from_publication(
                &original.publication
            )
            .unwrap()
        )
    );

    let session = journal.begin_recovered_clock_session(&replayed).unwrap();
    assert!(journal.begin_recovered_clock_session(&replayed).is_err());
    session
        .retain_ceiling(aos_hub_core::storage_authority::lease::LeaseClock {
            observed_at: sample().unwrap(),
            uncertainty: 2,
        })
        .unwrap();
    drop(session);
    assert!(journal.begin_recovered_clock_session(&replayed).is_err());
    assert!(journal.begin_clock_observation_session().is_err());
    let next = journal.inspect_clock_session(&policy()).unwrap();
    assert_eq!(next.expected_session, plan.successor_session);
    assert_ne!(next.successor_session, plan.successor_session);
    assert_eq!(journal.load().unwrap(), original);
}

#[test]
fn changed_review_clock_resource_and_head_refuse_without_a_resolution() {
    let file = Fixture::new();
    let journal = initialize(&file);
    drop(journal.begin_clock_observation_session().unwrap());
    let plan = journal.inspect_clock_session(&policy()).unwrap();
    let review = ClockRecoveryReview::sign(plan.clone(), &policy(), &[37; 32]).unwrap();
    assert!(ClockRecoveryReview::sign(plan.clone(), &policy(), &[38; 32]).is_err());

    let mut changed = review.clone();
    changed.plan.nonce = "a".repeat(64);
    assert!(journal.resolve_clock_session(&policy(), &changed).is_err());
    let mut changed_policy = policy();
    changed_policy.clock_qualification_digest = "8".repeat(64);
    assert!(journal
        .resolve_clock_session(&changed_policy, &review)
        .is_err());
    let mut changed = plan.clone();
    changed.file.inode = "1".into();
    let changed = ClockRecoveryReview::sign(changed, &policy(), &[37; 32]).unwrap();
    assert!(journal.resolve_clock_session(&policy(), &changed).is_err());
    let mut changed = plan.clone();
    changed.expected_head.installation.issuer_resource_id = "other-retained-resource".into();
    let changed = ClockRecoveryReview::sign(changed, &policy(), &[37; 32]).unwrap();
    assert!(journal.resolve_clock_session(&policy(), &changed).is_err());

    let mut expired = plan.clone();
    expired.issued_at = integer(100);
    expired.expires_at = integer(130);
    let expired = ClockRecoveryReview::sign(expired, &policy(), &[37; 32]).unwrap();
    assert!(journal.resolve_clock_session(&policy(), &expired).is_err());
    assert!(validate_observation(&plan, &policy(), plan.issued_at.get() - 1).is_err());
    assert!(validate_observation(&plan, &policy(), i64::MAX).is_err());

    let mut before_cutoff = plan.clone();
    before_cutoff.expected_head.journal.largest_issued_expiry = integer(plan.issued_at.get() + 20);
    assert!(validate_observation(&before_cutoff, &policy(), plan.issued_at.get()).is_err());
    let mut excessive = policy();
    excessive.clock_uncertainty = integer(i64::MAX);
    assert!(excessive.validate().is_err());

    let connection = rusqlite::Connection::open(&file.path).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM clock_resolutions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    assert!(connection
        .execute("UPDATE authority_clock SET session = NULL", [])
        .is_err());
    assert!(connection
        .execute("UPDATE clock_recovery_policy SET policy = X'00'", [])
        .is_err());
}

#[test]
fn used_format_two_recovery_refusal_preserves_exact_file_bytes() {
    let file = Fixture::new();
    let journal = file.initialize();
    let old = journal.begin_clock_observation_session().unwrap();
    old.retain_ceiling(clock(110)).unwrap();
    drop(old);
    let before = std::fs::read(&file.path).unwrap();
    assert!(journal.inspect_clock_session(&policy()).is_err());
    assert!(journal.verify_recovery_policy(Some(&policy())).is_err());
    assert!(journal.begin_clock_observation_session().is_err());
    assert_eq!(std::fs::read(&file.path).unwrap(), before);
    assert_eq!(journal.load().unwrap().journal.clock_floor.get(), 100);
}

#[test]
fn immutable_resolution_and_consumption_refuse_replacement_or_deletion() {
    let file = Fixture::new();
    let journal = initialize(&file);
    drop(journal.begin_clock_observation_session().unwrap());
    let review = ClockRecoveryReview::sign(
        journal.inspect_clock_session(&policy()).unwrap(),
        &policy(),
        &[37; 32],
    )
    .unwrap();
    let receipt = journal.resolve_clock_session(&policy(), &review).unwrap();
    drop(journal.begin_recovered_clock_session(&receipt).unwrap());
    let connection = rusqlite::Connection::open(&file.path).unwrap();
    for sql in [
        "DELETE FROM clock_resolutions",
        "UPDATE clock_resolutions SET receipt = X'00'",
        "INSERT OR REPLACE INTO clock_resolutions SELECT * FROM clock_resolutions",
        "DELETE FROM clock_resolution_consumptions",
        "INSERT OR REPLACE INTO clock_resolution_consumptions SELECT * FROM clock_resolution_consumptions",
        "UPDATE authority_clock SET session = NULL",
    ] {
        assert!(connection.execute(sql, []).is_err(), "{sql}");
    }
    file.reopen().unwrap().load().unwrap();
}

#[test]
fn copied_format_three_file_refuses_inspection_before_any_review() {
    let file = Fixture::new();
    let journal = initialize(&file);
    drop(journal.begin_clock_observation_session().unwrap());
    let before = std::fs::read(&file.path).unwrap();
    let fork = Fixture::new();
    std::fs::copy(&file.path, &fork.path).unwrap();
    let copied = std::fs::read(&fork.path).unwrap();
    assert!(fork.reopen().is_err());
    assert!(AuthorityJournal::open_recovery_existing(
        &fork.path,
        &fork.boundary,
        fork.marker.clone(),
        &policy()
    )
    .is_err());
    assert_eq!(std::fs::read(&fork.path).unwrap(), copied);
    assert_eq!(std::fs::read(&file.path).unwrap(), before);
    journal.inspect_clock_session(&policy()).unwrap();
}
