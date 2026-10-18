//! Journal replay tests for per-destination journals.

use super::*;
use crate::verify::{verify_journal, verify_journal_for_plan};

/// Appends hash-chained entries with continuous prior states.
struct Journal {
    plan_digest: Sha256Digest,
    entries: Vec<JournalEntry>,
}

impl Journal {
    fn new(plan_digest: Sha256Digest) -> Self {
        Self {
            plan_digest,
            entries: Vec::new(),
        }
    }

    fn summary(&self) -> JournalSummary {
        verify_journal(&self.entries).unwrap()
    }

    /// Appends an entry whose prior state is the replayed expectation.
    fn push(&mut self, new_state: ReleaseState, destination: Option<&str>) -> &mut Self {
        let prior_state = (!self.entries.is_empty()).then(|| {
            let probe = self.entry(new_state, destination, None);
            self.summary().expected_prior(&probe)
        });
        let entry = self.entry(new_state, destination, prior_state);
        self.entries.push(entry);
        self
    }

    fn entry(
        &self,
        new_state: ReleaseState,
        destination: Option<&str>,
        prior_state: Option<ReleaseState>,
    ) -> JournalEntry {
        JournalEntry {
            schema_version: crate::RELEASE_JOURNAL_ENTRY.to_owned(),
            sequence: u64::try_from(self.entries.len()).unwrap() + 1,
            previous_entry_digest: self.entries.last().map(|entry| entry.digest().unwrap()),
            plan_digest: self.plan_digest,
            manifest_digest: (new_state >= ReleaseState::Finalized
                && new_state != ReleaseState::Failed)
                .then(|| Sha256Digest::of_bytes("manifest")),
            prior_state,
            new_state,
            destination: destination.map(str::to_owned),
            operation_ids: Vec::new(),
            evidence: Vec::new(),
            recorded_at: "2026-09-03T00:00:00Z".to_owned(),
        }
    }

    /// Returns the journal with one more entry, without checking it.
    fn with(&self, entry: JournalEntry) -> Vec<JournalEntry> {
        let mut entries = self.entries.clone();
        entries.push(entry);
        entries
    }

    fn finalized(plan_digest: Sha256Digest) -> Self {
        let mut journal = Self::new(plan_digest);
        journal
            .push(ReleaseState::Planned, None)
            .push(ReleaseState::Built, None)
            .push(ReleaseState::Finalized, None);
        journal
    }
}

fn plan_digest() -> Sha256Digest {
    Sha256Digest::of_bytes("plan")
}

#[test]
fn destinations_interleave_after_finalization() {
    let mut journal = Journal::finalized(plan_digest());
    journal
        .push(ReleaseState::Published, Some("staging/candidate"))
        .push(ReleaseState::Published, Some("staging/stable"))
        .push(ReleaseState::Published, Some("production/candidate"))
        .push(ReleaseState::Rolling, Some("production/candidate"))
        .push(ReleaseState::Published, Some("production/stable"))
        .push(ReleaseState::Rolling, Some("production/candidate"))
        .push(ReleaseState::Rolling, Some("production/stable"))
        .push(ReleaseState::Complete, Some("production/candidate"));

    let summary = journal.summary();
    assert_eq!(summary.global, ReleaseState::Finalized);
    assert_eq!(
        summary.state_of("production/candidate"),
        Some(ReleaseState::Complete)
    );
    assert_eq!(
        summary.state_of("production/stable"),
        Some(ReleaseState::Rolling)
    );
    assert_eq!(
        summary.state_of("staging/stable"),
        Some(ReleaseState::Published)
    );
    assert_eq!(summary.state_of("staging/edge"), None);
    summary
        .require_rolling_allowed("production/stable")
        .unwrap();
    assert!(
        summary
            .require_rolling_allowed("production/candidate")
            .is_err()
    );
    assert!(summary.require_rolling_allowed("staging/edge").is_err());

    // Completed and published destinations cannot move backwards or skip.
    let complete = journal.entry(
        ReleaseState::Rolling,
        Some("production/candidate"),
        Some(ReleaseState::Complete),
    );
    assert!(verify_journal(&journal.with(complete)).is_err());
    let skip = journal.entry(
        ReleaseState::Complete,
        Some("staging/stable"),
        Some(ReleaseState::Published),
    );
    assert!(verify_journal(&journal.with(skip)).is_err());
    let again = journal.entry(
        ReleaseState::Published,
        Some("staging/stable"),
        Some(ReleaseState::Published),
    );
    assert!(verify_journal(&journal.with(again)).is_err());

    // A failure is terminal for every destination.
    journal.push(ReleaseState::Failed, None);
    assert!(journal.summary().is_failed());
    let after_failure = journal.entry(
        ReleaseState::Rolling,
        Some("production/stable"),
        Some(ReleaseState::Rolling),
    );
    assert!(verify_journal(&journal.with(after_failure)).is_err());
}

#[test]
fn production_destinations_follow_a_staging_publication() {
    let journal = Journal::finalized(plan_digest());
    let early = journal.entry(
        ReleaseState::Published,
        Some("production/stable"),
        Some(ReleaseState::Finalized),
    );
    assert!(verify_journal(&journal.with(early)).is_err());

    let before_finalization = Journal::new(plan_digest());
    let mut built = before_finalization;
    built
        .push(ReleaseState::Planned, None)
        .push(ReleaseState::Built, None);
    let premature = built.entry(
        ReleaseState::Published,
        Some("staging/stable"),
        Some(ReleaseState::Built),
    );
    assert!(verify_journal(&built.with(premature)).is_err());
}

#[test]
fn entries_reject_malformed_destinations_and_unknown_schemas() {
    let journal = Journal::finalized(plan_digest());
    let finalized = Some(ReleaseState::Finalized);
    for entry in [
        journal.entry(ReleaseState::Published, None, finalized),
        journal.entry(ReleaseState::Failed, Some("staging/stable"), finalized),
        journal.entry(ReleaseState::Published, Some("staging"), finalized),
        journal.entry(ReleaseState::Published, Some("staging/nightly"), finalized),
        journal.entry(
            ReleaseState::Published,
            Some("staging/stable"),
            Some(ReleaseState::Built),
        ),
    ] {
        assert!(verify_journal(&journal.with(entry)).is_err());
    }
    let mut unknown = journal.entry(ReleaseState::Failed, None, finalized);
    unknown.schema_version = "aos.release.journal-entry/v0".to_owned();
    assert!(verify_journal(&journal.with(unknown)).is_err());
}

#[test]
fn can_publish_follows_the_plan_and_contract_after_roles() -> anyhow::Result<()> {
    let (plan, _) = crate::verify::tests::qualification_fixture()?;
    let digest = Sha256Digest::of_bytes(crate::canonical::to_vec(&plan)?);
    let mut journal = Journal::new(digest);
    journal.push(ReleaseState::Planned, None);
    assert!(
        journal
            .summary()
            .can_publish(&plan, "staging/stable")
            .is_err()
    );
    journal
        .push(ReleaseState::Built, None)
        .push(ReleaseState::Finalized, None);

    let summary = journal.summary();
    summary.can_publish(&plan, "staging/stable")?;
    assert!(summary.can_publish(&plan, "production/stable").is_err());
    assert!(summary.can_publish(&plan, "production/edge").is_err());

    journal.push(ReleaseState::Published, Some("staging/stable"));
    let summary = journal.summary();
    summary.can_publish(&plan, "production/stable")?;
    assert!(summary.can_publish(&plan, "staging/stable").is_err());
    assert!(!summary.is_complete(&plan));
    verify_journal_for_plan(&plan, &journal.entries)?;

    for name in plan
        .destinations
        .iter()
        .map(|destination| destination.name.clone())
    {
        if journal.summary().state_of(&name).is_none() {
            journal.push(ReleaseState::Published, Some(&name));
        }
        journal
            .push(ReleaseState::Rolling, Some(&name))
            .push(ReleaseState::Complete, Some(&name));
    }
    assert!(journal.summary().is_complete(&plan));
    verify_journal_for_plan(&plan, &journal.entries)?;

    let unplanned = Journal::finalized(digest);
    let mut unplanned = unplanned;
    unplanned.push(ReleaseState::Published, Some("staging/edge"));
    assert!(verify_journal_for_plan(&plan, &unplanned.entries).is_err());

    let failed = {
        let mut journal = Journal::finalized(digest);
        journal.push(ReleaseState::Failed, None);
        journal.summary()
    };
    assert!(failed.can_publish(&plan, "staging/stable").is_err());
    Ok(())
}
