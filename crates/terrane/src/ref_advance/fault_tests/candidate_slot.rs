//! Pauses an exact genuine candidate slot before its retained authority checks.
//!
//! Selectors observe checked filesystem effects without granting authority or
//! changing their plans. The pause precedes native worker dispatch, so that the
//! actual retained clock and independent policy checks run after its release.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::{PublicationProof, PublicationTransaction};

/// Signals arrival and release of one path-bound retained candidate effect.
pub(in crate::ref_advance) struct CandidateSlotBarrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl CandidateSlotBarrier {
    /// Waits until the exact candidate reaches the pre-dispatch boundary.
    pub(in crate::ref_advance) async fn entered(&self) {
        self.entered.notified().await;
    }

    /// Releases the unchanged effect to its actual retained native checks.
    pub(in crate::ref_advance) fn release(&self) {
        self.release.notify_one();
    }

    /// Signals arrival and waits without retaining a synchronization mutex.
    pub(super) async fn pause(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// Retains a selector until its exact control path, reference and proof match.
pub(super) struct CandidateSlotPause {
    control: PathBuf,
    reference: BucketKey,
    barrier: Arc<CandidateSlotBarrier>,
}

impl CandidateSlotPause {
    /// Creates one inert selector and its shared observation signals.
    pub(super) fn new(control: PathBuf, reference: BucketKey) -> (Self, Arc<CandidateSlotBarrier>) {
        let barrier = Arc::new(CandidateSlotBarrier {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        (
            Self {
                control,
                reference,
                barrier: barrier.clone(),
            },
            barrier,
        )
    }

    /// Requires exact physical control placement and decoded candidate ref evidence.
    pub(super) fn matches(
        &self,
        target: &Path,
        transaction: Option<&PublicationTransaction>,
    ) -> bool {
        target
            .parent()
            .is_some_and(|parent| parent == self.control.join("publication/commits"))
            && transaction.is_some_and(|transaction| {
                matches!(transaction.proof, PublicationProof::Candidate(_))
                    && transaction
                        .changes
                        .iter()
                        .any(|change| change.key == self.reference.as_str())
            })
    }

    /// Consumes only a successfully matched selector into its pending pause.
    pub(super) fn into_barrier(self) -> Arc<CandidateSlotBarrier> {
        self.barrier
    }
}

#[tokio::test]
async fn candidate_slot_pause_reaches_genuine_checked_publication() {
    use super::{
        FaultFs, NativeFixture, TokioLocalFs, configured_with_fs, fixture, request, token,
    };
    use crate::store::LocalFs;
    use std::time::Duration;

    let fs = FaultFs::default();
    let coordinator =
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let root = coordinator.store().root();
    let control = {
        let held = crate::bucket::held::SingleHeld::acquire(coordinator.store())
            .await
            .unwrap();
        let destination = held.destination();
        let observed = destination.observe_publication().await.unwrap();
        let registration = observed
            .physical_reads()
            .first()
            .filter(|read| {
                read.path()
                    .file_name()
                    .is_some_and(|name| name == "backend-registration.cbor")
            })
            .unwrap();
        // The backend's checked physical observation binds the publication
        // control. Original authoring records occupy a different directory.
        registration.path().parent().unwrap().to_owned()
    };
    let mut candidate = None;
    for path in TokioLocalFs
        .read_dir(&control.join("publication/transactions"))
        .await
        .unwrap()
    {
        let bytes = TokioLocalFs.read_nofollow(&path).await.unwrap();
        let transaction = PublicationTransaction::decode(&bytes).unwrap();
        let (selector, _) =
            CandidateSlotPause::new(control.clone(), BucketKey::ref_record(reference).unwrap());
        let target = control.join("publication/commits/1");
        if matches!(transaction.proof, PublicationProof::Candidate(_)) {
            assert!(selector.matches(&target, Some(&transaction)));
            assert!(!selector.matches(&root.join("publication/commits/1"), Some(&transaction)));

            let (other_ref, _) = CandidateSlotPause::new(
                control.clone(),
                BucketKey::ref_record("refs/heads/_/other").unwrap(),
            );
            assert!(!other_ref.matches(&target, Some(&transaction)));
            candidate = Some(transaction);
        } else {
            assert!(!selector.matches(&target, Some(&transaction)));
        }
    }
    assert!(candidate.is_some());

    let barrier = fs.pause_candidate_slot(control, reference).unwrap();
    assert!(fs.pause_candidate_slot(root.to_owned(), reference).is_err());

    let publication = async {
        coordinator
            .advance(&mut session, request(vec![first.commit]))
            .await
            .unwrap()
    };
    let release = async {
        tokio::time::timeout(Duration::from_secs(2), barrier.entered())
            .await
            .unwrap();
        assert!(fs.candidate_slot_pause.lock().unwrap().is_none());
        barrier.release();
    };
    let (second, ()) = tokio::join!(publication, release);
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(session.record(), Some(&second));
}

#[test]
fn candidate_slot_pause_does_not_match_missing_evidence_or_other_control() {
    let (selector, _) = CandidateSlotPause::new(
        PathBuf::from("destination-control"),
        BucketKey::ref_record("refs/heads/_/main").unwrap(),
    );
    assert!(!selector.matches(Path::new("destination-control/publication/commits/1"), None));
    assert!(!selector.matches(Path::new("other-control/publication/commits/1"), None));
}

#[test]
fn current_authority_clock_reuses_exact_retained_state() {
    use crate::store::{Clock, TestClock};
    use std::time::{Duration, SystemTime};

    let source = TestClock::new(100);
    let destination = TestClock::new(100);
    let retained = source.retain_native_clock().unwrap();

    source.set(101, 0);

    assert_eq!(
        retained.now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(101)
    );
    assert_eq!(retained.monotonic(), Duration::ZERO);
    assert_eq!(
        destination.now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(100)
    );
}
