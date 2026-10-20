//! Executes historical interpretation through real signed native publications.
//!
//! Ordinary operator rows select inputs only. Actual Original records, full
//! history, current controls and native publication independently supply authority.

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{Guard, GuardConfig, HistoryObservation, StagedUpload, ViewSelection};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, RefStore, StoreErrorKind, TokioClock, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;
use terrane_format::auth::IssuerKey;
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::properties::{PropertyName, RootLayer, Value};
use terrane_format::refs::RefRecord;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

#[path = "historical_tests/graft_admission.rs"]
mod graft_admission;

#[tokio::test]
async fn historical_graft_admission_preserves_inert_overrides_through_publication_and_rollback()
-> TestResult {
    graft_admission::preserves_inert_overrides_through_publication_and_rollback().await
}

#[tokio::test]
async fn historical_graft_admission_refuses_untrusted_malformed_and_unauthorized_overrides_before_publication()
-> TestResult {
    graft_admission::refuses_untrusted_malformed_and_unauthorized_overrides_before_publication()
        .await
}

/// Preserves actual native witness failures without converting authority errors.
pub(in crate::guard) type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;
/// Uses the genuine native backend and production metadata validator.
pub(in crate::guard) type Native =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
/// Names the actual live policy authority and publication destination.
pub(in crate::guard) const REFERENCE: &str = "refs/heads/_/historical";

/// Owns actual native location and captured protected Original configuration.
pub(in crate::guard) struct Location {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    keys: Vec<IssuerKey>,
    config: GuardConfig,
    current_snapshot: Vec<u8>,
    /// Retains the genuinely published initial Legacy ref record.
    pub(in crate::guard) baseline: RefRecord,
    /// Names its original root obtained through full signed native verification.
    pub(in crate::guard) baseline_root: Digest,
}

impl Location {
    /// Publishes a real Legacy baseline before changing independently supplied inputs.
    ///
    /// # Errors
    /// Preserves actual admission, publication, Original and physical metadata errors.
    pub(in crate::guard) async fn open() -> TestResult<Self> {
        let native = crate::guard::recorded_native_fixture::fixture(false).await?;
        let mut session = native
            .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
            .await?;
        let baseline = native
            .commit_request(&mut session, crate::ref_advance::tests::request(Vec::new()))
            .await?;
        let guard = native.coordinator().guard();
        let verified = guard.verified_tree(baseline.commit).await?;
        let original = guard.original_commit(&baseline.commit)?;
        let root = guard.store().root().to_owned();
        Ok(Self {
            owner: TokioLocalFs.symlink_metadata(&root).await?.uid(),
            root,
            control: original.baseline().authority().control().to_owned(),
            keys: guard.keys().to_vec(),
            config: guard.config().clone(),
            current_snapshot: crate::guard::recorded_native_fixture::current_snapshot(&native)
                .await?,
            baseline_root: verified.commit.commit().tree,
            baseline,
        })
    }

    /// Reopens the actual backend without creating or repairing protected records.
    ///
    /// # Errors
    /// Preserves incompatible installed inputs and actual native reopen failures.
    ///
    /// # Panics
    /// Panics if the reopened native fixture violates its retained-history assertions.
    pub(in crate::guard) async fn reopen(
        &self,
        revision: u64,
        later: &[&str],
        rows: Vec<ViewSelection>,
    ) -> TestResult<Native> {
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: self.root.clone(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: self.owner,
                    control: None,
                }),
                chunk_profile_name: self.config.chunk_profile_name.clone(),
                chunk_profile: (*self.config.chunk_profile).clone(),
                locality: self.config.home.clone(),
            },
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new((*self.config.chunk_profile).clone()),
        )
        .await?;
        let guard = Guard::new_active(bucket, TokioClock, self.keys.clone(), self.config.clone())
            .with_recorded_authoring(RecordedContext::new(revision, 3, later)?, 1)?
            .with_view_selections(rows)?;
        let timing = CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?;
        let repository = Repository::reopen_native_retention(
            Coordinator::new(guard, timing, TokioLocalFs),
            &DomainNamespace {
                root: self.root.clone(),
                domain: "public".into(),
            },
            &self.control,
            self.owner,
        )
        .await?;
        assert_eq!(
            crate::guard::recorded_native_fixture::current_snapshot(&repository).await?,
            self.current_snapshot
        );
        Ok(repository)
    }

    /// Names an independently captured protected association for missing-Original controls.
    pub(in crate::guard) fn original_path(&self, view: Digest) -> PathBuf {
        self.control.join(format!(
            "commit-{}.cbor",
            view.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    /// Selects the genuine initial Legacy view without applying the authoring profile.
    ///
    /// # Errors
    /// Preserves invalid independent association errors.
    pub(in crate::guard) fn baseline_selection(&self) -> TestResult<ViewSelection> {
        Ok(ViewSelection::new(
            self.baseline.commit,
            self.baseline_root,
            Selection::Legacy,
            1,
        )?)
    }
}

/// Installs exact original roots obtained from actual full signed-history verification.
///
/// # Errors
/// Rejects unsupported independently supplied historical profiles.
pub(in crate::guard) fn selected(
    view: Digest,
    root: Digest,
    revision: u64,
    later: &[&str],
) -> TestResult<ViewSelection> {
    Ok(ViewSelection::new(
        view,
        root,
        Selection::Recorded(RecordedContext::new(revision, 3, later)?),
        1,
    )?)
}

/// Constructs repeated canonical graft occurrences with distinct local retention layers.
///
/// # Errors
/// Preserves actual physical tree construction failures.
pub(in crate::guard) fn graft_request(
    parents: Vec<Digest>,
    domain_overrides: bool,
) -> TestResult<CommitRequest> {
    graft_request_named(parents, domain_overrides, "index-roots")
}

fn graft_request_named(
    parents: Vec<Digest>,
    domain_overrides: bool,
    later_name: &'static str,
) -> TestResult<CommitRequest> {
    let child = Tree::build(
        Vec::new(),
        Some(vec![Property {
            name: later_name,
            value: b"\x00",
        }]),
        262144,
        TreeUse::Ordinary,
    )?;
    let entries = [
        (b"a".as_slice(), b"\x67forever".as_slice()),
        (b"b".as_slice(), b"\x62gc".as_slice()),
    ]
    .into_iter()
    .map(|(key, value)| LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree {
                root: child.root_identity(),
                props: Some(vec![Property {
                    name: if domain_overrides { "domain" } else { "retain" },
                    value: if domain_overrides {
                        if key == b"a" {
                            b"\x66public"
                        } else {
                            b"\x6cprivate:test"
                        }
                    } else {
                        value
                    },
                }]),
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    })
    .collect();
    let root = Tree::build(
        entries,
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut request = crate::ref_advance::tests::request(parents);
    request.commit.tree = root.root_identity();
    request.uploads = [child, root]
        .iter()
        .flat_map(|tree| tree.nodes())
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    Ok(request)
}

#[tokio::test]
async fn historical_root_witnesses_retain_recorded_occurrence_interpretations() -> TestResult {
    let location = Location::open().await?;
    let repository = location
        .reopen(1, &["index-roots"], vec![location.baseline_selection()?])
        .await?;
    let mut session = repository
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let head = repository
        .commit_request(
            &mut session,
            graft_request(vec![location.baseline.commit], false)?,
        )
        .await?;
    let guard = repository.coordinator().guard();
    let verified = guard.verified_tree(head.commit).await?;
    let history = guard.verified_history(head.commit).await?;
    assert_eq!(
        history
            .commit(&head.commit)
            .ok_or("missing genuine signed head")?
            .identity(),
        head.commit
    );
    let semantics =
        guard.historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?;
    assert_eq!(
        semantics,
        Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"])?)
    );
    let mut occurrences = verified.evidence.occurrences(262144)?;
    occurrences.sort_by(|left, right| left.path.cmp(&right.path));
    assert_eq!(
        occurrences
            .iter()
            .map(|item| item.path.as_slice())
            .collect::<Vec<_>>(),
        [b"/".as_slice(), b"/a", b"/b"]
    );
    assert_eq!(occurrences[1].root, occurrences[2].root);
    for (index, expected) in [(1, "forever"), (2, "gc")] {
        let layers = occurrences[index]
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let policy = semantics.resolve(&layers, guard.defaults_for(&verified.evidence))?;
        assert_eq!(
            policy.get(PropertyName::Retain),
            Some(&Value::Text(expected))
        );
        assert!(
            Selection::Recorded(RecordedContext::new(2, 3, &[])?)
                .resolve(&layers, guard.defaults_for(&verified.evidence))
                .is_err()
        );
    }
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head));
    assert!(guard.original_commit(&verified.commit.identity()).is_ok());
    Ok(())
}

#[tokio::test]
async fn historical_root_witnesses_use_one_candidate_interpretation_for_prior_comparison()
-> TestResult {
    let location = Location::open().await?;
    let repository = location
        .reopen(2, &["index-gaps"], vec![location.baseline_selection()?])
        .await?;
    let mut session = repository
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let previous = repository
        .commit_request(
            &mut session,
            graft_request_named(vec![location.baseline.commit], false, "index-gaps")?,
        )
        .await?;
    let previous_tree = repository
        .coordinator()
        .guard()
        .verified_tree(previous.commit)
        .await?;
    let previous_root = previous_tree.commit.commit().tree;
    drop(session);
    drop(repository);
    let repository = location
        .reopen(
            1,
            &["index-roots", "index-gaps"],
            vec![
                location.baseline_selection()?,
                selected(previous.commit, previous_root, 2, &["index-gaps"])?,
            ],
        )
        .await?;
    let mut session = repository
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let candidate = repository
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request(vec![previous.commit]),
        )
        .await?;
    let guard = repository.coordinator().guard();
    let verified = guard.verified_tree(candidate.commit).await?;
    let candidate_semantics =
        guard.historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?;
    assert_eq!(
        candidate_semantics,
        Selection::Recorded(RecordedContext::new(1, 3, &["index-roots", "index-gaps"])?)
    );
    let prior_roots =
        guard.authoring_roots_selected(&previous_tree.evidence, &candidate_semantics)?;
    assert!(prior_roots.iter().any(|(path, _)| path == b"/a"));
    assert!(
        guard
            .authoring_roots_selected(
                &previous_tree.evidence,
                &Selection::Recorded(RecordedContext::new(3, 3, &[])?)
            )
            .is_err()
    );
    let claims = verified
        .commit
        .commit()
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or("missing actual signed scope")?;
    // PROV-31 accepts a witnessed same-domain canonical ancestor claim. The
    // genuine request signs '/', while the actual previous '/a' remains affected.
    assert!(
        claims
            .roots()
            .iter()
            .any(|root| root.path() == b"/" && root.domain() == "public")
    );
    // Full parent execution is separate from the raw prior comparison above.
    let full = guard.verified_history(candidate.commit).await?;
    let plan = terrane_format::provenance::derive_root_changes(
        &full,
        verified.commit.commit(),
        guard.defaults_for(&verified.evidence),
    )?;
    assert!(plan.affected().iter().any(|root| {
        root.path() == b"/a"
            && root.domain() == "public"
            && root.side() == terrane_format::provenance::RootSide::Previous
    }));
    assert!(full.commit(&previous.commit).is_some());
    assert!(guard.original_commit(&previous.commit).is_ok());
    assert!(guard.original_commit(&candidate.commit).is_ok());
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(candidate));
    Ok(())
}

#[tokio::test]
async fn historical_scope_dispatch_preserves_checked_interpretations_and_refusals() -> TestResult {
    let location = Location::open().await?;
    let repository = location
        .reopen(1, &["index-roots"], vec![location.baseline_selection()?])
        .await?;
    let mut session = repository
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let head = repository
        .commit_request(
            &mut session,
            graft_request(vec![location.baseline.commit], false)?,
        )
        .await?;
    let root = repository
        .coordinator()
        .guard()
        .verified_tree(head.commit)
        .await?
        .commit
        .commit()
        .tree;
    let rows = vec![
        location.baseline_selection()?,
        selected(head.commit, root, 1, &["index-roots"])?,
    ];
    drop(session);
    drop(repository);
    let reopened = location.reopen(3, &[], rows.clone()).await?;
    let guard = reopened.coordinator().guard();
    guard
        .read_snapshot(REFERENCE, &crate::ref_advance::tests::token(), b"/a", "sdk")
        .await?;
    guard
        .read_commit_snapshot(
            head.commit,
            &crate::ref_advance::tests::token(),
            b"/b",
            "sdk",
        )
        .await?;
    let mut invalid_token = crate::ref_advance::tests::token();
    let last = invalid_token.last_mut().ok_or("empty actual token")?;
    *last ^= 1;
    assert!(
        guard
            .read_snapshot(REFERENCE, &invalid_token, b"/a", "sdk")
            .await
            .is_err()
    );
    assert!(
        guard
            .read_commit_snapshot(
                head.commit,
                &crate::ref_advance::tests::token(),
                b"/missing",
                "sdk"
            )
            .await
            .is_err()
    );
    let original = location.original_path(head.commit);
    let saved = original.with_extension("held");
    TokioLocalFs.rename(&original, &saved).await?;
    let missing_original = guard.verified_history(head.commit).await;
    TokioLocalFs.rename(&saved, &original).await?;
    assert!(missing_original.is_err());
    guard.verified_history(head.commit).await?;
    let missing = location
        .reopen(3, &[], vec![location.baseline_selection()?])
        .await?;
    assert!(
        missing
            .coordinator()
            .guard()
            .verified_tree(head.commit)
            .await
            .is_err()
    );
    let changed = location
        .reopen(
            3,
            &[],
            vec![
                location.baseline_selection()?,
                selected(head.commit, root, 3, &[])?,
            ],
        )
        .await?;
    assert!(
        changed
            .coordinator()
            .guard()
            .verified_tree(head.commit)
            .await
            .is_err()
    );
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head.clone()));

    // Historical permission never replaces actual current authority. The prior
    // root's administrator may revoke its own grants in an ordinary publication;
    // a zero ACL mask avoids every verb that implies read under AUTH-22.
    let current = location.reopen(1, &["index-roots"], rows).await?;
    let mut session = current
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let denied_head = current
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request_file_acl(
                vec![head.commit],
                b"current read revoked",
                0,
            ),
        )
        .await?;
    let guard = current.coordinator().guard();
    let historical_denial = guard
        .read_commit_snapshot(
            head.commit,
            &crate::ref_advance::tests::token(),
            b"/a",
            "sdk",
        )
        .await
        .err()
        .ok_or("historical read unexpectedly survived current ACL revocation")?;
    let expected_denial = StoreErrorKind::Denied {
        verb: "read",
        pattern: REFERENCE.to_owned(),
    };
    assert_eq!(historical_denial.kind(), &expected_denial);

    let reference_denial = guard
        .read_snapshot(
            REFERENCE,
            &crate::ref_advance::tests::token(),
            b"/file",
            "sdk",
        )
        .await
        .err()
        .ok_or("reference read unexpectedly survived current ACL revocation")?;
    assert_eq!(reference_denial.kind(), &expected_denial);

    // Original verification is independent of the caller's revoked permission.
    // Execute the published revocation's full history, including its signed
    // historical target, without granting the reader fresh authority.
    let history = guard.verified_history(denied_head.commit).await?;
    assert!(history.commit(&denied_head.commit).is_some());
    assert!(history.commit(&head.commit).is_some());
    assert!(guard.original_commit(&head.commit).is_ok());
    assert_eq!(
        current
            .coordinator()
            .guard()
            .store()
            .ref_get(REFERENCE)
            .await?,
        Some(denied_head)
    );
    Ok(())
}
