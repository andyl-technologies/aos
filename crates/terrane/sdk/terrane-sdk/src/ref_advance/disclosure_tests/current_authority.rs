//! Checks independently current source and destination authority at publication.
//!
//! Actual protected factories retain separate clocks and issuer keys. Late
//! expiry occurs at the genuine destination candidate slot, before the native
//! worker repeats both authorization decisions; no selected record is edited.

use super::*;
use crate::domain::DomainNamespace;
use crate::ref_advance::fault_tests::FaultFs;
use crate::ref_advance::{
    AdvanceError, CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection,
};
use crate::repository::Repository;
use crate::repository::local_authority::{LocalAuthority, LocalAuthorityParameters};
use crate::store::{InvalidReason, LocalFs, RefStore, StoreErrorKind, TestClock};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use terrane_format::auth::{
    Attenuation, Authority, Caveat, Grant, Token, Verb, Verbs, public_key_from_secret,
};
use terrane_format::identity::Identity;
use terrane_format::refs::{PrincipalKind, RefRecord};

const REFERENCE: &str = "refs/heads/_/main";
const PLAINTEXT: &[u8] = b"current authority is independent of original authoring evidence";
const START: u64 = 1000;
const EXPIRES: u64 = 1100;

/// Names the retained native repository used for current-authority witnesses.
pub(super) type NativeRepository =
    Repository<FileBucket<FaultFs, TokioClock, Validator>, TestClock, FaultFs>;

/// Owns an independently initialized repository and its genuine authority inputs.
pub(super) struct Factory {
    /// Retains the repository's original evidence and protected publication binding.
    pub(super) repository: NativeRepository,
    /// Supplies this physical repository's issuer key, capability and signing secret.
    pub(super) authority: LocalAuthority,
    /// Observes and pauses genuine filesystem publication effects.
    pub(super) fs: FaultFs,
    /// Supplies the independently controlled authorization clock.
    pub(super) clock: TestClock,
    /// Selects the private or public domain used by proposed fixture trees.
    pub(super) private: bool,
}

impl Factory {
    /// Initializes an independent native factory in the selected disclosure domain.
    ///
    /// # Panics
    /// Panics if fixture setup, secure randomness, credentials, bucket opening or
    /// protected original-retention initialization fails.
    pub(super) async fn initialize(private: bool) -> Self {
        let raw = raw_fixture().await;
        let root = raw.store().root().to_owned();
        let mut policy = raw.guard().config().clone();
        let domain = if private { "private:writer" } else { "public" };
        policy.storage_domain = domain.into();
        drop(raw);
        let credentials = root.with_file_name(format!(
            "{}-current-credentials",
            root.file_name().unwrap().to_string_lossy()
        ));
        let owner = TokioLocalFs.metadata(&root).await.unwrap().uid();
        let authority = LocalAuthority::initialize(
            &TokioLocalFs,
            &root,
            &credentials,
            LocalAuthorityParameters {
                owner_uid: owner,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "writer".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id: TokioLocalFs
                        .random_bytes(16)
                        .await
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                    workload: None,
                },
            },
        )
        .await
        .unwrap();
        let fs = FaultFs::default();
        let clock = TestClock::new(START);
        let bucket = FileBucket::open(
            config(root.clone()).await,
            fs.clone(),
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        let coordinator = Coordinator::new(
            Guard::new(
                bucket,
                clock.clone(),
                vec![authority.issuer_key().clone()],
                policy,
            ),
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .unwrap(),
            fs.clone(),
        );
        let original = root.with_file_name(format!(
            "{}-original-control",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs.create_dir_new(&original).await.unwrap();
        fs.set_permissions_and_sync(&original, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let repository = Repository::initialize_native_retention(
            coordinator,
            &DomainNamespace {
                root,
                domain: domain.into(),
            },
            &original,
            owner,
        )
        .await
        .unwrap();
        Self {
            repository,
            authority,
            fs,
            clock,
            private,
        }
    }

    /// Borrows the coordinator belonging to this retained native repository.
    pub(super) fn coordinator(
        &self,
    ) -> &Coordinator<FileBucket<FaultFs, TokioClock, Validator>, TestClock, FaultFs> {
        self.repository.coordinator()
    }

    /// Stages a file proposal with the requested parents and fixture root ACL.
    ///
    /// # Panics
    /// Panics if the ACL mask is unsupported or tree construction, identity
    /// calculation or staged metadata validation fails.
    pub(super) fn proposal(
        &self,
        parents: Vec<[u8; 32]>,
        verbs: u8,
    ) -> super::super::CommitRequest {
        let tree = tree(verbs, self.private);
        let staged = materialization::stage_tree(request_file(parents, PLAINTEXT), &tree);
        let mut proposal = self.authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        proposal
    }

    /// Resolves publication control from the actual held backend registration.
    ///
    /// # Panics
    /// Panics if exclusion or observation fails, the registration is absent or
    /// its physical path does not name `backend-registration.cbor`.
    pub(super) async fn control(&self) -> PathBuf {
        let held = crate::bucket::held::SingleHeld::acquire(self.coordinator().store())
            .await
            .unwrap();
        let destination = held.destination();
        let observed = destination.observe_publication().await.unwrap();
        let registration = observed.physical_reads().first().unwrap();
        assert_eq!(
            registration.path().file_name().unwrap(),
            "backend-registration.cbor"
        );
        registration.path().parent().unwrap().to_owned()
    }
}

fn tree(verbs: u8, private: bool) -> Tree<'static> {
    tree_with_mode(verbs, private, 0o644)
}

fn tree_with_mode(verbs: u8, private: bool, mode: u16) -> Tree<'static> {
    let acl: &'static [u8] = match verbs {
        31 => b"\x81\x82\x66writer\x18\x1f",
        15 => b"\x81\x82\x66writer\x0f",
        1 => b"\x81\x82\x66writer\x01",
        0 => b"\x81\x82\x67another\x18\x1f",
        _ => panic!("unsupported fixture grant"),
    };
    let properties = vec![
        Property {
            name: "acl",
            value: acl,
        },
        Property {
            name: "domain",
            value: if private {
                b"\x6eprivate:writer"
            } else {
                b"\x66public"
            },
        },
    ];
    Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode,
                    size: PLAINTEXT.len() as u64,
                    content: ContentRef::Inline(
                        TERRANE_V1
                            .calculate(IdentityKind::Chunk, PLAINTEXT)
                            .unwrap()
                            .terrane_v1_digest()
                            .unwrap(),
                    ),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(properties),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

/// Derives a genuine narrower capability and verifies it at the fixture start time.
///
/// # Panics
/// Panics if proposal construction, token decoding, attenuation or verification
/// fails.
pub(super) fn attenuate(factory: &Factory, caveat: Caveat) -> Vec<u8> {
    let proposal = factory.proposal(Vec::new(), 31);
    let secret = proposal.terminal_secret;
    let token = Token::decode(factory.authority.token())
        .unwrap()
        .attenuate(
            Attenuation {
                caveats: vec![caveat],
                ..Attenuation::default()
            },
            &secret,
            public_key_from_secret(&secret),
        )
        .unwrap();
    token
        .verify(std::slice::from_ref(factory.authority.issuer_key()), START)
        .unwrap();
    token.encode()
}

fn request(
    commit: [u8; 32],
    proposal: super::super::CommitRequest,
    token: Vec<u8>,
) -> DisclosureCommitRequest {
    DisclosureCommitRequest {
        proposal,
        selections: vec![DisclosureCommitSelection {
            source_reference: REFERENCE.into(),
            source_commit: commit,
            source_path: b"/file".to_vec(),
            source_token: token,
            destination_path: b"/file".to_vec(),
        }],
    }
}

fn assert_denied(result: Result<RefRecord, AdvanceError>, verb: &'static str, witness: &str) {
    assert!(
        matches!(&result, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { verb: actual, pattern } if *actual == verb && pattern == REFERENCE)),
        "{witness}: expected current {verb} denial for {REFERENCE}, observed {result:?}"
    );
}

// A distinct metadata candidate witnesses refusal before upload even when its
// ACL is unchanged and the original file bytes already exist in the destination.
fn denied_proposal(
    destination: &Factory,
    parent: [u8; 32],
    verbs: u8,
) -> (CommitRequest, Identity) {
    let candidate = tree_with_mode(verbs, destination.private, 0o600);
    let node = TERRANE_V1
        .calculate(IdentityKind::Node, candidate.root().encoded())
        .unwrap();
    let staged = materialization::stage_tree(request_file(vec![parent], PLAINTEXT), &candidate);
    let mut proposal = destination
        .authority
        .commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    (proposal, node)
}

async fn late_expiry(source_expires: bool) {
    let source = Factory::initialize(true).await;
    let destination = Factory::initialize(false).await;
    assert_ne!(
        source.authority.issuer_key().public_key,
        destination.authority.issuer_key().public_key
    );
    let mut source_session = source
        .coordinator()
        .begin(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .repository
        .commit_request(&mut source_session, source.proposal(Vec::new(), 31))
        .await
        .unwrap();
    let mut target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let before = target.record().cloned();
    let previous_epoch = before.as_ref().map_or(0, |head| head.writer_epoch);
    let mut proposal = destination.proposal(Vec::new(), 31);
    let source_token = if source_expires {
        attenuate(&source, Caveat::Before(EXPIRES))
    } else {
        source.authority.token().to_vec()
    };
    if !source_expires {
        proposal.token = attenuate(&destination, Caveat::Before(EXPIRES));
    }
    let barrier = destination
        .fs
        .pause_candidate_slot(destination.control().await, REFERENCE)
        .unwrap();
    let (rejected, competing_head) = {
        let publication = destination.coordinator().advance_disclosure(
            source.coordinator().guard(),
            &mut target,
            request(source_head.commit, proposal, source_token),
        );
        tokio::pin!(publication);
        // This real-runtime bound observes complete paired preparation only.
        // The authenticated clock and production publication limits are separate.
        let event_started = crate::diagnostic_clock::tick();
        tokio::select! {
            arrived = tokio::time::timeout(Duration::from_secs(15), barrier.entered()) => {
                arrived.unwrap();
                eprintln!(
                    "candidate slot source_expiry={source_expires} arrived after {:?}",
                    crate::diagnostic_clock::elapsed(event_started)
                );
            }
            completed = &mut publication => {
                panic!("genuine publication completed before the armed slot: {completed:?}");
            }
        }
        let coordination = async {
            let competitor = async {
                if source_expires {
                    source
                        .repository
                        .commit_request(
                            &mut source_session,
                            source.proposal(vec![source_head.commit], 1),
                        )
                        .await
                        .unwrap()
                } else {
                    let mut writer = destination
                        .coordinator()
                        .begin(REFERENCE, destination.authority.token(), "sdk")
                        .await
                        .unwrap();
                    destination
                        .repository
                        .commit_request(&mut writer, destination.proposal(Vec::new(), 15))
                        .await
                        .unwrap()
                }
            };
            tokio::pin!(competitor);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut competitor)
                    .await
                    .is_err(),
                "a real competing ACL/head/epoch transition must remain excluded"
            );
            if source_expires {
                source.clock.set(EXPIRES, 0);
            } else {
                destination.clock.set(EXPIRES, 0);
            }
            barrier.release();
            competitor.await
        };
        tokio::join!(publication, coordination)
    };
    assert_denied(
        rejected,
        if source_expires { "read" } else { "commit" },
        if source_expires {
            "late source expiry at Candidate slot"
        } else {
            "late destination expiry at Candidate slot"
        },
    );
    assert_eq!(target.record(), before.as_ref());
    let expected = if source_expires {
        before
    } else {
        Some(competing_head.clone())
    };
    assert_eq!(
        destination
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        expected
    );
    if source_expires {
        assert_ne!(competing_head.commit, source_head.commit);
        assert_eq!(competing_head.writer_epoch, source_head.writer_epoch);
    } else {
        assert!(competing_head.writer_epoch > previous_epoch);
    }
    // A fresh genuine token remains valid at the advanced clock; the expired
    // attenuated token is neither renewed nor made valid by moving time backward.
    let mut fresh = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let parents = fresh
        .record()
        .map(|head| vec![head.commit])
        .unwrap_or_default();
    let control = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut fresh,
            request(
                source_head.commit,
                destination.proposal(parents, if source_expires { 31 } else { 15 }),
                source.authority.token().to_vec(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(fresh.record(), Some(&control));
}

async fn fresh_authority() {
    let source = Factory::initialize(true).await;
    let destination = Factory::initialize(false).await;
    let mut author = source
        .coordinator()
        .begin(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let original = source
        .repository
        .commit_request(&mut author, source.proposal(Vec::new(), 31))
        .await
        .unwrap();
    let mut next_author = source
        .coordinator()
        .begin(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let current = source
        .repository
        .commit_request(&mut next_author, source.proposal(vec![original.commit], 31))
        .await
        .unwrap();
    assert_ne!(current.commit, original.commit);
    assert!(current.writer_epoch > original.writer_epoch);

    let mut target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let baseline = destination
        .repository
        .commit_request(&mut target, destination.proposal(Vec::new(), 31))
        .await
        .unwrap();
    let mut independent_writer = target.clone();
    let advanced = destination
        .repository
        .commit_request(
            &mut independent_writer,
            destination.proposal(vec![baseline.commit], 31),
        )
        .await
        .unwrap();
    assert_eq!(advanced.writer_epoch, baseline.writer_epoch);
    assert_eq!(advanced.seq, baseline.seq + 1);
    assert_ne!(advanced.commit, baseline.commit);
    // Admission receives the actual current parent; only the independently
    // retained expected whole head is stale, rather than its provenance inputs.
    let stale = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut target,
            request(
                original.commit,
                destination.proposal(vec![advanced.commit], 15),
                source.authority.token().to_vec(),
            ),
        )
        .await;
    assert!(
        matches!(&stale, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))),
        "stale whole-head result: {stale:?}"
    );
    assert_eq!(target.record(), Some(&baseline));
    assert_eq!(
        destination
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(advanced.clone())
    );
    let baseline = advanced;
    target = independent_writer;
    source.clock.set(EXPIRES, 0);
    destination.clock.set(EXPIRES, 0);
    // AUTH-22 makes Admin imply Commit. A genuine Commit-only token can publish
    // an unchanged ACL, but cannot authorize the separate ACL edit below.
    let commit_only = attenuate(&destination, Caveat::Verb(Verbs::new(15).unwrap()));
    destination
        .coordinator()
        .guard()
        .authorize(REFERENCE, &commit_only, Verb::Commit, &[], "sdk")
        .await
        .unwrap();

    // ACL edits check Admin before affected-root Commit. Keep those exact
    // refusals alongside unchanged-ACL attempts that reach Commit independently.
    // Expired destination tokens fail initial Commit authentication first.
    let cases = [
        (true, Caveat::Before(EXPIRES), 15, "read"),
        (false, Caveat::Before(EXPIRES), 15, "commit"),
        (
            true,
            Caveat::Epoch(REFERENCE.into(), original.writer_epoch),
            15,
            "read",
        ),
        (
            false,
            Caveat::Epoch(REFERENCE.into(), baseline.writer_epoch - 1),
            15,
            "admin",
        ),
        (
            false,
            Caveat::Epoch(REFERENCE.into(), baseline.writer_epoch - 1),
            31,
            "commit",
        ),
        (true, Caveat::Root("/file".into()), 15, "read"),
        (false, Caveat::Root("/file".into()), 15, "admin"),
        (false, Caveat::Root("/file".into()), 31, "commit"),
        (true, Caveat::Ref("refs/heads/_/other".into()), 15, "read"),
        (false, Caveat::Verb(Verbs::new(1).unwrap()), 15, "admin"),
        (false, Caveat::Verb(Verbs::new(1).unwrap()), 31, "commit"),
        (false, Caveat::Verb(Verbs::new(15).unwrap()), 15, "admin"),
    ];
    for (source_denial, caveat, candidate_acl, denied_verb) in cases {
        let witness = format!(
            "fresh {} authority, caveat {caveat:?}, candidate ACL {candidate_acl}",
            if source_denial {
                "source"
            } else {
                "destination"
            }
        );
        let narrowed = attenuate(if source_denial { &source } else { &destination }, caveat);
        let (mut proposal, denied_node) =
            denied_proposal(&destination, baseline.commit, candidate_acl);
        let source_token = if source_denial {
            narrowed
        } else {
            proposal.token = narrowed;
            source.authority.token().to_vec()
        };
        let rejected = destination
            .coordinator()
            .advance_disclosure(
                source.coordinator().guard(),
                &mut target,
                request(original.commit, proposal, source_token),
            )
            .await;
        assert_denied(rejected, denied_verb, &witness);
        assert_eq!(target.record(), Some(&baseline));
        assert_eq!(
            destination
                .coordinator()
                .store()
                .ref_get(REFERENCE)
                .await
                .unwrap(),
            Some(baseline.clone())
        );
        assert_eq!(
            source
                .coordinator()
                .store()
                .ref_get(REFERENCE)
                .await
                .unwrap(),
            Some(current.clone())
        );
        assert_eq!(
            destination
                .coordinator()
                .store()
                .has(std::slice::from_ref(&denied_node))
                .await
                .unwrap(),
            [false]
        );
    }
    // The selected immutable source predates the independently current read head.
    // A valid current pair must still certify that exact historical selection.
    let mut proposal = destination.proposal(vec![baseline.commit], 31);
    proposal.token = commit_only;
    let accepted = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut target,
            request(original.commit, proposal, source.authority.token().to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(target.record(), Some(&accepted));

    let alternative = Factory::initialize(false).await;
    let mut alternative_target = alternative
        .coordinator()
        .begin(REFERENCE, alternative.authority.token(), "sdk")
        .await
        .unwrap();
    let alternative_head = alternative
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut alternative_target,
            request(
                original.commit,
                alternative.proposal(Vec::new(), 31),
                source.authority.token().to_vec(),
            ),
        )
        .await
        .unwrap();
    let closed_destination = destination
        .repository
        .commit_request(&mut target, destination.proposal(vec![accepted.commit], 1))
        .await
        .unwrap();
    // The actual current root permits Read alone. An ACL edit is refused as
    // Admin; retaining that ACL independently exposes its Commit refusal.
    for (candidate_acl, denied_verb) in [(31, "admin"), (1, "commit")] {
        let (proposal, denied_node) =
            denied_proposal(&destination, closed_destination.commit, candidate_acl);
        let rejected = destination
            .coordinator()
            .advance_disclosure(
                source.coordinator().guard(),
                &mut target,
                request(original.commit, proposal, source.authority.token().to_vec()),
            )
            .await;
        assert_denied(
            rejected,
            denied_verb,
            &format!("closed current destination root, candidate ACL {candidate_acl}"),
        );
        assert_eq!(target.record(), Some(&closed_destination));
        assert_eq!(
            destination
                .coordinator()
                .store()
                .ref_get(REFERENCE)
                .await
                .unwrap(),
            Some(closed_destination.clone())
        );
        assert_eq!(
            source
                .coordinator()
                .store()
                .ref_get(REFERENCE)
                .await
                .unwrap(),
            Some(current.clone())
        );
        assert_eq!(
            destination
                .coordinator()
                .store()
                .has(std::slice::from_ref(&denied_node))
                .await
                .unwrap(),
            [false]
        );
    }

    let closed_source = source
        .repository
        .commit_request(&mut next_author, source.proposal(vec![current.commit], 0))
        .await
        .unwrap();
    assert_ne!(closed_source.commit, current.commit);
    let (proposal, denied_node) = denied_proposal(&alternative, alternative_head.commit, 15);
    let rejected = alternative
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut alternative_target,
            request(original.commit, proposal, source.authority.token().to_vec()),
        )
        .await;
    assert_denied(rejected, "read", "closed current source root");
    assert_eq!(alternative_target.record(), Some(&alternative_head));
    assert_eq!(
        alternative
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(alternative_head)
    );
    assert_eq!(
        source
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(closed_source)
    );
    assert_eq!(
        alternative
            .coordinator()
            .store()
            .has(std::slice::from_ref(&denied_node))
            .await
            .unwrap(),
        [false]
    );
}

/// Checks independent current heads, tokens, epochs and root ACLs during disclosure.
///
/// # Panics
/// Panics if authenticated setup fails, a late expiry publishes, a competing
/// transition bypasses exclusion, a refusal has the wrong verb or changes a head,
/// rejected metadata is uploaded, or a valid current pair is refused.
pub(super) async fn recheck_current_authority() {
    late_expiry(true).await;
    late_expiry(false).await;
    fresh_authority().await;
}
