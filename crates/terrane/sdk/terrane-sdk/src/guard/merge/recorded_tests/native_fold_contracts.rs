//! Executes trust-sensitive native folds with retained incoming changes.
//!
//! Signed publications and protected Originals establish every input. Fresh
//! repositories independently select their historical meanings before recipe
//! replay; decoded contexts and domain labels never configure those callers.

use super::SOURCE;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::merge::{Forest, MergeOperation, PreparedMerge, bind_occurrence_domains};
use crate::guard::view_selection::historical_tests::{Native, REFERENCE, TestResult, selected};
use crate::guard::{
    Guard, GuardConfig, HistoryObservation, StagedUpload, TreeEvidence, ViewSelection,
};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, RefStore, TokioClock, TokioLocalFs};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use terrane_format::algebra::{self, OperationDomains, Recipe};
use terrane_format::auth::IssuerKey;
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::provenance::{Preset, Selector};
use terrane_format::refs::{CommitSource, RefRecord};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

const MINIMUM: u64 = 262144;
const ACL: &[u8] = b"\x81\x82\x66writer\x18\x1f";
const BUILT_TRUST: &[u8] = b"\x82\x66source\x65built";
const POLICIES: &[terrane_format::refs::MergePolicy] = &[
    terrane_format::refs::MergePolicy::PreferTrusted,
    terrane_format::refs::MergePolicy::KeepConflict,
];

/// Inspects all independently selected context coordinates using primitives.
fn assert_context(
    bytes: &[u8],
    view: Digest,
    root: Digest,
    revision: u64,
    domain: &str,
) -> TestResult {
    let mut decoder = terrane_format::cbor::Decoder::new(bytes);
    assert_eq!(decoder.array(8)?, 8);
    assert_eq!(decoder.uint()?, 3);
    assert_eq!(decoder.bytes(32)?, view);
    assert_eq!(decoder.text(128)?, domain);
    decoder.skip_value(MINIMUM as usize)?;
    assert_eq!(decoder.simple()?, 0xf6);
    assert_eq!(decoder.uint()?, MINIMUM);
    decoder.skip_value(MINIMUM as usize)?;
    assert_eq!(decoder.array(4)?, 4);
    assert_eq!(decoder.bytes(32)?, root);
    assert_eq!(decoder.uint()?, revision);
    let selected = RecordedContext::new(revision, 3, &[])?;
    let names = selected.behavioral_names().collect::<Vec<_>>();
    assert_eq!(decoder.array(64)?, names.len());
    for name in names {
        assert_eq!(decoder.text(128)?, name);
    }
    assert_eq!(decoder.array(64)?, 0);
    decoder.finish()?;
    Ok(())
}

/// Checks the actual preprocessing schema, including its optional domain field.
fn assert_preprocessing(
    bytes: &[u8],
    inputs: &SignedInputs,
    filtered: Digest,
    contexts: &[terrane_format::provenance::TrustContext],
    preserved: Option<&[u8]>,
) -> TestResult {
    let mut decoder = terrane_format::cbor::Decoder::new(bytes);
    assert_eq!(decoder.map(3)?, 3);
    assert_eq!(decoder.uint()?, 1);
    assert_eq!(decoder.text(32)?, "merge");
    assert_eq!(decoder.uint()?, 2);
    assert_eq!(decoder.array(3)?, 3);
    for root in [inputs.roots[0], inputs.roots[1], filtered] {
        assert_eq!(decoder.bytes(32)?, root);
    }
    assert_eq!(decoder.uint()?, 3);
    assert_eq!(decoder.map(3)?, 3);
    assert_eq!(decoder.text(32)?, "trust");
    assert_eq!(decoder.map(4)?, 4);
    assert_eq!(decoder.uint()?, 1);
    decoder.skip_value(MINIMUM as usize)?;
    assert_eq!(decoder.uint()?, 2);
    assert_eq!(decoder.text(128)?, "terrane-verified-path/v1");
    assert_eq!(decoder.uint()?, 3);
    assert_eq!(decoder.array(2)?, 2);
    assert_eq!(decoder.array(2)?, 2);
    for context in contexts {
        assert_eq!(
            decoder.bytes(MINIMUM as usize)?,
            context.canonical_context()
        );
    }
    assert_eq!(decoder.array(5)?, 4 + usize::from(preserved.is_some()));
    assert_eq!(decoder.bytes(32)?, inputs.roots[0]);
    assert_eq!(decoder.bytes(32)?, inputs.roots[2]);
    assert_eq!(decoder.bytes(32)?, filtered);
    assert_eq!(decoder.array(1)?, 1);
    assert_eq!(decoder.bytes(128)?, b"excluded");
    if let Some(encoded) = preserved {
        let mut expected = terrane_format::cbor::Decoder::new(encoded);
        assert_eq!(decoder.text(128)?, expected.text(128)?);
        expected.finish()?;
    }
    assert_eq!(decoder.uint()?, 4);
    assert_eq!(decoder.array(0)?, 0);
    assert_eq!(decoder.text(32)?, "policy");
    assert_eq!(decoder.array(2)?, 2);
    assert_eq!(decoder.text(32)?, "prefer-trusted");
    assert_eq!(decoder.text(32)?, "keep-conflict");
    assert_eq!(decoder.text(32)?, "domains");
    decoder.skip_value(MINIMUM as usize)?;
    decoder.finish()?;
    Ok(())
}

/// Owns a real backend and its independent protected retention configuration.
struct NativeLocation {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    keys: Vec<IssuerKey>,
    config: GuardConfig,
    snapshot: Vec<u8>,
}

impl NativeLocation {
    /// Initializes the actual retention factory for one explicit routing domain.
    async fn open(domain: &str) -> TestResult<(Self, Native)> {
        let nonce = TokioLocalFs.random_bytes(16).await?;
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("terrane-native-fold-{suffix}"));
        let operator = root.with_file_name(format!("terrane-native-fold-operator-{suffix}"));
        let control = root.with_file_name(format!("terrane-native-fold-original-{suffix}"));
        for directory in [&operator, &control] {
            TokioLocalFs.create_dir_new(directory).await?;
            TokioLocalFs
                .set_permissions_and_sync(directory, std::fs::Permissions::from_mode(0o700))
                .await?;
        }
        let owner = TokioLocalFs.symlink_metadata(&operator).await?.uid();
        let config = GuardConfig {
            store_name: "local".into(),
            private_domain: "private:test".into(),
            home: terrane_format::refs::Locality::default(),
            initial_acl: vec![("writer".into(), 31)],
            min_chunk_size: MINIMUM,
            storage_domain: domain.into(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: Box::new(terrane_format::chunking::ChunkProfile::cdc_1m([0; 32])),
            policy_authority: None,
        };
        // This is the independently configured issuer used by the native token
        // fixture, not a key recovered from a serialized commit claim.
        let keys = vec![IssuerKey {
            issuer: "test".into(),
            key_id: "key".into(),
            public_key: [
                215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225,
                114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
            ],
            retirement: None,
        }];
        let store = Self::open_store(&root, owner, &config).await?;
        let guard = Guard::new_active(store, TokioClock, keys.clone(), config.clone())
            .with_legacy_authoring()?;
        let timing = Self::timing()?;
        let repository = Repository::initialize_native_retention(
            Coordinator::new(guard, timing, TokioLocalFs),
            &DomainNamespace {
                root: root.clone(),
                domain: domain.into(),
            },
            &control,
            owner,
        )
        .await?;
        let snapshot = crate::guard::recorded_native_fixture::current_snapshot(&repository).await?;
        Ok((
            Self {
                root,
                control,
                owner,
                keys,
                config,
                snapshot,
            },
            repository,
        ))
    }

    async fn open_store(
        root: &std::path::Path,
        owner: u32,
        config: &GuardConfig,
    ) -> TestResult<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>> {
        Ok(FileBucket::open(
            FileBucketConfig {
                root: root.to_owned(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: config.chunk_profile_name.clone(),
                chunk_profile: (*config.chunk_profile).clone(),
                locality: config.home.clone(),
            },
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new((*config.chunk_profile).clone()),
        )
        .await?)
    }

    fn timing() -> TestResult<CommitTiming> {
        Ok(CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?)
    }

    /// Reopens existing protected records; it never repairs an Original.
    async fn reopen(&self, revision: u64, rows: Vec<ViewSelection>) -> TestResult<Native> {
        let store = Self::open_store(&self.root, self.owner, &self.config).await?;
        let guard = Guard::new_active(store, TokioClock, self.keys.clone(), self.config.clone())
            .with_recorded_authoring(RecordedContext::new(revision, 3, &[])?, 1)?
            .with_view_selections(rows)?;
        let repository = Repository::reopen_native_retention(
            Coordinator::new(guard, Self::timing()?, TokioLocalFs),
            &DomainNamespace {
                root: self.root.clone(),
                domain: self.config.storage_domain.clone(),
            },
            &self.control,
            self.owner,
        )
        .await?;
        assert_eq!(
            crate::guard::recorded_native_fixture::current_snapshot(&repository).await?,
            self.snapshot,
        );
        Ok(repository)
    }
}

struct SignedInputs {
    location: NativeLocation,
    repository: Native,
    records: [RefRecord; 3],
    roots: [Digest; 3],
    rows: Vec<ViewSelection>,
}

fn symlink(target: &'static [u8]) -> Entry<'static> {
    Entry {
        kind: EntryKind::Symlink { target },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn properties(domain: Option<&[u8]>, trust: bool) -> Vec<Property<'_>> {
    let mut properties = vec![Property {
        name: "acl",
        value: ACL,
    }];
    if let Some(value) = domain {
        properties.push(Property {
            name: "domain",
            value,
        });
    }
    if trust {
        properties.push(Property {
            name: "trust",
            value: BUILT_TRUST,
        });
    }
    properties
}

fn flat<'a>(
    domain: Option<&'a [u8]>,
    file: &'static [u8],
    excluded: &'static [u8],
) -> TestResult<Tree<'a>> {
    Ok(Tree::build(
        vec![
            LeafItem {
                key: b"excluded".to_vec(),
                entry: symlink(excluded),
            },
            LeafItem {
                key: b"file".to_vec(),
                entry: symlink(file),
            },
        ],
        Some(properties(domain, true)),
        MINIMUM,
        TreeUse::Ordinary,
    )?)
}

fn graft_parent(child: &Tree<'_>, excluded: &'static [u8]) -> TestResult<Tree<'static>> {
    let mut mount = symlink(b"unused");
    mount.kind = EntryKind::Tree {
        root: child.root_identity(),
        props: Some(vec![Property {
            name: "trust",
            value: BUILT_TRUST,
        }]),
    };
    Ok(Tree::build(
        vec![
            LeafItem {
                key: b"excluded".to_vec(),
                entry: symlink(excluded),
            },
            LeafItem {
                key: b"mount".to_vec(),
                entry: mount,
            },
        ],
        Some(properties(Some(b"\x66public"), false)),
        MINIMUM,
        TreeUse::Ordinary,
    )?)
}

fn child(file: &'static [u8]) -> TestResult<Tree<'static>> {
    Ok(Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: symlink(file),
        }],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )?)
}

fn request(trees: &[&Tree<'_>], parents: Vec<Digest>, source: CommitSource) -> CommitRequest {
    let mut request = crate::ref_advance::tests::request(parents);
    request.commit.tree = trees[0].root_identity();
    request.commit.provenance.source = source;
    request.uploads = trees
        .iter()
        .flat_map(|tree| tree.nodes())
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    request
}

async fn publish(
    repository: &Native,
    reference: &str,
    trees: &[&Tree<'_>],
    parents: Vec<Digest>,
    source: CommitSource,
) -> TestResult<RefRecord> {
    let mut session = repository
        .begin(reference, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let record = repository
        .commit_request(&mut session, request(trees, parents, source))
        .await?;
    let checked = repository
        .coordinator()
        .guard()
        .verified_tree(record.commit)
        .await?;
    assert_eq!(checked.evidence.root, trees[0].root_identity());
    assert!(checked.commit.commit().signature.is_some());
    assert!(
        repository
            .coordinator()
            .guard()
            .original_commit(&record.commit)
            .is_ok()
    );
    Ok(record)
}

/// Publishes actual inputs under independently chosen authoring revisions.
async fn signed_inputs(domain: &str, trees: [&[&Tree<'_>]; 3]) -> TestResult<SignedInputs> {
    let (location, repository) = NativeLocation::open(domain).await?;
    let seed = publish(
        &repository,
        REFERENCE,
        trees[0],
        Vec::new(),
        CommitSource::Built,
    )
    .await?;
    let seed_root = trees[0][0].root_identity();
    let seed_row = ViewSelection::new(seed.commit, seed_root, Selection::Legacy, 1)?;
    drop(repository);

    let second = location.reopen(2, vec![seed_row.clone()]).await?;
    let base = publish(
        &second,
        REFERENCE,
        trees[0],
        vec![seed.commit],
        CommitSource::Built,
    )
    .await?;
    // Establish SOURCE under Recorded2 before its Recorded1 advance.
    let mut fork_request = crate::ref_advance::tests::request(Vec::new());
    fork_request.uploads.clear();
    let forked = second.fork(REFERENCE, SOURCE, fork_request).await?;
    let checked_fork = second
        .coordinator()
        .guard()
        .verified_tree(forked.commit)
        .await?;
    assert_eq!(checked_fork.evidence.root, seed_root);
    assert_eq!(checked_fork.commit.commit().tree, seed_root);
    assert_eq!(checked_fork.commit.commit().parents, [base.commit]);
    assert!(checked_fork.commit.commit().signature.is_some());
    assert!(
        second
            .coordinator()
            .guard()
            .original_commit(&forked.commit)
            .is_ok()
    );
    let mut rows = vec![
        seed_row,
        selected(base.commit, seed_root, 2, &[])?,
        selected(forked.commit, seed_root, 2, &[])?,
    ];
    drop(second);

    let third = location.reopen(3, rows.clone()).await?;
    let ours = publish(
        &third,
        REFERENCE,
        trees[1],
        vec![base.commit],
        CommitSource::Uploaded,
    )
    .await?;
    rows.push(selected(ours.commit, trees[1][0].root_identity(), 3, &[])?);
    drop(third);

    let first = location.reopen(1, rows.clone()).await?;
    let theirs = publish(
        &first,
        SOURCE,
        trees[2],
        vec![forked.commit],
        CommitSource::Built,
    )
    .await?;
    rows.push(selected(
        theirs.commit,
        trees[2][0].root_identity(),
        1,
        &[],
    )?);
    drop(first);
    let repository = location.reopen(3, rows.clone()).await?;
    Ok(SignedInputs {
        location,
        repository,
        records: [base, ours, theirs],
        roots: trees.map(|roots| roots[0].root_identity()),
        rows,
    })
}

/// Executes the actual native phase with a supplied, explicit exclusion decision.
///
/// This tests recomputation and replay, not ref publication or credential-derived
/// root authorization. Production publication independently owns those checks.
async fn fold(
    inputs: &SignedInputs,
    authorized_path: &[u8],
    full_path: &[u8],
) -> TestResult<PreparedMerge> {
    let guard = inputs.repository.coordinator().guard();
    let base = guard.verified_tree(inputs.records[0].commit).await?;
    let ours = guard.verified_tree(inputs.records[1].commit).await?;
    let theirs = guard.verified_tree(inputs.records[2].commit).await?;
    let ours_history = guard.verified_history(inputs.records[1].commit).await?;
    let incoming_history = guard.verified_history(inputs.records[2].commit).await?;
    let mut domains = OperationDomains::new();
    for (index, verified) in [&base, &ours, &theirs].into_iter().enumerate() {
        let selection = guard.select_view(
            inputs.records[index].commit,
            inputs.roots[index],
            HistoryObservation::default(),
        )?;
        bind_occurrence_domains(
            &mut domains,
            &verified.evidence,
            &selection,
            guard.defaults_for(&verified.evidence),
            MINIMUM,
        )?;
    }
    for (index, history) in [&ours_history, &incoming_history].into_iter().enumerate() {
        let selection = guard.select_view(
            inputs.records[index + 1].commit,
            inputs.roots[index + 1],
            HistoryObservation::default(),
        )?;
        let evaluator = selection.evaluator(
            history,
            (inputs.records[index + 1].commit, inputs.roots[index + 1]),
            Selector::preset(Preset::Any),
            &guard.config().storage_domain,
            None,
        )?;
        assert_eq!(evaluator.accepts_path(full_path), index == 1);
        assert_context(
            evaluator.canonical_context(),
            inputs.records[index + 1].commit,
            inputs.roots[index + 1],
            [3, 1][index],
            &guard.config().storage_domain,
        )?;
    }
    let authorized = BTreeSet::from([authorized_path.to_vec()]);
    let prepared = guard.recompute_merge(
        [&base, &ours, &theirs],
        [&ours_history, &incoming_history],
        [inputs.records[1].commit, inputs.records[2].commit],
        POLICIES,
        theirs.commit.commit().clone(),
        MergeOperation::Fold(&authorized),
    )?;
    assert_eq!(prepared.excluded, [b"excluded".to_vec()]);
    assert_eq!(
        prepared.commit.parents,
        [inputs.records[1].commit, inputs.records[2].commit]
    );
    assert_eq!(prepared.commit.profile_pair.conflicted, Some(false));
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(inputs.records[1].clone())
    );
    assert_eq!(
        guard.store().ref_get(SOURCE).await?,
        Some(inputs.records[2].clone())
    );
    Ok(prepared)
}

fn filtered_root(prepared: &PreparedMerge) -> TestResult<Digest> {
    let bytes = prepared
        .commit
        .profile_pair
        .recipe
        .as_ref()
        .ok_or("fold omitted recipe")?;
    match Recipe::decode(bytes)?.as_recipe() {
        Recipe::Merge { theirs, .. } => Ok(theirs),
        _ => Err("fold encoded another recipe operation".into()),
    }
}

/// Reauthenticates source views before binding decoded replay claims.
async fn replay(
    inputs: &SignedInputs,
    prepared: &PreparedMerge,
    preserved: Option<&[u8]>,
) -> TestResult {
    // Authoring revision is deliberately different from the producer's and the
    // first execution's. The installed original-view associations still govern.
    let fresh = inputs.location.reopen(1, inputs.rows.clone()).await?;
    let guard = fresh.coordinator().guard();
    let base = guard.verified_tree(inputs.records[0].commit).await?;
    let ours = guard.verified_tree(inputs.records[1].commit).await?;
    let original = guard.verified_tree(inputs.records[2].commit).await?;
    let histories = [
        guard.verified_history(inputs.records[1].commit).await?,
        guard.verified_history(inputs.records[2].commit).await?,
    ];
    let filtered_identity = filtered_root(prepared)?;
    assert_ne!(filtered_identity, inputs.roots[2]);
    let filtered_evidence =
        TreeEvidence::load_tree(guard.store(), filtered_identity, &prepared.uploads, MINIMUM)
            .await?;
    let output_evidence = TreeEvidence::load_tree(
        guard.store(),
        prepared.commit.tree,
        &prepared.uploads,
        MINIMUM,
    )
    .await?;
    let mut domains = OperationDomains::new();
    let mut evaluators = Vec::new();
    for (index, verified) in [&base, &ours, &original].into_iter().enumerate() {
        assert!(guard.original_commit(&inputs.records[index].commit).is_ok());
        let selection = guard.select_view(
            inputs.records[index].commit,
            inputs.roots[index],
            HistoryObservation::default(),
        )?;
        bind_occurrence_domains(
            &mut domains,
            &verified.evidence,
            &selection,
            guard.defaults_for(&verified.evidence),
            MINIMUM,
        )?;
        if index > 0 {
            let evaluator = selection.evaluator(
                &histories[index - 1],
                (inputs.records[index].commit, inputs.roots[index]),
                Selector::preset(Preset::Any),
                &guard.config().storage_domain,
                None,
            )?;
            assert_context(
                evaluator.canonical_context(),
                inputs.records[index].commit,
                inputs.roots[index],
                [2, 3, 1][index],
                &guard.config().storage_domain,
            )?;
            evaluators.push(evaluator);
        }
    }
    let base_tree = base.evidence.tree(inputs.roots[0], MINIMUM)?;
    let ours_tree = ours.evidence.tree(inputs.roots[1], MINIMUM)?;
    let original_tree = original.evidence.tree(inputs.roots[2], MINIMUM)?;
    let filtered_tree = filtered_evidence.tree(filtered_identity, MINIMUM)?;
    if let Some(domain) = preserved {
        assert!(
            original_tree
                .props()
                .into_iter()
                .flatten()
                .all(|property| property.name != "domain")
        );
        assert_eq!(
            filtered_tree
                .props()
                .into_iter()
                .flatten()
                .find(|property| property.name == "domain")
                .map(|property| property.value),
            Some(domain)
        );
    }
    let bytes = prepared
        .commit
        .profile_pair
        .recipe
        .as_ref()
        .ok_or("fold omitted recipe")?;
    assert_preprocessing(bytes, inputs, filtered_identity, &evaluators, preserved)?;
    let decoded = Recipe::decode(bytes)?;
    let bound = decoded
        .clone()
        .bind_domains(&domains)?
        .bind_fold_verified_with_domains(
            evaluators.clone(),
            &base_tree,
            &original_tree,
            &filtered_tree,
            &prepared.excluded,
            &domains,
        )?;
    assert_eq!(bound.as_recipe().encode(), *bytes);
    assert_eq!(
        bound.as_recipe().identity()?,
        decoded.as_recipe().identity()?
    );
    let mut roots = BTreeMap::new();
    for evidence in [
        &base.evidence,
        &ours.evidence,
        &original.evidence,
        &filtered_evidence,
        &output_evidence,
    ] {
        for root in &evidence.roots {
            roots.insert(*root, evidence.tree(*root, MINIMUM)?);
        }
    }
    let forest = Forest(roots);
    let Recipe::Merge {
        trust, policies, ..
    } = bound.as_recipe()
    else {
        return Err("rebound another operation".into());
    };
    let result = algebra::merge_with_domains(
        &base_tree,
        &ours_tree,
        &filtered_tree,
        policies,
        trust,
        &forest,
        &domains,
    )?;
    assert_eq!(result.tree.root_identity(), prepared.commit.tree);
    assert_eq!(result.recipe, *bytes);

    for changed in [
        Vec::new(),
        vec![evaluators[0].clone()],
        vec![evaluators[1].clone(), evaluators[0].clone()],
    ] {
        assert!(
            decoded
                .clone()
                .bind_domains(&domains)?
                .bind_fold_verified_with_domains(
                    changed,
                    &base_tree,
                    &original_tree,
                    &filtered_tree,
                    &prepared.excluded,
                    &domains,
                )
                .is_err()
        );
    }
    for exclusions in [Vec::new(), vec![b"excluded".to_vec(), b"excluded".to_vec()]] {
        assert!(
            decoded
                .clone()
                .bind_domains(&domains)?
                .bind_fold_verified_with_domains(
                    evaluators.clone(),
                    &base_tree,
                    &original_tree,
                    &filtered_tree,
                    &exclusions,
                    &domains,
                )
                .is_err()
        );
    }
    assert!(
        decoded
            .clone()
            .bind_domains(&OperationDomains::new())
            .is_err()
    );
    // Preserve the complete original root set while changing its labels. This
    // refusal cannot succeed merely because a registry omitted an input root.
    let wrong_properties = [Property {
        name: "domain",
        value: b"\x6dprivate:wrong",
    }];
    let wrong_effective = terrane_format::properties::resolve(
        &[terrane_format::properties::RootLayer {
            properties: &wrong_properties,
            overrides: &[],
        }],
        guard.defaults_for(&base.evidence),
    )?;
    let mut wrong_domains = OperationDomains::new();
    for evidence in [&base.evidence, &ours.evidence, &original.evidence] {
        for root in &evidence.roots {
            wrong_domains.bind_resolved(*root, &wrong_effective)?;
        }
    }
    assert!(decoded.clone().bind_domains(&wrong_domains).is_err());
    assert!(
        decoded
            .clone()
            .bind_domains(&domains)?
            .bind_fold_verified_with_domains(
                evaluators,
                &base_tree,
                &filtered_tree,
                &filtered_tree,
                &prepared.excluded,
                &domains,
            )
            .is_err()
    );
    Ok(())
}

/// Missing and substituted incoming associations refuse through real verification.
async fn refuse_association_changes(inputs: &SignedInputs) -> TestResult {
    let original = selected(inputs.records[2].commit, inputs.roots[2], 1, &[])?;
    for replacement in [
        None,
        Some(selected(inputs.records[2].commit, inputs.roots[1], 1, &[])?),
    ] {
        let mut rows = inputs
            .rows
            .iter()
            .filter(|row| *row != &original)
            .cloned()
            .collect::<Vec<_>>();
        if let Some(replacement) = replacement {
            rows.push(replacement);
        }
        let changed = inputs.location.reopen(3, rows).await?;
        assert!(
            changed
                .coordinator()
                .guard()
                .verified_tree(inputs.records[2].commit)
                .await
                .is_err()
        );
        assert!(
            changed
                .coordinator()
                .guard()
                .verified_history(inputs.records[2].commit)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn recorded_native_fold_selects_trusted_remaining_incoming_and_replays() -> TestResult {
    let base = flat(Some(b"\x66public"), b"base", b"keep")?;
    let ours = flat(Some(b"\x66public"), b"ours", b"keep")?;
    let incoming = flat(Some(b"\x66public"), b"incoming", b"exclude")?;
    let inputs = signed_inputs("public", [&[&base], &[&ours], &[&incoming]]).await?;
    let prepared = fold(&inputs, b"file", b"file").await?;
    let expected = flat(Some(b"\x66public"), b"incoming", b"keep")?;
    assert_eq!(prepared.commit.tree, expected.root_identity());
    assert_ne!(prepared.commit.tree, inputs.roots[1]);
    assert_eq!(filtered_root(&prepared)?, expected.root_identity());
    replay(&inputs, &prepared, None).await?;
    refuse_association_changes(&inputs).await
}

#[tokio::test]
async fn recorded_native_graft_fold_preserves_prefix_trust_and_original_associations() -> TestResult
{
    let children = [child(b"base")?, child(b"ours")?, child(b"incoming")?];
    let parents = [
        graft_parent(&children[0], b"keep")?,
        graft_parent(&children[1], b"keep")?,
        graft_parent(&children[2], b"exclude")?,
    ];
    let inputs = signed_inputs(
        "public",
        [
            &[&parents[0], &children[0]],
            &[&parents[1], &children[1]],
            &[&parents[2], &children[2]],
        ],
    )
    .await?;
    let prepared = fold(&inputs, b"mount", b"mount/file").await?;
    let expected_child = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: symlink(b"incoming"),
        }],
        Some(vec![Property {
            name: "domain",
            value: b"\x66public",
        }]),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let expected = graft_parent(&expected_child, b"keep")?;
    assert_eq!(prepared.commit.tree, expected.root_identity());
    assert_ne!(prepared.commit.tree, inputs.roots[1]);
    let expected_filtered = graft_parent(&children[2], b"keep")?;
    assert_eq!(filtered_root(&prepared)?, expected_filtered.root_identity());
    let evidence = TreeEvidence::load_tree(
        inputs.repository.coordinator().guard().store(),
        prepared.commit.tree,
        &prepared.uploads,
        MINIMUM,
    )
    .await?;
    assert!(evidence.roots.contains(&expected_child.root_identity()));
    assert!(
        evidence
            .ordinary_roots
            .contains(&expected_child.root_identity())
    );
    assert_eq!(
        evidence
            .tree(expected_child.root_identity(), MINIMUM)?
            .get(b"file"),
        Some(&symlink(b"incoming"))
    );
    replay(&inputs, &prepared, None).await?;
    refuse_association_changes(&inputs).await
}

#[tokio::test]
async fn recorded_native_fold_materializes_implicit_owner_and_replays_preserved_domain()
-> TestResult {
    let incoming = flat(None, b"incoming", b"exclude")?;
    let root_hex = incoming
        .root_identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let label = format!("private:terrane-v1:Node:{root_hex}");
    let mut domain = Vec::new();
    terrane_format::cbor::write_text(&mut domain, &label);
    // The physical namespace routes the source's independently computed default
    // owner. Base and ours explicitly use that same owner; no domain is widened.
    let base = flat(Some(&domain), b"base", b"keep")?;
    let ours = flat(Some(&domain), b"ours", b"keep")?;
    let inputs = signed_inputs(&label, [&[&base], &[&ours], &[&incoming]]).await?;
    let prepared = fold(&inputs, b"file", b"file").await?;
    let expected = flat(Some(&domain), b"incoming", b"keep")?;
    assert_eq!(filtered_root(&prepared)?, expected.root_identity());
    assert_eq!(prepared.commit.tree, expected.root_identity());
    assert_ne!(prepared.commit.tree, inputs.roots[1]);
    replay(&inputs, &prepared, Some(&domain)).await?;
    refuse_association_changes(&inputs).await
}
