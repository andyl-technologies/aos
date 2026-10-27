//! Witnesses immutable Memo loading, independent closures and mandatory replay.

#[cfg(all(feature = "tokio", unix))]
mod native;

mod wire;

use super::*;
use crate::store::*;
use std::collections::BTreeMap;
use std::error::Error as _;
use std::sync::Mutex;
use terrane_format::derivation::cache::{CacheObservation, CacheRefusal};
use terrane_format::derivation::evaluation::{EvaluationError, EvaluationWork, FoldReplay};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::indexing::carrier::SemanticContext;
use terrane_format::refs::Locality;
use terrane_format::tree_builder::Tree;
use wire::*;

struct ReadOnly {
    memos: BTreeMap<Digest, Vec<u8>>,
    nodes: BTreeMap<Digest, Vec<u8>>,
    gets: Mutex<Vec<Identity>>,
    failure: Option<(Identity, StoreErrorKind)>,
    capabilities: Capabilities,
}

impl ReadOnly {
    fn new() -> Self {
        Self {
            memos: BTreeMap::new(),
            nodes: BTreeMap::new(),
            gets: Mutex::new(Vec::new()),
            failure: None,
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}

impl CapabilityReport for ReadOnly {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for ReadOnly {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("replay must not persist content")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        assert_eq!(range, None);
        self.gets
            .lock()
            .unwrap_or_else(|error| panic!("request log: {error}"))
            .push(identity.clone());
        if let Some((subject, kind)) = &self.failure
            && subject == identity
        {
            return Err(StoreFailure::with_source(
                kind.clone(),
                std::io::Error::other("original backend diagnostic"),
            ));
        }
        let digest = identity
            .terrane_v1_digest()
            .unwrap_or_else(|error| panic!("subject: {error}"));
        let objects = match identity.kind() {
            IdentityKind::Memo => &self.memos,
            IdentityKind::Node => &self.nodes,
            _ => panic!("unexpected identity kind"),
        };
        objects.get(&digest).cloned().ok_or_else(|| {
            StoreFailure::with_source(
                StoreErrorKind::Absent(identity.clone()),
                std::io::Error::other("original backend diagnostic"),
            )
        })
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("replay must not query membership")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("replay must not enumerate content")
    }
}

fn identity(kind: IdentityKind, digest: Digest) -> Identity {
    TERRANE_V1
        .from_digest(kind, &digest)
        .unwrap_or_else(|error| panic!("fixture identity: {error}"))
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fixture store completes synchronously"),
    }
}

fn inputs<'t, 'a>(trees: &'t BTreeMap<Digest, Tree<'a>>) -> EvaluationInputs<'t, 'a> {
    EvaluationInputs {
        trees,
        minimum: MINIMUM,
        context: SemanticContext::new(3, 2, 1)
            .unwrap_or_else(|error| panic!("fixture context: {error}")),
        domains: None,
        provenance: &[],
        fold: None,
        overlay: None,
    }
}

fn selected<'a>(fixture: &Fixture, inventory: Option<&'a BTreeSet<Digest>>) -> Selection<'a> {
    Selection::Selected {
        memo: fixture.address(),
        nodes: inventory,
    }
}

fn outcome(store: &ReadOnly, fixture: &Fixture, inventory: Option<&BTreeSet<Digest>>) -> Outcome {
    ready(replay(
        store,
        &fixture.recipe,
        &inputs(&fixture.trees()),
        ReplayMode::Check,
        selected(fixture, inventory),
    ))
    .unwrap_or_else(|error| panic!("replay fixture: {error:?}"))
}

fn failure(result: Result<Outcome, Error>) -> Error {
    match result {
        Err(error) => error,
        Ok(outcome) => panic!("expected replay refusal, got {outcome:?}"),
    }
}

fn assert_output(actual: &Outcome, fixture: &Fixture) {
    assert_eq!(actual.replay.evaluation.recipe_hash, fixture.key());
    assert_eq!(actual.replay.evaluation.root, fixture.root);
    assert_eq!(actual.replay.evaluation.nodes, fixture.output);
    assert_eq!(actual.replay.memo.recipe_hash(), fixture.key());
    assert_eq!(actual.replay.memo.result_root(), fixture.root);
    assert_eq!(
        actual.replay.evaluation.closure_bytes,
        fixture.output.values().map(Vec::len).sum::<usize>()
    );
}

fn assert_reads(
    store: &ReadOnly,
    memo: Option<Digest>,
    nodes: &BTreeSet<Digest>,
    report: &LoadingReport,
) {
    let requests = store
        .gets
        .lock()
        .unwrap_or_else(|error| panic!("request log: {error}"));
    let mut expected = Vec::new();
    if let Some(memo) = memo {
        expected.push(identity(IdentityKind::Memo, memo));
    }
    expected.extend(nodes.iter().map(|node| identity(IdentityKind::Node, *node)));
    assert_eq!(*requests, expected);
    assert_eq!(report.work.gets, expected.len());
    let bytes: usize = requests
        .iter()
        .filter(|request| {
            !store
                .failure
                .as_ref()
                .is_some_and(|(subject, _)| *request == subject)
        })
        .filter_map(|request| {
            let digest = request
                .terrane_v1_digest()
                .unwrap_or_else(|error| panic!("request digest: {error}"));
            match request.kind() {
                IdentityKind::Memo => store.memos.get(&digest),
                IdentityKind::Node => store.nodes.get(&digest),
                _ => panic!("unexpected request kind"),
            }
        })
        .map(Vec::len)
        .sum();
    assert_eq!(report.work.returned_bytes, bytes);
    let successes = requests
        .iter()
        .filter(|request| {
            let digest = request
                .terrane_v1_digest()
                .unwrap_or_else(|error| panic!("request digest: {error}"));
            let held = match request.kind() {
                IdentityKind::Memo => store.memos.contains_key(&digest),
                IdentityKind::Node => store.nodes.contains_key(&digest),
                _ => false,
            };
            held && !store
                .failure
                .as_ref()
                .is_some_and(|(subject, _)| *request == subject)
        })
        .count();
    let memo_success = usize::from(memo.is_some_and(|address| {
        store.memos.contains_key(&address)
            && !store
                .failure
                .as_ref()
                .is_some_and(|(subject, _)| subject == &identity(IdentityKind::Memo, address))
    }));
    assert_eq!(report.work.identity_checks, successes + memo_success);
    assert_eq!(report.work.memo_decodes, memo_success);
}

fn assert_store_diagnostic(report: &LoadingReport, subject: &Identity, kind: &StoreErrorKind) {
    let diagnostic = report.diagnostics.iter().find(|diagnostic| matches!(diagnostic, Diagnostic::Store { identity, .. } if identity == subject));
    let Some(Diagnostic::Store { identity, failure }) = diagnostic else {
        panic!("missing original failure: {report:?}")
    };
    assert_eq!(identity, subject);
    assert_eq!(failure.kind(), kind);
    assert_eq!(
        failure
            .source()
            .unwrap_or_else(|| panic!("lost original source"))
            .to_string(),
        "original backend diagnostic"
    );
}

#[test]
fn memo_replay_loads_selected_records_and_complete_outputs() {
    for (kind, fixture) in [
        ("graft", Fixture::graft()),
        ("overlay", Fixture::overlay()),
        ("merge", Fixture::merge()),
        ("index", Fixture::index()),
    ] {
        let inventory = fixture.inventory();
        assert_ne!(fixture.key(), fixture.address());
        for _ in 0..2 {
            let mut store = fixture.store();
            let unrelated = leaf(&Vec::new(), None);
            let unrelated_address = hash(b"terrane-node-v1", &unrelated);
            assert!(!inventory.contains(&unrelated_address));
            store.nodes.insert(unrelated_address, unrelated);
            let result = outcome(&store, &fixture, Some(&inventory));
            assert_output(&result, &fixture);
            assert_eq!(
                result.replay.cache.observation,
                CacheObservation::Hit,
                "{kind}"
            );
            assert!(
                result.loading.diagnostics.is_empty(),
                "{kind}: {:?}",
                result.loading
            );
            assert_eq!(result.loading.work.identity_checks, inventory.len() + 2);
            assert_eq!(result.loading.work.memo_decodes, 1);
            assert_reads(&store, Some(fixture.address()), &inventory, &result.loading);
            if kind == "index" {
                assert_eq!(inventory.len(), 6);
                assert!(matches!(
                    result.replay.evaluation.work,
                    EvaluationWork::Index { .. }
                ));
            }
            if kind == "graft" {
                assert_eq!(result.replay.evaluation.closure_roots, 2);
            }
        }
        for (selection, expected) in [
            (Selection::Disabled, CacheObservation::Disabled),
            (Selection::EnabledNoSelection, CacheObservation::Miss),
        ] {
            let store = fixture.store();
            let result = ready(replay(
                &store,
                &fixture.recipe,
                &inputs(&fixture.trees()),
                ReplayMode::Check,
                selection,
            ))
            .unwrap_or_else(|error| panic!("{kind}: {error:?}"));
            assert_output(&result, &fixture);
            assert_eq!(result.replay.cache.observation, expected);
            assert_eq!(result.loading.work, LoadingWork::default());
            assert_reads(&store, None, &BTreeSet::new(), &result.loading);
        }
    }
}

#[test]
fn memo_replay_keeps_disabled_and_advisory_failures_equivalent() {
    let fixture = Fixture::index();
    let inventory = fixture.inventory();
    let extra_bytes = leaf(&Vec::new(), None);
    let extra_address = hash(b"terrane-node-v1", &extra_bytes);
    let no_inventory = outcome(&fixture.store(), &fixture, None);
    assert_output(&no_inventory, &fixture);
    assert_eq!(
        no_inventory.replay.cache.observation,
        CacheObservation::Refused(CacheRefusal::MissingOutput)
    );

    for (label, claimed, mutation) in [
        ("empty", BTreeSet::new(), 0),
        ("omitted", inventory.iter().copied().skip(1).collect(), 0),
        (
            "extra",
            inventory
                .union(&BTreeSet::from([extra_address]))
                .copied()
                .collect(),
            1,
        ),
        ("wrong bytes", inventory.clone(), 2),
    ] {
        let mut store = fixture.store();
        if mutation == 1 {
            store.nodes.insert(extra_address, extra_bytes.clone());
        }
        if mutation == 2 {
            let root = fixture.root;
            store.nodes.insert(root, leaf(&Vec::new(), None));
        }
        let result = outcome(&store, &fixture, Some(&claimed));
        assert_output(&result, &fixture);
        assert_eq!(
            result.replay.cache.observation,
            CacheObservation::Refused(CacheRefusal::InvalidOutput),
            "{label}"
        );
        assert_reads(&store, Some(fixture.address()), &claimed, &result.loading);
        if mutation == 1 {
            assert!(result.loading.diagnostics.is_empty());
        }
        if mutation == 2 {
            assert!(
                result
                    .loading
                    .diagnostics
                    .iter()
                    .any(|entry| matches!(entry, Diagnostic::AddressMismatch { .. }))
            );
        }
    }

    let missing_node = *inventory
        .first()
        .unwrap_or_else(|| panic!("nonempty inventory"));
    for unavailable in [false, true] {
        let mut store = fixture.store();
        let subject = identity(IdentityKind::Node, missing_node);
        let kind = if unavailable {
            StoreErrorKind::Unavailable {
                retry_after: Some(std::time::Duration::from_secs(3)),
            }
        } else {
            StoreErrorKind::Absent(subject.clone())
        };
        if unavailable {
            store.failure = Some((subject.clone(), kind.clone()));
        } else {
            store.nodes.remove(&missing_node);
        }
        let result = outcome(&store, &fixture, Some(&inventory));
        assert_output(&result, &fixture);
        assert_eq!(
            result.replay.cache.observation,
            CacheObservation::Refused(CacheRefusal::MissingOutput)
        );
        assert_store_diagnostic(&result.loading, &subject, &kind);
        assert_reads(&store, Some(fixture.address()), &inventory, &result.loading);
    }
    for unavailable in [false, true] {
        let mut store = fixture.store();
        let subject = identity(IdentityKind::Memo, fixture.address());
        let kind = if unavailable {
            StoreErrorKind::Unavailable {
                retry_after: Some(std::time::Duration::from_secs(3)),
            }
        } else {
            StoreErrorKind::Absent(subject.clone())
        };
        if unavailable {
            store.failure = Some((subject.clone(), kind.clone()));
        } else {
            store.memos.clear();
        }
        let result = outcome(&store, &fixture, Some(&inventory));
        assert_output(&result, &fixture);
        assert_eq!(
            result.replay.cache.observation,
            CacheObservation::Refused(CacheRefusal::Unavailable)
        );
        assert_store_diagnostic(&result.loading, &subject, &kind);
        assert_reads(
            &store,
            Some(fixture.address()),
            &BTreeSet::new(),
            &result.loading,
        );
    }

    let mut corruptions = vec![vec![0xff], vec![0; 72], fixture.record()];
    corruptions[2].push(0);
    let mut extra = fixture.record();
    extra[0] = 0xa3;
    extra.extend_from_slice(&[3, 0]);
    corruptions.push(extra);
    for bytes in corruptions {
        let address = hash(b"terrane-memo-v1", &bytes);
        let mut store = fixture.store();
        store.memos.insert(address, bytes);
        let result = ready(replay(
            &store,
            &fixture.recipe,
            &inputs(&fixture.trees()),
            ReplayMode::Check,
            Selection::Selected {
                memo: address,
                nodes: Some(&inventory),
            },
        ))
        .unwrap_or_else(|error| panic!("corrupt advisory: {error:?}"));
        assert_output(&result, &fixture);
        assert_eq!(
            result.replay.cache.observation,
            CacheObservation::Refused(CacheRefusal::CorruptRecord)
        );
        assert!(
            result
                .loading
                .diagnostics
                .iter()
                .any(|entry| matches!(entry, Diagnostic::Memo(_)))
        );
        assert_reads(&store, Some(address), &inventory, &result.loading);
    }
    for wrong_key in [false, true] {
        let mut store = fixture.store();
        let bytes = memo([0x44; 32], fixture.root);
        let address = if wrong_key {
            hash(b"terrane-memo-v1", &bytes)
        } else {
            fixture.address()
        };
        store.memos.insert(address, bytes);
        let result = ready(replay(
            &store,
            &fixture.recipe,
            &inputs(&fixture.trees()),
            ReplayMode::Check,
            Selection::Selected {
                memo: address,
                nodes: None,
            },
        ))
        .unwrap_or_else(|error| panic!("bad association: {error:?}"));
        assert_output(&result, &fixture);
        assert_eq!(
            result.replay.cache.observation,
            CacheObservation::Refused(if wrong_key {
                CacheRefusal::WrongKey
            } else {
                CacheRefusal::CorruptRecord
            })
        );
        assert_reads(&store, Some(address), &BTreeSet::new(), &result.loading);
    }
}

#[test]
fn memo_replay_reports_divergence_and_rebuilds() {
    let fixture = Fixture::graft();
    let bytes = memo(fixture.key(), [0x88; 32]);
    let address = hash(b"terrane-memo-v1", &bytes);
    for mode in [ReplayMode::Check, ReplayMode::Rebuild] {
        let mut store = fixture.store();
        store.memos.insert(address, bytes.clone());
        let result = ready(replay(
            &store,
            &fixture.recipe,
            &inputs(&fixture.trees()),
            mode,
            Selection::Selected {
                memo: address,
                nodes: None,
            },
        ));
        match mode {
            ReplayMode::Check => {
                let error = failure(result);
                assert_eq!(
                    error.replay,
                    ReplayError::Divergent {
                        recipe: fixture.key(),
                        claimed: [0x88; 32],
                        actual: fixture.root
                    }
                );
                assert_reads(&store, Some(address), &BTreeSet::new(), &error.loading);
            }
            ReplayMode::Rebuild => {
                let result = result.unwrap_or_else(|error| panic!("rebuild: {error:?}"));
                assert_output(&result, &fixture);
                assert!(result.replay.cache.rebuilt);
                assert_eq!(
                    result.replay.cache.observation,
                    CacheObservation::Refused(CacheRefusal::Divergent([0x88; 32]))
                );
                assert_reads(&store, Some(address), &BTreeSet::new(), &result.loading);
            }
        }
        assert_eq!(store.memos[&address], bytes);
    }

    let inventory = fixture.inventory();
    let node = *inventory
        .first()
        .unwrap_or_else(|| panic!("nonempty output"));
    let subject = identity(IdentityKind::Node, node);
    let kind = StoreErrorKind::Unavailable { retry_after: None };
    let mut store = fixture.store();
    store.memos.insert(address, bytes);
    store.failure = Some((subject.clone(), kind.clone()));
    let error = failure(ready(replay(
        &store,
        &fixture.recipe,
        &inputs(&fixture.trees()),
        ReplayMode::Check,
        Selection::Selected {
            memo: address,
            nodes: Some(&inventory),
        },
    )));
    assert_eq!(
        error.replay,
        ReplayError::Divergent {
            recipe: fixture.key(),
            claimed: [0x88; 32],
            actual: fixture.root
        }
    );
    assert_store_diagnostic(&error.loading, &subject, &kind);
    assert_reads(&store, Some(address), &inventory, &error.loading);
}

#[test]
fn memo_replay_preserves_mandatory_input_failures_and_separate_work() {
    let fixture = Fixture::graft();
    let inventory = fixture.inventory();
    let trees = fixture.trees();
    let absent = BTreeMap::new();
    let mut wrong_trees = trees.clone();
    let root = *trees
        .keys()
        .next()
        .unwrap_or_else(|| panic!("nonempty inputs"));
    let other = trees
        .iter()
        .find(|(key, _)| **key != root)
        .unwrap_or_else(|| panic!("distinct inputs"))
        .1
        .clone();
    wrong_trees.insert(root, other);
    let decoded = terrane_format::algebra::Recipe::decode(&fixture.recipe)
        .unwrap_or_else(|error| panic!("valid graft recipe: {error}"));
    assert_eq!(decoded.as_recipe().encode(), fixture.recipe);
    for (label, source, minimum, recipe_bytes, expected) in [
        (
            "missing operand",
            &absent,
            MINIMUM,
            fixture.recipe.clone(),
            EvaluationError::MissingRoot(fixture.first_operand),
        ),
        (
            "wrong addressed operand",
            &wrong_trees,
            MINIMUM,
            fixture.recipe.clone(),
            EvaluationError::Input(root),
        ),
        (
            "wrong geometry",
            &trees,
            MINIMUM + 1,
            fixture.recipe.clone(),
            EvaluationError::Input(fixture.first_operand),
        ),
        (
            "unsupported operation",
            &trees,
            MINIMUM,
            recipe("map", &[root], None),
            EvaluationError::Unsupported(String::from("map")),
        ),
        (
            "retained index",
            &trees,
            MINIMUM,
            recipe("index", &[root], None),
            EvaluationError::Unsupported(String::from("index specialization")),
        ),
        (
            "unsupported profile",
            &trees,
            MINIMUM,
            recipe("index", &[root], Some(index_args("other-profile"))),
            EvaluationError::Unsupported(String::from("index specialization")),
        ),
    ] {
        let mut input = inputs(source);
        input.minimum = minimum;
        let disabled = failure(ready(replay(
            &ReadOnly::new(),
            &recipe_bytes,
            &input,
            ReplayMode::Check,
            Selection::Disabled,
        )));
        assert_eq!(
            disabled.replay,
            ReplayError::Evaluation(expected),
            "{label}"
        );
        for fail_load in [false, true] {
            let mut store = fixture.store();
            let claim = memo(hash(b"terrane-memo-v1", &recipe_bytes), fixture.root);
            let address = hash(b"terrane-memo-v1", &claim);
            store.memos.insert(address, claim);
            let subject = identity(IdentityKind::Memo, address);
            if fail_load {
                store.failure = Some((
                    subject.clone(),
                    StoreErrorKind::Unavailable {
                        retry_after: Some(std::time::Duration::from_secs(3)),
                    },
                ));
            }
            let error = failure(ready(replay(
                &store,
                &recipe_bytes,
                &input,
                ReplayMode::Check,
                Selection::Selected {
                    memo: address,
                    nodes: Some(&inventory),
                },
            )));
            assert_eq!(error.replay, disabled.replay, "{label}");
            assert!(error.source().is_some());
            if fail_load {
                assert_store_diagnostic(
                    &error.loading,
                    &subject,
                    &StoreErrorKind::Unavailable {
                        retry_after: Some(std::time::Duration::from_secs(3)),
                    },
                );
            }
            let requested_nodes = if fail_load {
                BTreeSet::new()
            } else {
                inventory.clone()
            };
            assert_reads(&store, Some(address), &requested_nodes, &error.loading);
        }
    }
    assert!(SemanticContext::new(2, 2, 1).is_err());

    let mut domain_args = vec![0xa1];
    terrane_format::cbor::write_text(&mut domain_args, "domains");
    domain_args.extend_from_slice(&[0x81, 0x82]);
    terrane_format::cbor::write_bytes(&mut domain_args, &root);
    terrane_format::cbor::write_text(&mut domain_args, "private:memo-test");
    let domain_recipe = recipe("overlay", &[root], Some(domain_args));
    let trust_recipe = terrane_format::algebra::Recipe::Merge {
        base: root,
        ours: root,
        theirs: root,
        policies: &[terrane_format::algebra::MergePolicy::PreferTrusted],
        trust: &terrane_format::algebra::TrustContext::any(),
        domains: None,
    }
    .encode();
    for (label, recipe_bytes) in [
        ("missing domains", domain_recipe),
        ("missing checked trust", trust_recipe),
    ] {
        let decoded = terrane_format::algebra::Recipe::decode(&recipe_bytes)
            .unwrap_or_else(|error| panic!("valid {label} recipe: {error}"));
        assert_eq!(decoded.as_recipe().encode(), recipe_bytes);
        for fold in [
            None,
            Some(FoldReplay {
                original: [0x55; 32],
                excluded: &[],
                domains: None,
            }),
        ] {
            let mut input = inputs(&trees);
            input.fold = fold;
            let disabled = failure(ready(replay(
                &ReadOnly::new(),
                &recipe_bytes,
                &input,
                ReplayMode::Check,
                Selection::Disabled,
            )));
            let expected = if label == "missing domains" {
                EvaluationError::Recipe(terrane_format::algebra::RecipeError::Schema)
            } else if fold.is_some() {
                EvaluationError::MissingRoot([0x55; 32])
            } else {
                EvaluationError::Recipe(terrane_format::algebra::RecipeError::Trust(
                    terrane_format::algebra::TrustError::Unverified,
                ))
            };
            assert_eq!(
                disabled.replay,
                ReplayError::Evaluation(expected),
                "{label}"
            );
            let mut store = fixture.store();
            let claim = memo(hash(b"terrane-memo-v1", &recipe_bytes), fixture.root);
            let address = hash(b"terrane-memo-v1", &claim);
            store.memos.insert(address, claim);
            let error = failure(ready(replay(
                &store,
                &recipe_bytes,
                &input,
                ReplayMode::Rebuild,
                Selection::Selected {
                    memo: address,
                    nodes: Some(&inventory),
                },
            )));
            assert_eq!(error.replay, disabled.replay, "{label}");
            assert_reads(&store, Some(address), &inventory, &error.loading);
        }
    }

    let store = fixture.store();
    let result = outcome(&store, &fixture, Some(&inventory));
    assert_reads(&store, Some(fixture.address()), &inventory, &result.loading);
    assert_eq!(result.loading.work.identity_checks, 4);
    assert_eq!(result.loading.work.memo_decodes, 1);
    assert!(matches!(
        result.replay.evaluation.work,
        EvaluationWork::Graft { .. }
    ));
    assert_eq!(result.replay.evaluation.closure_roots, 2);

    assert_counter_overflow_preserves_replay(&fixture);
    let node = *inventory
        .first()
        .unwrap_or_else(|| panic!("nonempty output"));
    let subject = identity(IdentityKind::Node, node);
    let kind = StoreErrorKind::Absent(subject.clone());
    let mut store = fixture.store();
    store.nodes.remove(&node);
    let error = failure(ready(replay(
        &store,
        &fixture.recipe,
        &inputs(&absent),
        ReplayMode::Check,
        selected(&fixture, Some(&inventory)),
    )));
    assert!(matches!(
        error.replay,
        ReplayError::Evaluation(EvaluationError::MissingRoot(_))
    ));
    assert_store_diagnostic(&error.loading, &subject, &kind);
    assert_reads(&store, Some(fixture.address()), &inventory, &error.loading);
}

fn assert_counter_overflow_preserves_replay(fixture: &Fixture) {
    let inventory = fixture.inventory();
    let selection = selected(fixture, Some(&inventory));
    for (name, work) in [
        (
            "gets",
            LoadingWork {
                gets: usize::MAX,
                ..LoadingWork::default()
            },
        ),
        (
            "returned_bytes",
            LoadingWork {
                returned_bytes: usize::MAX,
                ..LoadingWork::default()
            },
        ),
        (
            "identity_checks",
            LoadingWork {
                identity_checks: usize::MAX,
                ..LoadingWork::default()
            },
        ),
        (
            "memo_decodes",
            LoadingWork {
                memo_decodes: usize::MAX,
                ..LoadingWork::default()
            },
        ),
    ] {
        for missing_input in [false, true] {
            let store = fixture.store();
            let report = LoadingReport {
                work,
                diagnostics: Vec::new(),
            };
            let (cache, report) = ready(loading::load_with_report(
                &store,
                &fixture.recipe,
                selection,
                report,
            ));
            assert!(report.diagnostics.iter().any(|diagnostic| matches!(diagnostic, Diagnostic::CounterOverflow(counter) if *counter == name)));
            let trees = if missing_input {
                BTreeMap::new()
            } else {
                fixture.trees()
            };
            let result = complete(
                cache,
                report,
                &fixture.recipe,
                &inputs(&trees),
                ReplayMode::Check,
                selection,
            );
            if missing_input {
                let error = failure(result);
                assert!(matches!(
                    error.replay,
                    ReplayError::Evaluation(EvaluationError::MissingRoot(_))
                ));
                assert!(!error.loading.diagnostics.is_empty());
            } else {
                let result =
                    result.unwrap_or_else(|error| panic!("overflow cannot skip replay: {error:?}"));
                assert_output(&result, fixture);
                assert_eq!(
                    result.replay.cache.observation,
                    if name == "memo_decodes" {
                        CacheObservation::Hit
                    } else {
                        CacheObservation::Refused(CacheRefusal::Unavailable)
                    }
                );
                assert!(!result.loading.diagnostics.is_empty());
            }
        }
    }
}
