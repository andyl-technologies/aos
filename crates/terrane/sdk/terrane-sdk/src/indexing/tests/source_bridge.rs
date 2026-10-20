//! Feeds genuinely fetched sources into explicit full immutable construction.

use super::*;
use terrane_format::cbor;
use terrane_format::indexing::{completion, incremental, maintenance};

/// Checks initialization and loss rebuilding against independently encoded carriers.
///
/// # Panics
/// Panics when construction, completion, lookup, immutable inputs or separate
/// work accounting disagree with the independent physical-byte oracle.
pub(super) fn prove_initialization_and_rebuild() {
    for only_missing in [false, true] {
        let baseline = if only_missing {
            Fixture::only_missing()
        } else {
            Fixture::small()
        };
        // These exact carrier bytes were assembled directly from literal rows,
        // bindings and independent physical boundaries, before construction runs.
        let expected_nodes: BTreeMap<_, _> = if only_missing {
            [baseline.primary, baseline.gap, baseline.missing]
                .into_iter()
                .map(|node| (node, baseline.nodes[&node].clone()))
                .collect()
        } else {
            baseline
                .expected_requests
                .iter()
                .filter(|node| **node != baseline.owner && **node != baseline.child)
                .map(|node| (*node, baseline.nodes[node].clone()))
                .collect()
        };

        for operation in 0..3 {
            let mut selected = baseline.clone();
            if operation == 0 {
                selected.owner = store_node(&mut selected.nodes, leaf(&selected.owner_rows, None));
            } else if operation == 2 {
                selected.primary = store_node(&mut selected.nodes, leaf(&[], None));
                selected.rebuild_owner();
            }
            let expected_source = if only_missing {
                BTreeMap::from([(selected.owner, selected.nodes[&selected.owner].clone())])
            } else {
                source::namespace(&selected)
            };
            // Loss is explicit: only mandatory namespace bytes exist. Divergent
            // auxiliary bytes may exist, but source acquisition never reads them.
            let store = ReadOnly::new(if operation == 2 {
                selected.nodes.clone()
            } else {
                expected_source.clone()
            });
            let raw = source::source(&store, selected.owner);
            assert_eq!(raw.namespace, expected_source);
            assert_requests(&store, &expected_source.keys().copied().collect());
            let sources = raw.sources().require();
            let recipe = IndexEvaluationRecipe::new(selected.owner, "uid").require();
            let prepared =
                incremental::PreparedSource::new(&recipe, &sources.trees, MINIMUM, raw.context)
                    .require();
            let expected_loading = Loading {
                gets: if only_missing { 1 } else { 2 },
                fetched_bytes: expected_source.values().map(Vec::len).sum(),
                identity_checks: if only_missing { 1 } else { 3 },
                node_decodes: if only_missing { 1 } else { 3 },
                namespace_roots: if only_missing { 1 } else { 3 },
                carrier_checks: 0,
            };
            let expected_reconstruction = Reconstruction {
                node_decodes: if only_missing { 2 } else { 4 },
                identity_checks: if only_missing { 1 } else { 2 },
                trees: if only_missing { 1 } else { 2 },
                entries: if only_missing { 1 } else { 7 },
                compared_nodes: if only_missing { 1 } else { 2 },
            };
            assert_eq!(raw.loading(), expected_loading);
            assert_eq!(sources.work, expected_reconstruction);
            assert_eq!(
                prepared.preparation_work(),
                incremental::PreparationWork {
                    roots: if only_missing { 1 } else { 3 },
                    nodes: if only_missing { 1 } else { 3 },
                    entries: if only_missing { 1 } else { 9 },
                    bindings: usize::from(operation != 0),
                    supplied_map_lookups: if only_missing { 2 } else { 6 },
                    cached_roots: if only_missing { 1 } else { 2 },
                    cache_insertions: if only_missing { 1 } else { 3 },
                }
            );

            let arena = maintenance::ByteArena::new(1024 * 1024).require();
            let (state, construction) = if operation == 0 {
                maintenance::initialize(&recipe, &prepared, &arena, MINIMUM, raw.context).require()
            } else {
                maintenance::rebuild(&recipe, &prepared, &arena, MINIMUM, raw.context).require()
            };
            let (actual, exported) = state.materialize().require();
            assert_eq!(actual.root, baseline.primary);
            assert_eq!(actual.nodes, expected_nodes);
            assert_eq!(exported.nodes, expected_nodes.len());
            assert_eq!(
                exported.bytes,
                expected_nodes.values().map(Vec::len).sum::<usize>()
            );
            assert_eq!(actual.work, evaluation::Work::default());
            assert_eq!(
                construction.kind,
                if operation == 0 {
                    maintenance::ConstructionKind::NewlyEnabled
                } else {
                    maintenance::ConstructionKind::Rebuild
                }
            );
            assert_eq!(
                construction.work.mode,
                incremental::PopulationMode::NewlyEnabled
            );
            assert!(construction.work.initialization.work.item_reads > 0);
            assert!(
                construction
                    .work
                    .batches
                    .iter()
                    .any(|batch| batch.work.stream.node_bytes_encoded > 0)
            );

            // The completion input is the actual materialized construction,
            // already compared with independently assembled I/P/G bytes.
            prove_completion(
                selected.owner,
                &baseline,
                &sources,
                &actual,
                &arena,
                raw.context,
                only_missing,
            );
            assert_eq!(raw.loading(), expected_loading);
            assert_eq!(raw.sources().require().work, expected_reconstruction);
            assert_requests(&store, &expected_source.keys().copied().collect());

            // Construction never changes the raw owner's original binding or
            // turns its incomplete/divergent bound index into a verified index.
            assert_eq!(raw.namespace, expected_source);
        }
    }
}

fn prove_completion<'value>(
    candidate: Digest,
    baseline: &Fixture,
    sources: &Sources<'value>,
    actual: &IndexData,
    arena: &'value maintenance::ByteArena,
    context: SemanticContext,
    only_missing: bool,
) {
    let original = sources.trees[&candidate].root().encoded().to_vec();
    let expected_owner = &baseline.nodes[&baseline.owner];
    let expected_recipe = recipe_bytes(baseline.owner);
    let recipe_hash = memo_hash(&expected_recipe);
    let expected_memo = memo_bytes(recipe_hash, baseline.primary);
    let memo_identity = memo_hash(&expected_memo);
    assert_ne!(recipe_hash, memo_identity);

    for policy in [
        completion::MemoPolicy::Include,
        completion::MemoPolicy::Omit,
    ] {
        let completed = completion::complete(
            candidate,
            &sources.trees,
            &[completion::Selection {
                attribute: "uid",
                data: actual,
            }],
            arena,
            MINIMUM,
            context,
            policy,
        )
        .require();
        assert_eq!(completed.owner.tree.root_identity(), baseline.owner);
        assert_eq!(completed.owner.tree.root().encoded(), expected_owner);
        assert_eq!(completed.associations.len(), 1);
        let association = &completed.associations[0];
        assert_eq!(association.attribute, "uid");
        assert_eq!(association.index, actual.root);
        assert_eq!(association.recipe_bytes, expected_recipe);
        assert_eq!(association.recipe_hash, recipe_hash);
        if policy == completion::MemoPolicy::Include {
            let memo = association.memo.as_ref().require();
            assert_eq!(memo.bytes, expected_memo);
            assert_eq!(memo.identity, memo_identity);
            assert_eq!(memo.memo.recipe_hash(), recipe_hash);
            assert_eq!(memo.memo.result_root(), actual.root);
        } else {
            assert!(association.memo.is_none());
        }
        assert_eq!(completed.work.graph_handles_copied, sources.trees.len());
        assert_eq!(
            completed.work.owner_handles_copied,
            usize::from(candidate != baseline.owner)
        );
        assert_eq!(completed.work.recipe_bytes_encoded, expected_recipe.len());
        assert_eq!(
            completed.work.recipe_bytes_hashed,
            expected_recipe.len() + b"terrane-memo-v1\0".len()
        );
        assert_eq!(
            completed.work.memo_bytes_encoded,
            if policy == completion::MemoPolicy::Include {
                expected_memo.len()
            } else {
                0
            }
        );
        assert_eq!(
            completed.work.memo_bytes_hashed,
            if policy == completion::MemoPolicy::Include {
                expected_memo.len() + b"terrane-memo-v1\0".len()
            } else {
                0
            }
        );
        assert_eq!(completed.work.checks.len(), 1);
        assert_eq!(
            completed.work.checks[0].before.candidates,
            if only_missing { 0 } else { 2 }
        );
        assert_eq!(completed.work.checks[0].before.missing_objects, 1);

        let mut graph = sources.trees.clone();
        graph.insert(
            completed.owner.tree.root_identity(),
            completed.owner.tree.clone(),
        );
        let recipe =
            IndexEvaluationRecipe::new(completed.owner.tree.root_identity(), "uid").require();
        let prepared = Prepared::prepare(recipe, &graph, MINIMUM, context, actual).require();
        assert_eq!(prepared.preparation(), &completed.work.checks[0].after);
        let candidates = prepared.candidates(b"\x01").require();
        assert_eq!(candidates.rows.len(), usize::from(!only_missing));
        assert_eq!(candidates.work.candidates, usize::from(!only_missing));
        if let Some(present) = candidates.rows.first() {
            assert_eq!(present.object(), OBJECT);
            assert_eq!(present.occurrences().require().rows.len(), 3);
        }
        // Zero candidate rows still retain the independently enumerated G.
        let missing = prepared.all_missing().require();
        assert_eq!(missing.rows.len(), 1);
        assert_eq!(missing.work.missing_rows, 1);
        assert_eq!(missing.rows[0].object(), OBJECT);
        let occurrences = missing.rows[0].occurrences().require();
        assert_eq!(occurrences.rows.len(), if only_missing { 1 } else { 3 });
        assert_eq!(
            occurrences.work.occurrences,
            if only_missing { 1 } else { 3 }
        );
        assert_eq!(sources.trees[&candidate].root().encoded(), original);
    }
}

fn recipe_bytes(owner: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa3, 1];
    cbor::write_text(&mut bytes, "index");
    bytes.extend_from_slice(&[2, 0x81]);
    cbor::write_bytes(&mut bytes, &owner);
    bytes.extend_from_slice(&[3, 0xa2]);
    cbor::write_text(&mut bytes, "profile");
    cbor::write_text(&mut bytes, "terrane-index/v1");
    cbor::write_text(&mut bytes, "attribute");
    cbor::write_text(&mut bytes, "uid");
    bytes
}

fn memo_bytes(recipe: Digest, index: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1];
    cbor::write_bytes(&mut bytes, &recipe);
    bytes.push(2);
    cbor::write_bytes(&mut bytes, &index);
    bytes
}

fn memo_hash(bytes: &[u8]) -> Digest {
    let mut preimage = b"terrane-memo-v1\0".to_vec();
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}
