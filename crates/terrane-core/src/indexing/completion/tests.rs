//! Exercises immutable completion against separately encoded owner/index/association oracles.

use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};

use super::model::add as add_tree;
use super::{model::*, *};
use crate::{
    cbor,
    indexing::{
        IndexRoots,
        incremental::{PreparedSource, discover},
        maintenance,
    },
    tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse},
};

fn run<'a>(
    owner: Digest,
    graph: &Graph<'a>,
    selections: &[Selection<'_>],
    arena: &'a maintenance::ByteArena,
) -> TestResult<Completion<'a>> {
    Ok(complete(
        owner,
        graph,
        selections,
        arena,
        MINIMUM,
        context()?,
        MemoPolicy::Include,
    )?)
}

fn assert_association(
    result: &Completion<'_>,
    attribute: &str,
    data: &evaluation::IndexData,
) -> TestResult {
    let association = result
        .associations
        .iter()
        .find(|value| value.attribute == attribute)
        .ok_or("missing association")?;
    let expected = recipe(result.owner.tree.root_identity(), attribute);
    let q = hash(b"terrane-memo-v1", &expected);
    let bytes = memo(q, data.root);
    let m = hash(b"terrane-memo-v1", &bytes);
    assert_eq!(association.recipe_bytes, expected);
    assert_eq!(association.recipe_hash, q);
    assert_eq!(association.index, data.root);
    let memo = association.memo.as_ref().ok_or("missing common Memo")?;
    assert_eq!(memo.bytes, bytes);
    assert_eq!(memo.identity, m);
    assert_eq!(memo.memo, Memo::new(q, data.root));
    assert_eq!(Memo::decode(&bytes)?, memo.memo);
    assert_ne!(q, m);
    Ok(())
}

#[test]
fn owner_completion_binds_independent_indexes_to_new_owner() -> TestResult {
    let arena = maintenance::ByteArena::new(1_000_000)?;
    let (mut graph, plain) = fixture()?;
    let base = graph[&plain].clone();
    assert_eq!(base.root().encoded(), namespace_wire(&base, None));
    let uid = index(&graph, plain, "uid");
    let tag = index(&graph, plain, "tag.a");
    let preserved = binding(&[("gid", OTHER)]);
    let original_properties = alloc::vec![
        Property {
            name: "index-roots",
            value: arena.copy(&preserved)?
        },
        Property {
            name: "index",
            value: &[0x80]
        }
    ];
    let old = base
        .with_properties(Some(original_properties.clone()))?
        .tree;
    let owner = old.root_identity();
    graph.insert(owner, old);
    let snapshots: BTreeMap<_, _> = graph
        .iter()
        .map(|(root, tree)| (*root, tree.root().encoded().to_vec()))
        .collect();
    let recipe_s = IndexEvaluationRecipe::new(owner, "uid")?;
    let source = PreparedSource::new(&recipe_s, &graph, MINIMUM, context()?)?;
    let (state, construction) =
        maintenance::initialize(&recipe_s, &source, &arena, MINIMUM, context()?)?;
    assert_eq!(
        construction.kind,
        maintenance::ConstructionKind::NewlyEnabled
    );
    let (actual, _) = state.materialize()?;
    assert_eq!(actual.root, uid.root);
    assert_eq!(actual.nodes, uid.nodes);
    let selections = [
        Selection {
            attribute: "tag.a",
            data: &tag,
        },
        Selection {
            attribute: "uid",
            data: &actual,
        },
    ];
    let before_arena = arena.payload_bytes();
    let result = run(owner, &graph, &selections, &arena)?;
    let merged = binding(&[("tag.a", tag.root), ("gid", OTHER), ("uid", uid.root)]);
    let expected_properties = [
        Property {
            name: "index",
            value: &[0x80],
        },
        Property {
            name: "index-roots",
            value: &merged,
        },
    ];
    let expected_owner = owner_wire(&base, &expected_properties);
    assert_eq!(result.owner.tree.root().encoded(), expected_owner);
    assert_eq!(
        result.owner.tree.root_identity(),
        hash(b"terrane-node-v1", &expected_owner)
    );
    assert_eq!(
        result
            .associations
            .iter()
            .map(|association| association.attribute.as_str())
            .collect::<Vec<_>>(),
        ["uid", "tag.a"]
    );
    assert_eq!(result.work.arena_bytes_copied, merged.len());
    assert_eq!(arena.payload_bytes() - before_arena, merged.len());
    assert_eq!(result.work.checks.len(), 2);
    for check in &result.work.checks {
        assert_eq!(check.before.candidates, 2);
        assert_eq!(check.before.missing_objects, 1);
        assert_eq!(check.after.verification.missing_objects, 1);
        assert_eq!(check.source.roots, 3);
        assert!(check.before.physical_work.node_bytes_hashed > 0);
    }
    assert_association(&result, "uid", &uid)?;
    assert_association(&result, "tag.a", &tag)?;
    assert_eq!(state.owner(), owner);
    for (root, bytes) in snapshots {
        assert_eq!(graph[&root].root().encoded(), bytes);
    }
    assert_eq!(uid.nodes, index(&graph, owner, "uid").nodes);
    assert_eq!(tag.nodes, index(&graph, owner, "tag.a").nodes);
    let reversed = [selections[1], selections[0]];
    let second = run(owner, &graph, &reversed, &arena)?;
    assert_eq!(second.associations, result.associations);
    assert_eq!(second.owner.tree.root().encoded(), expected_owner);
    Ok(())
}

#[test]
fn owner_completion_preserves_bindings_and_unchanged_descendants() -> TestResult {
    let arena = maintenance::ByteArena::new(1_000_000)?;
    let mut graph = Graph::new();
    let rows = (0..5000)
        .map(|number| {
            leaf(
                alloc::format!("directory-{number:06}").as_bytes(),
                Entry {
                    kind: EntryKind::Directory { mode: 0o755 },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            )
        })
        .collect();
    let plain = add_tree(&mut graph, rows, None)?;
    let base = graph[&plain].clone();
    assert!(base.root().level() > 0);
    let empty = index(&graph, plain, "uid");
    assert_eq!(empty.nodes[&empty.root], [0xa2, 1, 0, 2, 0x80]);
    let existing = binding(&[("tag.a", OTHER)]);
    let props = alloc::vec![
        Property {
            name: "index-roots",
            value: arena.copy(&existing)?
        },
        Property {
            name: "index",
            value: &[0x80]
        }
    ];
    let original = base.with_properties(Some(props))?.tree;
    let owner = original.root_identity();
    graph.insert(owner, original.clone());
    let selection = [Selection {
        attribute: "uid",
        data: &empty,
    }];
    let result = run(owner, &graph, &selection, &arena)?;
    let merged = binding(&[("uid", empty.root), ("tag.a", OTHER)]);
    let expected = owner_wire(
        &base,
        &[
            Property {
                name: "index-roots",
                value: &merged,
            },
            Property {
                name: "index",
                value: &[0x80],
            },
        ],
    );
    assert_eq!(result.owner.tree.root().encoded(), expected);
    assert_eq!(result.owner.emitted.len(), 1);
    assert_eq!(result.owner.work.node_encodings, 1);
    assert_eq!(result.owner.work.item_encodings, 0);
    for (old, new) in original
        .root()
        .children()
        .iter()
        .zip(result.owner.tree.root().children())
    {
        assert_eq!(old.identity(), new.identity());
        assert!(Rc::ptr_eq(old, new));
    }
    let roots = IndexRoots::decode_binding(
        result
            .owner
            .tree
            .props()
            .ok_or("missing properties")?
            .iter()
            .find(|value| value.name == "index-roots")
            .ok_or("missing binding")?
            .value,
    )?;
    assert_eq!(roots.get("tag.a"), Some(OTHER));
    assert_eq!(result.work.checks[0].before.candidates, 0);
    assert_eq!(result.work.checks[0].before.missing_objects, 0);
    assert_association(&result, "uid", &empty)?;
    Ok(())
}

#[test]
fn owner_completion_rebuilds_divergent_binding_without_changing_index_bytes() -> TestResult {
    let arena = maintenance::ByteArena::new(1_000_000)?;
    let (mut graph, plain) = fixture()?;
    let wrong = binding(&[("uid", OTHER)]);
    let corrupted_owner = graph[&plain]
        .with_properties(Some(alloc::vec![Property {
            name: "index-roots",
            value: arena.copy(&wrong)?
        }]))?
        .tree;
    let owner = corrupted_owner.root_identity();
    graph.insert(owner, corrupted_owner.clone());
    let expected = index(&graph, owner, "uid");
    let recipe_s = IndexEvaluationRecipe::new(owner, "uid")?;
    assert_eq!(
        lookup::Prepared::prepare(recipe_s, &graph, MINIMUM, context()?, &expected).err(),
        Some(evaluation::Error::Relationship)
    );
    let source = PreparedSource::new(&recipe_s, &graph, MINIMUM, context()?)?;
    let (rebuilt, full) = maintenance::rebuild(&recipe_s, &source, &arena, MINIMUM, context()?)?;
    assert_eq!(full.kind, maintenance::ConstructionKind::Rebuild);
    let (data, _) = rebuilt.materialize()?;
    assert_eq!(data.root, expected.root);
    assert_eq!(data.nodes, expected.nodes);
    let result = run(
        owner,
        &graph,
        &[Selection {
            attribute: "uid",
            data: &data,
        }],
        &arena,
    )?;
    assert_ne!(result.owner.tree.root_identity(), owner);
    assert_eq!(
        graph[&owner].root().encoded(),
        corrupted_owner.root().encoded()
    );
    assert_eq!(rebuilt.owner(), owner);
    assert_eq!(data.nodes, expected.nodes);
    assert_association(&result, "uid", &data)?;

    let changed = graph[&plain]
        .with_properties(Some(alloc::vec![Property {
            name: "index",
            value: &[0x81, 0x63, b'u', b'i', b'd']
        }]))?
        .tree;
    let next = changed.root_identity();
    let mut next_graph = graph.clone();
    next_graph.insert(next, changed);
    let next_recipe = IndexEvaluationRecipe::new(next, "uid")?;
    let replacement = PreparedSource::new(&next_recipe, &next_graph, MINIMUM, context()?)?;
    let discovery = discover(&source, &replacement)?;
    let (updated, incremental) = maintenance::update(&rebuilt, &discovery)?;
    assert_eq!(incremental.delta_data, 0);
    let (export, _) = updated.materialize()?;
    assert_eq!(export.nodes, expected.nodes);
    let second = run(
        next,
        &next_graph,
        &[Selection {
            attribute: "uid",
            data: &export,
        }],
        &arena,
    )?;
    assert_eq!(second.associations[0].index, result.associations[0].index);
    assert_ne!(
        second.associations[0].recipe_hash,
        result.associations[0].recipe_hash
    );
    assert_eq!(updated.owner(), next);
    assert!(second.work.checks[0].before.work.source_entries > 0);
    // Adding bindings to an equivalent namespace does not invent an index origin.
    assert_eq!(index(&next_graph, next, "uid").nodes, expected.nodes);
    Ok(())
}

#[test]
fn owner_completion_refuses_invalid_sources_selections_and_auxiliary_closures() -> TestResult {
    let (graph, owner) = fixture()?;
    let data = index(&graph, owner, "uid");
    let arena = maintenance::ByteArena::new(1_000_000)?;
    let selected = [Selection {
        attribute: "uid",
        data: &data,
    }];
    let refused = |graph: &Graph<'_>, root, selections: &[Selection<'_>]| {
        complete(
            root,
            graph,
            selections,
            &arena,
            MINIMUM,
            context().map_err(|_| Error::Limit)?,
            MemoPolicy::Omit,
        )
        .err()
        .ok_or(Error::Limit)
    };
    assert_eq!(refused(&graph, owner, &[])?, Error::EmptySelection);
    assert_eq!(
        refused(&graph, owner, &[selected[0], selected[0]])?,
        Error::DuplicateSelection
    );
    assert_eq!(
        refused(
            &graph,
            owner,
            &[Selection {
                attribute: "unknown",
                data: &data
            }]
        )?,
        Error::Binding(super::super::Error::UnknownAttribute)
    );
    assert_eq!(
        refused(&graph, OTHER, &selected)?,
        Error::Source(evaluation::Error::MissingSource)
    );
    let mut missing = graph.clone();
    let child = graph
        .keys()
        .find(|root| **root != owner)
        .copied()
        .ok_or("missing fixture child")?;
    missing.remove(&child);
    assert_eq!(
        refused(&missing, owner, &selected)?,
        Error::Source(evaluation::Error::MissingSource)
    );
    let mut wrong_key = graph.clone();
    wrong_key.insert(owner, graph[&child].clone());
    assert_eq!(
        refused(&wrong_key, owner, &selected)?,
        Error::Source(evaluation::Error::Source)
    );
    assert_eq!(
        complete(
            owner,
            &graph,
            &selected,
            &arena,
            MINIMUM + 1,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::Source(evaluation::Error::Source))
    );
    let mut missing_node = data.clone();
    missing_node.nodes.remove(&data.root);
    assert_eq!(
        refused(
            &graph,
            owner,
            &[Selection {
                attribute: "uid",
                data: &missing_node
            }]
        )?,
        Error::Index(evaluation::Error::MissingNode)
    );
    let mut corrupt = data.clone();
    corrupt.nodes.insert(data.root, alloc::vec![0xf6]);
    assert_eq!(
        refused(
            &graph,
            owner,
            &[Selection {
                attribute: "uid",
                data: &corrupt
            }]
        )?,
        Error::Index(evaluation::Error::Relationship)
    );
    let mut extra = data.clone();
    let empty = alloc::vec![0xa2, 1, 0, 2, 0x80];
    extra.nodes.insert(hash(b"terrane-node-v1", &empty), empty);
    assert_eq!(
        refused(
            &graph,
            owner,
            &[Selection {
                attribute: "uid",
                data: &extra
            }]
        )?,
        Error::Index(evaluation::Error::Relationship)
    );
    let divergent = index(&graph, child, "uid");
    assert_eq!(
        refused(
            &graph,
            owner,
            &[Selection {
                attribute: "uid",
                data: &divergent
            }]
        )?,
        Error::Index(evaluation::Error::Relationship)
    );
    for malformed in [alloc::vec![0xa0], {
        let mut value = binding(&[("uid", data.root)]);
        let last = value.len() - 1;
        value[last] = 0xf5;
        value
    }] {
        let mut malformed_graph = graph.clone();
        let bad = graph[&owner]
            .with_properties(Some(alloc::vec![Property {
                name: "index-roots",
                value: arena.copy(&malformed)?
            }]))?
            .tree;
        let bad_root = bad.root_identity();
        malformed_graph.insert(bad_root, bad);
        assert_eq!(
            refused(&malformed_graph, bad_root, &selected)?,
            Error::Source(evaluation::Error::Carrier(super::super::Error::Schema))
        );
        // A reached child's malformed binding is also refused even though the
        // immutable row relation alone would not interpret that wrapper.
        let bad_parent = add_tree(
            &mut malformed_graph,
            alloc::vec![leaf(b"g", graft(bad_root))],
            None,
        )?;
        assert!(matches!(
            refused(&malformed_graph, bad_parent, &selected)?,
            Error::Source(_)
        ));
    }
    assert_eq!(
        SemanticContext::new(2, 2, 1),
        Err(super::super::Error::Schema)
    );
    let expected_binding = binding(&[("uid", data.root)]);
    let before_layer = arena.payload_bytes();
    // Only malformed fixture payloads were copied during the refused cases.
    assert_eq!(before_layer, 1 + expected_binding.len());

    let mut layer_graph = graph.clone();
    let mut whiteout = graft([0; 32]);
    whiteout.kind = EntryKind::Whiteout;
    let layer = graph[&owner]
        .with_usage(TreeUse::OverlayLayer)?
        .insert(leaf(b"zz", whiteout))?
        .tree;
    let layer_root = layer.root_identity();
    let layer_bytes = layer.root().encoded().to_vec();
    layer_graph.insert(layer_root, layer);
    assert_eq!(index(&layer_graph, layer_root, "uid").nodes, data.nodes);
    let completed_layer = run(layer_root, &layer_graph, &selected, &arena)?;
    assert_eq!(completed_layer.owner.tree.usage(), TreeUse::OverlayLayer);
    assert_eq!(completed_layer.associations[0].index, data.root);
    let actual_binding = completed_layer
        .owner
        .tree
        .props()
        .and_then(|properties| {
            properties
                .iter()
                .find(|property| property.name == "index-roots")
        })
        .ok_or("missing completed layer binding")?;
    assert_eq!(actual_binding.value, expected_binding);
    // Successful completion adds one independently encoded binding payload.
    assert_eq!(
        completed_layer.work.arena_bytes_copied,
        expected_binding.len()
    );
    assert_eq!(arena.payload_bytes() - before_layer, expected_binding.len());
    assert_eq!(layer_graph[&layer_root].root().encoded(), layer_bytes);
    assert_association(&completed_layer, "uid", &data)?;
    assert_eq!(
        completed_layer.work.checks[0].before.candidates,
        completed_layer.work.checks[0].after.verification.candidates
    );
    assert_eq!(
        completed_layer.work.checks[0].before.missing_objects,
        completed_layer.work.checks[0]
            .after
            .verification
            .missing_objects
    );
    let mut unsupported = graph.clone();
    let conflict = Entry {
        kind: EntryKind::Conflict {
            candidates: alloc::vec![file(Some(&[1])), file(None)],
            base: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let conflict_root = add_tree(
        &mut unsupported,
        alloc::vec![leaf(b"conflict", conflict)],
        None,
    )?;
    assert_eq!(
        refused(&unsupported, conflict_root, &selected)?,
        Error::Source(evaluation::Error::Incomplete)
    );
    let override_bytes = binding(&[("uid", data.root)]);
    let override_entry = Entry {
        kind: EntryKind::Tree {
            root: child,
            props: Some(alloc::vec![Property {
                name: "index-roots",
                value: &override_bytes
            }]),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let mut overrides = graph.clone();
    let override_root = add_tree(
        &mut overrides,
        alloc::vec![LeafItem {
            key: b"g".to_vec(),
            entry: override_entry
        }],
        None,
    )?;
    assert_eq!(
        refused(&overrides, override_root, &selected)?,
        Error::Source(evaluation::Error::Source)
    );
    let zero = maintenance::ByteArena::new(0)?;
    assert_eq!(
        complete(
            owner,
            &graph,
            &selected,
            &zero,
            MINIMUM,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::Arena(maintenance::Error::Allocation))
    );
    assert_eq!(zero.payload_bytes(), 0);
    assert_eq!(arena.payload_bytes(), 1 + 2 * expected_binding.len());
    assert_eq!(data.nodes, index(&graph, owner, "uid").nodes);
    Ok(())
}

#[test]
fn owner_completion_forms_common_memo_only_after_binding_and_separates_work() -> TestResult {
    let (initial_graph, owner) = fixture()?;
    let data = index(&initial_graph, owner, "uid");
    let selection = [Selection {
        attribute: "uid",
        data: &data,
    }];
    let merged = binding(&[("uid", data.root)]);
    let arena = maintenance::ByteArena::new(merged.len())?;
    let mut graph = initial_graph.clone();
    let result = run(owner, &graph, &selection, &arena)?;
    let bytes = owner_wire(
        &graph[&owner],
        &[Property {
            name: "index-roots",
            value: &merged,
        }],
    );
    assert_eq!(result.owner.tree.root().encoded(), bytes);
    assert_eq!(result.work.owner_bytes_emitted, bytes.len());
    assert_eq!(
        result.work.owner_bytes_hashed,
        bytes.len() + b"terrane-node-v1\0".len()
    );
    assert_eq!(result.work.graph_handles_copied, graph.len());
    assert_eq!(result.work.owner_handles_copied, 1);
    assert_eq!(result.work.arena_bytes_copied, merged.len());
    assert_eq!(result.work.attribute_bytes_copied, 3);
    let expected_recipe = recipe(hash(b"terrane-node-v1", &bytes), "uid");
    assert_eq!(result.work.recipe_bytes_encoded, expected_recipe.len());
    assert_eq!(
        result.work.recipe_bytes_hashed,
        expected_recipe.len() + b"terrane-memo-v1\0".len()
    );
    assert_eq!(result.work.memo_bytes_encoded, 71);
    assert_eq!(
        result.work.memo_bytes_hashed,
        71 + b"terrane-memo-v1\0".len()
    );
    assert_association(&result, "uid", &data)?;
    let q_before = hash(b"terrane-memo-v1", &recipe(owner, "uid"));
    assert_ne!(result.associations[0].recipe_hash, q_before);
    let check = &result.work.checks[0];
    assert_eq!(check.before, check.after.verification);
    assert_eq!(check.before.work.source_roots, 3);
    assert_eq!(check.before.work.source_entries, 7);
    assert_eq!(check.before.work.nodes, 9);
    assert_eq!(check.before.work.rows, 12);
    let (decoded, hashed) = fixture_physical_bytes(&data);
    assert_eq!(check.before.physical_work.node_decodes, 18);
    assert_eq!(check.before.physical_work.node_bytes_decoded, decoded);
    assert_eq!(check.before.physical_work.node_bytes_hashed, hashed);
    assert_eq!(check.before.physical_work.reconstructions.len(), 9);
    for reconstruction in &check.before.physical_work.reconstructions {
        assert_eq!(reconstruction.initial.node_bytes_encoded, 5);
        assert_eq!(
            reconstruction.initial.node_bytes_hashed,
            5 + b"terrane-node-v1\0".len()
        );
        assert_eq!(reconstruction.entries.node_encodings, 1);
        if reconstruction.root == data.root {
            assert_eq!(reconstruction.properties.node_encodings, 1);
            assert_eq!(
                reconstruction.properties.root_properties.node_bytes_encoded,
                data.nodes[&data.root].len()
            );
        } else {
            assert_eq!(reconstruction.properties.node_encodings, 0);
        }
    }
    assert_eq!(result.work.binding_value_bytes_encoded, merged.len() - 16);
    assert_eq!(result.work.binding_bytes_encoded, merged.len() * 2 - 16);
    assert_eq!(check.after.loaded_nodes, data.nodes.len());
    assert_eq!(
        check.after.loaded_bytes,
        data.nodes.values().map(Vec::len).sum()
    );
    let root = result.owner.tree.root_identity();
    graph.insert(root, result.owner.tree.clone());
    let payload = arena.payload_bytes();
    let noop = run(root, &graph, &selection, &arena)?;
    assert_eq!(noop.work.arena_bytes_copied, 0);
    assert_eq!(noop.work.owner_bytes_emitted, 0);
    assert_eq!(noop.work.owner_bytes_hashed, 0);
    assert_eq!(noop.work.owner_handles_copied, 0);
    assert!(noop.owner.emitted.is_empty());
    assert!(Rc::ptr_eq(
        &result.owner.tree.root_rc(),
        &noop.owner.tree.root_rc()
    ));
    assert_eq!(arena.payload_bytes(), payload);
    assert_eq!(noop.associations, result.associations);
    assert!(noop.work.checks[0].source.bindings > 0);
    let small = maintenance::ByteArena::new(merged.len() - 1)?;
    assert_eq!(
        complete(
            owner,
            &graph,
            &selection,
            &small,
            MINIMUM,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::Arena(maintenance::Error::Allocation))
    );
    assert_eq!(small.payload_bytes(), 0);
    let omitted = complete(
        root,
        &graph,
        &selection,
        &arena,
        MINIMUM,
        context()?,
        MemoPolicy::Omit,
    )?;
    assert!(omitted.associations[0].memo.is_none());
    assert_eq!(omitted.work.memo_bytes_encoded, 0);
    assert_eq!(omitted.work.memo_bytes_hashed, 0);
    assert_eq!(omitted.work.recipe_bytes_encoded, expected_recipe.len());

    let zero = maintenance::ByteArena::new(0)?;
    let stable = maintenance::ByteArena::new(1000)?;
    let mut empty_graph = Graph::new();
    let empty_owner = add_tree(&mut empty_graph, Vec::new(), None)?;
    let empty_data = index(&empty_graph, empty_owner, "uid");
    let empty_binding = binding(&[("uid", empty_data.root)]);
    // Different legal in-memory property order must remain a true no-op.
    let properties = alloc::vec![
        Property {
            name: "index-roots",
            value: stable.copy(&empty_binding)?
        },
        Property {
            name: "index",
            value: &[0x80]
        }
    ];
    let completed = empty_graph[&empty_owner]
        .with_properties(Some(properties))?
        .tree;
    let completed_root = completed.root_identity();
    empty_graph.insert(completed_root, completed.clone());
    let same = run(
        completed_root,
        &empty_graph,
        &[Selection {
            attribute: "uid",
            data: &empty_data,
        }],
        &zero,
    )?;
    assert!(same.owner.emitted.is_empty());
    assert!(Rc::ptr_eq(&same.owner.tree.root_rc(), &completed.root_rc()));
    assert_eq!(same.work.arena_bytes_copied, 0);
    assert_eq!(same.work.checks[0].before.candidates, 0);
    assert_eq!(same.work.checks[0].before.missing_objects, 0);

    let gap_arena = maintenance::ByteArena::new(1000)?;
    let mut gap_graph = Graph::new();
    let gap_owner = add_tree(
        &mut gap_graph,
        alloc::vec![leaf(b"missing", file(None))],
        None,
    )?;
    let gap_data = index(&gap_graph, gap_owner, "uid");
    let gaps = run(
        gap_owner,
        &gap_graph,
        &[Selection {
            attribute: "uid",
            data: &gap_data,
        }],
        &gap_arena,
    )?;
    assert_eq!(gaps.work.checks[0].before.candidates, 0);
    assert_eq!(gaps.work.checks[0].before.missing_objects, 1);
    assert_eq!(gaps.work.checks[0].after.verification.candidates, 0);
    assert_eq!(gaps.work.checks[0].after.verification.missing_objects, 1);
    assert_association(&gaps, "uid", &gap_data)?;

    let mut count = usize::MAX;
    assert_eq!(super::add(&mut count, 1), Err(Error::Limit));
    assert_eq!(count, usize::MAX);
    let mut payload = Vec::new();
    cbor::write_array(&mut payload, 257);
    for number in 0..256 {
        let name = alloc::format!("tag.{number:03}{}", "a".repeat(246));
        assert_eq!(name.len(), 253);
        cbor::write_text(&mut payload, &name);
    }
    cbor::write_text(&mut payload, &alloc::format!("tag.{}", "z".repeat(176)));
    let large_arena = maintenance::ByteArena::new(100_000)?;
    let many_names: Vec<_> = (0..900)
        .map(|number| alloc::format!("tag.large-{number:04}"))
        .collect();
    let many_selections: Vec<_> = many_names
        .iter()
        .map(|name| Selection {
            attribute: name,
            data: &empty_data,
        })
        .collect();
    assert_eq!(
        complete(
            empty_owner,
            &empty_graph,
            &many_selections,
            &large_arena,
            MINIMUM,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::Binding(super::super::Error::Limit))
    );

    let mut large_graph = Graph::new();
    let large_owner = add_tree(
        &mut large_graph,
        Vec::new(),
        Some(alloc::vec![Property {
            name: "index",
            value: large_arena.copy(&payload)?
        }]),
    )?;
    assert_eq!(
        complete(
            large_owner,
            &large_graph,
            &[Selection {
                attribute: "uid",
                data: &empty_data
            }],
            &large_arena,
            MINIMUM,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::Owner(crate::tree_format::Error::Limit))
    );
    let expected_property = binding(&[("uid", empty_data.root)]);
    let expected_root = owner_wire(
        &empty_graph[&empty_owner],
        &[Property {
            name: "index-roots",
            value: &expected_property,
        }],
    );
    let collision_root = hash(b"terrane-node-v1", &expected_root);
    let mut collision = empty_graph.clone();
    collision.insert(collision_root, empty_graph[&empty_owner].clone());
    assert_eq!(
        complete(
            empty_owner,
            &collision,
            &[Selection {
                attribute: "uid",
                data: &empty_data
            }],
            &large_arena,
            MINIMUM,
            context()?,
            MemoPolicy::Omit
        )
        .err(),
        Some(Error::GraphCollision)
    );
    Ok(())
}
