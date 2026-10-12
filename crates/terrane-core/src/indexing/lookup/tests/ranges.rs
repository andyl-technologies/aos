//! Compares literal candidate models and population seeks with measured logarithmic work.

use super::*;

/// Checks literal candidate ranges, value types and logarithmic population seeks.
///
/// # Panics
/// Panics if fixture construction or an asserted lookup contract fails.
pub(super) fn check() {
    let (data, present, _, gap) = model();
    let (old, original) = sources();
    let bytes = binding("uid", data.root);
    let (owner, trees) = bind(old, &original, &bytes);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let prepared = Prepared::prepare(recipe, &trees, MINIMUM, context(), &data).unwrap();
    assert_eq!(
        (
            prepared.owner(),
            prepared.root(),
            prepared.gap_root(),
            prepared.attribute(),
            prepared.profile(),
            prepared.minimum(),
            prepared.context()
        ),
        (
            owner,
            data.root,
            Some(gap),
            "uid",
            "terrane-index/v1",
            MINIMUM,
            context()
        )
    );
    assert_eq!(prepared.preparation().verification.candidates, 2);
    assert_eq!(prepared.preparation().verification.missing_objects, 2);
    let found = prepared.candidates(b"\x01").unwrap();
    assert_eq!(found.rows.len(), 1);
    assert_eq!(
        (
            found.rows[0].object(),
            found.rows[0].route(),
            found.rows[0].value()
        ),
        (ONE, present, Some(b"\x01".as_slice()))
    );
    assert_eq!(found.work.candidates, 1);
    assert_eq!(
        found.work.source_nodes + found.work.route_nodes + found.work.source_roots,
        0
    );
    assert!(prepared.candidates(b"\x03").unwrap().rows.is_empty());
    assert_eq!(prepared.all_missing().unwrap().rows.len(), 2);
    for malformed in [b"\x18\x01".as_slice(), b"\x01\x02", b"\x9f\xff"] {
        assert!(prepared.candidates(malformed).is_err());
    }

    for attribute in ["hash.sha256", "tag.custom"] {
        let value_a = [alloc::vec![0x58, 0x20], alloc::vec![0x44; 32]].concat();
        let value_b = [alloc::vec![0x58, 0x20], alloc::vec![0x55; 32]].concat();
        let source = tree(alloc::vec![
            leaf(b"a", file(ONE, Some(&value_a), attribute, false)),
            leaf(b"b", file(ONE, Some(&value_b), attribute, true)),
            leaf(b"c", file(TWO, Some(&value_a), attribute, true)),
            leaf(b"d", file(ONE, None, attribute, false)),
        ]);
        let old = source.root_identity();
        let original = BTreeMap::from([(old, source)]);
        let mut nodes = BTreeMap::new();
        let a = add(&mut nodes, &[terminal(b"a", ONE)], None);
        let b = add(&mut nodes, &[terminal(b"b", ONE)], None);
        let c = add(&mut nodes, &[terminal(b"c", TWO)], None);
        let d = add(&mut nodes, &[terminal(b"d", ONE)], None);
        let gap = add(&mut nodes, &[forward(&ONE, ONE, d)], None);
        let root = add(
            &mut nodes,
            &[
                forward(&value_key(&value_a, ONE), ONE, a),
                forward(&value_key(&value_a, TWO), TWO, c),
                forward(&value_key(&value_b, ONE), ONE, b),
            ],
            Some(gap),
        );
        let data = IndexData {
            root,
            nodes,
            work: evaluation::Work::default(),
        };
        let bytes = binding(attribute, root);
        let (owner, trees) = bind(old, &original, &bytes);
        let prepared = Prepared::prepare(
            IndexEvaluationRecipe::new(owner, attribute).unwrap(),
            &trees,
            MINIMUM,
            context(),
            &data,
        )
        .unwrap();
        let a_rows = prepared.candidates(&value_a).unwrap();
        assert_eq!(
            a_rows
                .rows
                .iter()
                .map(|row| (row.object(), row.route(), row.value()))
                .collect::<Vec<_>>(),
            alloc::vec![
                (ONE, a, Some(value_a.as_slice())),
                (TWO, c, Some(value_a.as_slice()))
            ]
        );
        let b_rows = prepared.candidates(&value_b).unwrap();
        assert_eq!(
            b_rows
                .rows
                .iter()
                .map(|row| (row.object(), row.route(), row.value()))
                .collect::<Vec<_>>(),
            alloc::vec![(ONE, b, Some(value_b.as_slice()))]
        );
        assert_eq!(
            a_rows.rows[0].occurrences().unwrap().rows[0].content,
            ContentRef::Inline(ONE)
        );
        assert_eq!(
            b_rows.rows[0].occurrences().unwrap().rows[0].content,
            ContentRef::Manifest(ONE)
        );
        assert_eq!(prepared.missing(ONE).unwrap().rows[0].route(), d);
        if attribute == "hash.sha256" {
            assert!(prepared.candidates(b"\x01").is_err());
            assert!(prepared.candidates(b"\x58\x20").is_err());
        }
    }

    // Independent row population: each file has its literal object/route pair.
    // The supplementary construction oracle checks this model once, before queries.
    for population in [1usize, 31, 1024] {
        let values = [b"\x01".as_slice(), b"\x18\x18", b"\x41\x00", b"\x61x"];
        let mut rows = Vec::new();
        let mut expected = Vec::new();
        let mut nodes = BTreeMap::new();
        let mut pointer_values = Vec::new();
        let mut primary = Vec::new();
        for index in 0..population {
            let key = alloc::format!("file{index:05}").into_bytes();
            let mut object = [0; 32];
            object[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let value = values[index % values.len()];
            let manifest = index % 2 != 0;
            rows.push(leaf(
                &key,
                file(object, Some(value), "tag.custom", manifest),
            ));
            let route = add(&mut nodes, &[terminal(&key, object)], None);
            let mut pointer = Vec::new();
            cbor::write_bytes(&mut pointer, &route);
            pointer_values.push(pointer);
            expected.push((value, object, route, key, manifest));
        }
        for ((value, object, _, _, _), pointer) in expected.iter().zip(&pointer_values) {
            primary.push(LeafItem {
                key: value_key(value, *object),
                entry: Entry {
                    kind: EntryKind::Index {
                        targets: alloc::vec![*object],
                    },
                    attrs: alloc::vec![Attribute {
                        name: "index.occurrences",
                        value: pointer
                    }],
                    attrs_present: true,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            });
        }
        primary.sort_by(|left, right| left.key.cmp(&right.key));
        let primary_tree = Tree::build(primary, None, MINIMUM, TreeUse::Index).unwrap();
        for node in primary_tree.nodes() {
            nodes.insert(node.identity(), node.encoded().to_vec());
        }
        let data = IndexData {
            root: primary_tree.root_identity(),
            nodes,
            work: evaluation::Work::default(),
        };
        let source = tree(rows);
        let old = source.root_identity();
        let original = BTreeMap::from([(old, source)]);
        let bytes = binding("tag.custom", data.root);
        let (owner, trees) = bind(old, &original, &bytes);
        let recipe = IndexEvaluationRecipe::new(owner, "tag.custom").unwrap();
        let oracle = evaluation::construct(&recipe, &trees, MINIMUM, context()).unwrap();
        assert_eq!((data.root, &data.nodes), (oracle.root, &oracle.nodes));
        let prepared = Prepared::prepare(recipe, &trees, MINIMUM, context(), &data).unwrap();
        let before = prepared.preparation();
        for value in values
            .into_iter()
            .chain([b"\x00".as_slice(), b"\x18\x19", b"\x62xx"])
        {
            let result = prepared.candidates(value).unwrap();
            let mut model: Vec<_> = expected.iter().filter(|row| row.0 == value).collect();
            model.sort_by_key(|row| row.1);
            let actual: Vec<_> = result
                .rows
                .iter()
                .map(|row| (row.value().unwrap(), row.object(), row.route()))
                .collect();
            let expected_fields: Vec<_> = model.iter().map(|row| (row.0, row.1, row.2)).collect();
            assert_eq!(
                actual, expected_fields,
                "population {population} value {value:?}"
            );
            assert_eq!(result.work.candidates, model.len());
            let bits = usize::BITS - population.leading_zeros();
            assert!(result.work.comparisons <= 2 * bits as usize + 2);
            assert_eq!(
                result.work.source_nodes + result.work.route_nodes + result.work.source_comparisons,
                0
            );
            for (candidate, model) in result.rows.iter().zip(model) {
                let occurrences = candidate.occurrences().unwrap();
                assert_eq!(occurrences.rows.len(), 1);
                let occurrence = &occurrences.rows[0];
                assert_eq!(
                    (
                        occurrence.source_root,
                        &occurrence.key,
                        occurrence.content,
                        occurrence.size,
                        occurrence.value
                    ),
                    (
                        owner,
                        &model.3,
                        if model.4 {
                            ContentRef::Manifest(model.1)
                        } else {
                            ContentRef::Inline(model.1)
                        },
                        if model.4 { MINIMUM + 1 } else { 1 },
                        Some(model.0)
                    )
                );
                assert_eq!(occurrences.work.occurrences, 1);
                assert!(occurrences.work.source_comparisons > 0);
                assert!(occurrences.work.source_nodes > 0);
            }
        }
        assert_eq!(before, prepared.preparation());
    }
}
