//! Independently models physical wire work across prefix-compressed hierarchy levels.

use super::*;
use crate::tree_builder::StreamWork;

#[derive(Clone)]
struct ModelNode {
    last: Vec<u8>,
    digest: Digest,
    count: u64,
    weight: u64,
}

#[derive(Default)]
struct Model {
    nodes: BTreeMap<Digest, Vec<u8>>,
    work: StreamWork,
    encodings: usize,
    levels: usize,
}

fn identity(bytes: &[u8]) -> Digest {
    let mut preimage = b"terrane-node-v1\0".to_vec();
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}

fn item(row: &Row, previous: &[u8]) -> Vec<u8> {
    // Extract the independently assembled entry after the one-row Node frame.
    let mut bytes = Vec::new();
    let shared = previous
        .iter()
        .zip(&row.key)
        .take_while(|(a, b)| a == b)
        .count();
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &row.key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    let standalone = wire(core::slice::from_ref(row), None);
    let entry_offset = 5 + 1 + 1 + row.key.len() + usize::from(row.key.len() >= 24) + 1;
    bytes.extend_from_slice(&standalone[entry_offset..]);
    bytes
}

impl Model {
    fn store(
        &mut self,
        level: u8,
        items: &[Vec<u8>],
        last: Vec<u8>,
        count: u64,
        children_weight: u64,
    ) -> ModelNode {
        let mut bytes = alloc::vec![0xa2, 1, level, 2];
        cbor::write_array(&mut bytes, items.len());
        for item in items {
            bytes.extend_from_slice(item);
        }
        self.work.node_bytes_encoded += bytes.len();
        self.work.node_bytes_hashed += bytes.len() + b"terrane-node-v1\0".len();
        self.encodings += 1;
        let digest = identity(&bytes);
        let weight = bytes.len() as u64 + children_weight;
        self.nodes.insert(digest, bytes);
        ModelNode {
            last,
            digest,
            count,
            weight,
        }
    }

    fn cut(&mut self, size: usize, stored: usize, full: &[u8]) -> u8 {
        self.work.frontier_checks += 1;
        let total = size + stored;
        if total > 65_536 {
            return 1;
        }
        if total == 65_536 {
            return 2;
        }
        if total < 4_096 {
            return 0;
        }
        self.work.item_bytes_hashed += full.len();
        let base = if total >= 32_768 {
            1 << 24
        } else {
            (1 << 20) + (total - 4_096) * ((1 << 24) - (1 << 20)) / 28_672
        };
        let threshold = (base as u64 * stored as u64 / 8).min(1 << 32);
        let hash = blake3::hash(full);
        let hash = u32::from_le_bytes(hash.as_bytes()[..4].try_into().unwrap());
        if u64::from(hash) < threshold { 2 } else { 0 }
    }

    fn build(&mut self, rows: &[Row]) -> ModelNode {
        let mut leaves = Vec::new();
        let mut pending = Vec::new();
        let mut size = 0;
        let mut previous = Vec::new();
        for row in rows {
            let full = item(row, &[]);
            let stored = item(row, &previous);
            self.work.item_bytes_encoded += full.len() + stored.len();
            let decision = self.cut(size, stored.len(), &full);
            if decision == 1 {
                leaves.push(self.store(0, &pending, previous.clone(), pending.len() as u64, 0));
                pending.clear();
                size = 0;
                self.cut(0, full.len(), &full);
            }
            let stored = if decision == 1 { full } else { stored };
            size += stored.len();
            pending.push(stored);
            previous = row.key.clone();
            if decision == 2 {
                leaves.push(self.store(0, &pending, previous.clone(), pending.len() as u64, 0));
                pending.clear();
                size = 0;
                previous.clear();
            }
        }
        if !pending.is_empty() {
            leaves.push(self.store(0, &pending, previous, pending.len() as u64, 0));
        }
        let mut level = 0;
        while leaves.len() > 1 {
            level += 1;
            self.levels += 1;
            let mut parents = Vec::new();
            let mut pending = Vec::new();
            let mut size = 0;
            let mut count = 0;
            let mut weight = 0;
            let mut last = Vec::new();
            for child in leaves {
                let mut reference = alloc::vec![0x84];
                cbor::write_bytes(&mut reference, &child.last);
                cbor::write_bytes(&mut reference, &child.digest);
                cbor::write_uint(&mut reference, child.count);
                cbor::write_uint(&mut reference, child.weight);
                self.work.item_bytes_encoded += reference.len();
                let decision = self.cut(size, reference.len(), &reference);
                if decision == 1 {
                    parents.push(self.store(level, &pending, last.clone(), count, weight));
                    pending.clear();
                    size = 0;
                    count = 0;
                    weight = 0;
                    self.cut(0, reference.len(), &reference);
                }
                size += reference.len();
                count += child.count;
                weight += child.weight;
                last = child.last;
                pending.push(reference);
                if decision == 2 {
                    parents.push(self.store(level, &pending, last.clone(), count, weight));
                    pending.clear();
                    size = 0;
                    count = 0;
                    weight = 0;
                }
            }
            if !pending.is_empty() {
                parents.push(self.store(level, &pending, last, count, weight));
            }
            leaves = parents;
        }
        leaves.pop().unwrap()
    }
}

/// Proves physical verifier work against literal multilevel and repeated-graft models.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn prove_physical_work() {
    let (owner, graph) = sources();
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let data = independent(0);
    let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &data).unwrap();
    assert_eq!(checked.physical_work.reconstructions.len(), 14);
    for report in &checked.physical_work.reconstructions {
        assert_partition(&report.entries);
        assert_partition(&report.properties);
        assert_eq!(report.initial.node_bytes_encoded, 5);
        assert_eq!(report.initial.node_bytes_hashed, 21);
        if report.root == data.root {
            assert_eq!(report.properties.node_encodings, 1);
            assert_eq!(
                report.properties.stream.node_bytes_encoded,
                data.nodes[&data.root].len()
            );
            assert_eq!(
                report.properties.stream.node_bytes_hashed,
                data.nodes[&data.root].len() + b"terrane-node-v1\0".len()
            );
            assert_eq!(report.properties.stream, report.properties.root_properties);
        } else {
            assert_eq!(report.properties, crate::tree_builder::Work::default());
        }
    }

    let rows: Vec<_> = (0..2400)
        .map(|number| terminal(alloc::format!("prefix-{number:05}").as_bytes(), ONE))
        .collect();
    let mut model = Model::default();
    let route = model.build(&rows);
    assert!(model.levels >= 1);
    assert!(model.work.item_bytes_hashed > 0);
    let source = Tree::build(
        rows.iter()
            .map(|row| leaf(&row.key, file(ONE, Some(b"\x01"), false)))
            .collect(),
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let child = source.root_identity();
    let owner_tree = Tree::build(
        alloc::vec![leaf(b"g", graft(child)), leaf(b"h", graft(child))],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let owner = owner_tree.root_identity();
    let graph = BTreeMap::from([(child, source), (owner, owner_tree)]);
    let owner_rows = [
        forward(b"g", ONE, route.digest),
        forward(b"h", ONE, route.digest),
    ];
    let owner_route = add(&mut model.nodes, &owner_rows, None);
    let root = add(
        &mut model.nodes,
        &[forward(&primary_key(1, ONE), ONE, owner_route)],
        None,
    );
    let data = IndexData {
        root,
        nodes: model.nodes.clone(),
        work: Work::default(),
    };
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let result = evaluation::verify(&recipe, &graph, MINIMUM, context(), &data).unwrap();
    assert_eq!(result.candidates, 1);
    assert_eq!(result.missing_objects, 0);
    let physical = &result.physical_work;
    assert_eq!(physical.reconstructions.len(), 4);
    let route_reports: Vec<_> = physical
        .reconstructions
        .iter()
        .filter(|report| report.root == route.digest)
        .collect();
    assert_eq!(route_reports.len(), 2);
    assert_eq!(route_reports[0], route_reports[1]);
    for report in route_reports {
        assert_partition(&report.entries);
        assert_partition(&report.properties);
        assert_eq!(report.initial.node_bytes_encoded, 5);
        assert_eq!(report.initial.node_bytes_hashed, 21);
        assert_eq!(
            report.entries.stream.item_bytes_encoded,
            model.work.item_bytes_encoded
        );
        assert_eq!(
            report.entries.stream.item_bytes_hashed,
            model.work.item_bytes_hashed
        );
        assert_eq!(
            report.entries.stream.node_bytes_encoded,
            model.work.node_bytes_encoded
        );
        assert_eq!(
            report.entries.stream.node_bytes_hashed,
            model.work.node_bytes_hashed
        );
        assert_eq!(report.entries.node_encodings, model.encodings);
        assert_eq!(report.entries.new_levels.len(), model.levels);
        assert_eq!(
            report.entries.stream.frontier_checks,
            model.work.frontier_checks + model.levels + 3
        );
        assert_eq!(report.properties, crate::tree_builder::Work::default());
    }
    let route_bytes: usize = data
        .nodes
        .iter()
        .filter(|(digest, _)| **digest != root && **digest != owner_route)
        .map(|(_, bytes)| bytes.len())
        .sum();
    let checked_bytes = data.nodes[&root].len() + data.nodes[&owner_route].len() + 2 * route_bytes;
    assert_eq!(
        physical.node_bytes_hashed,
        checked_bytes + result.work.nodes * b"terrane-node-v1\0".len()
    );
    assert_eq!(physical.node_decodes, result.work.nodes + 4);
    assert_eq!(
        physical.node_bytes_decoded,
        checked_bytes
            + data.nodes[&root].len()
            + data.nodes[&owner_route].len()
            + 2 * data.nodes[&route.digest].len()
    );

    // Keep a complete, correctly hashed closure while falsifying an internal
    // ChildRef weight. Reconstructing the physical stream must reject it.
    let mut divergent = data.clone();
    let mut bytes = divergent.nodes.remove(&route.digest).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let divergent_route = identity(&bytes);
    divergent.nodes.insert(divergent_route, bytes);
    divergent.nodes.remove(&owner_route);
    divergent.nodes.remove(&root);
    let divergent_owner = add(
        &mut divergent.nodes,
        &[
            forward(b"g", ONE, divergent_route),
            forward(b"h", ONE, divergent_route),
        ],
        None,
    );
    divergent.root = add(
        &mut divergent.nodes,
        &[forward(&primary_key(1, ONE), ONE, divergent_owner)],
        None,
    );
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &divergent),
        Err(Error::Relationship)
    );

    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Ordinary).unwrap();
    let owner = empty.root_identity();
    let graph = BTreeMap::from([(owner, empty)]);
    let bytes = alloc::vec![0xa2, 1, 0, 2, 0x80];
    let root = identity(&bytes);
    let data = IndexData {
        root,
        nodes: BTreeMap::from([(root, bytes)]),
        work: Work::default(),
    };
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let result = evaluation::verify(&recipe, &graph, MINIMUM, context(), &data).unwrap();
    assert_eq!(result.physical_work.node_decodes, 2);
    assert_eq!(result.physical_work.node_bytes_decoded, 10);
    assert_eq!(result.physical_work.node_bytes_hashed, 21);
    let report = &result.physical_work.reconstructions[0];
    assert_eq!(report.entries, crate::tree_builder::Work::default());
    assert_eq!(report.properties, crate::tree_builder::Work::default());

    // The ordinary Tree codec distinguishes this seven-byte empty property
    // map, but the index carrier schema forbids it even on an empty primary.
    let bytes = alloc::vec![0xa3, 1, 0, 2, 0x80, 3, 0xa0];
    let root = identity(&bytes);
    let data = IndexData {
        root,
        nodes: BTreeMap::from([(root, bytes)]),
        work: Work::default(),
    };
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &data),
        Err(Error::Carrier(crate::indexing::Error::Schema))
    );
}

fn assert_partition(work: &crate::tree_builder::Work) {
    let mut phases = alloc::vec![work.completion, work.root_properties, work.preparation];
    phases.extend(work.regions.iter().map(|region| region.work));
    phases.extend(work.new_levels.iter().map(|level| level.work));
    assert_eq!(
        work.stream.item_reads,
        phases.iter().map(|phase| phase.item_reads).sum()
    );
    assert_eq!(
        work.stream.comparisons,
        phases.iter().map(|phase| phase.comparisons).sum()
    );
    assert_eq!(
        work.stream.frontier_checks,
        phases.iter().map(|phase| phase.frontier_checks).sum()
    );
    assert_eq!(
        work.stream.item_bytes_encoded,
        phases.iter().map(|phase| phase.item_bytes_encoded).sum()
    );
    assert_eq!(
        work.stream.node_bytes_encoded,
        phases.iter().map(|phase| phase.node_bytes_encoded).sum()
    );
    assert_eq!(
        work.stream.item_bytes_hashed,
        phases.iter().map(|phase| phase.item_bytes_hashed).sum()
    );
    assert_eq!(
        work.stream.node_bytes_hashed,
        phases.iter().map(|phase| phase.node_bytes_hashed).sum()
    );
    assert_eq!(work.adoption, StreamWork::default());
}
