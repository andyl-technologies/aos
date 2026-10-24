//! Literal namespace recurrence models and rehashed contextual refusal graphs.

use super::fields::{MINIMUM, context, digest, node, wire};
use super::models::{Case, cases};
use super::support::{Value, encode, hex};
use std::collections::BTreeMap;
use terrane_format::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    indexing::{
        IndexEvaluationRecipe,
        carrier::{self, Role},
        evaluation::{self, IndexData, Work},
    },
    tree_builder::Tree,
    tree_format::{self, EntryKind, NodeItems, TreeUse},
};

fn id(bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Node, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

fn source_trees(all: &[Case]) -> BTreeMap<Digest, Tree<'static>> {
    all.iter()
        .filter(|c| c.positive && c.family == "carrier-node" && c.usage == "ordinary")
        .map(|case| {
            let model = node(case);
            let NodeItems::Leaf(rows) = model.items else {
                panic!("namespace leaf")
            };
            let tree = Tree::build(rows, model.props, MINIMUM, TreeUse::Ordinary).unwrap();
            assert_eq!(
                tree.root_identity(),
                digest(&hex(case.identity)),
                "{} independent source root",
                case.name
            );
            assert_eq!(tree.root().encoded(), wire(case));
            (tree.root_identity(), tree)
        })
        .collect()
}

#[derive(Debug, PartialEq)]
struct Occurrence {
    hops: Vec<Vec<u8>>,
    object: Digest,
    value: Option<Vec<u8>>,
    layers: Vec<Vec<(String, Vec<u8>)>>,
}

fn inventory(
    trees: &BTreeMap<Digest, Tree<'static>>,
    root: Digest,
    hops: &mut Vec<Vec<u8>>,
    layers: &mut Vec<Vec<(String, Vec<u8>)>>,
    out: &mut Vec<Occurrence>,
) {
    let tree = &trees[&root];
    layers.push(
        tree.root()
            .node()
            .props
            .as_ref()
            .unwrap_or(&vec![])
            .iter()
            .map(|p| (p.name.to_owned(), p.value.to_vec()))
            .collect(),
    );
    for row in tree.iter() {
        hops.push(row.key.clone());
        match &row.entry.kind {
            EntryKind::File { size, content, .. } => {
                assert_eq!(*size, 33);
                let terrane_format::tree_format::ContentRef::Inline(object) = content else {
                    panic!("actual inline O")
                };
                out.push(Occurrence {
                    hops: hops.clone(),
                    object: *object,
                    value: row
                        .entry
                        .attrs
                        .iter()
                        .find(|a| a.name == "uid")
                        .map(|a| a.value.to_vec()),
                    layers: layers.clone(),
                });
            }
            EntryKind::Tree { root, props } => {
                layers.push(
                    props
                        .as_ref()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|p| (p.name.to_owned(), p.value.to_vec()))
                        .collect(),
                );
                inventory(trees, *root, hops, layers, out);
                layers.pop();
            }
            _ => panic!("complete finite source profile"),
        }
        hops.pop();
    }
    layers.pop();
}

#[path = "occurrences.rs"]
mod occurrences;

/// Checks four complete independent namespace occurrence recurrences.
///
/// # Panics
/// Panics if source models, local hops, opaque policy layers, auxiliary bytes, or exhaustive verification differ.
pub(crate) fn sources() {
    let all = cases();
    let trees = source_trees(&all);
    for graph in occurrences::graphs() {
        let owner = digest(&hex(graph.owner));
        let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
        let mut actual = Vec::new();
        inventory(&trees, owner, &mut Vec::new(), &mut Vec::new(), &mut actual);
        assert_eq!(
            actual, graph.occurrences,
            "{} complete path/O/value/opaque layers",
            graph.name
        );
        for occurrence in &actual {
            assert_eq!(
                occurrence.object,
                digest(&hex(
                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"
                ))
            );
            if let Some(value) = &occurrence.value {
                assert_eq!(value, &hex("1818"));
            }
        }
        let data = evaluation::construct(&recipe, &trees, MINIMUM, context()).unwrap();
        assert_eq!(
            data.root,
            digest(&hex(graph.primary)),
            "{} exact I",
            graph.name
        );
        for (digest, bytes) in &data.nodes {
            let independent = all
                .iter()
                .find(|c| c.positive && c.family == "carrier-node" && hex(c.identity) == *digest)
                .expect("published auxiliary Node");
            assert_eq!(
                bytes,
                &wire(independent),
                "{} full constructed P/G/I bytes",
                independent.name
            );
        }
        let verified = evaluation::verify(&recipe, &trees, MINIMUM, context(), &data).unwrap();
        assert_eq!(verified.candidates, usize::from(graph.present > 0));
        assert_eq!(verified.missing_objects, usize::from(graph.missing > 0));
        assert_eq!(
            actual.iter().filter(|o| o.value.is_some()).count(),
            graph.present
        );
        assert_eq!(
            actual.iter().filter(|o| o.value.is_none()).count(),
            graph.missing
        );
        if graph.name == "long-local-routes" {
            assert_eq!(actual[0].hops.len(), 18);
            assert_eq!(
                actual[0].hops.iter().map(Vec::len).sum::<usize>() + 17,
                4355
            );
            assert!(actual[0].hops.iter().all(|key| key.len() <= 255));
        }
        if graph.name == "repeated-grafts" {
            assert_ne!(actual[0].layers[1], actual[2].layers[1]);
        }
        if graph.present == 0 {
            assert_eq!(verified.candidates, 0);
            assert_eq!(verified.missing_objects, 1);
        }
    }
}

fn role(name: &str) -> Role {
    match name {
        "primary" => Role::Primary,
        "gap" => Role::Gap,
        "present-route" => Role::PresentRoute,
        "missing-route" => Role::MissingRoute,
        _ => panic!("declared contextual role"),
    }
}

// Rehash the mutation, then every referenced ancestor. Only the resulting
// reachable auxiliary closure remains, preventing unused-node or stale-ID
// failures from substituting for exhaustive source-relationship refusal.
fn rewire(
    current: Digest,
    replace: Digest,
    mutated: &Value,
    models: &BTreeMap<Digest, Value>,
    out: &mut BTreeMap<Digest, Vec<u8>>,
) -> Digest {
    let mut model = if current == replace {
        mutated.clone()
    } else {
        models[&current].clone()
    };
    if let Some(rows) = model.optional(2) {
        let mut changes = Vec::new();
        for row in rows.array() {
            let entry = &row.array()[2];
            if let Some(attrs) = entry.optional(9) {
                for (name, pointer) in attrs.fields() {
                    if name.text() == "index.occurrences" {
                        let old = digest(pointer.bytes());
                        let new = rewire(old, replace, mutated, models, out);
                        changes.push((old, new));
                    }
                }
            }
        }
        for (old, new) in changes {
            replace_pointer(&mut model, old, new);
        }
    }
    if let Some(props) = model.optional(3)
        && let Some((_, binding)) = props
            .fields()
            .iter()
            .find(|(k, _)| k.text() == "index-gaps")
    {
        let old = digest(&hex(binding.named("value").text()));
        let new = rewire(old, replace, mutated, models, out);
        replace_pointer(&mut model, old, new);
    }
    let bytes = encode(&model);
    let new = id(&bytes);
    out.insert(new, bytes);
    new
}

fn replace_pointer(value: &mut Value, old: Digest, new: Digest) {
    match value {
        Value::Bytes(bytes) if bytes.as_slice() == old => *bytes = new.to_vec(),
        Value::Text(text)
            if *text == old.iter().map(|b| format!("{b:02x}")).collect::<String>() =>
        {
            *text = Box::leak(
                new.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into_boxed_str(),
            );
        }
        Value::Array(values) => {
            for value in values {
                replace_pointer(value, old, new);
            }
        }
        Value::Map(fields) => {
            for (_, value) in fields {
                replace_pointer(value, old, new);
            }
        }
        _ => {}
    }
}

/// Requires each declared contextual refusal after valid source selection.
///
/// # Panics
/// Panics if role or placement checks accept a control, or a freshly rehashed relationship graph fails at an unrelated seam.
pub(crate) fn controls() {
    let all = cases();
    let trees = source_trees(&all);
    let models: BTreeMap<_, _> = all
        .iter()
        .filter(|c| c.positive && c.family == "carrier-node")
        .map(|c| (digest(&hex(c.identity)), c.model.clone()))
        .collect();
    for case in all.iter().filter(|c| c.family == "carrier-negative") {
        let bytes = wire(case);
        let owner = digest(&hex(case.source));
        let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
        assert!(
            trees.contains_key(&owner),
            "{} declared source R",
            case.name
        );
        let usage = if case.role == "ordinary-namespace" {
            TreeUse::Ordinary
        } else {
            TreeUse::Index
        };
        let decoded = tree_format::decode_node_for(&bytes, case.is_root, MINIMUM, usage);
        if matches!(case.scope, "format" | "format-context") {
            assert!(decoded.is_err(), "{} generic format/placement", case.name);
            continue;
        }
        let decoded = decoded.unwrap();
        if let Some(props) = &decoded.props
            && props.iter().any(|property| property.name == "index-gaps")
        {
            use terrane_format::properties::semantics::RecordedContext;
            for revision in [1, 2] {
                let old = RecordedContext::new(revision, 3, &["index-gaps"]).unwrap();
                old.validate_map(props)
                    .expect("canonical later metadata remains inert");
                old.validate_graft_overrides(props)
                    .expect("later metadata has no active placement restrictions");
            }
            assert!(carrier::SemanticContext::new(2, 2, 1).is_err());
        }

        if case.role == "ordinary-namespace" {
            assert!(
                terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])
                    .unwrap()
                    .validate_map(decoded.props.as_ref().unwrap())
                    .is_err()
            );
            continue;
        }
        let selected = role(case.role);
        if case.scope != "source-relationship" {
            assert!(
                carrier::validate_node(context(), selected, &decoded, case.is_root).is_err(),
                "{} role refusal",
                case.name
            );
            continue;
        }
        carrier::validate_node(context(), selected, &decoded, true)
            .expect("generic-valid and role-valid relationship control");
        let base = evaluation::construct(&recipe, &trees, MINIMUM, context()).unwrap();
        let target = match selected {
            Role::Primary => base.root,
            Role::Gap => {
                let root = tree_format::decode_node_for(
                    &base.nodes[&base.root],
                    true,
                    MINIMUM,
                    TreeUse::Index,
                )
                .unwrap();
                carrier::validate_node(context(), Role::Primary, &root, true)
                    .unwrap()
                    .unwrap()
                    .node()
            }
            Role::PresentRoute | Role::MissingRoute => {
                let prefix = if case.source
                    == "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d"
                {
                    "carrier-child-"
                } else {
                    "carrier-parent-"
                };
                let name = format!(
                    "{prefix}{}-route",
                    if selected == Role::PresentRoute {
                        "present"
                    } else {
                        "missing"
                    }
                );
                digest(&hex(all.iter().find(|c| c.name == name).unwrap().identity))
            }
        };
        let mut nodes = BTreeMap::new();
        let root = rewire(base.root, target, &case.model, &models, &mut nodes);
        assert_ne!(root, base.root, "{} mutation propagated to I", case.name);
        for (key, bytes) in &nodes {
            assert_eq!(*key, id(bytes), "{} newly hashed closure", case.name);
        }
        let data = IndexData {
            root,
            nodes,
            work: Work::default(),
        };
        assert!(
            matches!(
                evaluation::verify(&recipe, &trees, MINIMUM, context(), &data),
                Err(evaluation::Error::Relationship)
            ),
            "{} exhaustive source refusal",
            case.name
        );
    }
}
