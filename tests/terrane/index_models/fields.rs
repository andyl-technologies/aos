//! Complete public field models, identities, historical contexts and decoder refusals.

use super::models::{Case, cases};
use super::support::{Value, encode, hex, leak, published};
use terrane_format::{
    identity::{Descriptor, Digest, IdentityKind, TERRANE_V1},
    indexing::{
        IndexBinding, IndexEvaluationRecipe, IndexKey, IndexRoots,
        carrier::{self, Role, SemanticContext},
    },
    tree_format::{
        self, Attribute, ContentRef, Entry, EntryKind, ExtendedAttribute, LeafItem, Node,
        NodeItems, Property, TreeUse,
    },
};

/// Pins every physical fixture to the registered minimum Chunk size.
pub(crate) const MINIMUM: u64 = 262_144;

/// Returns the explicit registered carrier tuple 3/2/1.
///
/// # Panics
/// Panics if the owning API rejects that registered tuple.
pub(crate) fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

/// Copies an exact 32-byte fixture identity.
///
/// # Panics
/// Panics if the input is not exactly 32 bytes.
pub(crate) fn digest(bytes: &[u8]) -> Digest {
    bytes.try_into().expect("digest32")
}

/// Constructs raw property bindings from independent primitive fields.
///
/// # Panics
/// Panics if the model is not a text-keyed property map.
pub(crate) fn properties(value: &Value) -> Vec<Property<'static>> {
    value
        .fields()
        .iter()
        .map(|(k, v)| Property {
            name: k.text(),
            value: leak(encode(v)),
        })
        .collect()
}

/// Constructs every public Entry field from an independent primitive model.
///
/// # Panics
/// Panics if fixture fields are missing, mistyped, out of range, or use an unsupported entry or content tag.
pub(crate) fn entry(value: &Value) -> Entry<'static> {
    let kind = match value.field(1).uint() {
        1 => {
            let content = value.field(4).array();
            EntryKind::File {
                mode: value.field(2).uint().try_into().unwrap(),
                size: value.field(3).uint(),
                content: match content[0].uint() {
                    0 => ContentRef::Inline(digest(content[1].bytes())),
                    1 => ContentRef::Manifest(digest(content[1].bytes())),
                    _ => panic!("content tag"),
                },
                link_id: value.optional(5).map(|v| leak(v.bytes().to_vec())),
            }
        }
        4 => EntryKind::Tree {
            root: digest(value.field(6).bytes()),
            props: value.optional(7).map(properties),
        },
        7 => EntryKind::Index {
            targets: value
                .field(14)
                .array()
                .iter()
                .map(|v| digest(v.bytes()))
                .collect(),
        },
        _ => panic!("fixture entry type"),
    };
    Entry {
        kind,
        attrs: value
            .optional(9)
            .map(|m| {
                m.fields()
                    .iter()
                    .map(|(k, v)| Attribute {
                        name: k.text(),
                        value: leak(encode(v)),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        attrs_present: value.optional(9).is_some(),
        xattrs: value
            .optional(10)
            .map(|m| {
                m.fields()
                    .iter()
                    .map(|(k, v)| ExtendedAttribute {
                        name: leak(k.bytes().to_vec()),
                        value: leak(v.bytes().to_vec()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        xattrs_present: value.optional(10).is_some(),
        provenance: value.optional(11).map(|v| digest(v.bytes())),
    }
}

/// Constructs a complete public leaf Node from independent expanded fields.
///
/// # Panics
/// Panics if the fixture level, property fields or expanded Entry fields are invalid.
pub(crate) fn node(case: &Case) -> Node<'static> {
    Node {
        level: case.model.field(1).uint().try_into().unwrap(),
        items: NodeItems::Leaf(
            case.full_entries
                .iter()
                .map(|(key, value)| LeafItem {
                    key: key.clone(),
                    entry: entry(value),
                })
                .collect(),
        ),
        props: case.model.optional(3).map(properties),
    }
}

/// Selects the fixture's declared physical tree use.
pub(crate) fn usage(case: &Case) -> TreeUse {
    if case.usage == "ordinary" {
        TreeUse::Ordinary
    } else {
        TreeUse::Index
    }
}

/// Compares independently assembled bytes with the complete published wire.
///
/// # Panics
/// Panics if published fields are missing or the complete byte sequences differ.
pub(crate) fn wire(case: &Case) -> Vec<u8> {
    let independent = match &case.model {
        Value::Bytes(b) if case.family == "source-chunk" => b.clone(),
        _ => encode(&case.model),
    };
    let published = published(case.name, "wire");
    assert_eq!(
        independent, published,
        "{} complete primitive fields",
        case.name
    );
    published
}

/// Checks every immutable identity, preimage, and descriptor field.
///
/// # Panics
/// Panics if any published field or owning identity or descriptor differs.
pub(crate) fn immutable(case: &Case, bytes: &[u8], kind: IdentityKind) {
    let identity = TERRANE_V1.calculate(kind, bytes).unwrap();
    assert_eq!(
        identity.digest(),
        hex(case.identity),
        "{} identity",
        case.name
    );
    let domain = TERRANE_V1.domain(kind).unwrap();
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend(bytes);
    assert_eq!(
        preimage,
        published(case.name, "preimage"),
        "{} preimage",
        case.name
    );
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap();
    let expected = published(case.name, "descriptor_wire");
    let decoded = Descriptor::decode(&TERRANE_V1, &expected).unwrap();
    assert_eq!(descriptor, decoded, "{} descriptor fields", case.name);
    assert_eq!(descriptor.encode(), expected);
    assert_eq!(descriptor.algorithm(), "blake3");
    assert_eq!(descriptor.domain(), domain);
    assert_eq!(descriptor.digest(), identity.digest());
    assert_eq!(descriptor.size(), bytes.len() as u64);
    descriptor.verify_bytes(&TERRANE_V1, kind, bytes).unwrap();
}

/// Compares complete public Node and Entry models with published bytes.
///
/// # Panics
/// Panics if encoding, decoding, complete fields, or immutable descriptors differ.
pub(crate) fn compare_node(case: &Case) {
    let bytes = wire(case);
    let model = node(case);
    assert_eq!(
        tree_format::encode_node_for(&model, case.is_root, MINIMUM, usage(case)).unwrap(),
        bytes,
        "{} encoding",
        case.name
    );
    let decoded = tree_format::decode_node_for(&bytes, case.is_root, MINIMUM, usage(case)).unwrap();
    assert_eq!(decoded, model, "{} complete public Node fields", case.name);
    let NodeItems::Leaf(rows) = &decoded.items else {
        panic!("leaf witness")
    };
    for (row, (_, primitive)) in rows.iter().zip(&case.full_entries) {
        assert_eq!(
            tree_format::encode_entry(&row.entry, MINIMUM).unwrap(),
            encode(primitive)
        );
        assert_eq!(
            tree_format::decode_entry_bytes(&encode(primitive), MINIMUM).unwrap(),
            row.entry
        );
    }
    immutable(case, &bytes, IdentityKind::Node);
}

/// Checks independent owner bindings and closed or retained recipe fields.
///
/// # Panics
/// Panics if any positive model, lookup key, or declared decoder refusal differs.
pub(crate) fn bindings_and_recipes() {
    for case in cases().iter().filter(|c| {
        matches!(
            c.family,
            "owner-binding"
                | "closed-recipe"
                | "retained-recipe"
                | "historical-recipe"
                | "carrier-recipe"
        )
    }) {
        let bytes = wire(case);
        if case.family == "owner-binding" {
            if !case.positive {
                assert!(IndexRoots::decode_binding(&bytes).is_err(), "{}", case.name);
                continue;
            }
            let inner = case.model.named("value");
            let mut expected_bindings: Vec<_> = inner
                .fields()
                .iter()
                .map(|(name, node)| IndexBinding {
                    attribute: name.text(),
                    node: digest(&hex(node.text())),
                })
                .collect();
            expected_bindings.sort_by(|left, right| {
                encode(&Value::Text(left.attribute)).cmp(&encode(&Value::Text(right.attribute)))
            });

            let independent_inner = encode(inner);
            let roots = IndexRoots::decode_value(&independent_inner).unwrap();
            assert_eq!(roots.as_bindings(), expected_bindings);
            assert_eq!(roots.encode_value(), independent_inner);
            assert_eq!(roots.encode_binding().unwrap(), bytes);
            assert_eq!(IndexRoots::decode_binding(&bytes).unwrap(), roots);
        } else if !case.positive {
            assert!(
                IndexEvaluationRecipe::decode(&bytes).is_err(),
                "{}",
                case.name
            );
        } else {
            if case.family == "retained-recipe" {
                assert!(IndexEvaluationRecipe::decode(&bytes).is_err());
                let commit = commit_model(Some(bytes.clone()));
                let decoded =
                    terrane_format::refs::Commit::decode(&commit.encode().unwrap()).unwrap();
                assert_eq!(decoded, commit);
                assert_eq!(decoded.profile_pair.recipe.as_ref(), Some(&bytes));
            } else {
                let owner = digest(case.model.field(2).array()[0].bytes());
                let attribute = case.model.field(3).named("attribute").text();
                let recipe = IndexEvaluationRecipe::new(owner, attribute).unwrap();
                assert_eq!(recipe.encode(), bytes);
                assert_eq!(IndexEvaluationRecipe::decode(&bytes).unwrap(), recipe);
                assert_eq!(recipe.owner(), owner);
                assert_eq!(recipe.attribute(), attribute);
                assert_eq!(
                    recipe.profile(),
                    case.model.field(3).named("profile").text()
                );
                assert_eq!(
                    recipe.identity().unwrap().to_vec(),
                    published(case.name, "lookup_q")
                );
            }
            let mut preimage = b"terrane-memo-v1\0".to_vec();
            preimage.extend(&bytes);
            assert_eq!(preimage, published(case.name, "lookup_preimage"));
            assert_eq!(
                TERRANE_V1
                    .calculate(IdentityKind::Memo, &bytes)
                    .unwrap()
                    .digest(),
                published(case.name, "lookup_q")
            );
        }
    }
}

/// Checks complete opaque values, object suffixes, and inclusive equality bounds.
///
/// # Panics
/// Panics if canonical keys or bounds differ, or a malformed key is accepted.
pub(crate) fn keys() {
    for case in cases().iter().filter(|c| c.family == "opaque-key") {
        let bytes = if case.positive {
            published(case.name, "wire")
        } else {
            wire(case)
        };
        if !case.positive {
            assert!(IndexKey::decode(&bytes).is_err(), "{}", case.name);
            continue;
        }
        let value = encode(&case.model);
        let model = IndexKey::new(&value, [0xab; 32]).unwrap();
        assert_eq!(model.encode(), bytes);
        let decoded = IndexKey::decode(&bytes).unwrap();
        assert_eq!(decoded, model);
        assert_eq!(decoded.value(), value);
        assert_eq!(decoded.object(), [0xab; 32]);
        let (lower, upper) = model.equality_bounds();
        assert_eq!(lower, hex(case.lower));
        assert_eq!(upper, hex(case.upper));
        assert!(lower <= bytes && bytes <= upper);
    }
    assert_eq!(
        encode(&Value::Map(vec![
            (Value::Bytes(vec![]), Value::UInt(0)),
            (Value::UInt(256), Value::UInt(0))
        ])),
        hex("a2190100004000")
    );
}

/// Checks complete historical data without activating later carrier semantics.
///
/// # Panics
/// Panics if historical fields change or retained data acquires active interpretation.
pub(crate) fn historical() {
    for case in cases()
        .iter()
        .filter(|c| c.family == "historical-node" && c.positive)
    {
        compare_node(case);
        if case.usage == "index" {
            assert!(
                carrier::validate_node(context(), Role::Primary, &node(case), true).is_err(),
                "{} must remain retained only",
                case.name
            );
        } else if let Some(props) = node(case).props {
            use terrane_format::properties::semantics::RecordedContext;
            RecordedContext::new(1, 3, &["index-roots", "index-gaps"])
                .unwrap()
                .validate_map(&props)
                .unwrap();
            assert!(SemanticContext::new(1, 1, 1).is_err());
        }
    }
    let all = cases();
    let case = all
        .iter()
        .find(|c| c.family == "historical-commit")
        .unwrap();
    let bytes = wire(case);
    let recipe = encode(case.model.field(6).field(3));
    let model = commit_model(Some(recipe));
    assert_eq!(model.encode().unwrap(), bytes);
    assert_eq!(terrane_format::refs::Commit::decode(&bytes).unwrap(), model);
    immutable(case, &bytes, IdentityKind::Commit);
}

fn commit_model(recipe: Option<Vec<u8>>) -> terrane_format::refs::Commit {
    use terrane_format::refs::{Commit, CommitSource, PrincipalKind, ProfilePair, Provenance};
    Commit {
        tree: [1; 32],
        parents: vec![],
        provenance: Provenance {
            issuer: "issuer".into(),
            token_id: [2; 16],
            subject: "subject".into(),
            kind: PrincipalKind::Workload,
            workload_identity: None,
            process: "fixture process".into(),
            observed_at: 24,
            writer_epoch: 7,
            source: CommitSource::Built,
            embedded_token: None,
        },
        timestamp: 24,
        message: String::new(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    }
}

/// Checks complete carrier Nodes and the actual source Chunk descriptor.
///
/// # Panics
/// Panics if fields, role validation, immutable identities, or the raw Chunk envelope differ.
pub(crate) fn carriers() {
    for case in cases()
        .iter()
        .filter(|c| c.positive && matches!(c.family, "carrier-node" | "primitive-containing-node"))
    {
        compare_node(case);
        if case.family == "carrier-node" && case.usage == "index" {
            let role = if case.role.starts_with("present route") {
                Role::PresentRoute
            } else if case.role.starts_with("missing route") {
                Role::MissingRoute
            } else if case.role.starts_with("missing objects") {
                Role::Gap
            } else {
                Role::Primary
            };
            carrier::validate_node(context(), role, &node(case), true)
                .expect("declared positive role");
        }
        if case.family == "primitive-containing-node" && case.usage == "index" {
            assert!(
                carrier::validate_node(context(), Role::Primary, &node(case), true).is_err(),
                "{} generic opaque data remains inactive",
                case.name
            );
        }
    }
    let all = cases();
    let chunk = all.iter().find(|c| c.family == "source-chunk").unwrap();
    let bytes = wire(chunk);
    assert_eq!(bytes, b"inert D-104 direct-chunk fixture\n");
    assert_eq!(bytes.len(), 33);
    immutable(chunk, &bytes, IdentityKind::Chunk);
    let mut envelope = vec![0];
    envelope.extend(&bytes);
    let parsed = terrane_format::codec::parse_envelope(&envelope).unwrap();
    assert_eq!(parsed.codec, terrane_format::codec::Codec::Raw);
    assert_eq!(parsed.body, bytes);
}

/// Requires generic format or placement refusal of exact independent inputs.
///
/// # Panics
/// Panics if a malformed input is accepted or an expected placement model cannot be inspected.
pub(crate) fn negatives() {
    for case in cases()
        .iter()
        .filter(|c| !c.positive && (c.family == "historical-node" || c.scope == "format"))
    {
        let bytes = wire(case);
        if case.scope == "property-placement" {
            let node =
                tree_format::decode_node_for(&bytes, true, MINIMUM, TreeUse::Ordinary).unwrap();
            let NodeItems::Leaf(rows) = node.items else {
                panic!("graft leaf")
            };
            let EntryKind::Tree {
                props: Some(props), ..
            } = &rows[0].entry.kind
            else {
                panic!("graft override")
            };
            assert!(
                terrane_format::properties::validate_graft_overrides(props, &[]).is_err(),
                "{} actual placement refusal",
                case.name
            );
            continue;
        }
        assert!(
            tree_format::decode_node_for(&bytes, case.is_root, MINIMUM, usage(case)).is_err(),
            "{} exact generic refusal",
            case.name
        );
    }
}
