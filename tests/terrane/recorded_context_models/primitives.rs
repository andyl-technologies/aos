//! Constructs independent primitive context, evidence and complete recipe tables.
//!
//! No Terrane encoder supplies comparison bytes or malformed rejection inputs.
//! ```text
//! context = [3, view, domain, selector-bytes, baseline, minimum, selected,
//!            [root, revision, behavioral-names, later-names]]
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Represents independent primitive fields, including malformed raw assemblies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Value {
    /// An unsigned integer.
    UInt(u64),
    /// Opaque bytes.
    Bytes(Vec<u8>),
    /// UTF-8 text.
    Text(String),
    /// A boolean.
    Bool(bool),
    /// Null.
    Null,
    /// Ordered array fields.
    Array(Vec<Self>),
    /// Map fields sorted by encoded bytes at assembly.
    Map(Vec<(Self, Self)>),
    /// Preassembled CBOR that bypasses format validation.
    Raw(Vec<u8>),
}

/// Emits a shortest unsigned CBOR header.
pub(super) fn head(major: u8, argument: u64) -> Vec<u8> {
    if argument < 24 {
        return vec![(major << 5) | argument as u8];
    }
    let (width, additional) = if argument <= 255 {
        (1, 24)
    } else if argument <= 65535 {
        (2, 25)
    } else if argument <= u32::MAX.into() {
        (4, 26)
    } else {
        (8, 27)
    };
    let mut bytes = vec![(major << 5) | additional];
    bytes.extend_from_slice(&argument.to_be_bytes()[8 - width..]);
    bytes
}

/// Assembles canonical bytes without an owning CBOR or context encoder.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    match value {
        Value::UInt(value) => head(0, *value),
        Value::Bytes(bytes) => [head(2, bytes.len() as u64), bytes.clone()].concat(),
        Value::Text(text) => [head(3, text.len() as u64), text.as_bytes().to_vec()].concat(),
        Value::Bool(value) => vec![if *value { 0xf5 } else { 0xf4 }],
        Value::Null => vec![0xf6],
        Value::Array(fields) => {
            let mut bytes = head(4, fields.len() as u64);
            for field in fields {
                bytes.extend(encode(field));
            }
            bytes
        }
        Value::Map(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (encode(key), encode(value)))
                .collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut bytes = head(5, fields.len() as u64);
            for (key, value) in fields {
                bytes.extend(key);
                bytes.extend(value);
            }
            bytes
        }
        Value::Raw(bytes) => bytes.clone(),
    }
}

/// Constructs a text field.
pub(super) fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// Constructs a fixed opaque digest field, without evidence verification.
pub(super) fn digest(value: u8) -> Value {
    Value::Bytes(vec![value; 32])
}

/// Returns independently transcribed fixed revision vocabularies.
pub(super) fn vocabulary(revision: u64) -> Vec<String> {
    let mut names: Vec<_> = [
        "acl",
        "baseline",
        "chunk",
        "classify",
        "compaction_threshold",
        "compression",
        "dedup",
        "degraded",
        "domain",
        "durability",
        "encryption",
        "gap_merge_bytes",
        "hashes",
        "home",
        "index",
        "merge",
        "on-release",
        "passthrough",
        "prefetch",
        "quota",
        "reassembly",
        "redundancy",
        "reflog_retain",
        "replicate",
        "retain",
        "span_max_bytes",
        "store",
        "strict-attrs",
        "trust",
        "warm",
        "whole_pack_threshold",
        "wipe",
        "writers",
    ]
    .iter()
    .map(|name| (*name).into())
    .collect();
    if revision >= 2 {
        names.push("index-roots".into());
    }
    if revision >= 3 {
        names.push("index-gaps".into());
    }
    names.sort();
    names
}

fn names(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::Text).collect())
}

/// Retains all ordinary recorded-property field claims.
#[derive(Clone, Debug)]
pub(super) struct Recorded {
    /// Claimed original view root.
    pub(super) root: [u8; 32],
    /// Claimed registered semantic revision.
    pub(super) revision: u64,
    /// Complete literal behavioral vocabulary.
    pub(super) behavioral: Vec<String>,
    /// Claimed later preserve-only vocabulary.
    pub(super) later: Vec<String>,
}

/// Retains every context field independently of encoded wire data.
#[derive(Clone, Debug)]
pub(super) struct Context {
    /// Unique published name.
    pub(super) name: String,
    /// Tuple version.
    pub(super) version: u64,
    /// Claimed immutable view identity.
    pub(super) view: [u8; 32],
    /// Represented disclosure domain.
    pub(super) domain: String,
    /// Complete selector field model.
    pub(super) selector: Value,
    /// Absent or present baseline, preserving an empty present value.
    pub(super) baseline: Option<String>,
    /// Represented chunk minimum.
    pub(super) minimum: u64,
    /// Complete selected evidence row model, when present.
    pub(super) selected: Option<Value>,
    /// Explicit recorded claims, or no such claims for legacy tuples.
    pub(super) recorded: Option<Recorded>,
}

impl Context {
    /// Independently projects every field to a primitive tuple.
    pub(super) fn value(&self) -> Value {
        let mut fields = vec![
            Value::UInt(self.version),
            Value::Bytes(self.view.to_vec()),
            text(&self.domain),
            Value::Bytes(encode(&self.selector)),
            self.baseline
                .as_ref()
                .map_or(Value::Null, |value| text(value)),
            Value::UInt(self.minimum),
        ];
        if self.version >= 2 {
            fields.push(
                self.selected
                    .as_ref()
                    .map_or(Value::Null, |rows| Value::Bytes(encode(rows))),
            );
        }
        if let Some(recorded) = &self.recorded {
            fields.push(Value::Array(vec![
                Value::Bytes(recorded.root.to_vec()),
                Value::UInt(recorded.revision),
                names(&recorded.behavioral),
                names(&recorded.later),
            ]));
        }
        Value::Array(fields)
    }
}

/// Constructs the complete nested existing selected-side schema.
pub(super) fn selected_rows() -> Value {
    Value::Array(vec![Value::Array(vec![
        Value::Array(vec![
            digest(1),
            digest(4),
            Value::Bytes(b"dir/item".to_vec()),
        ]),
        text("hash.sha256"),
        text("public"),
        Value::Bytes(b"graft/dir/item".to_vec()),
        Value::Array(vec![
            digest(11),
            digest(12),
            text("hash.sha256"),
            text("sha256"),
            text("1"),
            Value::Bytes(encode(&Value::Bytes(vec![b'v'; 32]))),
            digest(13),
            Value::Array(vec![
                digest(14),
                digest(15),
                Value::Bytes(b"source/item".to_vec()),
            ]),
            Value::Array(vec![
                text("private:producer"),
                Value::Bytes(b"mount/source/item".to_vec()),
            ]),
        ]),
    ])])
}

/// Constructs an ordinary explicit context under one fixed revision.
pub(super) fn base_context(revision: u64) -> Context {
    Context {
        name: format!("recorded-context-revision-{revision}"),
        version: 3,
        view: [1; 32],
        domain: "public".into(),
        selector: Value::Array(vec![text("preset"), text("any")]),
        baseline: None,
        minimum: 262144,
        selected: None,
        recorded: Some(Recorded {
            root: [3; 32],
            revision,
            behavioral: vocabulary(revision),
            later: Vec::new(),
        }),
    }
}

/// Returns the complete independently constructed positive context inventory.
///
/// # Panics
/// Panics if an explicit fixture unexpectedly omits its recorded fields.
pub(super) fn contexts() -> Vec<Context> {
    let mut legacy = base_context(1);
    legacy.name = "recorded-context-legacy-one".into();
    legacy.version = 1;
    legacy.recorded = None;
    let mut side = legacy.clone();
    side.name = "recorded-context-legacy-two".into();
    side.version = 2;
    side.selected = Some(selected_rows());
    let mut models = vec![legacy, side];
    for revision in 1..=3 {
        let base = base_context(revision);
        let mut selected = base.clone();
        selected.name = format!("recorded-context-selected-{revision}");
        selected.selected = Some(selected_rows());
        models.extend([base, selected]);
    }
    for suffix in [
        "view",
        "root",
        "domain",
        "selector",
        "baseline-empty",
        "baseline",
        "minimum",
        "later",
        "later-order",
        "later-name-limit",
        "later-total-limit",
        "revision-two-later",
        "selected-multiple",
    ] {
        let mut model = base_context(if suffix == "revision-two-later" { 2 } else { 1 });
        model.name = format!("recorded-context-{suffix}");
        match suffix {
            "view" => model.view = [2; 32],
            "root" => present(model.recorded.as_mut(), "recorded fixture").root = [4; 32],
            "domain" => model.domain = "tenant:tenant-a".into(),
            "selector" => {
                model.selector = Value::Array(vec![
                    text("all"),
                    Value::Array(vec![
                        Value::Array(vec![text("preset"), text("strict")]),
                        Value::Array(vec![text("kind"), text("human")]),
                    ]),
                ])
            }
            "baseline-empty" => model.baseline = Some(String::new()),
            "baseline" => model.baseline = Some("baseline-a".into()),
            "minimum" => model.minimum = 4194304,
            "selected-multiple" => {
                let Value::Array(mut rows) = selected_rows() else {
                    panic!("row array")
                };
                let mut second = rows[0].clone();
                replace(&mut second, &[0, 2], Value::Bytes(b"dir/other".to_vec()));
                replace(&mut second, &[3], Value::Bytes(b"graft/dir/other".to_vec()));
                replace(
                    &mut second,
                    &[4, 5],
                    Value::Bytes(encode(&Value::Map(vec![
                        (
                            Value::UInt(1),
                            Value::Array(vec![
                                Value::Bool(false),
                                Value::Bool(true),
                                Value::Null,
                                Value::UInt(24),
                            ]),
                        ),
                        (Value::UInt(2), text("retained")),
                    ]))),
                );
                rows.push(second);
                model.selected = Some(Value::Array(rows));
            }
            _ => {
                let recorded = present(model.recorded.as_mut(), "recorded fixture");
                recorded.later = match suffix {
                    "later" => vec!["index-gaps".into(), "index-roots".into()],
                    "later-order" => vec!["aa".into(), "z".into(), "é".into()],
                    "later-name-limit" => vec![format!("{}a", "é".repeat(127))],
                    "later-total-limit" => later_limit(),
                    "revision-two-later" => vec!["index-gaps".into()],
                    _ => panic!("complete named context fixture"),
                };
            }
        }
        models.push(model);
    }
    models
}

fn later_limit() -> Vec<String> {
    let mut names = vec!["a".into()];
    names.extend((0..257).map(|number| format!("n{number:03}{}", "x".repeat(251))));
    names
}

/// Replaces an explicitly listed array field to construct primitive controls.
///
/// # Panics
/// Panics on an empty path, non-array intermediate, or out-of-range fixture index.
pub(super) fn replace(value: &mut Value, path: &[usize], replacement: Value) {
    let Value::Array(fields) = value else {
        panic!("array fixture path")
    };
    if path.len() == 1 {
        fields[path[0]] = replacement;
    } else {
        replace(&mut fields[path[0]], &path[1..], replacement);
    }
}

/// Retains complete enclosing recipe fields with their named publication row.
#[derive(Clone, Debug)]
pub(super) struct RecipeModel {
    /// Unique published recipe name.
    pub(super) name: String,
    /// Complete ordinary configuration model.
    pub(super) configuration: Value,
    /// Ordered operand roots, including filtered incoming for fold models.
    pub(super) roots: [[u8; 32]; 3],
}

impl RecipeModel {
    /// Assembles the complete primitive operation/operand/argument map.
    pub(super) fn value(&self) -> Value {
        Value::Map(vec![
            (Value::UInt(1), text("merge")),
            (
                Value::UInt(2),
                Value::Array(
                    self.roots
                        .iter()
                        .map(|root| Value::Bytes(root.to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::UInt(3),
                Value::Map(vec![
                    (
                        text("trust"),
                        Value::Map(vec![
                            (
                                Value::UInt(1),
                                Value::Array(vec![text("preset"), text("any")]),
                            ),
                            (Value::UInt(2), text("terrane-verified-path/v1")),
                            (Value::UInt(3), self.configuration.clone()),
                            (Value::UInt(4), Value::Array(Vec::new())),
                        ]),
                    ),
                    (
                        text("policy"),
                        Value::Array(vec![
                            text("prefer-trusted"),
                            text("prefer-newer"),
                            text("keep-conflict"),
                        ]),
                    ),
                ]),
            ),
        ])
    }
}

/// Constructs complete configurations with independently differing view revisions.
pub(super) fn recipes(contexts: &[Context]) -> Vec<RecipeModel> {
    let mut incoming = base_context(3);
    incoming.view = [2; 32];
    incoming.domain = "group:incoming".into();
    if let Some(recorded) = incoming.recorded.as_mut() {
        recorded.root = [4; 32];
    }
    let mut models: Vec<_> = contexts
        .iter()
        .filter(|context| !context.name.ends_with("later-total-limit"))
        .map(|context| RecipeModel {
            name: context
                .name
                .replacen("recorded-context", "recorded-recipe", 1),
            roots: [[5; 32], [3; 32], [4; 32]],
            configuration: Value::Array(vec![
                Value::Array(vec![
                    Value::Bytes(encode(&context.value())),
                    Value::Bytes(encode(&incoming.value())),
                ]),
                Value::Null,
            ]),
        })
        .collect();
    for domain in [false, true] {
        let mut fold = vec![
            digest(5),
            digest(4),
            digest(6),
            Value::Array(vec![
                Value::Bytes(b"a".to_vec()),
                Value::Bytes(b"a/child".to_vec()),
                Value::Bytes(b"z".to_vec()),
            ]),
        ];
        if domain {
            fold.push(text("group:incoming"));
        }
        models.push(RecipeModel {
            name: if domain {
                "recorded-recipe-fold-domain"
            } else {
                "recorded-recipe-fold"
            }
            .into(),
            roots: [[5; 32], [3; 32], [6; 32]],
            configuration: Value::Array(vec![
                Value::Array(vec![
                    Value::Bytes(encode(&base_context(1).value())),
                    Value::Bytes(encode(&incoming.value())),
                ]),
                Value::Array(fold),
            ]),
        });
    }
    models
}

/// Reconstructs every malformed primitive wire outside the rejecting encoder.
///
/// # Panics
/// Panics if a literal negative path does not match its independent field table.
pub(super) fn negatives() -> Vec<(String, Vec<u8>)> {
    let unsigned_max = Value::Raw(head(4, u64::MAX));
    let mut over = later_limit();
    over.push("zz".into());
    let changes: Vec<(&str, &[usize], Value)> = vec![
        ("version-zero", &[0], Value::UInt(0)),
        ("version-four", &[0], Value::UInt(4)),
        ("view-short", &[1], Value::Bytes(vec![b'v'; 31])),
        ("view-long", &[1], Value::Bytes(vec![b'v'; 33])),
        ("view-type", &[1], Value::UInt(1)),
        ("domain-type", &[2], Value::Bytes(b"public".to_vec())),
        ("selector-type", &[3], Value::Null),
        (
            "selector-unknown",
            &[3],
            Value::Bytes(encode(&Value::Array(vec![text("unknown"), text("x")]))),
        ),
        (
            "selector-trailing",
            &[3],
            Value::Bytes(
                [
                    encode(&Value::Array(vec![text("preset"), text("any")])),
                    vec![0],
                ]
                .concat(),
            ),
        ),
        ("baseline-type", &[4], Value::UInt(0)),
        ("minimum-type", &[5], text("262144")),
        ("selected-type", &[6], Value::Array(Vec::new())),
        ("selected-empty-bytes", &[6], Value::Bytes(Vec::new())),
        ("selected-empty-rows", &[6], Value::Bytes(vec![0x80])),
        ("selected-huge-bytes", &[6], Value::Raw(head(2, u64::MAX))),
        ("recorded-null", &[7], Value::Null),
        (
            "recorded-short",
            &[7],
            Value::Array(vec![digest(3), Value::UInt(1), names(&vocabulary(1))]),
        ),
        (
            "recorded-long",
            &[7],
            Value::Array(vec![
                digest(3),
                Value::UInt(1),
                names(&vocabulary(1)),
                Value::Array(Vec::new()),
                Value::Null,
            ]),
        ),
        ("root-short", &[7, 0], Value::Bytes(vec![b'r'; 31])),
        ("root-long", &[7, 0], Value::Bytes(vec![b'r'; 33])),
        ("root-type", &[7, 0], text("root")),
        ("revision-zero", &[7, 1], Value::UInt(0)),
        ("revision-four", &[7, 1], Value::UInt(4)),
        ("revision-type", &[7, 1], text("1")),
        ("behavior-empty", &[7, 2], Value::Array(Vec::new())),
        ("behavior-missing", &[7, 2], names(&vocabulary(1)[1..])),
        ("behavior-extra", &[7, 2], names(&vocabulary(2))),
        (
            "behavior-duplicate",
            &[7, 2],
            names(&[vec!["acl".into()], vocabulary(1)].concat()),
        ),
        (
            "behavior-reversed",
            &[7, 2],
            names(&vocabulary(1).into_iter().rev().collect::<Vec<_>>()),
        ),
        ("behavior-type", &[7, 2], Value::Null),
        ("later-empty-name", &[7, 3], Value::Array(vec![text("")])),
        (
            "later-name-over",
            &[7, 3],
            Value::Array(vec![text(&"x".repeat(256))]),
        ),
        (
            "later-unicode-over",
            &[7, 3],
            Value::Array(vec![text(&"é".repeat(128))]),
        ),
        (
            "later-duplicate",
            &[7, 3],
            Value::Array(vec![text("future"), text("future")]),
        ),
        (
            "later-reversed",
            &[7, 3],
            Value::Array(vec![text("z"), text("aa")]),
        ),
        ("later-overlap", &[7, 3], Value::Array(vec![text("acl")])),
        ("later-type", &[7, 3], Value::Array(vec![Value::UInt(1)])),
        ("later-total-over", &[7, 3], names(&over)),
        (
            "later-invalid-utf8",
            &[7, 3],
            Value::Array(vec![Value::Raw(vec![0x61, 0xff])]),
        ),
        ("later-huge-count", &[7, 3], unsigned_max.clone()),
        ("behavior-huge-count", &[7, 2], unsigned_max.clone()),
        ("recorded-huge-count", &[7], unsigned_max),
        ("view-huge-bytes", &[1], Value::Raw(head(2, u64::MAX))),
        (
            "later-huge-name",
            &[7, 3],
            Value::Array(vec![Value::Raw(head(3, u64::MAX))]),
        ),
        ("version-nonminimal", &[0], Value::Raw(vec![0x18, 3])),
        ("revision-nonminimal", &[7, 1], Value::Raw(vec![0x18, 1])),
    ];
    let mut models = Vec::new();
    for (name, path, replacement) in changes {
        let mut fields = base_context(1).value();
        replace(&mut fields, path, replacement);
        models.push((format!("recorded-negative-{name}"), encode(&fields)));
    }
    let base = encode(&base_context(1).value());
    let Value::Array(fields) = base_context(1).value() else {
        panic!("context array")
    };
    for (name, wire) in [
        ("tuple-short", encode(&Value::Array(fields[..7].to_vec()))),
        (
            "tuple-long",
            encode(&Value::Array([fields, vec![Value::Null]].concat())),
        ),
        (
            "tuple-type",
            encode(&Value::Map(vec![(Value::UInt(1), base_context(1).value())])),
        ),
        ("tuple-huge-count", head(4, u64::MAX)),
        (
            "tuple-nonminimal",
            [vec![0x98, 8], base[1..].to_vec()].concat(),
        ),
        ("truncated", base[..base.len() - 1].to_vec()),
        ("trailing", [base, vec![0]].concat()),
    ] {
        models.push((format!("recorded-negative-{name}"), wire));
    }
    let row_changes: Vec<(&str, &[usize], Value)> = vec![
        ("row-view", &[0, 0], digest(2)),
        ("row-domain", &[2], text("private:other")),
        ("row-name", &[1], text("hash.sha512")),
        ("row-short-view", &[0, 0], Value::Bytes(vec![b'v'; 31])),
        ("row-empty-path", &[0, 2], Value::Bytes(Vec::new())),
        ("row-invalid-path", &[3], Value::Bytes(b"../item".to_vec())),
        ("row-long-component", &[3], Value::Bytes(vec![b'x'; 256])),
        ("side-short-record", &[4, 0], Value::Bytes(vec![b'r'; 31])),
        ("side-empty-name", &[4, 2], text("")),
        ("side-value-trailing", &[4, 5], Value::Bytes(vec![1, 0])),
        (
            "side-value-nonminimal",
            &[4, 5],
            Value::Bytes(vec![0x18, 1]),
        ),
        (
            "side-empty-producer-path",
            &[4, 8, 1],
            Value::Bytes(Vec::new()),
        ),
    ];
    for (name, path, replacement) in row_changes {
        let Value::Array(mut rows) = selected_rows() else {
            panic!("rows")
        };
        replace(&mut rows[0], path, replacement);
        let mut fields = base_context(1).value();
        replace(&mut fields, &[6], Value::Bytes(encode(&Value::Array(rows))));
        models.push((format!("recorded-negative-{name}"), encode(&fields)));
    }
    let Value::Array(rows) = selected_rows() else {
        panic!("rows")
    };
    let Value::Array(row) = &rows[0] else {
        panic!("row")
    };
    for (name, malformed) in [
        (
            "row-duplicate",
            Value::Array([rows.clone(), rows.clone()].concat()),
        ),
        (
            "row-short",
            Value::Array(vec![Value::Array(row[..4].to_vec())]),
        ),
        (
            "row-long",
            Value::Array(vec![Value::Array(
                [row.clone(), vec![Value::Null]].concat(),
            )]),
        ),
    ] {
        let mut fields = base_context(1).value();
        replace(&mut fields, &[6], Value::Bytes(encode(&malformed)));
        models.push((format!("recorded-negative-{name}"), encode(&fields)));
    }
    let mut earlier = rows[0].clone();
    replace(&mut earlier, &[0, 2], Value::Bytes(b"dir/earlier".to_vec()));
    replace(
        &mut earlier,
        &[3],
        Value::Bytes(b"graft/dir/earlier".to_vec()),
    );
    let mut fields = base_context(1).value();
    replace(
        &mut fields,
        &[6],
        Value::Bytes(encode(&Value::Array(vec![rows[0].clone(), earlier]))),
    );
    models.push(("recorded-negative-row-reversed".into(), encode(&fields)));
    let mut fields = base_context(1).value();
    replace(
        &mut fields,
        &[6],
        Value::Bytes([encode(&selected_rows()), vec![0]].concat()),
    );
    models.push((
        "recorded-negative-selected-trailing".into(),
        encode(&fields),
    ));
    models
}

/// Requires an ordinary successful fixture result.
///
/// # Panics
/// Panics with the fixture reason and error when the result is unsuccessful.
pub(super) fn required<T, E: core::fmt::Debug>(result: Result<T, E>, reason: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{reason}: {error:?}"),
    }
}

/// Requires a present field independently declared by a model.
///
/// # Panics
/// Panics when the model-declared field is absent.
pub(super) fn present<T>(value: Option<T>, reason: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{reason}"),
    }
}

/// Reads a unique named published hex field from the complete reference.
///
/// # Panics
/// Panics for missing/ambiguous section or fields, odd widths, or malformed hex.
pub(super) fn published(name: &str, field: &str) -> Vec<u8> {
    const REFERENCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/recorded-context-reference.md"
    ));
    const HEADING: &str = "## Recorded property trust context field witnesses\n";
    assert_eq!(REFERENCE.matches(HEADING).count(), 1);
    let section = present(REFERENCE.split_once(HEADING), "published bounded section").1;
    let section = section.split("\n## ").next().unwrap_or(section);
    let marker = format!("### {name}\n");
    assert_eq!(section.matches(&marker).count(), 1, "unique {name}");
    let witness = present(section.split_once(&marker), "published named model").1;
    let witness = witness.split("\n### ").next().unwrap_or(witness);
    let prefix = format!("{field} = ");
    let values: Vec<_> = witness
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    assert_eq!(values.len(), 1, "unique {name} {field}");
    assert_eq!(values[0].len() % 2, 0);
    values[0]
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = required(core::str::from_utf8(pair), "ASCII hex");
            required(u8::from_str_radix(text, 16), "published lowercase hex")
        })
        .collect()
}
