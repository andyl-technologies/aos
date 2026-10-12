//! Independently reconstructs rejected lineage wires with primitive CBOR.
//!
//! No rejecting owning encoder produces these fixtures. Contradictory claims
//! remain ordinary data; refusal demonstrates format checks only.

use super::{fields, support::*};
use Value::{Array, Bool, Map, Raw, UInt};

/// Carries one named primitive negative input and its owning format family.
pub(super) struct Negative {
    /// Unique reference witness name.
    pub(super) name: String,
    /// Owning ordinary decoder to exercise.
    pub(super) family: Family,
    /// Independently reconstructed wire, including malformed headers.
    pub(super) wire: Vec<u8>,
}

fn add(wires: &mut Vec<Negative>, family: Family, label: &str, name: &str, value: Value) {
    wires.push(Negative {
        name: format!("bad-lineage-{label}-{name}"),
        family,
        wire: encode(&value),
    });
}

/// Copies the complete primitive array elements.
///
/// # Panics
/// Panics if the independently specified fixture is not an array.
fn array(value: &Value) -> Vec<Value> {
    if let Array(items) = value {
        items.clone()
    } else {
        panic!("fixture array")
    }
}

/// Copies the complete primitive map entries.
///
/// # Panics
/// Panics if the independently specified fixture is not a map.
fn entries(value: &Value) -> Vec<(Value, Value)> {
    if let Map(items) = value {
        items.clone()
    } else {
        panic!("fixture map")
    }
}

fn without(value: &Value, key: u64) -> Value {
    Map(entries(value)
        .into_iter()
        .filter(|(item, _)| !matches!(item, UInt(item) if *item == key))
        .collect())
}

/// Builds every malformed or represented-contradictory wire without owning codecs.
///
/// # Panics
/// Panics if a hard-coded fixture path or primitive table has the wrong shape.
pub(super) fn cases() -> Vec<Negative> {
    let pin = fields::pin(0, "local");
    let root = fields::root(b"/graft", fields::layers());
    let view = fields::view("public", false);
    let used = fields::used(true, false);
    let checked = fields::checked("local", true, false);
    let mut wires = vec![];
    for (family, label, model) in [
        (Family::Pin, "pin", &pin),
        (Family::Root, "root", &root),
        (Family::View, "view", &view),
        (Family::Used, "used", &used),
        (Family::Checked, "checked", &checked),
    ] {
        let wire = encode(model);
        for (name, malformed) in [
            ("trailing", [wire.clone(), vec![0]].concat()),
            ("truncated", wire[..wire.len() - 1].to_vec()),
            ("tag", [vec![0xc0], wire.clone()].concat()),
            (
                "indefinite",
                [vec![(wire[0] & 0xe0) | 31], wire[1..].to_vec(), vec![0xff]].concat(),
            ),
            ("null", vec![0xf6]),
            (
                "nonminimal-head",
                [
                    vec![(wire[0] & 0xe0) | 24, wire[0] & 31],
                    wire[1..].to_vec(),
                ]
                .concat(),
            ),
            (
                "huge-count",
                head(if matches!(model, Map(_)) { 5 } else { 4 }, u64::MAX),
            ),
        ] {
            add(&mut wires, family, label, name, Raw(malformed));
        }
        if let Map(items) = model {
            for (key, _) in items {
                let UInt(key) = key else {
                    panic!("numeric fixture key")
                };
                add(
                    &mut wires,
                    family,
                    label,
                    &format!("missing-{key}"),
                    without(model, *key),
                );
            }
            let count = u64::try_from(items.len()).unwrap_or_else(|_| panic!("map length"));
            let mut unknown = items.clone();
            unknown.push((UInt(count), UInt(0)));
            add(&mut wires, family, label, "unknown-key", Map(unknown));
            add(
                &mut wires,
                family,
                label,
                "version",
                changed(model, &[0], UInt(2)),
            );
            let mut reversed = head(5, count);
            for (key, value) in items.iter().rev() {
                reversed.extend_from_slice(&encode(key));
                reversed.extend_from_slice(&encode(value));
            }
            add(&mut wires, family, label, "key-order", Raw(reversed));
        } else {
            let mut short = array(model);
            short.pop();
            add(&mut wires, family, label, "short-tuple", Array(short));
            let mut long = array(model);
            long.push(UInt(0));
            add(&mut wires, family, label, "long-tuple", Array(long));
        }
    }
    for (name, path, value) in [
        ("kind-bool", vec![0], Bool(true)),
        ("key-bytes", vec![2], bytes(b"registration.cbor")),
        ("digest-empty", vec![3], bytes(b"")),
        ("digest-wide", vec![3], bytes(&[0; 33])),
        ("owner-id-short", vec![1, 1], bytes(&[0; 31])),
        ("kind", vec![0], UInt(6)),
        ("key", vec![2], text("registration.cbor/extra")),
        ("digest-short", vec![3], bytes(&[0; 31])),
        ("owner-version", vec![1, 0], UInt(3)),
        ("owner-relative-root", vec![1, 2], bytes(b"relative")),
        ("owner-domain", vec![1, 3], text("unknown")),
    ] {
        add(
            &mut wires,
            Family::Pin,
            "pin",
            name,
            changed(&pin, &path, value),
        );
    }
    for (kind, key) in [
        (
            1,
            format!("bootstrap-{}-{}-24.cbor", "02".repeat(32), "05".repeat(32)),
        ),
        (
            1,
            format!("bootstrap-{}-{}-024.cbor", "01".repeat(32), "05".repeat(32)),
        ),
        (2, format!("commit-{}.cbor", "AA".repeat(32))),
        (3, format!("import-{}.cbor", "07".repeat(31))),
        (4, format!("import-{}.cbor", "08".repeat(32))),
        (5, format!("import-trust-{}.cbor/extra", "09".repeat(32))),
    ] {
        add(
            &mut wires,
            Family::Pin,
            "pin",
            &format!("key-kind-{kind}-{}", key.len()),
            changed(&fields::pin(kind, "local"), &[2], text(&key)),
        );
    }
    add(
        &mut wires,
        Family::Pin,
        "pin",
        "bootstrap-overflow",
        changed(
            &fields::pin(1, "local"),
            &[2],
            text(&format!(
                "bootstrap-{}-{}-18446744073709551616.cbor",
                "01".repeat(32),
                "05".repeat(32)
            )),
        ),
    );
    add(
        &mut wires,
        Family::Pin,
        "pin",
        "key-utf8",
        changed(&pin, &[2], Raw(vec![0x61, 0xff])),
    );
    add(
        &mut wires,
        Family::Pin,
        "pin",
        "huge-digest",
        changed(&pin, &[3], Raw(head(2, u64::MAX))),
    );
    for provider in ["s3", "gcs"] {
        for (name, path, value) in [
            ("empty-endpoint", vec![1, 3, 2, 0], text("")),
            ("empty-control", vec![1, 4], bytes(b"")),
            ("provider", vec![1, 3, 1], text("unknown")),
        ] {
            add(
                &mut wires,
                Family::Pin,
                "pin",
                &format!("{provider}-{name}"),
                changed(&fields::pin(0, provider), &path, value),
            );
        }
    }
    for (name, path, value) in [
        ("empty-path", vec![1], bytes(b"")),
        ("relative-path", vec![1], bytes(b"graft")),
        ("path-dot", vec![1], bytes(b"/a/../b")),
        ("path-slash", vec![1], bytes(b"/a//b")),
        ("path-nul", vec![1], bytes(b"/a\0")),
        (
            "path-component-wide",
            vec![1],
            bytes(&[vec![b'/'], vec![b'x'; 256]].concat()),
        ),
        ("path-trailing-slash", vec![1], bytes(b"/a/")),
        (
            "path-too-long",
            vec![1],
            bytes(&[vec![b'/'], vec![b'x'; 4097]].concat()),
        ),
        ("empty-layers", vec![2], Array(vec![])),
        (
            "too-many-layers",
            vec![2],
            Array(vec![Array(vec![bytes(&[0xa0]), bytes(&[0xa0])]); 66]),
        ),
        ("root-width", vec![0], bytes(&[0; 31])),
        ("layer-tuple", vec![2, 0], Array(vec![bytes(&[0xa0])])),
        ("property-trailing", vec![2, 0, 0], bytes(&[0xa0, 0])),
        ("property-nonminimal", vec![2, 0, 0], bytes(&[0xb8, 0])),
        ("override-null", vec![2, 0, 1], bytes(&[0xf6])),
        (
            "property-invalid-domain",
            vec![2, 0, 0],
            bytes(&encode(&properties(vec![("domain", text("unknown"))]))),
        ),
        (
            "property-invalid-type",
            vec![2, 0, 0],
            bytes(&encode(&properties(vec![("hashes", Bool(true))]))),
        ),
        ("override-trailing", vec![2, 0, 1], bytes(&[0xa0, 0])),
    ] {
        add(
            &mut wires,
            Family::Root,
            "root",
            name,
            changed(&root, &path, value),
        );
    }
    for (name, path, major) in [
        ("path", vec![1], 2),
        ("layers", vec![2], 4),
        ("property", vec![2, 0, 0], 2),
        ("override", vec![2, 0, 1], 2),
    ] {
        add(
            &mut wires,
            Family::Root,
            "root",
            &format!("huge-{name}"),
            changed(&root, &path, Raw(head(major, u64::MAX))),
        );
    }
    for label in ["unknown", "private:", "group:", "tenant:"] {
        add(
            &mut wires,
            Family::View,
            "view",
            &format!("domain-{label}"),
            changed(&view, &[1], text(label)),
        );
    }
    add(
        &mut wires,
        Family::View,
        "view",
        "conflicting-occurrence",
        changed(&view, &[2, 2, 0], digest(99)),
    );
    let mut reversed_layers = fields::layers();
    reversed_layers.reverse();
    add(
        &mut wires,
        Family::View,
        "view",
        "conflicting-layers",
        changed(&view, &[2, 2, 2], Array(reversed_layers)),
    );
    add(
        &mut wires,
        Family::View,
        "view",
        "identity-width",
        changed(&view, &[0], bytes(&[0; 31])),
    );
    add(
        &mut wires,
        Family::View,
        "view",
        "huge-roots",
        changed(&view, &[2], Raw(head(4, u64::MAX))),
    );

    let used_fields = entries(&used);
    let at = |key| {
        used_fields
            .iter()
            .find(|(item, _)| matches!(item, UInt(item) if *item == key))
            .unwrap_or_else(|| panic!("used key"))
            .1
            .clone()
    };
    let mut reversed_issuers = array(&at(1));
    reversed_issuers.reverse();
    let mut reversed_disclosures = array(&at(2));
    reversed_disclosures.reverse();
    let mut reversed_controls = fields::controls(true);
    reversed_controls.reverse();
    for (name, path, value) in [
        ("issuer-order", vec![1], Array(reversed_issuers)),
        (
            "issuer-duplicate",
            vec![1],
            Array(vec![array(&at(1))[0].clone(); 2]),
        ),
        ("issuer-key-width", vec![1, 0, 2], bytes(&[0; 31])),
        ("disclosure-interval", vec![2, 1, 4], UInt(20)),
        ("disclosure-order", vec![2], Array(reversed_disclosures)),
        ("controls-order", vec![3], Array(reversed_controls)),
        ("controls-duplicate", vec![3], Array(vec![pin.clone(); 2])),
        ("registry-revision", vec![4, 1], UInt(2)),
        (
            "registry-missing-name",
            vec![4, 2],
            Array(
                fields::BEHAVIOR[..fields::BEHAVIOR.len() - 1]
                    .iter()
                    .map(|name| text(name))
                    .collect(),
            ),
        ),
        ("later-overlap", vec![4, 8], Array(vec![text("domain")])),
        ("profile-minimum", vec![5, 5], UInt(1)),
        ("profile-maximum", vec![5, 8, 2], UInt(1048576)),
        ("policy-null-shape", vec![5, 9], Bool(true)),
        (
            "unfenced-property",
            vec![6, 0, 2, 0, 2, 0, 0],
            bytes(&encode(&properties(vec![("future-note", text("inert"))]))),
        ),
    ] {
        add(
            &mut wires,
            Family::Used,
            "used",
            name,
            changed(&used, &path, value),
        );
    }
    for key in [1, 2, 3, 6] {
        add(
            &mut wires,
            Family::Used,
            "used",
            &format!("huge-rows-{key}"),
            changed(&used, &[key], Raw(head(4, u64::MAX))),
        );
    }
    let commit_wire = encode(&fields::commit(true));
    let commit_id = fields::commit_id(&commit_wire);
    let source_wire = encode(&fields::source(&commit_id, true));
    for (name, path, value) in [
        ("source-name", vec![1], text("refs/unknown/source")),
        ("source-notes", vec![1], text("refs/notes/source")),
        ("identity", vec![3], digest(99)),
        ("guard-width", vec![5], bytes(&[0; 31])),
        ("loss-bool", vec![6], Bool(true)),
        ("controls-mismatch", vec![7], Array(vec![])),
        ("original-version", vec![8, 0], UInt(3)),
        (
            "source-trailing",
            vec![2],
            bytes(&[source_wire, vec![0]].concat()),
        ),
        (
            "commit-trailing",
            vec![4],
            bytes(&[commit_wire, vec![0]].concat()),
        ),
    ] {
        add(
            &mut wires,
            Family::Checked,
            "checked",
            name,
            changed(&checked, &path, value),
        );
    }
    let malformed_source = changed(&fields::source(&commit_id, true), &[6], bytes(&[0; 31]));
    add(
        &mut wires,
        Family::Checked,
        "checked",
        "source-candidate-width",
        changed(&checked, &[2], bytes(&encode(&malformed_source))),
    );
    let malformed_commit = changed(&fields::commit(true), &[8], bytes(&[0; 63]));
    add(
        &mut wires,
        Family::Checked,
        "checked",
        "commit-signature-width",
        changed(&checked, &[4], bytes(&encode(&malformed_commit))),
    );
    let unsigned_bytes = encode(&without(&fields::commit(true), 8));
    let unsigned_id = fields::commit_id(&unsigned_bytes);
    let mut unsigned = checked.clone();
    set(
        &mut unsigned,
        &[2],
        bytes(&encode(&fields::source(&unsigned_id, true))),
    );
    set(&mut unsigned, &[3], bytes(&unsigned_id));
    set(&mut unsigned, &[4], bytes(&unsigned_bytes));
    add(
        &mut wires,
        Family::Checked,
        "checked",
        "unsigned-consistent-commit",
        unsigned,
    );
    add(
        &mut wires,
        Family::Checked,
        "checked",
        "source-commit-mismatch",
        changed(
            &checked,
            &[2],
            bytes(&encode(&fields::source(&[99; 32], true))),
        ),
    );
    for (key, major) in [(1, 3), (2, 2), (4, 2), (7, 4)] {
        add(
            &mut wires,
            Family::Checked,
            "checked",
            &format!("huge-field-{key}"),
            changed(&checked, &[key], Raw(head(major, u64::MAX))),
        );
    }
    wires
}
