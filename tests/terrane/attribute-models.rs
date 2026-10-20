//! Compares independent attribute field models with the owning public codecs.
//!
//! Fixed executable metadata, digest values and opaque signatures are inert.
//! Tests cover TEST-1/2/3 and DRV-1/2/6/8 format data without recomputation,
//! producer verification, repository operations or backend effects.
//!
//! ```text
//! AttrRecord = {1: object, 2: name, 3: value, 4: "function/version",
//!               5: producer, ?6: opaque_signature}
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "independent reference fixture failures intentionally panic"
)]

use terrane_format::{
    cbor,
    derived::{AttrRecord, AttributeName, AttributeValue, ElfValue, Function, Magic, ShebangValue},
    identity::{IdentityKind, TERRANE_V1},
};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/terrane/attribute-reference.md"
));
const OBJECT: [u8; 32] = [17; 32];
const PRODUCER: [u8; 32] = [34; 32];
const INTERPRETER: &str = "/opt/terrane/interpreter";

fn hexadecimal(name: &str, block: usize) -> Vec<u8> {
    let marker = format!("### attribute-{name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1);
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n##")
        .next()
        .unwrap();
    let raw = section
        .split("```hex\n")
        .nth(block + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn signature() -> [u8; 64] {
    core::array::from_fn(|index| u8::try_from(index).unwrap())
}

fn values() -> Vec<(String, &'static str, AttributeValue)> {
    let mut models = vec![
        ("sha256".into(), "sha256", AttributeValue::Sha256([49; 32])),
        ("sha512".into(), "sha512", AttributeValue::Sha512([50; 64])),
        (
            "git-blob-sha1".into(),
            "git-blob-sha1",
            AttributeValue::GitBlobSha1([51; 20]),
        ),
        (
            "git-blob-sha256".into(),
            "git-blob-sha256",
            AttributeValue::GitBlobSha256([52; 32]),
        ),
        (
            "dictionary".into(),
            "zstd-dictionary",
            AttributeValue::ZstdDictionary([53; 32]),
        ),
    ];
    for (label, magic) in [
        ("elf", Magic::Elf),
        ("shebang", Magic::Shebang),
        ("ar", Magic::Ar),
        ("zstd", Magic::Zstd),
        ("gzip", Magic::Gzip),
        ("tar", Magic::Tar),
        ("text", Magic::Text),
        ("other", Magic::Other),
    ] {
        models.push((
            format!("magic-{label}"),
            "magic",
            AttributeValue::Magic(magic),
        ));
    }
    for (class, machine) in [(32, 3), (64, 62)] {
        for linked in [false, true] {
            let label = if linked { "linked" } else { "static" };
            models.push((
                format!("elf{class}-{label}"),
                "elf",
                AttributeValue::Elf(ElfValue {
                    class,
                    machine,
                    elf_type: if linked { 3 } else { 2 },
                    interpreter: linked.then(|| INTERPRETER.to_owned()),
                    needed: if linked {
                        vec!["libz.so".into(), "liba.so".into(), "libz.so".into()]
                    } else {
                        vec![]
                    },
                }),
            ));
        }
    }
    for (label, argument) in [("plain", None), ("argument", Some("--mode inert"))] {
        models.push((
            format!("shebang-{label}"),
            "shebang",
            AttributeValue::Shebang(ShebangValue {
                interpreter: INTERPRETER.into(),
                argument: argument.map(str::to_owned),
            }),
        ));
    }
    assert_eq!(models.len(), 19);
    models
}

#[test]
fn reference_attribute_values_preserve_all_registered_models() {
    for (label, _, model) in values() {
        let wire = hexadecimal(&format!("value-{label}"), 0);
        assert_eq!(model.encode().unwrap(), wire, "{label}");
        let decoded = AttributeValue::decode(model.name(), &wire).unwrap();
        assert_eq!(decoded, model, "{label}");
        assert_eq!(decoded.encode().unwrap(), wire, "{label}");
    }
}

fn compare_record(label: &str, record: &AttrRecord) {
    let name = format!("record-{label}");
    let wire = hexadecimal(&name, 0);
    let preimage = hexadecimal(&name, 1);
    let digest = hexadecimal(&name, 2);

    assert_eq!(record.encode().unwrap(), wire, "{name}");
    let decoded = AttrRecord::decode(&wire).unwrap();
    assert_eq!(&decoded, record, "{name}");
    assert_eq!(decoded.encode().unwrap(), wire, "{name}");
    assert_eq!(record.signature_preimage().unwrap(), preimage, "{name}");
    assert_eq!(decoded.signature_preimage().unwrap(), preimage, "{name}");

    let mut unsigned = record.clone();
    unsigned.signature = None;
    let mut independent_preimage = b"terrane-attr-signature-v1\0".to_vec();
    independent_preimage.extend_from_slice(&unsigned.encode().unwrap());
    assert_eq!(independent_preimage, preimage, "{name}");

    let identity = TERRANE_V1
        .calculate(IdentityKind::Attribute, &wire)
        .unwrap();
    assert_eq!(identity.digest(), digest, "{name}");
    assert_eq!(record.identity().unwrap(), identity, "{name}");
    assert_eq!(decoded.identity().unwrap(), identity, "{name}");
}

#[test]
fn reference_attribute_records_preserve_fields_signatures_preimages_and_identities() {
    let mut count = 0;
    for (label, function_name, value) in values() {
        let unsigned = AttrRecord {
            object: OBJECT,
            value,
            function: Function {
                name: function_name.into(),
                version: "1".into(),
            },
            producer: PRODUCER,
            signature: None,
        };
        let mut signed = unsigned.clone();
        signed.signature = Some(signature());

        compare_record(&format!("{label}-unsigned"), &unsigned);
        compare_record(&format!("{label}-opaque-signature"), &signed);
        assert_eq!(unsigned.signature_preimage(), signed.signature_preimage());
        assert_ne!(unsigned.identity(), signed.identity());
        count += 2;
    }

    for (label, version, producer) in [
        ("magic-future", "2", PRODUCER),
        ("magic-other-producer", "1", [35; 32]),
    ] {
        for signed in [false, true] {
            let suffix = if signed {
                "opaque-signature"
            } else {
                "unsigned"
            };
            let record = AttrRecord {
                object: OBJECT,
                value: AttributeValue::Magic(Magic::Text),
                function: Function {
                    name: "magic".into(),
                    version: version.into(),
                },
                producer,
                signature: signed.then(signature),
            };
            compare_record(&format!("{label}-{suffix}"), &record);
            assert_eq!(
                record.function.supported(AttributeName::Magic),
                version == "1"
            );
            assert_ne!(
                record.identity().unwrap().digest(),
                hexadecimal("record-magic-text-unsigned", 2)
            );
            count += 1;
        }
    }
    assert_eq!(count, 42);
}

// This primitive tree bypasses the format encoders when reconstructing invalid
// records. It cannot grant a malformed wire an identity or producer authority.
#[derive(Clone)]
enum Primitive {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Array(Vec<Primitive>),
    Map(Vec<(u64, Primitive)>),
}

impl Primitive {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(value) => cbor::write_uint(out, *value),
            Self::Bytes(value) => cbor::write_bytes(out, value),
            Self::Text(value) => cbor::write_text(out, value),
            Self::Bool(value) => out.push(if *value { 0xf5 } else { 0xf4 }),
            Self::Null => out.push(0xf6),
            Self::Array(values) => {
                cbor::write_array(out, values.len());
                for value in values {
                    value.encode(out);
                }
            }
            Self::Map(fields) => {
                cbor::write_map(out, fields.len());
                for (key, value) in fields {
                    cbor::write_uint(out, *key);
                    value.encode(out);
                }
            }
        }
    }
}

fn text(value: &str) -> Primitive {
    Primitive::Text(value.into())
}

fn bytes(width: usize, byte: u8) -> Primitive {
    Primitive::Bytes(vec![byte; width])
}

fn replace(fields: &[(u64, Primitive)], key: u64, value: Primitive) -> Primitive {
    let mut fields = fields.to_vec();
    if let Some(field) = fields.iter_mut().find(|field| field.0 == key) {
        field.1 = value;
    } else {
        fields.push((key, value));
        fields.sort_by_key(|field| field.0);
    }
    Primitive::Map(fields)
}

fn negatives() -> Vec<(String, Option<AttributeName>, Primitive)> {
    let mut models = vec![];
    for (label, attribute, width, byte) in [
        ("sha256", AttributeName::Sha256, 32, 49),
        ("sha512", AttributeName::Sha512, 64, 50),
        ("git-blob-sha1", AttributeName::GitBlobSha1, 20, 51),
        ("git-blob-sha256", AttributeName::GitBlobSha256, 32, 52),
        ("dictionary", AttributeName::ZstdDictionary, 32, 53),
    ] {
        for (suffix, length) in [("short", width - 1), ("long", width + 1)] {
            models.push((
                format!("value-{label}-{suffix}"),
                Some(attribute),
                bytes(length, byte),
            ));
        }
    }
    models.push((
        "value-magic-unknown".into(),
        Some(AttributeName::Magic),
        text("future-class"),
    ));

    let elf = vec![
        (1, Primitive::Uint(64)),
        (2, Primitive::Uint(62)),
        (3, Primitive::Uint(3)),
        (4, text(INTERPRETER)),
        (
            5,
            Primitive::Array(vec![text("libz.so"), text("liba.so"), text("libz.so")]),
        ),
    ];
    for (label, key, value) in [
        ("class", 1, Primitive::Uint(16)),
        ("machine", 2, Primitive::Uint(65536)),
        ("type", 3, Primitive::Uint(65536)),
        ("interpreter-type", 4, Primitive::Bool(true)),
        ("interpreter-empty", 4, text("")),
        ("interpreter-nul", 4, text("a\0b")),
        ("needed-type", 5, text("liba.so")),
        (
            "needed-member-type",
            5,
            Primitive::Array(vec![Primitive::Bytes(b"liba.so".to_vec())]),
        ),
        ("needed-empty", 5, Primitive::Array(vec![text("")])),
        ("needed-nul", 5, Primitive::Array(vec![text("a\0b")])),
    ] {
        models.push((
            format!("value-elf-{label}"),
            Some(AttributeName::Elf),
            replace(&elf, key, value),
        ));
    }
    let shebang = vec![(1, text(INTERPRETER)), (2, Primitive::Null)];
    for (label, key, value) in [
        ("relative", 1, text("relative/interpreter")),
        ("empty", 1, text("")),
        ("nul", 1, text("/a\0b")),
        ("argument-type", 2, Primitive::Bool(true)),
        ("argument-empty", 2, text("")),
        ("argument-nul", 2, text("a\0b")),
    ] {
        models.push((
            format!("value-shebang-{label}"),
            Some(AttributeName::Shebang),
            replace(&shebang, key, value),
        ));
    }
    for (label, attribute, original, key) in [
        ("elf", AttributeName::Elf, elf, 4),
        ("shebang", AttributeName::Shebang, shebang, 2),
    ] {
        let missing: Vec<_> = original
            .iter()
            .filter(|field| field.0 != key)
            .cloned()
            .collect();
        models.push((
            format!("value-{label}-missing-optional-key"),
            Some(attribute),
            Primitive::Map(missing.clone()),
        ));
        let value = original
            .iter()
            .find(|field| field.0 == key)
            .unwrap()
            .1
            .clone();
        models.push((
            format!("value-{label}-unknown-key"),
            Some(attribute),
            replace(&missing, 9, value),
        ));
    }

    let base = vec![
        (1, bytes(32, 17)),
        (2, text("hash.sha256")),
        (3, bytes(32, 49)),
        (4, text("sha256/1")),
        (5, bytes(32, 34)),
    ];
    for (label, key, value) in [
        ("object-short", 1, bytes(31, 0)),
        ("object-long", 1, bytes(33, 0)),
        ("producer-short", 5, bytes(31, 0)),
        ("producer-long", 5, bytes(33, 0)),
        ("signature-short", 6, bytes(63, 0)),
        ("signature-long", 6, bytes(65, 0)),
        ("unknown-name", 2, text("hash.future")),
        ("name-type", 2, Primitive::Bytes(b"hash.sha256".to_vec())),
        ("value-type", 3, text("digest")),
        ("function-type", 4, Primitive::Bytes(b"sha256/1".to_vec())),
        ("function-no-version", 4, text("sha256")),
        ("function-empty-name", 4, text("/1")),
        ("function-empty-version", 4, text("sha256/")),
        ("function-extra-slash", 4, text("sha256/1/2")),
        ("function-invalid-character", 4, text("sha256/1!")),
    ] {
        models.push((format!("record-{label}"), None, replace(&base, key, value)));
    }
    let missing: Vec<_> = base.iter().filter(|field| field.0 != 5).cloned().collect();
    models.push((
        "record-missing-producer".into(),
        None,
        Primitive::Map(missing.clone()),
    ));
    models.push((
        "record-extra-key".into(),
        None,
        replace(&base, 7, Primitive::Null),
    ));
    models.push((
        "record-wrong-key".into(),
        None,
        replace(&missing, 7, bytes(32, 34)),
    ));
    assert_eq!(models.len(), 49);
    models
}

#[test]
fn reference_negative_attribute_wires_require_structural_rejection() {
    for (label, attribute, primitive) in negatives() {
        let mut independent = vec![];
        primitive.encode(&mut independent);
        let reference = hexadecimal(&format!("negative-{label}"), 0);
        assert_eq!(independent, reference, "{label}");

        if let Some(attribute) = attribute {
            assert!(
                AttributeValue::decode(attribute, &reference).is_err(),
                "{label}"
            );
        } else {
            assert!(AttrRecord::decode(&reference).is_err(), "{label}");
        }
    }
}
