//! Tests tuple projection, map ordering and filtering with unverified field data.

#![allow(clippy::expect_used)]

use super::*;
use crate::{
    cbor::Decoder,
    derived::{AttributeValue, ElfValue, Magic, ShebangValue},
    provenance::{Preset, Selector, validate_canonical_context},
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
};

#[derive(Clone)]
struct Payload {
    record: Digest,
    object: Digest,
    name: String,
    function: String,
    version: String,
    value: Vec<u8>,
    producer: Digest,
    location: EntryLocation,
    producer_domain: String,
    producer_path: Vec<u8>,
    view_path: Vec<u8>,
}

impl Payload {
    fn fields(&self) -> EvidenceFields<'_> {
        EvidenceFields {
            record: &self.record,
            object: &self.object,
            name: &self.name,
            function: &self.function,
            version: &self.version,
            value: &self.value,
            producer: &self.producer,
            location: &self.location,
            producer_domain: &self.producer_domain,
            producer_path: &self.producer_path,
        }
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn opaque<const N: usize>(state: &mut u64) -> [u8; N] {
    core::array::from_fn(|_| next(state) as u8)
}

fn path(width: usize, first: u8) -> Vec<u8> {
    let mut bytes = vec![b'p'; width];
    bytes[0] = first;
    if width == 4096 {
        for index in (240..4096).step_by(241) {
            bytes[index] = b'/';
        }
    }
    bytes
}

fn uint(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_uint(&mut bytes, value);
    bytes
}

fn text(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, value);
    bytes
}

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_bytes(&mut bytes, value);
    bytes
}

fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, values.len());
    for value in values {
        bytes.extend_from_slice(value);
    }
    bytes
}

fn location(value: &EntryLocation) -> Vec<u8> {
    array(&[bytes(&value.commit), bytes(&value.root), bytes(&value.path)])
}

fn expected_evidence(value: &Payload) -> Vec<u8> {
    array(&[
        bytes(&value.record),
        bytes(&value.object),
        text(&value.name),
        text(&value.function),
        text(&value.version),
        bytes(&value.value),
        bytes(&value.producer),
        location(&value.location),
        array(&[text(&value.producer_domain), bytes(&value.producer_path)]),
    ])
}

fn actual_evidence(value: &Payload) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_evidence(&mut bytes, value.fields());
    bytes
}

fn actual_rows(rows: &BTreeMap<SideAttributeKey, Payload>, view: Digest, domain: &str) -> Vec<u8> {
    selected(
        rows,
        view,
        domain,
        |value| &value.view_path,
        |output, value| {
            encode_evidence(output, value.fields());
        },
    )
}

fn expected_rows(
    rows: &BTreeMap<SideAttributeKey, Payload>,
    view: Digest,
    domain: &str,
) -> Vec<u8> {
    let values = rows
        .iter()
        .filter(|((location, _, row_domain), _)| location.commit == view && row_domain == domain)
        .map(|((selected, name, domain), value)| {
            array(&[
                location(selected),
                text(name),
                text(domain),
                bytes(&value.view_path),
                expected_evidence(value),
            ])
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        vec![]
    } else {
        array(&values)
    }
}

fn attribute(state: &mut u64, case: usize) -> AttributeValue {
    match case % 8 {
        0 => AttributeValue::Sha256(opaque(state)),
        1 => AttributeValue::Sha512(opaque(state)),
        2 => AttributeValue::GitBlobSha1(opaque(state)),
        3 => AttributeValue::GitBlobSha256(opaque(state)),
        4 => AttributeValue::ZstdDictionary(opaque(state)),
        5 => AttributeValue::Magic(
            Magic::parse(
                [
                    "elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other",
                ][case / 8 % 8],
            )
            .expect("registered magic"),
        ),
        6 => AttributeValue::Elf(ElfValue {
            class: if (case / 8).is_multiple_of(2) { 32 } else { 64 },
            machine: [0, 1, 23, 24, 255, 256, u16::MAX][case / 8 % 7],
            elf_type: next(state) as u16,
            interpreter: (case / 8).is_multiple_of(2).then(|| "/interpreter".into()),
            needed: (0..case / 8 % 4)
                .map(|index| format!("lib{index}.so"))
                .collect(),
        }),
        _ => AttributeValue::Shebang(ShebangValue {
            interpreter: "/interpreter".into(),
            argument: (case / 8).is_multiple_of(2).then(|| "a".into()),
        }),
    }
}

fn context(view: Digest, domain: &str, selected: &[u8]) -> Vec<u8> {
    let mut slots = vec![
        uint(if selected.is_empty() { 1 } else { 2 }),
        bytes(&view),
        text(domain),
        bytes(Selector::preset(Preset::Any).encode()),
        vec![0xf6],
        uint(262_144),
    ];
    if !selected.is_empty() {
        slots.push(bytes(selected));
    }
    array(&slots)
}

fn shuffle<T>(state: &mut u64, values: &mut [T]) {
    for index in (1..values.len()).rev() {
        let selected = (next(state) % (index + 1) as u64) as usize;
        values.swap(index, selected);
    }
}

#[test]
fn selected_evidence_models_preserve_tuple_fields_and_filtered_row_order() {
    let empty_argument = AttributeValue::Shebang(ShebangValue {
        interpreter: "/interpreter".into(),
        argument: Some(String::new()),
    });
    assert_eq!(
        empty_argument.encode(),
        Err(crate::derived::Error::InvalidValue)
    );

    let mut state = 0x892c_14af_7ed0_563b;
    for case in 0..48 {
        let view = opaque(&mut state);
        let other_view = opaque(&mut state);
        let domain = [
            "public",
            "tenant:selected",
            "group:selected",
            "private:selected",
        ][case % 4];
        let width = [1, 23, 255, 4096][case % 4];
        let count = [0, 1, 2, 7, 24, 256][case % 6];
        let mut rows = BTreeMap::new();
        for index in 0..count {
            let attribute = attribute(&mut state, case + index);
            let function = attribute.name().function();
            let mut root = opaque::<32>(&mut state);
            root[0] = index as u8;
            let key = (
                EntryLocation {
                    commit: if index % 3 == 1 { other_view } else { view },
                    root,
                    path: path(width, b'f'),
                },
                attribute.name().as_str().to_string(),
                if index % 4 == 1 {
                    "private:other"
                } else {
                    domain
                }
                .to_string(),
            );
            let value = Payload {
                record: opaque(&mut state),
                object: opaque(&mut state),
                name: attribute.name().as_str().into(),
                function: function.name,
                version: function.version,
                value: attribute.encode().expect("ordinary attribute value"),
                producer: opaque(&mut state),
                // Legacy inline evidence can be carried by a different commit.
                location: EntryLocation {
                    commit: opaque(&mut state),
                    root: opaque(&mut state),
                    path: path(width, b'w'),
                },
                producer_domain: [
                    "public",
                    "tenant:producer",
                    "group:producer",
                    "private:producer",
                ][index % 4]
                    .into(),
                producer_path: path(width, b'p'),
                view_path: path(width, b'v'),
            };

            let encoded = actual_evidence(&value);
            assert_eq!(encoded, expected_evidence(&value));
            let mut decoder = Decoder::new(&encoded);
            assert_eq!(decoder.array(9).expect("evidence width"), 9);
            for _ in 0..9 {
                decoder
                    .skip_value(encoded.len())
                    .expect("canonical tuple field");
            }
            decoder.finish().expect("one complete evidence tuple");
            let changes: [fn(&mut Payload); 12] = [
                |value| value.record[0] ^= 1,
                |value| value.object[0] ^= 1,
                |value| value.name.push_str("-changed"),
                |value| value.function.push_str("-changed"),
                |value| value.version.push_str(".changed"),
                |value| value.value = vec![0xf6],
                |value| value.producer[0] ^= 1,
                |value| value.location.commit[0] ^= 1,
                |value| value.location.root[0] ^= 1,
                |value| value.location.path[0] ^= 1,
                |value| {
                    value.producer_domain = if value.producer_domain == "public" {
                        "private:changed"
                    } else {
                        "public"
                    }
                    .into()
                },
                |value| value.producer_path[0] ^= 1,
            ];
            for change in changes {
                let mut changed = value.clone();
                change(&mut changed);
                assert_ne!(actual_evidence(&changed), encoded);
                assert_eq!(actual_evidence(&changed), expected_evidence(&changed));
            }
            rows.insert(key, value);
        }

        for selected_view in [view, other_view] {
            for selected_domain in [domain, "private:other", "private:absent"] {
                let expected = expected_rows(&rows, selected_view, selected_domain);
                assert_eq!(actual_rows(&rows, selected_view, selected_domain), expected);
                validate_canonical_context(&context(selected_view, selected_domain, &expected))
                    .expect("untrusted selected-row schema");
                if !expected.is_empty() {
                    let mut decoder = Decoder::new(&expected);
                    let count = decoder.array(expected.len()).expect("row count");
                    for _ in 0..count {
                        assert_eq!(decoder.array(5).expect("row width"), 5);
                        for _ in 0..5 {
                            decoder
                                .skip_value(expected.len())
                                .expect("canonical row field");
                        }
                    }
                    decoder.finish().expect("complete selected rows");
                }
                for _ in 0..3 {
                    let mut insertion = rows
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>();
                    shuffle(&mut state, &mut insertion);
                    let permuted: BTreeMap<_, _> = insertion.into_iter().collect();
                    assert_eq!(
                        actual_rows(&permuted, selected_view, selected_domain),
                        expected,
                        "map insertion history"
                    );
                }
            }
        }
    }
}
