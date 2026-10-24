//! Tests context version selection and every retained ordinary field.

#![allow(clippy::expect_used)]

use super::*;
use crate::{
    cbor::Decoder,
    provenance::{Preset, Selector, validate_canonical_context},
};
use alloc::{string::String, vec};

#[derive(Clone)]
struct Model {
    view: Digest,
    domain: String,
    selector: Vec<u8>,
    baseline: Option<String>,
    minimum: u64,
    selected: Vec<u8>,
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

fn location(commit: &[u8], root: &[u8], path: &[u8]) -> Vec<u8> {
    array(&[bytes(commit), bytes(root), bytes(path)])
}

/// Supplies schema-valid ordinary rows without constructing verified evidence.
fn evidence(model: &Model, state: &mut u64, count: usize, width: usize) -> Vec<u8> {
    let mut path = vec![b'p'; width];
    if width == 4096 {
        for index in (240..4096).step_by(241) {
            path[index] = b'/';
        }
    }
    let rows = (0..count)
        .map(|index| {
            let mut root = opaque::<32>(state);
            root[0] = index as u8;
            let value = bytes(&opaque::<32>(state));
            let side = array(&[
                bytes(&opaque::<32>(state)),
                bytes(&opaque::<32>(state)),
                text("hash.sha256"),
                text("sha256"),
                text("1"),
                bytes(&value),
                bytes(&opaque::<32>(state)),
                location(&opaque::<32>(state), &opaque::<32>(state), &path),
                array(&[text("public"), bytes(&path)]),
            ]);
            array(&[
                location(&model.view, &root, &path),
                text("hash.sha256"),
                text(&model.domain),
                bytes(&path),
                side,
            ])
        })
        .collect::<Vec<_>>();
    array(&rows)
}

fn actual(model: &Model) -> Vec<u8> {
    encode(ContextFields {
        view: &model.view,
        domain: &model.domain,
        selector: &model.selector,
        baseline: model.baseline.as_deref(),
        minimum: model.minimum,
        selected: &model.selected,
    })
}

fn expected(model: &Model) -> Vec<u8> {
    let mut slots = vec![
        uint(if model.selected.is_empty() { 1 } else { 2 }),
        bytes(&model.view),
        text(&model.domain),
        bytes(&model.selector),
        model
            .baseline
            .as_ref()
            .map_or_else(|| vec![0xf6], |value| text(value)),
        uint(model.minimum),
    ];
    if !model.selected.is_empty() {
        slots.push(bytes(&model.selected));
    }
    array(&slots)
}

#[test]
fn context_models_preserve_versions_presence_and_selected_bytes() {
    let mut state = 0x409b_715e_a38c_d267;
    let numbers = [
        0,
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for case in 0..144 {
        let mut model = Model {
            view: opaque(&mut state),
            domain: [
                "public",
                "tenant:generated",
                "group:generated",
                "private:generated",
            ][case % 4]
                .into(),
            selector: Selector::preset(
                [
                    Preset::Any,
                    Preset::SignedBaseline,
                    Preset::Strict,
                    Preset::Attested,
                ][case / 4 % 4],
            )
            .encode()
            .to_vec(),
            baseline: match case % 3 {
                0 => None,
                1 => Some(String::new()),
                _ => Some("b".repeat([1, 23, 24, 255, 256, 4096][case / 3 % 6])),
            },
            minimum: numbers[case / 12],
            selected: vec![],
        };
        for version in [1, 2] {
            if version == 2 {
                model.selected = evidence(
                    &model,
                    &mut state,
                    [1, 2, 7, 32][case % 4],
                    [1, 255, 4096][case % 3],
                );
            }
            let bytes = actual(&model);
            assert_eq!(
                bytes,
                expected(&model),
                "context model {case} version {version}"
            );
            validate_canonical_context(&bytes).expect("untrusted canonical schema");

            let mut decoder = Decoder::new(&bytes);
            assert_eq!(
                decoder.array(7).expect("context width"),
                if version == 1 { 6 } else { 7 }
            );
            assert_eq!(decoder.uint().expect("version"), version);
            assert_eq!(decoder.bytes(32).expect("view"), model.view);
            assert_eq!(decoder.text(bytes.len()).expect("domain"), model.domain);
            assert_eq!(
                decoder.bytes(bytes.len()).expect("selector"),
                model.selector
            );
            if let Some(baseline) = &model.baseline {
                assert_eq!(decoder.text(bytes.len()).expect("baseline"), baseline);
            } else {
                assert_eq!(decoder.simple().expect("null baseline"), 0xf6);
            }
            assert_eq!(decoder.uint().expect("minimum"), model.minimum);
            if version == 2 {
                assert_eq!(
                    decoder.bytes(bytes.len()).expect("exact evidence"),
                    model.selected
                );
            }
            decoder.finish().expect("one complete context");

            let changes: [fn(&mut Model); 5] = [
                |model| model.view[0] ^= 1,
                |model| {
                    model.domain = if model.domain == "public" {
                        "private:changed"
                    } else {
                        "public"
                    }
                    .into()
                },
                |model| {
                    model.selector = if model.selector == Selector::preset(Preset::Any).encode() {
                        Selector::preset(Preset::Strict)
                    } else {
                        Selector::preset(Preset::Any)
                    }
                    .encode()
                    .to_vec()
                },
                |model| {
                    model.baseline = if model.baseline.is_some() {
                        None
                    } else {
                        Some(String::new())
                    }
                },
                |model| model.minimum ^= 1,
            ];
            for change in changes {
                let mut changed = model.clone();
                change(&mut changed);
                assert_ne!(actual(&changed), bytes);
                assert_eq!(actual(&changed), expected(&changed));
            }
            let mut changed = model.clone();
            if version == 2 {
                *changed.selected.last_mut().expect("selected evidence") = b'q';
                assert_ne!(
                    actual(&changed),
                    bytes,
                    "selected bytes are retained verbatim"
                );
                changed.selected.clear();
                assert_ne!(actual(&changed), bytes, "empty evidence selects v1");
            } else {
                changed.selected = evidence(&changed, &mut state, 1, 1);
                assert_ne!(actual(&changed), bytes, "nonempty evidence selects v2");
            }
            assert_eq!(actual(&changed), expected(&changed));
            validate_canonical_context(&actual(&changed)).expect("evidence presence projection");
        }
    }
}
