//! Checks private capability preimages with ordinary unverified field models.
//!
//! ```text
//! authority preimage = canonical authority map without key 12
//! attenuation preimage = canonical attenuation map without key 6
//! ```
//!
//! These tests never issue, sign, attenuate or verify a capability. Arbitrary
//! key and signature bytes are opaque fields, not authenticated authority.

use super::*;
use crate::cbor::{self, Decoder};
use alloc::format;

const INTEGERS: [u64; 12] = [
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

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn opaque<const N: usize>(state: &mut u64) -> [u8; N] {
    core::array::from_fn(|_| next(state) as u8)
}

fn boundary_bytes<const N: usize>(state: &mut u64, case: usize) -> [u8; N] {
    match case % 3 {
        0 => [0; N],
        1 => [0xff; N],
        _ => opaque(state),
    }
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

/// Encodes independently selected fields in their registered numeric order.
fn projection(mut fields: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|(key, _)| *key);
    assert!(fields.windows(2).all(|pair| pair[0].0 < pair[1].0));

    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, fields.len());
    for (key, value) in fields {
        cbor::write_uint(&mut bytes, key);
        bytes.extend(value);
    }
    bytes
}

fn grant_projection(values: &[Grant]) -> Vec<u8> {
    array(
        &values
            .iter()
            .map(|value| array(&[text(value.pattern()), uint(u64::from(value.verbs().bits()))]))
            .collect::<Vec<_>>(),
    )
}

fn locality_projection(value: &Locality) -> Vec<u8> {
    projection(
        [(1, &value.region), (2, &value.zone), (3, &value.host)]
            .into_iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| (key, text(value))))
            .collect(),
    )
}

fn caveat_projection(value: &Caveat) -> Vec<u8> {
    let fields = match value {
        Caveat::Before(value) => vec![text("before"), uint(*value)],
        Caveat::After(value) => vec![text("after"), uint(*value)],
        Caveat::Ref(value) => vec![text("ref"), text(value)],
        Caveat::Root(value) => vec![text("root"), text(value)],
        Caveat::Verb(value) => vec![text("verb"), uint(u64::from(value.bits()))],
        Caveat::Domain(value) => vec![text("domain"), text(value)],
        Caveat::Surface(value) => vec![text("surface"), text(value)],
        Caveat::Locality(value) => vec![text("locality"), locality_projection(value)],
        Caveat::Epoch(reference, epoch) => vec![text("epoch"), text(reference), uint(*epoch)],
    };
    array(&fields)
}

fn authority_projection(block: &Signed<Authority>) -> Vec<u8> {
    let body = &block.body;
    let kind = match body.kind {
        PrincipalKind::Human => 1,
        PrincipalKind::Workload => 2,
        PrincipalKind::Service => 3,
    };
    let mut fields = vec![
        (1, text(&body.issuer)),
        (2, text(&body.key_id)),
        (3, text(&body.subject)),
        (4, uint(kind)),
        (
            5,
            array(
                &body
                    .groups
                    .iter()
                    .map(|value| text(value))
                    .collect::<Vec<_>>(),
            ),
        ),
        (6, uint(body.not_after)),
        (8, bytes(&body.token_id)),
        (9, grant_projection(&body.grants)),
        (11, bytes(&block.next_key)),
    ];
    if let Some(value) = body.not_before {
        fields.push((7, uint(value)));
    }
    if let Some(value) = &body.workload {
        fields.push((10, text(value)));
    }
    projection(fields)
}

fn attenuation_projection(block: &Signed<Attenuation>) -> Vec<u8> {
    let body = &block.body;
    let mut fields = vec![(5, bytes(&block.next_key))];
    if let Some(value) = body.not_after {
        fields.push((1, uint(value)));
    }
    if let Some(value) = body.not_before {
        fields.push((2, uint(value)));
    }
    if let Some(values) = &body.grants {
        fields.push((3, grant_projection(values)));
    }
    if !body.caveats.is_empty() {
        fields.push((
            4,
            array(
                &body
                    .caveats
                    .iter()
                    .map(caveat_projection)
                    .collect::<Vec<_>>(),
            ),
        ));
    }
    projection(fields)
}

/// Checks one complete canonical map without inventing a preimage decoder.
fn assert_map(bytes: &[u8], keys: &[u64], omitted: u64) {
    let mut decoder = Decoder::new(bytes);
    assert_eq!(decoder.map(12).expect("canonical map"), keys.len());
    for key in keys {
        assert_ne!(*key, omitted);
        assert_eq!(decoder.uint().expect("canonical numeric key"), *key);
        decoder
            .skip_value(bytes.len())
            .expect("complete canonical field");
    }
    decoder.finish().expect("one whole canonical value");
}

fn grants(case: usize) -> Vec<Grant> {
    let count = [1, 23, 24, 256][case % 4];
    (0..count)
        .map(|index| {
            grant(
                &format!("refs/heads/model-{case}-{index}/**"),
                ((case + index) % 31 + 1) as u8,
            )
        })
        .collect()
}

#[test]
fn authority_preimages_match_unsigned_models_and_omit_only_signature() {
    let mut state = 0x13d7_a956_b287_f641;
    for case in 0..144 {
        let number = INTEGERS[case / 12];
        let mut body = authority();
        let width = [0, 1, 23, 24, 255, 256][case % 6];
        body.issuer = "i".repeat(width);
        body.key_id = format!("key-{}", next(&mut state));
        body.subject = format!("subject-{}", next(&mut state));
        body.kind = [
            PrincipalKind::Human,
            PrincipalKind::Workload,
            PrincipalKind::Service,
        ][case / 4 % 3];
        body.groups = (0..[0, 1, 23, 24, 256][case % 5])
            .map(|index| format!("group-{index}"))
            .collect();
        body.not_after = number;
        body.not_before = (case & 1 != 0).then_some(number);
        body.workload = (case & 2 != 0).then(|| "w".repeat(width));
        body.token_id = boundary_bytes(&mut state, case);
        body.grants = grants(case);
        let block = Signed {
            body,
            next_key: boundary_bytes(&mut state, case + 1),
            signature: boundary_bytes(&mut state, case + 2),
        };

        let actual = format::authority_preimage(&block);
        assert_eq!(
            actual,
            authority_projection(&block),
            "authority model {case}"
        );
        let mut keys = vec![1, 2, 3, 4, 5, 6, 8, 9, 11];
        if block.body.not_before.is_some() {
            keys.push(7);
        }
        if block.body.workload.is_some() {
            keys.push(10);
        }
        keys.sort_unstable();
        assert_map(&actual, &keys, 12);

        let mut changed = block.clone();
        changed.signature = opaque(&mut state);
        assert_ne!(changed.signature, block.signature);
        assert_eq!(format::authority_preimage(&changed), actual);
        changed.next_key[case % 32] ^= 1;
        assert_ne!(format::authority_preimage(&changed), actual);

        let token = Token {
            authority: block.clone(),
            blocks: vec![],
        };
        assert_eq!(
            Token::decode(&token.encode()).expect("unverified field codec"),
            token
        );
        let changes: [fn(&mut Authority); 10] = [
            |body| body.issuer.push('!'),
            |body| body.key_id.push('!'),
            |body| body.subject.push('!'),
            |body| {
                body.kind = if body.kind == PrincipalKind::Human {
                    PrincipalKind::Service
                } else {
                    PrincipalKind::Human
                }
            },
            |body| body.groups.push("changed".to_string()),
            |body| body.not_after ^= 1,
            |body| {
                body.not_before = if body.not_before.is_some() {
                    None
                } else {
                    Some(0)
                }
            },
            |body| body.token_id[0] ^= 1,
            |body| body.grants[0] = grant("refs/heads/changed/**", 31),
            |body| {
                body.workload = if body.workload.is_some() {
                    None
                } else {
                    Some(String::new())
                }
            },
        ];
        for change in changes {
            let mut changed = block.clone();
            change(&mut changed.body);
            assert_ne!(format::authority_preimage(&changed), actual);
        }
    }
}

#[test]
fn attenuation_preimages_match_unsigned_models_for_every_caveat_and_presence() {
    let mut state = 0x57a3_c896_21ef_04bd;
    for case in 0..192 {
        let number = INTEGERS[case / 16];
        let presence = case % 16;
        let label = Locality {
            region: (case & 1 != 0).then(String::new),
            zone: (case & 2 != 0).then(|| "z".repeat([1, 23, 24, 255, 256][case % 5])),
            host: (case & 4 != 0).then(|| format!("host-{}", next(&mut state))),
        };
        let mut caveats = vec![
            Caveat::Before(number),
            Caveat::After(number),
            Caveat::Ref("refs/heads/model/**".to_string()),
            Caveat::Root("/model/**".to_string()),
            Caveat::Verb(Verbs::new((case % 31 + 1) as u8).expect("registered mask")),
            Caveat::Domain("public".to_string()),
            Caveat::Surface(String::new()),
            Caveat::Locality(label),
            Caveat::Epoch("refs/heads/model".to_string(), number),
        ];
        caveats.rotate_left(case % 9);
        if case.is_multiple_of(3) {
            caveats.extend(caveats.clone());
        }
        let block = Signed {
            body: Attenuation {
                not_after: (presence & 1 != 0).then_some(number),
                not_before: (presence & 2 != 0).then_some(number),
                grants: (presence & 4 != 0).then(|| grants(case)),
                caveats: if presence & 8 != 0 { caveats } else { vec![] },
            },
            next_key: boundary_bytes(&mut state, case),
            signature: boundary_bytes(&mut state, case + 1),
        };

        let actual = format::attenuation_preimage(&block);
        assert_eq!(
            actual,
            attenuation_projection(&block),
            "attenuation model {case}"
        );
        let keys: Vec<_> = (1..=4)
            .filter(|key| presence & (1 << (key - 1)) != 0)
            .chain(core::iter::once(5))
            .collect();
        assert_map(&actual, &keys, 6);

        let mut changed = block.clone();
        changed.signature = opaque(&mut state);
        assert_ne!(changed.signature, block.signature);
        assert_eq!(format::attenuation_preimage(&changed), actual);
        changed.next_key[case % 32] ^= 1;
        assert_ne!(format::attenuation_preimage(&changed), actual);

        let changes: [fn(&mut Attenuation); 4] = [
            |body| {
                body.not_after = if body.not_after.is_some() {
                    None
                } else {
                    Some(0)
                }
            },
            |body| {
                body.not_before = if body.not_before.is_some() {
                    None
                } else {
                    Some(0)
                }
            },
            |body| {
                body.grants = if body.grants.is_some() {
                    None
                } else {
                    Some(vec![grant("refs/heads/changed/**", 1)])
                }
            },
            |body| body.caveats.push(Caveat::Before(7)),
        ];
        for change in changes {
            let mut changed = block.clone();
            change(&mut changed.body);
            assert_ne!(format::attenuation_preimage(&changed), actual);
        }
        let token = Token {
            authority: Signed {
                body: authority(),
                next_key: opaque(&mut state),
                signature: opaque(&mut state),
            },
            blocks: vec![block],
        };
        assert_eq!(
            Token::decode(&token.encode()).expect("unverified field codec"),
            token
        );
    }
}
