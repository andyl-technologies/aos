//! Compares both published unsigned block projections with ordinary signed fields.
//!
//! Fixed public keys and signatures remain opaque bytes. The owning functions
//! serialize preimages only; there is no standalone unsigned-block decoder.
//! No token is issued, attenuated, authenticated or used for authorization.
//!
//! ```text
//! authority preimage = complete authority map with signature key 12 omitted
//! attenuation preimage = complete attenuation map with signature key 6 omitted
//! ```

#![allow(
    clippy::unwrap_used,
    reason = "independent fields must reproduce the published preimages"
)]

#[allow(
    clippy::duplicate_mod,
    reason = "isolated private consumers share the primitive reference reader"
)]
#[path = "support.rs"]
mod support;

use super::{
    Attenuation, Authority, Caveat, Grant, PrincipalKind, Signed, Verbs, attenuation_preimage,
    authority_preimage,
};
use alloc::{format, vec};
use support::{REFERENCE, Value, blocks, changed, hexadecimal, section};

fn public_key() -> [u8; 32] {
    hexadecimal("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        .unwrap()
        .try_into()
        .unwrap()
}

fn authority_model() -> Signed<Authority> {
    Signed {
        body: Authority {
            issuer: "issuer.example".into(),
            key_id: "k1".into(),
            subject: "ci-job".into(),
            kind: PrincipalKind::Workload,
            groups: vec!["builders".into()],
            not_after: 1_760_003_600,
            not_before: None,
            token_id: core::array::from_fn(|index| (index + 1) as u8),
            grants: vec![Grant::new("refs/heads/pr/**".into(), Verbs::new(7).unwrap()).unwrap()],
            workload: None,
        },
        next_key: public_key(),
        signature: hexadecimal(concat!(
            "7239961b2b42911f2f2ad53e5b8715d82f18ba850cad724863832e43d45bbd4ccffd",
            "924ffa1189b7695a7d6c610fb766ff7ea30a26cd69924f9f140edac5f609"
        ))
        .unwrap()
        .try_into()
        .unwrap(),
    }
}

fn authority_fields() -> Value {
    Value::Map(vec![
        (1, Value::Text("issuer.example".into())),
        (2, Value::Text("k1".into())),
        (3, Value::Text("ci-job".into())),
        (4, Value::Uint(2)),
        (5, Value::Array(vec![Value::Text("builders".into())])),
        (6, Value::Uint(1_760_003_600)),
        (8, Value::Bytes((1..=16).collect())),
        (
            9,
            Value::Array(vec![Value::Array(vec![
                Value::Text("refs/heads/pr/**".into()),
                Value::Uint(7),
            ])]),
        ),
        (11, Value::Bytes(public_key().to_vec())),
    ])
}

fn attenuation_model() -> Signed<Attenuation> {
    Signed {
        body: Attenuation {
            not_after: None,
            not_before: None,
            grants: None,
            caveats: vec![
                Caveat::Ref("refs/heads/pr/1234".into()),
                Caveat::Epoch("refs/heads/pr/1234".into(), 1),
            ],
        },
        next_key: public_key(),
        signature: hexadecimal(concat!(
            "3fda3b61fb042cf3fe81e027fb7968fef6f8e40fb59e7ccb98117c97392ba0bbd",
            "5aa8e92a5faf958af1cb6f61f739b5c6cec2e194e644058ea2d4f8989ac700c"
        ))
        .unwrap()
        .try_into()
        .unwrap(),
    }
}

fn attenuation_fields() -> Value {
    Value::Map(vec![
        (
            4,
            Value::Array(vec![
                Value::Array(vec![
                    Value::Text("ref".into()),
                    Value::Text("refs/heads/pr/1234".into()),
                ]),
                Value::Array(vec![
                    Value::Text("epoch".into()),
                    Value::Text("refs/heads/pr/1234".into()),
                    Value::Uint(1),
                ]),
            ]),
        ),
        (5, Value::Bytes(public_key().to_vec())),
    ])
}

fn observe_mutation(body: &str, index: usize, actual: &[u8]) {
    let wires = blocks(body, "hex", 3).unwrap();
    let wire = wires[index];
    let modified = changed(body, wire, &format!("00{}", &wire[2..]));
    assert_ne!(
        hexadecimal(blocks(&modified, "hex", 3).unwrap()[index]).unwrap(),
        actual
    );
    assert!(blocks(body.split_once("Complete token").unwrap().0, "hex", 3).is_err());
}

#[test]
fn published_authority_preimage_matches_unsigned_model() {
    let body = section(REFERENCE, "Capability token").unwrap();
    let wires = blocks(body, "hex", 3).unwrap();
    let published = hexadecimal(wires[0]).unwrap();
    let model = authority_model();
    let independent = authority_fields().encode();

    assert_eq!(independent, published);
    assert_eq!(authority_preimage(&model), published);
    observe_mutation(body, 0, &authority_preimage(&model));
    let mut changed_signature = authority_model();
    changed_signature.signature[0] ^= 1;
    assert_eq!(authority_preimage(&changed_signature), independent);
    let mut changed_field = authority_model();
    changed_field.body.not_after += 1;
    assert_ne!(authority_preimage(&changed_field), independent);
}

#[test]
fn published_attenuation_preimage_matches_unsigned_model() {
    let body = section(REFERENCE, "Capability token").unwrap();
    let wires = blocks(body, "hex", 3).unwrap();
    let published = hexadecimal(wires[1]).unwrap();
    let model = attenuation_model();
    let independent = attenuation_fields().encode();

    assert_eq!(independent, published);
    assert_eq!(attenuation_preimage(&model), published);
    observe_mutation(body, 1, &attenuation_preimage(&model));
    let mut changed_signature = attenuation_model();
    changed_signature.signature[0] ^= 1;
    assert_eq!(attenuation_preimage(&changed_signature), independent);
    let mut changed_field = attenuation_model();
    changed_field.body.caveats.reverse();
    assert_ne!(attenuation_preimage(&changed_field), independent);
}
