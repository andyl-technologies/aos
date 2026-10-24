//! Checks disclosure statement slots and normalized target preimages as data.
//!
//! These encoder-only statement projections have no owning typed decoder.
//! Primitive field inspection checks every slot; no signature is generated or
//! verified, and no disclosure authority or history holder is constructed.
//!
//! ```text
//! statement = [authority, source-domain, time, source, original,
//!              [ref, root, path, domain], content, target-binding]
//! preimage = ASCII-purpose || 0x00 || canonical-statement
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "complete bounded fixture assertions"
)]

#[allow(
    clippy::duplicate_mod,
    reason = "isolated private consumer modules share the primitive fixture oracle"
)]
#[path = "support.rs"]
mod support;
#[path = "target.rs"]
mod target;

use super::*;
use alloc::{format, vec};

struct Model {
    proof: DisclosureProof,
    source: EntrySource,
    original: Digest,
    destination: EntryLocation,
    binding: Digest,
}

fn model() -> Model {
    Model {
        proof: DisclosureProof {
            authority_key: "12".repeat(32),
            source_domain: "private:source".into(),
            observed_at: 256,
            signature: [0x66; 64],
        },
        source: EntrySource {
            commit: [11; 32],
            root: [12; 32],
            path: b"source/full/item".to_vec(),
        },
        original: [13; 32],
        destination: EntryLocation {
            commit: [16; 32],
            root: [14; 32],
            path: b"target/full/item".to_vec(),
        },
        binding: [15; 32],
    }
}

fn actual(model: &Model, kind: &EntryKind<'_>) -> Result<Vec<u8>, Rejected> {
    encode_statement(StatementFields {
        proof: &model.proof,
        source: &model.source,
        original: model.original,
        reference: "refs/heads/_/target",
        destination: &model.destination,
        target_domain: "private:target",
        kind,
        binding: model.binding,
    })
}

#[test]
fn reference_disclosure_statement_models_preserve_all_slots_and_preimages() {
    const PURPOSE: &[u8] = b"terrane-disclosure-proof-v1\0";
    let cases = [
        (
            "inline",
            EntryKind::File {
                mode: 0o644,
                size: 24,
                content: ContentRef::Inline([21; 32]),
                link_id: None,
            },
        ),
        (
            "manifest",
            EntryKind::File {
                mode: 0o600,
                size: 65536,
                content: ContentRef::Manifest([21; 32]),
                link_id: None,
            },
        ),
        ("directory", EntryKind::Directory { mode: 0o755 }),
        (
            "symlink",
            EntryKind::Symlink {
                target: b"raw/\xfftarget",
            },
        ),
    ];
    for (layout, (label, kind)) in cases.into_iter().enumerate() {
        let fields = support::statement(layout);
        let published_body = support::compare(&format!("disclosure-statement-{label}"), &fields);
        let published_preimage = support::reference(&format!("disclosure-preimage-{label}"));
        let independently_prefixed = [PURPOSE, fields.encode().as_slice()].concat();
        let model = model();
        let encoded = actual(&model, &kind).unwrap();

        assert_eq!(
            independently_prefixed, published_preimage,
            "complete primitive preimage"
        );
        assert_eq!(encoded, published_preimage, "owning statement projection");
        assert_eq!(&encoded[..PURPOSE.len()], PURPOSE);
        assert_eq!(&encoded[PURPOSE.len()..], published_body);
        assert_eq!(
            support::fields(&encoded[PURPOSE.len()..]),
            fields,
            "all eight slots and nested projections"
        );

        let mut changed = model;
        changed.proof.signature = [0x77; 64];
        changed.destination.commit = [0x55; 32];
        assert_eq!(
            actual(&changed, &kind).unwrap(),
            published_preimage,
            "excluded signature/self-identity slots"
        );
    }
    let model = model();
    for unsupported in [
        EntryKind::Tree {
            root: [21; 32],
            props: None,
        },
        EntryKind::Whiteout,
        EntryKind::Conflict {
            candidates: vec![],
            base: None,
        },
        EntryKind::Index { targets: vec![] },
    ] {
        assert_eq!(
            actual(&model, &unsupported),
            Err(Rejected),
            "unsupported content has no registered statement projection"
        );
    }
}

#[test]
fn reference_disclosure_target_models_preserve_normalized_fields_and_digest() {
    target::check();
}
