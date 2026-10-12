//! Constructs complete ordinary commit models for disclosure target normalization.
//!
//! Fixed signatures remain opaque. Original authoring context is copied from an
//! inert request through the syntax-only constructor, without authorization.
//!
//! ```text
//! normalized = complete commit with key 8 absent and typed proof signatures zero
//! binding = BLAKE3(ASCII-purpose || 0x00 || normalized)
//! ```

use super::support::{self, Value, map, text};
use crate::{
    auth::{Request, RequestRoot, Verb},
    provenance::disclosure_target_binding,
    refs::{
        Commit, CommitContext, CommitSource, DisclosureProof, EntryOrigin, EntryReceipt,
        EntrySource, Lease, Locality, PackLocation, PrincipalKind, ProfilePair, Provenance,
    },
};
use alloc::{format, vec, vec::Vec};

fn locality() -> Locality {
    Locality {
        region: Some("r".into()),
        zone: Some("z".into()),
        host: Some("h".into()),
    }
}

fn source() -> EntrySource {
    EntrySource {
        commit: [31; 32],
        root: [32; 32],
        path: b"origin/item".to_vec(),
    }
}

fn model(variant: &str, normalized: bool) -> Commit {
    let changed = variant == "signatures";
    let roots = [
        RequestRoot {
            path: b"/",
            domain: "private:target",
        },
        RequestRoot {
            path: b"/nested",
            domain: "group:target",
        },
    ];
    let locality = locality();
    let request = Request {
        reference: b"refs/heads/_/target",
        verb: Verb::Commit,
        roots: &roots,
        now: 0,
        surface: "api",
        locality: &locality,
        epochs: &[],
    };
    let context = CommitContext::from_request(&request).unwrap();
    assert_eq!(context.reference(), "refs/heads/_/target");
    assert_eq!(context.surface(), "api");
    assert_eq!(context.locality(), &locality);
    assert_eq!(
        context
            .roots()
            .iter()
            .map(|root| (root.path(), root.domain()))
            .collect::<Vec<_>>(),
        vec![
            (b"/".as_slice(), "private:target"),
            (b"/nested".as_slice(), "group:target")
        ]
    );

    let receipts = vec![
        EntryReceipt {
            root: [2; 32],
            path: b"a".to_vec(),
            origin: EntryOrigin::Current,
            attributes: Some(vec![
                ("magic".into(), EntryOrigin::Current),
                ("hash.sha256".into(), EntryOrigin::Source(source())),
            ]),
            reintroduced_from: Some(source()),
            disclosure_proof: Some(DisclosureProof {
                authority_key: "12".repeat(32),
                source_domain: "private:source".into(),
                observed_at: 256,
                signature: [if normalized {
                    0
                } else if changed {
                    0x81
                } else {
                    0x80
                }; 64],
            }),
        },
        EntryReceipt {
            root: [2; 32],
            path: b"b".to_vec(),
            origin: EntryOrigin::Source(source()),
            attributes: None,
            reintroduced_from: None,
            disclosure_proof: None,
        },
        EntryReceipt {
            root: [3; 32],
            path: b"c".to_vec(),
            origin: EntryOrigin::Current,
            attributes: None,
            reintroduced_from: Some(source()),
            disclosure_proof: Some(DisclosureProof {
                authority_key: "34".repeat(32),
                source_domain: "group:source".into(),
                observed_at: 65536,
                signature: [if normalized {
                    0
                } else if changed {
                    0x83
                } else {
                    0x82
                }; 64],
            }),
        },
    ];
    Commit {
        tree: [1; 32],
        parents: vec![[4; 32], [5; 32]],
        provenance: Provenance {
            issuer: "issuer-a".into(),
            token_id: [8; 16],
            subject: "subject-a".into(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("workload-a".into()),
            process: "process-a".into(),
            observed_at: 24,
            writer_epoch: 2,
            source: CommitSource::Merged,
            embedded_token: Some(support::token().encode()),
        },
        timestamp: 256,
        message: "retained metadata".into(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: Some(support::recipe(variant == "opaque").encode()),
            conflicted: Some(false),
            lease: Some(Lease {
                owner: "owner-a".into(),
                expiry: 999,
            }),
            required_properties: Some(
                map(vec![
                    (text("baseline"), text("baseline")),
                    (
                        text("trust"),
                        Value::Array(vec![text("preset"), text("strict")]),
                    ),
                ])
                .encode(),
            ),
            entry_receipts: Some(receipts),
            commit_context: Some(context),
        },
        packs: Some(vec![PackLocation {
            pack_id: [6; 16],
            locality,
        }]),
        signature: (!normalized).then_some([if changed { 0x91 } else { 0x90 }; 64]),
    }
}

/// Compares complete target models, exact normalized bytes and registered bindings.
///
/// # Panics
/// Panics on any mismatch in an ordinary format fixture.
pub(super) fn check() {
    const PURPOSE: &[u8] = b"terrane-disclosure-target-v1\0";
    let mut bindings = vec![];
    for variant in ["original", "signatures", "opaque"] {
        let whole = support::compare(
            &format!("disclosure-target-{variant}"),
            &support::target(variant, false),
        );
        let normalized = support::compare(
            &format!("disclosure-normalized-{variant}"),
            &support::target(variant, true),
        );
        let complete_model = model(variant, false);
        let normalized_model = model(variant, true);

        assert_eq!(
            complete_model.encode().unwrap(),
            whole,
            "complete independent target model"
        );
        assert_eq!(
            Commit::decode(&whole).unwrap(),
            complete_model,
            "every commit/nested field"
        );
        assert_eq!(normalized_model.encode().unwrap(), normalized);
        assert_eq!(
            Commit::decode(&normalized).unwrap(),
            normalized_model,
            "every normalized/nested field"
        );
        assert_eq!(normalized_model.signature_preimage().unwrap(), normalized);

        let independent_preimage = [PURPOSE, normalized.as_slice()].concat();
        let independent_binding = *blake3::hash(&independent_preimage).as_bytes();
        let published = support::reference(&format!("disclosure-binding-{variant}"));
        assert_eq!(
            independent_binding.as_slice(),
            published,
            "raw relationship, not immutable identity"
        );
        let actual = disclosure_target_binding(&complete_model).unwrap();
        assert_eq!(actual, independent_binding, "owning normalization/binding");
        assert_eq!(
            disclosure_target_binding(&normalized_model).unwrap(),
            actual
        );
        bindings.push(actual);

        // A primitive model comparison proves all retained fields survive, not
        // merely that a same-wire decode/re-encode yields its original input.
        assert_eq!(complete_model.provenance, normalized_model.provenance);
        assert_eq!(
            complete_model.profile_pair.recipe,
            normalized_model.profile_pair.recipe
        );
        assert_eq!(
            complete_model.profile_pair.required_properties,
            normalized_model.profile_pair.required_properties
        );
        assert_eq!(
            complete_model.profile_pair.commit_context,
            normalized_model.profile_pair.commit_context
        );
        assert_eq!(complete_model.packs, normalized_model.packs);
    }
    assert_eq!(
        bindings[0], bindings[1],
        "outer and every typed certificate signature normalize"
    );
    assert_ne!(
        bindings[0], bindings[2],
        "opaque signature-like data remains bound"
    );

    let complete = model("original", false);
    let original_binding = disclosure_target_binding(&complete).unwrap();
    let mut outer_only = complete.clone();
    outer_only.signature = Some([0x99; 64]);
    assert_eq!(
        disclosure_target_binding(&outer_only).unwrap(),
        original_binding
    );
    for index in [0, 2] {
        let mut certificate_only = complete.clone();
        certificate_only
            .profile_pair
            .entry_receipts
            .as_mut()
            .unwrap()[index]
            .disclosure_proof
            .as_mut()
            .unwrap()
            .signature = [0x99; 64];
        assert_eq!(
            disclosure_target_binding(&certificate_only).unwrap(),
            original_binding
        );
    }
    // All other complete metadata participates in the normalization preimage.
    let changes: [fn(&mut Commit); 7] = [
        |commit| commit.tree[0] ^= 1,
        |commit| commit.parents.reverse(),
        |commit| commit.provenance.process.push('x'),
        |commit| commit.timestamp += 1,
        |commit| commit.message.push('x'),
        |commit| commit.profile_pair.lease.as_mut().unwrap().expiry += 1,
        |commit| commit.packs.as_mut().unwrap()[0].pack_id[0] ^= 1,
    ];
    for change in changes {
        let mut changed = complete.clone();
        change(&mut changed);
        assert_ne!(
            disclosure_target_binding(&changed).unwrap(),
            original_binding
        );
    }
}
