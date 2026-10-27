//! Independently constructs complete public commit models and primitive fields.
//!
//! Context is constructed through its public syntax-only request-copy seam.
//! No request is authorized and no fixture signature is checked or produced.

use super::{
    fields,
    support::{Value, a, b, encode, m, n, repeated, set, t, texts},
};
use terrane_format::{
    auth::{Request, RequestRoot, Verb},
    refs::{
        Commit, CommitContext, CommitSource, DisclosureProof, EntryOrigin, EntryReceipt,
        EntrySource, Lease, Locality, PackLocation, PrincipalKind, ProfilePair, Provenance,
    },
};

/// Constructs a public locality model with all three labels.
pub(crate) fn locality() -> Locality {
    Locality {
        region: Some("region".into()),
        zone: Some("zone".into()),
        host: Some("host".into()),
    }
}

fn source() -> EntrySource {
    EntrySource {
        commit: [3; 32],
        root: [4; 32],
        path: b"source\xff".to_vec(),
    }
}

fn proof() -> DisclosureProof {
    DisclosureProof {
        authority_key: "ab".repeat(32),
        source_domain: "private:source".into(),
        observed_at: 42,
        signature: [7; 64],
    }
}

fn receipts() -> Vec<EntryReceipt> {
    let mut receipts: Vec<_> = b"abcdefgh"
        .iter()
        .map(|path| EntryReceipt {
            root: [1; 32],
            path: vec![*path],
            origin: EntryOrigin::Current,
            attributes: None,
            reintroduced_from: None,
            disclosure_proof: None,
        })
        .collect();
    receipts[1].origin = EntryOrigin::Source(source());
    receipts[2].attributes = Some(vec![]);
    receipts[3].origin = EntryOrigin::Source(source());
    receipts[3].attributes = Some(vec![
        ("z".into(), EntryOrigin::Current),
        ("aa".into(), EntryOrigin::Source(source())),
    ]);
    for receipt in &mut receipts[4..] {
        receipt.reintroduced_from = Some(source());
    }
    receipts[5].attributes = Some(vec![]);
    receipts[6].disclosure_proof = Some(proof());
    receipts[7].attributes = Some(vec![("z".into(), EntryOrigin::Source(source()))]);
    receipts[7].disclosure_proof = Some(proof());
    receipts
}

/// Constructs an inert scope model and compares each public context getter.
///
/// # Panics
/// Panics if a syntax-valid fixture scope is rejected or a copied field differs.
fn context() -> CommitContext {
    let locality = locality();
    let roots = [
        RequestRoot {
            path: b"/",
            domain: "public",
        },
        RequestRoot {
            path: b"/aa",
            domain: "private:fixture",
        },
        RequestRoot {
            path: b"/z",
            domain: "public",
        },
    ];
    let request = Request {
        reference: b"refs/heads/_/main",
        verb: Verb::Read,
        roots: &roots,
        now: 0,
        surface: "sdk",
        locality: &locality,
        epochs: &[],
    };
    let context = CommitContext::from_request(&request)
        .unwrap_or_else(|error| panic!("inert context: {error}"));
    assert_eq!(context.reference(), "refs/heads/_/main");
    assert_eq!(context.surface(), "sdk");
    assert_eq!(context.locality(), &locality);
    assert_eq!(context.roots().len(), roots.len());
    for (actual, expected) in context.roots().iter().zip(roots) {
        assert_eq!(actual.path(), expected.path);
        assert_eq!(actual.domain(), expected.domain);
    }
    context
}

fn base(kind: PrincipalKind, source: CommitSource) -> Commit {
    Commit {
        tree: [1; 32],
        parents: vec![],
        provenance: Provenance {
            issuer: "issuer".into(),
            token_id: [2; 16],
            subject: "subject".into(),
            kind,
            workload_identity: None,
            process: "fixture process".into(),
            observed_at: 24,
            writer_epoch: 7,
            source,
            embedded_token: None,
        },
        timestamp: 24,
        message: String::new(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
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

/// Constructs complete public commits separately from the independent CBOR field tables.
///
/// # Panics
/// Panics if the fixed scope fixture is rejected, copied context fields differ,
/// or an independent table no longer supports its required field paths.
pub(crate) fn models() -> Vec<(String, Commit, Value)> {
    let mut models = Vec::new();
    let kinds = [
        PrincipalKind::Human,
        PrincipalKind::Workload,
        PrincipalKind::Service,
    ];
    let sources = [
        CommitSource::Built,
        CommitSource::Uploaded,
        CommitSource::Imported,
        CommitSource::Merged,
        CommitSource::Derived,
        CommitSource::Migrated,
    ];
    for (kind_index, kind) in kinds.into_iter().enumerate() {
        for (source_index, source) in sources.into_iter().enumerate() {
            models.push((
                format!("commit-kind-{}-source-{}", kind_index + 1, source_index + 1),
                base(kind, source),
                fields::commit((kind_index + 1) as u64, (source_index + 1) as u64),
            ));
        }
    }
    for operation in fields::OPERATIONS {
        let mut model = base(PrincipalKind::Workload, CommitSource::Built);
        model.profile_pair.recipe = Some(encode(&fields::recipe(operation)));
        let mut primitive = fields::commit(2, 1);
        set(&mut primitive, &[6, 3], fields::recipe(operation));
        models.push((format!("commit-recipe-{operation}"), model, primitive));
    }

    let mut model = base(PrincipalKind::Workload, CommitSource::Built);
    model.parents = vec![[2; 32], [3; 32]];
    model.provenance.workload_identity = Some("workload".into());
    model.provenance.embedded_token = Some(encode(&fields::token(true)));
    model.message = "complete fixture λ".into();
    model.profile_pair.recipe = Some(encode(&fields::recipe("merge")));
    model.profile_pair.conflicted = Some(true);
    model.profile_pair.lease = Some(Lease {
        owner: "job".into(),
        expiry: 99,
    });
    let properties = texts(vec![
        ("hashes", a(vec![t("sha256"), t("sha512")])),
        ("classify", a(vec![t("elf"), t("shebang")])),
        ("index", a(vec![t("class.magic")])),
        ("strict-attrs", Value::Bool(true)),
    ]);
    model.profile_pair.required_properties = Some(encode(&properties));
    model.profile_pair.entry_receipts = Some(receipts());
    model.profile_pair.commit_context = Some(context());
    model.packs = Some(vec![
        PackLocation {
            pack_id: [16; 16],
            locality: locality(),
        },
        PackLocation {
            pack_id: [17; 16],
            locality: Locality::default(),
        },
    ]);
    model.signature = Some([18; 64]);

    let mut primitive = fields::commit(2, 1);
    set(
        &mut primitive,
        &[2],
        a(vec![repeated(2, 32), repeated(3, 32)]),
    );
    set(&mut primitive, &[3, 5], t("workload"));
    set(&mut primitive, &[3, 10], fields::token(true));
    set(&mut primitive, &[5], t("complete fixture λ"));
    for (key, value) in [
        (3, fields::recipe("merge")),
        (4, Value::Bool(true)),
        (5, m(vec![(1, t("job")), (2, n(99))])),
        (6, properties),
        (7, fields::receipts()),
        (8, fields::context()),
    ] {
        set(&mut primitive, &[6, key], value);
    }
    set(
        &mut primitive,
        &[7],
        a(vec![
            a(vec![repeated(16, 16), fields::locality()]),
            a(vec![repeated(17, 16), m(vec![])]),
        ]),
    );
    set(&mut primitive, &[8], b(&[18; 64]));
    models.push(("commit-complete-signed".into(), model, primitive));

    let mut model = base(PrincipalKind::Workload, CommitSource::Built);
    model.provenance.embedded_token = Some(encode(&fields::token(false)));
    model.profile_pair.conflicted = Some(false);
    model.profile_pair.required_properties = Some(encode(&texts(vec![])));
    model.profile_pair.entry_receipts = Some(vec![]);
    let mut primitive = fields::commit(2, 1);
    set(&mut primitive, &[3, 10], fields::token(false));
    set(&mut primitive, &[6, 4], Value::Bool(false));
    set(&mut primitive, &[6, 6], texts(vec![]));
    set(&mut primitive, &[6, 7], a(vec![]));
    models.push(("commit-explicit-empty-optionals".into(), model, primitive));

    let mut model = base(PrincipalKind::Workload, CommitSource::Built);
    model.parents = vec![[19; 32]; 256];
    let mut blocks = vec![fields::authority(false)];
    blocks.extend(vec![
        m(vec![(5, repeated(10, 32)), (6, repeated(11, 64))]);
        15
    ]);
    model.provenance.embedded_token = Some(encode(&a(blocks.clone())));
    let mut primitive = fields::commit(2, 1);
    set(&mut primitive, &[2], a(vec![repeated(19, 32); 256]));
    set(&mut primitive, &[3, 10], a(blocks));
    models.push(("commit-count-boundaries".into(), model, primitive));
    models
}
