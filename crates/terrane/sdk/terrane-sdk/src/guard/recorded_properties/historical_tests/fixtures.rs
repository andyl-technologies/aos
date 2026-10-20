//! Supplies literal ordinary trees and real core Token/signature/history fixtures.

use super::*;
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
    IdentityPrefix, RangeCapability, RefCapability, StoreErrorKind,
};
use terrane_format::identity::Identity;
use terrane_format::refs::{CommitSource, PrincipalKind, ProfilePair, Provenance};
use terrane_format::tree_format::{self, Entry, EntryKind, LeafItem, Node, NodeItems, Property};

/// Stores ordinary immutable input only; no fixture write or authority API exists.
pub(super) struct FixtureStore {
    records: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    capabilities: Capabilities,
}

impl FixtureStore {
    /// Initializes literal stored bytes independently of their later read validation.
    pub(super) fn new(nodes: &[(Digest, Vec<u8>)]) -> Self {
        Self {
            records: nodes
                .iter()
                .map(|(id, bytes)| (id.to_vec(), bytes.clone()))
                .collect(),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}

impl CapabilityReport for FixtureStore {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for FixtureStore {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.records
            .get(identity.digest())
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Ok(identities
            .iter()
            .map(|id| self.records.contains_key(id.digest()))
            .collect())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

/// Initializes all ordinary entry fields independently.
pub(super) fn entry(kind: EntryKind<'_>) -> Entry<'_> {
    Entry {
        kind,
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

/// Builds a physical canonical leaf from independently supplied complete fields.
///
/// # Panics
/// Panics if a literal physical fixture violates canonical TREE rules.
pub(super) fn tree(items: Vec<LeafItem<'_>>, props: Vec<Property<'_>>) -> (Digest, Vec<u8>) {
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(items),
        props: Some(props),
    };
    let wire = tree_format::encode_node(&node, true, MINIMUM).unwrap();
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &wire)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    (root, wire)
}

/// Supplies fixed malformed active-shaped metadata that older contexts preserve inertly.
pub(super) fn props(revision: u64) -> Vec<Property<'static>> {
    let mut props = vec![Property {
        name: "domain",
        value: b"\x66public",
    }];
    if revision <= 2 {
        props.push(Property {
            name: "index-gaps",
            value: &[0],
        });
    }
    if revision == 1 {
        props.push(Property {
            name: "index-roots",
            value: &[0],
        });
    }
    props
}

/// Selects independently supplied preservation registrations.
pub(super) fn later(revision: u64) -> &'static [&'static str] {
    match revision {
        1 => &["index-gaps", "index-roots"],
        2 => &["index-gaps"],
        _ => &[],
    }
}

/// Supplies caller-owned interpretation input, never decoded from Node properties.
///
/// # Panics
/// Panics if the literal registered input ceases to validate.
pub(super) fn selected(view: Digest, root: Digest, revision: u64) -> SelectedReadInterpretation {
    ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([RecordedAssociation::new(
            view,
            root,
            RecordedContext::new(revision, 3, later(revision)).unwrap(),
        )])
        .unwrap(),
    ))
    .select(view, root)
    .unwrap()
}

/// Supplies fixed ordinary defaults while explicit public domains remain literal.
pub(super) fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "local",
    }
}

/// Supplies independent original authority configuration, not verified evidence.
pub(super) fn bootstrap() -> OriginalBootstrapPolicy<'static> {
    OriginalBootstrapPolicy {
        authority: "original-fixture-authority",
        reference: "refs/heads/main",
        writer_epoch: 4,
        acl: &[],
    }
}

/// Supplies genuine issuer verification keys for real signature checks.
pub(super) fn keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer".into(),
        key_id: "issuer-key".into(),
        public_key: auth::public_key_from_secret(&[7; 32]),
        retirement: None,
    }]
}

/// Signs and independently rechecks an ordinary core record before insertion.
///
/// # Panics
/// Panics if literal Token, signature, claims, or checked insertion is invalid.
pub(super) fn retain(
    history: &mut VerifiedHistory,
    root: Digest,
    parents: Vec<Digest>,
    message: &str,
    claims: &[RequestRoot<'_>],
    modern: bool,
) -> VerifiedCommit {
    retain_with_verbs(history, root, parents, message, claims, modern, 20)
}

/// Supplies independently selected Commit/Admin grants to actual core signing.
///
/// # Panics
/// Panics if the literal Token, claims or checked signature insertion is invalid.
pub(super) fn retain_with_verbs(
    history: &mut VerifiedHistory,
    root: Digest,
    parents: Vec<Digest>,
    message: &str,
    claims: &[RequestRoot<'_>],
    modern: bool,
    mask: u8,
) -> VerifiedCommit {
    retain_with_verbs_selected(
        history,
        root,
        parents,
        message,
        claims,
        modern,
        (
            mask,
            terrane_format::properties::selected::Selection::Legacy,
        ),
    )
}

/// Signs and independently verifies a record under its installed interpretation.
///
/// # Panics
/// Panics if the genuine signature or immutable first insertion is invalid.
pub(super) fn retain_with_verbs_selected(
    history: &mut VerifiedHistory,
    root: Digest,
    parents: Vec<Digest>,
    message: &str,
    claims: &[RequestRoot<'_>],
    modern: bool,
    admission: (u8, terrane_format::properties::selected::Selection),
) -> VerifiedCommit {
    let (mask, selection) = admission;
    let token = Token::issue(
        Authority {
            issuer: "issuer".into(),
            key_id: "issuer-key".into(),
            subject: "build/baseline".into(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".into()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![Grant::new("refs/heads/main".into(), Verbs::new(mask).unwrap()).unwrap()],
            workload: Some("workload-identity".into()),
        },
        &[7; 32],
        auth::public_key_from_secret(&[9; 32]),
    )
    .unwrap();
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: claims,
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let commit = Commit {
        tree: root,
        parents,
        provenance: Provenance {
            issuer: "issuer".into(),
            token_id: [3; 16],
            subject: "build/baseline".into(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("workload-identity".into()),
            process: "test/sdk".into(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Built,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: message.into(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: modern.then(|| CommitContext::from_request(&request).unwrap()),
        },
        packs: None,
        signature: None,
    };
    let signed = if modern {
        sign_authored(commit, &[9; 32], &keys(), &request, 4)
    } else {
        sign(commit, &[9; 32], &keys(), &request, 4)
    }
    .unwrap();
    let verified = if modern {
        verify_history(signed.commit(), &keys(), claims, &[("refs/heads/main", 4)])
    } else {
        verify(signed.commit(), &keys(), &request, 4)
    }
    .unwrap();
    assert_eq!(signed.identity(), verified.identity());
    history
        .insert_commit_selected(verified.clone(), selection)
        .unwrap();
    verified
}

/// Assembles a primitive canonical CBOR head independently of context encoders.
pub(super) fn head(major: u8, value: u64) -> Vec<u8> {
    let mut out = vec![major << 5];
    match value {
        0..=23 => out[0] |= value as u8,
        24..=255 => {
            out[0] |= 24;
            out.push(value as u8);
        }
        256..=65535 => {
            out[0] |= 25;
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out[0] |= 26;
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
    out
}

/// Encodes complete literal UTF-8 fields.
pub(super) fn text(value: &str) -> Vec<u8> {
    let mut out = head(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

/// Encodes complete literal byte fields.
pub(super) fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// Encodes independently specified ordered fields.
pub(super) fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, values.len() as u64);
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

/// Checks independently modeled occurrence layers for two routes to one physical root.
///
/// # Panics
/// Panics if canonical ordinary loading or any complete literal layer/domain differs.
pub(super) async fn repeated_domain_override_witnesses() {
    let child_props = vec![
        Property {
            name: "index-gaps",
            value: &[0],
        },
        Property {
            name: "index-roots",
            value: &[0],
        },
    ];
    let child = tree(vec![], child_props.clone());
    let left_domain = text("tenant:left");
    let right_domain = text("tenant:right");
    let left = vec![
        Property {
            name: "domain",
            value: &left_domain,
        },
        Property {
            name: "index-roots",
            value: &[0],
        },
    ];
    let right = vec![Property {
        name: "domain",
        value: &right_domain,
    }];
    let root_props = props(1);
    let root = tree(
        vec![
            graft(b"left", child.0, Some(left.clone())),
            graft(b"right", child.0, Some(right.clone())),
        ],
        root_props.clone(),
    );
    let evidence = TreeEvidence::load_tree(
        &FixtureStore::new(&[root.clone(), child.clone()]),
        root.0,
        &[],
        MINIMUM,
    )
    .await
    .unwrap();
    let input = selected([41; 32], root.0, 1);
    let mut occurrences = evidence.occurrences(MINIMUM).unwrap();
    occurrences.sort_by(|left, right| left.path.cmp(&right.path));
    let complete = occurrences
        .iter()
        .map(|occurrence| {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let policy = input.resolve(&layers, defaults()).unwrap();
            (
                occurrence.root,
                occurrence.path.clone(),
                domain_label(&policy).unwrap().to_owned(),
                occurrence.layers.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        complete,
        vec![
            (
                root.0,
                b"/".to_vec(),
                "public".into(),
                vec![(root_props.clone(), vec![])]
            ),
            (
                child.0,
                b"/left".to_vec(),
                "tenant:left".into(),
                vec![(root_props.clone(), vec![]), (child_props.clone(), left)]
            ),
            (
                child.0,
                b"/right".to_vec(),
                "tenant:right".into(),
                vec![(root_props, vec![]), (child_props, right)]
            ),
        ]
    );
    assert_eq!(
        input
            .historical_roots(&evidence, MINIMUM, defaults())
            .unwrap(),
        vec![
            (b"/".to_vec(), "public".into()),
            (b"/left".to_vec(), "tenant:left".into()),
            (b"/right".to_vec(), "tenant:right".into()),
        ]
    );
    assert_eq!(evidence.nodes[&root.0], root.1);
    assert_eq!(evidence.nodes[&child.0], child.1);
}

/// Checks one vocabulary with different canonical owner defaults for the two evidence inputs.
///
/// # Panics
/// Panics if actual ordinary evidence or its independently modeled private defaults differ.
pub(super) async fn comparison_uses_each_evidence_private_default() {
    let raw = vec![
        Property {
            name: "index-gaps",
            value: &[0],
        },
        Property {
            name: "index-roots",
            value: &[0],
        },
    ];
    let old = tree(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(EntryKind::Symlink { target: b"prior" }),
        }],
        raw.clone(),
    );
    let new = tree(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(EntryKind::Symlink {
                target: b"candidate",
            }),
        }],
        raw.clone(),
    );
    let store = FixtureStore::new(&[old.clone(), new.clone()]);
    let previous = TreeEvidence::load_tree(&store, old.0, &[], MINIMUM)
        .await
        .unwrap();
    let candidate = TreeEvidence::load_tree(&store, new.0, &[], MINIMUM)
        .await
        .unwrap();
    let old_owner = format!(
        "private:terrane-v1:Node:{}",
        old.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let new_owner = format!(
        "private:terrane-v1:Node:{}",
        new.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(previous.default_domain, old_owner);
    assert_eq!(candidate.default_domain, new_owner);
    assert_ne!(old_owner, new_owner);
    let interpretation = selected([42; 32], candidate.root, 1);
    for (evidence, owner, root, wire) in [
        (&candidate, &new_owner, new.0, &new.1),
        (&previous, &old_owner, old.0, &old.1),
    ] {
        let defaults = Defaults {
            private_domain: &evidence.default_domain,
            ..defaults()
        };
        assert_eq!(
            interpretation
                .historical_roots(evidence, MINIMUM, defaults)
                .unwrap(),
            vec![(b"/".to_vec(), owner.clone())]
        );
        let occurrences = evidence.occurrences(MINIMUM).unwrap();
        assert_eq!(occurrences.len(), 1);
        assert_eq!(occurrences[0].root, root);
        assert_eq!(occurrences[0].path, b"/");
        assert_eq!(occurrences[0].layers, vec![(raw.clone(), vec![])]);
        assert_eq!(&evidence.nodes[&root], wire);
    }
    let wrong_defaults = Defaults {
        private_domain: &candidate.default_domain,
        ..defaults()
    };
    assert_ne!(
        interpretation
            .historical_roots(&previous, MINIMUM, wrong_defaults)
            .unwrap(),
        vec![(b"/".to_vec(), old_owner)]
    );
}
