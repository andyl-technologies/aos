//! Builds finite source and I/P/G expectations directly from canonical CBOR.
//!
//! No helper evaluates or rebuilds an index. Relationships are predicted from
//! literal file paths, inline values and independently addressed source objects.

use super::Required as _;
use std::collections::{BTreeMap, BTreeSet};

use terrane_format::cbor;
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};

/// Uses the actual fixture's separately admitted Chunk plaintext.
pub(super) const BODY: &[u8] = b"historical immutable body";
/// Selects the registered cdc-1m minimum independently of carrier bytes.
pub(super) const MINIMUM: u64 = 262144;

/// Retains an independently assembled graph and exact expected auxiliary reads.
#[derive(Clone)]
pub(super) struct Graph {
    /// All immutable namespace and auxiliary Node encodings.
    pub(super) nodes: BTreeMap<Digest, Vec<u8>>,
    /// Original completed owning namespace root.
    pub(super) owner: Digest,
    /// Actual detached primary Node identity.
    pub(super) primary: Digest,
    /// Missing-object Node identity.
    pub(super) gap: Digest,
    /// Present route Node identity.
    pub(super) present: Digest,
    /// Missing route Node identity.
    pub(super) missing: Digest,
    /// Independently addressed inline file content.
    pub(super) object: Digest,
    /// Full local source rows, retained for isolated valid-baseline mutations.
    pub(super) rows: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional shared source root in repeated-graft fixtures.
    pub(super) child: Option<Digest>,
    /// Every reached namespace Node, including shared children only once.
    pub(super) namespace: BTreeSet<Digest>,
}

impl Graph {
    /// Predicts one present and one missing occurrence of the same real object.
    ///
    /// # Panics
    /// Panics if the registered immutable Chunk identity cannot be calculated.
    pub(super) fn small() -> Self {
        let object = TERRANE_V1
            .calculate(IdentityKind::Chunk, BODY)
            .required()
            .terrane_v1_digest()
            .required();
        let mut nodes = BTreeMap::new();
        let present = insert(&mut nodes, leaf(&[(b"a".to_vec(), terminal(object))], None));
        let missing = insert(&mut nodes, leaf(&[(b"b".to_vec(), terminal(object))], None));
        let gap = insert(
            &mut nodes,
            leaf(&[(object.to_vec(), forward(object, missing))], None),
        );
        let mut key = vec![1];
        key.extend_from_slice(&object);
        let primary = insert(
            &mut nodes,
            leaf(
                &[(key, forward(object, present))],
                Some(properties(vec![(
                    "index-gaps",
                    wrapper(text(&hex(gap)), false),
                )])),
            ),
        );
        let rows = vec![
            (b"a".to_vec(), file(object, Some(1))),
            (b"b".to_vec(), file(object, None)),
        ];
        let owner = insert(
            &mut nodes,
            leaf(&rows, Some(owner_properties(Some(primary), true))),
        );
        Self {
            nodes,
            owner,
            primary,
            gap,
            present,
            missing,
            object,
            rows,
            child: None,
            namespace: BTreeSet::from([owner]),
        }
    }

    /// Predicts two graft occurrences sharing bytes but retaining different policy.
    ///
    /// # Panics
    /// Panics if the valid small baseline cannot be constructed.
    pub(super) fn repeated() -> Self {
        let mut result = Self::small();
        let child = result.owner;
        let mut present_rows = vec![
            (b"g".to_vec(), forward(result.object, result.present)),
            (b"h".to_vec(), forward(result.object, result.present)),
        ];
        let present = insert(&mut result.nodes, leaf(&present_rows, None));
        present_rows = vec![
            (b"g".to_vec(), forward(result.object, result.missing)),
            (b"h".to_vec(), forward(result.object, result.missing)),
        ];
        let missing = insert(&mut result.nodes, leaf(&present_rows, None));
        let gap = insert(
            &mut result.nodes,
            leaf(
                &[(result.object.to_vec(), forward(result.object, missing))],
                None,
            ),
        );
        let mut key = vec![1];
        key.extend_from_slice(&result.object);
        let primary = insert(
            &mut result.nodes,
            leaf(
                &[(key, forward(result.object, present))],
                Some(properties(vec![(
                    "index-gaps",
                    wrapper(text(&hex(gap)), false),
                )])),
            ),
        );
        result.rows = vec![
            (
                b"g".to_vec(),
                graft(child, Some(properties(vec![("index", names(&["uid"]))]))),
            ),
            (
                b"h".to_vec(),
                graft(child, Some(properties(vec![("index", names(&[]))]))),
            ),
        ];
        result.owner = insert(
            &mut result.nodes,
            leaf(&result.rows, Some(owner_properties(Some(primary), true))),
        );
        result.primary = primary;
        result.present = present;
        result.missing = missing;
        result.gap = gap;
        result.child = Some(child);
        result.namespace = BTreeSet::from([child, result.owner]);
        result
    }

    /// Rebinds a changed owner to an independently specified primary or no binding.
    pub(super) fn rebind(&mut self, binding: Option<Digest>, required: bool) {
        self.owner = insert(
            &mut self.nodes,
            leaf(&self.rows, Some(owner_properties(binding, required))),
        );
        self.namespace = self.child.into_iter().chain([self.owner]).collect();
    }
}

/// Calculates the raw Node domain preimage independently of index construction.
pub(super) fn hash(bytes: &[u8]) -> Digest {
    let mut preimage = b"terrane-node-v1\0".to_vec();
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}

/// Retains independently encoded bytes under their Node digest.
pub(super) fn insert(nodes: &mut BTreeMap<Digest, Vec<u8>>, bytes: Vec<u8>) -> Digest {
    let identity = hash(&bytes);
    nodes.insert(identity, bytes);
    identity
}

/// Encodes an actual inline Chunk file with an optional canonical uid.
pub(super) fn file(object: Digest, value: Option<u64>) -> Vec<u8> {
    let mut out = vec![if value.is_some() { 0xa5 } else { 0xa4 }, 1, 1, 2];
    cbor::write_uint(&mut out, 0o644);
    out.push(3);
    cbor::write_uint(&mut out, BODY.len() as u64);
    out.extend_from_slice(&[4, 0x82, 0]);
    cbor::write_bytes(&mut out, &object);
    if let Some(value) = value {
        out.extend_from_slice(&[9, 0xa1]);
        cbor::write_text(&mut out, "uid");
        cbor::write_uint(&mut out, value);
    }
    out
}

/// Encodes an inert revision-1 pointer on an ordinary file for context tests.
pub(super) fn file_with_pointer(object: Digest, pointer: Digest) -> Vec<u8> {
    let mut out = file(object, None);
    out[0] = 0xa5;
    out.extend_from_slice(&[9, 0xa1]);
    cbor::write_text(&mut out, "index.occurrences");
    cbor::write_bytes(&mut out, &pointer);
    out
}

/// Encodes one actual namespace graft with optional occurrence-local overrides.
pub(super) fn graft(root: Digest, overrides: Option<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![if overrides.is_some() { 0xa3 } else { 0xa2 }, 1, 4, 6];
    cbor::write_bytes(&mut out, &root);
    if let Some(overrides) = overrides {
        out.push(7);
        out.extend(overrides);
    }
    out
}

/// Encodes a closed terminal retaining the actual file identity.
pub(super) fn terminal(object: Digest) -> Vec<u8> {
    let mut out = vec![0xa2, 1, 7, 14, 0x81];
    cbor::write_bytes(&mut out, &object);
    out
}

/// Encodes a closed forwarding row retaining both object and exact continuation.
pub(super) fn forward(object: Digest, route: Digest) -> Vec<u8> {
    let mut out = vec![0xa3, 1, 7, 9, 0xa1];
    cbor::write_text(&mut out, "index.occurrences");
    cbor::write_bytes(&mut out, &route);
    out.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut out, &object);
    out
}

/// Encodes a canonical physical leaf with independently compressed local keys.
pub(super) fn leaf(rows: &[(Vec<u8>, Vec<u8>)], props: Option<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![if props.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut out, rows.len());
    let mut prior: &[u8] = &[];
    for (key, entry) in rows {
        let shared = key.iter().zip(prior).take_while(|(a, b)| a == b).count();
        out.push(0x83);
        cbor::write_bytes(&mut out, &key[shared..]);
        cbor::write_uint(&mut out, shared as u64);
        out.extend_from_slice(entry);
        prior = key;
    }
    if let Some(props) = props {
        out.push(3);
        out.extend(props);
    }
    out
}

/// Encodes canonical text-key maps using the registered length/byte ordering.
pub(super) fn properties(mut values: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    values.sort_by(|(a, _), (b, _)| (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes())));
    let mut out = Vec::new();
    cbor::write_map(&mut out, values.len());
    for (name, value) in values {
        cbor::write_text(&mut out, name);
        out.extend(value);
    }
    out
}

/// Encodes the exact noninherited owner-local wrapper and real policy inputs.
pub(super) fn owner_properties(binding: Option<Digest>, required: bool) -> Vec<u8> {
    let mut values = vec![
        (
            "acl",
            vec![
                0x81, 0x82, 0x66, b'w', b'r', b'i', b't', b'e', b'r', 0x18, 0x1f,
            ],
        ),
        ("domain", text("public")),
        ("index", names(if required { &["uid"] } else { &[] })),
    ];
    if let Some(binding) = binding {
        values.push((
            "index-roots",
            wrapper(properties(vec![("uid", text(&hex(binding)))]), false),
        ));
    }
    properties(values)
}

/// Encodes an exact property wrapper with an explicitly selected inherit flag.
pub(super) fn wrapper(value: Vec<u8>, inherit: bool) -> Vec<u8> {
    let mut out = vec![0xa2, 0x65, b'v', b'a', b'l', b'u', b'e'];
    out.extend(value);
    out.extend_from_slice(&[
        0x67,
        b'i',
        b'n',
        b'h',
        b'e',
        b'r',
        b'i',
        b't',
        if inherit { 0xf5 } else { 0xf4 },
    ]);
    out
}

/// Encodes a canonical inline name list.
pub(super) fn names(values: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_array(&mut out, values.len());
    for value in values {
        cbor::write_text(&mut out, value);
    }
    out
}

/// Encodes one canonical text value.
pub(super) fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_text(&mut out, value);
    out
}

/// Returns the registered lowercase Node digest spelling.
pub(super) fn hex(digest: Digest) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
