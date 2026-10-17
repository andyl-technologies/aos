//! Differential codec/storage controls and finite original admission cuts.
//!
//! The local counter authority observes real retained ResourceLoan lifetimes;
//! it supplies no host clock, installed quota or measurement entitlement.
//! Actual host cancellation is exercised by the existing SQLite GC controls.

// crucible-lint: allow panic-shortcut -- fixtures require exact canonical and typed first-cause failures.
#![allow(clippy::expect_used)]

use super::*;
use crucible_cas::content_store::DirectoryBlobBackend;
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn leaves(depth: u8, kind: ObjectKind, version: u32, count: u8) -> MerkleNode {
    MerkleNode {
        schema_version: MERKLE_NODE_SCHEMA_VERSION,
        depth,
        entry_count: u64::from(count),
        entries: (0..count)
            .map(|slot| {
                let mut key = [0; 32];
                let index = usize::from(depth) / 2;
                key[index] = if depth.is_multiple_of(2) {
                    slot << 4
                } else {
                    slot
                };
                (
                    slot,
                    MerkleEntry::Leaf {
                        key: CampaignHash::from_bytes(key),
                        value: ContentId::for_bytes(kind, version, &[slot]),
                    },
                )
            })
            .collect(),
    }
}

fn assert_differential(bytes: &[u8]) {
    assert_eq!(decode(bytes), codec::decode::<MerkleNode>(bytes));
}

#[test]
fn borrowed_body_matches_ordinary_codec_for_all_id_kinds_versions_and_slots() {
    let kinds = [
        ObjectKind::CampaignFact,
        ObjectKind::CampaignSnapshot,
        ObjectKind::MerkleNode,
        ObjectKind::Scenario,
        ObjectKind::Configuration,
        ObjectKind::Policy,
        ObjectKind::ExactManifest,
        ObjectKind::RamExtent,
        ObjectKind::RamTree,
        ObjectKind::DiskExtent,
        ObjectKind::DeviceState,
        ObjectKind::Observation,
        ObjectKind::Finding,
        ObjectKind::Projection,
        ObjectKind::Trace,
    ];
    for kind in kinds {
        for version in [0, 1, u32::MAX] {
            for depth in [0, DIGEST_NIBBLES - 1] {
                let node = leaves(depth, kind, version, 16);
                node.validate().expect("valid full leaf node");
                let bytes = codec::encode(&node);
                assert_eq!(decode(&bytes).expect("borrowed body"), node);
                assert_differential(&bytes);
            }
        }
    }
    assert_differential(&codec::encode(&MerkleNode::empty()));

    for mixed in [false, true] {
        let mut node = leaves(0, ObjectKind::RamExtent, 1, 16);
        for (slot, entry) in &mut node.entries {
            if !mixed || !slot.is_multiple_of(2) {
                *entry = MerkleEntry::Node {
                    content_id: ContentId::for_bytes(ObjectKind::MerkleNode, u32::MAX, &[*slot]),
                    entry_count: 1,
                };
            }
        }
        node.validate().expect("valid child node table");
        assert_differential(&codec::encode(&node));
    }
}

#[test]
fn every_body_byte_and_truncation_matches_the_ordinary_decoder() {
    let bytes = codec::encode(&leaves(0, ObjectKind::RamExtent, u32::MAX, 2));

    // Every field participates, including both ID texts and their length
    // prefixes. This is a finite differential corpus, not a parser fuzzer.
    for end in 0..bytes.len() {
        assert_differential(&bytes[..end]);
    }
    for offset in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert_differential(&changed);
    }
}

fn malformed_bodies(node: &MerkleNode) -> Vec<(Vec<u8>, CampaignCodecError)> {
    let bytes = codec::encode(node);
    let header = 4 + 1 + 8 + 8;
    let first = &node.entries[&0];
    let MerkleEntry::Leaf { value, .. } = first else {
        panic!("fixture must begin with a leaf");
    };
    let row = 1 + 1 + 32 + 8 + value.encoded_len();
    assert_eq!(bytes.len(), header + 2 * row);
    let mut bodies = Vec::new();

    let mut unsorted = bytes[..header].to_vec();
    unsorted.extend_from_slice(&bytes[header + row..]);
    unsorted.extend_from_slice(&bytes[header..header + row]);
    bodies.push((unsorted, CampaignCodecError::NonCanonical));

    let mut duplicate = bytes.clone();
    duplicate[header + row] = 0;
    bodies.push((
        duplicate,
        CampaignCodecError::InvalidValue {
            reason: "canonical map contains a duplicate key",
        },
    ));
    let mut unknown = bytes.clone();
    unknown[header + 1] = 9;
    bodies.push((
        unknown,
        CampaignCodecError::UnknownTag {
            kind: "merkle-entry",
            tag: 9,
        },
    ));
    let mut invalid_id = bytes.clone();
    invalid_id[header + 1 + 1 + 32 + 8] = b'R';
    bodies.push((
        invalid_id,
        CampaignCodecError::InvalidValue {
            reason: "content reference is invalid or noncanonical",
        },
    ));
    let mut long_id = bytes.clone();
    long_id[header + 1 + 1 + 32..header + 1 + 1 + 32 + 8].copy_from_slice(&257_u64.to_be_bytes());
    bodies.push((
        long_id,
        CampaignCodecError::LimitExceeded {
            limit: "content-id-text-bytes",
        },
    ));
    let mut invalid_utf8 = bytes.clone();
    invalid_utf8[header + 1 + 1 + 32 + 8] = 255;
    bodies.push((invalid_utf8, CampaignCodecError::InvalidUtf8));
    let mut trailing = bytes.clone();
    trailing.push(0);
    bodies.push((trailing, CampaignCodecError::TrailingBytes));
    bodies.push((
        bytes[..bytes.len() - 1].to_vec(),
        CampaignCodecError::Truncated,
    ));
    bodies
}

#[test]
fn real_stored_malformed_bodies_keep_ordinary_codec_error_priority() {
    let directory = tempfile::tempdir().expect("directory");
    let backend = Arc::new(DirectoryBlobBackend::new("body-corpus", directory.path()));
    let map = MerkleMap::new(backend.clone());
    let node = leaves(0, ObjectKind::RamExtent, 1, 2);
    let children = node.child_references().expect("valid child table");
    let original = map.persist_node(&node).expect("real valid prior object");

    for (body, expected) in malformed_bodies(&node) {
        assert_eq!(codec::decode::<MerkleNode>(&body), Err(expected.clone()));
        assert_eq!(decode(&body), Err(expected.clone()));
        let envelope =
            ObjectEnvelope::for_record(CampaignRecordKind::MerkleNode, children.clone(), body)
                .expect("authenticated malformed body envelope");
        let id = envelope.content_id();
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))
            .expect("real stored malformed body");
        assert!(matches!(
            map.read_node(id, 1),
            Err(CampaignStoreError::Codec(error)) if error == expected
        ));
    }
    assert_eq!(map.read_node(original, 0).expect("prior still valid"), node);
}

#[derive(Debug)]
struct ControlledOriginalRefusal;

impl std::fmt::Display for ControlledOriginalRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("controlled original admission refusal")
    }
}

impl std::error::Error for ControlledOriginalRefusal {}

struct Authority {
    used: Arc<AtomicU64>,
    calls: AtomicUsize,
    charges: Mutex<[u64; 256]>,
    fail_at: usize,
    refusal: DecodeAdmissionError,
}

struct Receipt {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Receipt {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > 256 * 1024 * 1024 {
            return Err(self.refusal.clone());
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
        self.charges.lock().expect("bounded charge witness")[ordinal] = bytes;
        if ordinal == self.fail_at {
            return Err(self.refusal.clone());
        }
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|used| *used <= 256 * 1024 * 1024)
            })
            .map_err(|_| self.refusal.clone())?;
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Receipt {
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

fn admitted_decode(
    body: &[u8],
    expected: &MerkleNode,
    borrowed: bool,
    fail_at: usize,
    refusal: DecodeAdmissionError,
) -> (Result<(), CampaignCodecError>, Vec<u64>) {
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        calls: AtomicUsize::new(0),
        charges: Mutex::new([0; 256]),
        fail_at,
        refusal,
    });
    let budget =
        DecodeBudget::new(authority.clone(), 1024 * 1024).expect("finite original account");
    let scope = budget.enter();
    let result = if borrowed {
        decode(body)
    } else {
        codec::decode(body)
    };
    let result = result.map(|node| {
        // The actual decoded owner closes before its original receipts.
        assert_eq!(&node, expected);
        drop(node);
    });
    drop(scope);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    let count = authority.calls.load(Ordering::SeqCst);
    let charges = authority.charges.lock().expect("charge witness")[..count].to_vec();
    (result, charges)
}

#[test]
fn borrowed_body_preserves_exact_original_charge_sequence_and_first_refusal() {
    let node = leaves(0, ObjectKind::RamExtent, 1, 2);
    let body = codec::encode(&node);
    let refusal = DecodeAdmissionError::new(ControlledOriginalRefusal);
    let ordinary = admitted_decode(&body, &node, false, usize::MAX, refusal.clone());
    let borrowed = admitted_decode(&body, &node, true, usize::MAX, refusal.clone());
    assert_eq!(ordinary, borrowed);
    assert_eq!(ordinary.0, Ok(()));

    // The unchanged Decoder still owns its ID strings. The canonical image
    // admission and final two text admissions form the last three charges.
    let image = ordinary.1.len() - 3;
    let receipt_growth =
        (4 * std::mem::size_of::<crucible_cas::owned_decode::ResourceLoan>()) as u64;
    assert_eq!(ordinary.1[image], body.len() as u64 + receipt_growth);
    for cut in [image, image + 1, image + 2] {
        let (original_result, original_charges) =
            admitted_decode(&body, &node, false, cut, refusal.clone());
        let (borrowed_result, borrowed_charges) =
            admitted_decode(&body, &node, true, cut, refusal.clone());
        assert_eq!(borrowed_result, original_result);
        assert_eq!(
            borrowed_result,
            Err(CampaignCodecError::DecodeAdmission(refusal.clone()))
        );
        assert_eq!(borrowed_charges, original_charges);
        assert_eq!(original_charges.len(), cut + 1);
    }
}

#[test]
fn prior_decode_error_and_original_refusal_keep_their_canonical_decision_order() {
    let node = leaves(0, ObjectKind::RamExtent, 1, 2);
    let bodies = malformed_bodies(&node);
    let body = codec::encode(&node);
    let refusal = DecodeAdmissionError::new(ControlledOriginalRefusal);
    let image = admitted_decode(&body, &node, false, usize::MAX, refusal.clone())
        .1
        .len()
        - 3;

    // The unsorted map is only rejected after canonical emission. A later
    // original ID admission refusal is checked before that byte decision.
    for cut in [image, image + 2] {
        let original = admitted_decode(&bodies[0].0, &node, false, cut, refusal.clone());
        let borrowed = admitted_decode(&bodies[0].0, &node, true, cut, refusal.clone());
        assert_eq!(original, borrowed);
        assert_eq!(
            borrowed.0,
            Err(CampaignCodecError::DecodeAdmission(refusal.clone()))
        );
    }
    // An unknown tag refuses during decode, before the canonical credit cut.
    let original = admitted_decode(&bodies[2].0, &node, false, image, refusal.clone());
    let borrowed = admitted_decode(&bodies[2].0, &node, true, image, refusal);
    assert_eq!(original, borrowed);
    assert_eq!(borrowed.0, Err(bodies[2].1.clone()));
    assert!(borrowed.1.len() <= image);
}
