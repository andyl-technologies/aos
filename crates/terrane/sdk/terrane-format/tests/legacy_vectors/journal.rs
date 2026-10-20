//! Reconstructs ordinary local-v1 incarnation and physical-intent wire models.
//!
//! Nonces, descriptor identities, leases and elapsed durations are untrusted
//! data. Independent primitive writers reproduce invalid inputs; none of these
//! tests select history, acquire a lease or propose physical effects.

use super::bucket::pack_id;
use super::support::{assert_published_digest, digest, hexadecimal, wire};
use terrane_format::{
    cbor,
    gc::{
        ArtifactBinding, ArtifactVersion, CreationJournal, DeleteAuthorization, DeleteOperation,
        DeletePhase, GcLease, JournalState,
    },
    identity::{Digest, IdentityKind, TERRANE_V1},
};

const PACK_KEY: &str = "objects/pack/00/000102030405060708090a0b0c0d0e0f.pack";
const INDEX_KEY: &str = "objects/pack/00/000102030405060708090a0b0c0d0e0f.idx";
const TRASH_KEY: &str = "trash/7/000102030405060708090a0b0c0d0e0f";
const OPERATION_KEY: &str = "gc/7/delete/000102030405060708090a0b0c0d0e0f/404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

fn authorization_digest() -> Digest {
    digest("a5802a8ed186b0f68a32c9277ac30f3a39b67941a548d96f2047c082903f6e8c")
}

fn uint_field(bytes: &mut Vec<u8>, key: u64, value: u64) {
    cbor::write_uint(bytes, key);
    cbor::write_uint(bytes, value);
}

fn tombstone_bytes() -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 5);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, &pack_id());
    for (key, value) in [(2, 7), (3, 1_760_000_002), (4, 2), (5, 2)] {
        uint_field(&mut bytes, key, value);
    }
    bytes
}

/// Writes the fixed binary table from its field model, independently of TRIX encoders.
fn index_witness() -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend_from_slice(b"TRPK");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&pack_id());
    bytes.extend_from_slice(b"TRIX");
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    for (hash, offset, stored, plaintext) in [
        (
            digest("9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0"),
            25_u64,
            16_u32,
            15_u32,
        ),
        (
            digest("b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0"),
            24,
            1,
            0,
        ),
    ] {
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&stored.to_le_bytes());
        bytes.extend_from_slice(&plaintext.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
    }
    assert_eq!(bytes.len(), 148);
    assert_eq!(
        TERRANE_V1
            .calculate(IdentityKind::Index, &bytes)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
        digest("7c0fa339c9072256d2f6537294a4ca55086523971d5c68cf27794d8196f9dc3a")
    );
    bytes
}

fn artifacts() -> [ArtifactVersion; 3] {
    [
        ArtifactVersion {
            key: PACK_KEY.into(),
            nonce: [0x11; 32],
            binding: ArtifactBinding::Pack {
                digest: digest("a832ebdf8d5c85eaa46b6323220a0ff42449c384d05b7dd65b00b807aecc5f44"),
                size: 181,
            },
            file_identity: hexadecimal("7061636bf4f55840"),
        },
        ArtifactVersion {
            key: INDEX_KEY.into(),
            nonce: [0x22; 32],
            binding: ArtifactBinding::Index {
                digest: digest("7c0fa339c9072256d2f6537294a4ca55086523971d5c68cf27794d8196f9dc3a"),
                size: 148,
            },
            file_identity: hexadecimal("696e646578f4f55840"),
        },
        ArtifactVersion {
            key: TRASH_KEY.into(),
            nonce: [0x33; 32],
            binding: ArtifactBinding::Trash(tombstone_bytes()),
            file_identity: hexadecimal("7472617368f4f55840"),
        },
    ]
}

fn write_binding(bytes: &mut Vec<u8>, binding: &ArtifactBinding) {
    match binding {
        ArtifactBinding::Pack { digest, size } | ArtifactBinding::Index { digest, size } => {
            cbor::write_array(bytes, 3);
            cbor::write_uint(
                bytes,
                u64::from(matches!(binding, ArtifactBinding::Index { .. })),
            );
            cbor::write_bytes(bytes, digest);
            cbor::write_uint(bytes, *size);
        }
        ArtifactBinding::Trash(tombstone) => {
            cbor::write_array(bytes, 2);
            cbor::write_uint(bytes, 2);
            cbor::write_bytes(bytes, tombstone);
        }
    }
}

/// Projects the invalid identity cases without calling CreationJournal::encode.
fn identity_wire(identity: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 6);
    uint_field(&mut bytes, 0, 1);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_text(&mut bytes, PACK_KEY);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_bytes(&mut bytes, &[0x11; 32]);
    uint_field(&mut bytes, 3, 1);
    cbor::write_uint(&mut bytes, 4);
    write_binding(
        &mut bytes,
        &ArtifactBinding::Pack {
            digest: [0; 32],
            size: 181,
        },
    );
    cbor::write_uint(&mut bytes, 5);
    cbor::write_bytes(&mut bytes, identity);
    bytes
}

/// Compares complete creation journal phase models and structural negatives.
///
/// # Panics
///
/// Panics if a published wire or decoded model differs, or an invalid wire is accepted.
pub(super) fn creations() {
    for (heading, state) in [
        ("### Creation journal pending", JournalState::Pending),
        (
            "### Creation journal invalidated",
            JournalState::Invalidated,
        ),
    ] {
        let model = CreationJournal {
            key: PACK_KEY.into(),
            nonce: [0x11; 32],
            state,
        };
        let published = wire(heading, 0);
        assert_eq!(model.encode().unwrap(), published, "{heading}");
        assert_eq!(
            CreationJournal::decode(&published).unwrap(),
            model,
            "{heading}"
        );
    }

    for (kind, artifact) in ["pack", "index", "trash"].into_iter().zip(artifacts()) {
        for owned in [false, true] {
            let state = if owned {
                JournalState::DeleteOwned {
                    binding: artifact.binding.clone(),
                    file_identity: artifact.file_identity.clone(),
                    operation_key: OPERATION_KEY.into(),
                    authorization: authorization_digest(),
                }
            } else {
                JournalState::Committed {
                    binding: artifact.binding.clone(),
                    file_identity: artifact.file_identity.clone(),
                }
            };
            let model = CreationJournal {
                key: artifact.key.clone(),
                nonce: artifact.nonce,
                state,
            };
            let phase = if owned { "owned" } else { "committed" };
            let heading = format!("### Creation journal {kind} {phase}");
            let published = wire(&heading, 0);
            assert_eq!(model.encode().unwrap(), published, "{heading}");
            assert_eq!(
                CreationJournal::decode(&published).unwrap(),
                model,
                "{heading}"
            );
        }
    }

    for (name, count) in [("min", 1), ("max", 128)] {
        let model = CreationJournal {
            key: PACK_KEY.into(),
            nonce: [0x11; 32],
            state: JournalState::Committed {
                binding: ArtifactBinding::Pack {
                    digest: [0; 32],
                    size: 181,
                },
                file_identity: vec![0x55; count],
            },
        };
        let heading = format!("### Creation journal identity {name}");
        let published = wire(&heading, 0);
        assert_eq!(model.encode().unwrap(), published, "{heading}");
        assert_eq!(
            CreationJournal::decode(&published).unwrap(),
            model,
            "{heading}"
        );
    }

    for (name, count) in [("empty", 0), ("long", 129)] {
        let negative = identity_wire(&vec![0x55; count]);
        assert_eq!(
            negative,
            wire(&format!("### Creation journal identity {name}"), 0)
        );
        assert!(CreationJournal::decode(&negative).is_err(), "{name}");
    }
}

fn authorization() -> DeleteAuthorization {
    DeleteAuthorization {
        nonce: core::array::from_fn(|index| 0x40 + u8::try_from(index).unwrap()),
        pack_id: pack_id(),
        cycle: 7,
        epoch: 2,
        original_lease: GcLease {
            holder: "collector".into(),
            epoch: 3,
            expiry: 1_760_003_600,
        },
        deletion_seconds: 60,
        artifacts: artifacts(),
        index_witness: index_witness(),
        elapsed_ns: 60_000_000_000,
    }
}

fn write_lease(bytes: &mut Vec<u8>, lease: &GcLease) {
    cbor::write_map(bytes, 3);
    cbor::write_uint(bytes, 1);
    cbor::write_text(bytes, &lease.holder);
    uint_field(bytes, 2, lease.epoch);
    uint_field(bytes, 3, lease.expiry);
}

/// Writes nested ordinary authorization fields without its rejecting encoder.
fn write_authorization(bytes: &mut Vec<u8>, model: &DeleteAuthorization) {
    cbor::write_map(bytes, 7);
    cbor::write_uint(bytes, 0);
    cbor::write_bytes(bytes, &model.nonce);
    cbor::write_uint(bytes, 1);
    cbor::write_array(bytes, 3);
    cbor::write_bytes(bytes, &model.pack_id);
    cbor::write_uint(bytes, model.cycle);
    cbor::write_uint(bytes, model.epoch);
    cbor::write_uint(bytes, 2);
    write_lease(bytes, &model.original_lease);
    uint_field(bytes, 3, model.deletion_seconds);
    cbor::write_uint(bytes, 4);
    cbor::write_array(bytes, 3);
    for artifact in &model.artifacts {
        cbor::write_array(bytes, 4);
        cbor::write_text(bytes, &artifact.key);
        cbor::write_bytes(bytes, &artifact.nonce);
        write_binding(bytes, &artifact.binding);
        cbor::write_bytes(bytes, &artifact.file_identity);
    }
    cbor::write_uint(bytes, 5);
    cbor::write_bytes(bytes, &model.index_witness);
    uint_field(bytes, 6, model.elapsed_ns);
}

/// Compares ordinary retirement records and the published raw authorization digest.
///
/// # Panics
///
/// Panics if a wire, model, raw digest or publication control differs, or an
/// independently constructed invalid operation is accepted.
pub(super) fn operations() {
    let model = authorization();
    let published = wire("### Delete authorization", 0);
    let mut independent = vec![];
    write_authorization(&mut independent, &model);
    assert_eq!(independent, published);
    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(model.digest().unwrap(), authorization_digest());
    assert_eq!(blake3::hash(&published).as_bytes(), &authorization_digest());
    // This raw hash binds inert fields; it grants no deletion authority.
    assert_published_digest(
        "## Layout and physical-intent record vectors",
        "its 640 canonical bytes, without an immutable-content domain prefix:\n\n```text\n",
        "\n```\n",
        *blake3::hash(&independent).as_bytes(),
    );

    for (heading, phase, revision) in [
        ("### Delete operation", DeletePhase::Authorized, 0),
        ("### Delete operation cancelled", DeletePhase::Cancelled, 6),
    ] {
        let operation = DeleteOperation {
            authorization: model.clone(),
            phase,
            revision,
            current_lease: GcLease {
                holder: "recovery".into(),
                epoch: 4,
                expiry: 1_760_007_200,
            },
        };
        let published = wire(heading, 0);
        assert_eq!(operation.encode().unwrap(), published, "{heading}");
        assert_eq!(
            DeleteOperation::decode(&published, OPERATION_KEY).unwrap(),
            operation,
            "{heading}"
        );
    }

    let mut negative = vec![];
    cbor::write_map(&mut negative, 5);
    uint_field(&mut negative, 0, 1);
    cbor::write_uint(&mut negative, 1);
    write_authorization(&mut negative, &model);
    uint_field(&mut negative, 2, 0);
    uint_field(&mut negative, 3, 0);
    cbor::write_uint(&mut negative, 4);
    negative.push(0xf6);
    assert_eq!(negative, wire("### Delete operation null lease", 0));
    assert!(DeleteOperation::decode(&negative, OPERATION_KEY).is_err());
}
