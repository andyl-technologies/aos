//! Tests for the on-disk format primitives: blob/file-artifact keys, index
//! encodings, and node metadata.

use super::*;
use crate::cache::{
    CacheExprSourceHash, CacheableInputFingerprint, DirEntryInput, FileTypeForInput,
    ImpureInputIdentityHash, ImpureInputKind, InputFingerprintError,
};

mod blob_index;
mod file_artifact_index;
mod node_metadata_index;
mod parse_artifact_index;

fn test_read_file_fingerprint(subject: &[u8], hash_byte: u8) -> CacheableInputFingerprint {
    CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::ReadFile,
        ImpureInputMode::Default,
        subject,
        DurableBlake3Hash::from_bytes([hash_byte; 32]),
    )
    .expect("persisted readFile input builds")
}

fn test_node_trace_payload(subject: &[u8], hash_byte: u8) -> PersistNodeTracePayload {
    let input = test_read_file_fingerprint(subject, hash_byte);
    PersistNodeTracePayload::from_cacheable_inputs([input]).expect("trace payload builds")
}

fn test_node_trace_dependency_keys() -> [PersistNodeMetadataKey; 3] {
    [
        PersistNodeMetadataKey::for_expression(
            CacheExprIdentity::new(
                test_cache_expr_source_hash(b"expression source"),
                crate::compile::IrId::new(7),
            ),
            [
                ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
                    b"left free var",
                )),
                ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
                    b"right free var",
                )),
            ],
        ),
        test_impure_input_node_key(b"first impure input"),
        test_impure_input_node_key(b"second impure input"),
    ]
}

fn test_impure_input_identity_hash(label: &[u8]) -> ImpureInputIdentityHash {
    ImpureInputIdentityHash::from_persisted_hash(DurableBlake3Hash::for_bytes(label))
}

fn test_cache_expr_source_hash(label: &[u8]) -> CacheExprSourceHash {
    CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(label))
}

fn test_impure_input_node_key(label: &[u8]) -> PersistNodeMetadataKey {
    PersistNodeMetadataKey::for_impure_input(test_impure_input_identity_hash(label))
}

#[test]
fn node_trace_payload_uses_stable_wire_bytes() {
    let read_file = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::ReadFile,
        ImpureInputMode::Default,
        b"/a",
        DurableBlake3Hash::from_bytes([0x11; 32]),
    )
    .expect("readFile persisted input builds");
    let hash_file = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::HashFile,
        ImpureInputMode::Default,
        b"/bin",
        DurableBlake3Hash::from_bytes([0x33; 32]),
    )
    .expect("hashFile persisted input builds");
    let path_exists = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::PathExists,
        ImpureInputMode::RequireDirectory,
        b"/dir",
        DurableBlake3Hash::from_bytes([0x22; 32]),
    )
    .expect("pathExists persisted input builds");
    let find_file_candidate = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::PathExists,
        ImpureInputMode::FindFileCandidate,
        b"/miss",
        DurableBlake3Hash::from_bytes([0x44; 32]),
    )
    .expect("findFile candidate persisted input builds");
    let payload = PersistNodeTracePayload::from_cacheable_inputs([
        read_file,
        hash_file,
        path_exists,
        find_file_candidate,
    ])
    .expect("payload builds");

    let encoded = payload.encode().expect("payload encodes");
    let mut expected = Vec::new();
    expected.extend_from_slice(b"AOS-NIX-NTRACE01");
    expected.extend_from_slice(&5u32.to_le_bytes());
    expected.extend_from_slice(&4u64.to_le_bytes());
    expected.push(2);
    expected.push(1);
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(b"/a");
    expected.push(7);
    expected.push(1);
    expected.extend_from_slice(&4u64.to_le_bytes());
    expected.extend_from_slice(&[0x33; 32]);
    expected.extend_from_slice(b"/bin");
    expected.push(5);
    expected.push(2);
    expected.extend_from_slice(&4u64.to_le_bytes());
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(b"/dir");
    expected.push(5);
    expected.push(3);
    expected.extend_from_slice(&5u64.to_le_bytes());
    expected.extend_from_slice(&[0x44; 32]);
    expected.extend_from_slice(b"/miss");
    expected.extend_from_slice(&0u64.to_le_bytes());

    assert_eq!(encoded, expected);
    assert_eq!(encoded[0..16], *b"AOS-NIX-NTRACE01");
    assert_eq!(encoded[28], 2);
    assert_eq!(encoded[29], 1);
    assert_eq!(encoded[72], 7);
    assert_eq!(encoded[73], 1);
    assert_eq!(encoded[118], 5);
    assert_eq!(encoded[119], 2);
    assert_eq!(encoded[164], 5);
    assert_eq!(encoded[165], 3);
    assert_eq!(&encoded[encoded.len() - 8..], 0u64.to_le_bytes().as_slice());
    assert_eq!(payload.memo_read_dependencies(), &[]);
}

#[test]
fn node_trace_payload_decodes_version_one_payloads() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"AOS-NIX-NTRACE01");
    encoded.extend_from_slice(&1u32.to_le_bytes());
    encoded.extend_from_slice(&0u64.to_le_bytes());

    let decoded = PersistNodeTracePayload::decode(&encoded).expect("v1 payload decodes");

    assert_eq!(decoded.inputs(), &[]);
    assert_eq!(decoded.memo_read_dependencies(), &[]);
    assert!(!decoded.is_tombstone());
}

#[test]
fn node_trace_payload_decodes_version_three_payloads_without_dependencies() {
    let payload = test_node_trace_payload(b"/src/default.nix", 0x55);
    let mut encoded = payload.encode().expect("payload encodes");
    encoded[16..20].copy_from_slice(&3u32.to_le_bytes());
    encoded.truncate(encoded.len() - 8);

    let decoded = PersistNodeTracePayload::decode(&encoded).expect("v3 payload decodes");

    assert_eq!(decoded.inputs(), payload.inputs());
    assert_eq!(decoded.memo_read_dependencies(), &[]);
    assert!(!decoded.is_tombstone());
}

#[test]
fn node_trace_payload_tombstone_uses_stable_wire_bytes() {
    let payload = PersistNodeTracePayload::tombstone();

    let encoded = payload.encode().expect("tombstone encodes");
    let decoded = PersistNodeTracePayload::decode(&encoded).expect("tombstone decodes");

    assert_eq!(encoded.len(), PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN);
    assert_eq!(encoded[0..16], *b"AOS-NIX-NTRACE01");
    assert_eq!(&encoded[16..20], 5u32.to_le_bytes().as_slice());
    assert_eq!(&encoded[20..28], u64::MAX.to_le_bytes().as_slice());
    assert!(decoded.is_tombstone());
    assert_eq!(decoded.inputs(), &[]);
    assert_eq!(decoded.memo_read_dependencies(), &[]);

    let mut old_tombstone = encoded;
    old_tombstone[16..20].copy_from_slice(&1u32.to_le_bytes());
    let error =
        PersistNodeTracePayload::decode(&old_tombstone).expect_err("v1 tombstone sentinel errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::InputCountOverflow { count: u64::MAX }
    );

    let dependency = test_impure_input_node_key(b"dependency");
    let tombstone_with_dependency = PersistNodeTracePayload::tombstone()
        .with_memo_read_dependencies([dependency])
        .expect("tombstone dependency list clears");
    assert_eq!(tombstone_with_dependency.memo_read_dependencies(), &[]);
    assert_eq!(
        tombstone_with_dependency
            .encode()
            .expect("tombstone still encodes"),
        payload.encode().expect("tombstone encodes again")
    );
}

#[test]
fn node_trace_payload_round_trips_cacheable_input_records() {
    let trace = vec![
        ImpureInputFingerprint::import(b"/src/default.nix", b"{ pkgs }: pkgs.hello")
            .expect("import input builds"),
        ImpureInputFingerprint::read_file(b"/src/README", b"readme bytes")
            .expect("readFile input builds"),
        ImpureInputFingerprint::hash_file(b"/src/archive.bin", b"binary\0bytes")
            .expect("hashFile input builds"),
        ImpureInputFingerprint::read_dir(
            b"/src",
            [
                DirEntryInput::new(b"default.nix", FileTypeForInput::Regular),
                DirEntryInput::new(b"lib", FileTypeForInput::Directory),
            ],
        )
        .expect("readDir input builds"),
        ImpureInputFingerprint::read_file_type(b"/src/default.nix", FileTypeForInput::Regular)
            .expect("readFileType input builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            b"/src/lib",
            ImpureInputMode::RequireDirectory,
            true,
        )
        .expect("pathExists input builds"),
        ImpureInputFingerprint::path_exists_with_mode(
            b"/src/missing",
            ImpureInputMode::FindFileCandidate,
            false,
        )
        .expect("findFile candidate input builds"),
        ImpureInputFingerprint::get_env(b"HOME", Some(b"/homeless-shelter"))
            .expect("getEnv input builds"),
    ];
    let expected_inputs: Vec<_> = trace
        .iter()
        .map(|input| input.as_cacheable().expect("trace input cacheable").clone())
        .collect();

    let payload = PersistNodeTracePayload::from_impure_trace(&trace).expect("payload builds");
    let encoded = payload.encode().expect("payload encodes");
    let decoded = PersistNodeTracePayload::decode(&encoded).expect("payload decodes");
    let expected_len = PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN
        + expected_inputs
            .iter()
            .map(|input| PERSIST_NODE_TRACE_INPUT_FIXED_LEN + input.identity().subject().len())
            .sum::<usize>();
    let expected_len = expected_len + 8;

    assert_eq!(payload.inputs(), expected_inputs.as_slice());
    assert_eq!(payload.memo_read_dependencies(), &[]);
    assert_eq!(encoded.len(), expected_len);
    assert_eq!(&encoded[..16], PERSIST_NODE_TRACE_PAYLOAD_MAGIC.as_slice());
    assert_eq!(decoded.inputs(), expected_inputs.as_slice());
    assert_eq!(decoded.memo_read_dependencies(), &[]);
    assert!(!decoded.is_tombstone());
    assert_eq!(decoded, payload);
}

#[test]
fn node_trace_payload_round_trips_memo_read_dependencies() {
    let input = test_read_file_fingerprint(b"/src/default.nix", 0xaa);
    let [
        expression_dependency,
        first_input_dependency,
        second_input_dependency,
    ] = test_node_trace_dependency_keys();
    let mut expected_dependencies = vec![
        second_input_dependency,
        expression_dependency,
        first_input_dependency,
        expression_dependency,
    ];
    expected_dependencies.sort_unstable();
    expected_dependencies.dedup();
    let payload = PersistNodeTracePayload::from_cacheable_inputs_and_memo_reads(
        [input.clone()],
        [
            second_input_dependency,
            expression_dependency,
            first_input_dependency,
            expression_dependency,
        ],
    )
    .expect("payload with dependencies builds");

    let encoded = payload.encode().expect("payload encodes");
    let decoded = PersistNodeTracePayload::decode(&encoded).expect("payload decodes");
    let dependency_count_offset =
        encoded.len() - 8 - (expected_dependencies.len() * PERSIST_NODE_TRACE_DEPENDENCY_FIXED_LEN);
    let dependency_bytes_offset = dependency_count_offset + 8;

    assert_eq!(payload.inputs(), &[input]);
    assert_eq!(
        payload.memo_read_dependencies(),
        expected_dependencies.as_slice()
    );
    assert_eq!(
        &encoded[dependency_count_offset..dependency_bytes_offset],
        (expected_dependencies.len() as u64)
            .to_le_bytes()
            .as_slice()
    );
    for (index, dependency) in expected_dependencies.iter().enumerate() {
        let start = dependency_bytes_offset + (index * PERSIST_NODE_TRACE_DEPENDENCY_FIXED_LEN);
        let end = start + PERSIST_NODE_METADATA_INDEX_KEY_LEN;
        assert_eq!(&encoded[start..end], dependency.index_bytes().as_slice());
        assert_eq!(
            &encoded[end..start + PERSIST_NODE_TRACE_DEPENDENCY_FIXED_LEN],
            [0; PERSIST_NODE_METADATA_VALUE_HASH_LEN].as_slice()
        );
    }
    assert_eq!(decoded, payload);
    assert_eq!(
        decoded.memo_read_dependencies(),
        expected_dependencies.as_slice()
    );
}

#[test]
fn node_trace_payload_decodes_memo_read_dependencies_canonically() {
    let [
        expression_dependency,
        first_input_dependency,
        second_input_dependency,
    ] = test_node_trace_dependency_keys();
    let wire_dependencies = [
        second_input_dependency,
        expression_dependency,
        first_input_dependency,
        expression_dependency,
    ];
    let mut expected_dependencies = wire_dependencies.to_vec();
    expected_dependencies.sort_unstable();
    expected_dependencies.dedup();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"AOS-NIX-NTRACE01");
    encoded.extend_from_slice(&4u32.to_le_bytes());
    encoded.extend_from_slice(&0u64.to_le_bytes());
    encoded.extend_from_slice(&(wire_dependencies.len() as u64).to_le_bytes());
    for dependency in wire_dependencies {
        encoded.extend_from_slice(&dependency.index_bytes());
    }

    let decoded = PersistNodeTracePayload::decode(&encoded).expect("payload decodes");
    let recoded = decoded.encode().expect("payload re-encodes");

    assert_eq!(decoded.inputs(), &[]);
    assert_eq!(
        decoded.memo_read_dependencies(),
        expected_dependencies.as_slice()
    );
    assert_ne!(recoded, encoded);
    assert_eq!(
        PersistNodeTracePayload::decode(&recoded)
            .expect("canonical payload decodes")
            .memo_read_dependencies(),
        expected_dependencies.as_slice()
    );
}

#[test]
fn node_trace_payload_rejects_count_without_enough_fixed_records() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"AOS-NIX-NTRACE01");
    encoded.extend_from_slice(&1u32.to_le_bytes());
    encoded.extend_from_slice(&(usize::MAX as u64).to_le_bytes());

    let error = PersistNodeTracePayload::decode(&encoded)
        .expect_err("huge count without bytes errors before allocation");

    assert_eq!(
        error,
        PersistNodeTracePayloadError::InputCountOverflow { count: u64::MAX }
    );
}

#[test]
fn node_trace_payload_rejects_impossible_kind_mode_pairs() {
    let input = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::GetEnv,
        ImpureInputMode::Default,
        b"HOME",
        DurableBlake3Hash::from_bytes([0x33; 32]),
    )
    .expect("getEnv persisted input builds");
    let payload = PersistNodeTracePayload::from_cacheable_inputs([input]).expect("payload builds");
    let mut encoded = payload.encode().expect("payload encodes");
    encoded[PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN + 1] = 2;

    let error = PersistNodeTracePayload::decode(&encoded)
        .expect_err("invalid persisted kind/mode pair errors");

    assert_eq!(
        error,
        PersistNodeTracePayloadError::Input {
            source: InputFingerprintError::InvalidInputMode {
                kind: ImpureInputKind::GetEnv,
                mode: ImpureInputMode::RequireDirectory,
            },
        }
    );
}

#[test]
fn node_trace_payload_rejects_uncacheable_inputs() {
    let trace = [ImpureInputFingerprint::current_time()];

    let error = PersistNodeTracePayload::from_impure_trace(&trace)
        .expect_err("uncacheable trace input errors");

    assert_eq!(
        error,
        PersistNodeTracePayloadError::UncacheableInput {
            input: UncacheableInput::CurrentTime,
        }
    );
}

#[test]
fn node_trace_payload_rejects_invalid_header_bytes() {
    let payload =
        PersistNodeTracePayload::from_cacheable_inputs(Vec::new()).expect("empty payload builds");
    let encoded = payload.encode().expect("empty payload encodes");

    let error =
        PersistNodeTracePayload::decode(&encoded[..8]).expect_err("short payload header errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::ShortPayload {
            expected: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
            actual: 8,
        }
    );

    let mut bad_magic = encoded.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        PersistNodeTracePayload::decode(&bad_magic),
        Err(PersistNodeTracePayloadError::InvalidMagic { .. })
    ));

    let mut bad_version = encoded;
    bad_version[16..20].copy_from_slice(&99u32.to_le_bytes());
    let error =
        PersistNodeTracePayload::decode(&bad_version).expect_err("bad payload version errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::UnsupportedVersion { version: 99 }
    );
}

#[test]
fn node_trace_payload_rejects_malformed_input_records() {
    let input =
        ImpureInputFingerprint::read_file(b"/src/default.nix", b"contents").expect("input builds");
    let payload = PersistNodeTracePayload::from_impure_trace([&input]).expect("payload builds");
    let encoded = payload.encode().expect("payload encodes");

    let mut invalid_kind = encoded.clone();
    invalid_kind[PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN] = 99;
    let error = PersistNodeTracePayload::decode(&invalid_kind).expect_err("bad input kind errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::InvalidInputKindTag { tag: 99 }
    );

    let mut invalid_mode = encoded.clone();
    invalid_mode[PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN + 1] = 99;
    let error = PersistNodeTracePayload::decode(&invalid_mode).expect_err("bad input mode errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::InvalidInputModeTag { tag: 99 }
    );

    let mut future_mode_in_old_payload = encoded.clone();
    future_mode_in_old_payload[16..20].copy_from_slice(&2u32.to_le_bytes());
    future_mode_in_old_payload[PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN + 1] = 3;
    let error = PersistNodeTracePayload::decode(&future_mode_in_old_payload)
        .expect_err("v2 payload cannot decode v3 findFile candidate mode");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::InvalidInputModeTag { tag: 3 }
    );

    let truncated = &encoded[..encoded.len() - 1];
    assert!(matches!(
        PersistNodeTracePayload::decode(truncated),
        Err(PersistNodeTracePayloadError::ShortPayload { .. })
    ));

    let mut trailing = encoded;
    trailing.extend_from_slice(b"trailing");
    let error =
        PersistNodeTracePayload::decode(&trailing).expect_err("trailing payload bytes error");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::TrailingBytes {
            remaining: b"trailing".len(),
        }
    );
}

#[test]
fn node_trace_payload_rejects_malformed_dependency_records() {
    let payload =
        PersistNodeTracePayload::from_cacheable_inputs(Vec::new()).expect("empty payload builds");
    let encoded = payload.encode().expect("empty payload encodes");

    let truncated_dependency_count = &encoded[..encoded.len() - 1];
    let error = PersistNodeTracePayload::decode(truncated_dependency_count)
        .expect_err("short dependency count errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::ShortPayload {
            expected: encoded.len(),
            actual: encoded.len() - 1,
        }
    );

    let mut truncated_dependency_key = Vec::new();
    truncated_dependency_key.extend_from_slice(b"AOS-NIX-NTRACE01");
    truncated_dependency_key.extend_from_slice(&4u32.to_le_bytes());
    truncated_dependency_key.extend_from_slice(&0u64.to_le_bytes());
    truncated_dependency_key.extend_from_slice(&1u64.to_le_bytes());
    truncated_dependency_key.extend_from_slice(&[0; PERSIST_NODE_METADATA_INDEX_KEY_LEN - 1]);
    let error = PersistNodeTracePayload::decode(&truncated_dependency_key)
        .expect_err("short dependency key errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::ShortPayload {
            expected: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN
                + 8
                + PERSIST_NODE_METADATA_INDEX_KEY_LEN,
            actual: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN + 8 + PERSIST_NODE_METADATA_INDEX_KEY_LEN
                - 1,
        }
    );

    let mut invalid_dependency_key = Vec::new();
    invalid_dependency_key.extend_from_slice(b"AOS-NIX-NTRACE01");
    invalid_dependency_key.extend_from_slice(&4u32.to_le_bytes());
    invalid_dependency_key.extend_from_slice(&0u64.to_le_bytes());
    invalid_dependency_key.extend_from_slice(&1u64.to_le_bytes());
    invalid_dependency_key.extend_from_slice(&[0xff; PERSIST_NODE_METADATA_INDEX_KEY_LEN]);
    let error = PersistNodeTracePayload::decode(&invalid_dependency_key)
        .expect_err("invalid dependency key errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::Dependency {
            source: PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 0xff },
        }
    );

    let dependency_key = test_impure_input_node_key(b"dependency");
    let mut invalid_dependency_value_tag = Vec::new();
    invalid_dependency_value_tag.extend_from_slice(b"AOS-NIX-NTRACE01");
    invalid_dependency_value_tag.extend_from_slice(&5u32.to_le_bytes());
    invalid_dependency_value_tag.extend_from_slice(&0u64.to_le_bytes());
    invalid_dependency_value_tag.extend_from_slice(&1u64.to_le_bytes());
    invalid_dependency_value_tag.extend_from_slice(&dependency_key.index_bytes());
    invalid_dependency_value_tag.push(99);
    invalid_dependency_value_tag.extend_from_slice(&[0; PERSIST_NODE_METADATA_VALUE_HASH_LEN - 1]);
    let error = PersistNodeTracePayload::decode(&invalid_dependency_value_tag)
        .expect_err("invalid dependency value-hash tag errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::InvalidDependencyValueHashTag { tag: 99 }
    );

    let mut nonzero_dependency_value_padding = Vec::new();
    nonzero_dependency_value_padding.extend_from_slice(b"AOS-NIX-NTRACE01");
    nonzero_dependency_value_padding.extend_from_slice(&5u32.to_le_bytes());
    nonzero_dependency_value_padding.extend_from_slice(&0u64.to_le_bytes());
    nonzero_dependency_value_padding.extend_from_slice(&1u64.to_le_bytes());
    nonzero_dependency_value_padding.extend_from_slice(&dependency_key.index_bytes());
    nonzero_dependency_value_padding.push(0);
    nonzero_dependency_value_padding.push(1);
    nonzero_dependency_value_padding
        .extend_from_slice(&[0; PERSIST_NODE_METADATA_VALUE_HASH_LEN - 2]);
    let error = PersistNodeTracePayload::decode(&nonzero_dependency_value_padding)
        .expect_err("non-zero dependency value-hash padding errors");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::NonZeroDependencyValueHashPadding
    );

    let mut trailing = encoded;
    trailing.extend_from_slice(b"x");
    let error =
        PersistNodeTracePayload::decode(&trailing).expect_err("trailing dependency bytes error");
    assert_eq!(
        error,
        PersistNodeTracePayloadError::TrailingBytes { remaining: 1 }
    );
}

#[test]
fn node_trace_log_appends_and_finds_latest_matching_entry() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let log = PersistNodeTraceLog::open(&log_path).expect("trace log opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let first_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));
    let latest_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"latest value"));
    let first = test_node_trace_payload(b"/src/first", 1);
    let other = test_node_trace_payload(b"/src/other", 2);
    let latest = test_node_trace_payload(b"/src/latest", 3);

    assert_eq!(log.path(), log_path.as_path());
    assert_eq!(log.lookup(key).expect("empty lookup succeeds"), None);

    log.append_trace(key, first_value_hash, &first)
        .expect("first trace appends");
    log.append_entry(PersistNodeTraceLogEntry::new(
        other_key,
        other_value_hash,
        other.clone(),
    ))
    .expect("other trace appends");
    log.append_trace(key, latest_value_hash, &latest)
        .expect("latest trace appends");

    let first_payload = first.encode().expect("first payload encodes");
    let other_payload = other.encode().expect("other payload encodes");
    let latest_payload = latest.encode().expect("latest payload encodes");
    let log_bytes = fs::read(log.path()).expect("trace log reads");
    let mut expected_first_record = Vec::new();
    expected_first_record.extend_from_slice(&key.index_bytes());
    expected_first_record.extend_from_slice(&first_value_hash.as_durable_hash().as_bytes());
    expected_first_record.extend_from_slice(&(first_payload.len() as u64).to_le_bytes());
    expected_first_record.extend_from_slice(&first_payload);

    assert!(log_bytes.starts_with(&expected_first_record));
    assert_eq!(
        log.lookup(key).expect("key lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            latest_value_hash,
            latest.clone()
        ))
    );
    assert_eq!(
        log.lookup(other_key).expect("other lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            other_key,
            other_value_hash,
            other.clone()
        ))
    );
    assert_eq!(
        fs::metadata(log.path()).expect("trace log metadata").len(),
        (PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN * 3) as u64
            + first_payload.len() as u64
            + other_payload.len() as u64
            + latest_payload.len() as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_lists_latest_entries_in_key_order() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let log = PersistNodeTraceLog::open(&log_path).expect("trace log opens");
    let first_key = test_impure_input_node_key(b"a");
    let second_key = test_impure_input_node_key(b"b");
    let first_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let stale_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale value"));
    let latest_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"latest value"));
    let first_payload = test_node_trace_payload(b"first", 1);
    let stale_payload = test_node_trace_payload(b"stale", 2);
    let latest_payload = PersistNodeTracePayload::tombstone();

    assert_eq!(
        log.latest_entries().expect("empty latest entries"),
        Vec::new()
    );

    log.append_entry(PersistNodeTraceLogEntry::new(
        second_key,
        stale_value_hash,
        stale_payload,
    ))
    .expect("stale entry appends");
    log.append_entry(PersistNodeTraceLogEntry::new(
        first_key,
        first_value_hash,
        first_payload.clone(),
    ))
    .expect("first entry appends");
    log.append_entry(PersistNodeTraceLogEntry::new(
        second_key,
        latest_value_hash,
        latest_payload.clone(),
    ))
    .expect("latest entry appends");

    let entries = log.latest_entries().expect("latest entries load");
    assert_eq!(entries.len(), 2);
    assert!(entries.windows(2).all(|pair| pair[0].key() < pair[1].key()));
    assert!(entries.contains(&PersistNodeTraceLogEntry::new(
        first_key,
        first_value_hash,
        first_payload
    )));
    assert!(entries.contains(&PersistNodeTraceLogEntry::new(
        second_key,
        latest_value_hash,
        latest_payload
    )));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_compacts_to_latest_entries() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let log = PersistNodeTraceLog::open(&log_path).expect("trace log opens");
    let first_key = test_impure_input_node_key(b"a");
    let second_key = test_impure_input_node_key(b"b");
    let first_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let stale_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale value"));
    let latest_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"latest value"));
    let first_payload = test_node_trace_payload(b"first", 1);
    let stale_payload = test_node_trace_payload(b"stale", 2);
    let latest_payload = PersistNodeTracePayload::tombstone();

    log.append_entry(PersistNodeTraceLogEntry::new(
        second_key,
        stale_value_hash,
        stale_payload,
    ))
    .expect("stale entry appends");
    log.append_entry(PersistNodeTraceLogEntry::new(
        first_key,
        first_value_hash,
        first_payload.clone(),
    ))
    .expect("first entry appends");
    log.append_entry(PersistNodeTraceLogEntry::new(
        second_key,
        latest_value_hash,
        latest_payload.clone(),
    ))
    .expect("latest entry appends");
    let before_len = fs::metadata(log.path())
        .expect("trace log metadata before compaction")
        .len();

    assert_eq!(log.compact_latest_entries().expect("log compacts"), 2);
    assert!(
        fs::metadata(log.path())
            .expect("trace log metadata after compaction")
            .len()
            < before_len
    );
    assert_eq!(
        log.lookup(first_key).expect("first lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            first_key,
            first_value_hash,
            first_payload
        ))
    );
    assert_eq!(
        log.lookup(second_key).expect("second lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            second_key,
            latest_value_hash,
            latest_payload
        ))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_compaction_truncates_stale_temp_file() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let log = PersistNodeTraceLog::open(&log_path).expect("trace log opens");
    let key = test_impure_input_node_key(b"input");
    let stale_temp_key = test_impure_input_node_key(b"stale temp");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let stale_temp_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale temp value"));
    let payload = test_node_trace_payload(b"input", 1);
    let stale_temp_payload = test_node_trace_payload(b"stale temp", 2);

    log.append_entry(PersistNodeTraceLogEntry::new(
        key,
        value_hash,
        payload.clone(),
    ))
    .expect("entry appends");
    let rewrite_id = 987_654_321;
    let stale_temp_path =
        log_path.with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
    let stale_temp_log = PersistNodeTraceLog::open(&stale_temp_path).expect("stale temp opens");
    stale_temp_log
        .append_entry(PersistNodeTraceLogEntry::new(
            stale_temp_key,
            stale_temp_value_hash,
            stale_temp_payload,
        ))
        .expect("stale temp entry appends");

    assert_eq!(
        log.compact_latest_entries_with_rewrite_id_for_tests(rewrite_id)
            .expect("log compacts"),
        1
    );
    assert_eq!(
        log.lookup(key).expect("key lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );
    assert_eq!(
        log.lookup(stale_temp_key)
            .expect("stale temp key lookup succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_open_rejects_truncated_record_header() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    fs::create_dir_all(log_path.parent().expect("log parent")).expect("parent creates");
    fs::write(&log_path, b"partial").expect("partial log writes");

    let error = PersistNodeTraceLog::open(&log_path).expect_err("truncated log errors");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::ShortRecordHeader {
                expected,
                actual,
            },
            ..
        } if expected == PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64 && actual == 7
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_open_rejects_truncated_record_payload() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&key.index_bytes());
    encoded.extend_from_slice(&value_hash.as_durable_hash().as_bytes());
    encoded.extend_from_slice(&999u64.to_le_bytes());
    encoded.extend_from_slice(b"short");
    fs::create_dir_all(log_path.parent().expect("log parent")).expect("parent creates");
    fs::write(&log_path, encoded).expect("truncated log writes");

    let error = PersistNodeTraceLog::open(&log_path).expect_err("truncated payload errors");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::ShortRecordPayload {
                expected,
                actual,
            },
            ..
        } if expected == PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64 + 999
            && actual == PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64 + 5
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_trace_log_open_rejects_malformed_record_payload() {
    let root = temp_root();
    let log_path = root.join("nodes").join("traces.log");
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = b"not-a-node-trace-payload-with-enough-bytes";
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&key.index_bytes());
    encoded.extend_from_slice(&value_hash.as_durable_hash().as_bytes());
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(payload);
    fs::create_dir_all(log_path.parent().expect("log parent")).expect("parent creates");
    fs::write(&log_path, encoded).expect("malformed log writes");

    let error = PersistNodeTraceLog::open(&log_path).expect_err("malformed payload errors");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::Payload { .. },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}
