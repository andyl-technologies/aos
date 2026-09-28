//! Genuine compiler output, hostile typed forms, and protected cold replay.
//!
//! Synthetic input/prerequisite verifiers are test-only claims. Protected
//! framing and consistency do not establish Root admission or read authority.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::super::candidate_tests::compile_fixture;
use super::super::*;
use super::*;
use crate::journal::JournalLimits;

fn payload(bytes: &[u8], domain: &[u8]) -> String {
    String::from_utf8(bytes[16 + domain.len()..].to_vec()).unwrap()
}

fn frame(domain: &[u8], payload: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload.as_bytes());
    bytes
}

fn duplicate_field(json: &str, field: &str, value: &serde_json::Value) -> String {
    let key = format!("\"{field}\":");
    json.replacen(&key, &format!("{key}{value},{key}"), 1)
}

#[test]
fn canonical_output_nonempty_compiler_profiles_preserve_declared_field_order() {
    for executable in [false, true] {
        let verified = compile_fixture(4096, Some(32), executable);
        let portable = verified.candidate.portable();
        let namespace = portable.namespace_graph_bytes();
        let advisory = portable.advisory_program_bytes();
        assert!(verified.candidate.namespace().rules().len() >= 4);
        assert_eq!(verified.candidate.advisory().decisions().len(), 2);
        validate_namespace(namespace).unwrap();
        validate_advisory(advisory).unwrap();
        validate_diagnostics(&verified.diagnostics).unwrap();

        for (bytes, domain) in [
            (namespace, NAMESPACE_DOMAIN),
            (advisory, ADVISORY_DOMAIN),
            (verified.diagnostics.as_slice(), DIAGNOSTICS_DOMAIN),
        ] {
            let original = payload(bytes, domain);
            let lexical: serde_json::Value = serde_json::from_str(&original).unwrap();
            assert_ne!(serde_json::to_string(&lexical).unwrap(), original);
        }
    }
}

#[test]
fn canonical_output_empty_compiler_profiles_roundtrip_without_synthetic_rules() {
    let verified = compile_fixture(4096, None, false);
    let portable = verified.candidate.portable();

    assert!(verified.candidate.namespace().rules().is_empty());
    assert!(verified.candidate.advisory().decisions().is_empty());
    validate_namespace(portable.namespace_graph_bytes()).expect("empty namespace profile");
    validate_advisory(portable.advisory_program_bytes()).expect("empty advisory profile");
    validate_diagnostics(&verified.diagnostics).expect("complete empty-input diagnostics");
}

#[test]
fn canonical_output_namespace_rejects_hostile_fields_shapes_and_rule_order() {
    let verified = compile_fixture(4096, Some(32), false);
    let bytes = verified.candidate.portable().namespace_graph_bytes();
    let json = payload(bytes, NAMESPACE_DOMAIN);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let handle = &value[1][0]["Source"]["handle"];
    let missing = json.replacen("\"execution_class\":\"DataOnly\",", "", 1);
    assert_ne!(missing, json);
    for hostile in [
        serde_json::to_string(&value).unwrap(),
        duplicate_field(&json, "handle", handle),
        json.replacen("\"Source\":{", "\"Source\":{\"unknown\":true,", 1),
        missing,
        json.replacen("\"Immutable\"", "\"Unregistered\"", 1),
        "{}".to_owned(),
        format!("{json} "),
    ] {
        assert!(validate_namespace(&frame(NAMESPACE_DOMAIN, &hostile)).is_err());
    }

    let (schema, mut rules): (NamespaceGraphSchemaV1, Vec<NamespaceRuleClaims>) =
        decode_exact(bytes, NAMESPACE_DOMAIN).unwrap();
    rules.swap(0, 1);
    let reordered = canonical_bytes(NAMESPACE_DOMAIN, &(schema, &rules)).unwrap();
    assert!(validate_namespace(&reordered).is_err());
    rules.swap(0, 1);
    let NamespaceRuleClaims::Compose(compose) = &mut rules[2] else {
        panic!("composition")
    };
    compose.inputs.reverse();
    assert!(
        validate_namespace(&canonical_bytes(NAMESPACE_DOMAIN, &(schema, rules)).unwrap()).is_err()
    );
}

#[test]
fn canonical_output_executable_claims_never_authenticate_changed_evidence() {
    let verified = compile_fixture(4096, Some(32), true);
    let bytes = verified.candidate.portable().namespace_graph_bytes();
    for change in 0..4 {
        let (schema, mut rules): (NamespaceGraphSchemaV1, Vec<NamespaceRuleClaims>) =
            decode_exact(bytes, NAMESPACE_DOMAIN).unwrap();
        let NamespaceRuleClaims::Source(source) = &mut rules[0] else {
            panic!("source")
        };
        match change {
            0 => source.execution_class = NamespaceExecutionClassV1::DataOnly,
            1 => {
                source.executable_source.as_mut().unwrap().handle = ResourceId::from_bytes([99; 16])
            }
            2 => {
                source.executable_source.as_mut().unwrap().descriptor = ObjectDescriptor::new(
                    MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
                    ObjectDigest::from_bytes([99; 32]),
                    64,
                )
            }
            _ => source.executable_source = None,
        }
        assert!(
            validate_namespace(&canonical_bytes(NAMESPACE_DOMAIN, &(schema, rules)).unwrap())
                .is_err()
        );
    }
}

#[test]
fn canonical_output_advisory_rejects_hostile_fields_outcomes_and_order() {
    let verified = compile_fixture(4096, Some(32), false);
    let bytes = verified.candidate.portable().advisory_program_bytes();
    let json = payload(bytes, ADVISORY_DOMAIN);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let missing = json.replacen("\"status\":\"Active\",", "", 1);
    assert_ne!(missing, json);
    for hostile in [
        serde_json::to_string(&value).unwrap(),
        duplicate_field(&json, "source", &value[0]["action"]["source"]),
        json.replacen("\"action\":{", "\"action\":{\"unknown\":true,", 1),
        missing,
        json.replacen("\"Readahead\"", "\"Unregistered\"", 1),
        "{}".to_owned(),
    ] {
        assert!(validate_advisory(&frame(ADVISORY_DOMAIN, &hostile)).is_err());
    }
    for change in 0..3 {
        let mut claims: Vec<AdvisoryDecisionClaims> = decode_exact(bytes, ADVISORY_DOMAIN).unwrap();
        match change {
            0 => claims.reverse(),
            1 => claims[0].effective_value = None,
            _ => claims[0].effective_value = Some(claims[0].action.bounded_value + 1),
        }
        assert!(validate_advisory(&canonical_bytes(ADVISORY_DOMAIN, &claims).unwrap()).is_err());
    }
}

#[test]
fn canonical_output_diagnostics_rejects_hostile_fields_and_complete_stage_corruption() {
    let verified = compile_fixture(4096, Some(32), false);
    let bytes = &verified.diagnostics;
    let json = payload(bytes, DIAGNOSTICS_DOMAIN);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let missing = json.replacen(&format!("\"commitment\":{},", value["commitment"]), "", 1);
    assert_ne!(missing, json);
    for hostile in [
        serde_json::to_string(&value).unwrap(),
        duplicate_field(&json, "commitment", &value["commitment"]),
        json.replacen('{', "{\"unknown\":true,", 1),
        missing,
        json.replacen("\"Normalize\"", "\"Unregistered\"", 1),
        "{}".to_owned(),
    ] {
        assert!(validate_diagnostics(&frame(DIAGNOSTICS_DOMAIN, &hostile)).is_err());
    }
    for change in 0..5 {
        let mut claims: ExplanationClaims = decode_exact(bytes, DIAGNOSTICS_DOMAIN).unwrap();
        match change {
            0 => {
                claims.stages.pop();
            }
            1 => claims.stages.swap(0, 1),
            2 => claims.stages[0].entries[0].stage = ExplanationStageV1::Lowering,
            3 => {
                let entry: ExplanationEntryClaims =
                    serde_json::from_value(value["stages"][0]["entries"][0].clone()).unwrap();
                claims.stages[0].entries = vec![entry; MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE + 1];
            }
            _ => claims.commitment = ObjectDigest::from_bytes([99; 32]),
        }
        // Repair the ordinary commitment for structural stage attacks: it must
        // not substitute for the complete ordered/bounded stage invariant.
        if change != 4 {
            claims.commitment =
                digest(b"aos.sandbox.policy-explanation.v2", &claims.stages).unwrap();
        }
        assert!(
            validate_diagnostics(&canonical_bytes(DIAGNOSTICS_DOMAIN, &claims).unwrap()).is_err()
        );
    }
}

#[test]
fn canonical_output_full_publication_survives_protected_commit_and_cold_replay() {
    let verified = compile_fixture(4096, Some(32), true);
    let diagnostics = encode_diagnostics_payload(
        verified.project,
        verified.sandbox,
        verified.candidate.commitment().digest(),
        &verified.diagnostics,
    )
    .unwrap();
    let diagnostics_digest = digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics);
    let candidate = encode_candidate_payload(1, &verified, diagnostics_digest).unwrap();
    let current = encode_current_payload(
        verified.project,
        verified.sandbox,
        1,
        verified.candidate.commitment().digest(),
        verified.normalized_input,
        diagnostics_digest,
        &verified.prerequisites,
    );
    let validator = PolicyCompilerReplayValidatorV1 {
        authenticated_prerequisites: BTreeMap::from([(
            verified.prerequisites.digest(),
            verified.prerequisites.clone(),
        )]),
    };
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "compiled-output.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    {
        let envelopes = [
            (PolicyCompilerJournalRecordKindV1::Candidate, &candidate),
            (PolicyCompilerJournalRecordKindV1::Diagnostics, &diagnostics),
        ]
        .into_iter()
        .map(|(kind, body)| {
            policy_reducer_envelope(
                policy_key(
                    kind,
                    verified.project,
                    verified.sandbox,
                    verified.candidate.commitment().digest(),
                )
                .unwrap(),
                1,
                None,
                body,
                &validator,
            )
            .unwrap()
        })
        .chain(std::iter::once(
            policy_reducer_envelope(
                policy_current_key(verified.project, verified.sandbox).unwrap(),
                1,
                None,
                &current,
                &validator,
            )
            .unwrap(),
        ))
        .collect();
        let mut adapter =
            ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
                &mut journal,
                validator.clone(),
            )
            .unwrap();
        let prepared = adapter.plan([90; 16], envelopes).unwrap();
        assert!(matches!(
            adapter.commit(prepared).unwrap(),
            DomainCommitOutcomeV1::Applied(_)
        ));
        validate_policy_projection(&adapter.replay().unwrap(), &validator).unwrap();
    }
    let sequence = journal.snapshot_sequence();
    drop(journal);
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "compiled-output.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    assert_eq!(journal.snapshot_sequence(), sequence);
    let adapter = ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
        &mut journal,
        validator.clone(),
    )
    .unwrap();
    let projection = adapter.replay().unwrap();
    validate_policy_projection(&projection, &validator).unwrap();
    for record in projection.records() {
        let body = policy_body(record, &validator).unwrap();
        match record.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => assert_eq!(body, candidate),
            PolicyCompilerJournalRecordKindV1::Diagnostics => {
                assert_eq!(body, diagnostics);
                assert_eq!(
                    decode_diagnostics_payload(body).unwrap(),
                    verified.diagnostics
                );
            }
            PolicyCompilerJournalRecordKindV1::Current => assert_eq!(body, current),
            _ => panic!("unexpected record"),
        }
    }
}
