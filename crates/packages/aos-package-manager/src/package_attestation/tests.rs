//! Tests for package event log, quote, and enrollment handling.

use super::*;
use aos_deployment_format::inventory::{InstalledPackageRecord, PackageInventoryDetails};
use aos_registry_format::consumer::{
    AttestationMeta, NativeArtifactMeta, PACKAGE_META_FORMAT, PackageMeta,
};
use tempfile::TempDir;

fn pcr_extension_witness(directory: &Path, exit_status: u8) -> (PathBuf, PathBuf) {
    let bash = std::env::split_paths(&std::env::var_os("PATH").expect("tool PATH"))
        .filter(|directory| directory.starts_with("/nix/store"))
        .map(|directory| directory.join("bash"))
        .find(|path| path.is_file())
        .expect("source-built AOS Bash must be in PATH");
    let bash = fs::canonicalize(bash).expect("resolve source-built Bash");
    assert!(bash.starts_with("/nix/store"));

    let executable = directory.join("pcrextend-witness");
    let capture = directory.join("arguments");
    let quoted_capture = capture.display().to_string().replace('\'', "'\\''");
    fs::write(
        &executable,
        format!(
            "#!{}\nprintf '%s\\n' \"$#\" \"$@\" > '{}'\nexit {}\n",
            bash.display(),
            quoted_capture,
            exit_status
        ),
    )
    .expect("write process witness");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make process witness executable");
    (executable, capture)
}

fn large_generation_event() -> MeasurementEvent {
    let content = format!("sha256:{}", "c".repeat(64));
    let activation_id = format!("sha256:{}", "a".repeat(64));
    let record = serde_json::json!({
        "schema": crate::attestation::native::GENERATION_SCHEMA,
        "sequence": 1,
        "profile_generation": 1,
        "content": content,
        "activation_id": activation_id,
        "quote": "",
        "inputs": {"retained-evidence": "x".repeat(2 * 1024 * 1024)}
    });
    let word =
        String::from_utf8(aos_core::json::canonical_json(&record).expect("canonical generation"))
            .expect("canonical JSON is UTF-8");
    MeasurementEvent {
        event_type: GENERATION_EVENT_TYPE,
        digest: format!("sha256:{}", digest_for_word(&word)),
        word,
        extends_pcr: true,
        pcr_value: None,
        package: None,
        package_count: None,
        generation_id: Some(format!("1:{content}")),
        activation_id: Some(activation_id),
    }
}

#[test]
fn pcr_extension_transports_large_records_as_exact_bounded_digest_arguments() {
    // This is a real process/argv witness, not a simulated TPM proof.
    let tmp = tempfile::tempdir().expect("fixture");
    let (executable, capture) = pcr_extension_witness(tmp.path(), 0);
    let event = large_generation_event();
    assert!(event.word.len() > 2 * 1024 * 1024);
    append_event_log(tmp.path(), std::slice::from_ref(&event)).expect("durable CEL");
    let cel_path = tmp.path().join(AOS_PACKAGE_CEL_REL);
    let before = fs::read(&cel_path).expect("original CEL bytes");

    extend_pcr15(&executable, std::slice::from_ref(&event)).expect("bounded process transport");

    let argument = format!(
        "15:sha256={}",
        hex::encode(Sha256::digest(event.word.as_bytes()))
    );
    assert_eq!(
        fs::read_to_string(capture).unwrap(),
        format!("1\n{argument}\n")
    );
    assert!(argument.len() < 128);
    assert_eq!(fs::read(&cel_path).unwrap(), before);
    let record: OwnedEventLogRecord = serde_json::from_slice(&before).expect("CEL event");
    assert_eq!(record.event, event.word);
    assert_eq!(record.digest, event.digest);

    let recovery =
        generation_measurement_recovery(tmp.path(), &event).expect("recover exact event");
    let mut expected = Sha256::new();
    expected.update([0u8; 32]);
    expected.update(Sha256::digest(event.word.as_bytes()));
    assert_eq!(recovery.before, format!("sha256:{}", "0".repeat(64)));
    assert_eq!(
        recovery.after,
        format!("sha256:{}", hex::encode(expected.finalize()))
    );
    assert_eq!(recovery.replayed, recovery.after);
    assert!(recovery.found && !recovery.has_later_extends);
    let log = String::from_utf8(before).unwrap();
    verify_package_event_log_against_measurement_catalog(&log, &recovery.after, None, &[])
        .expect("unchanged full-record CEL verifies");
}

#[test]
fn pcr_extension_rejects_digest_mismatch_before_starting_the_process() {
    let tmp = tempfile::tempdir().expect("fixture");
    let (executable, capture) = pcr_extension_witness(tmp.path(), 0);
    let mut event = large_generation_event();
    event.digest = format!("sha256:{}", "0".repeat(64));

    let error = extend_pcr15(&executable, &[event]).expect_err("mismatched event");

    assert!(
        error
            .to_string()
            .contains("differs from its exact recorded bytes")
    );
    assert!(
        !capture.exists(),
        "the helper must not run for a mismatched digest"
    );
}

#[test]
fn pcr_extension_failure_preserves_durable_cel_and_recovery_prefix() {
    let tmp = tempfile::tempdir().expect("fixture");
    let (executable, capture) = pcr_extension_witness(tmp.path(), 23);
    let event = large_generation_event();
    append_event_log(tmp.path(), std::slice::from_ref(&event))
        .expect("durable CEL before extension");
    let cel_path = tmp.path().join(AOS_PACKAGE_CEL_REL);
    let before = fs::read(&cel_path).unwrap();
    let prefix = generation_measurement_recovery(tmp.path(), &event).unwrap();

    extend_pcr15(&executable, std::slice::from_ref(&event)).expect_err("failed process witness");

    assert!(capture.exists(), "the real helper process ran and failed");
    assert_eq!(fs::read(&cel_path).unwrap(), before);
    let recovery = generation_measurement_recovery(tmp.path(), &event).unwrap();
    assert_eq!(recovery.before, prefix.before);
    assert_eq!(recovery.after, prefix.after);
    assert!(recovery.found && !recovery.has_later_extends);
    // A TPM-less retry reads the original event rather than appending it.
    assert!(
        !measure_generation_attestation(
            tmp.path(),
            event.generation_id.as_deref().unwrap(),
            event.activation_id.as_deref().unwrap(),
            event.word.as_bytes(),
        )
        .unwrap()
    );
    assert_eq!(fs::read(&cel_path).unwrap(), before);
}

fn installed_fixture(manifest: &[u8]) -> InstalledPackageRecord {
    let document_digest = package_manifest_digest_bytes(manifest);
    let deployment = NativeArtifactMeta {
        store_path: format!("/nix/store/{}-web-deployment", "0".repeat(32)),
        nar_hash: format!("sha256:{}", "a".repeat(64)),
        nar_size: manifest.len() as u64,
        document_sha256: document_digest,
        document_size: manifest.len() as u64,
        references: Vec::new(),
    };
    InstalledPackageRecord {
        store_path: "/nix/store/hash-web-1.0".into(),
        pushed_at: 1,
        pushed_by: "apm".into(),
        expires_at: None,
        is_root: true,
        last_accessed: 1,
        access_count: 0,
        apm: Some(PackageInventoryDetails {
            name: "web".into(),
            version: "1.0".into(),
            explicit: true,
            registry: "test".into(),
            installed_at: "2026-06-18T00:00:00Z".into(),
            held: false,
            source_drv: String::new(),
            source_nar_hash: "sha256:nar".into(),
            deployment: Some(deployment),
            module_documentation: None,
            qualification: None,
            attestation: AttestationMeta {
                root_digest: Some(format!("sha256:{}", "a".repeat(64))),
                ..Default::default()
            },
        }),
    }
}

fn write_quote_identity_fixture(dir: &Path, seed: &str) {
    for name in [
        "ek.pub", "ek.name", "ek.qname", "ak.pub", "ak.name", "ak.qname",
    ] {
        fs::write(dir.join(name), format!("{seed}:{name}")).expect("identity member");
    }
}

fn catalog_meta(root_hash: &str, measurement: &str) -> PackageMeta {
    PackageMeta {
        named_outputs: Default::default(),
        version_requirement: None,
        os_version: None,
        module_dependencies: Vec::new(),
        name: "web".into(),
        version: "1.0".into(),
        description: "Web package".into(),
        homepage: None,
        license: "MIT".into(),
        maintainer: "aos-team".into(),
        platform: "x86_64-linux".into(),
        store_path: "/nix/store/hash-web-1.0".into(),
        nar_hash: "sha256:nar".into(),
        nar_size: 1,
        references: Vec::new(),
        source_drv: String::new(),
        source_nar_hash: "sha256:nar".into(),
        closure_size: 1,
        sysroot: false,
        previous: None,
        images: Vec::new(),
        min_format: Some(PACKAGE_META_FORMAT),
        requires_features: vec!["attestation-v1".into()],
        deployment: None,
        module_documentation: None,
        qualification: None,
        attestation: AttestationMeta {
            root_digest: Some(root_hash.into()),
            root_hash: Some(root_hash.into()),
            root_hash_sig: Some("root.roothash.p7s".into()),
            provenance: None,
            measurement: Some(measurement.into()),
        },
    }
}

fn measured_fixture_log(tmp: &TempDir, manifest: &[u8]) -> (String, String, String) {
    let installed = installed_fixture(manifest);
    let apm = installed.apm.as_ref().expect("apm metadata");
    let root_hash = package_root_digest(apm).expect("package root digest");
    let manifest_digest = package_manifest_digest_bytes(manifest);
    let measurement =
        package_measurement_digest(&apm.name, &apm.version, &root_hash, &manifest_digest);
    append_event_log(
        tmp.path(),
        &measurement_events(tmp.path(), &[installed]).expect("events"),
    )
    .expect("write events");
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    (log, root_hash, measurement)
}

fn legacy_event_log_without_pcr_event_fields(log: &str) -> String {
    let lines = log
        .lines()
        .map(|line| {
            let mut record: serde_json::Value = serde_json::from_str(line).expect("record");
            let object = record.as_object_mut().expect("record object");
            object.remove("sequence_number");
            object.remove("pcr_index");
            object.remove("digests");
            object.remove("event_size");
            serde_json::to_string(&record).expect("legacy record")
        })
        .collect::<Vec<_>>();
    lines.join("\n") + "\n"
}

fn refresh_json_record_pcr_event_fields(record: &mut serde_json::Value) {
    let digest = record["digest"].as_str().expect("digest").to_string();
    let event_size = record["event"].as_str().expect("event").len();
    if record.get("event_size").is_some() {
        record["event_size"] = serde_json::Value::from(event_size);
    }
    if let Some(digests) = record
        .get_mut("digests")
        .and_then(|value| value.as_array_mut())
    {
        assert_eq!(digests.len(), 1);
        digests[0]["algorithm"] = serde_json::Value::String(PCR_BANK.into());
        digests[0]["digest"] = serde_json::Value::String(digest);
    }
}

fn tcg_pcr_event2_log_from_jsonl(log: &str) -> Vec<u8> {
    let mut binary = Vec::new();
    for (index, line) in log.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: OwnedEventLogRecord = serde_json::from_str(line).expect("record");
        validate_event_record_shape(index + 1, &record).expect("record shape");
        let event_type = match record.event_type.as_str() {
            PCR_BASELINE_EVENT_TYPE => TCG_EV_NO_ACTION,
            PACKAGE_SET_EVENT_TYPE | PACKAGE_EVENT_TYPE => TCG_EV_EVENT_TAG,
            other => panic!("unsupported event type {other}"),
        };
        let pcr_index = record.pcr_index.value.expect("pcr_index");
        let digest =
            parse_prefixed_sha256_hex("event digest", &record.digest).expect("event digest");
        let digest = hex::decode(digest).expect("event digest bytes");
        binary.extend_from_slice(&u32::from(pcr_index).to_le_bytes());
        binary.extend_from_slice(&event_type.to_le_bytes());
        binary.extend_from_slice(&1u32.to_le_bytes());
        binary.extend_from_slice(&TCG_ALG_SHA256.to_le_bytes());
        binary.extend_from_slice(&digest);
        binary.extend_from_slice(&(record.event.len() as u32).to_le_bytes());
        binary.extend_from_slice(record.event.as_bytes());
    }
    binary
}

#[test]
fn package_measurement_includes_root_and_manifest_digests() {
    let tmp = TempDir::new().expect("tempdir");
    let installed = installed_fixture(br#"{"package":"web","network":"private"}"#);
    let expected_root_digest = package_root_digest(installed.apm.as_ref().expect("apm metadata"))
        .expect("package root digest");

    let events = measurement_events(tmp.path(), &[installed]).expect("events");

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
    let package = events[1].package.as_ref().expect("package event");
    assert_eq!(package.name, "web");
    assert_eq!(package.root_digest, expected_root_digest);
    assert_eq!(
        package.manifest_digest,
        format!(
            "sha256:{}",
            digest_hex(br#"{"package":"web","network":"private"}"#)
        )
    );
    assert!(events[1].word.contains("name=3:web"));
}

#[test]
fn package_measurement_uses_authenticated_payload_root_digest() {
    let tmp = TempDir::new().expect("tempdir");
    let mut installed = installed_fixture(br#"{"package":"web","network":"private"}"#);
    installed
        .apm
        .as_mut()
        .unwrap()
        .deployment
        .as_mut()
        .unwrap()
        .nar_hash = format!("sha256:{}", "b".repeat(64));
    let expected_root_digest = package_root_digest(installed.apm.as_ref().expect("apm metadata"))
        .expect("package root digest");

    let events = measurement_events(tmp.path(), &[installed]).expect("events");

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
    assert_eq!(events[0].package_count, Some(1));
    let package = events[1].package.as_ref().expect("package event");
    assert_eq!(package.root_digest, expected_root_digest);
    assert_eq!(package.root_digest, format!("sha256:{}", "a".repeat(64)));
}

#[test]
fn native_companion_commitments_change_package_measurements() {
    let baseline = installed_fixture(br#"{"package":"web"}"#);
    let baseline_apm = baseline.apm.as_ref().unwrap();
    let original = package_manifest_digest(baseline_apm).unwrap();
    let companion = NativeArtifactMeta {
        store_path: format!("/nix/store/{}-web-companion", "1".repeat(32)),
        nar_hash: format!("sha256:{}", "c".repeat(64)),
        nar_size: 100,
        document_sha256: format!("sha256:{}", "d".repeat(64)),
        document_size: 50,
        references: Vec::new(),
    };

    let mut with_docs = baseline_apm.clone();
    with_docs.module_documentation = Some(companion.clone());
    let mut with_qualification = baseline_apm.clone();
    with_qualification.qualification = Some(companion);

    let docs_digest = package_manifest_digest(&with_docs).unwrap();
    let qualification_digest = package_manifest_digest(&with_qualification).unwrap();
    assert_ne!(original, docs_digest);
    assert_ne!(original, qualification_digest);
    assert_ne!(docs_digest, qualification_digest);

    with_qualification
        .qualification
        .as_mut()
        .unwrap()
        .document_sha256 = "invalid".into();
    assert!(package_manifest_digest(&with_qualification).is_err());
}

#[test]
fn package_measurement_changes_when_manifest_changes() {
    let tmp = TempDir::new().expect("tempdir");
    let first = installed_fixture(br#"{"package":"web","network":"private"}"#);
    let first_digest = measurement_events(tmp.path(), &[first]).expect("first")[1]
        .digest
        .clone();
    let second = installed_fixture(br#"{"package":"web","network":"host"}"#);
    let second_digest = measurement_events(tmp.path(), &[second]).expect("second")[1]
        .digest
        .clone();

    assert_ne!(first_digest, second_digest);
}

#[test]
fn package_measurement_accepts_matching_registry_measurement() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let mut installed = installed_fixture(manifest);
    let apm = installed.apm.as_mut().expect("apm metadata");
    let root_hash = package_root_digest(apm).expect("package root digest");
    let manifest_digest = package_manifest_digest_bytes(manifest);
    apm.attestation = AttestationMeta {
        root_digest: Some(root_hash.clone()),
        root_hash: Some(root_hash.clone()),
        root_hash_sig: Some("root.roothash.p7s".into()),
        provenance: None,
        measurement: Some(package_measurement_digest(
            &apm.name,
            &apm.version,
            &root_hash,
            &manifest_digest,
        )),
    };

    measurement_events(tmp.path(), &[installed]).expect("matching measurement");
}

#[test]
fn package_measurement_rejects_mismatched_registry_measurement() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let mut installed = installed_fixture(manifest);
    let apm = installed.apm.as_mut().expect("apm metadata");
    apm.attestation = AttestationMeta {
        root_digest: Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ),
        root_hash: Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ),
        root_hash_sig: Some("root.roothash.p7s".into()),
        provenance: None,
        measurement: Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ),
    };

    let err = measurement_events(tmp.path(), &[installed]).unwrap_err();
    assert!(format!("{err:#}").contains("does not match installed metadata"));
}

#[test]
fn package_event_log_verifier_accepts_catalog_match() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let verified =
        verify_package_event_log_against_catalog(&log, &pcr15, &catalog).expect("verify log");

    assert_eq!(verified.pcr15, pcr15);
    assert_eq!(verified.package_count, 1);
    assert_eq!(verified.current_packages.len(), 1);
    assert_eq!(verified.current_packages[0].name, "web");
    assert_eq!(verified.current_packages[0].version, "1.0");
    assert_eq!(verified.current_packages[0].root_digest, root_hash);
    assert_eq!(
        verified.current_packages[0].measurement,
        measurement.trim_start_matches("sha256:")
    );
}

#[test]
fn package_event_log_decoder_accepts_jsonl_bytes() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, _, _) = measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);

    let decoded = decode_package_event_log_bytes(log.as_bytes()).expect("jsonl decode");

    assert_eq!(decoded, log);
}

#[test]
fn package_event_log_decoder_accepts_tcg_pcr_event2_binary_profile() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];
    let binary = tcg_pcr_event2_log_from_jsonl(&log);

    let decoded = decode_package_event_log_bytes(&binary).expect("binary decode");
    let verified = verify_package_event_log_against_catalog(&decoded, &pcr15, &catalog)
        .expect("verify binary event log");

    assert_eq!(decoded, log);
    assert_eq!(verified.pcr15, pcr15);
    assert_eq!(verified.package_count, 1);
}

#[test]
fn package_event_log_decoder_rejects_unsupported_tcg_digest_count() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, _, _) = measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let mut binary = tcg_pcr_event2_log_from_jsonl(&log);
    binary[8..12].copy_from_slice(&2u32.to_le_bytes());

    let err = decode_package_event_log_bytes(&binary).unwrap_err();

    assert!(format!("{err:#}").contains("digest entries"));
}

#[test]
fn package_event_log_verifier_accepts_legacy_record_shape() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let legacy_log = legacy_event_log_without_pcr_event_fields(&log);
    let pcr15 = replay_package_event_log_pcr15(&legacy_log).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let verified = verify_package_event_log_against_catalog(&legacy_log, &pcr15, &catalog)
        .expect("verify legacy log");

    assert_eq!(verified.pcr15, pcr15);
    assert_eq!(verified.package_count, 1);
}

#[test]
fn package_event_log_verifier_replays_from_pcr_baseline() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let installed = installed_fixture(manifest);
    let apm = installed.apm.as_ref().expect("apm metadata");
    let root_hash = package_root_digest(apm).expect("package root digest");
    let manifest_digest = package_manifest_digest_bytes(manifest);
    let measurement =
        package_measurement_digest(&apm.name, &apm.version, &root_hash, &manifest_digest);
    let baseline = format!("sha256:{}", "11".repeat(32));
    let mut events = vec![pcr_baseline_event(&baseline)];
    events.extend(measurement_events(tmp.path(), &[installed]).expect("events"));
    append_event_log(tmp.path(), &events).expect("append log");
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let catalog =
        package_measurement_catalog_from_package_meta(&[catalog_meta(&root_hash, &measurement)])
            .expect("catalog");

    let verified = verify_package_event_log_against_measurement_catalog(
        &log,
        &pcr15,
        Some(&baseline),
        &catalog,
    )
    .expect("verify log");

    assert_eq!(verified.pcr15, pcr15);
    assert_eq!(verified.package_count, 1);
    assert_ne!(
        pcr15,
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn append_event_log_continues_sequence_numbers() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let installed = installed_fixture(manifest);
    let events = measurement_events(tmp.path(), &[installed]).expect("events");

    append_event_log(tmp.path(), &events[..1]).expect("append first event");
    append_event_log(tmp.path(), &events[1..]).expect("append remaining events");

    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    let sequence_numbers = log
        .lines()
        .map(|line| {
            let record: serde_json::Value = serde_json::from_str(line).expect("record json");
            record["sequence_number"].as_u64().expect("sequence number")
        })
        .collect::<Vec<_>>();
    assert_eq!(sequence_numbers, [1, 2]);
}

#[test]
fn generation_attestation_event_is_replayable_and_identity_bound() {
    let tmp = TempDir::new().expect("tempdir");
    let generation_id = format!("1:sha256:{}", "c".repeat(64));
    let record = serde_json::json!({
        "schema": crate::attestation::native::GENERATION_SCHEMA,
        "activation_id": format!("sha256:{}", "a".repeat(64)),
        "sequence": 1,
        "profile_generation": 1,
        "content": format!("sha256:{}", "c".repeat(64)),
        "evaluation_sha256": "sha256:manifest",
        "inputs": {},
        "eval_mode": "pure-eval",
        "quote_status": "quoted"
    });
    let canonical =
        String::from_utf8(aos_core::json::canonical_json(&record).expect("canonical record"))
            .expect("canonical JSON is UTF-8");
    let activation_a = format!("sha256:{}", "a".repeat(64));
    assert!(
        !measure_generation_attestation(
            tmp.path(),
            &generation_id,
            &activation_a,
            canonical.as_bytes(),
        )
        .expect("measure fixture")
    );
    assert!(
        !measure_generation_attestation(
            tmp.path(),
            &generation_id,
            &activation_a,
            canonical.as_bytes(),
        )
        .expect("replay measured fixture idempotently")
    );
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("event log");
    assert_eq!(
        log.lines().count(),
        1,
        "retry must not duplicate the PCR event"
    );
    let recovery_event = MeasurementEvent {
        event_type: GENERATION_EVENT_TYPE,
        digest: format!("sha256:{}", digest_for_word(&canonical)),
        word: canonical.clone(),
        extends_pcr: true,
        pcr_value: None,
        package: None,
        package_count: None,
        generation_id: Some(generation_id.clone()),
        activation_id: Some(activation_a.clone()),
    };
    let recovery = generation_measurement_recovery(tmp.path(), &recovery_event)
        .expect("recover generation measurement");
    assert!(recovery.before.starts_with("sha256:"));
    assert!(recovery.after.starts_with("sha256:"));
    assert!(recovery.replayed.starts_with("sha256:"));
    let digest = Sha256::digest(canonical.as_bytes());
    let mut pcr_hasher = Sha256::new();
    pcr_hasher.update([0_u8; 32]);
    pcr_hasher.update(digest);
    let expected_pcr = hex::encode(pcr_hasher.finalize());
    let verified =
        verify_package_event_log_against_measurement_catalog(&log, &expected_pcr, None, &[])
            .expect("verify generation event");
    assert_eq!(
        verified.generation_attestations.get(&activation_a),
        Some(&format!("sha256:{}", hex::encode(digest)))
    );

    let conflicting = canonical.replace("sha256:manifest", "sha256:other");
    let error = measure_generation_attestation(
        tmp.path(),
        &generation_id,
        &activation_a,
        conflicting.as_bytes(),
    )
    .expect_err("same activation id with different record must fail");
    assert!(error.to_string().contains("disagrees"));

    let activation_b = format!("sha256:{}", "b".repeat(64));
    let second = conflicting.replace(&activation_a, &activation_b);
    assert!(
        !measure_generation_attestation(
            tmp.path(),
            &generation_id,
            &activation_b,
            second.as_bytes(),
        )
        .expect("a new activation of the same generation must append")
    );
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("event log");
    assert_eq!(log.lines().count(), 2);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("replay repeated activation");
    let verified = verify_package_event_log_against_measurement_catalog(&log, &pcr15, None, &[])
        .expect("verify repeated activation events");
    assert_eq!(verified.generation_attestations.len(), 2);
    assert_eq!(
        verified
            .generation_attestation_prefix_digests
            .get(&activation_b)
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn package_measurement_catalog_entries_round_trip_through_json() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let installed = installed_fixture(manifest);
    let apm = installed.apm.as_ref().expect("apm metadata");
    let root_hash = package_root_digest(apm).expect("package root digest");
    let manifest_digest = package_manifest_digest_bytes(manifest);
    let measurement =
        package_measurement_digest(&apm.name, &apm.version, &root_hash, &manifest_digest);

    append_event_log(
        tmp.path(),
        &measurement_events(tmp.path(), &[installed]).expect("events"),
    )
    .expect("write events");
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let json = serde_json::to_string(&vec![PackageMeasurementCatalogEntry {
        name: "web".into(),
        version: "1.0".into(),
        root_digest: root_hash,
        measurement,
    }])
    .expect("serialize catalog");
    let catalog =
        serde_json::from_str::<Vec<PackageMeasurementCatalogEntry>>(&json).expect("catalog");

    let verified =
        verify_package_event_log_against_measurement_catalog(&log, &pcr15, None, &catalog)
            .expect("verify seed catalog");

    assert_eq!(verified.package_count, 1);
}

#[test]
fn canonical_package_measurement_catalog_dedupes_matching_entries() {
    let entry = PackageMeasurementCatalogEntry {
        name: "web".into(),
        version: "1.0".into(),
        root_digest: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .into(),
        measurement: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            .into(),
    };

    let catalog =
        canonical_package_measurement_catalog(&[entry.clone(), entry]).expect("canonical catalog");

    assert_eq!(catalog.len(), 1);
    assert_eq!(
        catalog[0].root_digest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        catalog[0].measurement,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn canonical_package_measurement_catalog_rejects_conflicts() {
    let first = PackageMeasurementCatalogEntry {
        name: "web".into(),
        version: "1.0".into(),
        root_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        measurement: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .into(),
    };
    let second = PackageMeasurementCatalogEntry {
        measurement: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .into(),
        ..first.clone()
    };

    let err = canonical_package_measurement_catalog(&[first, second]).unwrap_err();

    assert!(format!("{err:#}").contains("conflicting golden measurements"));
}

#[test]
fn package_event_log_verifier_rejects_pcr_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let catalog = vec![catalog_meta(&root_hash, &measurement)];
    let wrong_pcr = "0000000000000000000000000000000000000000000000000000000000000000";

    let err = verify_package_event_log_against_catalog(&log, wrong_pcr, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("replayed PCR 15"));
}

#[test]
fn package_event_log_verifier_rejects_digest_list_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package: serde_json::Value = serde_json::from_str(lines[1]).expect("package event");
    package["digests"][0]["digest"] =
        serde_json::Value::String(format!("sha256:{}", "bb".repeat(32)));
    let rewritten_package = serde_json::to_string(&package).expect("package json");
    lines[1] = &rewritten_package;
    let tampered = lines.join("\n") + "\n";
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("digest list does not match"));
}

#[test]
fn package_event_log_verifier_rejects_partial_pcr_event_shape() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
    package_set
        .as_object_mut()
        .expect("set event object")
        .remove("digests");
    let rewritten_set = serde_json::to_string(&package_set).expect("set json");
    lines[0] = &rewritten_set;
    let tampered = lines.join("\n") + "\n";
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("missing digests"));
}

#[test]
fn package_event_log_verifier_rejects_null_pcr_event_field() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
    package_set["digests"] = serde_json::Value::Null;
    let rewritten_set = serde_json::to_string(&package_set).expect("set json");
    lines[0] = &rewritten_set;
    let tampered = lines.join("\n") + "\n";
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("invalid type: null"));
}

#[test]
fn package_event_log_verifier_rejects_sequence_number_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
    package_set["sequence_number"] = serde_json::Value::from(2);
    let rewritten_set = serde_json::to_string(&package_set).expect("set json");
    lines[0] = &rewritten_set;
    let tampered = lines.join("\n") + "\n";
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("sequence_number"));
}

#[test]
fn package_event_log_verifier_rejects_catalog_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, _) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let catalog = vec![catalog_meta(
        &root_hash,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )];

    let err = verify_package_event_log_against_catalog(&log, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("registry golden measurement"));
}

#[test]
fn package_event_log_verifier_rejects_empty_log() {
    let err = verify_package_event_log_against_catalog(
        "",
        "0000000000000000000000000000000000000000000000000000000000000000",
        &[],
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("no package-set event"));
}

#[test]
fn package_event_log_verifier_accepts_empty_package_set_event() {
    let tmp = TempDir::new().expect("tempdir");
    append_event_log(
        tmp.path(),
        &measurement_events(tmp.path(), &[]).expect("events"),
    )
    .expect("write events");
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");

    let verified = verify_package_event_log_against_catalog(&log, &pcr15, &[]).expect("verify log");

    assert_eq!(verified.package_count, 0);
    assert!(verified.current_packages.is_empty());
}

#[test]
fn package_event_log_verifier_reports_latest_package_set() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = br#"{"package":"web","network":"private"}"#;
    let installed = installed_fixture(manifest);
    let root_hash = package_root_digest(installed.apm.as_ref().expect("apm metadata"))
        .expect("package root digest");
    let manifest_digest = package_manifest_digest_bytes(manifest);
    let measurement = package_measurement_digest("web", "1.0", &root_hash, &manifest_digest);
    append_event_log(
        tmp.path(),
        &measurement_events(tmp.path(), &[installed]).expect("events"),
    )
    .expect("write events");
    append_event_log(
        tmp.path(),
        &measurement_events(tmp.path(), &[]).expect("events"),
    )
    .expect("write events");
    let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
    let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let verified =
        verify_package_event_log_against_catalog(&log, &pcr15, &catalog).expect("verify log");

    assert_eq!(verified.package_count, 1);
    assert!(verified.current_packages.is_empty());
}

#[test]
fn package_event_log_verifier_rejects_package_set_digest_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
    let wrong_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let wrong_word = length_prefixed_word(
        "aos-package-set-v1",
        &[
            ("package-count", "1".to_string()),
            ("package-digests", wrong_digest.to_string()),
        ],
    );
    package_set["event"] = serde_json::Value::String(wrong_word.clone());
    package_set["digest"] =
        serde_json::Value::String(format!("sha256:{}", digest_for_word(&wrong_word)));
    refresh_json_record_pcr_event_fields(&mut package_set);
    let rewritten_set = serde_json::to_string(&package_set).expect("set json");
    lines[0] = &rewritten_set;
    let tampered = lines.join("\n") + "\n";
    let pcr15 = replay_package_event_log_pcr15(&tampered).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("package-set digest list"));
}

#[test]
fn package_event_log_verifier_rejects_package_set_count_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    let (log, root_hash, measurement) =
        measured_fixture_log(&tmp, br#"{"package":"web","network":"private"}"#);
    let mut lines = log.lines().collect::<Vec<_>>();
    let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
    package_set["package_count"] = serde_json::Value::from(0);
    let rewritten_set = serde_json::to_string(&package_set).expect("set json");
    lines[0] = &rewritten_set;
    let tampered = lines.join("\n") + "\n";
    let pcr15 = replay_package_event_log_pcr15(&tampered).expect("pcr replay");
    let catalog = vec![catalog_meta(&root_hash, &measurement)];

    let err = verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

    assert!(format!("{err:#}").contains("package_count does not match"));
}

#[test]
fn empty_package_set_still_has_replayable_set_event() {
    let tmp = TempDir::new().expect("tempdir");

    let events = measurement_events(tmp.path(), &[]).expect("events");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
    assert_eq!(events[0].package_count, Some(0));
}

#[test]
fn quote_nonce_parser_normalizes_hex() {
    assert_eq!(parse_quote_nonce_hex("A0b1").expect("nonce"), "a0b1");
}

#[test]
fn quote_nonce_parser_rejects_invalid_hex() {
    let odd = parse_quote_nonce_hex("abc").unwrap_err();
    assert!(format!("{odd:#}").contains("even-length"));

    let non_hex = parse_quote_nonce_hex("zz").unwrap_err();
    assert!(format!("{non_hex:#}").contains("only hex"));
}

#[test]
fn quote_bundle_verifier_rejects_invalid_nonce_before_tools() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let err = verify_attestation_quote_bundle(tmp.path(), "zz", &[]).unwrap_err();

    assert!(format!("{err:#}").contains("only hex"));
}

#[test]
fn quote_bundle_snapshot_copies_members_to_private_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for name in [
        "ak.pub",
        "quote.msg",
        "quote.sig",
        "quote.pcrs",
        "ek.pub",
        "ek.name",
        "ek.qname",
        "ak.name",
        "ak.qname",
    ] {
        fs::write(tmp.path().join(name), name).expect("bundle member");
    }

    let snapshot = private_quote_bundle_snapshot(tmp.path(), true).expect("snapshot");

    assert_ne!(snapshot.parent(), Some(tmp.path()));
    assert_eq!(
        fs::metadata(&snapshot)
            .expect("snapshot metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for name in [
        "ak.pub",
        "quote.msg",
        "quote.sig",
        "quote.pcrs",
        "ek.pub",
        "ek.name",
        "ek.qname",
        "ak.name",
        "ak.qname",
    ] {
        let copied = fs::read_to_string(snapshot.join(name)).expect("copied member");
        assert_eq!(copied, name);
    }
    fs::remove_dir_all(snapshot).expect("cleanup snapshot");
}

#[test]
fn quote_identity_catalog_accepts_matching_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_quote_identity_fixture(tmp.path(), "node-a");
    let identity = quote_identity_digests(tmp.path()).expect("identity");
    let identity_file = tmp.path().join("identity.json");
    fs::write(
        &identity_file,
        serde_json::json!({
            "version": 1,
            "anchors": [{
                "label": "node-a",
                "identity": identity,
            }],
        })
        .to_string(),
    )
    .expect("identity catalog");

    let anchor = verify_quote_bundle_trust(tmp.path(), &[identity_file]).expect("pinned identity");

    assert_eq!(
        anchor,
        Some(PackageQuoteTrustMatch {
            label: "node-a".into(),
            ak_ek_trusted: false,
        })
    );
}

#[test]
fn quote_identity_enrollment_writes_catalog_and_marks_trusted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_quote_identity_fixture(tmp.path(), "node-a");
    let catalog = tmp.path().join("quote-identity.json");
    let evidence = tmp.path().join("credential-activation.txt");
    fs::write(&evidence, "credential activation transcript").expect("evidence");

    let enrolled = enroll_quote_identity(
        tmp.path(),
        &catalog,
        "node-a",
        "credential-activation",
        &evidence,
    )
    .expect("enroll identity");

    assert_eq!(enrolled.label, "node-a");
    assert_eq!(enrolled.method, "credential-activation");
    assert!(enrolled.evidence_sha256.starts_with("sha256:"));

    let trust =
        verify_quote_bundle_trust(tmp.path(), &[catalog.clone()]).expect("enrolled identity");
    assert_eq!(
        trust,
        Some(PackageQuoteTrustMatch {
            label: "node-a".into(),
            ak_ek_trusted: true,
        })
    );
    let duplicate = enroll_quote_identity(
        tmp.path(),
        &catalog,
        "node-a-again",
        "credential-activation",
        &evidence,
    )
    .unwrap_err();
    assert!(format!("{duplicate:#}").contains("already contains this AK/EK identity"));
}

#[test]
fn quote_identity_enrollment_wins_over_duplicate_legacy_pin() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_quote_identity_fixture(tmp.path(), "node-a");
    let identity = quote_identity_digests(tmp.path()).expect("identity");
    let legacy_pin = tmp.path().join("legacy-pin.json");
    fs::write(
        &legacy_pin,
        serde_json::json!({
            "version": 1,
            "anchors": [{
                "label": "legacy-node-a",
                "identity": identity,
            }],
        })
        .to_string(),
    )
    .expect("legacy pin catalog");
    let enrolled_catalog = tmp.path().join("enrolled.json");
    let evidence = tmp.path().join("credential-activation.txt");
    fs::write(&evidence, "credential activation transcript").expect("evidence");
    enroll_quote_identity(
        tmp.path(),
        &enrolled_catalog,
        "enrolled-node-a",
        "credential-activation",
        &evidence,
    )
    .expect("enroll identity");

    let trust = verify_quote_bundle_trust(tmp.path(), &[legacy_pin, enrolled_catalog])
        .expect("enrolled identity");

    assert_eq!(
        trust,
        Some(PackageQuoteTrustMatch {
            label: "enrolled-node-a".into(),
            ak_ek_trusted: true,
        })
    );
}

#[test]
fn quote_identity_enrollment_rejects_unknown_method() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_quote_identity_fixture(tmp.path(), "node-a");
    let evidence = tmp.path().join("evidence.txt");
    fs::write(&evidence, "proof").expect("evidence");

    let err = enroll_quote_identity(
        tmp.path(),
        &tmp.path().join("quote-identity.json"),
        "node-a",
        "web-of-trust",
        &evidence,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("credential-activation"));
}

#[test]
fn quote_identity_catalog_rejects_mismatched_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bundle = tmp.path().join("bundle");
    let enrolled = tmp.path().join("enrolled");
    fs::create_dir_all(&bundle).expect("bundle dir");
    fs::create_dir_all(&enrolled).expect("enrolled dir");
    write_quote_identity_fixture(&bundle, "node-a");
    write_quote_identity_fixture(&enrolled, "node-b");
    let identity = quote_identity_digests(&enrolled).expect("identity");
    let identity_file = tmp.path().join("identity.json");
    fs::write(
        &identity_file,
        serde_json::json!({
            "version": 1,
            "anchors": [{
                "label": "node-b",
                "identity": identity,
            }],
        })
        .to_string(),
    )
    .expect("identity catalog");

    let err = verify_quote_bundle_trust(&bundle, &[identity_file]).unwrap_err();

    assert!(format!("{err:#}").contains("did not match any pinned identity"));
}

#[test]
fn quote_identity_catalog_validates_all_requested_files_before_matching() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_quote_identity_fixture(tmp.path(), "node-a");
    let identity = quote_identity_digests(tmp.path()).expect("identity");
    let matching_file = tmp.path().join("matching.json");
    let malformed_file = tmp.path().join("malformed.json");
    fs::write(
        &matching_file,
        serde_json::json!({
            "version": 1,
            "anchors": [{
                "label": "node-a",
                "identity": identity,
            }],
        })
        .to_string(),
    )
    .expect("matching identity catalog");
    let mut malformed_identity = quote_identity_digests(tmp.path()).expect("identity");
    malformed_identity.ak_public_sha256 = "sha256:not-a-digest".to_string();
    fs::write(
        &malformed_file,
        serde_json::json!({
            "version": 1,
            "anchors": [{
                "label": "bad",
                "identity": malformed_identity,
            }],
        })
        .to_string(),
    )
    .expect("malformed identity catalog");

    let err = verify_quote_bundle_trust(tmp.path(), &[matching_file, malformed_file]).unwrap_err();

    assert!(format!("{err:#}").contains("ak_public_sha256"));
}

#[test]
fn trusted_tpm2_tool_path_requires_absolute_expected_binary() {
    let path = validate_trusted_tpm2_tool_path(
        "AOS_TPM2_QUOTE",
        "tpm2_quote",
        "/nix/store/hash-tpm2-tools-5.7/bin/tpm2_quote",
    )
    .expect("trusted path");
    assert_eq!(
        path,
        PathBuf::from("/nix/store/hash-tpm2-tools-5.7/bin/tpm2_quote")
    );

    let relative =
        validate_trusted_tpm2_tool_path("AOS_TPM2_QUOTE", "tpm2_quote", "bin/tpm2_quote")
            .unwrap_err();
    assert!(format!("{relative:#}").contains("absolute tpm2_quote"));

    let wrong =
        validate_trusted_tpm2_tool_path("AOS_TPM2_QUOTE", "tpm2_quote", "/usr/bin/tpm2_pcrread")
            .unwrap_err();
    assert!(format!("{wrong:#}").contains("absolute tpm2_quote"));
}

#[test]
fn quote_pcr_values_extracts_pcr15() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("quote.pcrs");
    let mut values = Vec::new();
    values.extend([0x07; 32]);
    values.extend([0x0b; 32]);
    values.extend([0x0c; 32]);
    values.extend([0x15; 32]);
    fs::write(&path, values).expect("pcr values");

    let pcr15 = quoted_pcr15_from_values_file(&path).expect("quoted pcr15");

    assert_eq!(pcr15, "15".repeat(32));
}

#[test]
fn quote_pcr_values_rejects_unexpected_size() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("quote.pcrs");
    fs::write(&path, [0u8; 31]).expect("pcr values");

    let err = quoted_pcr15_from_values_file(&path).unwrap_err();

    assert!(format!("{err:#}").contains("expected 128"));
}

#[test]
fn tpm2_pcrread_parser_extracts_pcr15() {
    let output = format!(
        "sha256:\n  7 : 0x{}\n  15 : 0x{}\n",
        "07".repeat(32),
        "ab".repeat(32)
    );

    let pcr15 = parse_tpm2_pcrread_pcr15(&output).expect("pcr15");
    let pcr7 = parse_tpm2_pcrread_value(&output, 7).expect("pcr7");

    assert_eq!(pcr15, format!("sha256:{}", "ab".repeat(32)));
    assert_eq!(pcr7, format!("sha256:{}", "07".repeat(32)));
}

#[test]
fn quote_output_dir_must_be_new_absolute_and_private() {
    let parent = tempfile::tempdir().expect("tempdir");
    let output_dir = parent.path().join("quote");

    create_private_quote_output_dir(&output_dir).expect("private output dir");
    let metadata = fs::symlink_metadata(&output_dir).expect("metadata");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

    let reused = create_private_quote_output_dir(&output_dir).unwrap_err();
    assert!(format!("{reused:#}").contains("must not already exist"));

    let relative = create_private_quote_output_dir(Path::new("relative-quote")).unwrap_err();
    assert!(format!("{relative:#}").contains("absolute path"));
}

#[test]
fn quote_output_dir_rejects_symlink_parent() {
    let parent = tempfile::tempdir().expect("tempdir");
    let real_parent = parent.path().join("real");
    let link_parent = parent.path().join("link");
    fs::create_dir(&real_parent).expect("real parent");
    std::os::unix::fs::symlink(&real_parent, &link_parent).expect("symlink parent");

    let err = create_private_quote_output_dir(&link_parent.join("quote")).unwrap_err();
    assert!(format!("{err:#}").contains("parent must be a real directory"));
}
