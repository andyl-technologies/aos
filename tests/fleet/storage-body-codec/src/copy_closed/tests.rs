//! Controlled shared-MAC tests; no installed key or provider authority.

use super::*;
use aos_hub_core::storage_authority::{
    external_object::copy::{
        control::{CopyClaim, CopyControl, CopyProgress},
        CopySourceObject, ExternalCopyOriginal,
    },
    lease::LeaseInteger,
};
use aos_hub_core::storage_work::{
    StorageCredentialSelector, StorageWorkOperation, StorageWorkPlan,
};
use std::io::Write as _;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
};

fn request(now: i64) -> ExternalCopyRequest {
    let target = |id: &str, generation| {
        serde_json::json!({
            "stable_id":id,"authorization_scope_key":"org:1/registry:2",
            "control_permission":"placement.manage","generation_key":generation,
            "configuration_digest":"",
        })
    };
    let placement = |id, generation, prefix: &str| {
        serde_json::json!({
            "placement_id":id,"binding_id":"1","resource_version":generation,
            "write_spec_version":"3","registry_id":"2","cache_id":null,"prefix":prefix,
        })
    };
    let original: ExternalCopyOriginal = serde_json::from_value(serde_json::json!({
        "version":1,"deployment_id":"deployment",
        "topology":{"operation_id":"retained-operation","operation_kind":"replicate_placement",
            "authorization_scope_key":"org:1/registry:2","control_permission":"placement.manage",
            "created_at":"100","source":target("source", "4"),
            "destination":target("destination", "5")},
        "binding_id":"1","binding_stable_id":"binding","binding_resource_version":"6",
        "snapshot_revision":"a".repeat(64),"source":placement("10","4","source/"),
        "destination":placement("11","5","destination/"),"path":"nar/object.nar",
        "source_object":{"provider_version":"fixture-version","etag":"\"tag\"","bytes":"11"},
        "read_generation":"2","write_generation":"3","binding_write_revision":"8",
        "profile_digest":"b".repeat(64),"part_bytes":"5242880","expected_sha256":null,
    }))
    .unwrap();
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "e".repeat(32),
        deployment_id: "deployment".into(),
        issued_at: now,
        expires_at: now + 30,
        placement_id: 11,
        placement_resource_version: 5,
        binding_id: 1,
        binding_resource_version: 6,
        binding_kind: "s3".into(),
        binding_snapshot_revision: Some("a".repeat(64)),
        credential_references: vec![
            StorageCredentialSelector {
                purpose: "read".into(),
                generation: 2,
            },
            StorageCredentialSelector {
                purpose: "write".into(),
                generation: 3,
            },
        ],
        placement_prefix: "destination/".into(),
        operation: StorageWorkOperation::CopyObject {
            source_placement_id: 10,
            source_placement_resource_version: 4,
            source_prefix: "source/".into(),
            path: "nar/object.nar".into(),
            expected_size: 11,
            expected_etag: "\"tag\"".into(),
        },
    };
    let request = ExternalCopyRequest::new(
        original.clone(),
        CopyClaim {
            operation_resource_version: LeaseInteger::new(2).unwrap(),
            claim_token: "c".repeat(32),
            expires_at: LeaseInteger::new(now + 60).unwrap(),
        },
        plan,
        CopyControl::Advance,
        now,
    )
    .unwrap();
    request
}

#[test]
fn real_authenticators_check_positive_canonical_private_envelopes() {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let request = request(now);
    let literal = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let key = StorageWorkKey::new(literal).unwrap();
    let (request_body, request_signature) = request.sign(&key, "deployment", now).unwrap();
    let original = request.original.fingerprint().unwrap();
    let progress = CopyProgress {
        phase: CopyPhase::Closed,
        completed_parts: 1,
        copied_bytes: LeaseInteger::new(11).unwrap(),
        pending: false,
        destination: Some(CopySourceObject {
            provider_version: Some("controlled-destination".into()),
            etag: "\"closed\"".into(),
            bytes: LeaseInteger::new(11).unwrap(),
            guard_stamp: None,
        }),
        sha256: Some("d".repeat(64)),
    };
    let reply = ExternalCopyReply::new(&request, progress).unwrap();
    let (reply_body, reply_signature) = reply.sign(&key, &request).unwrap();
    authenticate(
        &key,
        &request_signature,
        &request_body,
        &reply_signature,
        &reply_body,
        "deployment",
        &original,
        now,
    )
    .unwrap();

    assert!(authenticate(
        &key,
        &request_signature,
        &request_body,
        &reply_signature,
        &reply_body,
        "foreign",
        &original,
        now
    )
    .is_err());
    assert!(authenticate(
        &key,
        &request_signature,
        &request_body,
        &request_signature,
        &reply_body,
        "deployment",
        &original,
        now
    )
    .is_err());
    assert!(authenticate(
        &key,
        &request_signature,
        &request_body,
        &reply_signature,
        &reply_body,
        "deployment",
        &original,
        now + 31
    )
    .is_err());
    let mut malformed = reply_body.clone();
    malformed.push(b' ');
    assert!(authenticate(
        &key,
        &request_signature,
        &request_body,
        &reply_signature,
        &malformed,
        "deployment",
        &original,
        now
    )
    .is_err());

    let root = std::env::temp_dir().join(format!(
        "aos-copy-closed-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let private = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        BodyFile {
            file: path.to_str().unwrap().into(),
            sha256: files::digest(bytes),
            byte_size: bytes.len().to_string(),
        }
    };
    let selection = Selection {
        version: 1,
        source_digest: "a".repeat(64),
        deployment_id: "deployment".into(),
        expected_original_sha256: original.clone(),
        key: private("key", literal),
        request: private("request", &request_body),
        reply: private("reply", &reply_body),
        request_signature,
        reply_signature,
    };
    let selection_bytes = serde_json::to_vec(&serde_json::json!({
        "version":selection.version,"sourceDigest":&selection.source_digest,
        "deploymentId":&selection.deployment_id,
        "expectedOriginalSha256":&selection.expected_original_sha256,
        "key":{"file":&selection.key.file,"sha256":&selection.key.sha256,"byteSize":&selection.key.byte_size},
        "request":{"file":&selection.request.file,"sha256":&selection.request.sha256,"byteSize":&selection.request.byte_size},
        "reply":{"file":&selection.reply.file,"sha256":&selection.reply.sha256,"byteSize":&selection.reply.byte_size},
        "requestSignature":&selection.request_signature,"replySignature":&selection.reply_signature,
    })).unwrap();
    let observation = inspect(selection).unwrap();
    assert_eq!(observation.scope, "authenticated_copy_closed_envelope_only");
    assert_eq!(observation.original_sha256, original);
    assert_eq!(observation.reply_sha256, files::digest(&reply_body));
    assert!(observation.observed_at >= now);
    if std::env::var("AOS_COPY_CLOSED_RETAIN_CASE").as_deref() == Ok("1") {
        private("selection.json", &selection_bytes);
        private(
            "observation.json",
            &serde_json::to_vec(&observation).unwrap(),
        );
        println!("CONTROLLED_CASE_ROOT={}", root.display());
    } else {
        fs::remove_dir_all(root).unwrap();
    }
}
