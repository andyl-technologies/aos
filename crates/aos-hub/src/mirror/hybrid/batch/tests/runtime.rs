//! Actual Native controller, Rust Worker, ordinary SDK facade and SQL commit.
//!
//! This gate requires an explicitly supplied source-built do-e2e artifact and
//! tools. It preserves its directory on failure and supplies no hosted evidence.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::PathBuf, process::Command};

use super::*;

struct Runner {
    child: std::process::Child,
    node: String,
}

fn nar_field(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
    output.resize(output.len() + (8 - bytes.len() % 8) % 8, 0);
}

impl Drop for Runner {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|status| status.is_none()) {
            // Graceful launcher termination also SIGKILLs its owned workerd.
            // Killing only Node would orphan the durable process on test panic.
            let _ = Command::new(&self.node)
                .args(["-e", "process.kill(Number(process.argv[1]), 'SIGTERM')"])
                .arg(self.child.id().to_string())
                .status();
        }
        let _ = self.child.wait();
    }
}

#[tokio::test]
#[ignore = "requires the source-built current Worker artifact and workerd"]
async fn actual_worker_none_zstd_publication_and_restart() {
    connected_runtime(false).await;
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "requires the source-built current Worker artifact and workerd"]
async fn actual_worker_managed_gc_and_unknown_restart() {
    connected_runtime(true).await;
}

async fn connected_runtime(gc_only: bool) {
    let root = PathBuf::from(std::env::var("AOS_MIRROR_RUNTIME_EVIDENCE").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let source = std::env::var("AOS_MIRROR_RUNTIME_SOURCE_SHA256").unwrap();
    assert!(valid_direct_digest(&source));
    let (temporary, db, registry, _, _, peer) = fixture().await;
    peer.abort();
    let database_path = temporary.keep().join("controller.db");
    std::fs::write(
        root.join("native-sql-location.txt"),
        database_path.to_string_lossy().as_bytes(),
    )
    .unwrap();

    let clock = DirectClockPolicy {
        version: 1,
        mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: WireInteger::new(1),
    };
    let mut profile = DirectManagedR2Profile {
        deployment_id: DEPLOYMENT.into(),
        account_id: "0123456789abcdef0123456789abcdef".into(),
        bucket_name: "controlled-test-bucket".into(),
        bucket_namespace: "controlled-test-namespace".into(),
        credential_id: "controlled-test-material".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "controlled-test-material/v1".into(),
        credential_fingerprint: String::new(),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: clock.commitment().unwrap(),
        clock_uncertainty_seconds: WireInteger::new(1),
    };
    let access = "controlled-test-access";
    let secret = "controlled-test-secret";
    profile.credential_fingerprint = profile
        .fingerprint_with_credentials(access, secret)
        .unwrap();
    let policy = DirectPrivateStagePolicyRef {
        policy_id: "controlled-test-policy".into(),
        policy_digest: direct_private_stage_policy_commitment(
            "controlled-test-policy",
            &profile.bucket_namespace,
        )
        .unwrap(),
        namespace: profile.bucket_namespace.clone(),
    };
    let guard_key = "mirror-independent-guard-fixture-key";
    let vars = BTreeMap::from([
        ("HUB_DEPLOYMENT_ID", DEPLOYMENT.to_owned()),
        (
            "HUB_STORAGE_WORK_KEY",
            String::from_utf8(PRODUCER_KEY.to_vec()).unwrap(),
        ),
        (
            "HUB_MIRROR_CANDIDATE_KEY",
            String::from_utf8(CANDIDATE_KEY.to_vec()).unwrap(),
        ),
        ("HUB_MIRROR_GUARD_KEY", guard_key.to_owned()),
        ("HUB_MIRROR_CANDIDATE_SOURCE_SHA256", source.clone()),
        (
            "HUB_MIRROR_CANDIDATE_SCRIPT_VERSION",
            format!("emulated-{source}"),
        ),
        ("HUB_TOPOLOGY", "hybrid".into()),
        ("HUB_DIRECT_UPLOAD_CLOCK_MODE", "bounded_utc".into()),
        ("HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS", "1".into()),
        (
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION",
            clock.commitment().unwrap(),
        ),
        ("HUB_DIRECT_UPLOAD_MANAGED_R2", "true".into()),
        ("HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID", access.into()),
        ("HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY", secret.into()),
        (
            "HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID",
            profile.account_id.clone(),
        ),
        (
            "HUB_DIRECT_UPLOAD_R2_BUCKET_NAME",
            profile.bucket_name.clone(),
        ),
        (
            "HUB_DIRECT_UPLOAD_R2_BUCKET_NAMESPACE",
            profile.bucket_namespace.clone(),
        ),
        (
            "HUB_DIRECT_UPLOAD_R2_CREDENTIAL_ID",
            profile.credential_id.clone(),
        ),
        ("HUB_DIRECT_UPLOAD_R2_CREDENTIAL_GENERATION", "1".into()),
        (
            "HUB_DIRECT_UPLOAD_R2_SECRET_VERSION_REF",
            profile.secret_version_ref.clone(),
        ),
        ("HUB_DIRECT_UPLOAD_R2_CHECKSUM", "md5".into()),
        (
            "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_ID",
            policy.policy_id.clone(),
        ),
        (
            "HUB_DIRECT_UPLOAD_R2_PRIVATE_POLICY_DIGEST",
            policy.policy_digest.clone(),
        ),
    ]);
    let metadata = b"mirror-test";
    let payload_size = 8 * 1024 * 1024 + 777;
    let mut prefix = Vec::new();
    for field in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
    ] {
        nar_field(field, &mut prefix);
    }
    prefix.extend_from_slice(&(payload_size as u64).to_le_bytes());
    let mut suffix = vec![0; (8 - payload_size % 8) % 8];
    nar_field(b")", &mut suffix);
    let mut plain = prefix.clone();
    plain.resize(plain.len() + payload_size, 42);
    plain.extend_from_slice(&suffix);
    let compressed = zstd::stream::encode_all(plain.as_slice(), 3).unwrap();
    let plain_hash = hex::encode(Sha256::digest(&plain));
    let compressed_hash = hex::encode(Sha256::digest(&compressed));
    let metadata_hash = hex::encode(Sha256::digest(metadata));
    let mut sources = serde_json::json!({
        "/registry/web/metadata.json": {
            "size": metadata.len(), "sha256": metadata_hash,
            "base64": base64::engine::general_purpose::STANDARD.encode(metadata)
        },
        "/registry/web/metadata-two.json": {
            "size": metadata.len(), "sha256": metadata_hash,
            "base64": base64::engine::general_purpose::STANDARD.encode(metadata)
        },
        "/registry/nar/none.nar": {
            "size": plain.len(), "sha256": plain_hash, "fill": 42,
            "prefix": base64::engine::general_purpose::STANDARD.encode(prefix),
            "suffix": base64::engine::general_purpose::STANDARD.encode(suffix)
        },
        "/registry/nar/zstd.nar.zst": {
            "size": compressed.len(), "sha256": compressed_hash,
            "base64": base64::engine::general_purpose::STANDARD.encode(&compressed)
        }
    });
    sources
        .as_object_mut()
        .unwrap()
        .extend(super::runtime_membership::sources());
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worker_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let worker_port = worker_listener.local_addr().unwrap().port();
    drop(worker_listener);
    let manifest = serde_json::json!({
        "sourceDigest":source, "vars":vars, "sources":sources, "workerPort":worker_port,
        "dist":std::env::var("AOS_MIRROR_RUNTIME_DIST").unwrap(),
        "workerd":std::env::var("AOS_MIRROR_RUNTIME_WORKERD").unwrap(),
        "tlsCertificate":fixtures.join("hub-hybrid-fleet-server.crt"),
        "tlsKey":fixtures.join("hub-hybrid-fleet-server.key"),
        "providerFixture":repository.join("pkgs/tools/aos-hub-mirror-r2-fixture.mjs")
    });
    std::fs::write(
        root.join("runtime.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let log = std::fs::File::create(root.join("launcher.log")).unwrap();
    let node = std::env::var("AOS_MIRROR_RUNTIME_NODE").unwrap();
    let mut runner = Runner {
        child: Command::new(&node)
            .arg(repository.join("pkgs/tools/aos-hub-mirror-runtime-e2e.mjs"))
            .arg(&root)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        node,
    };
    for _ in 0..300 {
        assert!(
            runner.child.try_wait().unwrap().is_none(),
            "runner exited; evidence retained"
        );
        if root.join("ready.json").exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let ready: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
    let origin = ready["origin"].as_str().unwrap();
    let ca = std::fs::read(fixtures.join("hub-hybrid-fleet-ca.crt")).unwrap();
    let client = RemoteStorageWorkClient::new(origin, DEPLOYMENT.into(), PRODUCER_KEY)
        .unwrap()
        .with_controlled_mirror(
            &profile,
            &policy,
            aos_hub_core::mirror_guard::MirrorGuardIssuer {
                source_digest: source.clone(),
                script_version: format!("emulated-{source}"),
            },
            CANDIDATE_KEY,
        )
        .unwrap()
        .with_mirror_guard_key(guard_key.as_bytes())
        .unwrap()
        .with_controlled_ca(&ca)
        .unwrap();
    let query_http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .build()
        .unwrap();
    if gc_only {
        #[cfg(feature = "test-support")]
        super::runtime_gc::run(&root, &db, &registry, &query_http, origin, &ca).await;
        assert!(root.join("gc-observations.json").is_file());
        std::fs::write(
            root.join("GC-PASS"),
            b"controlled managed physical guard only\n",
        )
        .unwrap();
        return;
    }

    super::runtime_membership::run(&root, &db, &registry, &client, &query_http, origin).await;
    let selected = vec![
        (
            "web/metadata-two.json".into(),
            MirrorVerification::Sha256 {
                sha256: metadata_hash.clone(),
                size: metadata.len() as u64,
            },
        ),
        (
            "web/metadata.json".into(),
            MirrorVerification::Sha256 {
                sha256: metadata_hash,
                size: metadata.len() as u64,
            },
        ),
        (
            "nar/none.nar".into(),
            MirrorVerification::Nar {
                file_sha256: Some(plain_hash.clone()),
                file_size: plain.len() as u64,
                compression: "none".into(),
                nar_sha256: plain_hash.clone(),
                nar_size: plain.len() as u64,
            },
        ),
        (
            "nar/zstd.nar.zst".into(),
            MirrorVerification::Nar {
                file_sha256: Some(compressed_hash),
                file_size: compressed.len() as u64,
                compression: "zstd".into(),
                nar_sha256: plain_hash,
                nar_size: plain.len() as u64,
            },
        ),
    ];
    let prepared = prepare(&db, &client, &registry, selected).await.unwrap();
    assert_eq!(prepared.len(), 4);
    let publication = crate::mirror::hybrid::publication::admit(
        &db,
        registry.id,
        &"5".repeat(64),
        &"6".repeat(64),
        &prepared,
    )
    .await
    .unwrap();
    let originals = prepared
        .iter()
        .map(|object| object.original.clone())
        .collect::<Vec<_>>();
    let http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        http.post(format!("{origin}/__fixture/restart"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        http.post(format!("{origin}/__fixture/lose-ack"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let publication_result = publish(&db, &client, prepared, &publication.publication_id).await;
    if let Err(error) = &publication_result {
        eprintln!("controlled publication result: {error:#}");
    }
    assert!(publication_result.is_err());
    let mut acknowledgements = Vec::new();
    for original in &originals {
        let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
        assert_eq!(retained.state, "committed");
        assert_eq!(retained.publication_commit_version, Some(7));
        acknowledgements.push(aos_hub_core::mirror_batch::MirrorBatchItem {
            original: original.clone(),
            step: MirrorStep::Acknowledge {
                commit_digest: retained.progress.unwrap().commit_digest(original).unwrap(),
            },
        });
    }
    let before = http
        .get(format!("{origin}/__fixture/provider/observations"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        http.post(format!("{origin}/__fixture/restart"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    drop(db);
    let db = Database::open(&database_path).await.unwrap();
    for (_, result) in run(
        &db,
        &client,
        acknowledgements,
        Some(&publication.publication_id),
    )
    .await
    {
        result.unwrap();
    }
    for original in &originals {
        assert!(db.mirror_import(&original.job_id).await.unwrap().is_none());
        let object = db
            .surface_object_named(
                aos_hub_core::db::SurfaceTarget::Registry(registry.id),
                &original.path,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(object.size, Some(original.verification.size() as i64));
    }
    let observations = http
        .get(format!("{origin}/__fixture/provider/observations"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    std::fs::write(
        root.join("provider-observations.json"),
        serde_json::to_vec_pretty(&observations).unwrap(),
    )
    .unwrap();
    assert_eq!(observations["openUploads"], 0);
    let counts = |report: &serde_json::Value| {
        report["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| {
                ["create", "part", "complete"].contains(&entry["action"].as_str().unwrap())
            })
            .map(|entry| {
                (
                    entry["action"].as_str().unwrap().to_owned(),
                    entry["requests"].as_u64().unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        counts(&before),
        counts(&observations),
        "exact lost ACK recovery redispatched a provider mutation"
    );
    assert_eq!(
        http.post(format!("{origin}/__fixture/provider/fault"))
            .json(&serde_json::json!({"action":"create","remaining":1}))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let unknown = vec![(
        "web/unknown.json".into(),
        MirrorVerification::Sha256 {
            sha256: hex::encode(Sha256::digest(metadata)),
            size: metadata.len() as u64,
        },
    )];
    assert!(prepare(&db, &client, &registry, unknown.clone())
        .await
        .is_err());
    let held = db
        .mirror_import_for_path(registry.id, "web/unknown.json")
        .await
        .unwrap()
        .unwrap();
    let after_unknown = http
        .get(format!("{origin}/__fixture/provider/observations"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(after_unknown["openUploads"], 1);
    assert_eq!(
        http.post(format!("{origin}/__fixture/restart"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    drop(db);
    let db = Database::open(&database_path).await.unwrap();
    assert!(prepare(&db, &client, &registry, unknown).await.is_err());
    let recovered = db
        .mirror_import_for_path(registry.id, "web/unknown.json")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.original, held.original);
    let after_recovery = http
        .get(format!("{origin}/__fixture/provider/observations"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        counts(&after_unknown),
        counts(&after_recovery),
        "unknown create was redispatched after restart"
    );
    std::fs::write(
        root.join("unknown-observations.json"),
        serde_json::to_vec_pretty(&after_recovery).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("PASS"), b"Actual controlled none/zstd producer, restart, independent guard, SQL publication and ACK passed. No hosted qualification.\n").unwrap();
}
