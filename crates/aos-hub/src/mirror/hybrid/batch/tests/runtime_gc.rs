//! Actual managed physical guard deletion and immutable unknown-outcome custody.
//!
//! Native signs ordinary storage-work plans for the fixture's selected binding
//! and write revision. Read-only fixture state observes the real durable guard;
//! the SQLite provider supplies actual effects and independent readback. This
//! does not qualify hosted conditional DELETE or SQL GC accounting.
//! The fixture transport retains production plan/result validation without
//! changing the production client's restriction on controlled TLS authority.

use std::path::Path;

use aos_hub_core::db::{BindingRecord, SurfacePlacementRecord, SurfaceTarget};
use sha2::Digest as _;

use super::*;

struct Controls<'a> {
    work: RemoteStorageWorkClient,
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    http: &'a reqwest::Client,
    transport: reqwest::Client,
    origin: &'a str,
    exchanges: Vec<serde_json::Value>,
}

impl Controls<'_> {
    async fn execute(
        &mut self,
        operation: StorageWorkOperation,
    ) -> anyhow::Result<StorageWorkResult> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            operation,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.send(&plan).await;
        self.exchanges.push(serde_json::json!({
            "plan": plan,
            "result": result.as_ref().ok(),
            "outcome": if result.is_ok() { "received" } else { "refused_or_unknown" },
        }));
        result
    }

    async fn send(&self, plan: &StorageWorkPlan) -> anyhow::Result<StorageWorkResult> {
        let bytes = serde_json::to_vec(plan)?;
        let signature = StorageWorkKey::new(PRODUCER_KEY)?.sign_body(&bytes)?;
        let mut response = self
            .transport
            .post(format!("{}{STORAGE_WORK_PATH}", self.origin))
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(bytes)
            .send()
            .await?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "controlled signed GC exchange refused or unknown"
        );
        let mut reply = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                reply.len() + chunk.len() <= plan.operation.maximum_result_bytes(),
                "controlled GC reply exceeds bound"
            );
            reply.extend_from_slice(&chunk);
        }
        let result = serde_json::from_slice(&reply)?;
        crate::storage_work::validate_result_for_test(plan, &result)?;
        plan.validate(DEPLOYMENT, aos_hub_core::clock::now_unix_secs())?;
        Ok(result)
    }

    async fn head(&mut self, path: &str) -> Option<StorageObjectIdentity> {
        let result = self
            .execute(StorageWorkOperation::Head { path: path.into() })
            .await
            .unwrap();
        match result.outcome {
            StorageWorkOutcome::Head { object } => Some(object),
            StorageWorkOutcome::NotFound => None,
            other => panic!("unexpected physical HEAD result: {other:?}"),
        }
    }

    async fn snapshot(&self, key: &str, claim: &str) -> serde_json::Value {
        let guard = self
            .http
            .post(format!("{}/__fixture/guard-state", self.origin))
            .json(&serde_json::json!({"key": key, "claimId": claim}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        let provider = self
            .http
            .get(format!("{}/__fixture/provider/observations", self.origin))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        serde_json::json!({"guard": guard, "provider": provider})
    }
}

fn deletion(path: &str, claim: &str, object: &StorageObjectIdentity) -> StorageWorkOperation {
    StorageWorkOperation::DeleteIfMatches {
        path: path.into(),
        claim_id: claim.into(),
        expected_etag: object.etag.clone(),
        expected_size: object.size,
        delete_binding_write_revision: None,
        expected_hash: None,
        expected_provider_version: object.provider_version.clone(),
    }
}

fn deletes(snapshot: &serde_json::Value) -> u64 {
    snapshot["provider"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["action"] == "delete")
        .map_or(0, |row| row["requests"].as_u64().unwrap())
}

fn absent(snapshot: &serde_json::Value, key: &str) -> bool {
    !snapshot["provider"]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["object_key"] == key)
}

pub(super) async fn run(
    root: &Path,
    db: &Database,
    registry: &aos_hub_core::db::RegistryRecord,
    http: &reqwest::Client,
    origin: &str,
    ca: &[u8],
) {
    let surface = SurfaceTarget::Registry(registry.id);
    let placement = db.list_surface_placements(surface).await.unwrap().remove(0);
    let binding = db.binding(placement.binding_id).await.unwrap().unwrap();
    let writer = db.surface_write_authority(surface).await.unwrap().unwrap();
    let write_state = db.binding_write_state(binding.id).await.unwrap().unwrap();
    assert_eq!(binding.kind, "deployment_r2");
    assert_eq!(writer.desired_placement_id, placement.id);
    assert_eq!(
        Some(writer.desired_binding_write_revision),
        write_state.current_write_revision
    );
    assert_eq!(writer.observed_placement_id, Some(placement.id));
    assert_eq!(
        writer.observed_binding_write_revision,
        write_state.current_write_revision
    );
    assert_eq!(writer.observed_generation, Some(writer.desired_generation));
    assert_eq!(writer.reconciliation_state, "ready");
    assert!(placement.effective_write_enabled);

    // The controlled mirror signer only admits mirror operations. GC uses the
    // original ordinary storage-work role and its actual managed binding.
    let work = RemoteStorageWorkClient::new(origin, DEPLOYMENT.into(), PRODUCER_KEY).unwrap();
    let selected_origin = url::Url::parse(origin).unwrap();
    assert_eq!(selected_origin.scheme(), "https");
    assert_eq!(selected_origin.host_str(), Some("localhost"));
    assert!(selected_origin.port().is_some());
    let transport = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .add_root_certificate(reqwest::Certificate::from_pem(ca).unwrap())
        .build()
        .unwrap();
    let mut controls = Controls {
        work,
        placement,
        binding,
        http,
        transport,
        origin,
        exchanges: Vec::new(),
    };
    let path = ".aos-internal/conditional-delete-probes/1001";
    let key = format!("{}/{path}", controls.placement.prefix);
    let mut cases = Vec::new();

    controls
        .execute(StorageWorkOperation::PutProbe {
            path: path.into(),
            content_base64: String::new(),
        })
        .await
        .unwrap();
    let original = controls.head(path).await.unwrap();
    assert_eq!(original.key, key);
    assert!(original.provider_version.is_some());
    let before = controls.snapshot(&key, "version-mismatch").await;
    assert!(before["guard"]["pendingMutation"].is_null());
    assert!(before["guard"]["pendingDelete"].is_null());
    let mut foreign = original.clone();
    foreign.provider_version = Some("foreign-writer-version".into());
    let refused = controls
        .execute(deletion(path, "version-mismatch", &foreign))
        .await
        .unwrap();
    assert_eq!(
        refused.outcome,
        StorageWorkOutcome::DeletePreconditionFailed
    );
    assert_eq!(controls.head(path).await, Some(original.clone()));
    let after = controls.snapshot(&key, "version-mismatch").await;
    assert_eq!(deletes(&after), deletes(&before));
    cases.push(serde_json::json!({"case": "version_mismatch", "before": before, "after": after}));

    let before = controls.snapshot(&key, "exact-delete").await;
    let exact = deletion(path, "exact-delete", &original);
    let result = controls.execute(exact.clone()).await.unwrap();
    assert_eq!(
        result.outcome,
        StorageWorkOutcome::ObjectDeleted {
            etag: original.etag.clone()
        }
    );
    assert_eq!(controls.head(path).await, None);
    let after = controls.snapshot(&key, "exact-delete").await;
    assert_eq!(deletes(&after), deletes(&before) + 1);
    assert!(absent(&after, &key));
    assert!(after["guard"]["pendingDelete"].is_null());
    assert_eq!(
        after["guard"]["deleteReceipt"]["claim"]["expected_provider_version"],
        original.provider_version.as_deref().unwrap()
    );
    assert_eq!(
        after["guard"]["deleteReceipt"]["outcome"]["kind"],
        "deleted"
    );
    cases.push(
        serde_json::json!({"case": "exact_delete_absence", "before": before, "after": after}),
    );

    controls
        .execute(StorageWorkOperation::PutProbe {
            path: path.into(),
            content_base64: String::new(),
        })
        .await
        .unwrap();
    let replacement = controls.head(path).await.unwrap();
    assert_ne!(replacement.provider_version, original.provider_version);
    let before = controls.snapshot(&key, "exact-delete").await;
    let replay = controls.execute(exact).await.unwrap();
    assert_eq!(replay.outcome, result.outcome);
    assert_eq!(controls.head(path).await, Some(replacement.clone()));
    let after = controls.snapshot(&key, "exact-delete").await;
    assert_eq!(deletes(&after), deletes(&before));
    assert!(!absent(&after, &key));
    cases.push(serde_json::json!({"case": "replay_preserves_new_writer", "before": before, "after": after, "replacement": replacement}));

    assert_eq!(
        http.post(format!("{origin}/__fixture/provider/fault"))
            .json(&serde_json::json!({"action": "delete", "remaining": 1}))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let before = controls.snapshot(&key, "unknown-delete").await;
    let unknown = deletion(path, "unknown-delete", &replacement);
    assert!(controls.execute(unknown.clone()).await.is_err());
    let after = controls.snapshot(&key, "unknown-delete").await;
    assert_eq!(deletes(&after), deletes(&before) + 1);
    assert!(
        absent(&after, &key),
        "positive provider effect was not independently read back"
    );
    assert_eq!(
        after["guard"]["pendingDelete"]["claim_id"],
        "unknown-delete"
    );
    assert_eq!(
        after["guard"]["pendingDelete"]["expected_provider_version"],
        replacement.provider_version.as_deref().unwrap()
    );
    assert!(after["guard"]["deleteReceipt"].is_null());
    cases.push(
        serde_json::json!({"case": "unknown_delete_effect", "before": before, "after": after}),
    );

    assert_eq!(
        http.post(format!("{origin}/__fixture/restart"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let before = controls.snapshot(&key, "unknown-delete").await;
    assert!(controls.execute(unknown).await.is_err());
    assert!(controls
        .execute(StorageWorkOperation::Head { path: path.into() })
        .await
        .is_err());
    assert!(controls
        .execute(StorageWorkOperation::PutProbe {
            path: path.into(),
            content_base64: String::new(),
        })
        .await
        .is_err());
    let after = controls.snapshot(&key, "unknown-delete").await;
    assert_eq!(
        after, before,
        "independent absence cleared or redispatched unknown custody"
    );
    cases.push(
        serde_json::json!({"case": "unknown_restart_refusal", "before": before, "after": after}),
    );

    assert_eq!(
        db.surface_write_authority(surface).await.unwrap(),
        Some(writer.clone())
    );
    assert_eq!(
        db.binding_write_state(controls.binding.id)
            .await
            .unwrap()
            .unwrap()
            .current_write_revision,
        write_state.current_write_revision
    );

    let report = serde_json::json!({
        "version": 1, "execution": "controlled", "scope": "managed physical guard and provider effects; no SQL GC accounting or hosted conditional DELETE qualification",
        "nativeTransport": "fixture-only signed transport using shared production plan/result validation; production Native execute TLS is not qualified",
        "deploymentId": DEPLOYMENT, "guardNamespace": "HybridObjectGuard", "guardNamespaceUniqueKey": "mirror-guard",
        "workerConfigurationSha256": hex::encode(sha2::Sha256::digest(std::fs::read(root.join("worker.capnp")).unwrap())),
        "placement": {"id": controls.placement.id, "resourceVersion": controls.placement.resource_version,
            "writeSpecVersion": controls.placement.write_spec_version, "prefix": controls.placement.prefix,
            "bindingId": controls.placement.binding_id},
        "binding": {"id": controls.binding.id, "resourceVersion": controls.binding.resource_version, "kind": controls.binding.kind},
        "writer": {"id": writer.id, "incarnationId": writer.incarnation_id,
            "desiredPlacementId": writer.desired_placement_id, "desiredWriteSpecVersion": writer.desired_write_spec_version,
            "desiredBindingWriteRevision": writer.desired_binding_write_revision, "desiredGeneration": writer.desired_generation,
            "observedPlacementId": writer.observed_placement_id, "observedWriteSpecVersion": writer.observed_write_spec_version,
            "observedBindingWriteRevision": writer.observed_binding_write_revision, "observedGeneration": writer.observed_generation,
            "reconciliationState": writer.reconciliation_state, "resourceVersion": writer.resource_version},
        "currentWriteRevision": write_state.current_write_revision,
        "physicalKey": key, "original": original, "controls": controls.exchanges, "cases": cases,
        "unknownOutcome": "blocked; independent provider absence does not settle the outstanding guard claim",
    });
    std::fs::write(
        root.join("gc-observations.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
