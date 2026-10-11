//! Explicit generated test inputs; none of these observations qualify a deployment.

use super::super::*;
use aos_hub_core::direct_upload::*;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};

pub(super) struct Fixture {
    pub directory: tempfile::TempDir,
    pub selection: PathBuf,
    pub public_key: PathBuf,
    pub private_key: PathBuf,
}

struct Inputs {
    directory: PathBuf,
    index: usize,
    captures: Vec<Value>,
    privacy: BTreeMap<String, Value>,
}

impl Inputs {
    fn file(&mut self, bytes: &[u8]) -> Value {
        self.index += 1;
        let name = format!("input-{}", self.index);
        std::fs::write(self.directory.join(&name), bytes).unwrap();
        json!({"path":name,"sha256":files::digest(bytes)})
    }

    fn document(&mut self, value: &impl serde::Serialize) -> Value {
        self.file(&serde_json::to_vec(value).unwrap())
    }

    fn privacy(&mut self, bytes: &[u8]) -> String {
        let hash = files::digest(bytes);
        if !self.privacy.contains_key(&hash) {
            let file = self.file(bytes);
            self.privacy.insert(hash.clone(), file);
        }
        hash
    }

    fn http(&mut self, url: String, status: u16, bytes: &[u8]) -> String {
        let body = self.privacy(bytes);
        let headers = self.privacy(b"content-type: application/octet-stream\r\n");
        self.privacy(
            &serde_json::to_vec(&json!({"version":1,"method":"GET","url":url,
            "status":status,"headersSha256":headers,"bodySha256":body}))
            .unwrap(),
        )
    }

    fn capture(&mut self, artifact: &DirectWorkerQualificationArtifact, result: Value) -> String {
        let observed = if result["kind"] == "expired_mutation_refused" {
            "100000"
        } else {
            "1100"
        };
        let file = self.document(&json!({"version":1,"requestSha256":"ab".repeat(32),
            "nonce":format!("{:064x}",self.index),"sourceDigest":artifact.source_digest,
            "scriptVersion":artifact.script_version,"observedAtMillis":observed,"result":result}));
        let hash = file["sha256"].as_str().unwrap().to_owned();
        self.captures.push(file);
        hash
    }
}

fn report(artifact: &DirectWorkerQualificationArtifact, observations: Value) -> Value {
    json!({"version":1,"executionKind":artifact.execution_kind,"deploymentId":artifact.deployment_id,
        "publicOrigin":artifact.public_origin,"sourceDigest":artifact.source_digest,
        "scriptVersion":artifact.script_version,"observations":observations})
}

pub(super) fn fixture() -> Fixture {
    let directory = tempfile::Builder::new()
        .prefix(".direct-review-test-")
        .tempdir_in(".")
        .unwrap();
    let mut inputs = Inputs {
        directory: directory.path().into(),
        index: 0,
        captures: Vec::new(),
        privacy: BTreeMap::new(),
    };
    let (mut artifact, public) = direct_worker_qualification_fixture();
    let now = super::super::now().unwrap();
    artifact.evidence.issued_at = WireInteger::new(now - 1);
    artifact.evidence.valid_until = WireInteger::new(now + 300);
    let mut reports = Vec::new();
    let mut add = |kind: &str, file: Value| {
        reports.push(json!({"kind":kind,"file":file}));
    };
    let clock_capture = inputs.capture(
        &artifact,
        json!({"kind":"clock","observedAtMillis":"1050","uncertaintySeconds":"1"}),
    );
    let expired_capture = inputs.capture(&artifact, json!({"kind":"expired_mutation_refused","cutoff":"100","observedAt":"101",
        "providerBefore":{"isolateId":"isolate-one","dispatches":12},"providerAfter":{"isolateId":"isolate-one","dispatches":12}}));
    let clock_file = inputs.document(&report(&artifact,json!({"samples":[{"sentAtMillis":"1000","receivedAtMillis":"1100","observedAtMillis":"1050","replySha256":clock_capture}],
        "expiredMutations":[{"cutoff":"100","observedAtMillis":"100000","isolateId":"isolate-one","providerDispatchesBefore":"12","providerDispatchesAfter":"12","replySha256":expired_capture}]})));
    artifact.evidence.clock.observation_sha256 = clock_file["sha256"].as_str().unwrap().into();
    artifact.evidence.clock.samples = WireInteger::new(1);
    artifact.evidence.clock.maximum_observed_skew_millis = WireInteger::new(50);
    add("clock", clock_file);

    let mut bulk = Vec::new();
    let mut metadata = Vec::new();
    let mut runtime = Vec::new();
    let original = json!({"deploymentId":artifact.deployment_id,"publicOrigin":artifact.public_origin,
        "sourceDigest":artifact.source_digest,"scriptVersion":artifact.script_version,
        "material":{"kind":"managed","profile":artifact.evidence.managed_profile,"policy":artifact.evidence.private_stage_policy}});
    for (phase, total) in [("content", 3), ("metadata", 4)] {
        for index in 1..=total {
            let object = format!("{phase}-{index}");
            let is_mixed = phase == "metadata" && index == 1;
            let bulk_active = if phase == "content" {
                index
            } else if is_mixed {
                3
            } else {
                0
            };
            let meta_active = if phase == "metadata" { index } else { 0 };
            let aggregate = bulk_active + meta_active;
            let (start, end) = if phase == "content" {
                (1000, 3000)
            } else {
                (1500, 2000)
            };
            let proof = json!({"sha256":"12".repeat(32),"byte_size":"1048576"});
            let proof_hash = files::digest(&serde_json::to_vec(&proof).unwrap());
            let message = format!("message-{object}");
            let provider_before = json!({"isolateId":"isolate-one","maximum":8,"active":0,"bulkActive":0,
                "metadataActive":0,"peakActive":8,"metadataAdmissionsDuringBulk":0,"dispatches":100});
            let provider_after = json!({"isolateId":"isolate-one","maximum":8,"active":0,"bulkActive":0,
                "metadataActive":0,"peakActive":8,"metadataAdmissionsDuringBulk":if is_mixed {1} else {0},"dispatches":101});
            let receipt = json!({"attempt":{"nonce":"cd".repeat(32),"startedAtMillis":start.to_string(),"providerBefore":provider_before},
                "finishedAtMillis":end.to_string(),"queueName":format!("direct-{phase}"),"messageId":message,
                "objects":{"aggregateActive":aggregate,"bulkActive":bulk_active,"metadataActive":meta_active},
                "providerAfter":provider_after,"verificationReplayed":false,"proof":proof});
            let capture = inputs.capture(&artifact, json!({"original":original,"objectId":object,
                "closed":{"objectId":object,"settlementMillis":"500"},"attempts":[{"attempt":receipt["attempt"],"receipt":receipt}],"nextAttempt":null}));
            let row = json!({"objectId":object,"isolateId":"isolate-one","messageId":message,"startedAtMillis":start.to_string(),
                "finishedAtMillis":end.to_string(),"byteSize":"1048576","sha256":"12".repeat(32),"proofSha256":proof_hash,
                "aggregateActive":aggregate.to_string(),"bulkActive":bulk_active.to_string(),"metadataActive":meta_active.to_string(),
                "freshProviderDispatches":"1","replySha256":capture});
            runtime.push(json!({"objectId":object,"isolateId":"isolate-one","byteSize":"1048576","sha256":"12".repeat(32),
                "proofSha256":proof_hash,"verificationMillis":(end-start).to_string(),"settlementMillis":"500",
                "peakParallelObjects":aggregate.to_string(),"peakParallelProviderRequests":"8","freshProviderDispatches":"1","replySha256":capture}));
            if phase == "content" {
                bulk.push(row);
            } else {
                metadata.push(row);
            }
        }
    }
    let mixed = inputs.document(&report(&artifact,json!({"samples":[{"isolateId":"isolate-one","bulkStartedAtMillis":"1000","bulkFinishedAtMillis":"3000",
        "metadataStartedAtMillis":"1500","metadataFinishedAtMillis":"2000","bulkActive":"3","metadataAdmissionsBefore":"0",
        "metadataAdmissionsAfter":"1","metadataReplySha256":metadata[0]["replySha256"]}]})));
    artifact
        .evidence
        .metadata_queue
        .mixed_load_observation_sha256 = Some(mixed["sha256"].as_str().unwrap().into());
    add("mixed_load", mixed);
    for (kind, rows, queue) in [
        ("bulk_queue", bulk, &mut artifact.evidence.bulk_queue),
        (
            "metadata_queue",
            metadata,
            &mut artifact.evidence.metadata_queue,
        ),
    ] {
        let observation = json!({"version":1,"executionKind":artifact.execution_kind,"deploymentId":artifact.deployment_id,
            "publicOrigin":artifact.public_origin,"sourceDigest":artifact.source_digest,"scriptVersion":artifact.script_version,
            "observations":{"queueName":queue.queue_name,"dependencyPhase":queue.dependency_phase,"samples":rows}});
        let file = inputs.document(&observation);
        queue.observation_sha256 = file["sha256"].as_str().unwrap().into();
        queue.completed_jobs = WireInteger::new(rows.len() as u64);
        add(kind, file);
        let config = inputs.document(&json!({"success":true,"errors":[],"result":{"queue_name":queue.queue_name,"consumers":[{
            "type":"worker","script_name":"reviewed-worker","settings":{"batch_size":queue.delivery_policy.maximum_batch_size.get(),"max_concurrency":2}}]}}));
        queue.configuration_readback_sha256 = config["sha256"].as_str().unwrap().into();
        add(
            if kind == "bulk_queue" {
                "bulk_configuration"
            } else {
                "metadata_configuration"
            },
            config,
        );
    }
    let runtime_file = inputs.document(&report(&artifact, json!({"samples":runtime})));
    artifact.evidence.runtime_measurement.observation_sha256 =
        runtime_file["sha256"].as_str().unwrap().into();
    artifact.evidence.runtime_measurement.samples = WireInteger::new(7);
    artifact
        .evidence
        .runtime_measurement
        .maximum_verification_millis = WireInteger::new(2000);
    artifact.evidence.runtime.qualification_digest =
        direct_qualification_digest(&artifact.evidence.runtime_measurement).unwrap();
    add("runtime", runtime_file);

    let privacy = artifact.evidence.privacy.as_mut().unwrap();
    let api_base = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets/{}/domains",
        privacy.provider_account_id, privacy.provider_bucket_name
    );
    let managed = inputs.http(
        format!("{api_base}/managed"),
        200,
        &serde_json::to_vec(&json!({"success":true,"errors":[],"result":{
        "bucketId":"ab".repeat(16),"domain":"disabled-public.example.test","enabled":false}}))
        .unwrap(),
    );
    let custom = inputs.http(
        format!("{api_base}/custom"),
        200,
        b"{\"success\":true,\"errors\":[],\"result\":{\"domains\":[]}}",
    );
    let policy = inputs.document(&json!({"version":1,"providerAccountId":privacy.provider_account_id,"providerBucketName":privacy.provider_bucket_name,
        "providerBucketId":"ab".repeat(16),"managedDomainCaptureSha256":managed,"customDomainsCaptureSha256":custom}));
    privacy.provider_policy_readback_sha256 = policy["sha256"].as_str().unwrap().into();
    add("privacy_policy", policy);
    let key = ".aos-direct-upload/known-object";
    let positive_body = b"actual positive fixture bytes";
    let positive = inputs.http(
        format!(
            "https://{}.r2.cloudflarestorage.com/{}/{key}",
            privacy.provider_account_id, privacy.provider_bucket_name
        ),
        200,
        positive_body,
    );
    let anonymous = inputs.http(
        format!("{}/{key}", privacy.public_endpoint),
        401,
        b"Unauthorized",
    );
    let worker = inputs.http(
        format!("{}/{key}", artifact.public_origin),
        404,
        b"Not found",
    );
    let custody = inputs.privacy(b"explicit test-only provisioning custody observation");
    let writer_source = inputs.privacy(b"explicit test-only runtime source/scope observation");
    let writers = inputs.privacy(&serde_json::to_vec(&json!({"version":1,"reviewerKeyId":artifact.reviewer_key_id,
        "providerAccountId":privacy.provider_account_id,"providerBucketName":privacy.provider_bucket_name,
        "namespace":privacy.namespace,"sourceDigest":artifact.source_digest,"scriptVersion":artifact.script_version,
        "independentWriterCount":"0","provisioningControlPlaneCustodyEvidence":[custody],
        "runtimeMutationApis":[{"route":"/_internal/storage/direct-upload-sdk-conformance","namespace":"sdk-fixture-namespace",
            "physicalKeyPrefix":".aos-direct-qualification/","guardCoverage":"outside_selected_namespace","observationSha256":writer_source}]})).unwrap());
    privacy.public_read_rejection_status = 401;
    let observed = inputs.document(&json!({"version":1,"namespace":privacy.namespace,"policyId":privacy.policy_id,
        "providerAccountId":privacy.provider_account_id,"providerBucketName":privacy.provider_bucket_name,"publicEndpoint":privacy.public_endpoint,
        "objectKey":key,"expectedSha256":files::digest(positive_body),"expectedByteSize":positive_body.len().to_string(),
        "authenticatedPositiveCaptureSha256":positive,"anonymousPublicCaptureSha256":anonymous,"unauthorizedWorkerCaptureSha256":worker,
        "independentWriterCount":"0","independentWriterReviewSha256":writers}));
    privacy.observation_sha256 = observed["sha256"].as_str().unwrap().into();
    add("privacy", observed);
    let response = inputs.privacy(b"<Error><Code>BadDigest</Code></Error>");
    let sdk = artifact.evidence.sdk_probe.as_mut().unwrap();
    let rejection = format!("{{\"version\":1,\"runId\":\"{}\",\"state\":\"negative\",\"status\":400,\"providerCode\":\"BadDigest\",\"responseSha256\":\"{}\",\"sourceSha256\":\"{}\"}}",sdk.original.run_id,response,"ef".repeat(32));
    sdk.direct_s3_checksum_rejection_sha256 = files::digest(rejection.as_bytes());
    add("sdk_checksum_rejection", inputs.file(rejection.as_bytes()));

    let public_file = inputs.file(public.as_bytes());
    let identity = DirectWorkerDeploymentIdentity {
        version: 1,
        deployment_id: artifact.deployment_id.clone(),
        public_origin: artifact.public_origin.clone(),
        source_digest: artifact.source_digest.clone(),
        script_version: artifact.script_version.clone(),
        qualification_public_key: public,
        clock_mode: artifact.evidence.clock_policy.mode,
        clock_qualification: artifact.evidence.clock_policy.commitment().unwrap(),
        clock_uncertainty_seconds: artifact.evidence.clock_policy.uncertainty_seconds,
        managed_profile: artifact.evidence.managed_profile.clone(),
        private_stage_policy: artifact.evidence.private_stage_policy.clone(),
        external_profiles: Vec::new(),
        bulk_queue: artifact.evidence.bulk_queue.queue_name.clone(),
        metadata_queue: artifact.evidence.metadata_queue.queue_name.clone(),
        bulk_queue_policy: artifact.evidence.bulk_queue.delivery_policy.clone(),
        metadata_queue_policy: artifact.evidence.metadata_queue.delivery_policy.clone(),
        maximum_parallel_objects: artifact.evidence.runtime.maximum_parallel_objects,
        qualification_limits: None,
    };
    let documents = json!({"reviewerPublicKey":public_file,"deploymentIdentity":inputs.document(&identity),"sdkProbe":inputs.document(&artifact.evidence.sdk_probe.as_ref().unwrap()),
        "privacy":inputs.document(&artifact.evidence.privacy.as_ref().unwrap()),"installation":null});
    let selection = json!({"version":1,"executionKind":artifact.execution_kind,"reviewerKeyId":artifact.reviewer_key_id,
        "deploymentId":artifact.deployment_id,"publicOrigin":artifact.public_origin,"sourceDigest":artifact.source_digest,"scriptVersion":artifact.script_version,
        "workerName":"reviewed-worker","runtimeBounds":{"maximumObjectBytes":"1048576","maximumVerificationSeconds":"2","settlementReserveSeconds":"1",
            "maximumParallelObjects":"4","maximumParallelProviderRequests":"8"},"issuedAt":artifact.evidence.issued_at,"validUntil":artifact.evidence.valid_until,
        "documents":documents,"reports":reports,"captureFiles":inputs.captures,"privacyFiles":inputs.privacy.into_values().collect::<Vec<_>>(),"installedFiles":[]});
    let selection_path = directory.path().join("selection.json");
    std::fs::write(
        &selection_path,
        serde_json::to_vec_pretty(&selection).unwrap(),
    )
    .unwrap();
    let private_key = directory.path().join("reviewer.seed");
    std::fs::write(&private_key, [0x19; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // The test sandbox remaps absolute ancestors; custody starts at trusted cwd.
    let private_key = private_key
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap()
        .to_path_buf();
    Fixture {
        public_key: directory.path().join(public_file["path"].as_str().unwrap()),
        directory,
        selection: selection_path,
        private_key,
    }
}
