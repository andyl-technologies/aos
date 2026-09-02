//! Environment-gated conformance against an actual S3-compatible service.

// crucible-lint: allow panic-shortcut -- environment-gated conformance fixtures fail loudly at the exact violated S3 invariant.
#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

use crucible_cas::content_store::conformance::{
    assert_blob_leaf_conformance, assert_ref_leaf_conformance,
};
use crucible_cas::content_store::{
    S3BlobBackend, S3RefBackend, StoreS3EndpointId, StoreS3RefCapability,
};
use crucible_s3_store::{AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient};

const ENDPOINT_ENV: &str = "CRUCIBLE_S3_TEST_ENDPOINT";
const BUCKET_ENV: &str = "CRUCIBLE_S3_TEST_BUCKET";
const PREFIX_ENV: &str = "CRUCIBLE_S3_TEST_PREFIX";

#[test]
#[ignore = "requires an exclusive unversioned S3-compatible test bucket and credentials"]
fn live_s3_service_passes_blob_and_ref_conformance() {
    let Some(deployment) = LiveDeployment::from_environment() else {
        eprintln!("{ENDPOINT_ENV} and {BUCKET_ENV} are not set; skipping live S3 conformance");
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("live-conformance Tokio runtime");
    let shared_config = runtime.block_on(async {
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(deployment.region.clone()))
            .load()
            .await
    });
    let sdk_config = aws_sdk_s3::config::Builder::from(&shared_config)
        .endpoint_url(&deployment.endpoint_url)
        .force_path_style(true)
        .build();
    let cleanup_client = aws_sdk_s3::Client::from_conf(sdk_config.clone());
    let client = Arc::new(
        AwsSdkS3Client::start(
            deployment.endpoint.clone(),
            aws_sdk_s3::Client::from_conf(sdk_config),
            AwsSdkS3ClientConfig::new(32, 8, 128 * 1024 * 1024, Duration::from_secs(30))
                .expect("bounded live-conformance worker policy"),
        )
        .expect("start live-conformance S3 worker"),
    );
    let strong = Arc::new(AwsSdkS3StrongCasClient::from_conformant_service(
        Arc::clone(&client),
    ));

    let blob_prefix = format!("{}/blob", deployment.root_prefix);
    let blob = S3BlobBackend::new_with_admin(
        "live-s3-conformance",
        deployment.endpoint.clone(),
        deployment.bucket.clone(),
        blob_prefix,
        12 * 1024 * 1024,
        5 * 1024 * 1024,
        client.clone(),
        strong.clone(),
    )
    .expect("construct live blob conformance leaf");
    assert_blob_leaf_conformance(&blob);

    let ref_prefix = format!("{}/refs", deployment.root_prefix);
    let refs = S3RefBackend::new(
        StoreS3RefCapability::new(
            deployment.endpoint.clone(),
            deployment.bucket.clone(),
            ref_prefix,
            strong.clone(),
        )
        .expect("construct live ref conformance capability"),
    );
    assert_ref_leaf_conformance(&refs);

    drop(refs);
    drop(blob);
    drop(strong);
    drop(client);
    runtime.block_on(clean_prefix(
        &cleanup_client,
        &deployment.bucket,
        &format!("{}/", deployment.root_prefix),
    ));
}

struct LiveDeployment {
    endpoint_url: String,
    endpoint: StoreS3EndpointId,
    bucket: String,
    region: String,
    root_prefix: String,
}

impl LiveDeployment {
    fn from_environment() -> Option<Self> {
        let endpoint_url = env::var(ENDPOINT_ENV).ok()?;
        let bucket = env::var(BUCKET_ENV).ok()?;
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let prefix = env::var(PREFIX_ENV).unwrap_or_else(|_| "crucible-conformance".to_string());
        let root_prefix = format!("{}/{}", prefix.trim_matches('/'), std::process::id());
        Some(Self {
            endpoint_url,
            endpoint: StoreS3EndpointId::new("live/s3-conformance-v1")
                .expect("live endpoint-policy identity"),
            bucket,
            region,
            root_prefix,
        })
    }
}

async fn clean_prefix(client: &aws_sdk_s3::Client, bucket: &str, prefix: &str) {
    let output = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .max_keys(1_000)
        .send()
        .await
        .expect("list live-conformance cleanup prefix");
    assert_ne!(
        output.is_truncated(),
        Some(true),
        "cleanup prefix is bounded"
    );
    for object in output.contents() {
        let key = object.key().expect("listed cleanup object has a key");
        client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .expect("delete live-conformance object");
    }
}
