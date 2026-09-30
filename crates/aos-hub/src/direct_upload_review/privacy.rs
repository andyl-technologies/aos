//! Correlated actual policy API, positive object and complete anonymous reply captures.
//!
//! Refusal status and disabled public policy are checked mechanically. The
//! independent reviewer evaluates full replies and writer review evidence; no
//! substring count proves absence of partial leaks or exclusive writers.
//!
//! ```text
//! capture = {version, method, url, status, headersSha256, bodySha256}
//! policy = {version, providerAccountId, providerBucketName, providerBucketId,
//!           managedDomainCaptureSha256, customDomainsCaptureSha256}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    files,
    selection::{DirectReviewReportKind as Kind, DirectReviewSelection},
};

/// Retained HTTP observation referencing complete response headers and body bytes.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewHttpCapture {
    /// Closed capture version, currently one.
    pub version: u32,
    /// Actual request method, GET for these observations.
    pub method: String,
    /// Actual request URL with no credentials or capability query.
    pub url: String,
    /// Actual response status, without inferred refusal classification.
    pub status: u16,
    /// Exact full retained response header bytes.
    pub headers_sha256: String,
    /// Exact full retained response body bytes.
    pub body_sha256: String,
}

/// Actual managed/custom domain policy API capture references.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewPrivacyPolicyReport {
    /// Closed policy capture version, currently one.
    pub version: u32,
    /// Actual account hosting the selected bucket.
    pub provider_account_id: String,
    /// Actual selected bucket name.
    pub provider_bucket_name: String,
    /// Actual bucket ID returned by the managed-domain API, distinct from its name.
    pub provider_bucket_id: String,
    /// Actual managed-domain API HTTP metadata capture.
    pub managed_domain_capture_sha256: String,
    /// Actual custom-domain API HTTP metadata capture.
    pub custom_domains_capture_sha256: String,
}

/// Independently collected known-object and anonymous denial observations.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewPrivacyReport {
    /// Closed privacy observation version, currently one.
    pub version: u32,
    /// Exact reviewed private namespace.
    pub namespace: String,
    /// Exact installed policy identity.
    pub policy_id: String,
    /// Actual account hosting the selected bucket.
    pub provider_account_id: String,
    /// Actual selected bucket name.
    pub provider_bucket_name: String,
    /// Actual managed public endpoint reported by provider API.
    pub public_endpoint: String,
    /// Exact known positive object key used for all object observations.
    pub object_key: String,
    /// SHA-256 of authenticated positive complete object bytes.
    pub expected_sha256: String,
    /// Actual authenticated positive complete object size.
    pub expected_byte_size: WireInteger,
    /// Actual authenticated exact-object GET HTTP metadata capture.
    pub authenticated_positive_capture_sha256: String,
    /// Actual anonymous managed-public exact-object GET HTTP metadata capture.
    pub anonymous_public_capture_sha256: String,
    /// Actual unauthorized Worker exact-object GET HTTP metadata capture.
    pub unauthorized_worker_capture_sha256: String,
    /// Independently observed writers bypassing the physical guard.
    pub independent_writer_count: WireInteger,
    /// Exact independent writer review document; evaluated by the reviewer.
    pub independent_writer_review_sha256: String,
}

/// Independent assessment of one known runtime mutation path's guard coverage.
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectReviewGuardCoverage {
    /// Actual source and policy evidence show physical guard mediation.
    Guarded,
    /// The reviewer identified a distinct scope outside the selected namespace.
    OutsideSelectedNamespace,
    /// The runtime path can mutate the selected namespace without its guard.
    BypassesGuard,
}

/// Known mutating runtime API and its independently evaluated scope.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewRuntimeMutationApi {
    /// Actual route or provider API identity inspected by the reviewer.
    pub route: String,
    /// Actual namespace targeted by this runtime path.
    pub namespace: String,
    /// Actual physical object key prefix targeted by this runtime path.
    pub physical_key_prefix: String,
    /// Independent coverage assessment, requiring the selected evidence below.
    pub guard_coverage: DirectReviewGuardCoverage,
    /// Exact retained source/policy observation supporting that assessment.
    pub observation_sha256: String,
}

/// Explicit independent writer assessment, separate from provisioning authority.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewWriterAssessment {
    /// Closed assessment version, currently one.
    pub version: u32,
    /// Exact independent reviewer identity selecting the assessment.
    pub reviewer_key_id: String,
    /// Actual account hosting the selected bucket.
    pub provider_account_id: String,
    /// Actual selected bucket name.
    pub provider_bucket_name: String,
    /// Exact installed selected private namespace.
    pub namespace: String,
    /// Actual compiled source reviewed for runtime mutation paths.
    pub source_digest: String,
    /// Exact current script reviewed for runtime mutation paths.
    pub script_version: String,
    /// Independently observed selected-namespace writers bypassing its guard.
    pub independent_writer_count: WireInteger,
    /// Retained evidence of authorized provisioning/key-installation custody.
    pub provisioning_control_plane_custody_evidence: Vec<String>,
    /// Known runtime mutation paths, including protected SDK qualification APIs.
    pub runtime_mutation_apis: Vec<DirectReviewRuntimeMutationApi>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChecksumRejection {
    version: u32,
    run_id: String,
    state: String,
    status: u16,
    provider_code: String,
    response_sha256: String,
    source_sha256: String,
}

fn selected<'a>(files: &'a BTreeMap<String, Vec<u8>>, hash: &str) -> Result<&'a [u8]> {
    files
        .get(hash)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow::anyhow!("complete privacy capture commitment absent"))
}

fn http(files: &BTreeMap<String, Vec<u8>>, hash: &str) -> Result<DirectReviewHttpCapture> {
    let capture: DirectReviewHttpCapture = serde_json::from_slice(selected(files, hash)?)
        .map_err(|_| anyhow::anyhow!("privacy HTTP capture is not a closed supported format"))?;
    let url = url::Url::parse(&capture.url)
        .map_err(|_| anyhow::anyhow!("privacy capture URL invalid"))?;
    ensure!(
        capture.version == 1
            && capture.method == "GET"
            && url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some(),
        "privacy HTTP capture identity invalid"
    );
    selected(files, &capture.headers_sha256)?;
    selected(files, &capture.body_sha256)?;
    Ok(capture)
}

fn api(files: &BTreeMap<String, Vec<u8>>, hash: &str, expected_url: &str) -> Result<Value> {
    let capture = http(files, hash)?;
    ensure!(
        capture.status == 200 && capture.url == expected_url,
        "provider policy API capture audience differs"
    );
    let body: Value = serde_json::from_slice(selected(files, &capture.body_sha256)?)
        .map_err(|_| anyhow::anyhow!("provider policy API reply malformed"))?;
    ensure!(
        body["success"] == true && body["errors"].as_array().is_some_and(Vec::is_empty),
        "provider policy API readback failed"
    );
    Ok(body["result"].clone())
}

fn object_url(
    capture: &DirectReviewHttpCapture,
    origin: &str,
    key: &str,
    bucket: Option<&str>,
) -> Result<()> {
    let mut expected =
        url::Url::parse(origin).map_err(|_| anyhow::anyhow!("privacy endpoint invalid"))?;
    let mut path = expected
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("privacy endpoint cannot address objects"))?;
    path.clear();
    if let Some(bucket) = bucket {
        path.push(bucket);
    }
    for segment in key.split('/') {
        path.push(segment);
    }
    drop(path);
    ensure!(
        expected.as_str() == capture.url,
        "privacy capture addresses a different object or endpoint"
    );
    Ok(())
}

pub(super) fn validate<F>(
    base: &Path,
    selection: &DirectReviewSelection,
    artifact: &DirectWorkerQualificationArtifact,
    take: &mut F,
) -> Result<()>
where
    F: FnMut(Kind, &str) -> Result<Vec<u8>>,
{
    let expected = artifact
        .evidence
        .privacy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("managed privacy evidence absent"))?;
    let sdk = artifact
        .evidence
        .sdk_probe
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("managed SDK evidence absent"))?;
    let mut retained = BTreeMap::new();
    for file in &selection.privacy_files {
        let bytes = files::selected_observation(base, file)?;
        ensure!(
            retained.insert(file.sha256.clone(), bytes).is_none(),
            "privacy retained input duplicated"
        );
    }
    let observed: DirectReviewPrivacyReport =
        serde_json::from_slice(&take(Kind::Privacy, &expected.observation_sha256)?)
            .map_err(|_| anyhow::anyhow!("privacy report is not a closed supported format"))?;
    let policy: DirectReviewPrivacyPolicyReport = serde_json::from_slice(&take(
        Kind::PrivacyPolicy,
        &expected.provider_policy_readback_sha256,
    )?)
    .map_err(|_| anyhow::anyhow!("privacy policy report is not a closed supported format"))?;
    ensure!(
        observed.version == 1
            && policy.version == 1
            && observed.namespace == expected.namespace
            && observed.policy_id == expected.policy_id
            && observed.provider_account_id == expected.provider_account_id
            && observed.provider_bucket_name == expected.provider_bucket_name
            && policy.provider_account_id == expected.provider_account_id
            && policy.provider_bucket_name == expected.provider_bucket_name
            && observed.public_endpoint == expected.public_endpoint
            && observed.independent_writer_count == expected.independent_writer_count
            && valid_direct_digest(&observed.expected_sha256)
            && observed.expected_byte_size.get() > 0
            && !observed.object_key.is_empty()
            && !observed
                .object_key
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "privacy report profile, positive object or writer review differs"
    );
    let writer_review: DirectReviewWriterAssessment = serde_json::from_slice(selected(
        &retained,
        &observed.independent_writer_review_sha256,
    )?)
    .map_err(|_| anyhow::anyhow!("independent writer review document malformed"))?;
    ensure!(
        writer_review.version == 1
            && writer_review.reviewer_key_id == selection.reviewer_key_id
            && writer_review.provider_account_id == expected.provider_account_id
            && writer_review.provider_bucket_name == expected.provider_bucket_name
            && writer_review.namespace == expected.namespace
            && writer_review.source_digest == artifact.source_digest
            && writer_review.script_version == artifact.script_version
            && writer_review.independent_writer_count == observed.independent_writer_count
            && !writer_review
                .provisioning_control_plane_custody_evidence
                .is_empty()
            && !writer_review.runtime_mutation_apis.is_empty(),
        "independent writer assessment audience or evidence incomplete"
    );
    for hash in &writer_review.provisioning_control_plane_custody_evidence {
        selected(&retained, hash)?;
    }
    let mut routes = std::collections::BTreeSet::new();
    for api in &writer_review.runtime_mutation_apis {
        selected(&retained, &api.observation_sha256)?;
        ensure!(
            !api.route.is_empty()
                && !api.namespace.is_empty()
                && !api.physical_key_prefix.is_empty()
                && routes.insert(api.route.as_str())
                && api.guard_coverage != DirectReviewGuardCoverage::BypassesGuard,
            "known runtime path bypasses the selected physical guard or lacks scope evidence"
        );
    }
    ensure!(
        routes.contains("/_internal/storage/direct-upload-sdk-conformance")
            && (artifact.evidence.qualification_limits.is_none()
                || routes.contains("/_internal/storage/direct-upload-qualification")),
        "known mutating qualification APIs absent from independent writer assessment"
    );
    let api_base = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets/{}/domains",
        expected.provider_account_id, expected.provider_bucket_name
    );
    let managed = api(
        &retained,
        &policy.managed_domain_capture_sha256,
        &format!("{api_base}/managed"),
    )?;
    let custom = api(
        &retained,
        &policy.custom_domains_capture_sha256,
        &format!("{api_base}/custom"),
    )?;
    ensure!(
        policy.provider_bucket_id.len() == 32
            && policy
                .provider_bucket_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && managed["bucketId"].as_str() == Some(policy.provider_bucket_id.as_str())
            && managed["enabled"] == false
            && managed["domain"]
                .as_str()
                .is_some_and(|domain| format!("https://{domain}") == expected.public_endpoint)
            && custom["domains"]
                .as_array()
                .is_some_and(|domains| domains.iter().all(|domain| domain["enabled"] == false)),
        "public bucket policy is enabled or addresses different material"
    );
    let positive = http(&retained, &observed.authenticated_positive_capture_sha256)?;
    let anonymous = http(&retained, &observed.anonymous_public_capture_sha256)?;
    let worker = http(&retained, &observed.unauthorized_worker_capture_sha256)?;
    object_url(
        &positive,
        &format!(
            "https://{}.r2.cloudflarestorage.com",
            expected.provider_account_id
        ),
        &observed.object_key,
        Some(&expected.provider_bucket_name),
    )?;
    object_url(
        &anonymous,
        &observed.public_endpoint,
        &observed.object_key,
        None,
    )?;
    object_url(&worker, &artifact.public_origin, &observed.object_key, None)?;
    ensure!(
        positive.status == 200
            && positive.body_sha256 == observed.expected_sha256
            && u64::try_from(selected(&retained, &positive.body_sha256)?.len())?
                == observed.expected_byte_size.get()
            && anonymous.status == expected.public_read_rejection_status
            && worker.status == expected.worker_namespace_rejection_status
            && anonymous.body_sha256 != positive.body_sha256
            && worker.body_sha256 != positive.body_sha256,
        "privacy captures lack correlated positive bytes and actual denied reads"
    );
    // The SDK commitment is canonical JSON, independent of retained file formatting.
    let rejection_bytes = take(
        Kind::SdkChecksumRejection,
        &sdk.direct_s3_checksum_rejection_sha256,
    )?;
    let rejection: ChecksumRejection = serde_json::from_slice(&rejection_bytes)
        .map_err(|_| anyhow::anyhow!("direct checksum rejection report malformed"))?;
    ensure!(
        files::digest(&serde_json::to_vec(&rejection)?) == sdk.direct_s3_checksum_rejection_sha256
            && rejection.version == 1
            && rejection.run_id == sdk.original.run_id
            && rejection.state == "negative"
            && rejection.status == 400
            && rejection.provider_code == "BadDigest"
            && valid_direct_digest(&rejection.source_sha256),
        "direct checksum refusal was not actually observed"
    );
    let response = selected(&retained, &rejection.response_sha256)?;
    ensure!(
        std::str::from_utf8(response)
            .ok()
            .is_some_and(|body| body.contains("<Code>BadDigest</Code>")),
        "complete direct checksum refusal body differs"
    );
    Ok(())
}
