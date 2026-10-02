//! Bounded request-only Copy observations for a genuinely pending exchange.
//!
//! The original fingerprint uses the production shared method. This does not
//! authenticate the envelope, prove a current SQL claim, assess expiry against
//! a current clock, or grant dispatch/settlement. Raw request custody and actual
//! post-auth source-point lifetime observations remain separate joins.
//!
//! ```text
//! storage-body-codec copy-request <private-selection.json>
//! selection = {version, sourceDigest, deploymentId, originalRequest, receivedRequest}
//! result = {version, scope, sourceDigest, requestSha256, requestBytes,
//!           originalSha256, codecSourceSha256, request}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::copy::control::{
    ExternalCopyRequest, MAX_EXTERNAL_COPY_CONTROL_BYTES,
};
use serde::{Deserialize, Serialize};

use super::files::{self, BodyFile};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    version: u32,
    source_digest: String,
    deployment_id: String,
    original_request: BodyFile,
    received_request: BodyFile,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    version: u32,
    scope: &'static str,
    source_digest: String,
    request_sha256: String,
    request_bytes: String,
    original_sha256: String,
    codec_source_sha256: String,
    request: ExternalCopyRequest,
}

fn decode(body: &[u8], deployment: &str) -> Result<ExternalCopyRequest> {
    ensure!(
        body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
        "excessive copy request"
    );
    let request: ExternalCopyRequest = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&request)? == body,
        "noncanonical copy request"
    );
    request.validate_observation_shape(deployment)?;
    Ok(request)
}

/// Observes one exact original/received request without accepting its authority.
///
/// # Errors
/// Returns an error for invalid selection, private file custody or commitments,
/// changed original/received bytes, excessive or noncanonical JSON, unknown
/// fields, malformed intrinsic pins, or a foreign deployment.
pub(super) fn inspect(selection: Selection) -> Result<Observation> {
    ensure!(
        selection.version == 1 && files::valid_digest(&selection.source_digest),
        "invalid pending copy selection"
    );
    for reference in [&selection.original_request, &selection.received_request] {
        ensure!(
            reference.byte_size.parse::<usize>()? <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "pending copy request exceeds its own bound"
        );
    }
    let mut consumed = 0;
    let original = files::read(&selection.original_request, &mut consumed)?;
    let received = files::read(&selection.received_request, &mut consumed)?;
    ensure!(original == received, "pending copy original differs");
    let request = decode(&received, &selection.deployment_id)?;
    let mut source = Vec::new();
    for file in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("files.rs").as_slice(),
        include_bytes!("classify.rs").as_slice(),
        include_bytes!("storage_work.rs").as_slice(),
        include_bytes!("ingress.rs").as_slice(),
        include_bytes!("controls.rs").as_slice(),
        include_bytes!("copy_request.rs").as_slice(),
        include_bytes!("copy_closed.rs").as_slice(),
    ] {
        source.extend_from_slice(file);
    }
    Ok(Observation {
        version: 1,
        scope: "intrinsic_unauthenticated_pending_copy_request",
        source_digest: selection.source_digest,
        request_sha256: files::digest(&received),
        request_bytes: received.len().to_string(),
        original_sha256: request.original.fingerprint()?,
        codec_source_sha256: files::digest(&source),
        request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::storage_authority::external_object::copy::control::{CopyClaim, CopyControl};
    use aos_hub_core::storage_authority::{
        external_object::copy::ExternalCopyOriginal, lease::LeaseInteger,
    };
    use aos_hub_core::storage_work::{
        StorageCredentialSelector, StorageWorkOperation, StorageWorkPlan,
    };

    #[test]
    fn canonical_pending_request_shares_fingerprint_and_refuses_malformed_or_foreign() {
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
        })).unwrap();
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "e".repeat(32),
            deployment_id: "deployment".into(),
            issued_at: 100,
            expires_at: 130,
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
                expires_at: LeaseInteger::new(200).unwrap(),
            },
            plan,
            CopyControl::Advance,
            100,
        )
        .unwrap();
        let body = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode(&body, "deployment")
                .unwrap()
                .original
                .fingerprint()
                .unwrap(),
            original.fingerprint().unwrap()
        );
        assert!(decode(&body, "foreign").is_err());
        let mut changed = serde_json::to_value(&request).unwrap();
        changed["invented_authority"] = serde_json::json!(true);
        assert!(decode(&serde_json::to_vec(&changed).unwrap(), "deployment").is_err());
        let mut noncanonical = body.clone();
        noncanonical.push(b' ');
        assert!(decode(&noncanonical, "deployment").is_err());
    }
}
