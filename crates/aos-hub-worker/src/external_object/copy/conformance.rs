//! Closed controlled-provider exercise of actual copy stream bytes and cancellation.
//!
//! This leaf is absent from default builds. It provides no production admission,
//! lease, configured provider contract, guard settlement or business completion.

use anyhow::{ensure, Result};
use aos_hub_core::{
    db::OciSha256State,
    direct_upload::{DirectChecksumAlgorithm, DirectPart, DirectPartChecksum, WireInteger},
    sigv4::{presign_direct_upload_part, presign_versioned_conditional_range, PresignParams},
    storage_authority::{external_object::copy::CopySourceObject, lease::LeaseInteger},
};
use base64::Engine as _;
use serde::Deserialize;
use worker::{Request, Response};

use super::{
    stream::{hash_range, upload_range, SourceRange},
    window::DispatchWindow,
};

const BYTES: u64 = 5 * 1024 * 1024 + 7;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    scenario: String,
}

/// Runs a closed fixture with production stream helpers and no business authority.
///
/// # Errors
/// Returns an error for malformed request framing or response construction.
pub(crate) async fn fetch(mut request: Request) -> worker::Result<Response> {
    match exercise(&mut request).await {
        Ok(value) => Response::from_json(&value),
        Err(_) => Response::error("external copy stream fixture refused", 409),
    }
}

async fn exercise(request: &mut Request) -> Result<serde_json::Value> {
    let body = crate::hybrid::read_bounded_body(request, 1024)
        .await?
        .ok_or_else(|| anyhow::anyhow!("copy fixture control oversized"))?;
    let input: Input = serde_json::from_slice(&body)?;
    ensure!(
        matches!(
            input.scenario.as_str(),
            "positive"
                | "replacement"
                | "wrong_second"
                | "truncate"
                | "early_reject"
                | "stall"
                | "cancel"
        ),
        "copy fixture scenario unknown"
    );
    let signal = request.inner().signal();
    let now = aos_hub_core::clock::now_unix_secs();
    let window = DispatchWindow {
        expires_at: now + if input.scenario == "stall" { 2 } else { 25 },
        uncertainty: 0,
        client_signal: &signal,
        fresh: &|| Ok(()),
        lifetime: super::lifetime::Lifetime::new(signal.clone())?,
    };
    crate::direct_upload::provider_capacity::configure(3)?;
    let capacity = crate::direct_upload::provider_capacity::acquire_class_checked(
        2,
        crate::direct_upload::provider_capacity::Class::Bulk,
        &|| window.check(),
    )
    .await?;
    window.lifetime.retain_capacity(capacity)?;
    let source = CopySourceObject {
        provider_version: "controlled-source-version".into(),
        etag: "\"controlled-source-tag\"".into(),
        bytes: LeaseInteger::new(BYTES as i64)?,
    };
    let range = SourceRange {
        source: &source,
        offset: 0,
        bytes: BYTES,
    };
    let path = format!("/fixture/{}/source", input.scenario);
    let date = aos_hub_core::sigv4::amz_date_from_unix(now);
    let parameters = PresignParams {
        access_key: "controlled-fixture-access",
        secret_key: "controlled-fixture-secret",
        region: "controlled-fixture-region",
        service: "s3",
        scheme: "https",
        host: "copy-fixture.invalid",
        path: &path,
        expires_secs: 25,
        amz_date: &date,
    };
    let read = presign_versioned_conditional_range(&parameters, &source, 0, BYTES, 25)?;
    let initial = OciSha256State::initial();
    let first = hash_range(&read, &range, initial.clone(), &window).await?;
    let part = DirectPart {
        part_number: 1,
        offset: WireInteger::new(0),
        byte_size: WireInteger::new(BYTES),
        sha256: first.sha256.clone(),
        checksum: DirectPartChecksum {
            algorithm: DirectChecksumAlgorithm::Sha256,
            value: base64::engine::general_purpose::STANDARD.encode(hex::decode(&first.sha256)?),
        },
    };
    let destination = format!("/fixture/{}/destination", input.scenario);
    let write_parameters = PresignParams {
        path: &destination,
        ..parameters
    };
    let write =
        presign_direct_upload_part(&write_parameters, "controlled-positive-upload", &part, 25)?;
    let (etag, actual) = upload_range(&read, &write, &range, initial, &first, &window).await?;
    Ok(serde_json::json!({
        "etag": etag,
        "sha256": actual.sha256,
        "bytes": actual.source_state.total_bytes,
        "providerPeak": crate::direct_upload::provider_capacity::observation().peak_active,
        "nativeSignalCloses": super::lifetime::signal_closes(),
        "scope": "controlled source bytes and native transfer only"
    }))
}
