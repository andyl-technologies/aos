//! Purpose probes at the exact original provider, with final cutoff checks.

use anyhow::{ensure, Result};
use aos_hub_core::{
    s3surface::{Method as S3Method, S3Surface},
    storage_work::binding_custody::StorageCredentialCustodyProbe,
    topology_probe::StorageCredentialProbeEvidence,
};
use worker::{Fetch, Method, Request, RequestInit, RequestRedirect, Response};

pub(super) async fn execute(
    surface: &S3Surface,
    request: &StorageCredentialCustodyProbe,
) -> Result<StorageCredentialProbeEvidence> {
    let reference = &request.snapshot.credentials[0];
    let path = format!(
        ".aos/credential-probes/{}/{}/{}",
        reference.purpose, reference.generation, request.probe_token
    );
    let mut evidence = serde_json::Map::new();
    let now = aos_hub_core::clock::now_unix_secs();
    let valid = match reference.purpose.as_str() {
        "read" | "presign" => {
            let response = send(
                request,
                &surface.object_url(S3Method::Get, &path, now)?,
                Method::Get,
            )
            .await?;
            let status = response.status_code();
            evidence.insert("getStatus".into(), status.into());
            status == 404 || (200..300).contains(&status)
        }
        "list" => {
            let response = send(request, &surface.list_url(None, 1, now)?, Method::Get).await?;
            let status = response.status_code();
            evidence.insert("listStatus".into(), status.into());
            (200..300).contains(&status)
        }
        "delete" => {
            let response = send(
                request,
                &surface.object_url(S3Method::Delete, &path, now)?,
                Method::Delete,
            )
            .await?;
            let status = response.status_code();
            evidence.insert("deleteStatus".into(), status.into());
            (200..300).contains(&status)
        }
        "write" => {
            let recovery = send(
                request,
                &surface.list_multipart_uploads_url(&path, now)?,
                Method::Get,
            )
            .await?;
            let recovery_status = recovery.status_code();
            evidence.insert("multipartRecoveryListStatus".into(), recovery_status.into());
            ensure!(
                (200..300).contains(&recovery_status),
                "credential probe recovery listing refused"
            );
            let bytes = crate::direct_digest::read_bounded_native(recovery, 1024 * 1024).await?;
            let uploads =
                surface.parse_exact_multipart_uploads(&path, std::str::from_utf8(&bytes)?)?;
            evidence.insert("recoveredMultipartUploads".into(), uploads.len().into());
            for upload_id in uploads {
                let url = surface.multipart_url(
                    "abort",
                    &path,
                    Some(&upload_id),
                    None,
                    aos_hub_core::clock::now_unix_secs(),
                )?;
                let response = send(request, &url, Method::Delete).await?;
                ensure!(
                    (200..300).contains(&response.status_code()),
                    "credential probe known recovery abort refused"
                );
            }
            let url = surface.multipart_url(
                "create",
                &path,
                None,
                None,
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let response = send(request, &url, Method::Post).await?;
            let status = response.status_code();
            evidence.insert("multipartCreateStatus".into(), status.into());
            if (200..300).contains(&status) {
                let bytes =
                    crate::direct_digest::read_bounded_native(response, 1024 * 1024).await?;
                let upload_id = aos_hub_core::s3surface::parse_multipart_upload_id(
                    std::str::from_utf8(&bytes)?,
                )?;
                let url = surface.multipart_url(
                    "abort",
                    &path,
                    Some(&upload_id),
                    None,
                    aos_hub_core::clock::now_unix_secs(),
                )?;
                let response = send(request, &url, Method::Delete).await?;
                let status = response.status_code();
                evidence.insert("multipartAbortStatus".into(), status.into());
                (200..300).contains(&status)
            } else {
                false
            }
        }
        _ => anyhow::bail!("credential probe purpose unsupported"),
    };
    Ok(StorageCredentialProbeEvidence {
        valid,
        conditional_writes_supported: false,
        error: (!valid).then(|| "credential purpose rejected by provider".into()),
        evidence: serde_json::Value::Object(evidence),
    })
}

async fn send(
    original: &StorageCredentialCustodyProbe,
    url: &str,
    method: Method,
) -> Result<Response> {
    aos_hub_core::url_guard::is_safe_remote_url(url)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(url, &init)?;
    original.validate(
        &original.snapshot.deployment_id,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    crate::direct_upload::provider_capacity::record_dispatch();
    Ok(Fetch::Request(request).send().await?)
}
