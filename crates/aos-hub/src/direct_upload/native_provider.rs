//! Native S3 multipart controls and bounded streaming verification.
//!
//! Client parts use signed provider URLs. Only control documents enter this
//! adapter during upload; verification explicitly streams the completed object
//! in Native mode. Hybrid keeps its existing Worker executor.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    direct_upload::{
        DirectChecksumAlgorithm, DirectManifestPart, DirectPart, DirectPlacementRef,
        DirectUploadIntent,
    },
    s3surface::{self, S3Surface},
    sigv4::{DirectPartCopySource, DirectSignedProviderRequest},
};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};

/// Positive provider identity; the ETag is never interpreted as a content hash.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeObject {
    /// Provider's strong ETag used only as a conditional-read identity.
    pub etag: String,
    /// Actual version identifier when the provider enables versioning.
    pub provider_version: Option<String>,
}

/// Full-object measurement obtained by consuming a conditional read to EOF.
pub(crate) struct NativeVerifiedObject {
    /// SHA-256 of all bytes consumed to EOF.
    pub sha256: String,
    /// Exact measured object length.
    pub byte_size: u64,
    /// Bounded metadata bytes, collected only for metadata objects.
    pub metadata: Vec<u8>,
}

/// Signs provider control operations and measures closed objects with bounded memory.
pub(crate) struct NativeS3Upload {
    surface: S3Surface,
    http: reqwest::Client,
}

impl NativeS3Upload {
    /// Wraps an authorized private surface and the hardened Native HTTP client.
    pub(crate) fn new(surface: S3Surface, http: reqwest::Client) -> Self {
        Self { surface, http }
    }

    /// Returns the configured provider origin without its bearer query string.
    ///
    /// # Errors
    /// Returns an error for an unsafe path or invalid provider coordinates.
    pub(crate) fn origin(&self, path: &str) -> Result<String> {
        let url = self.surface.object_url(s3surface::Method::Head, path, 1)?;
        Ok(url::Url::parse(&url)?.origin().ascii_serialization())
    }

    /// Signs one exact UploadPart with its size, checksum and retained lifetime.
    ///
    /// # Errors
    /// Returns an error for invalid geometry, credentials or signing inputs.
    pub(crate) fn part(
        &self,
        path: &str,
        upload_id: &str,
        part: &DirectPart,
        now: i64,
        ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.surface
            .direct_upload_part_request(path, upload_id, part, now, ttl)
    }

    /// Creates a multipart upload and validates the returned bucket and key.
    ///
    /// # Errors
    /// Returns an error for failed transport, refusal or malformed coordinates.
    pub(crate) async fn create(&self, path: &str, now: i64) -> Result<String> {
        let request = self.surface.direct_create_multipart_request(
            path,
            DirectChecksumAlgorithm::Md5,
            now,
            30,
        )?;
        let response = self
            .send(reqwest::Method::POST, request, Some(Vec::new()))
            .await?;
        let xml = self.xml(response).await?;
        let physical = self.surface.physical_key(path)?;
        let (bucket, key) = physical
            .split_once('/')
            .context("missing multipart bucket")?;
        s3surface::parse_direct_create_multipart(&xml, bucket, key)
    }

    /// Closes an exact multipart manifest and retains its positive object identity.
    ///
    /// # Errors
    /// Returns an error for inconsistent manifests or a missing positive closure.
    pub(crate) async fn complete(
        &self,
        path: &str,
        upload_id: &str,
        intent: &DirectUploadIntent,
        placement: &DirectPlacementRef,
        parts: &[DirectManifestPart],
        now: i64,
    ) -> Result<NativeObject> {
        let body = s3surface::direct_complete_multipart_xml(intent, placement, parts)?;
        let url = self
            .surface
            .multipart_url("complete", path, Some(upload_id), None, now)?;
        let response = self
            .send(
                reqwest::Method::POST,
                unsigned_headers(url),
                Some(body.into_bytes()),
            )
            .await?;
        let version = provider_version(&response)?;
        let physical = self.surface.physical_key(path)?;
        let (bucket, key) = physical
            .split_once('/')
            .context("missing completed object bucket")?;
        let receipt =
            s3surface::parse_direct_complete_multipart(&self.xml(response).await?, bucket, key)?;
        Ok(NativeObject {
            etag: receipt.etag,
            provider_version: version,
        })
    }

    /// Aborts the retained upload only on a positive provider response.
    ///
    /// # Errors
    /// Returns an error for failed transport, ambiguous absence or refusal.
    pub(crate) async fn abort(&self, path: &str, upload_id: &str, now: i64) -> Result<()> {
        let url = self
            .surface
            .multipart_url("abort", path, Some(upload_id), None, now)?;
        // NoSuchUpload is ambiguous: a completed object may remain. Require a
        // positive abort, keeping uncertain outcomes in the SQL journal.
        self.send(reqwest::Method::DELETE, unsigned_headers(url), None)
            .await?;
        Ok(())
    }

    /// Deletes a private stage conditionally without touching a changed object.
    ///
    /// # Errors
    /// Returns an error for unsafe identity, failed transport or refusal.
    pub(crate) async fn delete(&self, path: &str, etag: &str, now: i64) -> Result<()> {
        let url = self
            .surface
            .object_url(s3surface::Method::Delete, path, now)?;
        crate::fetch::is_safe_remote_url(&url)?;
        let response = self
            .http
            .delete(&url)
            .header(reqwest::header::IF_MATCH, etag)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("staging cleanup transport failed"))?;
        ensure!(
            response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND,
            "staging cleanup refused"
        );
        Ok(())
    }

    /// Writes an actual zero-byte object conditional on the observed prior identity.
    ///
    /// # Errors
    /// Returns an error for a changed prior object, failed transport or missing ETag.
    pub(crate) async fn empty(
        &self,
        path: &str,
        prior_etag: Option<&str>,
        now: i64,
    ) -> Result<NativeObject> {
        // This URL stays inside Native. The provider validates the empty body
        // and the conditional write; clients never receive an unrestricted PUT.
        let condition = match prior_etag {
            Some(etag) => (
                "if-match",
                aos_hub_core::surface_write::strong_if_match_etag(etag)?,
            ),
            None => ("if-none-match", "*".to_owned()),
        };
        let request = DirectSignedProviderRequest {
            url: self.surface.object_url(s3surface::Method::Put, path, now)?,
            required_headers: [
                ("content-length", "0".to_owned()),
                ("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==".to_owned()),
                condition,
            ]
            .into_iter()
            .map(
                |(name, value)| aos_hub_core::direct_upload::DirectRequiredHeader {
                    name: name.to_owned(),
                    value,
                },
            )
            .collect(),
        };
        let response = self
            .send(reqwest::Method::PUT, request, Some(Vec::new()))
            .await?;
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .context("empty PUT response omitted ETag")?
            .to_str()?;
        Ok(NativeObject {
            etag: aos_hub_core::surface_write::strong_if_match_etag(etag)?,
            provider_version: provider_version(&response)?,
        })
    }

    /// Streams the retained object to EOF and checks its complete SHA-256 and size.
    ///
    /// # Errors
    /// Returns an error for changed identity, stream failure, content mismatch or
    /// excessive metadata. Composite provider checksums are never consulted.
    pub(crate) async fn verify(
        &self,
        path: &str,
        object: &NativeObject,
        intent: &DirectUploadIntent,
        collect_metadata: bool,
        now: i64,
    ) -> Result<NativeVerifiedObject> {
        let request = self.surface.closed_stage_read_request(
            path,
            &object.etag,
            object.provider_version.as_deref(),
            now,
            300,
        )?;
        let response = self.send(reqwest::Method::GET, request, None).await?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "verification requires full object response"
        );
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .context("verification response omitted ETag")?
            .to_str()?;
        ensure!(etag == object.etag, "verification object changed");
        if let Some(version) = &object.provider_version {
            ensure!(
                provider_version(&response)?.as_ref() == Some(version),
                "verification version changed"
            );
        }

        let mut stream = response.bytes_stream();
        let mut digest = Sha256::new();
        let mut byte_size = 0_u64;
        let mut metadata = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|_| anyhow::anyhow!("uploaded object verification stream failed"))?;
            byte_size = byte_size
                .checked_add(u64::try_from(chunk.len())?)
                .context("verification size overflow")?;
            ensure!(byte_size <= intent.byte_size.get(), NativeIntegrityMismatch);
            digest.update(&chunk);
            if collect_metadata {
                ensure!(
                    byte_size <= 256 * 1024,
                    "upload metadata exceeds parser limit"
                );
                metadata.extend_from_slice(&chunk);
            }
        }
        let sha256 = hex::encode(digest.finalize());
        ensure!(
            byte_size == intent.byte_size.get() && sha256 == intent.expected_sha256,
            NativeIntegrityMismatch
        );
        Ok(NativeVerifiedObject {
            sha256,
            byte_size,
            metadata,
        })
    }

    /// Reads bounded provider metadata for a conditional write or verification.
    ///
    /// # Errors
    /// Returns an error for failed transport or missing or unsafe object identity.
    pub(crate) async fn head(&self, path: &str, now: i64) -> Result<Option<NativeObject>> {
        let url = self
            .surface
            .object_url(s3surface::Method::Head, path, now)?;
        crate::fetch::is_safe_remote_url(&url)?;
        let response = self
            .http
            .head(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("baseline metadata transport failed"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(response.status().is_success(), "baseline metadata refused");
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .context("baseline omitted ETag")?
            .to_str()?
            .to_owned();
        Ok(Some(NativeObject {
            etag: aos_hub_core::surface_write::strong_if_match_etag(&etag)?,
            provider_version: provider_version(&response)?,
        }))
    }

    /// Measures a prior cache object for existing quota and replacement accounting.
    ///
    /// # Errors
    /// Returns an error for failed transport, changed identity or excessive size.
    pub(crate) async fn inspect(&self, path: &str, now: i64) -> Result<Option<NativeBaseline>> {
        let Some(object) = self.head(path, now).await? else {
            return Ok(None);
        };
        let etag = object.etag.clone();
        let request = self.surface.closed_stage_read_request(
            path,
            &etag,
            object.provider_version.as_deref(),
            now,
            300,
        )?;
        let response = self.send(reqwest::Method::GET, request, None).await?;
        ensure!(
            response.status() == reqwest::StatusCode::OK
                && response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    == Some(etag.as_str()),
            "baseline object changed"
        );
        let mut stream = response.bytes_stream();
        let mut digest = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| anyhow::anyhow!("baseline object stream failed"))?;
            size = size
                .checked_add(u64::try_from(chunk.len())?)
                .context("baseline size overflow")?;
            ensure!(
                size <= aos_hub_core::direct_upload::MAX_DIRECT_OBJECT_BYTES,
                "baseline exceeds supported size"
            );
            digest.update(&chunk);
        }
        Ok(Some(NativeBaseline {
            size: i64::try_from(size)?,
            sha256: hex::encode(digest.finalize()),
            etag,
        }))
    }

    /// Copies one authorized stage range into the retained final multipart upload.
    ///
    /// # Errors
    /// Returns an error for invalid ranges, failed transport or invalid provider XML.
    pub(crate) async fn copy_part(
        &self,
        source_path: &str,
        destination_path: &str,
        destination_upload: &str,
        part: &DirectPart,
        now: i64,
    ) -> Result<String> {
        let physical = self.surface.physical_key(source_path)?;
        let (bucket, key) = physical
            .split_once('/')
            .context("missing copy source bucket")?;
        let request = self.surface.direct_upload_part_copy_request(
            destination_path,
            destination_upload,
            part.part_number,
            &DirectPartCopySource {
                bucket,
                full_key: key,
                first_byte: part.offset.get(),
                last_byte: part
                    .offset
                    .get()
                    .checked_add(part.byte_size.get())
                    .and_then(|end| end.checked_sub(1))
                    .context("invalid copy range")?,
            },
            now,
            30,
        )?;
        let response = self.send(reqwest::Method::PUT, request, None).await?;
        Ok(s3surface::parse_direct_upload_part_copy(&self.xml(response).await?)?.etag)
    }

    async fn send(
        &self,
        method: reqwest::Method,
        signed: DirectSignedProviderRequest,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        crate::fetch::is_safe_remote_url(&signed.url)?;
        let timeout = if method == reqwest::Method::GET {
            3600
        } else {
            30
        };
        let mut request = self
            .http
            .request(method, &signed.url)
            .timeout(std::time::Duration::from_secs(timeout));
        for header in &signed.required_headers {
            request = request.header(&header.name, &header.value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        // The configured client disables redirects. Bearer URLs and provider
        // response bodies must never be attached to public error messages.
        let response = request
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("storage control transport failed"))?;
        ensure!(
            response.status().is_success(),
            "storage control request refused"
        );
        Ok(response)
    }

    async fn xml(&self, response: reqwest::Response) -> Result<String> {
        crate::fetch::read_text_capped(
            response,
            s3surface::MAX_DIRECT_MULTIPART_RESPONSE_BYTES as u64,
            "multipart control response",
        )
        .await
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains a prior cache object's independently measured accounting identity.
pub(crate) struct NativeBaseline {
    /// Full measured length used by the cache write ticket.
    pub size: i64,
    /// Full measured content hash, never a composite provider checksum.
    pub sha256: String,
    /// Strong provider identity for the existing object.
    pub etag: String,
}

#[derive(Debug, thiserror::Error)]
#[error("uploaded object failed full SHA-256 or size verification")]
/// Marks permanent content mismatch separately from retryable transport failure.
pub(crate) struct NativeIntegrityMismatch;

fn unsigned_headers(url: String) -> DirectSignedProviderRequest {
    DirectSignedProviderRequest {
        url,
        required_headers: Vec::new(),
    }
}

fn provider_version(response: &reqwest::Response) -> Result<Option<String>> {
    Ok(response
        .headers()
        .get("x-amz-version-id")
        .map(|value| -> Result<String> {
            let value = value.to_str()?;
            ensure!(
                !value.is_empty() && value.len() <= 2048,
                "invalid provider version"
            );
            Ok(value.to_owned())
        })
        .transpose()?
        .filter(|version| version != "null"))
}
