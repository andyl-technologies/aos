//! Sequential bounded experiments preserving each dependent provider phase.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{DirectChecksumAlgorithm, DirectPart, DirectPartChecksum, WireInteger},
    s3surface::{self, Method},
    sigv4::{DirectPartCopySource, DirectSignedProviderRequest},
    surface_write::PartTag,
};
use base64::Engine as _;
use md5::{Digest as _, Md5};

use super::{
    config::Loaded,
    journal::{digest, write_new, Journal},
    model::{Intent, ObjectReceipt, Original, PartReceipt, Phase, Report, ResultKind},
    transport::{self, Request, Response},
};

const FIRST_PART: usize = 5 * 1024 * 1024;
const OBJECT_SIZE: usize = FIRST_PART + 32 * 1024;
const METADATA_LIMIT: u64 = 512 * 1024;

fn now() -> i64 {
    aos_hub_core::clock::now_unix_secs()
}

fn ordinary(method: reqwest::Method, url: String, body: Option<Vec<u8>>) -> Request {
    Request {
        method,
        url,
        headers: Vec::new(),
        body,
    }
}

fn direct(request: DirectSignedProviderRequest, body: Option<Vec<u8>>) -> Request {
    Request {
        method: reqwest::Method::PUT,
        url: request.url,
        headers: request
            .required_headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect(),
        body,
    }
}

fn strong_etag(value: &str) -> Result<String> {
    ensure!(
        !value.contains("://") && !value.to_ascii_lowercase().contains("x-amz-"),
        "provider ETag cannot be retained safely"
    );
    aos_hub_core::surface_write::strong_if_match_etag(value)
}

fn xml(response: &Response) -> Result<&str> {
    std::str::from_utf8(&response.body)
        .map_err(|_| anyhow::anyhow!("provider receipt is not valid XML text"))
}

fn successful(response: &Response) -> Result<()> {
    ensure!(
        (200..300).contains(&response.status),
        "provider did not return a positive receipt"
    );
    Ok(())
}

struct Probe {
    loaded: Loaded,
    journal: Journal,
}

impl Probe {
    async fn create(&mut self, phase: Phase, key: &str) -> Result<String> {
        let request = ordinary(
            reqwest::Method::POST,
            self.loaded
                .surface
                .multipart_url("create", key, None, None, now())?,
            Some(Vec::new()),
        );
        let exchange = transport::dispatch(
            &self.loaded,
            &self.journal,
            Intent::new(phase, key),
            request,
        )
        .await?;
        let (exchange, response) = exchange.read(&self.journal, METADATA_LIMIT, true).await?;
        successful(&response)?;
        let upload = s3surface::parse_direct_create_multipart(
            xml(&response)?,
            &self.loaded.bucket,
            &self.full_key(key),
        )?;
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            None,
            None,
        )?;
        Ok(upload)
    }

    fn full_key(&self, key: &str) -> String {
        format!("{}/{}", self.loaded.prefix, key)
    }

    fn part(
        &self,
        key: &str,
        upload: &str,
        number: u32,
        offset: u64,
        bytes: &[u8],
    ) -> Result<Request> {
        let part = DirectPart {
            part_number: number,
            offset: WireInteger::new(offset),
            byte_size: WireInteger::new(bytes.len() as u64),
            sha256: digest(bytes),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Md5,
                value: base64::engine::general_purpose::STANDARD.encode(Md5::digest(bytes)),
            },
        };
        // The exact direct request binds byte length and Content-MD5. Retain
        // its commitment, never its URL, before sending either test body.
        Ok(direct(
            self.loaded
                .surface
                .direct_upload_part_request(key, upload, &part, now(), 900)?,
            Some(bytes.to_vec()),
        ))
    }

    fn part_intent(
        &self,
        phase: Phase,
        key: &str,
        upload: &str,
        number: u32,
        offset: u64,
        bytes: &[u8],
        request: &Request,
    ) -> Intent {
        let mut intent = Intent::new(phase, key);
        intent.upload_id_sha256 = Some(digest(upload.as_bytes()));
        intent.part_number = Some(number);
        intent.first_byte = Some(offset);
        intent.size = bytes.len() as u64;
        intent.expected_sha256 = Some(digest(bytes));
        intent.checksum_md5_base64 = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-md5"))
            .map(|(_, value)| value.clone());
        intent
    }

    async fn upload(
        &mut self,
        phase: Phase,
        key: &str,
        upload: &str,
        number: u32,
        offset: u64,
        bytes: &[u8],
        request: Request,
    ) -> Result<PartReceipt> {
        let intent = self.part_intent(phase, key, upload, number, offset, bytes, &request);
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange.read(&self.journal, METADATA_LIMIT, true).await?;
        successful(&response)?;
        ensure!(
            response.body.is_empty(),
            "provider UploadPart returned an unexpected body"
        );
        let etag = strong_etag(
            response
                .etag
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("provider part receipt omitted ETag"))?,
        )?;
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            Some((bytes.len() as u64, digest(bytes))),
            None,
        )?;
        Ok(PartReceipt {
            part_number: number,
            etag,
        })
    }

    async fn refusal(
        &mut self,
        intent: Intent,
        request: Request,
        codes: &[&str],
        statuses: &[u16],
    ) -> Result<()> {
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange.read(&self.journal, METADATA_LIMIT, true).await?;
        let code = transport::denied(&response, codes, statuses)?;
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Denied,
            None,
            Some(code),
        )
    }

    async fn complete(
        &mut self,
        phase: Phase,
        key: &str,
        upload: &str,
        parts: &[PartReceipt],
    ) -> Result<String> {
        let tags: Vec<_> = parts
            .iter()
            .map(|part| PartTag {
                part_number: part.part_number,
                etag: part.etag.clone(),
            })
            .collect();
        let manifest = s3surface::complete_multipart_xml(&tags)?.into_bytes();
        let mut intent = Intent::new(phase, key);
        intent.upload_id_sha256 = Some(digest(upload.as_bytes()));
        intent.manifest = parts.to_vec();
        let request = ordinary(
            reqwest::Method::POST,
            self.loaded
                .surface
                .multipart_url("complete", key, Some(upload), None, now())?,
            Some(manifest),
        );
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange.read(&self.journal, METADATA_LIMIT, true).await?;
        successful(&response)?;
        let receipt = s3surface::parse_direct_complete_multipart(
            xml(&response)?,
            &self.loaded.bucket,
            &self.full_key(key),
        )?;
        self.loaded.public_receipt(&receipt.etag)?;
        let etag = strong_etag(&receipt.etag)?;
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            None,
            None,
        )?;
        Ok(etag)
    }

    async fn head(
        &mut self,
        phase: Phase,
        key: &str,
        completed_etag: &str,
        expected: &[u8],
    ) -> Result<ObjectReceipt> {
        let mut intent = Intent::new(phase, key);
        intent.source_etag = Some(completed_etag.into());
        let request = ordinary(
            reqwest::Method::HEAD,
            self.loaded.surface.object_url(Method::Head, key, now())?,
            None,
        );
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange.read(&self.journal, 0, false).await?;
        successful(&response)?;
        let etag = strong_etag(
            response
                .etag
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("provider HEAD omitted ETag"))?,
        )?;
        ensure!(
            etag == completed_etag && response.content_length == Some(expected.len() as u64),
            "provider HEAD differs from the original completed object"
        );
        let receipt = ObjectReceipt {
            key: self.full_key(key),
            etag,
            provider_version: response.version.clone(),
            size: expected.len() as u64,
            sha256: digest(expected),
        };
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            None,
            None,
        )?;
        Ok(receipt)
    }

    async fn read(
        &mut self,
        phase: Phase,
        key: &str,
        original: &ObjectReceipt,
        range: Option<(u64, u64)>,
        expected: &[u8],
        retain: bool,
    ) -> Result<Vec<u8>> {
        let mut intent = Intent::new(phase, key);
        intent.source_etag = Some(original.etag.clone());
        intent.first_byte = range.map(|value| value.0);
        intent.size = expected.len() as u64;
        intent.expected_sha256 = Some(digest(expected));
        let mut request = ordinary(
            reqwest::Method::GET,
            self.loaded.surface.object_url(Method::Get, key, now())?,
            None,
        );
        request
            .headers
            .push(("if-match".into(), original.etag.clone()));
        if let Some((first, last)) = range {
            request
                .headers
                .push(("range".into(), format!("bytes={first}-{last}")));
        }
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange
            .read(&self.journal, expected.len() as u64, retain)
            .await?;
        ensure!(
            response.status == if range.is_some() { 206 } else { 200 }
                && response.etag.as_deref() == Some(&original.etag)
                && response.version == original.provider_version
                && response.bytes == expected.len() as u64
                && response.sha256 == digest(expected),
            "provider conditional read changed the original object identity or content"
        );
        if let Some((first, last)) = range {
            ensure!(
                response.content_range.as_deref()
                    == Some(&format!("bytes {first}-{last}/{}", original.size)),
                "provider range response differs from its exact selected bytes"
            );
        }
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            Some((response.bytes, response.sha256.clone())),
            None,
        )?;
        Ok(response.body)
    }

    async fn copy_part(
        &mut self,
        key: &str,
        upload: &str,
        source_key: &str,
        source: &ObjectReceipt,
        number: u32,
        first: u64,
        last: u64,
    ) -> Result<PartReceipt> {
        let full_key = self.full_key(source_key);
        let selector = DirectPartCopySource {
            bucket: &self.loaded.bucket,
            full_key: &full_key,
            first_byte: first,
            last_byte: last,
        };
        let request = direct(
            self.loaded.surface.direct_upload_part_copy_request(
                key,
                upload,
                number,
                &selector,
                now(),
                900,
            )?,
            None,
        );
        let mut intent = Intent::new(Phase::ProviderCopyPart, key);
        intent.upload_id_sha256 = Some(digest(upload.as_bytes()));
        intent.source_etag = Some(source.etag.clone());
        intent.first_byte = Some(first);
        intent.size = last - first + 1;
        intent.part_number = Some(number);
        let exchange = transport::dispatch(&self.loaded, &self.journal, intent, request).await?;
        let (exchange, response) = exchange.read(&self.journal, METADATA_LIMIT, true).await?;
        successful(&response)?;
        let receipt = s3surface::parse_direct_upload_part_copy(xml(&response)?)?;
        self.loaded.public_receipt(&receipt.etag)?;
        let etag = strong_etag(&receipt.etag)?;
        exchange.finish(
            &mut self.journal,
            &response,
            ResultKind::Positive,
            None,
            None,
        )?;
        Ok(PartReceipt {
            part_number: number,
            etag,
        })
    }
}

pub(super) async fn run(loaded: Loaded, directory: &Path, output: &Path) -> Result<String> {
    ensure!(!output.exists(), "operator report output must be new");
    let run_id = uuid::Uuid::new_v4().to_string();
    let seed = digest(run_id.as_bytes()).into_bytes();
    let bytes: Vec<_> = (0..OBJECT_SIZE)
        .map(|index| seed[index % seed.len()])
        .collect();
    let original = Original {
        version: 1,
        source_kind: "operator_core_s3surface_http".into(),
        executable_sha256: super::journal::executable_digest()?,
        package_version: env!("CARGO_PKG_VERSION").into(),
        run_id: run_id.clone(),
        started_at: now(),
        endpoint: loaded.endpoint.clone(),
        bucket: loaded.bucket.clone(),
        private_staging_prefix: loaded.prefix.clone(),
        policy: loaded.policy.clone(),
        policy_review_sha256: loaded.policy_review_sha256.clone(),
        expected_size: bytes.len() as u64,
        expected_sha256: digest(&bytes),
    };
    let journal = Journal::create(directory, &original)?;
    let mut probe = Probe { loaded, journal };
    let source_key = format!(".aos-direct-qualification/{run_id}/source");
    let source_upload = probe.create(Phase::CreateSource, &source_key).await?;
    let first_request = probe.part(&source_key, &source_upload, 1, 0, &bytes[..FIRST_PART])?;
    let mut bad_request = first_request.clone();
    let mut bad_bytes = bytes[..FIRST_PART].to_vec();
    bad_bytes[0] ^= 1;
    bad_request.body = Some(bad_bytes.clone());
    let bad_intent = probe.part_intent(
        Phase::RejectBadChecksum,
        &source_key,
        &source_upload,
        1,
        0,
        &bad_bytes,
        &first_request,
    );
    probe
        .refusal(
            bad_intent,
            bad_request,
            &["BadDigest", "InvalidDigest", "ChecksumMismatch"],
            &[400],
        )
        .await?;

    let first = probe
        .upload(
            Phase::UploadSourcePart,
            &source_key,
            &source_upload,
            1,
            0,
            &bytes[..FIRST_PART],
            first_request.clone(),
        )
        .await?;
    let last_request = probe.part(
        &source_key,
        &source_upload,
        2,
        FIRST_PART as u64,
        &bytes[FIRST_PART..],
    )?;
    let last = probe
        .upload(
            Phase::UploadSourcePart,
            &source_key,
            &source_upload,
            2,
            FIRST_PART as u64,
            &bytes[FIRST_PART..],
            last_request,
        )
        .await?;
    let source_etag = probe
        .complete(
            Phase::CompleteSource,
            &source_key,
            &source_upload,
            &[first, last],
        )
        .await?;
    let late_intent = probe.part_intent(
        Phase::LatePartAfterComplete,
        &source_key,
        &source_upload,
        1,
        0,
        &bytes[..FIRST_PART],
        &first_request,
    );
    probe
        .refusal(late_intent, first_request, &["NoSuchUpload"], &[404])
        .await?;
    let source = probe
        .head(Phase::SourceHead, &source_key, &source_etag, &bytes)
        .await?;
    probe
        .read(
            Phase::SourceFullRead,
            &source_key,
            &source,
            None,
            &bytes,
            false,
        )
        .await?;

    let mut anonymous = url::Url::parse(&probe.loaded.surface.object_url(
        Method::Get,
        &source_key,
        now(),
    )?)?;
    anonymous.set_query(None);
    probe
        .refusal(
            Intent::new(Phase::AnonymousRead, &source_key),
            ordinary(reqwest::Method::GET, anonymous.into(), None),
            &["AccessDenied", "Unauthorized", "NoSuchKey"],
            &[401, 403, 404],
        )
        .await?;

    let streamed_key = format!(".aos-direct-qualification/{run_id}/streamed-copy");
    let streamed_upload = probe
        .create(Phase::CreateStreamedCopy, &streamed_key)
        .await?;
    let mut streamed_parts = Vec::new();
    for (index, part) in bytes.chunks(FIRST_PART).enumerate() {
        let first = (index * FIRST_PART) as u64;
        let observed = probe
            .read(
                Phase::SourceRangeRead,
                &source_key,
                &source,
                Some((first, first + part.len() as u64 - 1)),
                part,
                true,
            )
            .await?;
        let request = probe.part(
            &streamed_key,
            &streamed_upload,
            index as u32 + 1,
            first,
            &observed,
        )?;
        streamed_parts.push(
            probe
                .upload(
                    Phase::UploadStreamedCopyPart,
                    &streamed_key,
                    &streamed_upload,
                    index as u32 + 1,
                    first,
                    &observed,
                    request,
                )
                .await?,
        );
    }
    let streamed_etag = probe
        .complete(
            Phase::CompleteStreamedCopy,
            &streamed_key,
            &streamed_upload,
            &streamed_parts,
        )
        .await?;
    let streamed_copy = probe
        .head(
            Phase::StreamedCopyHead,
            &streamed_key,
            &streamed_etag,
            &bytes,
        )
        .await?;
    probe
        .read(
            Phase::StreamedCopyFullRead,
            &streamed_key,
            &streamed_copy,
            None,
            &bytes,
            false,
        )
        .await?;

    let copied_key = format!(".aos-direct-qualification/{run_id}/provider-copy");
    let copied_upload = probe.create(Phase::CreateProviderCopy, &copied_key).await?;
    let mut copied_parts = Vec::new();
    for (index, part) in bytes.chunks(FIRST_PART).enumerate() {
        let first = (index * FIRST_PART) as u64;
        copied_parts.push(
            probe
                .copy_part(
                    &copied_key,
                    &copied_upload,
                    &source_key,
                    &source,
                    index as u32 + 1,
                    first,
                    first + part.len() as u64 - 1,
                )
                .await?,
        );
    }
    let copied_etag = probe
        .complete(
            Phase::CompleteProviderCopy,
            &copied_key,
            &copied_upload,
            &copied_parts,
        )
        .await?;
    let provider_copy = probe
        .head(Phase::ProviderCopyHead, &copied_key, &copied_etag, &bytes)
        .await?;
    probe
        .read(
            Phase::ProviderCopyFullRead,
            &copied_key,
            &provider_copy,
            None,
            &bytes,
            false,
        )
        .await?;
    probe
        .read(
            Phase::SourceFinalRead,
            &source_key,
            &source,
            None,
            &bytes,
            false,
        )
        .await?;

    let abort_key = format!(".aos-direct-qualification/{run_id}/aborted");
    let abort_upload = probe.create(Phase::CreateAbort, &abort_key).await?;
    let tail = probe.part(&abort_key, &abort_upload, 1, 0, &bytes[..FIRST_PART])?;
    let mut abort_intent = Intent::new(Phase::Abort, &abort_key);
    abort_intent.upload_id_sha256 = Some(digest(abort_upload.as_bytes()));
    let abort_request = ordinary(
        reqwest::Method::DELETE,
        probe.loaded.surface.multipart_url(
            "abort",
            &abort_key,
            Some(&abort_upload),
            None,
            now(),
        )?,
        None,
    );
    let exchange =
        transport::dispatch(&probe.loaded, &probe.journal, abort_intent, abort_request).await?;
    let (exchange, response) = exchange.read(&probe.journal, METADATA_LIMIT, true).await?;
    ensure!(
        matches!(response.status, 200 | 204) && response.body.is_empty(),
        "provider Abort did not positively acknowledge the original upload"
    );
    exchange.finish(
        &mut probe.journal,
        &response,
        ResultKind::Positive,
        None,
        None,
    )?;
    let tail_intent = probe.part_intent(
        Phase::LatePartAfterAbort,
        &abort_key,
        &abort_upload,
        1,
        0,
        &bytes[..FIRST_PART],
        &tail,
    );
    probe
        .refusal(tail_intent, tail, &["NoSuchUpload"], &[404])
        .await?;

    let report = Report {
        original,
        source,
        streamed_copy,
        provider_copy,
        observations: probe.journal.observations,
        cleanup_state: "retained_known_objects".into(),
    };
    write_new(output, &report)
}
