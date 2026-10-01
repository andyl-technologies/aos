//! Bounded operator HTTPS dispatch with durable originals and value-free errors.

use anyhow::{ensure, Result};
use sha2::{Digest as _, Sha256};

use super::{
    config::Loaded,
    journal::Journal,
    model::{Intent, Observation, ResponseCommitment, ResultKind},
};

#[derive(Clone)]
pub(super) struct Request {
    pub method: reqwest::Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub(super) struct Exchange {
    index: usize,
    intent: Intent,
    response: reqwest::Response,
    secrets: Vec<zeroize::Zeroizing<String>>,
}

pub(super) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub bytes: u64,
    pub sha256: String,
    pub etag: Option<String>,
    pub version: Option<String>,
    pub request_id: Option<String>,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
}

pub(super) async fn dispatch(
    loaded: &Loaded,
    journal: &Journal,
    mut intent: Intent,
    request: Request,
) -> Result<Exchange> {
    let url = url::Url::parse(&request.url)
        .map_err(|_| anyhow::anyhow!("operator request URL is invalid"))?;
    ensure!(
        url.origin().ascii_serialization() == loaded.endpoint,
        "operator request changed its selected origin"
    );
    intent.authorization_sha256 = super::journal::digest(&serde_json::to_vec(&(
        request.method.as_str(),
        &request.url,
        &request.headers,
    ))?);
    intent.request_sha256 = super::journal::digest(&serde_json::to_vec(&(
        &intent.authorization_sha256,
        request.body.as_deref().map(super::journal::digest),
    ))?);
    let mut outgoing = loaded.http.request(request.method, url);
    for (name, value) in request.headers {
        outgoing = outgoing.header(name, value);
    }
    if let Some(body) = request.body {
        outgoing = outgoing.body(body);
    }
    let request = outgoing
        .build()
        .map_err(|_| anyhow::anyhow!("operator request cannot be encoded"))?;

    // A durable original precedes the first provider await. Transport and lost
    // replies leave this intent without an observation; no caller retries it.
    let index = journal.begin(&intent)?;
    let response = loaded
        .http
        .execute(request)
        .await
        .map_err(super::transport_failure::request_error)?;
    Ok(Exchange {
        index,
        intent,
        response,
        secrets: loaded.receipt_secrets(),
    })
}

fn header(
    response: &reqwest::Response,
    name: &str,
    secrets: &[zeroize::Zeroizing<String>],
) -> Result<Option<String>> {
    response
        .headers()
        .get(name)
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| anyhow::anyhow!("provider receipt header is invalid"))?;
            ensure!(
                value.len() <= 512
                    && !value.chars().any(char::is_control)
                    && !value.contains("://")
                    && !value.to_ascii_lowercase().contains("x-amz-"),
                "provider receipt header cannot be retained safely"
            );
            ensure!(
                !secrets.iter().any(|secret| value.contains(secret.as_str())),
                "provider receipt contains protected credential material"
            );
            Ok(value.to_owned())
        })
        .transpose()
}

impl Exchange {
    pub async fn read(
        mut self,
        journal: &Journal,
        maximum: u64,
        retain_body: bool,
    ) -> Result<(Self, Response)> {
        let status = self.response.status().as_u16();
        let etag = header(&self.response, "etag", &self.secrets)?;
        let version = header(&self.response, "x-amz-version-id", &self.secrets)?;
        let request_id = header(&self.response, "x-amz-request-id", &self.secrets)?;
        let content_range = header(&self.response, "content-range", &self.secrets)?;
        let content_length = header(&self.response, "content-length", &self.secrets)?
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("provider response length is invalid"))
            })
            .transpose()?;
        // HEAD declares the object size but consumes no response body.
        ensure!(
            !retain_body || content_length.is_none_or(|size| size <= maximum),
            "provider response exceeds its admitted body bound"
        );
        let mut body = Vec::new();
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        while let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(super::transport_failure::response_error)?
        {
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("provider response size overflowed"))?;
            ensure!(
                bytes <= maximum,
                "provider response exceeds its admitted body bound"
            );
            hash.update(&chunk);
            if retain_body {
                body.extend_from_slice(&chunk);
            }
        }
        let response = Response {
            status,
            body,
            bytes,
            sha256: hex::encode(hash.finalize()),
            etag,
            version,
            request_id,
            content_length,
            content_range,
        };
        // Receipt parsing may still fail. Keep the exact bounded response
        // commitment without turning an HTTP reply into settled effect proof.
        journal.received(
            self.index,
            &ResponseCommitment {
                operation_id: self.intent.operation_id.clone(),
                phase: self.intent.phase,
                status: response.status,
                response_bytes: response.bytes,
                response_sha256: response.sha256.clone(),
                provider_request_id: response.request_id.clone(),
            },
        )?;
        Ok((self, response))
    }

    pub fn finish(
        self,
        journal: &mut Journal,
        response: &Response,
        result: ResultKind,
        actual: Option<(u64, String)>,
        error_code: Option<String>,
    ) -> Result<()> {
        let observation = Observation {
            operation_id: self.intent.operation_id,
            phase: self.intent.phase,
            result,
            status: response.status,
            response_bytes: response.bytes,
            response_sha256: response.sha256.clone(),
            provider_request_id: response.request_id.clone(),
            error_code,
            etag: response.etag.clone(),
            provider_version: response.version.clone(),
            actual_size: actual.as_ref().map(|value| value.0),
            actual_sha256: actual.map(|value| value.1),
        };
        journal.finish(self.index, observation)
    }
}

/// Only exact provider refusal codes establish a negative observation.
pub(super) fn denied(response: &Response, codes: &[&str], statuses: &[u16]) -> Result<String> {
    ensure!(
        statuses.contains(&response.status),
        "provider did not positively refuse the request"
    );
    let text = std::str::from_utf8(&response.body)
        .map_err(|_| anyhow::anyhow!("provider refusal is not a supported document"))?;
    let code = text
        .split_once("<Code>")
        .and_then(|(_, tail)| tail.split_once("</Code>"))
        .map(|(code, _)| code)
        .filter(|code| codes.contains(code));
    ensure!(
        text.contains("<Error>")
            && text.matches("<Code>").count() == 1
            && text.matches("</Code>").count() == 1,
        "provider refusal is not an exact closed error observation"
    );
    code.map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("provider returned an unqualified refusal code"))
}
