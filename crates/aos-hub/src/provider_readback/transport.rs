//! Fixed HTTPS requests and bounded exposed response observations.
//!
//! Semantic request bytes exclude credentials and signed query values. Exposed
//! bodies are application observations; TLS framing and billed bytes are unknown.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use aos_hub_core::sigv4::{self, BucketReadback, PresignParams};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    config::{Credentials, Operation, Selection},
    journal::Journal,
};

pub(super) fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn boot_now() -> Result<Duration> {
    let value = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
        rustix::time::ClockId::Boottime,
    ))?;
    Ok(Duration::new(
        u64::try_from(value.tv_sec)?,
        u32::try_from(value.tv_nsec)?,
    ))
}

pub(super) struct Cutoff {
    wall: u64,
    boot: Duration,
    instant: Instant,
}

impl Cutoff {
    pub fn new(selection: &Selection) -> Result<Self> {
        let now = unix_now()?;
        selection.validate(now)?;
        let reserved = now
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("clock reserve overflow"))?;
        let useful = selection
            .expires_at
            .checked_sub(reserved)
            .ok_or_else(|| anyhow::anyhow!("cleanup reserve absent"))?;
        Ok(Self {
            wall: selection.expires_at - 2,
            boot: boot_now()? + Duration::from_secs(useful),
            instant: Instant::now() + Duration::from_secs(useful),
        })
    }

    pub fn remaining(&self) -> Result<Duration> {
        ensure!(unix_now()? < self.wall, "original wall cutoff elapsed");
        let boot = self
            .boot
            .checked_sub(boot_now()?)
            .ok_or_else(|| anyhow::anyhow!("original boot cutoff elapsed"))?;
        let elapsed = self
            .instant
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("original monotonic cutoff elapsed"))?;
        let wall = self
            .wall
            .checked_sub(unix_now()?)
            .ok_or_else(|| anyhow::anyhow!("original wall cutoff elapsed"))?;
        let remaining = boot.min(elapsed).min(Duration::from_secs(wall));
        ensure!(!remaining.is_zero(), "original cutoff elapsed");
        Ok(remaining)
    }
}

pub(super) struct Request {
    pub operation: Operation,
    pub method: reqwest::Method,
    pub url: Zeroizing<String>,
    pub bearer: bool,
    pub semantic: Value,
}

pub(super) fn requests(
    selection: &Selection,
    credentials: &Credentials,
    now: u64,
    expires: u64,
) -> Result<Vec<Request>> {
    let endpoint = url::Url::parse(&selection.endpoint)?;
    let host = endpoint[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    let date = sigv4::amz_date_from_unix(i64::try_from(now)?);
    let mut result = Vec::new();
    for &operation in &selection.operations {
        let keys: Vec<Option<&str>> = if operation == Operation::ObjectHead {
            selection
                .object_keys
                .iter()
                .map(|key| Some(key.as_str()))
                .collect()
        } else {
            vec![None]
        };
        for key in keys {
            let api = matches!(
                operation,
                Operation::R2Bucket
                    | Operation::R2Cors
                    | Operation::R2Lifecycle
                    | Operation::TokenVerify
                    | Operation::TokenDetails
            );
            let method = if matches!(operation, Operation::BucketHead | Operation::ObjectHead) {
                reqwest::Method::HEAD
            } else {
                reqwest::Method::GET
            };
            let path = if api {
                api_path(selection, operation)?
            } else {
                match key {
                    Some(key) => format!("/{}/{key}", selection.bucket),
                    None => format!("/{}", selection.bucket),
                }
            };
            let url = if api {
                ensure!(
                    credentials.cloudflare_token.is_some(),
                    "Cloudflare token absent"
                );
                format!("https://api.cloudflare.com/client/v4{path}")
            } else {
                let credential = credentials
                    .s3
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("S3 credential absent"))?;
                let params = PresignParams {
                    access_key: &credential.access_key,
                    secret_key: &credential.secret_key,
                    region: &credential.region,
                    service: "s3",
                    scheme: "https",
                    host: &host,
                    path: &path,
                    expires_secs: u32::try_from(expires.min(300))?,
                    amz_date: &date,
                };
                let prefix = format!("{}/", selection.prefix);
                match operation {
                    Operation::BucketHead | Operation::ObjectHead => {
                        sigv4::presign_head_url(&params)?
                    }
                    Operation::Objects => sigv4::presign_list_url(&params, &prefix, None, 1000)?,
                    Operation::Multipart => sigv4::presign_multipart_url(
                        &params,
                        "GET",
                        &[
                            ("uploads", String::new()),
                            ("prefix", prefix),
                            ("max-uploads", "1000".into()),
                        ],
                    )?,
                    Operation::Cors => {
                        sigv4::presign_bucket_readback(&params, BucketReadback::Cors)?
                    }
                    Operation::Lifecycle => {
                        sigv4::presign_bucket_readback(&params, BucketReadback::Lifecycle)?
                    }
                    Operation::Location => {
                        sigv4::presign_bucket_readback(&params, BucketReadback::Location)?
                    }
                    Operation::Versioning => {
                        sigv4::presign_bucket_readback(&params, BucketReadback::Versioning)?
                    }
                    Operation::Policy => {
                        sigv4::presign_bucket_readback(&params, BucketReadback::Policy)?
                    }
                    _ => anyhow::bail!("unsupported read selector"),
                }
            };
            let semantic = json!({"operation":operation,"method":method.as_str(),"origin":if api {"https://api.cloudflare.com"} else {&selection.endpoint},
                "path":path,"prefix":if matches!(operation,Operation::Objects|Operation::Multipart) {Some(format!("{}/", selection.prefix))} else {None},
                "maximumEntries":if matches!(operation,Operation::Objects|Operation::Multipart) {Some(1000)} else {None},
                "requestBodyBytes":"0","authenticationBytesRetained":false});
            result.push(Request {
                operation,
                method,
                url: Zeroizing::new(url),
                bearer: api,
                semantic,
            });
        }
    }
    Ok(result)
}

fn api_path(selection: &Selection, operation: Operation) -> Result<String> {
    let account = selection
        .account_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("account absent"))?;
    let bucket = format!("/accounts/{account}/r2/buckets/{}", selection.bucket);
    Ok(match operation {
        Operation::R2Bucket => bucket,
        Operation::R2Cors => format!("{bucket}/cors"),
        Operation::R2Lifecycle => format!("{bucket}/lifecycle"),
        Operation::TokenVerify | Operation::TokenDetails => {
            let base = match selection.token_kind.as_deref() {
                Some("user") => "/user/tokens".to_owned(),
                Some("account") => format!("/accounts/{account}/tokens"),
                _ => anyhow::bail!("token scope differs"),
            };
            if operation == Operation::TokenVerify {
                format!("{base}/verify")
            } else {
                format!(
                    "{base}/{}",
                    selection
                        .token_id
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("token identity absent"))?
                )
            }
        }
        _ => anyhow::bail!("unsupported API read"),
    })
}

// Withhold the entire content and its hash, rather than hashing a redaction.
pub(super) fn sensitive(bytes: &[u8], credentials: &Credentials) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    credentials.protected(bytes)
        || [
            "x-amz-signature",
            "x-amz-credential",
            "authorization",
            "access_token",
            "secretaccesskey",
            "\"value\"",
            "\"token\"",
        ]
        .iter()
        .any(|marker| text.contains(marker))
        || serde_json::from_slice::<Value>(bytes)
            .ok()
            .is_some_and(|value| sensitive_fields(&value, credentials))
}

fn sensitive_fields(value: &Value, credentials: &Credentials) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "value" | "token" | "access_token" | "secret" | "secretaccesskey" | "authorization"
            ) || sensitive_fields(value, credentials)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| sensitive_fields(value, credentials)),
        Value::String(text) => {
            credentials.protected(text.as_bytes())
                || text.to_ascii_lowercase().contains("x-amz-signature")
        }
        _ => false,
    }
}

pub(super) struct Body {
    pub bytes: Zeroizing<Vec<u8>>,
    pub exposed: u64,
    pub eof: bool,
    pub outcome: &'static str,
}

impl Body {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            exposed: 0,
            eof: false,
            outcome: "unread",
        }
    }

    pub fn push(&mut self, bytes: &[u8], maximum: usize) -> Result<()> {
        self.exposed = self
            .exposed
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow::anyhow!("exposed count overflow"))?;
        let retained = maximum.saturating_sub(self.bytes.len()).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
        ensure!(self.exposed <= maximum as u64, "response bound exceeded");
        Ok(())
    }
}

pub(super) async fn observe(
    client: &reqwest::Client,
    request: &Request,
    credentials: &Credentials,
    selection: &Selection,
    cutoff: &Cutoff,
    journal: &Journal,
    ordinal: usize,
) -> Result<Value> {
    let mut builder = client
        .request(request.method.clone(), request.url.as_str())
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .timeout(cutoff.remaining()?);
    if request.bearer {
        builder = builder.bearer_auth(
            credentials
                .cloudflare_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("token absent"))?,
        );
    }
    let built = builder
        .build()
        .map_err(|_| anyhow::anyhow!("fixed request construction failed"))?;
    let mut intent = request.semantic.clone();
    intent["constructedRequestTargetBytes"] = Value::String(
        built.url()[url::Position::BeforePath..url::Position::AfterQuery]
            .len()
            .to_string(),
    );
    intent["constructedHeaderFieldBytes"] = Value::String(
        built
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            .to_string(),
    );
    intent["transportAddedHeaderBytes"] = Value::Null;
    let intent = journal.write(
        &format!("{ordinal:02}-intent.json"),
        &serde_json::to_vec(&intent)?,
    )?;
    // Durability may consume the window. Recheck before the sole dispatch.
    cutoff.remaining()?;
    let started = Instant::now();
    let mut body = Body::new();
    let mut status = None;
    let mut safe_headers = serde_json::Map::new();
    match tokio::time::timeout(cutoff.remaining()?, client.execute(built)).await {
        Ok(Ok(mut response)) => {
            status = Some(response.status().as_u16());
            for key in [
                "content-length",
                "content-type",
                "content-encoding",
                "etag",
                "x-amz-version-id",
                "x-amz-request-id",
                "cf-ray",
            ] {
                if let Some(value) = response.headers().get(key).and_then(|v| v.to_str().ok()) {
                    if value.len() <= 1024 && !sensitive(value.as_bytes(), credentials) {
                        safe_headers.insert(key.into(), Value::String(value.into()));
                    }
                }
            }
            body.outcome = "partial";
            loop {
                let remaining = match cutoff.remaining() {
                    Ok(value) => value,
                    Err(_) => {
                        body.outcome = "cutoff";
                        break;
                    }
                };
                match tokio::time::timeout(remaining, response.chunk()).await {
                    Ok(Ok(Some(chunk))) => {
                        if body.push(&chunk, selection.maximum_response_bytes).is_err() {
                            body.outcome = "response_too_large";
                            break;
                        }
                    }
                    Ok(Ok(None)) => {
                        if cutoff.remaining().is_ok() {
                            body.eof = true;
                            body.outcome = "complete";
                        } else {
                            body.outcome = "cutoff";
                        }
                        break;
                    }
                    Ok(Err(_)) => {
                        body.outcome = "response_read_failed";
                        break;
                    }
                    Err(_) => {
                        body.outcome = "cutoff";
                        break;
                    }
                }
            }
        }
        Ok(Err(_)) => body.outcome = "transport_failed",
        Err(_) => body.outcome = "cutoff",
    }
    let token_json_unknown = request.operation == Operation::TokenDetails
        && serde_json::from_slice::<Value>(&body.bytes).is_err();
    let withheld = sensitive(&body.bytes, credentials) || !body.eof || token_json_unknown;
    let body_ref = if withheld {
        None
    } else {
        Some(journal.write(&format!("{ordinal:02}-response.body"), &body.bytes)?)
    };
    let identity_encoding = safe_headers
        .get("content-encoding")
        .is_none_or(|value| value.as_str() == Some("identity"));
    let facts = if !withheld && status == Some(200) && identity_encoding {
        facts(request.operation, &body.bytes, selection).ok()
    } else {
        None
    };
    Ok(
        json!({"ordinal":ordinal,"intent":intent,"operation":request.operation,"httpStatus":status,"headers":safe_headers,
        "outcome":body.outcome,"exposedResponseBodyBytes":body.exposed.to_string(),"bufferedResponseBodyBytes":body.bytes.len().to_string(),
        "persistedResponseBodyBytes":if withheld {None} else {Some(body.bytes.len().to_string())},
        "responseEof":body.eof,"responseBody":body_ref,"contentWithheld":withheld,"facts":facts,
        "elapsedNanos":started.elapsed().as_nanos().to_string(),"tlsPolicy":"ordinary_verified_https","authenticatedHttpsResponseObserved":status.is_some(),"redirectsFollowed":false,"dispatchInvocations":1,
        "rawRequestWireBytes":null,"rawResponseWireBytes":null,"providerBilledBytes":null,"effectivePermissions":null,
        "globalWriterClosure":null,"completeBucketInventory":null,"remoteDrain":null}),
    )
}

pub(super) fn facts(operation: Operation, bytes: &[u8], selection: &Selection) -> Result<Value> {
    if operation == Operation::Objects {
        let xml = std::str::from_utf8(bytes)?;
        let (objects, continuation, truncated) =
            aos_hub_core::s3surface::parse_list_objects_v2_evidence(xml)?;
        let prefix = format!("{}/", selection.prefix);
        ensure!(
            xml.matches("<Prefix>").count() == 1
                && xml.contains(&format!("<Prefix>{prefix}</Prefix>"))
                && xml.matches("<Name>").count() == 1
                && xml.contains(&format!("<Name>{}</Name>", selection.bucket)),
            "listed bucket or prefix echo differs"
        );
        ensure!(
            objects.len() <= 1000 && objects.iter().all(|object| object.key.starts_with(&prefix)),
            "listed object escapes selected prefix"
        );
        return Ok(
            json!({"listedObjects":objects.iter().map(|object| json!({"key":object.key,"size":object.size,"etag":object.strong_etag})).collect::<Vec<_>>(),
            "truncated":truncated,"continuationPresent":continuation.is_some(),"pageCount":1,"fullInventory":null}),
        );
    }
    if matches!(
        operation,
        Operation::R2Bucket
            | Operation::R2Cors
            | Operation::R2Lifecycle
            | Operation::TokenVerify
            | Operation::TokenDetails
    ) {
        let value: Value = serde_json::from_slice(bytes)?;
        ensure!(
            value.get("success") == Some(&Value::Bool(true)) && value.get("result").is_some(),
            "API result is not successful"
        );
        return Ok(
            json!({"observedApiResult":value.get("result"),"permissionInterpretation":null,"selectedCredentialAssociation":null}),
        );
    }
    Ok(
        json!({"schemaInterpretation":null,"scope":"retained_bucket_metadata_or_single_multipart_page"}),
    )
}
