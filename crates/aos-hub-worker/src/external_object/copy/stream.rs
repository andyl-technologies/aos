//! Native length-limited conditional range transfer without Rust stream callbacks.
//!
//! A first immutable range read supplies a real checksum. A second read of that
//! exact provider version and condition feeds a native FixedLengthStream with
//! backpressure. Clean source EOF, checksum equality and a positive UploadPart
//! receipt are all required; none independently settles the permanent turn.

use anyhow::{ensure, Result};
use aos_hub_core::{
    db::OciSha256State, sigv4::DirectSignedProviderRequest,
    storage_authority::external_object::copy::CopySourceObject,
};
use base64::Engine as _;
use futures_util::future::try_join;
use js_sys::{Array, Function, Reflect, Uint8Array};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect, ResponseBody};

use super::bytes::{RangeBytes, RangeDigest, CHUNK_BYTES};
use super::window::DispatchWindow;

/// Selects an exact versioned range after the caller's guard and lease checks.
pub(super) struct SourceRange<'a> {
    pub(super) source: &'a CopySourceObject,
    pub(super) offset: u64,
    pub(super) bytes: u64,
}

impl SourceRange<'_> {
    fn end(&self) -> Result<u64> {
        self.source.validate()?;
        let end = self
            .offset
            .checked_add(self.bytes)
            .ok_or_else(|| anyhow::anyhow!("copy source range overflow"))?;
        ensure!(
            self.bytes > 0
                && self.bytes <= aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES
                && end <= self.source.bytes.get() as u64,
            "copy source range differs"
        );
        Ok(end)
    }

    fn headers(&self, signed: &DirectSignedProviderRequest) -> Result<Headers> {
        let end = self.end()?;
        let expected = format!("bytes={}-{}", self.offset, end - 1);
        ensure!(
            signed.required_headers.len() == 2
                && signed.required_headers[0].name == "if-match"
                && signed.required_headers[0].value == self.source.etag
                && signed.required_headers[1].name == "range"
                && signed.required_headers[1].value == expected,
            "copy source signed headers differ"
        );
        let url = url::Url::parse(&signed.url)?;
        let versions: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key == "versionId")
            .map(|(_, value)| value.into_owned())
            .collect();
        ensure!(
            versions == [self.source.provider_version.clone()],
            "copy source signed version differs"
        );
        provider_headers(signed)
    }

    fn validate_response(&self, response: &worker::Response) -> Result<()> {
        let end = self.end()?;
        let headers = response.headers();
        ensure!(
            response.status_code() == 206
                && headers.get("etag")?.as_deref() == Some(self.source.etag.as_str())
                && headers.get("x-amz-version-id")?.as_deref()
                    == Some(self.source.provider_version.as_str())
                && headers.get("content-length")?.as_deref()
                    == Some(self.bytes.to_string().as_str())
                && headers.get("content-range")?.as_deref()
                    == Some(
                        format!(
                            "bytes {}-{}/{}",
                            self.offset,
                            end - 1,
                            self.source.bytes.get()
                        )
                        .as_str()
                    ),
            "copy conditional response identity differs"
        );
        Ok(())
    }
}

/// Hashes the first exact source pass without collecting a part body.
///
/// The caller retains its provider pool and source permit across this future.
/// The window checks authenticated deadlines and floor before dispatch and
/// after every await, and cancels a blocked stream on cutoff or client abort.
///
/// # Errors
/// Refuses changed source metadata, failed/truncated reads, excessive bytes,
/// unqualified clock, expired authority or canceled invocation.
pub(super) async fn hash_range(
    signed: &DirectSignedProviderRequest,
    range: &SourceRange<'_>,
    continuation: OciSha256State,
    window: &DispatchWindow<'_>,
) -> Result<RangeBytes> {
    window
        .run(async {
            let cancellation = Cancellation::new(&window.lifetime)?;
            let fresh = || window.check();
            let reader =
                source_reader(signed, range, &cancellation, &fresh, &window.lifetime).await?;
            pump(&reader, range, continuation, None, &fresh).await
        })
        .await
}

/// Transfers the same immutable source pass into one native framed part.
///
/// No callbacks outlive this future. Dropping either failed branch cancels its
/// exact native GET/PUT and writer, leaving the physical turn unresolved.
///
/// # Errors
/// Refuses changed source/checksum, failed native framing, absent positive part
/// acknowledgement, cancellation or any stale authenticated dispatch window.
pub(super) async fn upload_range(
    read: &DirectSignedProviderRequest,
    write: &DirectSignedProviderRequest,
    range: &SourceRange<'_>,
    continuation: OciSha256State,
    expected: &RangeBytes,
    window: &DispatchWindow<'_>,
) -> Result<(String, RangeBytes)> {
    window
        .run(upload_range_inner(
            read,
            write,
            range,
            continuation,
            expected,
            window,
        ))
        .await
}

async fn upload_range_inner(
    read: &DirectSignedProviderRequest,
    write: &DirectSignedProviderRequest,
    range: &SourceRange<'_>,
    continuation: OciSha256State,
    expected: &RangeBytes,
    window: &DispatchWindow<'_>,
) -> Result<(String, RangeBytes)> {
    let fresh = &|| window.check();
    let cancellation = Cancellation::new(&window.lifetime)?;
    let reader = source_reader(read, range, &cancellation, fresh, &window.lifetime).await?;
    let writer = FramedWriter::new(range.bytes, &window.lifetime)?;
    let headers = provider_headers(write)?;
    let checksum_matches = match write.required_headers.get(1) {
        Some(header) if header.name == "x-amz-checksum-sha256" => {
            header.value
                == base64::engine::general_purpose::STANDARD.encode(hex::decode(&expected.sha256)?)
        }
        Some(header) if header.name == "content-md5" => {
            header.value
                == base64::engine::general_purpose::STANDARD.encode(hex::decode(&expected.md5)?)
        }
        _ => false,
    };
    ensure!(
        write.required_headers.len() == 2
            && write.required_headers[0].name == "content-length"
            && headers.get("content-length")?.as_deref() == Some(range.bytes.to_string().as_str())
            && checksum_matches,
        "copy outgoing signed length or checksum differs"
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Put)
        .with_redirect(RequestRedirect::Manual)
        .with_headers(headers)
        .with_body(Some(writer.readable.clone().into()));
    let request = Request::new_with_init(&write.url, &init)?;
    let send = async {
        fresh()?;
        crate::direct_upload::provider_capacity::record_dispatch();
        let response = Fetch::Request(request)
            .send_with_signal(&worker::AbortSignal::from(cancellation.0.signal()))
            .await?;
        fresh()?;
        ensure!(response.status_code() == 200, "copy part unacknowledged");
        let etag = response
            .headers()
            .get("etag")?
            .ok_or_else(|| anyhow::anyhow!("copy part ETag absent"))?;
        aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
        Ok::<_, anyhow::Error>(etag)
    };
    let receive = async {
        let actual = pump(&reader, range, continuation, Some(&writer), fresh).await?;
        ensure!(
            actual.sha256 == expected.sha256
                && actual.md5 == expected.md5
                && actual.source_state == expected.source_state,
            "copy source second pass differs"
        );
        writer.close().await?;
        fresh()?;
        Ok::<_, anyhow::Error>(actual)
    };
    try_join(send, receive).await
}

async fn source_reader(
    signed: &DirectSignedProviderRequest,
    range: &SourceRange<'_>,
    cancellation: &Cancellation,
    fresh: &dyn Fn() -> Result<()>,
    lifetime: &super::lifetime::Lifetime,
) -> Result<Reader> {
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_redirect(RequestRedirect::Manual)
        .with_headers(range.headers(signed)?);
    let request = Request::new_with_init(&signed.url, &init)?;
    fresh()?;
    crate::direct_upload::provider_capacity::record_dispatch();
    let response = Fetch::Request(request)
        .send_with_signal(&worker::AbortSignal::from(cancellation.0.signal()))
        .await?;
    fresh()?;
    range.validate_response(&response)?;
    let (_, body) = response.into_parts();
    let ResponseBody::Stream(stream) = body else {
        anyhow::bail!("copy source native stream unavailable");
    };
    Reader::new(stream.into(), lifetime)
}

async fn pump(
    reader: &Reader,
    range: &SourceRange<'_>,
    continuation: OciSha256State,
    writer: Option<&FramedWriter>,
    fresh: &dyn Fn() -> Result<()>,
) -> Result<RangeBytes> {
    let mut digest = RangeDigest::new(range.offset, range.bytes, continuation)?;
    loop {
        fresh()?;
        let (bytes, done) = reader.read().await?;
        fresh()?;
        if bytes.length() > 0 {
            // One bounded native view and one bounded Rust hashing slice exist;
            // no tee, part buffer or background producer is created.
            digest.update(&bytes.to_vec())?;
            if let Some(writer) = writer {
                writer.write(&bytes).await?;
                fresh()?;
            }
        }
        if done {
            return digest.finish();
        }
    }
}

fn provider_headers(signed: &DirectSignedProviderRequest) -> Result<Headers> {
    aos_hub_core::url_guard::is_safe_remote_url(&signed.url)?;
    let headers = Headers::new();
    for required in &signed.required_headers {
        headers.set(&required.name, &required.value)?;
    }
    Ok(headers)
}

struct Cancellation(
    worker::web_sys::AbortController,
    super::lifetime::Registration,
);

impl Cancellation {
    fn new(lifetime: &super::lifetime::Lifetime) -> Result<Self> {
        let controller = worker::web_sys::AbortController::new().map_err(|_| refused())?;
        let registration = lifetime.register(controller.clone().into(), "abort")?;
        Ok(Self(controller, registration))
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        let _ = invoke(self.0.as_ref(), "abort", &[]);
    }
}

struct Reader {
    native: JsValue,
    ended: std::cell::Cell<bool>,
    _registration: super::lifetime::Registration,
}

impl Reader {
    fn new(stream: JsValue, lifetime: &super::lifetime::Lifetime) -> Result<Self> {
        let options = js_sys::Object::new();
        Reflect::set(&options, &"mode".into(), &"byob".into()).map_err(|_| refused())?;
        let native = invoke(&stream, "getReader", &[options.into()])?;
        let registration = lifetime.register(native.clone(), "cancel")?;
        Ok(Self {
            native,
            ended: std::cell::Cell::new(false),
            _registration: registration,
        })
    }

    async fn read(&self) -> Result<(Uint8Array, bool)> {
        let view = Uint8Array::new_with_length(CHUNK_BYTES as u32);
        let result = awaited(invoke(&self.native, "read", &[view.into()])?).await?;
        let done = Reflect::get(&result, &"done".into())
            .map_err(|_| refused())?
            .as_bool()
            .ok_or_else(refused)?;
        let value = Reflect::get(&result, &"value".into()).map_err(|_| refused())?;
        let bytes = if done && value.is_undefined() {
            Uint8Array::new_with_length(0)
        } else {
            value.dyn_into::<Uint8Array>().map_err(|_| refused())?
        };
        ensure!(
            bytes.length() as usize <= CHUNK_BYTES && (done || bytes.length() > 0),
            "copy native source chunk differs"
        );
        self.ended.set(done);
        Ok((bytes, done))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if !self.ended.get() {
            if let Ok(value) = invoke(&self.native, "cancel", &[]) {
                discard_rejection(value);
            }
        }
        let _ = invoke(&self.native, "releaseLock", &[]);
    }
}

struct FramedWriter {
    readable: JsValue,
    native: JsValue,
    closed: std::cell::Cell<bool>,
    _registration: super::lifetime::Registration,
}

impl FramedWriter {
    fn new(bytes: u64, lifetime: &super::lifetime::Lifetime) -> Result<Self> {
        ensure!(bytes <= (1_u64 << 53) - 1, "copy length is not exact");
        let constructor = Reflect::get(&js_sys::global(), &"FixedLengthStream".into())
            .map_err(|_| refused())?
            .dyn_into::<Function>()
            .map_err(|_| refused())?;
        let arguments = Array::new();
        arguments.push(&JsValue::from_f64(bytes as f64));
        let stream = Reflect::construct(&constructor, &arguments).map_err(|_| refused())?;
        let readable = Reflect::get(&stream, &"readable".into()).map_err(|_| refused())?;
        let writable = Reflect::get(&stream, &"writable".into()).map_err(|_| refused())?;
        let native = invoke(&writable, "getWriter", &[])?;
        let registration = lifetime.register(native.clone(), "abort")?;
        Ok(Self {
            readable,
            native,
            closed: std::cell::Cell::new(false),
            _registration: registration,
        })
    }

    async fn write(&self, bytes: &Uint8Array) -> Result<()> {
        awaited(invoke(&self.native, "write", &[bytes.clone().into()])?).await?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        awaited(invoke(&self.native, "close", &[])?).await?;
        self.closed.set(true);
        Ok(())
    }
}

impl Drop for FramedWriter {
    fn drop(&mut self) {
        if !self.closed.get() {
            if let Ok(value) = invoke(&self.native, "abort", &[]) {
                discard_rejection(value);
            }
        }
        let _ = invoke(&self.native, "releaseLock", &[]);
    }
}

fn discard_rejection(value: JsValue) {
    if let Ok(handler) = Reflect::get(&js_sys::global(), &"Boolean".into()) {
        let _ = invoke(&value, "catch", &[handler]);
    }
}

fn invoke(object: &JsValue, name: &str, arguments: &[JsValue]) -> Result<JsValue> {
    let method = Reflect::get(object, &JsValue::from_str(name))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())?;
    let values = Array::new();
    for value in arguments {
        values.push(value);
    }
    method.apply(object, &values).map_err(|_| refused())
}

async fn awaited(value: JsValue) -> Result<JsValue> {
    let promise = value.dyn_into::<js_sys::Promise>().map_err(|_| refused())?;
    JsFuture::from(promise).await.map_err(|_| refused())
}

fn refused() -> anyhow::Error {
    anyhow::anyhow!("copy native stream refused")
}
