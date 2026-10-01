//! Native workerd streaming hashes of exact private staged bytes.
//!
//! The runtime's non-retaining `crypto.DigestStream` owns cryptographic state.
//! A BYOB reader bounds each incoming view to 64 KiB. Full SHA, exact byte counts,
//! per-part SHA and declared provider checksums are compared independently of
//! response headers. This helper establishes bytes, not source immutability,
//! provider closure, guard admission or logical publication eligibility.
//!
//! Runtime contract: <https://developers.cloudflare.com/workers/runtime-apis/web-crypto/>.
//! The extension is explicitly feature-checked; absence has no buffered fallback.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::{
    DirectChecksumAlgorithm, DirectManifestPart, DirectUploadIntent,
};
use base64::Engine as _;
use js_sys::{Array, ArrayBuffer, Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Response, ResponseBody};

const CHUNK_BYTES: u32 = 64 * 1024;

mod forward;
pub(crate) use forward::{forward_part, PartStreamVerification};

/// Independently computed full digest and exact stream length.
pub(crate) struct VerifiedStreamDigest {
    pub(crate) sha256: String,
    pub(crate) byte_size: u64,
}

/// Hashes a native stream with an exact conservative byte ceiling.
///
/// The caller independently owns source immutability and same-GET identity.
/// This supports factual baseline hashing when no prior source digest exists.
///
/// # Errors
/// Returns an error for unavailable native interfaces or excessive/failed bytes.
pub(crate) async fn hash_response(
    response: Response,
    maximum_bytes: u64,
) -> Result<VerifiedStreamDigest> {
    ensure!(
        response.status_code() == 200,
        "native hash observation refused"
    );
    let full = Digest::new("SHA-256")?;
    let (_, body) = response.into_parts();
    let reader = match body {
        ResponseBody::Stream(stream) => Some(Reader::new(stream.into())?),
        ResponseBody::Empty => None,
        _ => anyhow::bail!("native hash requires stream"),
    };
    let mut counted = 0_u64;
    if let Some(reader) = reader {
        loop {
            let (value, done) = reader.read().await?;
            ensure!(
                value.length() <= CHUNK_BYTES,
                "native hash chunk exceeds bound"
            );
            counted = counted
                .checked_add(u64::from(value.length()))
                .ok_or_else(|| anyhow::anyhow!("native hash size overflow"))?;
            ensure!(counted <= maximum_bytes, "native hash source exceeds bound");
            if value.length() > 0 {
                full.write(&value).await?;
            }
            if done {
                break;
            }
            ensure!(value.length() > 0, "native hash empty unfinished chunk");
        }
    }
    Ok(VerifiedStreamDigest {
        sha256: hex::encode(full.finish().await?),
        byte_size: counted,
    })
}

/// Reads compact native response metadata with a bound before Rust body copies.
///
/// Each runtime view is at most 64 KiB. The complete retained buffer is bounded
/// by `cap`; oversized views and cumulative lengths are rejected before copying.
/// This helper does not hash, authenticate or interpret the response.
///
/// # Errors
/// Returns a value-free error for unavailable BYOB interfaces, stream failures,
/// oversized metadata or malformed native stream results.
pub(crate) async fn read_bounded_native(response: Response, cap: usize) -> Result<Vec<u8>> {
    read_bounded_native_observed(response, cap, &|_| {}).await
}

/// Observes only byte views actually returned by the bounded native reader.
pub(crate) async fn read_bounded_native_observed(
    response: Response,
    cap: usize,
    consumed: &dyn Fn(u64),
) -> Result<Vec<u8>> {
    ensure!(
        cap > 0 && cap <= 512 * 1024,
        "native metadata bound invalid"
    );
    read_bounded_native_with_limit(response, cap, consumed).await
}

async fn read_bounded_native_with_limit(
    response: Response,
    cap: usize,
    consumed: &dyn Fn(u64),
) -> Result<Vec<u8>> {
    let (_, body) = response.into_parts();
    let reader = match body {
        ResponseBody::Stream(stream) => Reader::new(stream.into())?,
        ResponseBody::Empty => return Ok(Vec::new()),
        _ => anyhow::bail!("metadata requires native stream"),
    };
    let mut bytes = Vec::new();
    loop {
        let (view, done) = reader.read().await?;
        let length = view.length() as usize;
        consumed(length as u64);
        ensure!(
            length <= CHUNK_BYTES as usize
                && bytes
                    .len()
                    .checked_add(length)
                    .is_some_and(|size| size <= cap),
            "native metadata exceeds bound"
        );
        bytes.extend_from_slice(&view.to_vec());
        if done {
            return Ok(bytes);
        }
        ensure!(
            length > 0,
            "native metadata returned empty unfinished chunk"
        );
    }
}

/// Verifies exact streamed bytes using native bounded-memory hashing.
///
/// The caller must retain immutable closed-stage proof and admission around the
/// actual provider GET. Failed observation may retry that same immutable source;
/// this helper never changes provider/session/guard state.
///
/// # Errors
/// Returns a value-free error for unavailable native/BYOB interfaces, failed
/// input, incorrect size/full SHA/part identity, or malformed manifest geometry.
pub(crate) async fn verify_response(
    response: Response,
    intent: &DirectUploadIntent,
    parts: &[DirectManifestPart],
) -> Result<VerifiedStreamDigest> {
    verify_response_observed(response, intent, parts, &|_| {}).await
}

/// Observes each actual native read before integrity checks accept its bytes.
pub(crate) async fn verify_response_observed(
    response: Response,
    intent: &DirectUploadIntent,
    parts: &[DirectManifestPart],
    consumed: &dyn Fn(u64),
) -> Result<VerifiedStreamDigest> {
    intent.validate()?;
    ensure!(
        response.status_code() == 200,
        "stage byte observation refused"
    );
    ensure!(
        parts.len() == intent.part_count()? as usize,
        "stage byte manifest incomplete"
    );
    for (index, part) in parts.iter().enumerate() {
        ensure!(
            part.part.part_number as usize == index + 1,
            "stage byte manifest unordered"
        );
        part.part.validate(intent)?;
    }

    let full = Digest::new("SHA-256")?;
    let (_, body) = response.into_parts();
    let reader = match body {
        ResponseBody::Stream(stream) => Some(Reader::new(stream.into())?),
        ResponseBody::Empty if intent.byte_size.get() == 0 => None,
        _ => anyhow::bail!("stage body requires native stream"),
    };
    let mut counted = 0_u64;
    let mut part_index = 0_usize;
    let mut part_bytes = 0_u64;
    let mut part_hash = parts.first().map(|part| PartHash::new(part)).transpose()?;

    if let Some(reader) = &reader {
        loop {
            let (value, done) = reader.read().await?;
            let length = value.length();
            consumed(u64::from(length));
            ensure!(length <= CHUNK_BYTES, "stage runtime chunk exceeds bound");
            counted = counted
                .checked_add(u64::from(length))
                .ok_or_else(|| anyhow::anyhow!("stage stream size overflow"))?;
            ensure!(
                counted <= intent.byte_size.get(),
                "stage stream exceeds declared size"
            );
            if length > 0 {
                full.write(&value).await?;
                let mut offset = 0_u32;
                while offset < length {
                    let member = parts
                        .get(part_index)
                        .ok_or_else(|| anyhow::anyhow!("stage stream exceeds manifest"))?;
                    let remaining = member
                        .part
                        .byte_size
                        .get()
                        .checked_sub(part_bytes)
                        .ok_or_else(|| anyhow::anyhow!("stage part size overflow"))?;
                    let amount = remaining.min(u64::from(length - offset)) as u32;
                    ensure!(amount > 0, "stage part geometry invalid");
                    let view = value.subarray(offset, offset + amount);
                    let digest = part_hash
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("stage part digest missing"))?;
                    digest.write(&view).await?;
                    part_bytes += u64::from(amount);
                    offset += amount;
                    if part_bytes == member.part.byte_size.get() {
                        let finished = part_hash
                            .take()
                            .ok_or_else(|| anyhow::anyhow!("stage part digest missing"))?;
                        finished.finish(member).await?;
                        part_index += 1;
                        part_bytes = 0;
                        part_hash = parts.get(part_index).map(PartHash::new).transpose()?;
                    }
                }
            }
            if done {
                break;
            }
            ensure!(length > 0, "stage runtime returned empty unfinished chunk");
        }
    }
    ensure!(
        counted == intent.byte_size.get() && part_index == parts.len() && part_bytes == 0,
        "stage stream length differs"
    );
    let sha256 = hex::encode(full.finish().await?);
    ensure!(
        sha256 == intent.expected_sha256,
        "stage full digest differs"
    );
    Ok(VerifiedStreamDigest {
        sha256,
        byte_size: counted,
    })
}

struct PartHash {
    sha: Digest,
    md5: Option<Digest>,
}

impl PartHash {
    fn new(part: &DirectManifestPart) -> Result<Self> {
        Self::new_part(&part.part)
    }

    fn new_part(part: &aos_hub_core::direct_upload::DirectPart) -> Result<Self> {
        Ok(Self {
            sha: Digest::new("SHA-256")?,
            md5: if part.checksum.algorithm == DirectChecksumAlgorithm::Md5 {
                Some(Digest::new("MD5")?)
            } else {
                None
            },
        })
    }

    async fn write(&self, bytes: &Uint8Array) -> Result<()> {
        self.sha.write(bytes).await?;
        if let Some(md5) = &self.md5 {
            md5.write(bytes).await?;
        }
        Ok(())
    }

    async fn finish(self, member: &DirectManifestPart) -> Result<()> {
        self.finish_part(&member.part).await
    }

    async fn finish_part(self, member: &aos_hub_core::direct_upload::DirectPart) -> Result<()> {
        let sha = self.sha.finish().await?;
        ensure!(hex::encode(&sha) == member.sha256, "stage part SHA differs");
        let checksum = match self.md5 {
            Some(md5) => md5.finish().await?,
            None => sha,
        };
        ensure!(
            base64::engine::general_purpose::STANDARD.encode(checksum) == member.checksum.value,
            "stage provider checksum differs"
        );
        Ok(())
    }
}

struct Digest {
    writer: JsValue,
    promise: Promise,
    algorithm_bytes: usize,
    closed: std::cell::Cell<bool>,
}

impl Digest {
    fn new(algorithm: &str) -> Result<Self> {
        let crypto =
            Reflect::get(&js_sys::global(), &JsValue::from_str("crypto")).map_err(|_| refused())?;
        let constructor = Reflect::get(&crypto, &JsValue::from_str("DigestStream"))
            .map_err(|_| refused())?
            .dyn_into::<Function>()
            .map_err(|_| refused())?;
        let args = Array::new();
        args.push(&JsValue::from_str(algorithm));
        let stream = Reflect::construct(&constructor, &args)
            .map_err(|_| refused())
            .context("native digest constructor failed")?;
        let promise = Reflect::get(&stream, &JsValue::from_str("digest"))
            .map_err(|_| refused())?
            .dyn_into::<Promise>()
            .map_err(|_| refused())?;
        // Native Boolean handles any eventual rejection without inspecting its
        // private value, a leaked Rust closure or an unhandled diagnostic.
        let handler = Reflect::get(&js_sys::global(), &JsValue::from_str("Boolean"))
            .map_err(|_| refused())?;
        invoke(promise.as_ref(), "catch", &[handler])?;
        // Validate the completion interface before acquiring a native writer;
        // malformed features must not leave an unowned locked digest stream.
        let writer = invoke(&stream, "getWriter", &[])?;
        Ok(Self {
            writer,
            promise,
            algorithm_bytes: if algorithm == "MD5" { 16 } else { 32 },
            closed: std::cell::Cell::new(false),
        })
    }

    async fn write(&self, bytes: &Uint8Array) -> Result<()> {
        awaited(invoke(&self.writer, "write", &[bytes.clone().into()])?).await?;
        Ok(())
    }

    async fn finish(self) -> Result<Vec<u8>> {
        awaited(invoke(&self.writer, "close", &[])?).await?;
        self.closed.set(true);
        let value = JsFuture::from(self.promise.clone())
            .await
            .map_err(|_| refused())?;
        let buffer = value.dyn_into::<ArrayBuffer>().map_err(|_| refused())?;
        ensure!(
            buffer.byte_length() as usize == self.algorithm_bytes,
            "native stage digest size differs"
        );
        let bytes = Uint8Array::new(buffer.as_ref());
        Ok(bytes.to_vec())
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        if !self.closed.get() {
            if let Ok(value) = invoke(
                &self.writer,
                "abort",
                &[JsValue::from_str("stage verification canceled")],
            ) {
                consume_rejection(value);
            }
        }
        let _ = invoke(&self.writer, "releaseLock", &[]);
    }
}

/// Keeps each storage-side byte-stream read within the fixed 64 KiB view.
pub(crate) struct Reader {
    reader: JsValue,
    ended: std::cell::Cell<bool>,
}

impl Reader {
    /// Opens a native BYOB reader without reading or buffering the object.
    ///
    /// # Errors
    /// Returns an error when the platform has no native BYOB reader.
    pub(crate) fn new(stream: JsValue) -> Result<Self> {
        let options = js_sys::Object::new();
        Reflect::set(
            &options,
            &JsValue::from_str("mode"),
            &JsValue::from_str("byob"),
        )
        .map_err(|_| refused())?;
        Ok(Self {
            reader: invoke(&stream, "getReader", &[options.into()])
                .context("native BYOB reader unavailable")?,
            ended: std::cell::Cell::new(false),
        })
    }

    /// Reads one bounded native view and an independent end-of-stream flag.
    ///
    /// # Errors
    /// Returns an error for failed reads or an oversized/unfinished empty view.
    pub(crate) async fn read(&self) -> Result<(Uint8Array, bool)> {
        let buffer = Uint8Array::new_with_length(CHUNK_BYTES);
        let result = awaited(invoke(&self.reader, "read", &[buffer.into()])?)
            .await
            .context("native BYOB read failed")?;
        let done = Reflect::get(&result, &JsValue::from_str("done"))
            .map_err(|_| refused())?
            .as_bool()
            .ok_or_else(refused)?;
        let value = Reflect::get(&result, &JsValue::from_str("value")).map_err(|_| refused())?;
        let bytes = if value.is_undefined() && done {
            Uint8Array::new_with_length(0)
        } else {
            value.dyn_into::<Uint8Array>().map_err(|_| refused())?
        };
        self.ended.set(done);
        ensure!(
            bytes.length() <= CHUNK_BYTES && (done || bytes.length() > 0),
            "native BYOB reader exceeded its fixed view bound"
        );
        Ok((bytes, done))
    }

    /// Cancels the exact native reader, including an outstanding BYOB read.
    ///
    /// Native cancellation closes the source and resolves its pending read. It
    /// does not settle a provider mutation or authenticate any object identity.
    pub(crate) fn cancel(&self) {
        if !self.ended.replace(true) {
            if let Ok(value) = invoke(
                &self.reader,
                "cancel",
                &[JsValue::from_str("stage verification canceled")],
            ) {
                consume_rejection(value);
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.cancel();
        let _ = invoke(&self.reader, "releaseLock", &[]);
    }
}

fn invoke(object: &JsValue, name: &str, arguments: &[JsValue]) -> Result<JsValue> {
    let function = Reflect::get(object, &JsValue::from_str(name))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())?;
    let args = Array::new();
    for argument in arguments {
        args.push(argument);
    }
    function.apply(object, &args).map_err(|_| refused())
}

async fn awaited(value: JsValue) -> Result<JsValue> {
    let promise = value.dyn_into::<Promise>().map_err(|_| refused())?;
    JsFuture::from(promise).await.map_err(|_| refused())
}

fn refused() -> anyhow::Error {
    anyhow::anyhow!("native stage stream interface refused")
}

fn consume_rejection(value: JsValue) {
    if value.is_instance_of::<Promise>() {
        if let Ok(handler) = Reflect::get(&js_sys::global(), &JsValue::from_str("Boolean")) {
            let _ = invoke(&value, "catch", &[handler]);
        }
    }
}
