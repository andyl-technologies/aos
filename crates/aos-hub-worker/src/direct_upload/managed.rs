//! Ordinary pinned R2 binding operations with native bounded streams.
//!
//! Create and Complete use their actual SDK acknowledgements. Same-GET metadata
//! identifies the immutable source incarnation before its stream is consumed.
//! A native backpressured stream hashes each copied part independently; object
//! bytes never enter a Rust part buffer or the Native control transport.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use js_sys::{Array, Function, Object, Promise, Reflect};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Env, Response, ResponseBody};

mod stream;

pub(crate) type ObjectReceipt = DirectHostedSdkObjectReceipt;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateReceipt {
    pub(crate) upload_id: Option<String>,
    pub(crate) empty: Option<ObjectReceipt>,
}

pub(crate) fn probe(env: &Env) -> Result<()> {
    let bucket = bucket(env)?;
    for method in [
        "createMultipartUpload",
        "resumeMultipartUpload",
        "get",
        "head",
        "put",
        "delete",
    ] {
        function(&bucket, method)?;
    }
    let crypto =
        Reflect::get(&js_sys::global(), &JsValue::from_str("crypto")).map_err(|_| refused())?;
    function(&crypto, "DigestStream")?;
    Ok(())
}

pub(crate) fn bucket(env: &Env) -> Result<JsValue> {
    Ok(env
        .bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?
        .as_ref()
        .clone())
}

pub(crate) async fn create(env: &Env, key: &str, empty: bool) -> Result<CreateReceipt> {
    create_checked(env, key, empty, || Ok(())).await
}

/// Rechecks the original cutoff after waiting for provider capacity.
pub(crate) async fn create_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    empty: bool,
    before_dispatch: F,
) -> Result<CreateReceipt> {
    create_class_checked(
        env,
        key,
        empty,
        super::provider_capacity::Class::Foreground,
        before_dispatch,
    )
    .await
}

/// Creates a source under the selected shared capacity class and fresh cutoff.
pub(crate) async fn create_class_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    empty: bool,
    class: super::provider_capacity::Class,
    before_dispatch: F,
) -> Result<CreateReceipt> {
    let _capacity =
        super::provider_capacity::acquire_class_checked(1, class, &before_dispatch).await?;
    let bucket = bucket(env)?;
    before_dispatch()?;
    if empty {
        let acknowledged = invoke_await_unmetered(
            &bucket,
            "put",
            &[
                JsValue::from_str(key),
                js_sys::Uint8Array::new_with_length(0).into(),
            ],
        )
        .await?;
        return Ok(CreateReceipt {
            upload_id: None,
            empty: Some(identity(&acknowledged)?),
        });
    }
    let upload =
        invoke_await_unmetered(&bucket, "createMultipartUpload", &[JsValue::from_str(key)]).await?;
    let upload_id = text(&upload, "uploadId")?;
    ensure!(
        !upload_id.is_empty()
            && upload_id.len() <= 2048
            && !upload_id.chars().any(char::is_control),
        "direct SDK upload identity invalid"
    );
    for method in ["uploadPart", "complete", "abort"] {
        function(&upload, method)?;
    }
    Ok(CreateReceipt {
        upload_id: Some(upload_id),
        empty: None,
    })
}

pub(crate) async fn complete(
    env: &Env,
    key: &str,
    upload_id: &str,
    parts: &[DirectManifestPart],
) -> Result<ObjectReceipt> {
    complete_checked(env, key, upload_id, parts, || Ok(())).await
}

/// Rechecks original publication authority immediately before the SDK mutation.
pub(crate) async fn complete_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    upload_id: &str,
    parts: &[DirectManifestPart],
    before_complete: F,
) -> Result<ObjectReceipt> {
    ensure!(
        !parts.is_empty() && parts.len() <= MAX_DIRECT_PARTS as usize,
        "direct SDK completion count invalid"
    );
    let upload = resume(&bucket(env)?, key, upload_id)?;
    let encoded = Array::new();
    for (index, part) in parts.iter().enumerate() {
        ensure!(
            part.part.part_number as usize == index + 1 && valid_direct_etag(&part.etag),
            "direct SDK completion part invalid"
        );
        let member = Object::new();
        set(&member, "partNumber", &JsValue::from(part.part.part_number))?;
        set(
            &member,
            "etag",
            &JsValue::from_str(&part.etag[1..part.etag.len() - 1]),
        )?;
        encoded.push(&member);
    }
    identity(&invoke_await_checked(&upload, "complete", &[encoded.into()], before_complete).await?)
}

pub(crate) async fn abort(env: &Env, key: &str, upload_id: &str) -> Result<()> {
    abort_checked(env, key, upload_id, || Ok(())).await
}

/// Rechecks the immutable Abort cutoff at the actual provider dispatch.
pub(crate) async fn abort_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    upload_id: &str,
    before_dispatch: F,
) -> Result<()> {
    invoke_await_checked(
        &resume(&bucket(env)?, key, upload_id)?,
        "abort",
        &[],
        before_dispatch,
    )
    .await?;
    Ok(())
}

/// Deletes the exact acknowledged empty stage under its original dispatch cutoff.
pub(crate) async fn abort_empty_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    original: &ObjectReceipt,
    before_dispatch: F,
) -> Result<()> {
    ensure!(
        original.byte_size.get() == 0,
        "direct empty Abort source is not empty"
    );
    ensure!(
        head(env, key).await?.as_ref() == Some(original),
        "direct empty Abort incarnation changed"
    );
    invoke_await_checked(
        &bucket(env)?,
        "delete",
        &[JsValue::from_str(key)],
        before_dispatch,
    )
    .await?;
    Ok(())
}

pub(crate) async fn get(
    env: &Env,
    key: &str,
    range: Option<(u64, u64)>,
) -> Result<(
    ObjectReceipt,
    worker::web_sys::ReadableStream,
    super::provider_capacity::Permit,
)> {
    get_class(env, key, range, super::provider_capacity::Class::Foreground).await
}

pub(crate) async fn get_class(
    env: &Env,
    key: &str,
    range: Option<(u64, u64)>,
    class: super::provider_capacity::Class,
) -> Result<(
    ObjectReceipt,
    worker::web_sys::ReadableStream,
    super::provider_capacity::Permit,
)> {
    get_class_checked(env, key, range, class, || Ok(())).await
}

/// Rechecks the read authority after waiting for shared provider capacity.
pub(crate) async fn get_class_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    range: Option<(u64, u64)>,
    class: super::provider_capacity::Class,
    before_dispatch: F,
) -> Result<(
    ObjectReceipt,
    worker::web_sys::ReadableStream,
    super::provider_capacity::Permit,
)> {
    let capacity =
        super::provider_capacity::acquire_class_checked(1, class, &before_dispatch).await?;
    before_dispatch()?;
    let (identity, stream) = get_unmetered(env, key, range).await?;
    Ok((identity, stream, capacity))
}

/// Opens a source while its caller retains an aggregate provider reservation.
///
/// This seam permits a pair verifier to reserve both live GET slots atomically.
pub(crate) async fn get_reserved(
    env: &Env,
    key: &str,
    capacity: &super::provider_capacity::Permit,
) -> Result<(ObjectReceipt, worker::web_sys::ReadableStream)> {
    let _retained = capacity;
    get_unmetered(env, key, None).await
}

async fn get_unmetered(
    env: &Env,
    key: &str,
    range: Option<(u64, u64)>,
) -> Result<(ObjectReceipt, worker::web_sys::ReadableStream)> {
    let bucket = bucket(env)?;
    let mut arguments = vec![JsValue::from_str(key)];
    if let Some((offset, length)) = range {
        ensure!(
            length > 0 && offset <= MAX_DIRECT_OBJECT_BYTES && length <= MAX_DIRECT_PART_BYTES,
            "direct SDK range invalid"
        );
        let range = Object::new();
        set(&range, "offset", &JsValue::from_f64(offset as f64))?;
        set(&range, "length", &JsValue::from_f64(length as f64))?;
        let options = Object::new();
        set(&options, "range", &range)?;
        arguments.push(options.into());
    }
    let object = invoke_await_unmetered(&bucket, "get", &arguments).await?;
    ensure!(
        !object.is_null() && !object.is_undefined(),
        "direct SDK closed source absent"
    );
    let identity = identity(&object)?;
    let body = Reflect::get(&object, &JsValue::from_str("body"))
        .map_err(|_| refused())?
        .dyn_into::<worker::web_sys::ReadableStream>()
        .map_err(|_| refused())?;
    Ok((identity, body))
}

pub(crate) async fn head(env: &Env, key: &str) -> Result<Option<ObjectReceipt>> {
    let object = invoke_await(&bucket(env)?, "head", &[JsValue::from_str(key)]).await?;
    if object.is_null() || object.is_undefined() {
        return Ok(None);
    }
    Ok(Some(identity(&object)?))
}

pub(crate) async fn verify(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    intent: &DirectUploadIntent,
    parts: &[DirectManifestPart],
) -> Result<()> {
    verify_class(
        env,
        key,
        closed,
        intent,
        parts,
        super::provider_capacity::Class::Foreground,
    )
    .await
}

pub(crate) async fn verify_class(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    intent: &DirectUploadIntent,
    parts: &[DirectManifestPart],
    class: super::provider_capacity::Class,
) -> Result<()> {
    verify_class_observed(env, key, closed, intent, parts, class, None).await
}

/// Measures actual source consumption without changing immutable verification.
pub(crate) async fn verify_class_observed(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    intent: &DirectUploadIntent,
    parts: &[DirectManifestPart],
    class: super::provider_capacity::Class,
    original: Option<super::observation::Object>,
) -> Result<()> {
    let (snapshot, stream, _capacity) = get_class(env, key, None, class).await?;
    ensure!(
        &snapshot == closed && snapshot.byte_size == intent.byte_size,
        "direct SDK source incarnation changed"
    );
    let mut observation = original.map(super::observation::Read::new);
    let consumed = |bytes| {
        if let Some(observation) = &observation {
            observation.consumed(bytes);
        }
    };
    let verified = crate::direct_digest::verify_response_observed(
        Response::from_body(ResponseBody::Stream(stream))?,
        intent,
        parts,
        &consumed,
    )
    .await?;
    ensure!(
        verified.sha256 == intent.expected_sha256 && verified.byte_size == intent.byte_size.get(),
        "direct SDK verification differs"
    );
    if let Some(observation) = &mut observation {
        observation.positive();
    }
    Ok(())
}

pub(crate) async fn copy_part(
    env: &Env,
    source_key: &str,
    closed: &ObjectReceipt,
    destination_key: &str,
    upload_id: &str,
    intent: &DirectUploadIntent,
    part: &DirectPart,
) -> Result<DirectManifestPart> {
    copy_part_checked(
        env,
        source_key,
        closed,
        destination_key,
        upload_id,
        intent,
        part,
        || Ok(()),
    )
    .await
}

/// Rechecks the original cutoff after the awaited source GET and before upload.
pub(crate) async fn copy_part_checked<F: Fn() -> Result<()>>(
    env: &Env,
    source_key: &str,
    closed: &ObjectReceipt,
    destination_key: &str,
    upload_id: &str,
    intent: &DirectUploadIntent,
    part: &DirectPart,
    before_upload: F,
) -> Result<DirectManifestPart> {
    part.validate(intent)?;
    let _capacity = super::provider_capacity::acquire_checked(2, &before_upload).await?;
    let (identity, stream) = get_unmetered(
        env,
        source_key,
        Some((part.offset.get(), part.byte_size.get())),
    )
    .await?;
    ensure!(
        &identity == closed,
        "direct SDK copy source incarnation changed"
    );
    let (forwarded, proof) = crate::direct_digest::forward_part(stream, intent, part)?;
    let mut fixed = stream::FixedPartStream::new(forwarded, part.byte_size.get())?;
    let destination = resume(&bucket(env)?, destination_key, upload_id)?;
    before_upload()?;
    let result = invoke_await_unmetered(
        &destination,
        "uploadPart",
        &[JsValue::from(part.part_number), fixed.readable().into()],
    )
    .await;
    if result.is_err() {
        fixed.cancel();
        proof.cancel();
    }
    // Provider acknowledgement alone cannot satisfy exact source integrity.
    let verified = proof.verify().await;
    if verified.is_err() {
        fixed.cancel();
    }
    let forwarded = fixed.finish().await;
    let result = result?;
    verified?;
    forwarded?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(&text(&result, "etag")?)?;
    ensure!(
        valid_direct_etag(&etag),
        "direct SDK copied part acknowledgement invalid"
    );
    Ok(DirectManifestPart {
        part: part.clone(),
        etag,
    })
}

pub(crate) async fn read_metadata(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    maximum: usize,
) -> Result<Vec<u8>> {
    read_metadata_class(
        env,
        key,
        closed,
        maximum,
        super::provider_capacity::Class::Foreground,
    )
    .await
}

pub(crate) async fn read_metadata_class(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    maximum: usize,
    class: super::provider_capacity::Class,
) -> Result<Vec<u8>> {
    read_metadata_class_observed(env, key, closed, maximum, class, None).await
}

/// Measures bounded semantic rereads independently of the full-source read.
pub(crate) async fn read_metadata_class_observed(
    env: &Env,
    key: &str,
    closed: &ObjectReceipt,
    maximum: usize,
    class: super::provider_capacity::Class,
    original: Option<super::observation::Object>,
) -> Result<Vec<u8>> {
    ensure!(
        closed.byte_size.get() <= maximum as u64,
        "direct semantic source exceeds bound"
    );
    let (identity, stream, _capacity) = get_class(env, key, None, class).await?;
    ensure!(
        &identity == closed,
        "direct semantic source incarnation changed"
    );
    let mut observation = original.map(super::observation::Read::metadata);
    let consumed = |bytes| {
        if let Some(observation) = &observation {
            observation.consumed(bytes);
        }
    };
    let bytes = crate::direct_digest::read_bounded_native_observed(
        Response::from_body(ResponseBody::Stream(stream))?,
        maximum,
        &consumed,
    )
    .await?;
    if let Some(observation) = &mut observation {
        observation.positive();
    }
    Ok(bytes)
}

pub(crate) async fn upload_probe_part(
    env: &Env,
    key: &str,
    upload_id: &str,
    number: u32,
    bytes: &[u8],
) -> Result<String> {
    upload_probe_part_checked(env, key, upload_id, number, bytes, || Ok(())).await
}

/// Rechecks the probe's original cutoff after waiting for provider capacity.
pub(crate) async fn upload_probe_part_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    upload_id: &str,
    number: u32,
    bytes: &[u8],
    before_dispatch: F,
) -> Result<String> {
    ensure!(bytes.len() <= 64 * 1024, "SDK probe bytes exceed bound");
    let result = invoke_await_checked(
        &resume(&bucket(env)?, key, upload_id)?,
        "uploadPart",
        &[
            JsValue::from(number),
            js_sys::Uint8Array::from(bytes).into(),
        ],
        before_dispatch,
    )
    .await?;
    aos_hub_core::surface_write::strong_if_match_etag(&text(&result, "etag")?)
}

/// Distinguishes a positive provider NoSuchUpload refusal from transport ambiguity.
pub(crate) async fn rejected_closed_part(
    env: &Env,
    key: &str,
    upload_id: &str,
    bytes: &[u8],
) -> Result<&'static str> {
    rejected_closed_part_checked(env, key, upload_id, bytes, || Ok(())).await
}

/// Checks the original probe cutoff immediately before the late-part dispatch.
pub(crate) async fn rejected_closed_part_checked<F: Fn() -> Result<()>>(
    env: &Env,
    key: &str,
    upload_id: &str,
    bytes: &[u8],
    before_dispatch: F,
) -> Result<&'static str> {
    ensure!(bytes.len() <= 64 * 1024, "SDK probe bytes exceed bound");
    let _capacity = super::provider_capacity::acquire_checked(1, &before_dispatch).await?;
    let upload = resume(&bucket(env)?, key, upload_id)?;
    before_dispatch()?;
    let promise = invoke(
        &upload,
        "uploadPart",
        &[JsValue::from(1_u32), js_sys::Uint8Array::from(bytes).into()],
    )?
    .dyn_into::<Promise>()
    .map_err(|_| refused())?;
    match JsFuture::from(promise).await {
        Ok(_) => Ok("positive_unexpected_late_part"),
        Err(value) => {
            let message = Reflect::get(&value, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_default();
            // Only the SDK's positively identified provider denial is negative
            // evidence. Network failures, cancellation and unfamiliar codes
            // retain unknown classification without diagnostic disclosure.
            if message.contains("NoSuchUpload")
                || (message.contains("10024")
                    && message.contains("multipart upload does not exist"))
            {
                Ok("negative")
            } else {
                Ok("unknown_sdk_rejection")
            }
        }
    }
}

pub(crate) fn identity(object: &JsValue) -> Result<ObjectReceipt> {
    let version = text(object, "version")?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(&text(object, "etag")?)?;
    let size = Reflect::get(object, &JsValue::from_str("size"))
        .map_err(|_| refused())?
        .as_f64()
        .filter(|size| {
            size.is_finite()
                && *size >= 0.0
                && size.fract() == 0.0
                && *size <= MAX_DIRECT_OBJECT_BYTES as f64
        })
        .ok_or_else(refused)?;
    ensure!(
        aos_hub_core::storage_work::valid_provider_version(&version) && valid_direct_etag(&etag),
        "direct SDK acknowledgement invalid"
    );
    Ok(ObjectReceipt {
        version,
        etag,
        byte_size: WireInteger::new(size as u64),
    })
}

pub(crate) fn resume(bucket: &JsValue, key: &str, upload_id: &str) -> Result<JsValue> {
    invoke(
        bucket,
        "resumeMultipartUpload",
        &[JsValue::from_str(key), JsValue::from_str(upload_id)],
    )
}

pub(crate) async fn invoke_await(
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
) -> Result<JsValue> {
    invoke_await_checked(object, method, arguments, || Ok(())).await
}

pub(crate) async fn invoke_await_checked<F: Fn() -> Result<()>>(
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
    before_dispatch: F,
) -> Result<JsValue> {
    invoke_await_class_checked(
        object,
        method,
        arguments,
        super::provider_capacity::Class::Foreground,
        before_dispatch,
    )
    .await
}

/// Invokes one SDK effect under its shared capacity class and original cutoff.
pub(crate) async fn invoke_await_class_checked<F: Fn() -> Result<()>>(
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
    class: super::provider_capacity::Class,
    before_dispatch: F,
) -> Result<JsValue> {
    let _capacity =
        super::provider_capacity::acquire_class_checked(1, class, &before_dispatch).await?;
    before_dispatch()?;
    invoke_await_unmetered(object, method, arguments).await
}

async fn invoke_await_unmetered(
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
) -> Result<JsValue> {
    super::provider_capacity::record_dispatch();
    let promise = invoke(object, method, arguments)?
        .dyn_into::<Promise>()
        .map_err(|_| refused())?;
    JsFuture::from(promise).await.map_err(|_| refused())
}

fn invoke(object: &JsValue, method: &str, arguments: &[JsValue]) -> Result<JsValue> {
    let arguments = arguments.iter().cloned().collect::<Array>();
    function(object, method)?
        .apply(object, &arguments)
        .map_err(|_| refused())
}

fn function(object: &JsValue, method: &str) -> Result<Function> {
    Reflect::get(object, &JsValue::from_str(method))
        .map_err(|_| refused())?
        .dyn_into()
        .map_err(|_| refused())
}

fn set(object: &JsValue, name: &str, value: &JsValue) -> Result<()> {
    Reflect::set(object, &JsValue::from_str(name), value).map_err(|_| refused())?;
    Ok(())
}

fn text(object: &JsValue, name: &str) -> Result<String> {
    Reflect::get(object, &JsValue::from_str(name))
        .map_err(|_| refused())?
        .as_string()
        .ok_or_else(refused)
}

fn refused() -> anyhow::Error {
    anyhow::anyhow!("direct native R2 SDK interface refused")
}
