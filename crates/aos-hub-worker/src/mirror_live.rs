//! Fresh uncached upstream streams delivered without a Native byte relay.
//!
//! A distinct ingress grant and independently reviewed live purpose admit one
//! GET/HEAD. Provider capacity survives through EOF, error or client cancellation.
//! Each source view and Rust copy is at most 64 KiB; no whole body is retained.
//! This path writes no stage, object, journal, pointer or catalogue.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::hybrid_ingress::{
    live::{
        HybridLiveDeliveryClass, HybridLiveDeliveryTarget, LiveBodyBudget, LIVE_STREAM_SECONDS,
    },
    HybridIngressAssertion, HybridIngressKey,
};
use futures_util::stream;
use worker::{
    Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, ResponseBody,
};

use crate::direct_upload::{config::QualifiedConfig, provider_capacity};

/// Opens a separately reviewed source only after exact current ingress authentication.
///
/// # Errors
/// Refuses foreign or stale grants, unreviewed profiles and unsafe source framing.
pub(crate) async fn deliver(
    env: &Env,
    key: &HybridIngressKey,
    compact: &str,
    request: &HybridIngressAssertion,
) -> Result<Response> {
    // Authenticate before reading configuration or taking shared capacity.
    key.verify_live_delivery(compact, request, aos_hub_core::clock::now_unix_secs())?;
    let config = QualifiedConfig::load(env).await?;
    let (profile, _) = config.managed(env)?;
    let target =
        key.verify_live_delivery(compact, request, i64::try_from(config.latest_now()?)?)?;
    ensure!(
        target.protected_profile_digest == profile.digest()?,
        "live profile changed"
    );
    let (accepted, live) =
        crate::mirror_import::acceptance::require_live(env, &profile, &config.acceptance_evidence)
            .await?;
    let before_dispatch = || -> Result<()> {
        let now = config.latest_now()?;
        accepted.check(now)?;
        live.validate_dispatch_time(now)?;
        key.verify_live_delivery(compact, request, i64::try_from(now)?)?;
        Ok(())
    };
    let maximum = target.maximum_bytes.min(live.maximum_bytes);
    let metadata = target.class == HybridLiveDeliveryClass::Metadata;
    let buffer = crate::mirror_import::buffers::acquire(metadata, &before_dispatch).await?;
    let capacity = provider_capacity::acquire_class_checked(
        1,
        if metadata {
            provider_capacity::Class::Metadata
        } else {
            provider_capacity::Class::Bulk
        },
        &before_dispatch,
    )
    .await?;

    let headers = Headers::new();
    headers.set("accept-encoding", "identity")?;
    let method = if request.method == "HEAD" {
        Method::Head
    } else {
        Method::Get
    };
    let mut init = RequestInit::new();
    init.with_method(method.clone())
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let upstream = Request::new_with_init(target.upstream_url()?.as_str(), &init)?;
    let stream_cutoff = request
        .issued_at
        .checked_add(LIVE_STREAM_SECONDS)
        .context("live stream cutoff overflow")?;
    let cancellation = SourceCancellation::new()?;
    let signal = worker::AbortSignal::from(cancellation.0.signal());
    let response = bounded(stream_cutoff, config.uncertainty, async {
        before_dispatch()?;
        provider_capacity::record_dispatch();
        Ok(Fetch::Request(upstream).send_with_signal(&signal).await?)
    })
    .await?;
    let now = i64::try_from(config.latest_now()?)?;
    ensure!(
        now < stream_cutoff,
        "live source response arrived after stream cutoff"
    );
    if response.status_code() == 404 {
        return Ok(Response::empty()?
            .with_status(404)
            .with_headers(delivery_headers(&target, None)?));
    }
    ensure!(
        response.status_code() == 200,
        "live upstream status refused"
    );
    let encoding = response.headers().get("content-encoding")?;
    ensure!(
        encoding
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "live transformed source refused"
    );
    let declared = response
        .headers()
        .get("content-length")?
        .map(|value| value.parse::<u64>())
        .transpose()
        .context("live length malformed")?;
    ensure!(
        declared.is_none_or(|size| size <= maximum),
        "live source exceeds measured ceiling"
    );
    let headers = delivery_headers(&target, declared)?;
    if method == Method::Head {
        return Ok(Response::empty()?.with_headers(headers));
    }

    let (_, body) = response.into_parts();
    let reader = match body {
        ResponseBody::Stream(stream) => Some(crate::direct_digest::Reader::new(stream.into())?),
        ResponseBody::Empty => None,
        _ => anyhow::bail!("live delivery requires a native source stream"),
    };
    let state = StreamState {
        reader,
        _cancellation: cancellation,
        _buffer: buffer,
        _capacity: capacity,
        budget: LiveBodyBudget::new(maximum, declared)?,
        cutoff: stream_cutoff,
        uncertainty: config.uncertainty,
    };
    let output = stream::try_unfold(state, |mut state| async move {
        if state.budget.ended() {
            return Ok(None);
        }
        let now = aos_hub_core::clock::now_unix_secs()
            .checked_add(
                i64::try_from(state.uncertainty)
                    .map_err(|_| worker::Error::RustError("live clock overflow".into()))?,
            )
            .ok_or_else(|| worker::Error::RustError("live clock overflow".into()))?;
        if now >= state.cutoff {
            return Err(worker::Error::RustError("live stream expired".into()));
        }
        let Some(reader) = &state.reader else {
            state
                .budget
                .consume(0, true)
                .map_err(|_| worker::Error::RustError("live body truncated".into()))?;
            return Ok(None);
        };
        let (view, done) = bounded(state.cutoff, state.uncertainty, reader.read())
            .await
            .map_err(|_| worker::Error::RustError("live source read failed".into()))?;
        let now = aos_hub_core::clock::now_unix_secs()
            .checked_add(
                i64::try_from(state.uncertainty)
                    .map_err(|_| worker::Error::RustError("live clock overflow".into()))?,
            )
            .ok_or_else(|| worker::Error::RustError("live clock overflow".into()))?;
        if now >= state.cutoff {
            return Err(worker::Error::RustError("live stream expired".into()));
        }
        state
            .budget
            .consume(u64::from(view.length()), done)
            .map_err(|_| worker::Error::RustError("live body length refused".into()))?;
        // A BYOB EOF may contain the final nonempty view. Deliver it before
        // dropping the reader and its retained provider capacity on the next poll.
        if view.length() == 0 && done {
            return Ok(None);
        }
        Ok(Some((view.to_vec(), state)))
    });
    Ok(Response::from_stream(output)?.with_headers(headers))
}

struct StreamState {
    reader: Option<crate::direct_digest::Reader>,
    _cancellation: SourceCancellation,
    _buffer: crate::mirror_import::buffers::Permit,
    // The source occupies actual provider capacity until EOF/error/cancellation.
    _capacity: provider_capacity::Permit,
    budget: LiveBodyBudget,
    cutoff: i64,
    uncertainty: u64,
}

fn delivery_headers(target: &HybridLiveDeliveryTarget, length: Option<u64>) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("cache-control", "private, no-store")?;
    headers.set("vary", "Authorization, Cookie")?;
    headers.set(
        "content-type",
        aos_hub_core::keymap::content_type(&target.path),
    )?;
    headers.set("x-content-type-options", "nosniff")?;
    if aos_hub_core::keymap::is_producer_document(&target.path) {
        headers.set("content-security-policy", "sandbox")?;
        headers.set("content-disposition", "attachment")?;
    }
    if let Some(length) = length {
        headers.set("content-length", &length.to_string())?;
    }
    Ok(headers)
}

/// Returns only a bounded fresh metadata query; bulk sources never enter Native.
///
/// # Errors
/// Refuses changed plans, unreviewed profiles and excessive or malformed source bodies.
pub(crate) async fn inspect_metadata(
    env: &Env,
    plan: &aos_hub_core::storage_work::StorageWorkPlan,
) -> Result<aos_hub_core::storage_work::StorageWorkResult> {
    use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

    let StorageWorkOperation::InspectMirrorLiveMetadata { target } = &plan.operation else {
        anyhow::bail!("not a live metadata query");
    };
    target.validate()?;
    ensure!(
        target.class == HybridLiveDeliveryClass::Metadata,
        "bulk query refused"
    );
    let config = QualifiedConfig::load(env).await?;
    let (profile, _) = config.managed(env)?;
    ensure!(
        target.protected_profile_digest == profile.digest()?,
        "live profile changed"
    );
    let (accepted, live) =
        crate::mirror_import::acceptance::require_live(env, &profile, &config.acceptance_evidence)
            .await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let before_dispatch = || -> Result<()> {
        let latest = config.latest_now()?;
        accepted.check(latest)?;
        live.validate_dispatch_time(latest)?;
        plan.validate(&deployment, i64::try_from(latest)?)?;
        ensure!(
            latest < u64::try_from(plan.expires_at)?,
            "live metadata request expired"
        );
        Ok(())
    };
    let _buffer = crate::mirror_import::buffers::acquire(true, &before_dispatch).await?;
    let _capacity = provider_capacity::acquire_class_checked(
        1,
        provider_capacity::Class::Metadata,
        &before_dispatch,
    )
    .await?;
    let maximum = target.maximum_bytes.min(live.maximum_bytes);
    let headers = Headers::new();
    headers.set("accept-encoding", "identity")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(target.upstream_url()?.as_str(), &init)?;
    let cutoff = plan
        .issued_at
        .checked_add(LIVE_STREAM_SECONDS)
        .context("live query cutoff overflow")?;
    let _cancellation = SourceCancellation::new()?;
    let signal = worker::AbortSignal::from(_cancellation.0.signal());
    let response = bounded(cutoff, config.uncertainty, async {
        before_dispatch()?;
        provider_capacity::record_dispatch();
        Ok(Fetch::Request(request).send_with_signal(&signal).await?)
    })
    .await?;
    ensure!(
        i64::try_from(config.latest_now()?)? < cutoff,
        "live query response expired"
    );
    if response.status_code() == 404 {
        return Ok(crate::surface::storage_work_result(
            plan,
            StorageWorkOutcome::NotFound,
            0,
        ));
    }
    ensure!(
        response.status_code() == 200,
        "live query source status refused"
    );
    ensure!(
        response
            .headers()
            .get("content-encoding")?
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "live query encoding refused"
    );
    let declared = response
        .headers()
        .get("content-length")?
        .map(|value| value.parse::<u64>())
        .transpose()
        .context("live query length malformed")?;
    ensure!(
        declared.is_none_or(|size| size <= maximum),
        "live query source exceeds bound"
    );
    let bytes = bounded(
        cutoff,
        config.uncertainty,
        crate::direct_digest::read_bounded_native(response, usize::try_from(maximum)?),
    )
    .await?;
    ensure!(
        i64::try_from(config.latest_now()?)? < cutoff
            && declared.is_none_or(|size| size == bytes.len() as u64),
        "live query expired or truncated"
    );
    use base64::Engine as _;
    let outcome = StorageWorkOutcome::MirrorLiveMetadata {
        sha256: aos_hub_core::hybrid_ingress::body_sha256(&bytes),
        size: bytes.len() as u64,
        content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    };
    Ok(crate::surface::storage_work_result(
        plan,
        outcome,
        bytes.len() as u64,
    ))
}

struct SourceCancellation(worker::web_sys::AbortController);

impl SourceCancellation {
    fn new() -> Result<Self> {
        worker::web_sys::AbortController::new()
            .map(Self)
            .map_err(|_| anyhow::anyhow!("live source cancellation unavailable"))
    }
}

impl Drop for SourceCancellation {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The timer belongs to this invocation; shared pools never wake foreign I/O.
async fn bounded<T>(
    cutoff: i64,
    uncertainty: u64,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let latest = aos_hub_core::clock::now_unix_secs()
        .checked_add(i64::try_from(uncertainty)?)
        .context("live clock overflow")?;
    let remaining = cutoff
        .checked_sub(latest)
        .filter(|seconds| *seconds > 0)
        .context("live stream expired")?;
    let timer = worker::Delay::from(std::time::Duration::from_secs(u64::try_from(remaining)?));
    match futures_util::future::select(Box::pin(operation), Box::pin(timer)).await {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(_) => anyhow::bail!("live source deadline reached"),
    }
}
