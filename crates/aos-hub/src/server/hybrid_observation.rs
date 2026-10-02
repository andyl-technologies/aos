//! Exposed application frames for one actual Native Hybrid ingress invocation.
//!
//! Hash-only counters preserve unread, partial, failed and cancelled outcomes.
//! Response frames offered by Native are distinct from bytes independently
//! received by the Worker. The wrapper forwards every frame, including trailers,
//! without buffering, retrying, reading ahead or changing any authority check.

use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aos_hub_core::hybrid_ingress::observation::IngressCheckedContexts;
use axum::body::{Body, Bytes, HttpBody};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use http_body::{Frame, SizeHint};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Default)]
struct ObservedFrames {
    digest: Sha256,
    bytes: u64,
    eof: bool,
    failed: bool,
    overflow: bool,
}

impl ObservedFrames {
    fn observe(&mut self, bytes: &[u8]) {
        if let Some(length) = self.bytes.checked_add(bytes.len() as u64) {
            self.bytes = length;
            self.digest.update(bytes);
        } else {
            self.overflow = true;
        }
    }

    fn receipt(&self) -> FrameReceipt {
        FrameReceipt {
            exposed_bytes: self.bytes.to_string(),
            exposed_sha256: hex::encode(self.digest.clone().finalize()),
            eof: self.eof,
            failed: self.failed,
            overflow: self.overflow,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameReceipt {
    exposed_bytes: String,
    exposed_sha256: String,
    eof: bool,
    failed: bool,
    overflow: bool,
}

struct State {
    request_id: Option<String>,
    method: String,
    path_sha256: String,
    compact_sha256: Option<String>,
    original_sha256: Option<String>,
    phase: Option<String>,
    envelope_authenticated: bool,
    body_authenticated: bool,
    stage: &'static str,
    status: Option<u16>,
    checks: Option<IngressCheckedContexts>,
    request: ObservedFrames,
    reply: ObservedFrames,
    emitted: bool,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    version: u8,
    request_id: &'a Option<String>,
    method: &'a str,
    path_sha256: &'a str,
    compact_sha256: &'a Option<String>,
    original_sha256: &'a Option<String>,
    phase: &'a Option<String>,
    native_handler_source_sha256: &'a str,
    checked_context_source_sha256: &'a str,
    envelope_authenticated: bool,
    body_authenticated: bool,
    stage: &'a str,
    status: Option<u16>,
    checked_contexts: &'a Option<IngressCheckedContexts>,
    request_consumed: FrameReceipt,
    reply_offered: FrameReceipt,
    completed_at_unix_micros: String,
}

impl State {
    fn emit(&mut self) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        static SOURCE: OnceLock<String> = OnceLock::new();
        let source = SOURCE.get_or_init(|| {
            let mut digest = Sha256::new();
            digest.update(include_bytes!("../server.rs"));
            digest.update(include_bytes!("hybrid_observation.rs"));
            hex::encode(digest.finalize())
        });
        let receipt = Receipt {
            version: 1,
            request_id: &self.request_id,
            method: &self.method,
            path_sha256: &self.path_sha256,
            compact_sha256: &self.compact_sha256,
            original_sha256: &self.original_sha256,
            phase: &self.phase,
            native_handler_source_sha256: source,
            checked_context_source_sha256:
                aos_hub_core::hybrid_ingress::observation::observation_source_sha256(),
            envelope_authenticated: self.envelope_authenticated,
            body_authenticated: self.body_authenticated,
            stage: self.stage,
            status: self.status,
            checked_contexts: &self.checks,
            request_consumed: self.request.receipt(),
            reply_offered: self.reply.receipt(),
            completed_at_unix_micros: now.as_micros().to_string(),
        };
        let Ok(encoded) = serde_json::to_string(&receipt) else {
            return;
        };
        if encoded.len() > 16 * 1024 {
            return;
        }
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        let _span = self.span.enter();
        tracing::info!("native_ingress_application_body_observation {encoded}");
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // Last-owner destruction also covers cancellation where a request body
        // outlives the handler guard. It cannot manufacture a completed check.
        self.emit();
    }
}

/// Owns observation until the handler returns or is cancelled.
pub(super) struct IngressObservation(Arc<Mutex<State>>);

impl IngressObservation {
    pub(super) fn new(headers: &HeaderMap, method: &str, path: &str) -> Self {
        let request_id = single_header(headers, "x-aos-fleet-request-id")
            .filter(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .map(str::to_owned);
        let compact_sha256 = single_header(headers, "x-aos-hybrid-ingress")
            .filter(|value| value.len() <= 16 * 1024)
            .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
        Self(Arc::new(Mutex::new(State {
            request_id,
            method: if method.len() <= 32 {
                method.into()
            } else {
                String::new()
            },
            path_sha256: hex::encode(Sha256::digest(path.as_bytes())),
            compact_sha256,
            original_sha256: None,
            phase: None,
            envelope_authenticated: false,
            body_authenticated: false,
            stage: "cancelled",
            status: None,
            checks: None,
            request: ObservedFrames::default(),
            reply: ObservedFrames::default(),
            emitted: false,
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
        })))
    }

    pub(super) fn authenticated_envelope(
        &self,
        assertion: &aos_hub_core::hybrid_ingress::HybridIngressAssertion,
    ) {
        if let Ok(mut state) = self.0.lock() {
            state.envelope_authenticated = true;
            state.phase = assertion.upload_phase.clone();
            state.original_sha256 = serde_json::to_vec(assertion)
                .ok()
                .map(|bytes| hex::encode(Sha256::digest(bytes)));
        }
    }

    pub(super) fn request_body(&self, body: Body) -> Body {
        Body::new(ObservedBody {
            inner: body,
            state: Arc::clone(&self.0),
            reply: false,
        })
    }

    pub(super) fn authenticated_body(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.body_authenticated = true;
        }
    }

    pub(super) fn handler_complete(&self, status: StatusCode, checks: IngressCheckedContexts) {
        if let Ok(mut state) = self.0.lock() {
            state.stage = "handler_completed";
            state.status = Some(status.as_u16());
            state.checks = Some(checks);
        }
    }

    pub(super) fn response(self, response: Response, stage: &'static str) -> Response {
        if let Ok(mut state) = self.0.lock() {
            state.stage = stage;
            state.status = Some(response.status().as_u16());
        }
        let (parts, body) = response.into_parts();
        let response = Response::from_parts(
            parts,
            Body::new(ObservedBody {
                inner: body,
                state: Arc::clone(&self.0),
                reply: true,
            }),
        );
        // The response wrapper now owns the actual EOF/drop observation.
        if let Ok(mut state) = self.0.lock() {
            state.stage = stage;
        }
        response
    }
}

impl Drop for IngressObservation {
    fn drop(&mut self) {
        if Arc::strong_count(&self.0) == 1 {
            if let Ok(mut state) = self.0.lock() {
                state.emit();
            }
        }
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

struct ObservedBody {
    inner: Body,
    state: Arc<Mutex<State>>,
    reply: bool,
}

impl HttpBody for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(context);
        if let Ok(mut state) = self.state.lock() {
            let observed = if self.reply {
                &mut state.reply
            } else {
                &mut state.request
            };
            match &result {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(bytes) = frame.data_ref() {
                        observed.observe(bytes);
                    }
                    // Some bodies signal final EOF on their last frame without
                    // requiring another poll; preserve that actual inner fact.
                    if self.inner.is_end_stream() {
                        observed.eof = true;
                    }
                }
                Poll::Ready(None) => observed.eof = true,
                Poll::Ready(Some(Err(_))) => observed.failed = true,
                Poll::Pending => {}
            }
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            let observed = if self.reply {
                &mut state.reply
            } else {
                &mut state.request
            };
            if self.inner.is_end_stream() {
                observed.eof = true;
            }
            if self.reply || Arc::strong_count(&self.state) == 1 {
                state.emit();
            }
        }
    }
}

#[cfg(test)]
mod tests;
