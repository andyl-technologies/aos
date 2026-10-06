//! Optional complete-window application frame inventory, without body images.
//!
//! Admission ordinals and a completion chain detect missing exported records.
//! Counts describe Native consumption and offering, never network delivery or
//! authentication. A dropped or unread stream remains incomplete. The window
//! stops observation admission at its cutoff without cancelling handlers.
//!
//! The optional environment policy is closed JSON:
//! ```text
//! {"version":1,"windowId":"<32 lowercase hex>","startUnixMillis":"...","endUnixMillis":"..."}
//! ```

use super::body_frames::{FrameReceipt, ObservedFrames};
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use http_body::{Frame, SizeHint};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

const MAX_PENDING: u64 = 4096;
const MAX_WINDOW_MILLIS: u64 = 3_600_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Policy {
    version: u8,
    window_id: String,
    start_unix_millis: String,
    end_unix_millis: String,
}

struct Counters {
    started: u64,
    terminal: u64,
    pending: u64,
    incomplete: u64,
    chain: [u8; 32],
    overflow: bool,
    closed: bool,
    begun: bool,
    summary_emitted: bool,
}

struct Window {
    policy: Policy,
    policy_sha256: String,
    start: Instant,
    end: Instant,
    counters: Mutex<Counters>,
    dispatcher: tracing::Dispatch,
    #[cfg(test)]
    records: Mutex<Vec<serde_json::Value>>,
    #[cfg(test)]
    raw_records: Mutex<Vec<String>>,
}

fn source_sha256() -> &'static str {
    static SOURCE: OnceLock<String> = OnceLock::new();
    SOURCE.get_or_init(|| {
        let mut hash = Sha256::new();
        hash.update(include_bytes!("body_frames.rs"));
        hash.update(include_bytes!("body_inventory.rs"));
        hex::encode(hash.finalize())
    })
}

impl Window {
    fn new(policy: Policy, start: Instant, end: Instant) -> anyhow::Result<Arc<Self>> {
        let policy_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&policy)?));
        Ok(Arc::new(Self {
            policy,
            policy_sha256,
            start,
            end,
            counters: Mutex::new(Counters {
                started: 0,
                terminal: 0,
                pending: 0,
                incomplete: 0,
                chain: [0; 32],
                overflow: false,
                closed: false,
                begun: false,
                summary_emitted: false,
            }),
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            #[cfg(test)]
            records: Mutex::new(Vec::new()),
            #[cfg(test)]
            raw_records: Mutex::new(Vec::new()),
        }))
    }

    fn emit(&self, value: &impl Serialize) {
        let Ok(encoded) = serde_json::to_string(value) else {
            return;
        };
        if encoded.len() > 4096 {
            return;
        }
        #[cfg(test)]
        if let Ok(mut records) = self.records.lock() {
            if records.len() < 128 {
                if let Ok(value) = serde_json::from_str(&encoded) {
                    records.push(value);
                }
            }
        }
        #[cfg(test)]
        if let Ok(mut records) = self.raw_records.lock() {
            if records.len() < 128 {
                records.push(encoded.clone());
            }
        }
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        tracing::info!("native_application_body_inventory {encoded}");
    }

    fn begin_locked(&self, counters: &mut Counters) {
        if counters.begun {
            return;
        }
        counters.begun = true;
        self.emit(&serde_json::json!({
            "version": 1, "event": "begin", "windowId": self.policy.window_id,
            "policySha256": self.policy_sha256, "producerSha256": source_sha256(),
            "policy": self.policy,
        }));
    }

    fn begin(&self) {
        if let Ok(mut counters) = self.counters.lock() {
            self.begin_locked(&mut counters);
        }
    }

    fn admit(&self) -> Option<u64> {
        let now = Instant::now();
        if now < self.start || now >= self.end {
            return None;
        }
        let mut counters = self.counters.lock().ok()?;
        if counters.closed {
            return None;
        }
        self.begin_locked(&mut counters);
        if counters.pending == MAX_PENDING || counters.started == u64::MAX {
            counters.overflow = true;
            return None;
        }
        counters.started += 1;
        counters.pending += 1;
        Some(counters.started)
    }

    fn close(&self) {
        if let Ok(mut counters) = self.counters.lock() {
            counters.closed = true;
            self.summary(&mut counters);
        }
    }

    fn summary(&self, counters: &mut Counters) {
        if !counters.closed || counters.pending != 0 || counters.summary_emitted {
            return;
        }
        counters.summary_emitted = true;
        self.emit(&serde_json::json!({
            "version": 1, "event": "end", "windowId": self.policy.window_id,
            "policySha256": self.policy_sha256, "producerSha256": source_sha256(),
            "started": counters.started.to_string(), "terminal": counters.terminal.to_string(),
            "pending": counters.pending.to_string(), "incomplete": counters.incomplete.to_string(),
            "overflow": counters.overflow, "chainSha256": hex::encode(counters.chain),
        }));
    }

    fn finish(&self, member: &Member) {
        let Ok(mut counters) = self.counters.lock() else {
            return;
        };
        let Some(terminal) = counters.terminal.checked_add(1) else {
            counters.overflow = true;
            return;
        };
        let request = member.request.receipt();
        let reply = member.reply.receipt();
        let complete = member.returned
            && request.eof
            && reply.eof
            && !request.failed
            && !reply.failed
            && !request.overflow
            && !reply.overflow
            && !member.request.trailers
            && !member.reply.trailers;
        let record = MemberReceipt {
            version: 1,
            event: "member",
            window_id: &self.policy.window_id,
            policy_sha256: &self.policy_sha256,
            producer_sha256: source_sha256(),
            admission_ordinal: member.ordinal.to_string(),
            completion_ordinal: terminal.to_string(),
            previous_chain_sha256: hex::encode(counters.chain),
            method: &member.method,
            path_sha256: &member.path_sha256,
            request_id: &member.request_id,
            transport_call_id: &member.transport_call_id,
            status: member.status,
            handler_returned: member.returned,
            request_consumed: request,
            reply_offered: reply,
            request_trailers: member.request.trailers,
            reply_trailers: member.reply.trailers,
            typed_evidence: matched_evidence(member),
        };
        let Ok(raw) = serde_json::to_vec(&record) else {
            counters.overflow = true;
            return;
        };
        let mut hash = Sha256::new();
        hash.update(counters.chain);
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(&raw);
        counters.chain = hash.finalize().into();
        counters.terminal = terminal;
        let Some(pending) = counters.pending.checked_sub(1) else {
            counters.overflow = true;
            return;
        };
        counters.pending = pending;
        if !complete {
            counters.incomplete += 1;
        }
        self.emit(&record);
        self.summary(&mut counters);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberReceipt<'a> {
    version: u8,
    event: &'static str,
    window_id: &'a str,
    policy_sha256: &'a str,
    producer_sha256: &'a str,
    admission_ordinal: String,
    completion_ordinal: String,
    previous_chain_sha256: String,
    method: &'a str,
    path_sha256: &'a str,
    request_id: &'a Option<String>,
    transport_call_id: &'a Option<String>,
    status: Option<u16>,
    handler_returned: bool,
    request_consumed: FrameReceipt,
    reply_offered: FrameReceipt,
    request_trailers: bool,
    reply_trailers: bool,
    typed_evidence: Option<aos_hub_core::application_body_observation::BodyEvidence>,
}

fn matched_evidence(
    member: &Member,
) -> Option<aos_hub_core::application_body_observation::BodyEvidence> {
    let evidence = member.typed_evidence.as_ref()?;
    if member.request.trailers || member.reply.trailers {
        return None;
    }
    fn matches(
        frames: &ObservedFrames,
        image: &aos_hub_core::application_body_observation::EncodedImage,
    ) -> bool {
        let receipt = frames.receipt();
        receipt.eof
            && !receipt.failed
            && !receipt.overflow
            && receipt.exposed_bytes == image.byte_size
            && receipt.exposed_sha256 == image.sha256
    }
    if !matches(&member.reply, &evidence.reply) {
        return None;
    }
    if evidence
        .request
        .as_ref()
        .is_some_and(|request| !matches(&member.request, request))
    {
        return None;
    }
    Some(evidence.clone())
}

struct Member {
    window: Arc<Window>,
    ordinal: u64,
    method: String,
    path_sha256: String,
    request_id: Option<String>,
    transport_call_id: Option<String>,
    status: Option<u16>,
    returned: bool,
    typed_evidence: Option<aos_hub_core::application_body_observation::BodyEvidence>,
    request: ObservedFrames,
    reply: ObservedFrames,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.window.finish(self);
    }
}

fn correlation(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    (values.next().is_none()
        && value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| value.to_owned())
}

async fn observe(State(window): State<Arc<Window>>, request: Request, next: Next) -> Response {
    let Some(ordinal) = window.admit() else {
        return next.run(request).await;
    };
    let member = Arc::new(Mutex::new(Member {
        window,
        ordinal,
        method: request.method().to_string(),
        path_sha256: hex::encode(Sha256::digest(request.uri().path().as_bytes())),
        request_id: correlation(request.headers(), "x-aos-fleet-request-id"),
        transport_call_id: correlation(request.headers(), "x-aos-storage-call-id"),
        status: None,
        returned: false,
        typed_evidence: None,
        request: ObservedFrames::default(),
        reply: ObservedFrames::default(),
    }));
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(parts, tap(body, &member, false));
    let response = aos_hub_core::application_body_observation::observe(next.run(request)).await;
    if let Ok(mut state) = member.lock() {
        state.status = Some(response.status().as_u16());
        state.returned = true;
        state.typed_evidence = response
            .extensions()
            .get::<aos_hub_core::application_body_observation::BodyEvidence>()
            .cloned();
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, tap(body, &member, true))
}

fn tap(body: Body, member: &Arc<Mutex<Member>>, reply: bool) -> Body {
    if body.is_end_stream() {
        if let Ok(mut state) = member.lock() {
            let frames = if reply {
                &mut state.reply
            } else {
                &mut state.request
            };
            frames.eof = true;
        }
    }
    Body::new(TappedBody {
        inner: body,
        member: Arc::clone(member),
        reply,
    })
}

struct TappedBody {
    inner: Body,
    member: Arc<Mutex<Member>>,
    reply: bool,
}

impl HttpBody for TappedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(context);
        if let Ok(mut state) = self.member.lock() {
            let frames = if self.reply {
                &mut state.reply
            } else {
                &mut state.request
            };
            frames.observe_result(&result, self.inner.is_end_stream());
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

impl Drop for TappedBody {
    fn drop(&mut self) {
        if self.inner.is_end_stream() {
            if let Ok(mut state) = self.member.lock() {
                let frames = if self.reply {
                    &mut state.reply
                } else {
                    &mut state.request
                };
                frames.eof = true;
            }
        }
    }
}

fn selected_window(raw: &str) -> anyhow::Result<Arc<Window>> {
    anyhow::ensure!(raw.len() <= 1024, "body inventory policy exceeds bound");
    let policy: Policy = serde_json::from_str(raw)?;
    anyhow::ensure!(
        policy.version == 1
            && policy.window_id.len() == 32
            && policy
                .window_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "body inventory identity differs"
    );
    fn decimal(value: &str) -> anyhow::Result<u64> {
        let parsed: u64 = value.parse()?;
        anyhow::ensure!(
            parsed.to_string() == value,
            "body inventory time is not canonical"
        );
        Ok(parsed)
    }
    let start = decimal(&policy.start_unix_millis)?;
    let end = decimal(&policy.end_unix_millis)?;
    let clock = Instant::now();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    anyhow::ensure!(
        start >= now && end > start && end - now <= MAX_WINDOW_MILLIS,
        "body inventory window is past or exceeds bound"
    );
    Window::new(
        policy,
        clock + Duration::from_millis(start - now),
        clock + Duration::from_millis(end - now),
    )
}

/// Applies an explicitly selected count-only observation window.
///
/// Absent configuration returns the original router without another layer.
/// The environment policy changes observation only, and never grants authority.
///
/// # Errors
///
/// Returns an error for a malformed, past or unbounded selected policy.
pub(super) fn optional(app: Router) -> anyhow::Result<Router> {
    let raw = match std::env::var("AOS_NATIVE_BODY_INVENTORY") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(app),
        Err(error) => return Err(error.into()),
    };
    let window = selected_window(&raw)?;
    let timer = Arc::clone(&window);
    tokio::spawn(async move {
        tokio::time::sleep_until(timer.start).await;
        timer.begin();
        tokio::time::sleep_until(timer.end).await;
        timer.close();
    });
    Ok(app.layer(axum::middleware::from_fn_with_state(window, observe)))
}

#[cfg(test)]
mod tests;
