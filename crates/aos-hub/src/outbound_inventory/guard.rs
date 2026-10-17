//! RAII ownership of an actual offered request and its exposed response prefix.
//!
//! Credential-control requests provide only their already-known length. Response
//! chunks are borrowed only to count exposed length, with hashing disabled; no
//! body bytes are retained. Signatures, headers and configuration are not passed
//! to this observer.
//!
//! ```text
//! offered = {owner, transportCallId:null|actual32hex, requestSha256:null|64hex,
//!            offeredRequestBytes:<decimal>}
//! terminal = {dispatchOrdinal, replyStatus, exposedReplySha256, exposedReplyBytes,
//!             replyEof, outcome, elapsedMicros}
//! ```

use std::{sync::Arc, time::Instant};

use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{selected, window::Window};

/// Names only the finite source-owned remote-storage dispatch families.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Owner {
    Capabilities,
    BindingControl,
    Execute,
    FrozenHead,
    ExternalHead,
    FrozenDelete,
    ExternalCopy,
    ManagedCleanup,
    ExternalOciControl,
    ExternalOciSource,
    MirrorGuard,
    CredentialCustody,
    StorageAuthority,
    MirrorGuardBatch,
    ExternalCleanup,
    OciProjection,
    DirectAuthority,
}

/// Distinguishes digestable protocol bytes from a length-only sensitive control.
pub(crate) enum Image<'a> {
    /// Borrows nonsecret constructor bytes without retaining a raw body image.
    Nonsecret(&'a [u8]),
    /// Records only an already-known length; no secret bytes are passed here.
    SecretLength(usize),
}

struct Active {
    window: Arc<Window>,
    ordinal: u64,
    owner: Owner,
    call_id: Option<String>,
    request_sha256: Option<String>,
    offered: usize,
    status: Option<u16>,
    hasher: Option<Sha256>,
    exposed: u64,
    eof: bool,
    started: Instant,
}

/// Owns only an optional local observation; it never owns or drains transport.
pub(crate) struct Observation(Option<Active>);

impl Observation {
    /// Records an offer in the selected interval without changing its request.
    pub(crate) fn start(owner: Owner, image: Image<'_>, call_id: Option<&str>) -> Self {
        let Some(window) = selected() else {
            return Self(None);
        };
        if !window.within_time() {
            return Self(None);
        }
        let call_id = call_id
            .filter(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .map(str::to_owned);
        let (offered, request_sha256, hasher) = match image {
            Image::Nonsecret(body) => (
                body.len(),
                Some(hex::encode(Sha256::digest(body))),
                Some(Sha256::new()),
            ),
            Image::SecretLength(bytes) => (bytes, None, None),
        };
        let record = json!({"owner":owner, "transportCallId":call_id,
            "requestSha256":request_sha256, "offeredRequestBytes":offered.to_string()});
        let Some(ordinal) = window.offer(record) else {
            return Self(None);
        };
        Self(Some(Active {
            window,
            ordinal,
            owner,
            call_id,
            request_sha256,
            offered,
            status: None,
            hasher,
            exposed: 0,
            eof: false,
            started: Instant::now(),
        }))
    }

    /// Records the status actually returned by the existing client.
    pub(crate) fn response(&mut self, status: u16) {
        if let Some(active) = &mut self.0 {
            active.status = Some(status);
        }
    }

    /// Counts only chunks already exposed to the existing response consumer.
    pub(crate) fn exposed(&mut self, bytes: &[u8]) {
        if let Some(active) = &mut self.0 {
            if let Some(next) = active.exposed.checked_add(bytes.len() as u64) {
                active.exposed = next;
            } else {
                active.window.poison();
            }
            if let Some(hasher) = &mut active.hasher {
                hasher.update(bytes);
            }
            #[cfg(test)]
            active.window.exposed.notify_one();
        }
    }

    /// Records the consumer's actual EOF without claiming authentication.
    pub(crate) fn eof(&mut self) {
        if let Some(active) = &mut self.0 {
            active.eof = true;
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        let Some(active) = self.0.take() else {
            return;
        };
        let outcome = if active.eof {
            "reply_eof_unverified"
        } else if active.status.is_some() {
            "reply_unfinished"
        } else {
            "send_unfinished"
        };
        let reply_hash = active.hasher.map(|hash| hex::encode(hash.finalize()));
        let record = json!({"event":"terminal", "dispatchOrdinal":active.ordinal.to_string(),
            "owner":active.owner, "transportCallId":active.call_id,
            "requestSha256":active.request_sha256, "offeredRequestBytes":active.offered.to_string(),
            "replyStatus":active.status, "exposedReplySha256":reply_hash,
            "exposedReplyBytes":active.exposed.to_string(), "replyEof":active.eof,
            "outcome":outcome, "elapsedMicros":active.started.elapsed().as_micros().to_string(),
            "replyMacAuthentication":null, "finalSqlAuthority":null});
        active
            .window
            .terminal(record, !active.eof, active.status.is_none());
    }
}
