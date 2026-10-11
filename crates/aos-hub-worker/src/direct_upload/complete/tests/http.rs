//! Bounded localhost HTTP peer recording actual authenticated control requests.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

use super::{Fixture, DEPLOYMENT, ORIGIN};
use crate::direct_upload::control::Transport;

pub(super) const KEY: &str = "fixture-native-control-authentication-key";

#[derive(Clone, Default)]
pub(super) struct Capture {
    pub(super) requests: Vec<DirectLogicalRequestEnvelope>,
    pub(super) bodies: Vec<Vec<u8>>,
    pub(super) reply_bytes: Vec<usize>,
    dropped_commit: bool,
}

pub(super) struct Server {
    address: SocketAddr,
    capture: Arc<Mutex<Capture>>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Server {
    pub(super) async fn start(
        fixtures: Vec<Fixture>,
        refused: Option<String>,
        drop_commit: bool,
    ) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let capture = Arc::new(Mutex::new(Capture::default()));
        let recorded = Arc::clone(&capture);
        let (shutdown, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = tokio::select! {
                    _ = &mut stopped => break,
                    connected = listener.accept() => connected.unwrap(),
                };
                let (headers, body) = read_message(&mut stream).await.unwrap();
                let signature = header(&headers, DIRECT_LOGICAL_SIGNATURE_HEADER).unwrap();
                let key = StorageWorkKey::new(KEY).unwrap();
                let envelope =
                    verify_direct_logical_request(&key, signature, &body, DEPLOYMENT, ORIGIN, 111)
                        .unwrap();
                assert!(headers
                    .starts_with(&format!("POST /{} HTTP/1.1\r\n", envelope.request.phase())));

                let should_drop = {
                    let mut capture = recorded.lock().unwrap();
                    capture.bodies.push(body);
                    capture.requests.push(envelope.clone());
                    if drop_commit
                        && !capture.dropped_commit
                        && matches!(envelope.request, DirectUploadLogicalRequest::Commit { .. })
                    {
                        capture.dropped_commit = true;
                        true
                    } else {
                        false
                    }
                };
                if should_drop {
                    // The peer received the complete commit before losing its
                    // response. The client cannot infer a Native outcome.
                    continue;
                }

                let reply = reply(&fixtures, refused.as_deref(), &envelope);
                let outgoing = DirectLogicalReplyEnvelope {
                    context: envelope.context,
                    reply,
                };
                let signed = sign_direct_logical_reply(&key, &outgoing).unwrap_or_else(|error| {
                    panic!(
                        "fixture {} reply bytes={} failed: {error}",
                        envelope.request.phase(),
                        serde_json::to_vec(&outgoing).unwrap().len()
                    )
                });
                recorded.lock().unwrap().reply_bytes.push(signed.body.len());
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}: {}\r\nconnection: close\r\n\r\n",
                    signed.body.len(),
                    DIRECT_LOGICAL_SIGNATURE_HEADER,
                    signed.signature
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&signed.body).await.unwrap();
            }
        });
        Self {
            address,
            capture,
            shutdown,
            task,
        }
    }

    pub(super) fn transport(&self) -> HttpTransport {
        HttpTransport {
            address: self.address,
        }
    }

    pub(super) fn captured(&self) -> Capture {
        self.capture.lock().unwrap().clone()
    }

    pub(super) async fn stop(self) {
        self.shutdown.send(()).unwrap();
        self.task.await.unwrap();
    }
}

pub(super) struct HttpTransport {
    address: SocketAddr,
}

#[async_trait::async_trait(?Send)]
impl Transport for HttpTransport {
    async fn post(&self, phase: &str, signed: SignedDirectControl) -> Result<SignedDirectControl> {
        ensure!(
            signed.body.len() <= MAX_DIRECT_CONTROL_BYTES,
            "fixture request exceeds control bound"
        );
        let mut stream = TcpStream::connect(self.address).await?;
        let headers = format!("POST /{phase} HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\n{}: {}\r\nconnection: close\r\n\r\n", self.address, signed.body.len(), DIRECT_LOGICAL_SIGNATURE_HEADER, signed.signature);
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(&signed.body).await?;
        let (headers, body) = read_message(&mut stream).await?;
        ensure!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "fixture Native transport refused"
        );
        let signature = header(&headers, DIRECT_LOGICAL_SIGNATURE_HEADER)?.into();
        Ok(SignedDirectControl { body, signature })
    }
}

async fn read_message(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        ensure!(
            headers.len() < 16 * 1024,
            "fixture HTTP headers exceed bound"
        );
        headers.push(stream.read_u8().await?);
    }
    let headers = String::from_utf8(headers)?;
    let length = header(&headers, "content-length")?.parse::<usize>()?;
    ensure!(
        length <= MAX_DIRECT_CONTROL_BYTES,
        "fixture HTTP body exceeds control bound"
    );
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok((headers, body))
}

fn header<'a>(headers: &'a str, name: &str) -> Result<&'a str> {
    headers
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .ok_or_else(|| anyhow::anyhow!("fixture HTTP header absent"))
}

fn status(item: &Fixture, state: DirectSessionState) -> DirectSessionStatus {
    DirectSessionStatus {
        session: item.complete.session.clone(),
        resource_version: WireInteger::new(9),
        intent: item.admission.intent.clone(),
        placements: item
            .complete
            .manifests
            .iter()
            .map(|item| item.placement.clone())
            .collect(),
        state,
        parts: Vec::new(),
        next_cursor: None,
        outstanding_grants: false,
    }
}

fn reply(
    fixtures: &[Fixture],
    refused: Option<&str>,
    envelope: &DirectLogicalRequestEnvelope,
) -> DirectUploadLogicalReply {
    let mut reply = DirectUploadLogicalReply {
        admissions: Vec::new(),
        sessions: Vec::new(),
        session_summaries: Vec::new(),
        authorizations: Vec::new(),
        baseline_permissions: Vec::new(),
        errors: Vec::new(),
    };
    match &envelope.request {
        DirectUploadLogicalRequest::Authorize {
            sessions,
            baseline_evidence,
            baseline_witnesses,
            baseline_witness_refs,
            retained_stage_digests,
            stage_evidence,
            complete_step,
            ..
        } => {
            for authorization in sessions {
                if *complete_step == Some(DirectCompleteStep::Baseline)
                    && Some(authorization.session.session_id.as_str()) == refused
                {
                    reply.errors.push(DirectItemError {
                        item_id: authorization.session.session_id.clone(),
                        code: DirectItemErrorCode::Denied,
                    });
                    continue;
                }
                let item = fixtures
                    .iter()
                    .find(|item| item.complete.session == authorization.session)
                    .unwrap();
                if authorization.complete_intent.as_ref() != Some(&item.complete) {
                    reply.errors.push(DirectItemError {
                        item_id: authorization.session.session_id.clone(),
                        code: DirectItemErrorCode::Conflict,
                    });
                    continue;
                }
                match complete_step {
                    Some(DirectCompleteStep::Baseline) => {
                        assert!(stage_evidence.contains(&item.stage));
                    }
                    Some(DirectCompleteStep::Promote) => {
                        let reference = retained_stage_digests
                            .iter()
                            .find(|reference| reference.session == item.complete.session)
                            .unwrap();
                        assert_eq!(reference.expand(&item.stage).unwrap(), item.stage);
                    }
                    _ => {}
                }
                reply.authorizations.push(authorization.clone());
                if *complete_step == Some(DirectCompleteStep::Freeze) {
                    reply.admissions.push(item.admission.clone());
                    reply.session_summaries.push(DirectLogicalSessionSummary {
                        session: item.complete.session.clone(),
                        resource_version: WireInteger::new(9),
                        state: DirectSessionState::Freezing,
                        outstanding_grants: false,
                    });
                }
            }
            if *complete_step == Some(DirectCompleteStep::Promote) {
                assert!(baseline_witnesses.is_empty());
                for baseline in baseline_evidence {
                    let reference = baseline_witness_refs
                        .iter()
                        .find(|reference| {
                            reference.baseline_digest == baseline.fingerprint().unwrap()
                        })
                        .unwrap();
                    let witness = reference.expand(baseline).unwrap();
                    if Some(baseline.binding.session.session_id.as_str()) == refused {
                        continue;
                    }
                    reply
                        .baseline_permissions
                        .push(DirectDestinationBaselinePermission {
                            binding: baseline.binding.clone(),
                            baseline_digest: baseline.fingerprint().unwrap(),
                            witness_digest: witness.fingerprint().unwrap(),
                            request_nonce: envelope.context.request_nonce.clone(),
                            expires_at: witness.expires_at,
                        });
                }
            }
        }
        DirectUploadLogicalRequest::Commit {
            evidence,
            final_guards,
            final_guard_refs,
        } => {
            assert!(final_guards.is_empty());
            for evidence in evidence {
                let item = fixtures
                    .iter()
                    .find(|item| item.admission.session_id == evidence.session_id)
                    .unwrap();
                assert_eq!(evidence.operation_id, item.complete.operation_id);
                let reference = final_guard_refs
                    .iter()
                    .find(|reference| reference.session == item.complete.session)
                    .unwrap();
                assert_eq!(
                    reference
                        .expand(
                            &item.admission,
                            &item.complete,
                            evidence,
                            std::slice::from_ref(&item.baseline),
                            DEPLOYMENT,
                        )
                        .unwrap(),
                    item.settled.guard
                );
                reply.admissions.push(item.admission.clone());
                reply
                    .sessions
                    .push(status(item, DirectSessionState::Committed));
            }
        }
        _ => panic!("unexpected Complete control phase"),
    }
    reply
}
