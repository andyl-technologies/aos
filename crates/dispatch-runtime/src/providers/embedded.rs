//! Cooperative in-process backends with explicit shared-memory limitations.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use dispatch_model::{Assignment, ValidatedProblem};
use dispatch_protocol::{
    canonical::{model_digest, request_digest_for_backend},
    framing::{read_frame_async, write_frame_async},
    json::from_slice,
    wire::{self, worker_envelope::Body},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, watch},
    task::JoinHandle,
};

use super::{ExecutionProvider, ResourceGrant, WorkerConnection, WorkerControl, WorkerLaunch};
use crate::{
    RuntimeError,
    connection::{default_wire_limits, protocol_error, version},
    worker::{input_error_code, parse_problem, rejected, rejected_model, verify_finished},
};

/// Gives an embedded backend cooperative cancellation without forceful claims.
#[derive(Clone)]
pub struct CooperativeCancellation {
    receiver: watch::Receiver<bool>,
}

impl CooperativeCancellation {
    /// Returns whether the supervising runtime requested cancellation.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Waits until cancellation is requested or the owner disappears.
    pub async fn cancelled(&mut self) {
        crate::scheduler::cancellation(&mut self.receiver).await;
    }
}

/// Contains an untrusted candidate and separately classified search termination.
pub struct EmbeddedSolution {
    /// The backend's stopping reason.
    pub termination: wire::Termination,
    /// The candidate, independently checked before returning to the consumer.
    pub assignment: Option<Assignment>,
    /// Backend-reported search evidence, not an independently checked proof.
    pub evidence: Option<wire::SearchEvidence>,
    /// Bounded diagnostic details.
    pub detail: String,
}

/// Implements a Rust-native cooperative search engine without an external ABI.
///
/// Implementations must respond to cancellation and await cleanup of any work
/// they spawn before returning. They share the caller's process and memory;
/// neither this trait nor its provider can terminate a noncooperating engine.
#[async_trait]
pub trait EmbeddedBackend: Send + Sync {
    /// Returns an immutable compiler/engine capability profile.
    fn capabilities(&self) -> wire::Capabilities;

    /// Searches a validated problem and returns an untrusted candidate.
    ///
    /// # Errors
    /// Returns backend execution or unsupported-model errors; these are not
    /// allocation infeasibility claims.
    async fn solve(
        &self,
        problem: ValidatedProblem,
        options: wire::SolveOptions,
        hint: Option<Assignment>,
        cancellation: CooperativeCancellation,
    ) -> Result<EmbeddedSolution, RuntimeError>;
}

/// Executes an explicitly supplied Rust engine with cooperative cancellation.
pub struct EmbeddedProvider {
    backend: Arc<dyn EmbeddedBackend>,
}

impl EmbeddedProvider {
    /// Selects the in-process backend explicitly; no native fallback is implied.
    pub fn new(backend: Arc<dyn EmbeddedBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl ExecutionProvider for EmbeddedProvider {
    fn grant(&self) -> ResourceGrant {
        ResourceGrant { hard_cancellation: false, independent_memory: false, aggregate_accounting: false, owner_cleanup: false, enforced_memory_bytes: None, enforced_limits: None, description: "cooperative Rust backend sharing caller process, memory, and accounting; no hard termination or independent OOM containment".into() }
    }

    async fn launch(&self, launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError> {
        let (client, server) = tokio::io::duplex(65_536);
        let (reader, writer) = tokio::io::split(client);
        let (cancellation, _) = watch::channel(false);
        let backend = self.backend.clone();
        let cancel_receiver = cancellation.subscribe();
        let task = tokio::spawn(async move {
            let (reader, writer) = tokio::io::split(server);
            serve(backend, reader, writer, launch, cancel_receiver).await
        });
        Ok(WorkerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            control: Arc::new(EmbeddedControl {
                cancellation,
                task: Mutex::new(Some(task)),
            }),
        })
    }
}

struct EmbeddedControl {
    cancellation: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<Result<(), RuntimeError>>>>,
}

impl Drop for EmbeddedControl {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
    }
}

#[async_trait]
impl WorkerControl for EmbeddedControl {
    async fn stop(&self) -> Result<(), RuntimeError> {
        self.cancellation.send_replace(true);
        let mut task = self.task.lock().await;
        if let Some(task) = task.as_mut() {
            // Completion confirms containment even if the search itself failed.
            // Clear the handle before another cleanup attempt can poll it again.
            let _ = task.await;
        }
        *task = None;
        Ok(())
    }
}

async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    backend: Arc<dyn EmbeddedBackend>,
    mut reader: R,
    mut writer: W,
    launch: WorkerLaunch,
    mut cancellation: watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    let hello = read_frame_async(&mut reader, 65_536)
        .await
        .map_err(protocol_error)?;
    if !matches!(hello.body, Some(Body::Hello(_)))
        || hello.session_generation != launch.session_generation
        || hello.worker_generation != launch.worker_generation
    {
        return Err(RuntimeError::Protocol(
            "embedded negotiation generation mismatch".into(),
        ));
    }
    let mut capabilities = backend.capabilities();
    capabilities.protocol_version = Some(version());
    capabilities.model_versions = vec![version()];
    if capabilities.limits.is_none() {
        capabilities.limits = Some(default_wire_limits(launch.max_frame_bytes));
    }
    let Some(Body::Hello(requested)) = hello.body.as_ref() else {
        return Err(RuntimeError::Protocol("embedded Hello missing".into()));
    };
    let limits = dispatch_protocol::negotiation::negotiate(requested, &capabilities)?.limits;
    capabilities.limits = Some(limits.clone());
    let response = envelope(&hello, Body::Capabilities(capabilities.clone()));
    write_frame_async(&mut writer, &response, 65_536)
        .await
        .map_err(protocol_error)?;
    let mut last_request = hello.request_id;
    let mut prepared: BTreeMap<String, (ValidatedProblem, u64)> = BTreeMap::new();
    let mut prepared_bytes = 0u64;
    loop {
        let request = tokio::select! {
            request = read_frame_async(&mut reader, limits.max_frame_bytes) => request.map_err(protocol_error)?,
            _ = crate::scheduler::cancellation(&mut cancellation) => return Ok(()),
        };
        if request.session_generation != hello.session_generation
            || request.worker_generation != hello.worker_generation
            || request.request_id <= last_request
        {
            return Err(RuntimeError::Protocol(
                "embedded request correlation mismatch".into(),
            ));
        }
        last_request = request.request_id;
        match request.body.as_ref() {
            Some(Body::Prepare(prepare)) => {
                let size = u64::try_from(prepare.problem_json.len()).unwrap_or(u64::MAX);
                if u64::try_from(prepared.len()).unwrap_or(u64::MAX)
                    >= u64::from(limits.max_prepared)
                    || prepared_bytes
                        .checked_add(size)
                        .is_none_or(|total| total > limits.max_prepared_bytes)
                {
                    return Err(RuntimeError::Overloaded("embedded prepared inputs"));
                }
                let model = parse_problem(&prepare.problem_json, &limits)?;
                let digest = model_digest(&model).map_err(protocol_error)?.to_vec();
                if !prepare.model_digest.is_empty() && prepare.model_digest != digest {
                    return Err(RuntimeError::Protocol(
                        "embedded prepare commitment mismatch".into(),
                    ));
                }
                let handle = request.request_id.to_string();
                prepared.insert(handle.clone(), (model, size));
                prepared_bytes += size;
                write_frame_async(
                    &mut writer,
                    &envelope(
                        &request,
                        Body::Prepared(wire::Prepared {
                            handle,
                            model_digest: digest,
                        }),
                    ),
                    limits.max_frame_bytes,
                )
                .await
                .map_err(protocol_error)?;
                continue;
            }
            Some(Body::Release(release)) => {
                let Some((_, size)) = prepared.remove(&release.handle) else {
                    return Err(RuntimeError::StaleHandle);
                };
                prepared_bytes = prepared_bytes.saturating_sub(size);
                write_frame_async(
                    &mut writer,
                    &envelope(
                        &request,
                        Body::Released(wire::Released {
                            handle: release.handle.clone(),
                        }),
                    ),
                    limits.max_frame_bytes,
                )
                .await
                .map_err(protocol_error)?;
                continue;
            }
            _ => {}
        }
        let Some(Body::Solve(solve)) = request.body.as_ref() else {
            return Err(RuntimeError::Protocol(
                "embedded worker expected Solve, Prepare, or Release".into(),
            ));
        };
        let model = if solve.prepared_handle.is_empty() {
            match parse_problem(&solve.problem_json, &limits) {
                Ok(model) => model,
                Err(error) => {
                    let response = rejected(&request, input_error_code(&error), &error.to_string());
                    write_frame_async(&mut writer, &response, limits.max_frame_bytes)
                        .await
                        .map_err(protocol_error)?;
                    continue;
                }
            }
        } else if !solve.problem_json.is_empty() {
            return Err(RuntimeError::Protocol(
                "embedded solve mixes inline and prepared inputs".into(),
            ));
        } else {
            prepared
                .get(&solve.prepared_handle)
                .map(|(problem, _)| problem.clone())
                .ok_or(RuntimeError::StaleHandle)?
        };
        let hint = if solve.hint_json.is_empty() {
            None
        } else {
            Some(
                from_slice(
                    &solve.hint_json,
                    limits.json_limits().map_err(protocol_error)?,
                )
                .map_err(protocol_error)?,
            )
        };
        let Some(mut options) = solve.options.clone() else {
            let response = rejected_model(
                &request,
                &model,
                &capabilities,
                wire::ErrorCode::InvalidMessage,
                "embedded solve options missing",
            )?;
            write_frame_async(&mut writer, &response, limits.max_frame_bytes)
                .await
                .map_err(protocol_error)?;
            continue;
        };
        if options.threads == 0
            || !capabilities.search_modes.contains(&options.mode)
            || options.seed.is_some() && !capabilities.seed_supported
        {
            let code = if options.threads == 0 {
                wire::ErrorCode::InvalidMessage
            } else {
                wire::ErrorCode::UnsupportedModel
            };
            let response = rejected_model(
                &request,
                &model,
                &capabilities,
                code,
                "embedded requested options unsupported",
            )?;
            write_frame_async(&mut writer, &response, limits.max_frame_bytes)
                .await
                .map_err(protocol_error)?;
            continue;
        }
        let digest = model_digest(&model).map_err(protocol_error)?.to_vec();
        let request_digest =
            request_digest_for_backend(&model, &capabilities.backend_name, &options, hint.as_ref())
                .map_err(protocol_error)?
                .to_vec();
        if !solve.model_digest.is_empty() && solve.model_digest != digest
            || !solve.request_digest.is_empty() && solve.request_digest != request_digest
        {
            let response = rejected_model(
                &request,
                &model,
                &capabilities,
                wire::ErrorCode::CommitmentMismatch,
                "embedded solve commitment mismatch",
            )?;
            write_frame_async(&mut writer, &response, limits.max_frame_bytes)
                .await
                .map_err(protocol_error)?;
            continue;
        }
        options.wall_time_millis = solve
            .remaining_wall_time_millis
            .unwrap_or(options.wall_time_millis);
        let solution = backend
            .solve(
                model.clone(),
                options.clone(),
                hint,
                CooperativeCancellation {
                    receiver: cancellation.clone(),
                },
            )
            .await;
        let mut finished = match solution {
            Ok(solution) => wire::Finished {
                termination: solution.termination as i32,
                assignment_json: solution
                    .assignment
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?
                    .unwrap_or_default(),
                evidence: solution.evidence,
                detail: solution.detail,
                ..Default::default()
            },
            Err(error) => wire::Finished {
                termination: if matches!(error, RuntimeError::Unsupported(_)) {
                    wire::Termination::Rejected
                } else {
                    wire::Termination::ExecutionFailed
                } as i32,
                error_code: matches!(error, RuntimeError::Unsupported(_))
                    .then_some(wire::ErrorCode::UnsupportedModel as i32),
                detail: error.to_string(),
                ..Default::default()
            },
        };
        finished.diagnostics_truncated = finished.detail.chars().count() > 4096;
        finished.detail = finished.detail.chars().take(4096).collect();
        finished.model_digest = digest;
        finished.request_digest = request_digest;
        finished.backend_build_id = capabilities.backend_build_id.clone();
        finished.observation_basis_json = serde_json::to_vec(&model.problem().observation_basis)?;
        finished.effective_options = Some(options);
        verify_finished(&model, &mut finished, &limits)?;
        write_frame_async(
            &mut writer,
            &envelope(&request, Body::Finished(finished)),
            limits.max_frame_bytes,
        )
        .await
        .map_err(protocol_error)?;
    }
}

fn envelope(request: &wire::WorkerEnvelope, body: Body) -> wire::WorkerEnvelope {
    wire::WorkerEnvelope {
        protocol_version: request.protocol_version,
        session_generation: request.session_generation,
        worker_generation: request.worker_generation,
        request_id: request.request_id,
        body: Some(body),
    }
}
