//! Negotiated connections to trusted validation and verification runners.

use std::time::Duration;

use dispatch_protocol::{
    framing::{read_frame_async, write_frame_async},
    wire::{self, worker_envelope::Body},
};

use crate::{RuntimeError, providers::WorkerConnection};

pub(crate) struct ConnectedWorker {
    pub connection: WorkerConnection,
    pub capabilities: wire::Capabilities,
    pub generation: u64,
    pub next_request: u64,
    pub max_frame_bytes: u32,
}

impl ConnectedWorker {
    pub async fn negotiate(
        mut connection: WorkerConnection,
        session_generation: u64,
        generation: u64,
        max_frame_bytes: u32,
        expected_build: Option<&str>,
    ) -> Result<Self, RuntimeError> {
        let limits = default_wire_limits(max_frame_bytes);
        let hello = wire::WorkerEnvelope {
            protocol_version: Some(version()),
            session_generation,
            worker_generation: generation,
            request_id: 1,
            body: Some(Body::Hello(wire::Hello {
                protocol_versions: vec![version()],
                model_versions: vec![version()],
                limits: Some(limits),
                required_capabilities: vec![],
            })),
        };
        let result = async {
            write_frame_async(&mut connection.writer, &hello, 65_536)
                .await
                .map_err(protocol_error)?;
            let response = read_frame_async(&mut connection.reader, 65_536)
                .await
                .map_err(protocol_error)?;
            check_response(&hello, &response)?;
            let Some(Body::Capabilities(capabilities)) = response.body else {
                return Err(RuntimeError::Protocol(
                    "worker did not return capabilities".into(),
                ));
            };
            if capabilities.backend_build_id.is_empty()
                || expected_build.is_some_and(|expected| expected != capabilities.backend_build_id)
            {
                return Err(RuntimeError::Protocol(
                    "backend build does not match trusted initialization metadata".into(),
                ));
            }
            let Some(Body::Hello(requested)) = hello.body.as_ref() else {
                return Err(RuntimeError::Protocol("initial Hello missing".into()));
            };
            let negotiated = dispatch_protocol::negotiation::negotiate(requested, &capabilities)?;
            let selected = negotiated.limits.max_frame_bytes;
            let mut capabilities = capabilities;
            capabilities.limits = Some(negotiated.limits);
            Ok((capabilities, selected))
        }
        .await;
        match result {
            Ok((capabilities, selected)) => Ok(Self {
                connection,
                capabilities,
                generation,
                next_request: 2,
                max_frame_bytes: selected,
            }),
            Err(error) => Err(error),
        }
    }

    pub async fn solve<F>(
        &mut self,
        session_generation: u64,
        problem_json: Vec<u8>,
        hint_json: Vec<u8>,
        options: wire::SolveOptions,
        remaining: Duration,
        mut on_validation: F,
    ) -> Result<wire::Finished, RuntimeError>
    where
        F: FnMut(wire::ValidationBinding) -> Result<(), RuntimeError>,
    {
        if !self.capabilities.search_modes.contains(&options.mode) {
            return Err(RuntimeError::Unsupported(
                "backend does not implement requested search mode".into(),
            ));
        }
        if options.seed.is_some() && !self.capabilities.seed_supported {
            return Err(RuntimeError::Unsupported(
                "backend does not support explicit seeds".into(),
            ));
        }
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Protocol("request identity exhausted".into()))?;
        let request = wire::WorkerEnvelope {
            protocol_version: Some(version()),
            session_generation,
            worker_generation: self.generation,
            request_id,
            body: Some(Body::Solve(wire::Solve {
                problem_json,
                hint_json,
                options: Some(options),
                remaining_wall_time_millis: Some(
                    u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                ),
                ..Default::default()
            })),
        };
        write_frame_async(&mut self.connection.writer, &request, self.max_frame_bytes)
            .await
            .map_err(protocol_error)?;
        let mut validated: Option<(Vec<u8>, Vec<u8>)> = None;
        loop {
            let response = read_frame_async(&mut self.connection.reader, self.max_frame_bytes)
                .await
                .map_err(protocol_error)?;
            check_response(&request, &response)?;
            match response.body {
                Some(Body::Finished(finished)) => {
                    if let Some((model, request)) = &validated
                        && (finished.model_digest != *model || finished.request_digest != *request)
                    {
                        return Err(dispatch_protocol::ProtocolError::CommitmentMismatch.into());
                    }
                    return Ok(finished);
                }
                Some(Body::Progress(progress)) => {
                    if let Some(binding) = progress.validation_binding {
                        if validated.is_some()
                            || progress.stage != wire::ExecutionStage::Materializing as i32
                            || binding.model_digest.len() != 32
                            || binding.request_digest.len() != 32
                        {
                            return Err(RuntimeError::Protocol(
                                "invalid trusted validation binding event".into(),
                            ));
                        }
                        let commitments =
                            (binding.model_digest.clone(), binding.request_digest.clone());
                        on_validation(binding)?;
                        validated = Some(commitments);
                    }
                }
                Some(Body::Error(error)) => {
                    if error.code == wire::ErrorCode::CommitmentMismatch as i32 {
                        return Err(dispatch_protocol::ProtocolError::CommitmentMismatch.into());
                    }
                    return Err(RuntimeError::Protocol(error.detail));
                }
                _ => return Err(RuntimeError::Protocol("unexpected solve response".into())),
            }
        }
    }

    pub async fn validate_input(
        &mut self,
        session_generation: u64,
        problem_json: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Protocol("request identity exhausted".into()))?;
        let request = wire::WorkerEnvelope {
            protocol_version: Some(version()),
            session_generation,
            worker_generation: self.generation,
            request_id,
            body: Some(Body::Prepare(wire::Prepare {
                problem_json,
                model_digest: Vec::new(),
            })),
        };
        write_frame_async(&mut self.connection.writer, &request, self.max_frame_bytes)
            .await
            .map_err(protocol_error)?;
        let response = read_frame_async(&mut self.connection.reader, self.max_frame_bytes)
            .await
            .map_err(protocol_error)?;
        check_response(&request, &response)?;
        let prepared = match response.body {
            Some(Body::Prepared(prepared)) if prepared.model_digest.len() == 32 => prepared,
            Some(Body::Error(error)) => return Err(RuntimeError::Protocol(error.detail)),
            _ => {
                return Err(RuntimeError::Protocol(
                    "invalid preparation response".into(),
                ));
            }
        };
        // The session retains portable input. No native-local cache allocation
        // must remain charged after this validation probe.
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Protocol("request identity exhausted".into()))?;
        let release = wire::WorkerEnvelope {
            protocol_version: Some(version()),
            session_generation,
            worker_generation: self.generation,
            request_id,
            body: Some(Body::Release(wire::Release {
                handle: prepared.handle,
            })),
        };
        write_frame_async(&mut self.connection.writer, &release, self.max_frame_bytes)
            .await
            .map_err(protocol_error)?;
        let response = read_frame_async(&mut self.connection.reader, self.max_frame_bytes)
            .await
            .map_err(protocol_error)?;
        check_response(&release, &response)?;
        if !matches!(response.body, Some(Body::Released(_))) {
            return Err(RuntimeError::Protocol(
                "prepared input release failed".into(),
            ));
        }
        Ok(prepared.model_digest)
    }
}

pub(crate) fn default_wire_limits(max_frame_bytes: u32) -> wire::WireLimits {
    wire::WireLimits {
        max_frame_bytes,
        max_problem_bytes: u64::from(max_frame_bytes),
        max_decoded_bytes: u64::from(max_frame_bytes).saturating_mul(8),
        max_items: 100_000,
        max_targets: 100_000,
        max_dimensions: 128,
        max_memberships: 1_000_000,
        max_domain_entries: 1_000_000,
        max_overrides: 1_000_000,
        max_constraints: 100_000,
        max_objectives: 10_000,
        max_nesting: 64,
        max_string_bytes: 4096,
        max_prepared: 16,
        max_prepared_bytes: u64::from(max_frame_bytes).saturating_mul(16),
        max_diagnostic_bytes: 16_384,
    }
}

pub(crate) fn version() -> wire::Version {
    wire::Version { major: 1, minor: 0 }
}

pub(crate) fn protocol_error(error: dispatch_protocol::ProtocolError) -> RuntimeError {
    RuntimeError::Wire(error)
}

pub(crate) fn check_response(
    request: &wire::WorkerEnvelope,
    response: &wire::WorkerEnvelope,
) -> Result<(), RuntimeError> {
    if response.protocol_version != request.protocol_version
        || response.session_generation != request.session_generation
        || response.worker_generation != request.worker_generation
        || response.request_id != request.request_id
    {
        return Err(RuntimeError::Protocol(
            "mismatched protocol correlation or generation".into(),
        ));
    }
    Ok(())
}
