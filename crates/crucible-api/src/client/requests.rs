//! Borrowed canonical lifecycle and command request projections.
//!
//! Requests retain their existing newline-delimited field order:
//!
//! ```text
//! crucible.rpc/hello-request
//! version=<major>.<minor>.<patch>+<build>
//! client=<name>
//! ```

use super::*;
use request_storage::{Hex, encode, line, session};

pub(super) fn encode_hello_request(request: &HelloRequest) -> Result<Bytes, ControlClientError> {
    encode(|output| {
        output.write_str("crucible.rpc/hello-request\n")?;
        let version = request.version;
        line(
            output,
            "version",
            format_args!(
                "{}.{}.{}+{}",
                version.major, version.minor, version.patch, version.build
            ),
        )?;
        line(output, "client", &request.client_name)
    })
}

pub(super) fn encode_create_session_request(
    request: &CreateSessionRequest,
) -> Result<Bytes, ControlClientError> {
    request_storage::authority()?;
    let bytes = match &request.source {
        CreateSessionSource::Inline { scenario } => Some(
            scenario
                .to_compact_binary_admitted()
                .map_err(client_output_admission)?,
        ),
        CreateSessionSource::ScenarioRef { .. } => None,
    };
    encode(|output| {
        output.write_str("crucible.rpc/create-session-request\n")?;
        match &request.source {
            CreateSessionSource::ScenarioRef { name } => {
                line(output, "source", "scenario-ref")?;
                line(output, "name", name)?;
            }
            CreateSessionSource::Inline { scenario } => {
                let definition = scenario.scenario_def();
                line(output, "source", "inline")?;
                line(output, "scenario-id", Hex(&definition.id().bytes))?;
                line(output, "scenario-seed", Hex(&definition.seed().bytes()))?;
                line(
                    output,
                    "app-random-draw-cap",
                    definition.app_random_draw_cap(),
                )?;
                line(
                    output,
                    "scenario-payload",
                    Hex(bytes.as_deref().ok_or(std::fmt::Error)?),
                )?;
            }
        }
        line(output, "seed", Hex(&request.seed.bytes()))?;
        line(output, "start-paused", request.start_paused)
    })
}

pub(super) fn encode_resume_session_request(
    request: &ResumeSessionRequest,
) -> Result<Bytes, ControlClientError> {
    request_storage::authority()?;
    let scenario = request
        .scenario
        .to_compact_binary_admitted()
        .map_err(client_output_admission)?;
    let schedule = request
        .schedule
        .to_compact_binary_admitted()
        .map_err(client_output_admission)?;
    let checkpoint = request
        .checkpoint
        .to_compact_binary_admitted()
        .map_err(client_output_admission)?;
    encode(|output| {
        output.write_str("crucible.rpc/resume-session-request\n")?;
        line(output, "scenario-id", Hex(&request.scenario.id().bytes))?;
        line(
            output,
            "scenario-seed",
            Hex(&request.scenario.seed().bytes()),
        )?;
        line(
            output,
            "app-random-draw-cap",
            request.scenario.app_random_draw_cap(),
        )?;
        line(output, "scenario-payload", Hex(&scenario))?;
        line(output, "seed", Hex(&request.seed.bytes()))?;
        line(output, "schedule", Hex(&schedule))?;
        line(output, "checkpoint", Hex(&checkpoint))?;
        if let Some(closure) = &request.replay_closure {
            line(
                output,
                "campaign-replay-closure-version",
                closure.schema_version(),
            )?;
            line(
                output,
                "campaign-replay-closure-identity",
                Hex(&closure.identity().bytes),
            )?;
            line(
                output,
                "campaign-replay-closure-size",
                closure.payload_len(),
            )?;
            line(
                output,
                "campaign-replay-closure-payload",
                Hex(closure.payload()),
            )?;
        }
        let source = &request.observation_source;
        line(
            output,
            "campaign-observation-source-version",
            source.schema_version(),
        )?;
        line(
            output,
            "campaign-observation-source-identity",
            Hex(&source.identity().bytes),
        )?;
        line(
            output,
            "campaign-observation-source-proof-size",
            source.proof().len(),
        )?;
        line(
            output,
            "campaign-observation-source-proof",
            Hex(source.proof()),
        )?;
        line(
            output,
            "campaign-observation-source-evidence-size",
            source.evidence().len(),
        )?;
        line(
            output,
            "campaign-observation-source-evidence",
            Hex(source.evidence()),
        )
    })
}

pub(super) fn encode_destroy_session_request(
    request: &DestroySessionRequest,
) -> Result<Bytes, ControlClientError> {
    encode(|output| {
        output.write_str("crucible.rpc/destroy-session-request\n")?;
        session(output, request.session)?;
        epoch(output, request.expected_epoch)
    })
}

pub(super) fn encode_get_reproduction_request(
    request: &GetReproductionRequest,
) -> Result<Bytes, ControlClientError> {
    encode(|output| {
        output.write_str("crucible.rpc/get-reproduction-request\n")?;
        session(output, request.session)?;
        epoch(output, request.expected_epoch)
    })
}

pub(super) fn encode_attach_request(request: &AttachRequest) -> Result<Bytes, ControlClientError> {
    encode(|output| {
        output.write_str("crucible.rpc/attach-request\n")?;
        session(output, request.session)?;
        epoch(output, request.expected_epoch)?;
        line(output, "from-seq", request.from.next_sequence)?;
        line(output, "client-name", &request.client_name)
    })
}

pub(super) fn encode_send_request(request: &SendRequest) -> Result<Bytes, ControlClientError> {
    request_storage::authority()?;
    let predicate = match &request.command {
        SessionCommand::SetBreakpoint { spec, .. } => Some(
            spec.predicate
                .to_compact_binary_admitted()
                .map_err(client_output_admission)?,
        ),
        _ => None,
    };
    let action = match &request.command {
        SessionCommand::SetBreakpoint { spec, .. } => match &spec.disposition {
            BreakpointDisposition::Action(action) => Some(
                action
                    .to_compact_binary_admitted()
                    .map_err(client_output_admission)?,
            ),
            _ => None,
        },
        _ => None,
    };
    encode(|output| {
        output.write_str("crucible.rpc/send-request\n")?;
        session(output, request.session)?;
        epoch(output, request.expected_epoch)?;
        line(output, "command-id", request.command_id)?;
        let kind = command_kind_name(SessionCommandKind::from(&request.command));
        line(output, "command", format_args!("crucible.cmd.{kind}"))?;
        match &request.command {
            SessionCommand::Query { kind, .. } => {
                output.write_str("query=")?;
                match kind {
                    QueryKind::Snapshot => output.write_str("snapshot")?,
                    QueryKind::BreakpointFirings => output.write_str("breakpoint-firings")?,
                    QueryKind::State => output.write_str("state")?,
                    QueryKind::EventLogLength => output.write_str("event-log-length")?,
                    QueryKind::SearchFrontier => output.write_str("search-frontier")?,
                    QueryKind::ResolvedEffectTrace => output.write_str("resolved-effect-trace")?,
                    QueryKind::ExecutionFingerprint { node } => write!(
                        output,
                        "execution-fingerprint|{}",
                        Hex(node.name.as_bytes())
                    )?,
                    QueryKind::DebugOperatorEndpoint => {
                        output.write_str("debug-operator-endpoint")?
                    }
                }
                output.write_char('\n')?;
            }
            SessionCommand::SetBreakpoint { spec, .. } => {
                line(
                    output,
                    "breakpoint-predicate",
                    Hex(predicate.as_deref().ok_or(std::fmt::Error)?),
                )?;
                match &spec.disposition {
                    BreakpointDisposition::Suspend => {
                        line(output, "breakpoint-disposition", "suspend")?
                    }
                    BreakpointDisposition::Trace => {
                        line(output, "breakpoint-disposition", "trace")?
                    }
                    BreakpointDisposition::Action(_) => line(
                        output,
                        "breakpoint-disposition",
                        format_args!("action:{}", Hex(action.as_deref().ok_or(std::fmt::Error)?)),
                    )?,
                }
                line(
                    output,
                    "breakpoint-policy",
                    breakpoint_policy_request_wire(spec.policy),
                )?;
            }
            SessionCommand::CreateSavepoint { label, .. } => {
                line(output, "savepoint-label", Hex(label.as_bytes()))?
            }
            SessionCommand::Step {
                mode: StepMode::Duration(duration),
            } => line(output, "step-duration-ticks", duration.ticks)?,
            _ => {}
        }
        Ok(())
    })
}

fn epoch(output: &mut dyn std::fmt::Write, value: Option<u64>) -> std::fmt::Result {
    match value {
        Some(value) => line(output, "expected-epoch", value),
        None => line(output, "expected-epoch", "none"),
    }
}
