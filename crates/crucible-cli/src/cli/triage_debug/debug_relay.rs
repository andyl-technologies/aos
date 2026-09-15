//! Debug command planning and authenticated remote relay execution.

use super::debug_terminal::{
    RemoteGuestChannelRequest, parse_debug_session_ref, run_remote_debug_relay_async,
    run_remote_guest_channel, run_remote_guest_fork,
};
use super::*;

pub(crate) fn plan_debug_invocation(
    _cli: &Cli,
    args: &DebugArgs,
) -> Result<DebugInvocationPlan, CliError> {
    #[cfg(any(test, feature = "test-double"))]
    if _cli.backend == Backend::Double {
        return Err(CliError::Backend(
            "selected backend `double` does not implement open_gdbstub".to_string(),
        ));
    }

    let target = debug_target(args)?;
    if let DebugPlanTarget::Session(session) = &target {
        parse_debug_session_ref(session)?;
    }
    let coordinate = debug_coordinate(args, &target)?;
    let checkpoint_stride = args
        .checkpoint_stride
        .map(validate_debug_checkpoint_stride)
        .transpose()?;
    if args.node.as_deref().is_some_and(str::is_empty) {
        return Err(usage_error("--node must not be empty"));
    }
    let gdb_listen = args
        .gdb_listen
        .clone()
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    crucible::DebugGdbEndpoint::new("gdb_listen", gdb_listen.clone())
        .map_err(|error| usage_error(format!("invalid --gdb-listen: {error}")))?;

    let verb = debug_verb(args)?;
    let explicit_fork = matches!(verb, DebugInteractiveVerbPlan::ForkDebug);
    let guest_shell = matches!(
        verb,
        DebugInteractiveVerbPlan::Exec { .. }
            | DebugInteractiveVerbPlan::Pty { .. }
            | DebugInteractiveVerbPlan::Ssh
    );
    if args.record_transcript.is_some() && !guest_shell {
        return Err(usage_error(
            "--record-transcript is available only with debug exec, pty, or ssh",
        ));
    }
    if args.guest_idle_timeout.is_some() && !guest_shell {
        return Err(usage_error(
            "--guest-idle-timeout is available only with debug exec, pty, or ssh",
        ));
    }
    let guest_idle_timeout = parse_run_duration_budget_ticks(
        args.guest_idle_timeout.as_deref().unwrap_or("30s"),
    )
    .map(Duration::from_nanos)
    .ok_or_else(|| {
        usage_error(
            "--guest-idle-timeout must be a positive duration using ticks, ns, us, ms, or s",
        )
    })?;
    if (explicit_fork || guest_shell) && !args.allow_mutate {
        return Err(usage_error(
            "the selected fork-debug or guest exec/PTY/SSH operation requires --allow-mutate authorization",
        ));
    }
    let read_only = !(explicit_fork || guest_shell);
    let mut session_commands = vec![SessionCommand::query_snapshot()];
    let mut engine_operations = vec![
        DebugEngineOperation::ResolveTarget,
        DebugEngineOperation::Instantiate,
        DebugEngineOperation::AttachGdbProxy,
        DebugEngineOperation::OpenGdbstub,
        DebugEngineOperation::Goto,
        DebugEngineOperation::RestoreNearestCheckpointReplay,
        DebugEngineOperation::ReadOnlyInspection,
        DebugEngineOperation::NoSymbolServer,
        DebugEngineOperation::MultiVcpuThreadEnumeration,
        DebugEngineOperation::DisableRawGdbSingleStep,
    ];

    match &verb {
        DebugInteractiveVerbPlan::AttachGdb => {
            engine_operations.push(DebugEngineOperation::AttachGdbProxy);
        }
        DebugInteractiveVerbPlan::ForkDebug => {
            session_commands.push(SessionCommand::fork_current());
            engine_operations.push(DebugEngineOperation::NonCanonicalBranchFork);
        }
        DebugInteractiveVerbPlan::Goto(_) => {
            engine_operations.push(DebugEngineOperation::Goto);
        }
        DebugInteractiveVerbPlan::ReverseStep { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseStep);
            engine_operations.push(DebugEngineOperation::RestoreNearestCheckpointReplay);
        }
        DebugInteractiveVerbPlan::ReverseContinue { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseContinue);
        }
        DebugInteractiveVerbPlan::Exec { .. }
        | DebugInteractiveVerbPlan::Pty { .. }
        | DebugInteractiveVerbPlan::Ssh => {
            engine_operations.push(DebugEngineOperation::GuestIntrospection);
        }
    }

    if checkpoint_stride.is_some() {
        engine_operations.push(DebugEngineOperation::CheckpointCadence);
    }

    let plan = DebugInvocationPlan {
        target,
        coordinate,
        node: args.node.clone(),
        gdb_listen,
        read_only,
        allow_mutate: args.allow_mutate,
        checkpoint_stride,
        record_transcript: args.record_transcript.clone(),
        guest_idle_timeout,
        verb,
        session_commands,
        engine_operations,
        surface_contract: crucible::DebugCliSurfaceContract::rfc0010(),
        owns_debug_state: false,
        raw_gdb_single_step_allowed: false,
        non_canonical_branch_label: (explicit_fork || guest_shell)
            .then(|| "NON-CANONICAL debug branch".to_string()),
    };
    if !plan.proves_t_dbg_8() {
        return Err(CliError::Backend(
            "debug planner does not satisfy the RFC-0010 debug surface contract".to_string(),
        ));
    }
    Ok(plan)
}

pub(crate) fn run_remote_debug_relay(
    cli: &Cli,
    plan: &DebugInvocationPlan,
) -> Result<(), CliError> {
    let daemon = cli
        .daemon
        .as_deref()
        .ok_or_else(|| backend_error("remote debugger relay requires --daemon"))?;
    let DebugPlanTarget::Session(session_text) = &plan.target else {
        return Err(usage_error(
            "remote debugger relay requires --session id:epoch:seed",
        ));
    };
    let backend_plan = plan_backend_selection(cli)?
        .ok_or_else(|| backend_error("remote debugger relay has no backend route"))?;
    if backend_plan.daemon_security.is_none() && !cli.trusted_unauthenticated_daemon {
        return Err(usage_error(
            "remote debugging requires daemon mutual TLS or explicit --trusted-unauthenticated-daemon",
        ));
    }
    let session = parse_debug_session_ref(session_text)?;
    let gdb_listen: std::net::SocketAddr = plan.gdb_listen.parse().map_err(|error| {
        usage_error(format!(
            "remote --gdb-listen must be a TCP socket address: {error}"
        ))
    })?;
    if !gdb_listen.ip().is_loopback() {
        return Err(usage_error(
            "remote --gdb-listen must use a loopback address",
        ));
    }
    let node = plan
        .node
        .as_deref()
        .ok_or_else(|| usage_error("remote debugger attachment requires --node NODE"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let node = crucible::NodeId {
        name: node.to_owned(),
    };
    match &plan.verb {
        DebugInteractiveVerbPlan::AttachGdb => runtime.block_on(run_remote_debug_relay_async(
            daemon,
            &backend_plan,
            session,
            node,
            gdb_listen,
        )),
        DebugInteractiveVerbPlan::Exec { argv } => {
            runtime.block_on(run_remote_guest_channel(RemoteGuestChannelRequest {
                daemon,
                backend_plan: &backend_plan,
                session,
                node,
                open: crucible_api::GuestIntrospectionMessage::Exec {
                    argv: argv.clone(),
                    record_transcript: plan.record_transcript.is_some(),
                },
                interactive: false,
                transcript_path: plan.record_transcript.as_deref(),
                guest_idle_timeout: plan.guest_idle_timeout,
            }))
        }
        DebugInteractiveVerbPlan::Pty {
            argv,
            columns,
            rows,
        } => runtime.block_on(run_remote_guest_channel(RemoteGuestChannelRequest {
            daemon,
            backend_plan: &backend_plan,
            session,
            node,
            open: crucible_api::GuestIntrospectionMessage::Pty {
                argv: argv.clone(),
                columns: *columns,
                rows: *rows,
                record_transcript: plan.record_transcript.is_some(),
            },
            interactive: true,
            transcript_path: plan.record_transcript.as_deref(),
            guest_idle_timeout: plan.guest_idle_timeout,
        })),
        DebugInteractiveVerbPlan::Ssh => {
            runtime.block_on(run_remote_guest_channel(RemoteGuestChannelRequest {
                daemon,
                backend_plan: &backend_plan,
                session,
                node,
                open: crucible_api::GuestIntrospectionMessage::Ssh {
                    record_transcript: plan.record_transcript.is_some(),
                },
                interactive: true,
                transcript_path: plan.record_transcript.as_deref(),
                guest_idle_timeout: plan.guest_idle_timeout,
            }))
        }
        DebugInteractiveVerbPlan::ForkDebug => {
            runtime.block_on(run_remote_guest_fork(daemon, &backend_plan, session, node))
        }
        DebugInteractiveVerbPlan::Goto(_)
        | DebugInteractiveVerbPlan::ReverseStep { .. }
        | DebugInteractiveVerbPlan::ReverseContinue { .. } => runtime.block_on(
            run_remote_debug_reposition(daemon, &backend_plan, session, node, &plan.verb),
        ),
    }
}

async fn run_remote_debug_reposition(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
    verb: &DebugInteractiveVerbPlan,
) -> Result<(), CliError> {
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let reposition_result: Result<Option<crucible_api::DebugRepositionResult>, CliError> = async {
        client
            .attach_debugger(session, &lease, &node)
            .await
            .map_err(control_client_error)?;
        match verb {
            DebugInteractiveVerbPlan::Goto(target) => client
                .debug_goto(session, &lease, target)
                .await
                .map(Some)
                .map_err(control_client_error),
            DebugInteractiveVerbPlan::ReverseStep { grain } => client
                .debug_reverse_step(session, &lease, *grain)
                .await
                .map(Some)
                .map_err(control_client_error),
            DebugInteractiveVerbPlan::ReverseContinue { condition } => {
                let condition = parse_debug_reverse_condition(condition)?;
                client
                    .debug_reverse_continue(session, &lease, &condition)
                    .await
                    .map_err(control_client_error)
            }
            DebugInteractiveVerbPlan::AttachGdb
            | DebugInteractiveVerbPlan::ForkDebug
            | DebugInteractiveVerbPlan::Exec { .. }
            | DebugInteractiveVerbPlan::Pty { .. }
            | DebugInteractiveVerbPlan::Ssh => Err(backend_error(
                "non-reposition debug verb reached reposition dispatcher",
            )),
        }
    }
    .await;
    let release_result = client.release_debug_controller(session, &lease).await;
    let target = reposition_result?;
    release_result.map_err(control_client_error)?;
    match target {
        Some(target) => print_debug_landed_runtime(&target),
        None => println!("crucible: reverse-continue found no matching prior condition"),
    }
    Ok(())
}

fn print_debug_landed_runtime(result: &crucible_api::DebugRepositionResult) {
    let landed = &result.landed;
    println!("crucible: debugger repositioned");
    println!("requested-coordinate={}", landed.requested_coordinate);
    println!("landed-configuration={}", landed.configuration);
    println!("landed-runtime-state={}", landed.runtime_state);
    println!("landed-virtual-time={}", landed.virtual_time_ticks);
    println!("landed-schedule-prefix={}", landed.schedule_prefix_len);
    println!("landed-event-log-prefix={}", landed.event_log_prefix);
    println!("landed-event-log-bytes={}", landed.event_log_bytes);
    println!("landed-event-log-events={}", landed.event_log_events);
    for (node, retired) in &landed.node_icounts {
        println!("landed-node-icount.{node}={retired}");
    }
    println!("gateway-generation={}", landed.gateway_generation);
    println!("retired-world-cleanup={}", landed.retired_world_cleanup);
    if let Some(sequence) = result.target_event_sequence {
        println!("target-event-sequence={sequence}");
    }
}
