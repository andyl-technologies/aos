//! Debugger CLI planning, policy, guest-channel, and transcript tests.

use super::*;

#[test]
pub(super) fn cli_debug_surface_parses_full_t_dbg_8_flags_and_verbs() -> Result<(), Box<dyn Error>>
{
    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "case.crucible",
        "--at",
        "icount:guest-a:102",
        "--node",
        "guest-a",
        "--gdb-listen",
        "127.0.0.1:9000",
        "--checkpoint-stride",
        "4",
        "reverse-step",
        "event",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };

    assert_eq!(args.target.as_deref(), Some("case.crucible"));
    assert_eq!(args.at.as_deref(), Some("icount:guest-a:102"));
    assert_eq!(args.node.as_deref(), Some("guest-a"));
    assert_eq!(args.gdb_listen.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(args.checkpoint_stride, Some(4));
    assert!(matches!(
        &args.verb,
        Some(DebugVerbArgs::ReverseStep {
            grain: DebugStepGrainArg::Event
        })
    ));

    let plan = plan_debug_invocation(&cli, args)?;

    assert!(matches!(&plan.target, DebugPlanTarget::Artifact(_)));
    assert!(matches!(
        &plan.coordinate,
        DebugPlanCoordinate::At(crucible::DebugCoordinate::NodeIcount {
            node,
            icount
        }) if node.name == "guest-a" && icount.retired == 102
    ));
    assert_eq!(plan.node.as_deref(), Some("guest-a"));
    assert!(plan.read_only);
    assert!(!plan.allow_mutate);
    assert_eq!(plan.checkpoint_stride, Some(4));
    assert!(
        plan.session_commands
            .iter()
            .all(SessionCommand::is_read_only),
        "reverse-step grains are realized by the debug reverse-step/goto path, not unsupported session step modes"
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::ReverseStep)
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::RestoreNearestCheckpointReplay)
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::CheckpointCadence)
    );
    assert!(plan.proves_t_dbg_8());

    Ok(())
}
#[test]
pub(super) fn cli_remote_debug_selects_the_daemon_backend_route() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "http://127.0.0.1:9000",
        "--trusted-unauthenticated-daemon",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--node",
        "node-a",
        "attach-gdb",
    ]);

    let plan = plan_backend_selection(&cli)?.ok_or("debug must select a backend route")?;

    assert_eq!(plan.target, BackendExecutionTarget::RemoteDaemon);
    assert_eq!(plan.reason, BackendSelectionReason::RemoteDaemon);
    assert_eq!(plan.daemon.as_deref(), Some("http://127.0.0.1:9000"));
    assert!(plan.remote_uses_control_api);
    Ok(())
}

#[test]
pub(super) fn cli_debug_validates_session_before_backend_discovery() {
    let cli = Cli::parse_from(["crucible", "debug", "--session", "not-a-session"]);

    let error = dispatch(&cli).expect_err("malformed session must fail before backend discovery");

    assert!(matches!(error, CliError::Usage(_)));
    assert!(error.to_string().contains("--session"));
}

#[test]
pub(super) fn cli_debug_reverse_condition_parser_accepts_documented_forms() {
    assert_eq!(
        parse_debug_reverse_condition("quiescent")
            .unwrap_or_else(|error| panic!("quiescent condition must parse: {error}")),
        crucible::Predicate::quiescent()
    );
    assert_eq!(
        parse_debug_reverse_condition("at:42")
            .unwrap_or_else(|error| panic!("at condition must parse: {error}")),
        crucible::Predicate::at(crucible::VirtualTime { ticks: 42 })
    );
    let predicate = crucible::Predicate::quiescent();
    let encoded = predicate
        .to_compact_binary()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        parse_debug_reverse_condition(&format!("hex:{encoded}"))
            .unwrap_or_else(|error| panic!("compact condition must parse: {error}")),
        predicate
    );
    assert!(parse_debug_reverse_condition("unknown").is_err());
}

#[test]
pub(super) fn cli_debug_guest_channels_require_mutation_authorization_and_preserve_argv()
-> Result<(), Box<dyn Error>> {
    let denied = Cli::try_parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--node",
        "node-a",
        "exec",
        "--",
        "/bin/echo",
        "hello world",
    ])?;
    let Commands::Debug(denied_args) = &denied.command else {
        panic!("expected debug command");
    };
    assert!(plan_debug_invocation(&denied, denied_args).is_err());

    let allowed = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--node",
        "node-a",
        "--allow-mutate",
        "--record-transcript",
        "guest.crgt",
        "--guest-idle-timeout",
        "250ms",
        "exec",
        "--",
        "/bin/echo",
        "hello world",
    ]);
    let Commands::Debug(args) = &allowed.command else {
        panic!("expected debug command");
    };
    let plan = plan_debug_invocation(&allowed, args)?;
    assert!(!plan.read_only);
    assert_eq!(
        plan.record_transcript.as_deref(),
        Some(Path::new("guest.crgt"))
    );
    assert_eq!(plan.guest_idle_timeout, Duration::from_millis(250));
    assert!(matches!(
        plan.verb,
        DebugInteractiveVerbPlan::Exec { ref argv }
            if argv == &[String::from("/bin/echo"), String::from("hello world")]
    ));
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::GuestIntrospection)
    );

    let irrelevant_timeout = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--node",
        "node-a",
        "--guest-idle-timeout",
        "1s",
        "attach-gdb",
    ]);
    let Commands::Debug(args) = &irrelevant_timeout.command else {
        panic!("expected debug command");
    };
    let error = plan_debug_invocation(&irrelevant_timeout, args)
        .expect_err("guest idle timeout must be rejected outside guest channels");
    assert!(matches!(error, CliError::Usage(_)));

    let zero_timeout = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--node",
        "node-a",
        "--allow-mutate",
        "--guest-idle-timeout",
        "0s",
        "exec",
        "--",
        "/bin/true",
    ]);
    let Commands::Debug(args) = &zero_timeout.command else {
        panic!("expected debug command");
    };
    let error = plan_debug_invocation(&zero_timeout, args)
        .expect_err("zero guest idle timeout must be rejected");
    assert!(matches!(error, CliError::Usage(_)));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
pub(super) async fn cli_guest_transcript_is_versioned_directional_and_exclusive()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = temp.path().join("guest.crgt");
    let request = crucible_api::GuestIntrospectionRecord::new(
        7,
        crucible_api::GuestIntrospectionMessage::Input(vec![0, 1, 2]),
    )?;
    let response = crucible_api::GuestIntrospectionRecord::new(
        7,
        crucible_api::GuestIntrospectionMessage::Output {
            stream: crucible_api::GuestOutputStream::Stdout,
            bytes: vec![3, 4],
        },
    )?;
    let mut writer = GuestTranscriptWriter::create(&path).await?;
    writer
        .record(GuestTranscriptDirection::HostToGuest, &request)
        .await?;
    writer
        .record(GuestTranscriptDirection::GuestToHost, &response)
        .await?;
    writer.finish().await?;

    let bytes = fs::read(&path)?;
    assert_eq!(&bytes[..8], GUEST_TRANSCRIPT_HEADER);
    let mut offset = 8;
    for (direction, expected) in [(1_u8, request), (2_u8, response)] {
        assert_eq!(bytes[offset], direction);
        assert_eq!(&bytes[offset + 1..offset + 4], &[0, 0, 0]);
        let length = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into()?) as usize;
        offset += 8;
        let decoded = crucible_api::GuestIntrospectionRecord::decode(
            &bytes[offset..offset.saturating_add(length)],
        )?;
        assert_eq!(decoded, expected);
        offset += length;
    }
    assert_eq!(offset, bytes.len());
    assert!(GuestTranscriptWriter::create(&path).await.is_err());
    Ok(())
}

#[test]
pub(super) fn cli_debug_surface_requires_explicit_fork_for_allow_mutate()
-> Result<(), Box<dyn Error>> {
    let checkpoint = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--at-checkpoint",
        checkpoint,
        "--allow-mutate",
        "fork-debug",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };

    let plan = plan_debug_invocation(&cli, args)?;

    assert!(matches!(&plan.target, DebugPlanTarget::Session(_)));
    assert!(matches!(
        &plan.coordinate,
        DebugPlanCoordinate::AtCheckpoint(_)
    ));
    assert!(matches!(&plan.verb, DebugInteractiveVerbPlan::ForkDebug));
    assert!(plan.allow_mutate);
    assert!(!plan.read_only);
    assert_eq!(
        plan.non_canonical_branch_label.as_deref(),
        Some("NON-CANONICAL debug branch")
    );
    assert!(
        plan.session_commands
            .contains(&SessionCommand::fork_current())
    );
    assert!(
        plan.engine_operations
            .contains(&DebugEngineOperation::NonCanonicalBranchFork)
    );
    assert!(plan.proves_t_dbg_8());

    Ok(())
}

#[test]
pub(super) fn cli_debug_allow_mutate_does_not_fork_implicitly() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--allow-mutate",
        "goto",
        "vtime:7",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };

    let plan = plan_debug_invocation(&cli, args)?;

    assert!(plan.allow_mutate);
    assert!(plan.read_only);
    assert!(
        !plan
            .session_commands
            .contains(&SessionCommand::fork_current())
    );
    assert!(plan.non_canonical_branch_label.is_none());
    assert!(plan.proves_t_dbg_8());

    Ok(())
}

#[test]
pub(super) fn cli_debug_surface_rejects_conflicts_and_backend_without_gdbstub() {
    assert!(
        Cli::try_parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--read-only",
            "--allow-mutate",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--at-event",
            "1",
            "--at-failure",
        ])
        .is_err()
    );

    let cli = Cli::parse_from(["crucible", "debug", "case.crucible", "fork-debug"]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = plan_debug_invocation(&cli, args)
        .expect_err("fork-debug must require explicit mutation authorization");
    assert!(error.to_string().contains("requires --allow-mutate"));

    let cli = Cli::parse_from(["crucible", "--backend", "double", "debug", "case.crucible"]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("double backend must not advertise a gdbstub debug surface"),
        Err(error) => error,
    };

    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("open_gdbstub"));

    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "case.crucible",
        "--checkpoint-stride",
        "0",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("zero checkpoint stride must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("non-zero"));

    let cli = Cli::parse_from(["crucible", "debug", "case.crucible", "--node", ""]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = match plan_debug_invocation(&cli, args) {
        Ok(_) => panic!("empty debug node must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--node"));

    let cli = Cli::parse_from([
        "crucible",
        "debug",
        "case.crucible",
        "--record-transcript",
        "guest.crgt",
        "attach-gdb",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("expected debug command");
    };
    let error = plan_debug_invocation(&cli, args)
        .expect_err("transcript recording must be limited to guest channels");
    assert!(error.to_string().contains("exec, pty, or ssh"));
}

#[test]
pub(super) fn cli_debug_surface_defaults_coordinate_by_target_kind() -> Result<(), Box<dyn Error>> {
    let artifact_cli = Cli::parse_from(["crucible", "debug", "case.crucible"]);
    let Commands::Debug(args) = &artifact_cli.command else {
        panic!("expected debug command");
    };
    let artifact_plan = plan_debug_invocation(&artifact_cli, args)?;
    assert!(matches!(
        artifact_plan.coordinate,
        DebugPlanCoordinate::AtFailure
    ));

    let savepoint = "blake3:1111111111111111111111111111111111111111111111111111111111111111";
    let savepoint_cli = Cli::parse_from(["crucible", "debug", savepoint]);
    let Commands::Debug(args) = &savepoint_cli.command else {
        panic!("expected debug command");
    };
    let savepoint_plan = plan_debug_invocation(&savepoint_cli, args)?;
    assert!(matches!(
        savepoint_plan.coordinate,
        DebugPlanCoordinate::AtCheckpoint(_)
    ));

    let session_cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:7000",
        "debug",
        "--session",
        "7:12:1111111111111111111111111111111111111111111111111111111111111111",
    ]);
    let Commands::Debug(args) = &session_cli.command else {
        panic!("expected debug command");
    };
    let session_plan = plan_debug_invocation(&session_cli, args)?;
    assert!(matches!(
        session_plan.coordinate,
        DebugPlanCoordinate::Current
    ));

    Ok(())
}
