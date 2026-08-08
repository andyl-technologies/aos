//! Debug target, coordinate, and interactive verb parsing.

use super::*;

pub(in super::super) fn debug_target(args: &DebugArgs) -> Result<DebugPlanTarget, CliError> {
    match (&args.target, &args.session) {
        (Some(_), Some(_)) => Err(usage_error(
            "debug accepts either ARTIFACT|SAVEPOINT or --session, not both",
        )),
        (None, None) => Err(usage_error(
            "debug requires ARTIFACT|SAVEPOINT or --session",
        )),
        (None, Some(session)) => Ok(DebugPlanTarget::Session(session.clone())),
        (Some(target), None) => {
            if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("debug target", target)
            {
                Ok(DebugPlanTarget::Savepoint(reference.hash()))
            } else {
                Ok(DebugPlanTarget::Artifact(PathBuf::from(target)))
            }
        }
    }
}

pub(in super::super) fn debug_coordinate(
    args: &DebugArgs,
    target: &DebugPlanTarget,
) -> Result<DebugPlanCoordinate, CliError> {
    if let Some(at) = &args.at {
        return parse_debug_at_coordinate(at).map(DebugPlanCoordinate::At);
    }
    if let Some(sequence) = args.at_event {
        return Ok(DebugPlanCoordinate::AtEvent(sequence));
    }
    if args.at_failure {
        return Ok(DebugPlanCoordinate::AtFailure);
    }
    if let Some(checkpoint) = &args.at_checkpoint {
        return crucible::ContentAddressedBlobRef::parse("at-checkpoint", checkpoint)
            .map(|reference| DebugPlanCoordinate::AtCheckpoint(reference.hash()))
            .map_err(|error| usage_error(format!("invalid --at-checkpoint: {error}")));
    }
    Ok(match target {
        DebugPlanTarget::Artifact(_) => DebugPlanCoordinate::AtFailure,
        DebugPlanTarget::Savepoint(hash) => DebugPlanCoordinate::AtCheckpoint(*hash),
        DebugPlanTarget::Session(_) => DebugPlanCoordinate::Current,
    })
}

pub(in super::super) fn parse_debug_at_coordinate(
    value: &str,
) -> Result<crucible::DebugCoordinate, CliError> {
    if let Some(ticks) = value.strip_prefix("vtime:") {
        return parse_virtual_time(ticks);
    }
    if let Some(node_icount) = value.strip_prefix("icount:") {
        return parse_node_icount(node_icount);
    }
    if let Some(sequence) = value.strip_prefix("event:") {
        return parse_u64_value("--at event", sequence)
            .map(crucible::DebugCoordinate::event_sequence);
    }
    if value.contains(':') {
        return parse_node_icount(value);
    }
    parse_virtual_time(value)
}

pub(in super::super) fn parse_virtual_time(
    value: &str,
) -> Result<crucible::DebugCoordinate, CliError> {
    let ticks = parse_u64_value("--at", value)?;
    Ok(crucible::DebugCoordinate::virtual_time(
        crucible::VirtualTime { ticks },
    ))
}

pub(in super::super) fn parse_node_icount(
    value: &str,
) -> Result<crucible::DebugCoordinate, CliError> {
    let Some((node, retired)) = value.split_once(':') else {
        return Err(usage_error(
            "--at node-icount coordinates must be `icount:<node>:<retired>`",
        ));
    };
    if node.is_empty() {
        return Err(usage_error("--at node-icount coordinate has an empty node"));
    }
    let retired = parse_u64_value("--at", retired)?;
    Ok(crucible::DebugCoordinate::node_icount(
        crucible::NodeId {
            name: node.to_string(),
        },
        crucible::Icount { retired },
    ))
}

pub(in super::super) fn parse_u64_value(field: &'static str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        usage_error(format!(
            "{field} must be an unsigned integer value, got `{value}`"
        ))
    })
}

pub(in super::super) fn validate_debug_checkpoint_stride(stride: u64) -> Result<u64, CliError> {
    let Ok(every) = usize::try_from(stride) else {
        return Err(usage_error(
            "--checkpoint-stride is too large for this platform",
        ));
    };
    if crucible::DebugCheckpointStride::new(every).is_none() {
        return Err(usage_error("--checkpoint-stride must be non-zero"));
    }
    Ok(stride)
}

pub(in super::super) fn debug_verb(args: &DebugArgs) -> Result<DebugInteractiveVerbPlan, CliError> {
    match &args.verb {
        None | Some(DebugVerbArgs::AttachGdb) => Ok(DebugInteractiveVerbPlan::AttachGdb),
        Some(DebugVerbArgs::ForkDebug) => Ok(DebugInteractiveVerbPlan::ForkDebug),
        Some(DebugVerbArgs::Goto { coord }) => {
            parse_debug_at_coordinate(coord).map(DebugInteractiveVerbPlan::Goto)
        }
        Some(DebugVerbArgs::ReverseStep { grain }) => Ok(DebugInteractiveVerbPlan::ReverseStep {
            grain: grain.reverse_grain(),
        }),
        Some(DebugVerbArgs::ReverseContinue { condition }) => {
            Ok(DebugInteractiveVerbPlan::ReverseContinue {
                condition: condition.clone(),
            })
        }
        Some(DebugVerbArgs::Exec { argv }) => {
            Ok(DebugInteractiveVerbPlan::Exec { argv: argv.clone() })
        }
        Some(DebugVerbArgs::Pty {
            columns,
            rows,
            argv,
        }) => Ok(DebugInteractiveVerbPlan::Pty {
            argv: argv.clone(),
            columns: *columns,
            rows: *rows,
        }),
        Some(DebugVerbArgs::Ssh) => Ok(DebugInteractiveVerbPlan::Ssh),
    }
}
