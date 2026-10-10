//! Canonical fixed-width physical fault-actor observations.

use super::*;

fn validate(report: RamControlFaultActorReport) -> Result<(), RamControlError> {
    if report.worker_generation == 0
        || report.thread_id == 0
        || (report.membership_released && report.failure.is_none())
        || (report.failure == Some(RamControlFaultActorFailure::RequestedExit)
            && !report.exit_requested)
        || matches!(report.failure, Some(RamControlFaultActorFailure::Io { errno }) if errno < 0)
    {
        return Err(RamControlError::InvalidFrame);
    }
    Ok(())
}

pub(super) fn encode(
    out: &mut Vec<u8>,
    report: Option<RamControlFaultActorReport>,
) -> Result<(), RamControlError> {
    out.push(u8::from(report.is_some()));
    let Some(report) = report else {
        return Ok(());
    };
    validate(report)?;
    out.extend_from_slice(&report.worker_generation.to_be_bytes());
    out.extend_from_slice(&report.thread_id.to_be_bytes());
    out.push(u8::from(report.exit_requested));
    out.push(u8::from(report.membership_released));
    match report.failure {
        None => out.push(0),
        Some(RamControlFaultActorFailure::RequestedExit) => out.push(1),
        Some(RamControlFaultActorFailure::Io { errno }) => {
            out.push(2);
            out.extend_from_slice(&errno.to_be_bytes());
        }
        Some(RamControlFaultActorFailure::Other) => out.push(3),
    }
    Ok(())
}

pub(super) fn decode(
    input: &mut Decoder<'_>,
) -> Result<Option<RamControlFaultActorReport>, RamControlError> {
    if !input.boolean()? {
        return Ok(None);
    }
    let report = RamControlFaultActorReport {
        worker_generation: input.u64()?,
        thread_id: input.u64()?,
        exit_requested: input.boolean()?,
        membership_released: input.boolean()?,
        failure: match input.byte()? {
            0 => None,
            1 => Some(RamControlFaultActorFailure::RequestedExit),
            2 => Some(RamControlFaultActorFailure::Io {
                errno: i32::from_be_bytes(input.take()?),
            }),
            3 => Some(RamControlFaultActorFailure::Other),
            _ => return Err(RamControlError::InvalidFrame),
        },
    };
    validate(report)?;
    Ok(Some(report))
}
