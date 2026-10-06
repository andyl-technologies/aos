//! Canonical original-operation failure observations with fixed scalar bounds.

use super::*;

pub(super) fn encode(
    out: &mut Vec<u8>,
    failure: Option<RamControlOperationFailure>,
) -> Result<(), RamControlError> {
    out.push(u8::from(failure.is_some()));
    let Some(failure) = failure else {
        return Ok(());
    };
    out.push(failure.operation as u8);
    out.extend_from_slice(&failure.policy_revision.to_be_bytes());
    out.extend_from_slice(&failure.topology_generation.to_be_bytes());
    match failure.cause {
        RamControlFailureCause::Io { errno } => {
            if errno < 0 {
                return Err(RamControlError::InvalidFrame);
            }
            out.push(0);
            out.extend_from_slice(&errno.to_be_bytes());
        }
        RamControlFailureCause::Native { status } => {
            if status == 0 {
                return Err(RamControlError::InvalidFrame);
            }
            out.push(1);
            out.extend_from_slice(&status.to_be_bytes());
        }
        RamControlFailureCause::Supervision { kind } => {
            out.push(2);
            out.push(kind as u8);
        }
        RamControlFailureCause::Other => out.push(3),
    }
    Ok(())
}

pub(super) fn decode(
    input: &mut Decoder<'_>,
) -> Result<Option<RamControlOperationFailure>, RamControlError> {
    if !input.boolean()? {
        return Ok(None);
    }
    let operation = match input.byte()? {
        0 => RamControlFailureOperation::ControlSetup,
        1 => RamControlFailureOperation::Cleanup,
        2 => RamControlFailureOperation::Quiescence,
        3 => RamControlFailureOperation::ForkRearm,
        4 => RamControlFailureOperation::PageIn,
        5 => RamControlFailureOperation::Writeback,
        6 => RamControlFailureOperation::FingerprintUpdate,
        _ => return Err(RamControlError::InvalidFrame),
    };
    let policy_revision = input.u64()?;
    let topology_generation = input.u64()?;
    let cause = match input.byte()? {
        0 => RamControlFailureCause::Io {
            errno: i32::from_be_bytes(input.take()?),
        },
        1 => RamControlFailureCause::Native {
            status: i32::from_be_bytes(input.take()?),
        },
        2 => RamControlFailureCause::Supervision {
            kind: match input.byte()? {
                0 => RamControlSupervisionFailure::Expired,
                1 => RamControlSupervisionFailure::Canceled,
                2 => RamControlSupervisionFailure::MissingPolicy,
                3 => RamControlSupervisionFailure::Capacity,
                4 => RamControlSupervisionFailure::Uncertain,
                _ => return Err(RamControlError::InvalidFrame),
            },
        },
        3 => RamControlFailureCause::Other,
        _ => return Err(RamControlError::InvalidFrame),
    };
    Ok(Some(RamControlOperationFailure {
        operation,
        policy_revision,
        topology_generation,
        cause,
    }))
}
