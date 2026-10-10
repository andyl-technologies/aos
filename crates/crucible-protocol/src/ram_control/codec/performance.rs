//! Canonical fixed-width diagnostic reports and scalar validation.

use super::*;

pub(super) fn encode(
    out: &mut Vec<u8>,
    performance: Option<RamControlPerformance>,
) -> Result<(), RamControlError> {
    out.push(u8::from(performance.is_some()));
    let Some(performance) = performance else {
        return Ok(());
    };
    validate(&performance)?;
    out.extend_from_slice(&performance.generation.to_be_bytes());
    out.push(u8::from(performance.active));
    out.push(u8::from(performance.complete));
    out.extend_from_slice(&performance.pending_operations.to_be_bytes());
    for io in performance.io {
        for value in [
            io.operations,
            io.completed,
            io.failed,
            io.syscalls,
            io.transferred_bytes,
            io.elapsed_ns,
            io.maximum_elapsed_ns,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

pub(super) fn decode(
    input: &mut Decoder<'_>,
) -> Result<Option<RamControlPerformance>, RamControlError> {
    match input.byte()? {
        0 => return Ok(None),
        1 => {}
        _ => return Err(RamControlError::InvalidFrame),
    }
    let mut result = RamControlPerformance {
        generation: input.u64()?,
        active: input.boolean()?,
        complete: input.boolean()?,
        pending_operations: input.u64()?,
        io: [RamControlIoMeasurement::default(); RAM_PERFORMANCE_IO_CLASSES],
    };
    for io in &mut result.io {
        *io = RamControlIoMeasurement {
            operations: input.u64()?,
            completed: input.u64()?,
            failed: input.u64()?,
            syscalls: input.u64()?,
            transferred_bytes: input.u64()?,
            elapsed_ns: input.u64()?,
            maximum_elapsed_ns: input.u64()?,
        };
    }
    validate(&result)?;
    Ok(Some(result))
}

fn validate(result: &RamControlPerformance) -> Result<(), RamControlError> {
    if result.generation == 0 {
        return Err(RamControlError::InvalidFrame);
    }
    for (index, io) in result.io.iter().enumerate() {
        if io.completed.checked_add(io.failed) != Some(io.operations)
            || io.maximum_elapsed_ns > io.elapsed_ns
            || (index == RamControlIoClass::Sync as usize && io.transferred_bytes != 0)
        {
            return Err(RamControlError::InvalidFrame);
        }
    }
    Ok(())
}
