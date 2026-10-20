//! Borrows the terminal native control seal beneath complete source ancestry.
//!
//! ```text
//! DCPPARK1 | process,thread,uid,socket-device,socket-inode,frames,channels
//! ```
//!
//! The seven scalars are big-endian U64 values. This allocation-free framing
//! join authenticates no kernel wait, fresh descriptor, durable host ACK or
//! restore permission. The installed semantic source verifier remains required.

#[cfg(test)]
#[path = "writer_terminal_park_tests.rs"]
mod tests;

pub(super) struct OriginalTerminalControlPark<'a> {
    body: &'a [u8],
}

fn number(body: &[u8], offset: usize) -> Result<u64, &'static str> {
    let end = offset
        .checked_add(8)
        .ok_or("terminal park scalar overflow")?;
    let bytes = body
        .get(offset..end)
        .ok_or("terminal park scalar truncated")?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

impl<'a> OriginalTerminalControlPark<'a> {
    /// Borrows the original seal only after exact native body joins.
    ///
    /// # Errors
    /// Refuses foreign editions, scalars, original process/UID or frame counts.
    /// Full writer and control body validation precedes this additional join.
    pub(super) fn parse(
        body: &'a [u8],
        final_history: &[u8],
        control_history: &[u8],
        original_process: u64,
    ) -> Result<Self, &'static str> {
        if body.len() != 64 || body.get(..8) != Some(b"DCPPARK1") {
            return Err("terminal park edition or exact extent differs");
        }
        let process = number(body, 8)?;
        let thread = number(body, 16)?;
        let uid = number(body, 24)?;
        let inode = number(body, 40)?;
        let frames = number(body, 48)?;
        let channels = number(body, 56)?;
        if process == 0
            || process > i32::MAX as u64
            || process != original_process
            || thread == 0
            || thread > i32::MAX as u64
            || uid > u32::MAX as u64
            || inode == 0
            || frames > 64
            || !(1..=64).contains(&channels)
        {
            return Err("terminal park scalar geometry differs");
        }
        if final_history.get(..8) != Some(b"DCPBUD01")
            || number(final_history, 8)? != process
            || number(final_history, 16)? != uid
            || control_history.get(..8) != Some(b"DCPCTL01")
            || number(control_history, 8)? != process
            || number(control_history, 16)? != frames
        {
            return Err("terminal park changed the original writer/control census");
        }
        Ok(Self { body })
    }

    /// Borrows unchanged original bytes without reconstructing an accepted DTO.
    pub(super) fn body(&self) -> &'a [u8] {
        self.body
    }
}
