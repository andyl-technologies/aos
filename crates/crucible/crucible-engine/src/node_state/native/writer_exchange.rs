//! Borrowed native writer/control evidence beneath the authenticated source.
//!
//! These parsers check bounded byte framing and original custody only. Native
//! message headers remain opaque and are validated by the installed native
//! source consumer. A successful parse grants no execution or restore right.
//!
//! ```text
//! DCPFIN01 | nine BE-U64 scalars | original request | original response | history
//! DCPCTL01 | process,count | seven BE-U64 scalars and bytes for each original row
//! ```

#[cfg(test)]
#[path = "writer_exchange_tests.rs"]
mod tests;

pub(super) struct OriginalFinalExchange<'a> {
    body: &'a [u8],
}

struct Cursor<'a> {
    body: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn bytes(&mut self, extent: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(extent)
            .ok_or("native evidence extent overflow")?;
        let body = self
            .body
            .get(self.offset..end)
            .ok_or("native evidence truncated")?;
        self.offset = end;
        Ok(body)
    }

    fn number(&mut self) -> Result<u64, &'static str> {
        let mut result = 0u64;
        for byte in self.bytes(8)? {
            result = (result << 8) | u64::from(*byte);
        }
        Ok(result)
    }

    fn finished(&self) -> Result<(), &'static str> {
        if self.offset == self.body.len() {
            Ok(())
        } else {
            Err("native evidence trailing bytes")
        }
    }
}

impl<'a> OriginalFinalExchange<'a> {
    /// Borrows a complete original worker exchange beneath source verification.
    pub(super) fn parse(
        body: &'a [u8],
        final_history: &[u8],
        original_process: u64,
    ) -> Result<Self, &'static str> {
        if body.len() > 2 * 1024 * 1024 + 8192 {
            return Err("final exchange exceeds its selected byte account");
        }
        let mut cursor = Cursor { body, offset: 0 };
        if cursor.bytes(8)? != b"DCPFIN01" {
            return Err("final exchange edition differs");
        }
        let process = cursor.number()?;
        let received = cursor.number()?;
        let acknowledged = cursor.number()?;
        let history_length = cursor.number()?;
        let request_transferred = cursor.number()?;
        let response_transferred = cursor.number()?;
        let error = cursor.number()?;
        let header_length = cursor.number()?;
        let ordinal = cursor.number()?;
        if original_process == 0
            || original_process > i32::MAX as u64
            || process != original_process
            || received != 1
            || acknowledged != 1
            || error != 0
            || ordinal != 1
            || !(1..=4096).contains(&header_length)
            || history_length != final_history.len() as u64
            || history_length > 2 * 1024 * 1024
            || request_transferred != header_length + history_length
            || response_transferred != header_length
        {
            return Err("final exchange is not the complete original copy acknowledgement");
        }
        let header_length = usize::try_from(header_length).map_err(|_| "header extent overflow")?;
        // Exact native headers are retained, not decoded as an Apache layout.
        cursor.bytes(header_length)?;
        cursor.bytes(header_length)?;
        let history_length =
            usize::try_from(history_length).map_err(|_| "history extent overflow")?;
        if cursor.bytes(history_length)? != final_history {
            return Err("native final exchange changed the original attempted debit body");
        }
        cursor.finished()?;
        Ok(Self { body })
    }

    pub(super) fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// Checks original row framing while retaining incomplete and failed originals.
///
/// A complete row is transport completion only. This validation does not infer
/// native acceptance, durable host custody, a consumed ACK or replenished credit.
pub(super) fn validate_control_history(body: &[u8], process: u64) -> Result<(), &'static str> {
    if body.len() > 5 * 1024 * 1024 || process == 0 || process > i32::MAX as u64 {
        return Err("control evidence exceeds selected geometry");
    }
    let mut cursor = Cursor { body, offset: 0 };
    if cursor.bytes(8)? != b"DCPCTL01" || cursor.number()? != process {
        return Err("control evidence edition or original process differs");
    }
    let count = cursor.number()?;
    if count > 64 {
        return Err("control history exceeds original unreplenished frame bank");
    }
    for index in 0..count {
        let outgoing = cursor.number()?;
        let complete = cursor.number()?;
        let extent = cursor.number()?;
        let transferred = cursor.number()?;
        let error = cursor.number()?;
        let close_error = cursor.number()?;
        let ordinal = cursor.number()?;
        if outgoing > 1
            || complete > 1
            || extent > 4096 + 64 * 1024
            || transferred > extent
            || error > i32::MAX as u64
            || close_error > i32::MAX as u64
            || ordinal != index
            || (complete == 1 && (transferred != extent || error != 0 || close_error != 0))
        {
            return Err("original control row shape or completion differs");
        }
        cursor.bytes(usize::try_from(extent).map_err(|_| "control extent overflow")?)?;
    }
    cursor.finished()
}
