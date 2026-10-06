//! Borrowed CBOR container admission before the owning Serde decoder.
//!
//! The generic allocation adapter hides size hints to prevent uncharged Vec
//! preallocation. This walk checks the two format count limits directly from
//! their declared headers without allocating or inspecting opaque payload bytes.

use super::*;

const MAX_DEPTH: usize = 128;

pub(super) fn check(bytes: &[u8]) -> Result<(), CrucibleMeasurementError> {
    let mut cursor = Cursor { bytes, position: 0 };
    cursor
        .fields(false, 0)
        .map_err(|reason| ownership::encoding_error(&reason))?;
    if cursor.position != bytes.len() {
        return Err(CrucibleMeasurementError::NonCanonicalEvidence);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn fields(&mut self, terminal: bool, depth: usize) -> Result<(), &'static str> {
        let (major, count) = self.header()?;
        if major != 5 {
            return Err("measurement CBOR fields must be a map");
        }
        self.item_count(count, 2)?;
        for _ in 0..count {
            let (major, length) = self.header()?;
            if major != 3 {
                return Err("measurement CBOR field names must be text");
            }
            let key = self.take(length)?;
            match (terminal, key) {
                (false, b"entries") => self.container(
                    4,
                    MAX_MEASUREMENT_EVENT_ENTRIES,
                    "at most 1000000 scheduler entries",
                    depth + 1,
                )?,
                (false, b"terminal") => self.fields(true, depth + 1)?,
                (true, b"node_icounts") => self.container(
                    5,
                    MAX_MEASUREMENT_TERMINAL_NODES,
                    "at most 65536 terminal node counters",
                    depth + 1,
                )?,
                _ => self.skip(depth + 1)?,
            }
        }
        Ok(())
    }

    fn container(
        &mut self,
        expected: u8,
        maximum: usize,
        limit: &'static str,
        depth: usize,
    ) -> Result<(), &'static str> {
        let (major, count) = self.header()?;
        if major != expected {
            return Err("invalid measurement CBOR container kind");
        }
        if count > maximum as u64 {
            return Err(limit);
        }
        self.children(major, count, depth)
    }

    fn skip(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_DEPTH {
            return Err("measurement CBOR nesting exceeds 128 levels");
        }
        let (major, argument) = self.header()?;
        match major {
            2 | 3 => {
                self.take(argument)?;
            }
            4 | 5 => self.children(major, argument, depth)?,
            6 => self.skip(depth + 1)?,
            _ => {}
        }
        Ok(())
    }

    fn children(&mut self, major: u8, count: u64, depth: usize) -> Result<(), &'static str> {
        let count = self.item_count(count, if major == 5 { 2 } else { 1 })?;
        for _ in 0..count {
            self.skip(depth + 1)?;
        }
        Ok(())
    }

    fn item_count(&self, count: u64, multiplier: usize) -> Result<usize, &'static str> {
        usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(multiplier))
            .filter(|count| *count <= self.bytes.len().saturating_sub(self.position))
            .ok_or("truncated measurement CBOR container")
    }

    fn header(&mut self) -> Result<(u8, u64), &'static str> {
        let initial = self.take(1)?[0];
        let additional = initial & 31;
        let width = match additional {
            0..=23 => return Ok((initial >> 5, u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err("measurement CBOR requires definite-length containers"),
        };
        let mut encoded = [0; 8];
        encoded[8 - width..].copy_from_slice(self.take(width as u64)?);
        Ok((initial >> 5, u64::from_be_bytes(encoded)))
    }

    fn take(&mut self, length: u64) -> Result<&[u8], &'static str> {
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| self.position.checked_add(length))
            .ok_or("measurement CBOR length overflows")?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated measurement CBOR value")?;
        self.position = end;
        Ok(bytes)
    }
}
