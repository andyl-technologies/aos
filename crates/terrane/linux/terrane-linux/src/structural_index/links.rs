//! Checks immutable hard-link membership before exposing canonical inode paths.

use super::{Error, Index, Kind, NONE, number, offset32};

impl Index<'_> {
    pub(super) fn validate_links(&self) -> Result<(), Error> {
        let mut cursor = 0usize;
        let mut files = 0usize;
        for position in 0..self.count {
            let entry = self.entry(position).ok_or(Error::Tree)?;
            let record = self.record(position)?;
            let canonical = number::<4>(record, 64)? as u32;
            let first = offset32(record, 68)?;
            let count = offset32(record, 72)?;
            if first != cursor {
                return Err(Error::Tree);
            }
            if !matches!(entry.kind(), Kind::File { .. }) {
                if canonical != NONE || count != 0 {
                    return Err(Error::Tree);
                }
                continue;
            }
            files += 1;
            if canonical > position || (canonical != position && count != 0) {
                return Err(Error::Tree);
            }
            let owner = self.entry(canonical).ok_or(Error::Tree)?;
            let owner_record = self.record(canonical)?;
            if !matches!(owner.kind(), Kind::File { .. })
                || number::<4>(owner_record, 64)? != u64::from(canonical)
                || number::<4>(owner_record, 72)? == 0
                || owner.kind() != entry.kind()
                || owner.governing_boundary()? != entry.governing_boundary()?
                || self.metadata_bytes(canonical)? != self.metadata_bytes(position)?
            {
                return Err(Error::Tree);
            }
            if canonical != position {
                continue;
            }
            let end = cursor.checked_add(count).ok_or(Error::Tree)?;
            if end > (self.bytes.len() - self.links) / 4 {
                return Err(Error::Tree);
            }
            let mut previous = None;
            for member in cursor..end {
                let member = number::<4>(
                    self.bytes,
                    self.links + member.checked_mul(4).ok_or(Error::Tree)?,
                )? as u32;
                if previous.is_none() && member != canonical
                    || previous.is_some_and(|prior| prior >= member)
                    || number::<4>(self.record(member)?, 64)? != u64::from(canonical)
                    || !matches!(self.decode(member)?.1, Kind::File { .. })
                {
                    return Err(Error::Tree);
                }
                previous = Some(member);
            }
            cursor = end;
        }
        if cursor != files
            || self
                .links
                .checked_add(cursor.checked_mul(4).ok_or(Error::Tree)?)
                != Some(self.bytes.len())
        {
            return Err(Error::Tree);
        }
        Ok(())
    }
}
