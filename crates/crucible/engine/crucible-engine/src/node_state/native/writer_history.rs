//! Borrowed original DMTCP writer records without execution or restore authority.
//!
//! `DCPBUD01` contains eight magic bytes, six big-endian U64 header scalars,
//! original root bytes, and seven scalars plus path bytes for every file row.
//! Parsing never allocates, opens paths, adopts descriptors, or changes accounts.

const MAXIMUM_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_ROWS: u64 = 4096;
const MAXIMUM_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAXIMUM_ACCOUNT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[cfg(test)]
#[path = "writer_history_tests.rs"]
mod tests;

/// Borrows one unchanged original writer debit record.
pub(super) struct WriterHistory<'a> {
    body: &'a [u8],
    process: u64,
    uid: u64,
    count: u64,
    charged: u64,
    copy_buffer: bool,
    root: &'a [u8],
    rows_offset: usize,
}

#[derive(Clone, Copy)]
struct Row<'a> {
    relative: &'a [u8],
    directory: bool,
    adopted: bool,
    active: bool,
    charged: u64,
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    body: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn number(&mut self) -> Result<u64, &'static str> {
        let end = self.offset.checked_add(8).ok_or("writer scalar overflow")?;
        let bytes = self
            .body
            .get(self.offset..end)
            .ok_or("writer scalar truncated")?;
        let mut value = 0u64;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        self.offset = end;
        Ok(value)
    }

    fn text(&mut self, length: u64, maximum: usize) -> Result<&'a [u8], &'static str> {
        let length = usize::try_from(length).map_err(|_| "writer string length overflow")?;
        if length == 0 || length > maximum {
            return Err("writer string exceeds its fixed geometry");
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or("writer string overflow")?;
        let bytes = self
            .body
            .get(self.offset..end)
            .ok_or("writer string truncated")?;
        if bytes.contains(&0) {
            return Err("writer string contains NUL");
        }
        self.offset = end;
        Ok(bytes)
    }

    fn boolean(&mut self) -> Result<bool, &'static str> {
        match self.number()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("writer boolean is foreign"),
        }
    }

    fn row(&mut self) -> Result<Row<'a>, &'static str> {
        let length = self.number()?;
        let directory = self.boolean()?;
        let adopted = self.boolean()?;
        let active = self.boolean()?;
        let charged = self.number()?;
        let device = self.number()?;
        let inode = self.number()?;
        let relative = self.text(length, 255)?;
        if charged > MAXIMUM_FILE_BYTES
            || (active && !adopted)
            || (!adopted && (charged != 0 || device != 0 || inode != 0))
            || (adopted && inode == 0)
        {
            return Err("writer row effects exceed original adoption or credit");
        }
        Ok(Row {
            relative,
            directory,
            adopted,
            active,
            charged,
            device,
            inode,
        })
    }
}

impl<'a> WriterHistory<'a> {
    /// Checks all original rows without copying or trusting file lengths.
    ///
    /// # Errors
    /// Refuses foreign editions, unsafe path geometry, duplicate original paths,
    /// incomplete directory ancestry, inconsistent debit totals or extra bytes.
    pub(super) fn parse(body: &'a [u8]) -> Result<Self, &'static str> {
        if !(56..=MAXIMUM_RECORD_BYTES).contains(&body.len()) || body.get(..8) != Some(b"DCPBUD01")
        {
            return Err("writer history edition or record credit differs");
        }
        let mut cursor = Cursor { body, offset: 8 };
        let process = cursor.number()?;
        let uid = cursor.number()?;
        let count = cursor.number()?;
        let charged = cursor.number()?;
        let copy_buffer = cursor.boolean()?;
        let root_length = cursor.number()?;
        let root = cursor.text(root_length, 4095)?;
        if process == 0
            || process > i32::MAX as u64
            || uid > u32::MAX as u64
            || count > MAXIMUM_ROWS
            || charged > MAXIMUM_ACCOUNT_BYTES
            || root.first() != Some(&b'/')
            || (root.len() > 1
                && root[1..]
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || part == b"." || part == b".."))
        {
            return Err("writer header or inert source-root geometry differs");
        }
        let rows_offset = cursor.offset;
        let mut supplementary = None;
        let mut total = 0u64;
        for index in 0..count {
            let row = cursor.row()?;
            let mut parts = row.relative.split(|byte| *byte == b'/');
            let first = parts.next().ok_or("writer path empty")?;
            let second = parts.next();
            if parts.next().is_some()
                || first.is_empty()
                || first == b"."
                || first == b".."
                || second.is_some_and(|part| part.is_empty() || part == b"." || part == b"..")
            {
                return Err("writer path exceeds one supplementary directory");
            }
            if row.directory {
                if supplementary.is_some()
                    || second.is_some()
                    || !first.ends_with(b"_files")
                    || row.adopted
                    || row.active
                    || row.charged != 0
                    || row.device != 0
                    || row.inode != 0
                {
                    return Err("writer directory birth is foreign");
                }
                supplementary = Some(first);
            } else if second.is_some() && supplementary != Some(first) {
                return Err("saved file lacks its preceding original directory birth");
            }

            // Fixed 4096-row bound admits this allocation-free duplicate check.
            let mut preceding = Cursor {
                body,
                offset: rows_offset,
            };
            for _ in 0..index {
                if preceding.row()?.relative == row.relative {
                    return Err("writer original path repeated");
                }
            }
            total = total
                .checked_add(row.charged)
                .ok_or("writer debit overflow")?;
        }
        if cursor.offset != body.len() || total != charged {
            return Err("writer complete row debit census differs");
        }
        Ok(Self {
            body,
            process,
            uid,
            count,
            charged,
            copy_buffer,
            root,
            rows_offset,
        })
    }

    /// Borrows the exact source object, including failed attempted-write charges.
    pub(super) fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Returns the original process identity as inert preservation data.
    pub(super) fn process(&self) -> u64 {
        self.process
    }

    /// Checks a later final account against the original pre-capture record.
    ///
    /// # Errors
    /// Refuses dropped rows, lower attempted charges, changed original file
    /// identities, live producer buffers/FDs or a foreign original account.
    pub(super) fn preserves(&self, earlier: &Self) -> Result<(), &'static str> {
        if self.process != earlier.process
            || self.uid != earlier.uid
            || self.root != earlier.root
            || self.count < earlier.count
            || self.charged < earlier.charged
            || self.copy_buffer
        {
            return Err("final writer account differs from original capture ancestry");
        }
        let mut final_rows = Cursor {
            body: self.body,
            offset: self.rows_offset,
        };
        let mut old_rows = Cursor {
            body: earlier.body,
            offset: earlier.rows_offset,
        };
        for index in 0..self.count {
            let final_row = final_rows.row()?;
            if final_row.active {
                return Err("final writer record still owns a live producer descriptor");
            }
            if index < earlier.count {
                let old_row = old_rows.row()?;
                if final_row.relative != old_row.relative
                    || final_row.directory != old_row.directory
                    || final_row.charged < old_row.charged
                    || (old_row.adopted
                        && (!final_row.adopted
                            || final_row.device != old_row.device
                            || final_row.inode != old_row.inode))
                {
                    return Err("final writer row dropped original custody or debit");
                }
            }
        }
        Ok(())
    }
}
