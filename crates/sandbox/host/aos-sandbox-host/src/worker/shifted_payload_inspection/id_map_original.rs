//! Keeps the fixed shifted inspection's map File, bytes and actual first cause.
//!
//! The enclosing paid launch inspection alone selects UID/GID map reads and
//! authenticates their process. This destination runs the same existing native
//! open/read and parser; it creates no process, mapping or launch authority.

use super::*;
use std::io::Read as _;


pub(in crate::worker) struct ShiftedIdMapOriginalV2 {
    file: Option<File>,
    open: Option<std::result::Result<(), rustix::io::Errno>>,
    bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    length: Option<Result<()>>,
    parsed: Option<Result<()>>,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<HostError>,
}

impl ShiftedIdMapOriginalV2 {
    pub(in crate::worker) fn new() -> Self {
        Self {
            file: None, open: None, bytes: Vec::new(), read: None,
            length: None, parsed: None, returned: None, entered: false, closed: None,
        }
    }

    pub(super) fn capture_once(&mut self, pid: u32, kind: &'static str, host_start: u32, count: u32) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some((|| {
            match open_id_map(pid, kind) {
                Ok(descriptor) => {
                    self.file = Some(File::from(descriptor));
                    self.open = Some(Ok(()));
                }
                Err(cause) => {
                    self.open = Some(Err(cause));
                    return Err(closed());
                }
            }
            self.read_opened_once(host_start, count)
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    fn read_opened_once(&mut self, host_start: u32, count: u32) -> Result<()> {
        self.read = Some(read_id_map_bytes!(self.file.as_ref().ok_or_else(closed)?, &mut self.bytes));
        if !matches!(self.read, Some(Ok(_))) { return Err(closed()); }
        self.length = Some(if self.bytes.len() > MAXIMUM_ID_MAP_BYTES {
            Err(HostError::Worker("payload ID map exceeds its bound".to_owned()))
        } else { Ok(()) });
        if !matches!(self.length, Some(Ok(()))) { return Err(closed()); }
        self.parsed = Some(parse_exact_id_map(&self.bytes, host_start, count));
        if matches!(self.parsed, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.open).or_else(|| error(&self.read)).or_else(|| error(&self.length))
            .or_else(|| error(&self.parsed)).or_else(|| error(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        // At most 128 one-byte whitespace-separated fields can reach the same
        // parser's borrowed-field and u32 tables. Four bounded byte copies
        // dominate Vec growth; path/error formatting has fixed source bounds.
        let parser = MAXIMUM_ID_MAP_BYTES.checked_mul(
            std::mem::size_of::<&str>().checked_add(std::mem::size_of::<u32>())?,
        )?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add((MAXIMUM_ID_MAP_BYTES + 1).checked_mul(4)?)?
            .checked_add(parser)?.checked_add(2 * 25 + 512)?;
        Some((memory, 1, 1))
    }
}

fn closed() -> HostError {
    HostError::Worker("original shifted map inspection remains closed".to_owned())
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_bad_read_keeps_the_original_file_and_same_io_error() {
        let descriptor = rustix::fs::open("/proc/self/uid_map",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let mut original = ShiftedIdMapOriginalV2::new();
        original.file = Some(File::from(descriptor));
        original.open = Some(Ok(()));
        original.entered = true;

        assert!(original.read_opened_once(1, 65_536).is_err());
        let cause = original.read.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(cause.raw_os_error(), Some(rustix::io::Errno::BADF.raw_os_error()));
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.file.as_ref().unwrap().metadata().is_ok());

        assert!(original.capture_once(std::process::id(), "uid_map", 1, 65_536).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        assert!(original.file.as_ref().unwrap().metadata().is_ok());
        assert!(original.parsed.is_none());
    }

    #[test]
    fn missing_real_proc_map_keeps_native_open_error_through_reentry() {
        let mut original = ShiftedIdMapOriginalV2::new();
        assert!(original.capture_once(u32::MAX, "uid_map", 1, 65_536).is_err());
        assert_eq!(original.open, Some(Err(rustix::io::Errno::NOENT)));
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.capture_once(std::process::id(), "uid_map", 1, 65_536).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        assert!(original.file.is_none());
    }
}
