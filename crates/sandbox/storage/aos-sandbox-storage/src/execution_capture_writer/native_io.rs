//! Gates each selected file syscall through the original native clock policy.
//!
//! The ordinary adapter passes None and keeps the existing standard-library
//! read_exact/write_all/seek algorithms. Selected calls use the same algorithms
//! with a concrete file adapter; partial or interrupted operations cannot enter
//! another native syscall without the same owning clock gate. A native refusal
//! and its independently owed after observation remain resident in the stream.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3;

// This closed DATA roster cannot contain Files or effect owners. A failed
// after-clock keeps the successful primitive's actual value and read prefix.
pub(crate) enum CaptureFileNativeDataV3 {
    Unit,
    Count(usize),
    Offset(u64),
    Metadata(Metadata),
    Read { length: usize, bytes: [u8; super::READBACK_BUFFER_BYTES] },
}

pub(crate) trait CaptureFileNativeValueV3 {
    fn retain_native_data_v3(&self) -> CaptureFileNativeDataV3;
}
impl CaptureFileNativeValueV3 for () {
    fn retain_native_data_v3(&self) -> CaptureFileNativeDataV3 { CaptureFileNativeDataV3::Unit }
}
impl CaptureFileNativeValueV3 for usize {
    fn retain_native_data_v3(&self) -> CaptureFileNativeDataV3 { CaptureFileNativeDataV3::Count(*self) }
}
impl CaptureFileNativeValueV3 for u64 {
    fn retain_native_data_v3(&self) -> CaptureFileNativeDataV3 { CaptureFileNativeDataV3::Offset(*self) }
}
impl CaptureFileNativeValueV3 for Metadata {
    fn retain_native_data_v3(&self) -> CaptureFileNativeDataV3 { CaptureFileNativeDataV3::Metadata(self.clone()) }
}

#[derive(Clone, Copy)]
enum Failure { Before, Native, After }

pub(crate) struct CaptureFileIoOriginalV3 {
    clocks: CaptureWorkerClockOriginalV3<2>,
    native: Option<io::Error>,
    native_errno: Option<rustix::io::Errno>,
    positive: Option<CaptureFileNativeDataV3>,
    first: Option<Failure>,
}

impl CaptureFileIoOriginalV3 {
    #[cfg(test)]
    pub(crate) fn expired_wall_fixture_v3() -> Self {
        Self { clocks: CaptureWorkerClockOriginalV3::expired_wall_fixture_v3().unwrap(),
            native: None, native_errno: None, positive: None, first: None }
    }

    pub(crate) fn from_worker_v3(
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
        boot: [u8; 16], cutoff: u64,
    ) -> Self {
        Self { clocks: CaptureWorkerClockOriginalV3::from_worker_v3(context, boot, cutoff), native: None, native_errno: None, positive: None, first: None }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Before => self.clocks.failure_at_v3(0),
            Failure::Native => self.native_errno.as_ref().map(|cause| cause as _)
                .or_else(|| self.native.as_ref().map(|cause| cause as _)),
            Failure::After => self.clocks.failure_at_v3(1),
        }
    }

    // Callers keep any newly owned native value in their existing original
    // before returning from action. Only a unit or other non-owning result may
    // cross this helper's independently owed after-clock refusal.
    pub(crate) fn observe_errno_v3(
        &mut self, action: impl FnOnce() -> Result<(), rustix::io::Errno>,
    ) -> Result<(), rustix::io::Errno> {
        let mut native_errno = None;
        let result = self.observe_native_v3(|| action().map_err(|cause| {
            native_errno = Some(cause);
            io::Error::from_raw_os_error(cause.raw_os_error())
        }));
        if let Some(cause) = native_errno { self.native_errno.get_or_insert(cause); }
        result.map_err(|_| native_errno.unwrap_or(rustix::io::Errno::IO))
    }

    pub(crate) fn observe_native_v3<T: CaptureFileNativeValueV3>(
        &mut self, action: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.observe_native_data_v3(|| {
            let value = action()?;
            let data = value.retain_native_data_v3();
            Ok((value, data))
        })
    }

    fn observe_native_data_v3<T>(
        &mut self, action: impl FnOnce() -> io::Result<(T, CaptureFileNativeDataV3)>,
    ) -> io::Result<T> {
        // An interrupted/partial failure is retained. A standard-library retry
        // refuses before IO instead of replacing its native cause or prefix.
        if self.first.is_some() || self.positive.is_some() { return Err(refusal()); }
        self.first = Some(Failure::Before);
        self.clocks.observe_once_v3(0).map_err(|_| refusal())?;
        let result = action();
        let value = match result {
            Ok((value, data)) => {
                // The actual positive value/prefix is parked BEFORE the owed
                // after. A failed bookend cannot dispose its native DATA.
                self.positive = Some(data);
                Some(value)
            }
            Err(cause) => { self.native = Some(cause); None }
        };
        let post = self.clocks.observe_once_v3(1);
        let Some(value) = value else {
            self.first = Some(Failure::Native);
            return Err(refusal());
        };
        self.first = Some(Failure::After);
        post.map_err(|_| refusal())?;
        self.clocks.retire_positive_range_v3(0..2).map_err(|_| refusal())?;
        self.positive = None;
        self.first = None;
        Ok(value)
    }

}

#[derive(Debug)]
struct CaptureFileIoRefusedV3;
impl std::fmt::Display for CaptureFileIoRefusedV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected Capture file operation retained its original refusal")
    }
}
impl std::error::Error for CaptureFileIoRefusedV3 {}
fn refusal() -> io::Error { io::Error::other(CaptureFileIoRefusedV3) }

pub(crate) struct CaptureFileIoV3<'file> {
    pub(crate) file: &'file mut File,
    pub(crate) original: Option<&'file mut CaptureFileIoOriginalV3>,
}

impl CaptureFileIoV3<'_> {
    // Preserve File's own optimized ordinary adapters exactly. Only the
    // selected native destination routes each primitive through our Write/Read
    // implementations; the standard-library combinator remains the one loop.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.original.is_none() { self.file.write_all(bytes) }
        else { Write::write_all(self, bytes) }
    }

    pub(super) fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        if self.original.is_none() { self.file.read_exact(bytes) }
        else { Read::read_exact(self, bytes) }
    }

    fn observe_v3<T: CaptureFileNativeValueV3>(&mut self, action: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
        match self.original.as_deref_mut() {
            Some(original) => original.observe_native_v3(|| action(self.file)),
            None => action(self.file),
        }
    }

    pub(crate) fn sync_all(&mut self) -> io::Result<()> {
        self.observe_v3(|file| file.sync_all())
    }

    pub(super) fn sync_data(&mut self) -> io::Result<()> {
        self.observe_v3(|file| file.sync_data())
    }

    pub(super) fn metadata(&mut self) -> io::Result<Metadata> {
        self.observe_v3(|file| file.metadata())
    }
}

impl Write for CaptureFileIoV3<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.observe_v3(|file| file.write(bytes))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.observe_v3(|file| file.flush())
    }
}

impl Read for CaptureFileIoV3<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self.original.as_deref_mut() {
            Some(original) => {
                if bytes.len() > super::READBACK_BUFFER_BYTES { return Err(refusal()); }
                original.observe_native_data_v3(|| {
                    let length = self.file.read(bytes)?;
                    let mut reached = [0; super::READBACK_BUFFER_BYTES];
                    reached[..length].copy_from_slice(&bytes[..length]);
                    Ok((length, CaptureFileNativeDataV3::Read { length, bytes: reached }))
                })
            }
            None => self.file.read(bytes),
        }
    }
}

impl Seek for CaptureFileIoV3<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.observe_v3(|file| file.seek(position))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn failed_after_keeps_the_actual_positive_write_and_read_results() {
        let mut file = tempfile::tempfile().unwrap();
        let mut write_original = CaptureFileIoOriginalV3 {
            clocks: CaptureWorkerClockOriginalV3::fresh_wall_fixture_v3().unwrap(),
            native: None, native_errno: None, positive: None, first: None,
        };
        // Consume only the after destination to model a real refused bookend;
        // the selected operation still enters its actual before and file IO.
        write_original.clocks.observe_once_v3(1).unwrap();

        let write = CaptureFileIoV3 { file: &mut file, original: Some(&mut write_original) }.write_all(b"actual-prefix");

        assert!(write.is_err());
        assert!(matches!(write_original.first, Some(Failure::After)));
        assert!(matches!(write_original.positive, Some(CaptureFileNativeDataV3::Count(13))));
        assert!(write_original.failure().is_some());
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut read_original = CaptureFileIoOriginalV3 {
            clocks: CaptureWorkerClockOriginalV3::fresh_wall_fixture_v3().unwrap(),
            native: None, native_errno: None, positive: None, first: None,
        };
        read_original.clocks.observe_once_v3(1).unwrap();
        let mut readback = [0; 13];

        let read = CaptureFileIoV3 { file: &mut file, original: Some(&mut read_original) }.read(&mut readback);

        assert!(read.is_err());
        assert!(matches!(read_original.first, Some(Failure::After)));
        match read_original.positive.as_ref().unwrap() {
            CaptureFileNativeDataV3::Read { length, bytes } => {
                assert_eq!(*length, 13);
                assert_eq!(&bytes[..*length], b"actual-prefix");
            }
            _ => panic!("actual native read result was not retained"),
        }
        assert!(read_original.failure().is_some());
    }

    #[test]
    fn expired_wall_gate_preserves_file_and_original_refusal_on_another_write() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("aos-capture-native-gate-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        file.write_all(b"retained").unwrap();
        let mut original = CaptureFileIoOriginalV3 {
            clocks: CaptureWorkerClockOriginalV3::expired_wall_fixture_v3().unwrap(),
            native: None, native_errno: None, positive: None, first: None,
        };

        let result = CaptureFileIoV3 { file: &mut file, original: Some(&mut original) }.write_all(b"forbidden");

        assert!(result.is_err());
        assert!(matches!(original.first, Some(Failure::Before)));
        assert!(original.native.is_none());
        let first_cause = original.failure().unwrap() as *const dyn std::error::Error;
        let retry = CaptureFileIoV3 { file: &mut file, original: Some(&mut original) }.write_all(b"also-forbidden");
        assert!(retry.is_err());
        assert!(std::ptr::eq(first_cause, original.failure().unwrap()));
        assert_eq!(std::fs::read(&path).unwrap(), b"retained");
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
