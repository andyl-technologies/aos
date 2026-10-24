//! Shares bounded Root proc reads with the caller's retained native destination.
//!
//! The fixed role owns its path and admission. This inert storage supplies no
//! process identity, role or permission to acquire a file.

use std::error::Error;
use std::fs::File;
use std::io::{Read as _, Take};

pub(crate) struct BoundedFileReadOriginalV1 {
    read: Option<std::io::Result<usize>>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) text: String,
    reader: Option<Take<File>>,
    open: Option<std::io::Result<()>>,
}

impl BoundedFileReadOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            read: None,
            bytes: Vec::new(),
            text: String::new(),
            reader: None,
            open: None,
        }
    }

    pub(crate) fn read_once(
        &mut self,
        path: &str,
        maximum: u64,
        text: bool,
        retained: bool,
    ) -> Result<(), ()> {
        if self.open.is_some() {
            return Err(());
        }
        match File::open(path) {
            Ok(file) => {
                self.reader = Some(file.take(maximum + 1));
                self.open = Some(Ok(()));
            }
            Err(cause) => self.open = Some(Err(cause)),
        }
        let Some(reader) = self.reader.as_mut() else {
            if !retained {
                drop(self.open.take());
            }
            return Err(());
        };

        let read = if text {
            reader.read_to_string(&mut self.text)
        } else {
            reader.read_to_end(&mut self.bytes)
        };
        if retained {
            self.read = Some(read);
            if matches!(self.read, Some(Ok(_))) { Ok(()) } else { Err(()) }
        } else {
            // The original temporary File ended before mapping the IO/length
            // result. The mapped native error also ended before the buffer.
            drop(self.reader.take());
            read.map(|_| ()).map_err(|_| ())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.open.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.read.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &dyn Error))
    }

    pub(crate) fn requested_bytes_v1(maximum: usize) -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(maximum.checked_add(1)?.checked_mul(4)?)?
            .checked_add(8192)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_read_keeps_actual_file_and_bytes_after_name_removal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("observation");
        std::fs::write(&path, b"native bytes").unwrap();
        let mut original = BoundedFileReadOriginalV1::new();

        original.read_once(path.to_str().unwrap(), 64, false, true).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(original.bytes, b"native bytes");
        assert_eq!(original.reader.as_ref().unwrap().get_ref().metadata().unwrap().len(), 12);
        assert!(original.failure().is_none());
        assert!(original.read_once(path.to_str().unwrap(), 64, false, true).is_err());
        assert_eq!(original.bytes, b"native bytes");
        assert!(original.reader.is_some());
    }

    #[test]
    fn invalid_utf8_retains_same_native_error_and_open_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid-map");
        std::fs::write(&path, [0xff]).unwrap();
        let mut original = BoundedFileReadOriginalV1::new();

        assert!(original.read_once(path.to_str().unwrap(), 64, true, true).is_err());

        let native = original.read.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(native.kind(), std::io::ErrorKind::InvalidData);
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap(), native));
        assert!(original.reader.is_some());
    }

    #[test]
    fn ordinary_adapter_disposes_native_temporary_at_original_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("observation");
        std::fs::write(&path, b"bounded").unwrap();
        let mut ordinary = BoundedFileReadOriginalV1::new();
        let mut selected = BoundedFileReadOriginalV1::new();

        ordinary.read_once(path.to_str().unwrap(), 3, false, false).unwrap();
        selected.read_once(path.to_str().unwrap(), 3, false, true).unwrap();

        assert_eq!(ordinary.bytes, b"boun");
        assert_eq!(ordinary.bytes, selected.bytes);
        assert!(ordinary.reader.is_none());
        assert!(ordinary.read.is_none());
        assert!(selected.reader.is_some());
        assert!(matches!(selected.read, Some(Ok(4))));
    }

    #[test]
    fn missing_file_keeps_first_actual_open_error_across_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing");
        let mut original = BoundedFileReadOriginalV1::new();
        assert!(original.read_once(path.to_str().unwrap(), 64, false, true).is_err());
        let native = original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        let pointer = native as *const std::io::Error;

        std::fs::write(&path, b"later").unwrap();
        assert!(original.read_once(path.to_str().unwrap(), 64, false, true).is_err());

        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap(), pointer));
        assert!(original.reader.is_none());
    }
}
