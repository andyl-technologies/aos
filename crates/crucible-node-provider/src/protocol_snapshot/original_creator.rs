//! Borrows original creator data without reconstructing a process/thread owner.
//!
//! The pinned implementation's actual ThreadId debug spelling is historical
//! data only. An archive reader cannot turn it into a live creator identity.

use super::ProtocolCaptureOwner;
use crate::ProviderError;
use serde::Serialize;

pub(crate) struct OriginalProtocolCreatorView<'a>(&'a ProtocolCaptureOwner);

impl ProtocolCaptureOwner {
    pub(crate) fn original_creator_view(
        &self,
    ) -> Result<OriginalProtocolCreatorView<'_>, ProviderError> {
        self.ensure_current()?;
        Ok(OriginalProtocolCreatorView(self))
    }
}

impl Serialize for OriginalProtocolCreatorView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        self.0.ensure_current().map_err(serde::ser::Error::custom)?;
        struct ThreadText {
            bytes: [u8; 64],
            used: usize,
        }
        impl std::fmt::Write for ThreadText {
            fn write_str(&mut self, text: &str) -> std::fmt::Result {
                let end = self
                    .used
                    .checked_add(text.len())
                    .filter(|n| *n <= self.bytes.len())
                    .ok_or(std::fmt::Error)?;
                self.bytes[self.used..end].copy_from_slice(text.as_bytes());
                self.used = end;
                Ok(())
            }
        }
        let ProtocolCaptureOwner { pid, thread } = self.0;
        let mut text = ThreadText {
            bytes: [0; 64],
            used: 0,
        };
        write!(&mut text, "{thread:?}").map_err(serde::ser::Error::custom)?;
        let thread =
            std::str::from_utf8(&text.bytes[..text.used]).map_err(serde::ser::Error::custom)?;
        (
            "source-private.original-creator-rust-thread/12",
            pid,
            thread,
        )
            .serialize(serializer)
    }
}
