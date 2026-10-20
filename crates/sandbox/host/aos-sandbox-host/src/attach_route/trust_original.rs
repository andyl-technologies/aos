//! Retains the exact existing Host trust reader's fixed-file native prefix.
//!
//! The selected consumer requires an active genuine HostLaunch borrower. This
//! destination neither opens an arbitrary path nor manufactures trust or a key.

use std::error::Error;

pub(crate) struct HostLaunchTrustOriginalV2 {
    pub(super) bytes: Vec<u8>,
    pub(super) read: Option<std::io::Result<usize>>,
    pub(super) metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(super) file: Option<std::io::Result<std::fs::File>>,
}

impl HostLaunchTrustOriginalV2 {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new(), read: None, metadata: None, file: None }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.file).or_else(|| error(&self.metadata)).or_else(|| error(&self.read))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
