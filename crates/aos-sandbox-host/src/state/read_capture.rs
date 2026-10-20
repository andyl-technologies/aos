//! Retains the existing fixed Host snapshot reader through original posts.
//!
//! Ordinary loading still uses its original local disposition. The selected
//! route parks the same input File/bytes and original returned error before a
//! positive state can move to the sole Host broker. No path, decoder, account,
//! accepted request or authority factory is introduced here.

use std::error::Error;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use super::{HostState, FileHostStateStore, canary_capacity::NativeStateReadbackV1};
use crate::{HostError, Result};

/// Holds one fixed native snapshot read and its actual outcome without retry.
#[doc(hidden)]
#[must_use = "keep the original snapshot prefix through independent posts"]
pub struct HostStateReadAttemptV2 {
    native: NativeStateReadbackV1,
    result: Option<Result<HostState>>,
    entered: bool,
    taken: bool,
}

impl HostStateReadAttemptV2 {
    /// Installs empty native slots without opening or allocating input bytes.
    #[must_use]
    pub fn new() -> Self {
        Self { native: NativeStateReadbackV1::retained_with_root_causes_v2(),
            result: None, entered: false, taken: false }
    }

    pub(crate) fn receiving_demand_v2() -> Option<ResourceVector> {
        // Dominant bounded input/model/canonical-byte lanes use the existing
        // sixteen-MiB format limit. Decoder/allocator overhead remains subject
        // to the same independently installed Host memory/kernel backstop;
        // this is not a claim that JSON bytes equal exact heap allocation.
        let memory = (3 * super::MAXIMUM_STATE_BYTES).checked_add(super::HEADER_BYTES)?
            .checked_add(2 * std::mem::size_of::<Self>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1).with(D::MetadataEntries, 2))
    }

    pub(super) fn refuse_unsupported_v2(&mut self) -> Result<HostState> {
        if !self.entered {
            self.entered = true;
            self.result = Some(Err(HostError::Fence("selected Host snapshot reader is unavailable")));
        }
        Err(HostError::Fence("selected Host snapshot reader is unavailable"))
    }

    pub(crate) fn load_once_v2(&mut self, store: &FileHostStateStore) -> Result<HostState> {
        if self.entered {
            return Err(HostError::Fence("original Host snapshot reader was already entered"));
        }
        self.entered = true;
        self.result = Some(store.load_into(&mut self.native));
        if self.failure().is_some() {
            return Err(HostError::Fence("original Host snapshot read failed"));
        }
        match self.result.take() {
            Some(Ok(state)) => { self.taken = true; Ok(state) }
            _ => Err(HostError::Fence("original Host snapshot read has no positive state")),
        }
    }

    /// Borrows the actual first root/open/read/parse error without recapture.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure_v2()
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }
}

impl Default for HostStateReadAttemptV2 {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use super::*;
    use crate::state::HostStateStore as _;

    #[test]
    fn malformed_snapshot_keeps_the_same_file_input_and_first_returned_error() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open_exclusive(root.path()).unwrap();
        let path = root.path().join("state.bin");
        let bytes = vec![0_u8; super::super::HEADER_BYTES];
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = HostStateReadAttemptV2::new();

        assert!(read.load_once_v2(&store).is_err());
        let first = read.failure().unwrap() as *const dyn Error;
        assert!(read.native.file().is_ok());
        assert_eq!(read.native.bytes(), bytes);
        assert!(read.load_once_v2(&store).is_err());
        assert!(std::ptr::eq(read.failure().unwrap(), first));
        assert!(!read.taken);
    }

    #[test]
    fn selected_read_moves_the_same_positive_state_and_keeps_native_custody() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open_exclusive(root.path()).unwrap();
        store.commit(&HostState::default()).unwrap();
        let mut read = HostStateReadAttemptV2::new();

        let actual = read.load_once_v2(&store).unwrap();

        assert_eq!(actual, store.load().unwrap());
        assert!(read.native.file().is_ok());
        assert!(read.taken);
        assert!(read.failure().is_none());
        assert!(read.load_once_v2(&store).is_err());
    }
}
