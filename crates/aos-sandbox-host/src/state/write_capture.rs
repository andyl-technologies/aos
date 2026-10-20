//! Keeps the same atomic Host snapshot writer's native prefix through posts.
//!
//! This is inert IO disposition DATA. It creates no Host original, account,
//! accepted request, execution permission or positive completion token. The
//! selected Host owner prepays before constructing and using this destination.

use std::error::Error;

use super::{FileHostStateStore, HostState, canary_capacity::NativeStateReadbackV1, envelope_body_v2};
use crate::{HostError, Result};

/// Retains one exact encoded snapshot, write descriptor and returned outcome.
///
/// Native failures leave the same temporary file and bytes resident. No retry,
/// cleanup unlink or synthetic successful state transition is offered here.
#[doc(hidden)]
#[must_use = "retain the native snapshot prefix through independent posts"]
pub struct HostStateWriteAttemptV2 {
    native: NativeStateReadbackV1,
    encoded: Option<Result<Vec<u8>>>,
    completion: Option<Result<()>>,
    entered: bool,
    origin: Option<super::execution_origin::ExecutionOriginBindingV2>,
}

impl HostStateWriteAttemptV2 {
    /// Constructs empty snapshot custody without allocating a body or doing IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            native: NativeStateReadbackV1::retained_with_root_causes_v2(),
            encoded: None,
            completion: None,
            entered: false,
            origin: None,
        }
    }

    pub(crate) fn argument_pair_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        Self::sequence_demand_v2(2)
    }

    pub(crate) fn sequence_demand_v2(attempts: usize) -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        // All completed envelopes/native files remain resident. The same
        // serial writer has at most one extra body/envelope construction lane
        // and the same current/proposed pure models. These three byte planes
        // are a peak, not one fresh copy for every retained write.
        let memory = attempts.checked_add(3)?.checked_mul(super::MAXIMUM_STATE_BYTES)?
            .checked_add(attempts.checked_mul(super::HEADER_BYTES)?)?
            .checked_add(attempts.checked_mul(2)?.checked_mul(std::mem::size_of::<Self>())?)?;
        let stored = attempts.checked_mul(super::MAXIMUM_STATE_BYTES.checked_add(super::HEADER_BYTES)?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(attempts).ok()?)
            .with(D::StorageBytes, u64::try_from(stored).ok()?)
            .with(D::PublicationStagingBytes, u64::try_from(super::MAXIMUM_STATE_BYTES + super::HEADER_BYTES).ok()?)
            // Every write addresses the same held directory/state.bin/state.next.
            .with(D::MetadataEntries, 3))
    }

    pub(crate) fn commit_execution_origin_once_v2(&mut self, store: &FileHostStateStore,
        state: &HostState, binding: super::execution_origin::ExecutionOriginBindingV2) -> Result<()>
    {
        if self.entered || self.origin.is_some()
            || !state.contains_execution_origin_v2(binding)
        {
            return Err(HostError::Fence("execution origin write has no exact resident row"));
        }
        self.origin = Some(binding);
        self.commit_once(store, state)
    }

    pub(crate) fn committed_origin_v2(&self) -> Result<ExecutionOriginCommitV2<'_>> {
        if !self.is_complete() || self.origin.is_none() {
            return Err(HostError::Fence("execution origin commit is incomplete or unknown"));
        }
        Ok(ExecutionOriginCommitV2 { capture: self })
    }

    pub(super) fn refuse_unsupported(&mut self) -> Result<()> {
        if !self.entered {
            self.entered = true;
            self.completion = Some(Err(HostError::Fence("selected Host snapshot writer is unavailable")));
        }
        Err(HostError::Fence("selected Host snapshot writer is unavailable"))
    }

    pub(super) fn commit_once(&mut self, store: &FileHostStateStore, state: &HostState) -> Result<()> {
        if self.entered {
            return Err(HostError::Fence("selected Host snapshot writer was already entered"));
        }
        self.entered = true;
        self.encoded = Some(encode_selected_snapshot_v2(state));
        let Some(Ok(encoded)) = self.encoded.as_ref() else {
            return Err(HostError::Fence("selected Host snapshot encoding failed"));
        };
        self.completion = Some(store.write_atomic_inner(encoded, Some(&mut self.native)));
        if !self.completion.as_ref().is_some_and(Result::is_ok) {
            return Err(HostError::Fence("selected Host snapshot outcome is unknown"));
        }
        Ok(())
    }

    /// Borrows the first actual encode/native/write refusal without recapture.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.encoded.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
            .or_else(|| self.native.failure_v2())
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|error| error as _))
    }

    /// Reports completion of the actual atomic write, without granting an effect.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.entered && self.completion.as_ref().is_some_and(Result::is_ok)
            && self.failure().is_none()
    }
}

/// Borrows the exact successful native latch write; it carries no account.
pub(crate) struct ExecutionOriginCommitV2<'a> {
    capture: &'a HostStateWriteAttemptV2,
}

impl ExecutionOriginCommitV2<'_> {
    pub(crate) fn binding_v2(&self) -> super::execution_origin::ExecutionOriginBindingV2 {
        // The only constructor checks this exact resident Some slot.
        match self.capture.origin {
            Some(binding) => binding,
            None => std::process::abort(),
        }
    }
}

impl Default for HostStateWriteAttemptV2 {
    fn default() -> Self { Self::new() }
}

// The ordinary Vec-based StateWire encoder keeps its original ownership/drop
// order. The selected writer uses the same serde schema and envelope while
// borrowing the resident tables, avoiding a second full snapshot clone.
struct Values<'a, K, V>(&'a std::collections::BTreeMap<K, V>);

impl<K, V: serde::Serialize> serde::Serialize for Values<'_, K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0.values() { sequence.serialize_element(value)?; }
        sequence.end()
    }
}

struct Observations<'a>(&'a std::collections::BTreeMap<[u8; 16], u64>);

impl serde::Serialize for Observations<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (incarnation_id, sequence_number) in self.0 {
            sequence.serialize_element(&super::ObservationSequence {
                incarnation_id: *incarnation_id, sequence: *sequence_number,
            })?;
        }
        sequence.end()
    }
}

struct BorrowedSnapshot<'a>(&'a HostState);

impl serde::Serialize for BorrowedSnapshot<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let state = self.0;
        super::serialize_state_wire_v2(serializer, &Values(&state.fences), &Values(&state.requests),
            &Observations(&state.observation_sequences), &Values(&state.scope_replays),
            &Values(&state.scope_handles), &Values(&state.existing_output_observations),
            &Values(&state.fuse_worker_launches), &state.execution_origins,
            [!state.scope_replays.is_empty(), !state.scope_handles.is_empty(),
                !state.existing_output_observations.is_empty(), !state.fuse_worker_launches.is_empty(),
                !state.execution_origins.is_empty()])
    }
}

struct BoundedBody(Vec<u8>);

impl std::io::Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > super::MAXIMUM_STATE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("encoded host state exceeds sixteen MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn encode_selected_snapshot_v2(state: &HostState) -> Result<Vec<u8>> {
    let mut body = BoundedBody(Vec::new());
    body.0.try_reserve_exact(super::MAXIMUM_STATE_BYTES)
        .map_err(|error| HostError::State(error.to_string()))?;
    serde_json::to_writer(&mut body, &BorrowedSnapshot(state))
        .map_err(|error| HostError::State(error.to_string()))?;
    envelope_body_v2(body.0)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::state::HostStateStore as _;

    #[test]
    fn retained_and_ordinary_writers_emit_the_same_snapshot_bytes() {
        let retained_root = tempfile::tempdir().unwrap();
        let ordinary_root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(retained_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(ordinary_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = FileHostStateStore::open_exclusive(retained_root.path()).unwrap();
        let ordinary = FileHostStateStore::open_exclusive(ordinary_root.path()).unwrap();
        let state = HostState::default();
        let mut capture = HostStateWriteAttemptV2::new();

        retained.commit_retaining_v2(&state, &mut capture).unwrap();
        ordinary.commit(&state).unwrap();

        assert!(capture.is_complete());
        assert!(capture.native.file().is_ok());
        assert_eq!(capture.encoded.as_ref().unwrap().as_ref().unwrap(),
            &super::super::encode_envelope(&HostState::default()).unwrap());
        assert_eq!(std::fs::read(retained_root.path().join("state.bin")).unwrap(),
            std::fs::read(ordinary_root.path().join("state.bin")).unwrap());
    }

    #[test]
    fn serial_launch_writes_keep_every_distinct_native_file() {
        use std::os::fd::AsFd as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open_exclusive(root.path()).unwrap();
        let mut captures: [HostStateWriteAttemptV2; 24] =
            std::array::from_fn(|_| HostStateWriteAttemptV2::new());

        for capture in &mut captures {
            store.commit_retaining_v2(&HostState::default(), capture).unwrap();
        }

        let mut files = std::collections::BTreeSet::new();
        for (index, capture) in captures.iter().enumerate() {
            assert!(capture.is_complete());
            let metadata = rustix::fs::fstat(capture.native.file().unwrap().as_fd()).unwrap();
            assert!(files.insert((metadata.st_dev, metadata.st_ino)));
            // Replaced envelopes stay open even after their names disappear.
            assert_eq!(metadata.st_nlink, if index == captures.len() - 1 { 1 } else { 0 });
        }
        let demand = HostStateWriteAttemptV2::sequence_demand_v2(captures.len()).unwrap();
        assert_eq!(demand.get(aos_sandbox_core::ResourceDimension::OpenFiles), files.len() as u64);
        assert!(!root.path().join("state.next").exists());
    }

    #[test]
    fn a_prior_temporary_is_retained_as_cold_debt_and_retry_keeps_the_first_cause() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open_exclusive(root.path()).unwrap();
        let temporary = root.path().join("state.next");
        std::fs::write(&temporary, b"earlier unknown write").unwrap();
        let mut capture = HostStateWriteAttemptV2::new();

        assert!(store.commit_retaining_v2(&HostState::default(), &mut capture).is_err());
        let first = capture.failure().unwrap() as *const dyn Error;
        let native = capture.failure().unwrap().source().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap();
        assert_eq!(*native, rustix::io::Errno::EXIST);
        assert!(store.commit_retaining_v2(&HostState::default(), &mut capture).is_err());

        assert!(std::ptr::eq(capture.failure().unwrap(), first));
        assert!(!capture.is_complete());
        assert!(matches!(capture.encoded, Some(Ok(_))));
        assert_eq!(std::fs::read(temporary).unwrap(), b"earlier unknown write");
    }

    #[test]
    fn a_missing_root_name_keeps_the_actual_io_cause_and_encoded_input() {
        let parent = tempfile::tempdir().unwrap();
        let named = parent.path().join("named");
        std::fs::create_dir(&named).unwrap();
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open_exclusive(&named).unwrap();
        std::fs::rename(&named, parent.path().join("held")).unwrap();
        let mut capture = HostStateWriteAttemptV2::new();

        assert!(store.commit_retaining_v2(&HostState::default(), &mut capture).is_err());

        let actual = capture.failure().unwrap().source().unwrap()
            .downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(actual.kind(), std::io::ErrorKind::NotFound);
        assert!(matches!(capture.encoded, Some(Ok(_))));
        assert!(capture.native.file().is_err());
        assert!(!capture.is_complete());
    }
}
