//! Retains a source-born key and one private boot transfer before Child exists.
//!
//! The owning Source creates this holder only after its complete selected birth
//! tuple is fixed. Its boot loan permits preparation, never semantic admission,
//! native execution, capture or restoration. A later original post-Hello
//! association must authenticate the actual SDK writer and native read.

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    thread::ThreadId,
};

use crucible_node_contract::{ContentRef, Id, Validate};

use super::{OperationFailure, refused};

#[path = "birth/history.rs"]
mod history;

// Batch the same complete-byte check without retaining a whole executable.
// Every defining scratch quote below and in the startup children uses this bank.
const HOST_EXECUTABLE_STREAM_BYTES: usize = 256 * 1024;

#[path = "host_startup.rs"]
mod host_startup;
pub use host_startup::PacketCompleteOriginalHostSdk;

#[path = "native_startup.rs"]
mod native_startup;
#[path = "native_wire.rs"]
mod native_wire;
#[path = "report_startup.rs"]
mod report_startup;
pub use native_wire::{
    PacketCompleteNativeImport18StartupWire, PacketCompleteNativeRestoredSettledStartupWire,
    PacketCompleteNativeRestoredSuffixStartupWire, PacketCompleteNativeStartupWire,
};

/// Borrows one original source-owned private boot material transfer.
///
/// This loan has no public constructor, Clone or serialization implementation.
/// Its caller writes the borrowed material only into the same supervised
/// private child launch. A copied key or decoded birth value cannot issue a
/// source association or native admission marker.
pub struct PacketCompleteAckPeerBootMaterial<'a> {
    source: &'a super::super::PacketCompleteSemanticSource,
    original: std::cell::Ref<'a, OriginalAckPeerBirth>,
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalAckPeerBirth {
    process: u32,
    thread: ThreadId,
    key: [u8; 32],
    birth_id: [u8; 32],
    host_executable: ContentRef,
    host_file: File,
    host_revision: HostRevision,
    private_launch: Id,
    source_birth: Vec<u8>,
    expected_host_registration: Vec<u8>,
    boot_started: std::cell::Cell<bool>,
    ready: bool,
    failed: bool,
    report_startup_required: bool,
    report_startup: Option<report_startup::OriginalReportStartupFinalization>,
    native_startup: Option<native_startup::OriginalNativeStartupFinalization>,
    native_import18: Option<native_startup::OriginalNativeImport18Finalization>,
    // The link is inline and weak. Its one shared allocation is precharged by
    // Core before all three links are attached; members keep that owner alive.
    native_host_finalization: Option<crate::node_admission::OriginalHostFinalizationSource>,
    host_startup: std::cell::RefCell<Option<host_startup::OriginalHostStartupMarker>>,
}

pub(super) struct OriginalAckPeerInputs<'a> {
    pub(super) key: &'a [u8; 32],
    pub(super) birth_id: &'a [u8; 32],
    pub(super) host_executable: &'a ContentRef,
    pub(super) private_launch: &'a Id,
    pub(super) source_birth: &'a [u8],
    pub(super) host_registration: &'a [u8],
}

#[derive(PartialEq, Eq)]
struct HostRevision {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl HostRevision {
    fn read(file: &File) -> Result<Self, OperationFailure> {
        let metadata = file
            .metadata()
            .map_err(|_| refused("original ACK host executable metadata is unavailable"))?;
        if !metadata.is_file() {
            return Err(refused(
                "original ACK host executable is not a regular file",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

impl OriginalAckPeerBirth {
    // This grants only a borrowed immutable Id. The original Birth remains
    // shared-loaned and unstarted throughout the caller's identity calculation.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn import18_private_launch_data(
        &self,
    ) -> Result<&Id, crate::node_contract::RuntimeError> {
        self.authenticate_unstarted_storage_phase_with_error::<crate::node_contract::RuntimeError>(
        )?;
        Ok(&self.private_launch)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_unstarted_storage_phase(
        &self,
    ) -> Result<(), OperationFailure> {
        self.authenticate_unstarted_storage_phase_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_unstarted_storage_phase_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<(), E> {
        if self.process != std::process::id() {
            return Err(E::origin("original ACK birth belongs to another process"));
        }
        if self.thread != std::thread::current().id() {
            return Err(E::origin("original ACK birth belongs to another thread"));
        }
        if !self.ready || self.failed || self.boot_started.get() {
            return Err(E::refused(
                "original private birth is not ready and unstarted",
            ));
        }
        Ok(())
    }

    // Only the original Source's selected-birth constructor calls this function.
    // The two full canonical input banks come from that same Source and must be
    // reserved and charged before this transfer. They are not public permits.
    pub(super) fn reserve_into(
        host_executable: &ContentRef,
        private_launch: &Id,
        source_birth: &mut Option<Vec<u8>>,
        expected_host_registration: &mut Option<Vec<u8>>,
        completed: &mut Option<Self>,
        report_startup_required: bool,
    ) -> Result<(), OperationFailure> {
        if completed.is_some() {
            return Err(refused("original ACK birth slot is occupied"));
        }
        host_executable
            .validate()
            .map_err(|_| refused("original ACK host executable reference is invalid"))?;
        private_launch
            .validate()
            .map_err(|_| refused("original ACK private launch identity is invalid"))?;
        if source_birth.as_ref().is_none_or(Vec::is_empty)
            || expected_host_registration
                .as_ref()
                .is_none_or(Vec::is_empty)
        {
            return Err(refused("original ACK full birth inputs are absent"));
        }

        let host_file = File::open("/proc/self/exe")
            .map_err(|_| refused("original ACK host executable cannot be retained"))?;
        let host_revision = HostRevision::read(&host_file)?;
        *completed = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            key: [0; 32],
            birth_id: [0; 32],
            host_executable: host_executable.clone(),
            host_file,
            host_revision,
            private_launch: private_launch.clone(),
            source_birth: Vec::new(),
            expected_host_registration: Vec::new(),
            boot_started: std::cell::Cell::new(false),
            ready: false,
            failed: false,
            report_startup_required,
            report_startup: None,
            native_startup: None,
            native_import18: None,
            native_host_finalization: None,
            host_startup: std::cell::RefCell::new(None),
        });
        let original = completed
            .as_mut()
            .ok_or_else(|| refused("original ACK birth slot absent"))?;
        match (source_birth.take(), expected_host_registration.take()) {
            (Some(source), Some(registration)) => {
                original.source_birth = source;
                original.expected_host_registration = registration;
            }
            (source, registration) => {
                *source_birth = source;
                *expected_host_registration = registration;
                original.failed = true;
                return Err(refused("original ACK birth input banks changed"));
            }
        }

        // The result holder precedes entropy and complete executable checks.
        // Failure keeps the same full input banks, file and even partial key.
        let result = (|| {
            original.authenticate_original()?;
            File::open("/dev/urandom")
                .and_then(|mut random| random.read_exact(&mut original.key))
                .map_err(|_| refused("original ACK birth key could not be filled"))?;
            original.birth_id =
                blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &original.key);
            original.authenticate_original()?;
            original.ready = true;
            Ok(())
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() {
            return Err(refused("original ACK birth belongs to another process"));
        }
        if self.thread != std::thread::current().id() {
            return Err(refused("original ACK birth belongs to another thread"));
        }
        Ok(())
    }

    pub(super) fn authenticate_original(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let current = File::open("/proc/self/exe")
            .map_err(|_| refused("original ACK current executable is unavailable"))?;
        if HostRevision::read(&self.host_file)? != self.host_revision
            || HostRevision::read(&current)? != self.host_revision
            || self.host_revision.length != self.host_executable.length.get()
        {
            return Err(refused("original ACK host executable identity changed"));
        }

        // This streams the normative CNP content identity with fixed scratch.
        // The header is exactly canonical::hash("cnp.blob.v1", complete_bytes),
        // not an invented MAC construction or a partial executable measurement.
        let domain = b"cnp.blob.v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        hasher.update(&(domain.len() as u32).to_be_bytes());
        hasher.update(domain);
        hasher.update(&self.host_revision.length.to_be_bytes());
        let mut scratch = [0; HOST_EXECUTABLE_STREAM_BYTES];
        let mut offset = 0;
        while offset < self.host_revision.length {
            let remaining = self.host_revision.length - offset;
            let length = usize::try_from(remaining.min(scratch.len() as u64))
                .map_err(|_| refused("original ACK executable extent overflow"))?;
            self.host_file
                .read_exact_at(&mut scratch[..length], offset)
                .map_err(|_| refused("original ACK executable measurement failed"))?;
            hasher.update(&scratch[..length]);
            offset += length as u64;
        }
        let digest = hasher.finalize().to_hex();
        if self.host_executable.hash.algorithm != "blake3-256"
            || self.host_executable.hash.domain != "cnp.blob.v1"
            || self.host_executable.hash.digest != digest.as_str()
            || self.host_executable.media_type != "application/octet-stream"
            || HostRevision::read(&self.host_file)? != self.host_revision
            || HostRevision::read(&current)? != self.host_revision
        {
            return Err(refused("original ACK complete host executable changed"));
        }
        self.ensure_origin()
    }

    pub(super) fn original_post_hello_inputs(
        &self,
    ) -> Result<OriginalAckPeerInputs<'_>, OperationFailure> {
        self.authenticate_original()?;
        if !self.ready || self.failed || !self.boot_started.get() {
            return Err(refused(
                "ACK original private boot has not completed preparation",
            ));
        }
        Ok(OriginalAckPeerInputs {
            key: &self.key,
            birth_id: &self.birth_id,
            host_executable: &self.host_executable,
            private_launch: &self.private_launch,
            source_birth: &self.source_birth,
            host_registration: &self.expected_host_registration,
        })
    }

    pub(super) fn begin_private_boot(&self) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if !self.ready || self.failed {
            return Err(refused("original ACK birth is incomplete or refused"));
        }
        if self.boot_started.get() {
            return Err(refused("original ACK private boot was already started"));
        }
        self.boot_started.set(true);
        Ok(())
    }
}

impl<'a> PacketCompleteAckPeerBootMaterial<'a> {
    pub(in crate::node_adapters::cnp::semantic) fn original_native_startup_authentication_scratch_data()
    -> usize {
        use std::mem::size_of;
        // The exact same material uses its retained file and fixed stream bank.
        // File-open conversion is the pinned small-C-string stack path.
        super::super::PacketCompleteSemanticSource::original_native_host_barrier_authentication_scratch_data()
            + HOST_EXECUTABLE_STREAM_BYTES
            + size_of::<blake3::Hasher>()
            + size_of::<File>()
            + 2 * size_of::<std::fs::Metadata>()
            + 3 * size_of::<HostRevision>()
            + size_of::<blake3::Hash>()
            + 64
            + 384
            + size_of::<std::io::Error>()
            + size_of::<OperationFailure>()
    }

    pub(super) fn from_original(
        source: &'a super::super::PacketCompleteSemanticSource,
        original: std::cell::Ref<'a, OriginalAckPeerBirth>,
    ) -> Self {
        Self { source, original }
    }

    fn authenticate_startup_member(&self) -> Result<(), OperationFailure> {
        self.original
            .authenticate_report_startup_before_boot(self.source)?;
        self.original
            .authenticate_native_startup_before_boot(self.source)
    }

    /// Rechecks the actual original creator and complete measured executable.
    ///
    /// # Errors
    /// Refuses an expired selected startup member, changed creator/thread, file
    /// identity or complete executable bytes.
    pub fn authenticate_original(&self) -> Result<(), OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.authenticate_original()
    }

    /// Borrows the private key solely for the original supervised boot writer.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn private_key(&self) -> Result<&[u8; 32], OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.key)
    }

    /// Borrows the original birth identity without issuing peer admission.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn birth_id(&self) -> Result<&[u8; 32], OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.birth_id)
    }

    /// Borrows the actual measured host executable reference.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn host_executable(&self) -> Result<&ContentRef, OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.host_executable)
    }

    /// Borrows the exact private launch identity.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn private_launch(&self) -> Result<&Id, OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.private_launch)
    }

    /// Borrows the full original source birth binding bytes.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn source_birth_bytes(&self) -> Result<&[u8], OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.source_birth)
    }

    /// Borrows the complete expected host registration association bytes.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or an expired selected startup member.
    pub fn expected_host_registration_bytes(&self) -> Result<&[u8], OperationFailure> {
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        Ok(&self.original.expected_host_registration)
    }
}

impl OriginalAckPeerBirth {
    pub(in crate::node_adapters::cnp::semantic) fn retained_heap_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(E::refused("retained ACK birth foreign origin"));
        }
        // File, revision, private key/birth arrays and scalar states are inline
        // in the Source allocation. No executable read, hash or cut renewal.
        let reference =
            crate::node_contract::NodeRuntime::capture_reference_storage(&self.host_executable)
                .map_err(E::runtime)?;
        super::super::retained_values::sum_with_error::<E, _>(
            [
                reference,
                self.host_startup
                    .try_borrow()
                    .map_err(|_| E::refused("original host constructor marker busy"))?
                    .as_ref()
                    .map(|state| state.retained_storage_data().map_err(E::runtime))
                    .transpose()?
                    .unwrap_or(0),
                self.private_launch.allocated_capacity(),
                self.source_birth.capacity(),
                self.expected_host_registration.capacity(),
                self.report_startup
                    .as_ref()
                    .map(|state| state.retained_storage_data_with_error::<E>(maximum))
                    .transpose()?
                    .unwrap_or(0),
                self.native_startup
                    .as_ref()
                    .map(|state| state.retained_storage_data_with_error::<E>(maximum))
                    .transpose()?
                    .unwrap_or(0),
                self.native_import18
                    .as_ref()
                    .map(|state| state.retained_storage_data_with_error::<E>(maximum))
                    .transpose()?
                    .unwrap_or(0),
            ],
            maximum,
        )
    }
}

impl OriginalAckPeerBirth {
    /// Checks the original birth phase without exposing its borrowed inputs.
    ///
    /// The descriptor observer needs only this authentication result. The
    /// original input bundle remains within the ACK peer module and its children.
    ///
    /// # Errors
    /// Refuses the same foreign process/thread, unready, failed or unstarted
    /// original birth rejected by the underlying input validator.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_initial_lifecycle_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.original_initial_lifecycle_inputs_data().map(|_| ())
    }

    pub(super) fn original_initial_lifecycle_inputs_data(
        &self,
    ) -> Result<OriginalAckPeerInputs<'_>, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !self.ready || self.failed || !self.boot_started.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(OriginalAckPeerInputs {
            key: &self.key,
            birth_id: &self.birth_id,
            host_executable: &self.host_executable,
            private_launch: &self.private_launch,
            source_birth: &self.source_birth,
            host_registration: &self.expected_host_registration,
        })
    }
}

pub(crate) use host_startup::{
    PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote,
};

#[path = "birth/settled17.rs"]
mod settled17;

#[path = "birth/initial15_normalization.rs"]
mod initial15_normalization;

#[path = "birth/import18_construction.rs"]
pub(super) mod import18_construction;
