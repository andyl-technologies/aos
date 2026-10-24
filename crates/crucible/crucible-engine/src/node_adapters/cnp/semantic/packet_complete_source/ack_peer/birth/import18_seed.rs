//! Owns bank-free private inputs beside the Source's original completed Job.
//!
//! This operational seed retains every clone/File/key prefix before later work.
//! Its once-only transfer assembles private boot custody after the Source has
//! separately funded startup-bank copies. It supplies no mapping generation,
//! Recipe, Initial or native member. Original banks remain with Completion.

use super::*;
use crate::node_adapters::cnp::semantic::source::{
    private_birth_clone_construction_data, private_birth_clone_counter_scratch_data,
};
use crate::node_contract::RuntimeError;
use std::mem::size_of;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalImport18PrivateSeed
{
    host: Option<ContentRef>,
    private_launch: Option<Id>,
    file: Option<File>,
    revision: Option<HostRevision>,
    key: [u8; 32],
    birth_id: Option<[u8; 32]>,
    started: bool,
    complete: bool,
    failure: Option<RuntimeError>,
    process: u32,
    thread: ThreadId,
}

impl OriginalImport18PrivateSeed {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn empty() -> Self {
        Self {
            host: None,
            private_launch: None,
            file: None,
            revision: None,
            key: [0; 32],
            birth_id: None,
            started: false,
            complete: false,
            failure: None,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn prepare(
        &mut self,
        host: &ContentRef,
        private_launch: &Id,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.started = true;
        let result = self.construct(host, private_launch);
        if let Err(error) = result {
            if self.failure.is_none() {
                self.failure = Some(error);
            }
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.complete = true;
        Ok(())
    }

    fn construct(&mut self, host: &ContentRef, private_launch: &Id) -> Result<(), RuntimeError> {
        self.host = Some(host.clone());
        self.private_launch = Some(private_launch.clone());
        self.file = Some(File::open("/proc/self/exe").map_err(|_| RuntimeError::OwnerUnavailable)?);
        self.revision = Some(private_identity::read_revision(
            self.file.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
        )?);
        self.authenticate_file()?;
        private_identity::fill_private_key(&mut self.key)?;
        self.birth_id = Some(blake3::derive_key(
            "source-owned.packet-canonical-ack-birth/5",
            &self.key,
        ));
        self.authenticate_file()
    }

    fn authenticate_file(&self) -> Result<(), RuntimeError> {
        private_identity::authenticate_private_file(
            self.process,
            self.thread,
            self.host.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            self.file.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            self.revision
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate(
        &self,
    ) -> Result<(), RuntimeError> {
        if !self.started || !self.complete || self.failure.is_some() || self.birth_id.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.authenticate_file()
    }

    /// Moves original private inputs into a retained, initially closed Birth.
    ///
    /// The Source has already authenticated the completed job and admitted both
    /// startup banks. No entropy or executable clone is repeated here. Installing
    /// the destination before the final File check retains every moved child if
    /// that check fails. Native startup gates remain closed.
    ///
    /// # Errors
    /// Refuses an occupied destination, incomplete seed, missing bank or changed
    /// executable identity, preserving every original child on either side.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retain_birth_into(
        &mut self,
        source: &mut Vec<u8>,
        registration: &mut Vec<u8>,
        completed: &mut Option<OriginalAckPeerBirth>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.authenticate()?;
        if source.is_empty() || registration.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let children = (
            self.host.take(),
            self.private_launch.take(),
            self.file.take(),
            self.revision.take(),
            self.birth_id.take(),
        );
        let (host_executable, private_launch, host_file, host_revision, birth_id) = match children {
            (Some(host), Some(launch), Some(file), Some(revision), Some(birth_id)) => {
                (host, launch, file, revision, birth_id)
            }
            (host, launch, file, revision, birth_id) => {
                self.host = host;
                self.private_launch = launch;
                self.file = file;
                self.revision = revision;
                self.birth_id = birth_id;
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        self.complete = false;
        *completed = Some(OriginalAckPeerBirth {
            process: self.process,
            thread: self.thread,
            key: std::mem::take(&mut self.key),
            birth_id,
            host_executable,
            host_file,
            host_revision,
            private_launch,
            source_birth: std::mem::take(source),
            expected_host_registration: std::mem::take(registration),
            boot_started: std::cell::Cell::new(false),
            ready: false,
            failed: true,
            report_startup_required: true,
            report_startup: None,
            native_startup: None,
            native_import18: None,
            native_host_finalization: None,
            host_startup: std::cell::RefCell::new(None),
        });
        let birth = completed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        private_identity::authenticate_private_file(
            birth.process,
            birth.thread,
            &birth.host_executable,
            &birth.host_file,
            &birth.host_revision,
        )?;
        birth.ready = true;
        birth.failed = false;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn birth_transfer_counter_scratch_data()
    -> usize {
        HOST_EXECUTABLE_STREAM_BYTES
            + private_identity::delegation_controls()
            + size_of::<&mut Self>()
            + size_of::<&mut Vec<u8>>() * 2
            + size_of::<&mut Option<OriginalAckPeerBirth>>()
            + size_of::<&mut OriginalAckPeerBirth>()
            + size_of::<OriginalAckPeerBirth>()
            + size_of::<Option<OriginalAckPeerBirth>>()
            + size_of::<(
                Option<ContentRef>,
                Option<Id>,
                Option<File>,
                Option<HostRevision>,
                Option<[u8; 32]>,
            )>()
            + size_of::<(ContentRef, Id, File, HostRevision, [u8; 32])>()
            + size_of::<[u8; 32]>()
            + size_of::<Result<(), RuntimeError>>()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn known_backing(
        &self,
    ) -> Result<usize, RuntimeError> {
        let mut bytes = self
            .private_launch
            .as_ref()
            .map_or(0, Id::allocated_capacity);
        if let Some(host) = &self.host {
            for text in [
                &host.hash.algorithm,
                &host.hash.domain,
                &host.hash.digest,
                &host.media_type,
            ] {
                bytes = bytes
                    .checked_add(text.capacity())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        if let Some(RuntimeError::SchedulerRefused(message)) = &self.failure {
            bytes = bytes
                .checked_add(message.capacity())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(bytes)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn construction_data(
        host: &ContentRef,
        private_launch: &Id,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let (clone_temporary, clone_controls) =
            private_birth_clone_construction_data(host, private_launch, maximum)?;
        let mut retained = private_launch.as_str().len();
        for text in [
            &host.hash.algorithm,
            &host.hash.domain,
            &host.hash.digest,
            &host.media_type,
        ] {
            retained = retained
                .checked_add(text.len())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let temporary = retained
            .checked_add(clone_temporary)
            .and_then(|sum| sum.checked_add(size_of::<Self>()))
            .and_then(|sum| sum.checked_add(size_of::<Option<Self>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::counter_scratch_data()
            .checked_add(clone_controls)
            .ok_or(RuntimeError::ResourceLimit)?;
        if [retained, temporary, scratch]
            .into_iter()
            .any(|bytes| bytes > maximum)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok([retained, temporary, scratch])
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn counter_scratch_data()
    -> usize {
        // Actual clone/stream/header workspace only. Opaque std/IO runtime and
        // kernel descriptors stay in the separate original deployment domain.
        HOST_EXECUTABLE_STREAM_BYTES
            + private_identity::delegation_controls()
            + private_birth_clone_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&ContentRef>()
            + size_of::<&Id>()
            + size_of::<Option<ContentRef>>()
            + size_of::<Option<Id>>()
            + size_of::<Option<File>>()
            + size_of::<Option<HostRevision>>()
            + size_of::<&File>() * 2
            + size_of::<HostRevision>() * 3
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>() * 3
            + size_of::<usize>() * 4
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>() * 2
    }
}

impl OriginalAckPeerBirth {
    /// Allows a census of complete or failed construction before startup effects.
    ///
    /// # Errors
    /// Refuses foreign creation custody, started boot or any startup finalizer.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_isolated_construction_storage_data(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.boot_started.get()
            || !self.report_startup_required
            || self.report_startup.is_some()
            || self.native_startup.is_some()
            || self.native_import18.is_some()
            || self.native_host_finalization.is_some()
            || self
                .host_startup
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Joins the unchanged accepted banks to the same complete private Birth.
    ///
    /// # Errors
    /// Refuses failed, started, finalized, changed or foreign private custody.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_isolated_declaration_banks_data(
        &self,
        private_launch: &Id,
        host: &ContentRef,
        source: &[u8],
        registration: &[u8],
    ) -> Result<(), RuntimeError> {
        self.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
        self.authenticate_isolated_construction_storage_data()?;
        if &self.private_launch != private_launch
            || &self.host_executable != host
            || self.source_birth != source
            || self.expected_host_registration != registration
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        private_identity::authenticate_private_file(
            self.process,
            self.thread,
            &self.host_executable,
            &self.host_file,
            &self.host_revision,
        )
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn isolated_declaration_counter_scratch_data()
    -> usize {
        private_identity::authentication_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Id>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8]>() * 2
            + size_of::<bool>()
            + size_of::<Result<(), RuntimeError>>() * 2
    }

    /// Revokes private boot without dropping the original key, File or banks.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn revoke_isolated_construction(
        &mut self,
    ) {
        self.ready = false;
        self.failed = true;
    }
}

#[cfg(test)]
#[path = "import18_seed/tests.rs"]
mod tests;
