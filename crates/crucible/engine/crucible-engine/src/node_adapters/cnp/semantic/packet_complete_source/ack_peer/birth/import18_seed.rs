//! Owns bank-free private inputs beside the Source's original completed Job.
//!
//! This operational seed retains every clone/File/key prefix before later work.
//! It supplies no Birth ready bit, mapping nonce/generation, Recipe, Initial or
//! native member. Canonical banks remain with the original Job/Completion.

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

#[cfg(test)]
#[path = "import18_seed/tests.rs"]
mod tests;
