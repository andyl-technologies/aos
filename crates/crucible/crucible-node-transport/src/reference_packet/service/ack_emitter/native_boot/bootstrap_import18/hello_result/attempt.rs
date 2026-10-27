//! Retains the fresh provider challenge and actual initial SDK Hello result.
//!
//! The entropy destination exists before private receipt. Nonblocking kernel
//! reads preserve partial bytes and scalar errors under the original cut.
//! Completed result ownership precedes terminal admission or SDK validation.

use crate::ProviderError;
use crate::envelope::Nullable;
use crate::handshake::{HelloRequest, HelloResult, Limits};
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18HelloSelectionData;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::Bytes;
use rustix::io::Errno;
use std::mem::size_of;

type EntropyRead = fn(&mut [u8]) -> Result<usize, Errno>;

/// Retains physical entropy, constructor and terminal-result slots.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    cut: Option<OperationalDeadline>,
    row: Option<[usize; 3]>,
    provider_nonce: [u8; 32],
    filled: usize,
    entropy_error: Option<Errno>,
    result: Option<HelloResult>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    EntropyComplete,
    Constructed,
    Complete,
    Failed,
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        stage: _,
        cut: _,
        row: _,
        provider_nonce: _,
        filled: _,
        entropy_error: _,
        result: _,
    } = value;
};

impl Attempt {
    /// Initializes physical output slots without allocation or entropy access.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            cut: None,
            row: None,
            provider_nonce: [0; 32],
            filled: 0,
            entropy_error: None,
            result: None,
        }
    }

    /// Spends this occurrence before enclosing guards or admission callbacks.
    ///
    /// # Errors
    /// Refuses foreign creator custody or a previously spent attempt.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the independently admitted row before entropy or field allocation.
    ///
    /// # Errors
    /// Refuses foreign custody, an incorrect stage or an occupied quote slot.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Acquires a real kernel challenge and retains the complete SDK result.
    ///
    /// The enclosing owner authenticates the original launch, request and roster
    /// around either outcome. Every fallible check precedes fresh field clones;
    /// the completed result is stored before the terminal cut check.
    ///
    /// # Errors
    /// Refuses stale/substituted custody, re-entry, unavailable kernel entropy,
    /// malformed initial inputs or an expired terminal cut.
    pub(super) fn construct_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        selection: &PacketNativeImport18HelloSelectionData,
        request: &HelloRequest,
        limits: Limits,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        let outcome = self.construct_current_data(launch, selection, request, limits, cut);
        let terminal = self.guard(cut);
        if let Err(error) = outcome.and(terminal) {
            self.stage = Stage::Failed;
            return Err(error);
        }
        Ok(())
    }

    fn construct_current_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        selection: &PacketNativeImport18HelloSelectionData,
        request: &HelloRequest,
        limits: Limits,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.result.is_some()
            || request.controller_nonce.as_slice().len() != 32
            || request.session_id != binding.authority.session_id
            || request.resume_session.is_some()
            || !request.extensions.is_empty()
            || limits != launch.limits
        {
            return Err(refused());
        }
        self.fill_current_data(cut, read_os_data as EntropyRead)?;
        self.guard(cut)?;
        self.result = Some(HelloResult {
            version: "CNP/1".to_owned(),
            session_id: binding.authority.session_id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            controller_nonce: request.controller_nonce.clone(),
            provider_nonce: Bytes::new(self.provider_nonce.to_vec()),
            selected_features: selection.0.clone(),
            limits,
            resume_token: Nullable(None),
            provider_identity: launch.selection.provider.clone(),
            resumed_operations: Vec::new(),
        });
        self.stage = Stage::Constructed;
        Ok(())
    }

    fn fill_current_data(
        &mut self,
        cut: OperationalDeadline,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
    ) -> Result<(), ProviderError> {
        while self.filled < self.provider_nonce.len() {
            self.guard(cut)?;
            let outcome = read(&mut self.provider_nonce[self.filled..]);
            // Preserve actual bytes/error facts before every terminal check.
            // Linux reports partial progress as a successful count; EINTR
            // therefore retries only the still-unfilled original suffix.
            match outcome {
                Ok(count) => {
                    if count == 0 || count > self.provider_nonce.len() - self.filled {
                        return Err(refused());
                    }
                    self.filled += count;
                }
                Err(error) => self.entropy_error = Some(error),
            }
            self.guard(cut)?;
            match outcome {
                Ok(_) | Err(Errno::INTR) => {}
                Err(_) => return Err(refused()),
            }
        }
        self.stage = Stage::EntropyComplete;
        Ok(())
    }

    /// Completes after original terminal admission and complete input guards.
    ///
    /// # Errors
    /// Refuses stale custody, incomplete entropy or a missing constructed result.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.guard(self.cut.ok_or_else(refused)?)?;
        if self.stage != Stage::Constructed || self.filled != 32 || self.result.is_none() {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Closes the occurrence without releasing actual initialized outputs.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Lends the completed result under the unchanged original custody and cut.
    ///
    /// This DATA loan neither validates SDK claims nor grants publication.
    ///
    /// # Errors
    /// Refuses stale/substituted custody or incomplete/refused construction.
    pub(in super::super) fn data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<&HelloResult, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.filled != 32 {
            return Err(refused());
        }
        let result = self.result.as_ref().ok_or_else(refused)?;
        if result.provider_nonce.as_slice() != self.provider_nonce {
            return Err(refused());
        }
        Ok(result)
    }

    /// Counts actual surviving result fields without re-encoding either nonce.
    ///
    /// # Errors
    /// Refuses foreign custody, noninitial branches or metadata overflow.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(result) = &self.result {
            let HelloResult {
                version,
                session_id,
                incarnation_id,
                controller_nonce,
                provider_nonce,
                selected_features,
                limits,
                resume_token,
                provider_identity,
                resumed_operations,
            } = result;
            if resume_token.0.is_some() || !resumed_operations.is_empty() {
                return Err(refused());
            }
            observer.observe(version)?;
            observer.observe(session_id)?;
            observer.observe(incarnation_id)?;
            observer.observe(controller_nonce)?;
            observer.observe(provider_nonce)?;
            observer.observe(selected_features)?;
            observer.observe(limits)?;
            observer.observe(resume_token)?;
            observer.observe(provider_identity)?;
            observer.observe(resumed_operations)?;
        }
        requested_metadata_backing_storage_data(&observer.finish())
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn result_fixture_data(&self) -> Option<&HelloResult> {
        self.result.as_ref()
    }

    #[cfg(test)]
    pub(in super::super) fn entropy_filled_fixture_data(&self) -> usize {
        self.filled
    }

    /// Names real entropy, physical output, guard and retained-census controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&PacketNativeImport18HelloSelectionData>()
            + size_of::<&HelloRequest>()
            + size_of::<&HelloResult>()
            + size_of::<&Bytes>() * 2
            + size_of::<Limits>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<EntropyRead>()
            + size_of::<&mut [u8]>()
            + size_of::<Result<usize, Errno>>()
            + size_of::<Option<Errno>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<rustix::rand::GetRandomFlags>()
            + size_of::<usize>() * 4
    }
}

fn read_os_data(destination: &mut [u8]) -> Result<usize, Errno> {
    // Blocking entropy initialization cannot suspend the original startup cut.
    // EAGAIN is a retained refusal; it does not substitute deterministic bytes.
    rustix::rand::getrandom(destination, rustix::rand::GetRandomFlags::NONBLOCK)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 SDK Hello result refused")
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
