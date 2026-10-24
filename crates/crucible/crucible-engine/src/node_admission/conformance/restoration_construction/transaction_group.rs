//! Retains the exact original tickets and assigned IDs across same-node dispatch.
//!
//! The installed window stores this fixed owner before moving any original out
//! of the registered capsule. Each OnceCell is written at most once. Partial
//! transfer, refusal and unwinding keep all moved tickets/IDs in this root;
//! neither a target nor a whole-holder requery reconstructs them from labels.

use super::*;
use std::{cell::OnceCell, mem::size_of, thread::ThreadId};

pub(super) struct OriginalRestorationTransactionGroup {
    process: u32,
    thread: ThreadId,
    archive: CompleteOriginalRestorationSource,
    tickets: [OnceCell<CompleteOriginalNativeTicket>; 3],
    prepare_ids: OnceCell<[Id; 3]>,
    commit_ids: OnceCell<[Id; 3]>,
    completed: std::cell::Cell<bool>,
}

impl OriginalRestorationTransactionGroup {
    pub(super) fn retain_originals_into(
        window: &super::window::CompleteOriginalRestorationWindow,
        archive: &CompleteOriginalRestorationSource,
        tickets: &mut [Option<CompleteOriginalNativeTicket>; 3],
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
        output: &mut Option<Rc<Self>>,
    ) -> Result<(), RuntimeError> {
        if output.is_some()
            || tickets.iter().any(Option::is_none)
            || prepare_ids.is_none()
            || commit_ids.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        window.authenticate_original_transfer_inputs_data(
            archive,
            [
                tickets[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                tickets[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                tickets[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            prepare_ids.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            commit_ids.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
        )?;
        *output = Some(Rc::new(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            archive: CompleteOriginalRestorationSource {
                inner: Rc::clone(&archive.inner),
            },
            tickets: std::array::from_fn(|_| OnceCell::new()),
            prepare_ids: OnceCell::new(),
            commit_ids: OnceCell::new(),
            completed: std::cell::Cell::new(false),
        }));
        let group = output.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        for index in 0..3 {
            let original = tickets[index]
                .take()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            if let Err(original) = group.tickets[index].set(original) {
                tickets[index] = Some(original);
                return Err(RuntimeError::DuplicateOperation);
            }
        }
        let ids = prepare_ids.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(ids) = group.prepare_ids.set(ids) {
            *prepare_ids = Some(ids);
            return Err(RuntimeError::DuplicateOperation);
        }
        let ids = commit_ids.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(ids) = group.commit_ids.set(ids) {
            *commit_ids = Some(ids);
            return Err(RuntimeError::DuplicateOperation);
        }
        group.completed.set(true);
        group.authenticate_archive(archive)
    }

    pub(super) fn authenticate_archive(
        &self,
        archive: &CompleteOriginalRestorationSource,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self.completed.get() || !Rc::ptr_eq(&self.archive.inner, &archive.inner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive.inner.authenticate_birth()
    }

    pub(super) fn ticket(
        &self,
        selected: usize,
    ) -> Result<&CompleteOriginalNativeTicket, RuntimeError> {
        self.origin()?;
        self.tickets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn prepare_id(&self, selected: usize) -> Result<&Id, RuntimeError> {
        self.origin()?;
        self.prepare_ids
            .get()
            .and_then(|ids| ids.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn commit_id(&self, selected: usize) -> Result<&Id, RuntimeError> {
        self.origin()?;
        self.commit_ids
            .get()
            .and_then(|ids| ids.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Borrows the exact moved originals for a post-transfer observation.
    ///
    /// No ticket, ID, archive or native owner is cloned or recreated. The
    /// collector compares these actual slots with its retained Source roster
    /// before every phase; a partial transfer cannot produce this complete loan.
    pub(super) fn original_group_inputs_data<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        sdks: [&'a crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        launches: &'a [crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;
                3],
        encoded_launches: [&'a [u8]; 3],
        runtime: &'a ConformanceRuntime,
        activation: &'a ActivationRecord,
        journals: [&'a ContentRef; 3],
        selected: usize,
    ) -> Result<OriginalRestorationConstructionInputs<'a>, RuntimeError> {
        self.original_group_observed_inputs_data(
            sources,
            sdks,
            launches,
            encoded_launches,
            runtime.observation_data(),
            activation,
            journals,
            selected,
        )
    }

    pub(super) fn original_group_observed_inputs_data<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        sdks: [&'a crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        launches: &'a [crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;
                3],
        encoded_launches: [&'a [u8]; 3],
        runtime: crate::node_contract::ConformanceRuntimeObservation<'a>,
        activation: &'a ActivationRecord,
        journals: [&'a ContentRef; 3],
        selected: usize,
    ) -> Result<OriginalRestorationConstructionInputs<'a>, RuntimeError> {
        self.authenticate_archive(&self.archive)?;
        let inputs = OriginalRestorationConstructionInputs {
            sources,
            sdks,
            launches,
            encoded_launches,
            tickets: [self.ticket(0)?, self.ticket(1)?, self.ticket(2)?],
            selected,
            prepare_ids: self
                .prepare_ids
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            commit_ids: self
                .commit_ids
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            source: sources
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            launch: launches
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            encoded_launch: encoded_launches
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            archive: &self.archive,
            ticket: self.ticket(selected)?,
            runtime,
            activation,
            journals,
            journal: journals
                .get(selected)
                .copied()
                .ok_or(RuntimeError::ForeignAuthority)?,
            prepare_id: self.prepare_id(selected)?,
            commit_id: self.commit_id(selected)?,
        };
        inputs.authenticate_original_group_data()?;
        Ok(inputs)
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.origin()?;
        let mut total =
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<Self>();
        // The archive and its Source allocation are independently counted by
        // the same whole-window observation. These same-Rc handles add no new
        // child allocation. Authenticate every actual occupied edge first.
        for ticket in &self.tickets {
            if let Some(ticket) = ticket.get() {
                ticket.authenticate_source(&self.archive)?;
            }
        }
        for ids in [self.prepare_ids.get(), self.commit_ids.get()]
            .into_iter()
            .flatten()
        {
            for id in ids {
                total = total
                    .checked_add(id.allocated_capacity())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<OriginalRestorationConstructionInputs<'static>>()
            + size_of::<Result<OriginalRestorationConstructionInputs<'static>, RuntimeError>>()
            + size_of::<[&CompleteOriginalNativeTicket; 3]>()
            + size_of::<[&Id; 3]>()
            + size_of::<[Option<&[Id; 3]>; 2]>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<&[Id; 3]>, 2>>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::slice::Iter<'static, OnceCell<CompleteOriginalNativeTicket>>>()
            + size_of::<Result<usize, RuntimeError>>()
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive.inner.authenticate_birth()
    }
}
