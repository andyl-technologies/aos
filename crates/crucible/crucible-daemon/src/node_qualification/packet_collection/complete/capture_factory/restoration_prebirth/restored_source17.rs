//! Forwards a genuine current17 load into retained prebirth ticket custody.
//!
//! The signed archive and every initialized decoder remain in caller-owned slots.
//! A completed Source moves into the output before any post-validation refusal or
//! ticket issuance. This boundary supplies no target binding or native permission.

use super::*;
use crucible_engine::node_contract::RuntimeError;
use crucible_engine::node_state::CompleteRestoredSettledSourceLoadAttempt;
use std::mem::{align_of, size_of};

impl PacketCompleteArchiveCodeFactory {
    /// Loads and retains a current17 Source before transferring its tickets once.
    ///
    /// The caller supplies separately observed surrounding setup storage. The
    /// existing strict Source loader still authenticates the complete signed
    /// closure, actual code graph and all-owner factory callback. Even a failed
    /// final fence leaves a completed Source and every issued ticket retained.
    /// The caller keeps `pending`, `source_output` and `output` in its actual
    /// owning object across unwind guards. The Source slot spans loader guards;
    /// the capsule Rc slot spans ticket transfer and the final code fence.
    ///
    /// # Errors
    /// Refuses occupied Source/capsule outputs, absent archive, spent load attempt, foreign
    /// code ownership, exhausted independent limits or a failed ticket transfer.
    pub fn prepare_restored_settled_restoration_prebirth_into(
        self: &Rc<Self>,
        graph: Rc<CompleteArchiveCodeGraph>,
        archive: &mut Option<NativeArchiveRecord>,
        limits: HostSchedulingContinuationLimits,
        additional_retained_bytes: usize,
        pending: &mut Option<CompleteRestoredSettledSourceLoadAttempt>,
        source_output: &mut Option<CollectingCompleteRestorationSource>,
        output: &mut Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), StateError> {
        if output.is_some() || source_output.is_some() {
            return Err(refused("restored17 prebirth output is occupied"));
        }
        let construction = Self::restored_settled_prebirth_construction_bytes_data()?;
        let additional = additional_retained_bytes
            .checked_add(construction)
            .ok_or_else(|| refused("restored17 prebirth construction storage overflow"))?;
        let result = self.prepare_restored_settled_restoration_source_into(
            &graph,
            archive,
            limits,
            additional,
            pending,
            source_output,
        );

        // The loader writes the caller's actual retained Source slot before its
        // postguards. An unwind there therefore keeps the transferred archive.
        // On return, move it straight into the actual retained capsule slot; no
        // fallible operation intervenes before the destination owns the Source.
        if let Some(source) = source_output.take() {
            *output = Some(Rc::new(RefCell::new(PacketCompleteRestorationPrebirth {
                factory: Rc::clone(self),
                code_graph: graph,
                source,
                native: std::array::from_fn(|_| None),
                initial15_control: RefCell::new(
                    initial15_control::Initial15PrebirthControlMembers::new(),
                ),
                initial15_control_started: Cell::new(false),
                initial15_control_failed: Cell::new(false),
                host_ticket: None,
                host: None,
                host_attempted: false,
                source17_ticket_completion: Some(false),
                host_source17_admission: None,
                fresh_graph: None,
                fresh_factory: None,
                binding_attempted: false,
                runtime_attempted: false,
                report_startup_holder: None,
                runtime: None,
                failed_runtime: None,
                publication: None,
                restored_results: None,
                restored_actions: RefCell::new(Vec::new()),
                process: std::process::id(),
                thread: std::thread::current().id(),
            })));
        }
        result?;
        // The capsule Rc is already caller-retained before any ticket transfer
        // or later callback. Unwind leaves its exact partial issuance intact.
        let original = output
            .as_ref()
            .ok_or_else(|| refused("restored17 completed Source is absent"))?;
        let mut original = original.try_borrow_mut().map_err(error)?;
        for (index, selected) in self.inner.authority.roster().sources.iter().enumerate() {
            original.native[index] = Some(
                original
                    .source
                    .take_native_ticket(&selected.installation().owner.owner.id)
                    .map_err(error)?,
            );
        }
        original.host_ticket = Some(original.source.take_host_ticket().map_err(error)?);
        drop(original);

        let original = output
            .as_ref()
            .ok_or_else(|| refused("restored17 completed capsule is absent"))?;
        original
            .try_borrow()
            .map_err(error)?
            .authenticate_code_selection_data()?;
        let mut held = original.try_borrow_mut().map_err(error)?;
        if held.source17_ticket_completion != Some(false)
            || held.native.iter().any(Option::is_none)
            || held.host_ticket.is_none()
        {
            return Err(refused("restored17 ticket completion changed"));
        }
        held.source17_ticket_completion = Some(true);
        Ok(())
    }

    /// Names independent capsule retention and concrete constructor temporaries.
    ///
    /// The Source loader separately prices its own output and decoder owners.
    /// These terms cover the prospective caller-retained capsule Rc, its inline
    /// construction value and the actual local Source/output/result views.
    /// The Rc term uses the same defining checked Daemon layout as the later
    /// actual capsule census.
    ///
    /// # Errors
    /// Refuses checked shared-allocation layout or total extent overflow.
    pub fn restored_settled_prebirth_construction_bytes_data() -> Result<usize, StateError> {
        let retained = super::super::super::retained::shared_requested_storage(
            size_of::<RefCell<PacketCompleteRestorationPrebirth>>(),
            align_of::<RefCell<PacketCompleteRestorationPrebirth>>(),
        )
        .map_err(error)?;
        let headers = size_of::<initial15_control::Initial15PrebirthControlMembers>()
            + size_of::<PacketCompleteRestorationPrebirth>()
            + size_of::<Option<CollectingCompleteRestorationSource>>()
            + size_of::<RefCell<PacketCompleteRestorationPrebirth>>()
            + size_of::<Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>>()
            + size_of::<Rc<CompleteArchiveCodeGraph>>()
            + size_of::<Result<(), StateError>>()
            + size_of::<&mut Option<CompleteRestoredSettledSourceLoadAttempt>>()
            + size_of::<&mut Option<NativeArchiveRecord>>()
            + size_of::<&mut Option<CollectingCompleteRestorationSource>>()
            + size_of::<&mut Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>>()
            + size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, PacketCompleteRestorationPrebirth>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<usize>()
            + size_of::<Result<usize, RuntimeError>>();
        retained
            .checked_add(headers)
            .ok_or_else(|| refused("restored17 prebirth construction storage overflow"))
    }
}
