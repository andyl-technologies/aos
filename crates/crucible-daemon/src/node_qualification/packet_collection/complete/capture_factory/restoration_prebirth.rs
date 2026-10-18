//! Retains actual source tickets before constructing the fresh restoration graph.
//!
//! The capsule keeps the strong code-validation graph alive while its source
//! carries only a weak plan witness. It exists before the first ticket transfer,
//! retains partial preparation on refusal, and issues no native birth/report,
//! whole-preparation context, readiness or restoration installation permission.

mod host_source17;
mod precredit;
mod producer_publication;
pub(in crate::node_qualification::packet_collection::complete) mod publication;
mod restoration_storage;
mod restored_source17;

use super::*;
use crucible::node_admission::{CompleteArchiveCodeGraph, ConformanceGraph};
use crucible::node_contract::{
    CollectingCompleteRestorationSource, HostSchedulingContinuationLimits, HostSchedulingOwner,
    HostSchedulingSelection,
};
use crucible::node_state::{CompleteOriginalHostTicket, CompleteOriginalNativeTicket};
use std::cell::Cell;

/// Owns the same verified source and all four once-issued prebirth tickets.
///
/// Keep this capsule outside unwind guards through fresh preparation/cleanup.
/// Its actual factory and code graph are retained, while any attempted fresh
/// graph stays owned even when target binding fails. It never launches a Child.
#[must_use = "retain original source tickets and partial fresh owners on refusal"]
pub struct PacketCompleteRestorationPrebirth {
    factory: Rc<PacketCompleteArchiveCodeFactory>,
    code_graph: Rc<CompleteArchiveCodeGraph>,
    source: CollectingCompleteRestorationSource,
    native: [Option<CompleteOriginalNativeTicket>; 3],
    initial15_control: RefCell<initial15_control::Initial15PrebirthControlMembers>,
    initial15_control_started: Cell<bool>,
    initial15_control_failed: Cell<bool>,
    host_ticket: Option<CompleteOriginalHostTicket>,
    host: Option<HostSchedulingOwner>,
    host_attempted: bool,
    // None preserves the initial-family path. A current17 partial capsule stays
    // false until its actual loader, ticket transfers and final code fence pass.
    source17_ticket_completion: Option<bool>,
    host_source17_admission: Option<host_source17::HostSource17Admission>,
    fresh_graph: Option<Rc<ConformanceGraph>>,
    fresh_factory: Option<Rc<PacketCompleteCaptureFactory>>,
    binding_attempted: bool,
    runtime_attempted: bool,
    report_startup_holder:
        Option<std::rc::Weak<RefCell<super::super::PacketCompleteReportStartupHolder>>>,
    runtime: Option<RefCell<ConformanceRuntime>>,
    failed_runtime: Option<crucible::node_contract::ConformanceRuntimeFailure>,
    publication: Option<publication::OriginalRestorationPublicationOwners>,
    restored_results: Option<
        RefCell<super::super::restored_publication::StoredPacketRestoredProducerResultPublisher>,
    >,
    restored_actions:
        RefCell<Vec<RefCell<super::super::restored_publication::RestoredProducerAction>>>,
    process: u32,
    thread: std::thread::ThreadId,
}

impl PacketCompleteArchiveCodeFactory {
    /// Fills a caller-retained prebirth capsule before issuing any source ticket.
    ///
    /// The caller supplies its real code-selection graph, signed selected-load
    /// archive and finite decode limits. Successful full source validation moves
    /// immediately into `output`; subsequent refusal leaves partial tickets in
    /// that exact slot. This inline capsule allocates no independent Box/bank.
    /// Actual startup/native/graph holders still require their own checked whole
    /// preparation before native report/Prepare MAC. This is not their admission.
    ///
    /// # Errors
    /// Refuses occupied output, foreign code ownership, an unsupported archive,
    /// exhausted decode bounds or any failed/repeated original ticket transfer.
    pub fn prepare_original_restoration_prebirth_into(
        self: &Rc<Self>,
        graph: Rc<CompleteArchiveCodeGraph>,
        archive: NativeArchiveRecord,
        limits: HostSchedulingContinuationLimits,
        output: &mut Option<PacketCompleteRestorationPrebirth>,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if output.is_some() {
            return Err(refused("original restoration prebirth slot is occupied"));
        }
        let source = self.prepare_original_restoration_source(&graph, archive, limits)?;
        *output = Some(PacketCompleteRestorationPrebirth {
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
            source17_ticket_completion: None,
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
        });
        let original = output
            .as_mut()
            .ok_or_else(|| refused("prebirth capsule is absent"))?;
        for (index, source) in self.inner.authority.roster().sources.iter().enumerate() {
            original.native[index] = Some(
                original
                    .source
                    .take_native_ticket(&source.installation().owner.owner.id)
                    .map_err(error)?,
            );
        }
        original.host_ticket = Some(original.source.take_host_ticket().map_err(error)?);
        original.authenticate_code_owner()
    }
}

impl PacketCompleteRestorationPrebirth {
    fn authenticate_creator(&self) -> Result<(), StateError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("restoration prebirth belongs to another creator"));
        }
        Ok(())
    }

    fn authenticate_code_owner(&self) -> Result<(), StateError> {
        self.authenticate_creator()?;
        if self.source17_ticket_completion == Some(false) {
            return Err(refused(
                "restored17 Source and ticket transfer did not complete",
            ));
        }
        self.authenticate_code_selection_data()
    }

    fn authenticate_code_selection_data(&self) -> Result<(), StateError> {
        self.authenticate_creator()?;
        self.factory.authenticate_code_owner()?;
        self.code_graph.plan().reauthenticate().map_err(error)?;
        self.code_graph
            .plan()
            .authenticate_authority(self.factory.inner.authority.as_ref())
            .map_err(error)?;
        self.authenticate_creator()
    }

    /// Constructs and retains the actual restored Host2 from its original ticket.
    ///
    /// The existing Host2 constructor authenticates complete historical selection
    /// and the distinct target incarnation. No node, scheduler attachment or Ready
    /// is issued here. A refused first attempt remains spent in this capsule.
    ///
    /// # Errors
    /// Refuses foreign creator/code custody, missing/reused host ticket, another
    /// source selection or failure to create the actual original Host source.
    pub fn prepare_original_host(
        &mut self,
        selection: HostSchedulingSelection,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if self.host_attempted || self.binding_attempted {
            return Err(refused(
                "original restored host preparation was already attempted",
            ));
        }
        self.host_attempted = true;
        let ticket = self
            .host_ticket
            .take()
            .ok_or_else(|| refused("original host ticket is absent"))?;
        let owner = HostSchedulingOwner::restore_complete_original_continuation(
            selection,
            self.factory.inner.host.world().clone(),
            ticket,
        )
        .map_err(operation_failure)?;
        self.host = Some(owner);
        self.authenticate_code_owner()
    }

    /// Borrows a strong alias of the actual restored Host source for graph installation.
    ///
    /// # Errors
    /// Refuses foreign custody or an absent actual archive-ticketed Host owner.
    pub fn original_host_source(&self) -> Result<Rc<HostSchedulingSource>, StateError> {
        self.authenticate_code_owner()?;
        self.host
            .as_ref()
            .map(HostSchedulingOwner::source)
            .ok_or_else(|| refused("actual restored host has not been prepared"))
    }

    /// Transfers real baseline peers into the same prebirth preparation holder.
    ///
    /// Actual native birth and baseline transport owners require their existing
    /// admission before this entry. It does not launch a Child or obtain native
    /// authority from archive data. The immutable capsule loan ends before the
    /// same registered holder negotiates/attaches each actual peer and retains
    /// its genuine completed-Admit preparation. No HOST query is sent here, and
    /// no opaque verifier loan survives into the later HOST-ticket phase.
    ///
    /// # Errors
    /// Refuses a foreign/bound capsule, absent holder, changed baseline source or
    /// failed SDK/native preparation. Surviving originals stay in holder slots.
    pub fn prepare_original_fresh_connections<
        V: crucible_node_provider::handshake::TrustedHandshakeVerifier,
    >(
        original: &Rc<RefCell<Self>>,
        connections: &mut [Option<super::super::PacketCompletePreparationConnection>; 3],
        verifiers: &mut [V; 3],
    ) -> Result<(), StateError> {
        let startup = Self::original_preparation_holder(original)?;
        for member in 0..3 {
            super::super::PacketCompleteReportStartupHolder::prepare_original_connection_into(
                &startup,
                member,
                &mut connections[member],
                &mut verifiers[member],
            )
            .map_err(error)?;
        }
        original
            .try_borrow()
            .map_err(error)?
            .authenticate_code_owner()
    }

    /// Dispatches actual ticketed HOST queries before target graph construction.
    ///
    /// The preceding connection transaction must have retained all three actual
    /// completed-Admit preparations in this capsule's registered holder. Core
    /// observes their real backing and the installed resource policy before
    /// constructing/dispatching each Query. Unsupported native Fresh publication
    /// remains a terminal refusal, with original results and custody retained.
    ///
    /// # Errors
    /// Refuses foreign/busy capsules, missing original holders/preparations,
    /// repeated query windows, unknown storage or any native/SDK failure.
    pub fn prepare_original_fresh_host_reports(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), StateError> {
        let startup = Self::original_preparation_holder(original)?;
        for member in 0..3 {
            super::super::PacketCompleteReportStartupHolder::call_original_fresh_restore_query(
                &startup, member,
            )
            .map_err(error)?;
        }
        original
            .try_borrow()
            .map_err(error)?
            .authenticate_code_owner()
    }

    fn original_preparation_holder(
        original: &Rc<RefCell<Self>>,
    ) -> Result<Rc<RefCell<super::super::PacketCompleteReportStartupHolder>>, StateError> {
        let held = original.try_borrow().map_err(error)?;
        held.authenticate_code_owner()?;
        if held.binding_attempted || held.runtime_attempted || held.fresh_graph.is_some() {
            return Err(refused("fresh host preparation follows graph binding"));
        }
        held.report_startup_holder
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| refused("actual original report startup holder is absent"))
    }

    /// Retains the actual fresh graph before binding this source once to its plan.
    ///
    /// Core authenticates all four issued tickets, distinct actual authorities,
    /// historical selection, same archive-ticketed Host and real fresh graph.
    /// Failure keeps the supplied graph and all original tickets in this capsule.
    ///
    /// # Errors
    /// Refuses missing owners, foreign/stale graph, changed selection or any prior
    /// binding attempt. No failed binding can be retried with another target.
    pub fn bind_original_target_graph(
        &mut self,
        graph: &mut Option<Rc<ConformanceGraph>>,
        factory: &Rc<PacketCompleteCaptureFactory>,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if self.binding_attempted || self.native.iter().any(Option::is_none) {
            return Err(refused("original target graph binding is unavailable"));
        }
        if graph.is_none() {
            return Err(refused("incoming fresh graph is absent"));
        }
        self.binding_attempted = true;
        self.fresh_graph = graph.take();
        self.fresh_factory = Some(Rc::clone(factory));
        factory.current()?;
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("actual restored host is absent"))?
            .source();
        let graph = self
            .fresh_graph
            .as_ref()
            .ok_or_else(|| refused("actual fresh graph is absent"))?;
        graph
            .plan()
            .authenticate_authority(factory.authority.as_ref())
            .map_err(error)?;
        let startup = self
            .report_startup_holder
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| refused("actual original report startup holder is absent"))?;
        startup
            .try_borrow()
            .map_err(error)?
            .authenticates_target_data(factory.authority.as_ref(), graph.plan())
            .map_err(error)?;
        if !Rc::ptr_eq(&host, &factory.host) {
            return Err(refused(
                "fresh factory does not own this restored Host source",
            ));
        }
        self.source
            .bind_original_target_plan(graph, &host)
            .map_err(error)?;
        self.authenticate_code_owner()
    }

    /// Fills the actual Host node output before returning any postguard refusal.
    ///
    /// The caller retains this same node in its prepared realization. It carries
    /// the bound fresh collecting plan and original archive ticket association;
    /// it grants no readiness or restored activation.
    ///
    /// # Errors
    /// Refuses occupied output, absent bound graph/Host, another target or any
    /// existing Host node preparation. Postguard failure leaves output populated.
    pub fn prepare_original_host_node_into(
        &self,
        target: &ActivationRecord,
        output: &mut Option<crucible::node_contract::PreparedHostSchedulingNode>,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if output.is_some() {
            return Err(refused("actual restored Host node output is occupied"));
        }
        let graph = self
            .fresh_graph
            .as_ref()
            .ok_or_else(|| refused("actual fresh graph is absent"))?;
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("actual restored host is absent"))?
            .source();
        let node = self
            .source
            .prepare_original_host_node(graph, &host, target)
            .map_err(error)?;
        *output = Some(node);
        self.authenticate_code_owner()
    }

    /// Constructs and retains the actual inactive source-bound complete runtime.
    ///
    /// The shared graph remains the same allocation kept by this capsule and
    /// the new runtime. Refused construction stays in the Core failure capsule;
    /// neither failure nor a final code guard drops an incoming native owner.
    /// No report query or Source12 preparation is performed by this method.
    ///
    /// # Errors
    /// Refuses missing/foreign owners, repeated construction or unavailable
    /// original runtime custody. The input slot is untouched before dispatch.
    pub fn prepare_original_runtime(
        &mut self,
        prepared: &mut Option<crucible::node_contract::PreparedRealization>,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if self.runtime_attempted {
            return Err(refused(
                "original fresh runtime construction was already attempted",
            ));
        }
        let graph = Rc::clone(
            self.fresh_graph
                .as_ref()
                .ok_or_else(|| refused("actual fresh graph is absent"))?,
        );
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("actual restored host is absent"))?
            .source();
        if prepared.is_none() {
            return Err(refused("actual prepared restoration owners are absent"));
        }
        self.runtime_attempted = true;
        let prepared = prepared
            .take()
            .ok_or_else(|| refused("actual prepared restoration owners are absent"))?;
        match ConformanceRuntime::from_prepared_complete_original_restoration(
            graph,
            prepared,
            host,
            &self.source,
        ) {
            Ok(runtime) => self.runtime = Some(RefCell::new(runtime)),
            Err(failure) => {
                let reason = failure.reason.clone();
                self.failed_runtime = Some(failure);
                return Err(refused(reason));
            }
        }
        self.authenticate_code_owner()
    }

    /// Borrows the actual same-source native ticket slot for its owning signer.
    ///
    /// This data loan creates no context, mapping or MAC permission. The Source
    /// signer independently checks its own native association, the genuine Core
    /// preparation context and SDK assignments before consuming the ticket.
    ///
    /// # Errors
    /// Refuses absent runtime/bound graph, foreign membership, a consumed ticket
    /// or changed original code ownership. Unsupported signer phases stay closed.
    pub fn native_preparation_data(
        &mut self,
        member: usize,
    ) -> Result<
        (
            &crucible::node_state::CompleteOriginalRestorationSource,
            &mut Option<CompleteOriginalNativeTicket>,
        ),
        StateError,
    > {
        self.authenticate_code_owner()?;
        if self.runtime.is_none() || self.failed_runtime.is_some() {
            return Err(refused("actual inactive fresh runtime is unavailable"));
        }
        let graph = self
            .fresh_graph
            .as_ref()
            .ok_or_else(|| refused("actual fresh graph is absent"))?;
        let source = self.source.original_source_data(graph).map_err(error)?;
        let selected = self
            .factory
            .inner
            .authority
            .roster()
            .sources
            .get(member)
            .ok_or_else(|| refused("original native member is absent"))?;
        let ticket = self
            .native
            .get_mut(member)
            .ok_or_else(|| refused("original native ticket slot is absent"))?;
        let original = ticket
            .as_ref()
            .ok_or_else(|| refused("original native ticket was consumed"))?;
        if original.owner().map_err(error)?.owner != selected.installation().owner.owner.id {
            return Err(refused("original native ticket membership differs"));
        }
        Ok((source, ticket))
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_report_startup_target_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
    ) -> Result<(), StateError> {
        self.authenticate_creator()?;
        self.factory.authenticate_retained_code_origin_data()?;
        if std::ptr::eq(authority, self.factory.inner.authority.as_ref())
            || self.binding_attempted
            || self.runtime_attempted
            || self.runtime.is_some()
            || self.failed_runtime.is_some()
            || self.fresh_graph.is_some()
            || self.fresh_factory.is_some()
            || self.native.iter().any(Option::is_none)
            || self.host_ticket.is_some()
        {
            return Err(refused(
                "actual fresh report startup holders are unavailable",
            ));
        }
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("actual restored Host is absent"))?
            .source();
        if !Rc::ptr_eq(&host, authority.host_source()) {
            return Err(refused("fresh report authority uses another restored Host"));
        }
        self.source
            .authenticate_original_prebirth_host_data(&host)
            .map_err(error)?;
        let historical = self.code_graph.plan().evidence();
        let fresh = plan.evidence();
        if historical.plan_ref != fresh.plan_ref
            || historical.refused_ref != fresh.refused_ref
            || historical.sources != fresh.sources
            || historical.world != fresh.world
        {
            return Err(refused(
                "fresh report plan changes the historical code selection",
            ));
        }
        for (ticket, source) in self.native.iter().zip(&authority.roster().sources) {
            let ticket = ticket
                .as_ref()
                .ok_or_else(|| refused("actual native ticket is absent"))?;
            if ticket.owner().map_err(error)?.owner != source.installation().owner.owner.id {
                return Err(refused(
                    "fresh report Source roster changes native membership",
                ));
            }
        }
        self.authenticate_creator()
    }

    pub(in crate::node_qualification::packet_collection::complete) fn bind_report_startup_holder(
        &mut self,
        holder: &Rc<RefCell<super::super::PacketCompleteReportStartupHolder>>,
    ) -> Result<(), StateError> {
        self.authenticate_creator()?;
        if self.report_startup_holder.is_some() || self.binding_attempted || self.runtime_attempted
        {
            return Err(refused("original report startup holder was already bound"));
        }
        self.report_startup_holder = Some(Rc::downgrade(holder));
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_report_startup_storage_data(
        &self,
        original: &Rc<RefCell<Self>>,
        maximum: usize,
    ) -> Result<usize, StateError> {
        self.authenticate_creator()?;
        self.factory.authenticate_retained_code_origin_data()?;
        if self.binding_attempted
            || self.runtime_attempted
            || self.runtime.is_some()
            || self.failed_runtime.is_some()
            || self.fresh_graph.is_some()
            || self.fresh_factory.is_some()
        {
            return Err(refused("report storage loan crossed its pre-Child phase"));
        }
        let mut counter = super::super::retained::Counter::new(maximum);
        counter
            .add(
                self.initial15_control
                    .try_borrow()
                    .map_err(error)?
                    .retained_requested_storage_data(counter.remaining())
                    .map_err(error)?,
            )
            .map_err(error)?;
        counter.rc(original).map_err(error)?;
        if let Some(holder) = &self.report_startup_holder {
            counter.weak(holder).map_err(error)?;
        }
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("actual restored Host is absent"))?
            .source();
        counter
            .add(
                self.source
                    .retained_original_prebirth_storage_data(&host, counter.remaining())
                    .map_err(error)?,
            )
            .map_err(error)?;
        counter
            .add(
                self.factory
                    .retained_report_startup_code_storage_data(counter.remaining())?,
            )
            .map_err(error)?;
        counter.rc(&self.code_graph).map_err(error)?;
        let allowance = counter
            .remaining()
            .checked_add(std::mem::size_of_val(self.code_graph.as_ref()))
            .ok_or_else(|| refused("code graph observer allowance overflow"))?;
        let graph = self
            .code_graph
            .original_retained_requested_storage_data(allowance)
            .map_err(error)?;
        counter
            .add(
                graph
                    .checked_sub(std::mem::size_of_val(self.code_graph.as_ref()))
                    .ok_or_else(|| refused("code graph requested root differs"))?,
            )
            .map_err(error)?;
        self.authenticate_creator()?;
        Ok(counter.bytes())
    }

    /// Borrows this capsule's actual inactive collecting runtime for data admission.
    ///
    /// This exposes no mutable runtime or ordinary graph. A later Core startup
    /// issuer must still authenticate the actual bound source/plan and installed
    /// scenario resource policy before creating its opaque query grant.
    ///
    /// # Errors
    /// Refuses foreign creation/code ownership or an absent/failed runtime.
    pub fn original_runtime_data(
        &self,
    ) -> Result<std::cell::Ref<'_, ConformanceRuntime>, StateError> {
        self.authenticate_code_owner()?;
        self.runtime
            .as_ref()
            .ok_or_else(|| refused("actual inactive fresh runtime is absent"))?
            .try_borrow()
            .map_err(|_| refused("actual inactive fresh runtime is absent"))
    }
}

mod invocation;

mod restoration_transaction;

mod installed;

#[path = "restoration_prebirth/restored_suffix.rs"]
mod restored_suffix;

#[path = "restoration_prebirth/construction.rs"]
mod construction;
mod fresh_runtime;

mod runtime_owner;

mod producer_lifecycle;

#[path = "restoration_prebirth/initial15_control.rs"]
pub(in crate::node_qualification::packet_collection::complete) mod initial15_control;
