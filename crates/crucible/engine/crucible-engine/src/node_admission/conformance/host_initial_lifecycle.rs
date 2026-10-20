//! Admits one original host's initial protocol lifecycle before new effects.
//!
//! The fixed whole roster supplies outstanding original commitments. The
//! selected SDK, launch guard, registered role and socket path belong to that
//! same retained holder. A data projection cannot construct this opaque action.

use std::{cell::RefCell, mem::size_of, path::Path, rc::Rc};

use crucible_node_transport::{
    client::OriginalHelloJournal, connection::OriginalRetainedSupervisor,
    reference_packet::service::PacketNative5SourceLaunch,
};

use super::InstalledConformancePlan;
use crate::{
    node_adapters::cnp::{
        CnpSemanticLaunchGuard, CnpSemanticPreparation, InstalledCnpConformanceRole,
        PacketCompleteOriginalHostSdk, PacketCompleteSemanticSource,
    },
    node_contract::RuntimeError,
};

/// Borrows the exact complete holder and selected initial-lifecycle inputs.
///
/// Each SDK loan names the same actual fixed holder slot. The installed
/// authority checks these identities before Source or SDK data observers run.
/// This scope supplies no control, socket, preparation or native permission.
pub struct OriginalHostInitialLifecycleScope<'a> {
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    pub(crate) launches: &'a [PacketNative5SourceLaunch; 3],
    pub(crate) sdks: [&'a PacketCompleteOriginalHostSdk; 3],
    pub(crate) selected: usize,
    target: OriginalHostInitialLifecycleTarget<'a>,
    pub(crate) socket: &'a Path,
    pub(crate) supervisor: &'a OriginalRetainedSupervisor,
    hello_slot: &'a Rc<RefCell<Option<OriginalHelloJournal>>>,
}

enum OriginalHostInitialLifecycleTarget<'a> {
    Unattached {
        guard: &'a CnpSemanticLaunchGuard,
        role: &'a InstalledCnpConformanceRole,
    },
    Prepared(&'a CnpSemanticPreparation),
}

impl OriginalHostInitialLifecycleScope<'_> {
    /// Borrows the same actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the fixed actual Source roster counted separately by Core.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows the same retained immutable typed launch bank.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows all actual SDK slots whose outstanding actions coexist.
    pub fn sdks(&self) -> &[&PacketCompleteOriginalHostSdk; 3] {
        &self.sdks
    }

    /// Names the selected member in those actual fixed arrays.
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Borrows the original guard only while its input slot remains unattached.
    pub fn original_guard(&self) -> Option<&CnpSemanticLaunchGuard> {
        match self.target {
            OriginalHostInitialLifecycleTarget::Unattached { guard, .. } => Some(guard),
            OriginalHostInitialLifecycleTarget::Prepared(_) => None,
        }
    }

    /// Borrows the actual registered role before it moves into preparation.
    pub fn original_role(&self) -> Option<&InstalledCnpConformanceRole> {
        match self.target {
            OriginalHostInitialLifecycleTarget::Unattached { role, .. } => Some(role),
            OriginalHostInitialLifecycleTarget::Prepared(_) => None,
        }
    }

    /// Borrows the actual completed preparation for the terminal owning requery.
    pub fn original_preparation(&self) -> Option<&CnpSemanticPreparation> {
        match self.target {
            OriginalHostInitialLifecycleTarget::Prepared(preparation) => Some(preparation),
            OriginalHostInitialLifecycleTarget::Unattached { .. } => None,
        }
    }

    /// Borrows the exact selected socket path retained before issue.
    pub fn control_socket(&self) -> &Path {
        self.socket
    }

    /// Borrows the same already admitted concrete protocol supervisor owner.
    pub fn supervisor(&self) -> &OriginalRetainedSupervisor {
        self.supervisor
    }

    /// Borrows the registered original Hello destination retained before issue.
    pub fn hello_slot(&self) -> &Rc<RefCell<Option<OriginalHelloJournal>>> {
        self.hello_slot
    }

    /// Compares the same registered Hello allocation before the SDK moves it.
    pub fn is_original_hello_slot(
        &self,
        actual: &Rc<RefCell<Option<OriginalHelloJournal>>>,
    ) -> bool {
        Rc::ptr_eq(self.hello_slot, actual)
    }

    /// Compares the actual installed plan without renewing currentness.
    pub fn is_original_plan(&self, actual: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &actual.0)
    }

    /// Compares the actual authority before any owner callback.
    pub fn is_original_authority(&self, actual: &dyn super::ConformanceAdmissionAuthority) -> bool {
        self.plan.has_authority(actual)
    }

    /// Compares each actual Source allocation with the registered roster.
    pub fn is_original_sources(&self, actual: &[Rc<PacketCompleteSemanticSource>; 3]) -> bool {
        self.sources
            .iter()
            .zip(actual)
            .all(|(left, right)| Rc::ptr_eq(left, right))
    }

    /// Compares the immutable original launch array without encoding it.
    pub fn is_original_launches(&self, actual: &[PacketNative5SourceLaunch; 3]) -> bool {
        std::ptr::eq(self.launches, actual)
    }

    /// Compares the selected SDK with its original fixed holder slot.
    pub fn is_original_sdk(&self, selected: usize, actual: &PacketCompleteOriginalHostSdk) -> bool {
        self.sdks
            .get(selected)
            .is_some_and(|sdk| std::ptr::eq(*sdk, actual))
    }

    /// Compares the actual selected guard, never a copied PID or label.
    pub fn is_original_guard(&self, actual: &CnpSemanticLaunchGuard) -> bool {
        self.original_guard()
            .is_some_and(|guard| std::ptr::eq(guard, actual))
    }

    /// Compares the actual registered role before consuming its input slot.
    pub fn is_original_role(&self, actual: &InstalledCnpConformanceRole) -> bool {
        self.original_role()
            .is_some_and(|role| std::ptr::eq(role, actual))
    }

    /// Compares the same preparation retained before terminal callbacks.
    pub fn is_original_preparation(&self, actual: &CnpSemanticPreparation) -> bool {
        self.original_preparation()
            .is_some_and(|prepared| std::ptr::eq(prepared, actual))
    }

    /// Compares the actual independently owned supervisor handle.
    pub fn is_original_supervisor(&self, actual: &OriginalRetainedSupervisor) -> bool {
        std::ptr::eq(self.supervisor, actual)
    }
}

/// Names actual installed resource policy and the precredited observer phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalHostInitialLifecyclePolicy {
    /// Bounds current owners, outstanding actions and this complete new window.
    pub maximum_requested_bytes: usize,
    /// Bounds actual HOST descriptor views and their remaining closed phases.
    /// Native-process/kernel certification remains its separate baseline action.
    pub maximum_owned_descriptors: usize,
    /// Counts fixed Core, Source, SDK and concrete-holder observer headers.
    pub declared_observer_scratch_bytes: usize,
}

/// Separates complete holder storage from Core's actual Source roster walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalHostInitialLifecycleStorage {
    /// Counts real retained SDK, guard, role, supervisor and original input owners.
    pub retained_holder_bytes: usize,
    /// Bounds the concrete holder's simultaneous observation phase.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Counts actual concrete holder HOST descriptor views, excluding Source3.
    pub retained_descriptors: usize,
    /// Bounds the concrete authority callback's temporary open descriptors.
    pub maximum_simultaneous_transient_descriptors: usize,
}

/// Counts fixed Core views before any lifecycle owner or projection walk.
///
/// The actual window/member layouts are added by the final Source consumer
/// alongside the provider's complete compiled lifecycle and socket counters.
pub(crate) fn fixed_scope_scratch_data() -> Result<usize, RuntimeError> {
    [
        size_of::<OriginalHostInitialLifecycleScope<'static>>(),
        size_of::<OriginalHostInitialLifecyclePolicy>(),
        // The issuer keeps its initial and terminal whole-holder views
        // together while comparing growth before private Source issue.
        2 * size_of::<OriginalHostInitialLifecycleStorage>(),
        // Source and outstanding-commitment banks coexist in that check.
        2 * size_of::<[usize; 3]>(),
    ]
    .into_iter()
    .try_fold(0usize, |total, value| {
        total.checked_add(value).ok_or(RuntimeError::ResourceLimit)
    })
}

/// Borrows original member identity for a callback outside mutable owner banks.
///
/// Core and Source validate the SDK-origin and selected read owner privately.
/// The installed authority checks its retained holder, Source, plan and revision
/// without borrowing the SDK, guard, controller or preparation banks again.
pub struct OriginalHostInitialLifecycleMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
    selected: usize,
}

impl OriginalHostInitialLifecycleMemberScope<'_> {
    /// Borrows the original installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the selected actual Source allocation.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Names the same member in the registered fixed Source roster.
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Compares the private actual plan allocation without renewing it.
    pub fn is_original_plan(&self, actual: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &actual.0)
    }

    /// Compares the same installed authority without following protocol owners.
    pub fn is_original_authority(&self, actual: &dyn super::ConformanceAdmissionAuthority) -> bool {
        self.plan.has_authority(actual)
    }
}

/// Owns one separately admitted socket and initial-protocol construction window.
///
/// Its identity is made only by the same Source-authenticated SDK after Core's
/// complete current-owner, outstanding-action and new-phase conjunction passes.
/// Source retains its nonrenewing issue state before this value can be returned.
/// It grants no common graph, Arm, execution, Capture or behavioral acceptance.
#[must_use = "retain this window beside its same original SDK and launch guard"]
pub struct CompleteOriginalHostInitialLifecycleWindow {
    plan: super::WeakInstalledConformancePlan,
    source: std::rc::Weak<PacketCompleteSemanticSource>,
    identity: crate::node_adapters::cnp::PacketCompleteInitialLifecycleIdentity,
    quote: crate::node_adapters::cnp::PacketCompleteInitialLifecycleQuote,
    selected: usize,
    creator: u32,
    thread: std::thread::ThreadId,
    requested_peak: usize,
    policy: OriginalHostInitialLifecyclePolicy,
    admitted_descriptor_peak: usize,
}

impl InstalledConformancePlan {
    pub(crate) fn has_same_initial_original_plan_data(&self, actual: &Self) -> bool {
        Rc::ptr_eq(&self.0, &actual.0)
    }

    /// Reserves the same original host's socket and initial protocol lifecycle.
    ///
    /// All three current Source owners and their still-live original commitments
    /// coexist with the complete concrete holder. Only the selected host's new
    /// fixed lifecycle row is added; no old aggregate budget is recursively used
    /// as an owning row. Earlier retired finalization temporaries stay retired.
    ///
    /// # Errors
    /// Refuses foreign identities, ambiguous rosters, an unsupported live owner,
    /// repeated issue, insufficient real policy or incomplete prospective data.
    /// No socket or protocol effect occurs in this issuer.
    // crucible-lint: allow rust-allow -- These borrowed actual inputs independently close holder, native, SDK and installed role identity.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_original_host_initial_lifecycle(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        selected: usize,
        guard: &CnpSemanticLaunchGuard,
        role: &InstalledCnpConformanceRole,
        control_socket: &Path,
        supervisor: &OriginalRetainedSupervisor,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
    ) -> Result<CompleteOriginalHostInitialLifecycleWindow, RuntimeError> {
        if selected >= 3 {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scope = OriginalHostInitialLifecycleScope {
            plan: self,
            sources,
            launches,
            sdks,
            selected,
            target: OriginalHostInitialLifecycleTarget::Unattached { guard, role },
            socket: control_socket,
            supervisor,
            hello_slot: registered_hello,
        };
        let policy = self
            .0
            .authority
            .original_host_initial_lifecycle_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_host_initial_lifecycle_counter_scratch_data()?;
        if policy.maximum_requested_bytes == 0
            || policy.maximum_owned_descriptors == 0
            || fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self
            .0
            .authority
            .authenticate_original_host_initial_lifecycle(&self.evidence(), &scope, &policy)?;
        let mut peak = sum(
            &[
                storage.retained_holder_bytes,
                storage.maximum_simultaneous_transient_bytes,
                policy.declared_observer_scratch_bytes,
            ],
            policy.maximum_requested_bytes,
        )?;
        let mut descriptor_peak = sum(
            &[
                storage.retained_descriptors,
                storage.maximum_simultaneous_transient_descriptors,
                CnpSemanticLaunchGuard::original_initial_lifecycle_transient_descriptor_data(),
            ],
            policy.maximum_owned_descriptors,
        )?;
        let mut source_bytes = [0; 3];
        let mut outstanding = [0; 3];
        for index in 0..3 {
            if (0..index).any(|prior| Rc::ptr_eq(&sources[prior], &sources[index])) {
                return Err(RuntimeError::ForeignAuthority);
            }
            descriptor_peak = sum(
                &[
                    descriptor_peak,
                    sources[index].original_initial_lifecycle_descriptor_views_precredit_data()?,
                    scope.sdks[index].original_initial_lifecycle_pending_descriptor_data()?,
                ],
                policy.maximum_owned_descriptors,
            )?;
            source_bytes[index] = sources[index]
                .original_initial_lifecycle_source_storage_data(policy.maximum_requested_bytes)?;
            outstanding[index] = scope.sdks[index].original_initial_lifecycle_outstanding_data(
                &sources[index],
                &launches[index],
                self,
                index != selected,
            )?;
            peak = sum(
                &[peak, source_bytes[index], outstanding[index]],
                policy.maximum_requested_bytes,
            )?;
        }
        let quote = scope.sdks[selected].original_initial_lifecycle_quote_data(
            &sources[selected],
            &launches[selected],
            self,
            guard,
            role,
            control_socket,
            policy.maximum_requested_bytes,
        )?;
        peak = sum(
            &[peak, quote.requested_peak_data()?],
            policy.maximum_requested_bytes,
        )?;

        // No construction or kernel callback follows this final whole-holder
        // requery. Source rechecks its actual immutable inputs while installing
        // the sticky private issue state; refusal cannot reopen an old window.
        let after = self
            .0
            .authority
            .authenticate_original_host_initial_lifecycle(&self.evidence(), &scope, &policy)?;
        if after.retained_descriptors > storage.retained_descriptors
            || after.maximum_simultaneous_transient_descriptors
                > storage.maximum_simultaneous_transient_descriptors
            || after.retained_holder_bytes > storage.retained_holder_bytes
            || after.maximum_simultaneous_transient_bytes
                > storage.maximum_simultaneous_transient_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut terminal_descriptors = sum(
            &[
                after.retained_descriptors,
                after.maximum_simultaneous_transient_descriptors,
                CnpSemanticLaunchGuard::original_initial_lifecycle_transient_descriptor_data(),
            ],
            policy.maximum_owned_descriptors,
        )?;
        for index in 0..3 {
            terminal_descriptors = sum(
                &[
                    terminal_descriptors,
                    sources[index].original_initial_lifecycle_descriptor_views_precredit_data()?,
                    scope.sdks[index].original_initial_lifecycle_pending_descriptor_data()?,
                ],
                policy.maximum_owned_descriptors,
            )?;
            if sources[index]
                .original_initial_lifecycle_source_storage_data(policy.maximum_requested_bytes)?
                > source_bytes[index]
                || scope.sdks[index].original_initial_lifecycle_outstanding_data(
                    &sources[index],
                    &launches[index],
                    self,
                    index != selected,
                )? > outstanding[index]
            {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        if terminal_descriptors > descriptor_peak {
            return Err(RuntimeError::ResourceLimit);
        }
        if scope.sdks[selected].original_initial_lifecycle_quote_data(
            &sources[selected],
            &launches[selected],
            self,
            guard,
            role,
            control_socket,
            policy.maximum_requested_bytes,
        )? != quote
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let identity = scope.sdks[selected].retain_original_initial_lifecycle_issue_data(
            &sources[selected],
            self,
            &launches[selected],
            guard,
            role,
            control_socket,
            registered_hello,
            quote,
        )?;
        Ok(CompleteOriginalHostInitialLifecycleWindow {
            plan: self.downgrade(),
            source: Rc::downgrade(&sources[selected]),
            identity,
            quote,
            selected,
            creator: std::process::id(),
            thread: std::thread::current().id(),
            requested_peak: peak,
            policy,
            admitted_descriptor_peak: descriptor_peak,
        })
    }

    /// Counts the complete fixed Core, Source, SDK and socket observer windows.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow before a data walk.
    pub fn original_host_initial_lifecycle_counter_scratch_data() -> Result<usize, RuntimeError> {
        sum(
            &[
                fixed_scope_scratch_data()?,
                size_of::<CompleteOriginalHostInitialLifecycleWindow>(),
                size_of::<OriginalHostInitialLifecycleMemberScope<'static>>(),
                PacketCompleteSemanticSource::original_initial_lifecycle_counter_scratch_data()?,
            ],
            usize::MAX,
        )
    }
}

impl CompleteOriginalHostInitialLifecycleWindow {
    /// Returns the actual complete admitted conjunction as data.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    pub(crate) fn authenticate_member(
        &self,
    ) -> Result<Rc<PacketCompleteSemanticSource>, RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let source = self
            .source
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.identity.authenticate_original_source_data(&source)?;
        let scope = OriginalHostInitialLifecycleMemberScope {
            plan: &plan,
            source: &source,
            selected: self.selected,
        };
        plan.0
            .authority
            .authenticate_original_host_initial_lifecycle_member(&plan.evidence(), &scope)?;
        self.identity.authenticate_original_source_data(&source)?;
        Ok(source)
    }
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(*value)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

impl CompleteOriginalHostInitialLifecycleWindow {
    /// Counts this Window's actual weak backing views without issuing rights.
    ///
    /// The enclosing fixed slot counts this value inline. Its quote, digests
    /// and flags are fixed data; the only independent backing is the original
    /// plan/Source/SDK-origin/read-owner/registered-Hello Weak allocations.
    /// Views are conservatively repeated without a cross-observer alias refund.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or a requested bound below those views.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        sum(&[
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<super::Plan>(),
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<PacketCompleteSemanticSource>(),
            crate::node_adapters::cnp::PacketCompleteInitialLifecycleIdentity::retained_requested_storage_data(),
        ], maximum)
    }

    /// Returns the separately admitted HOST descriptor conjunction as data.
    pub fn admitted_descriptor_peak_data(&self) -> usize {
        self.admitted_descriptor_peak
    }

    /// Acquires the same selected control socket into its original output slot.
    ///
    /// The SDK retains its nonrenewing phase before descriptor acquisition.
    /// Kernel-resource admission is checked separately from requested Rust heap.
    ///
    /// # Errors
    /// Refuses changed inputs, repeated effects, acquisition failure or final
    /// original currency loss. The same descriptor and guard remain held.
    pub fn acquire_original_control_socket_into(
        &mut self,
        sdk: &mut PacketCompleteOriginalHostSdk,
        guard: &CnpSemanticLaunchGuard,
        control_socket: &Path,
        completed: &mut Option<std::os::unix::net::UnixStream>,
    ) -> Result<(), RuntimeError> {
        let source = self.authenticate_member()?;
        let result = (|| {
            sdk.acquire_original_initial_socket_into(
                &self.identity,
                self.quote,
                guard,
                control_socket,
                completed,
            )?;
            self.authenticate_member()?;
            self.identity
                .authenticate_original_guard_current(guard, &source)
        })();
        if result.is_err() {
            self.identity.revoke();
        }
        result
    }

    /// Connects the same retained SDK to its admitted original control stream.
    ///
    /// # Errors
    /// Refuses another SDK/Child/supervisor, a repeated Hello, transport failure
    /// or terminal original currency loss. No controller can be extracted.
    pub fn connect_original_host_sdk_into(
        &mut self,
        sdk: &mut PacketCompleteOriginalHostSdk,
        guard: &CnpSemanticLaunchGuard,
        stream: &mut Option<std::os::unix::net::UnixStream>,
        operational: &Rc<dyn crucible_node_transport::connection::ConnectionSupervisor>,
        supervisor: &OriginalRetainedSupervisor,
    ) -> Result<(), RuntimeError> {
        let source = self.authenticate_member()?;
        let result = (|| {
            sdk.connect_original_initial_lifecycle_into(
                &self.identity,
                guard,
                stream,
                operational,
                supervisor,
            )?;
            self.authenticate_member()?;
            self.identity
                .authenticate_original_guard_current(guard, &source)
        })();
        if result.is_err() {
            self.identity.revoke();
        }
        result
    }

    /// Retains selected codec, Discover/Realize and once-Admit preparation owners.
    ///
    /// The private sink moves the same Controller/Handshake directly into the
    /// original guard and the same literal Hello into its registered slot. The
    /// actual preparation, response and registry owners enter caller slots
    /// before terminal callbacks. Ordinary preparation remains independent.
    ///
    /// # Errors
    /// Refuses changed inputs, partial/repeated attachment, invalid selected
    /// responses, failed MAC/once-Admit or terminal original currency loss.
    /// Originals stay in their SDK, guard, preparation or registered slots.
    // crucible-lint: allow rust-allow -- Each original slot independently preserves partial lifecycle custody.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_original_initial_lifecycle_into(
        &mut self,
        sdk: &mut PacketCompleteOriginalHostSdk,
        launch: &PacketNative5SourceLaunch,
        guard: &mut Option<CnpSemanticLaunchGuard>,
        role: &mut Option<InstalledCnpConformanceRole>,
        supervisor: &OriginalRetainedSupervisor,
        planned_admit: &crucible_node_format::Id,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
        completed: &mut Option<CnpSemanticPreparation>,
        admitted: &mut Option<crucible_node_transport::bodies::ResponseBody>,
        registry: &mut Option<crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
    ) -> Result<(), RuntimeError> {
        let source = self.authenticate_member()?;
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let result = (|| {
            sdk.prepare_original_initial_lifecycle_into(
                &self.identity,
                launch,
                &plan,
                guard,
                role,
                supervisor,
                planned_admit,
                registered_hello,
                completed,
                admitted,
                registry,
                &mut || self.authenticate_member().map(|_| ()),
            )?;
            self.authenticate_member()?;
            self.identity.authenticate_original_preparation_current(
                completed.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                &source,
            )
        })();
        if result.is_err() {
            self.identity.revoke();
        }
        result
    }

    /// Requeries the same complete holder after the preparation inputs move.
    ///
    /// Core reconstructs only a borrowed Prepared target over the actual output.
    /// It observes current complete owners plus remaining direct commitments;
    /// no old aggregate grant becomes a future owning row. Actual completed
    /// constructor phases retire only through their same private Source state.
    ///
    /// # Errors
    /// Refuses foreign outputs, changed installed policy, unsupported owners,
    /// resource overrun or terminal original read-owner loss.
    // crucible-lint: allow rust-allow -- Fixed-roster originals and the moved actual target independently authenticate the terminal whole conjunction.
    #[allow(clippy::too_many_arguments)]
    pub fn recheck_original_inputs_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        preparation: &CnpSemanticPreparation,
        control_socket: &Path,
        supervisor: &OriginalRetainedSupervisor,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
    ) -> Result<usize, RuntimeError> {
        let source = self.authenticate_member()?;
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if self.selected >= 3 || !Rc::ptr_eq(&source, &sources[self.selected]) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.identity.authenticate_original_preparation_data(
            preparation,
            &source,
            &plan,
            registered_hello,
        )?;
        sdks[self.selected].authenticate_original_initial_completed_data(&self.identity)?;
        let scope = OriginalHostInitialLifecycleScope {
            plan: &plan,
            sources,
            launches,
            sdks,
            selected: self.selected,
            target: OriginalHostInitialLifecycleTarget::Prepared(preparation),
            socket: control_socket,
            supervisor,
            hello_slot: registered_hello,
        };
        let result = (|| {
            let actual_policy = plan
                .0
                .authority
                .original_host_initial_lifecycle_policy(&plan.evidence(), &scope)?;
            if actual_policy != self.policy {
                return Err(RuntimeError::ForeignAuthority);
            }
            let storage = plan
                .0
                .authority
                .authenticate_original_host_initial_lifecycle(
                    &plan.evidence(),
                    &scope,
                    &self.policy,
                )?;
            let mut descriptors = sum(
                &[
                    storage.retained_descriptors,
                    storage.maximum_simultaneous_transient_descriptors,
                    CnpSemanticLaunchGuard::original_initial_lifecycle_transient_descriptor_data(),
                ],
                self.policy.maximum_owned_descriptors,
            )?;
            let mut total = sum(
                &[
                    storage.retained_holder_bytes,
                    storage.maximum_simultaneous_transient_bytes,
                    self.policy.declared_observer_scratch_bytes,
                ],
                self.policy.maximum_requested_bytes,
            )?;
            for index in 0..3 {
                if (0..index).any(|prior| Rc::ptr_eq(&sources[prior], &sources[index])) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                descriptors = sum(
                    &[
                        descriptors,
                        sources[index]
                            .original_initial_lifecycle_descriptor_views_precredit_data()?,
                        scope.sdks[index].original_initial_lifecycle_pending_descriptor_data()?,
                    ],
                    self.policy.maximum_owned_descriptors,
                )?;
                total = sum(
                    &[
                        total,
                        sources[index].original_initial_lifecycle_source_storage_data(
                            self.policy.maximum_requested_bytes,
                        )?,
                        scope.sdks[index].original_initial_lifecycle_outstanding_data(
                            &sources[index],
                            &launches[index],
                            &plan,
                            true,
                        )?,
                    ],
                    self.policy.maximum_requested_bytes,
                )?;
            }
            self.authenticate_member()?;
            self.identity
                .authenticate_original_preparation_current(preparation, &source)?;
            let _complete_host_descriptor_peak = descriptors;
            Ok(total)
        })();
        if result.is_err() {
            self.identity.revoke();
        }
        result
    }
}
