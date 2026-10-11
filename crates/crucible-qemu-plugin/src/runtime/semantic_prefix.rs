//! Installed controller-nine original command and scoped callback ownership.
//!
//! This owner retains the complete preparation, real runtime, original Role64
//! allocation, initializer ACK and backed command before source selection. Its
//! separate context never releases the legacy callback, FIFO or worker holds.
//! Unread peer datagrams remain outside capture custody.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};

use crucible_node_contract::Position;
use crucible_protocol::node_control::{
    CommandJournal, NativeCommandError, NativeEffectCompute, NativePrefixPreparation,
};

use super::OwnedCallbackRuntimeState;
use super::installed_endpoint_owner::InstalledEndpointCustody;
use crate::native_node_control::NativePreparationTransportState;
use crate::native_node_control::administrative_inbox::{
    NativeAdministrativeInbox, NativeAdministrativeInboxError,
};
use crate::native_node_control::administrative_mailbox::NativeAdministrativeReplyCredit;

mod abi;
mod command;
mod context;
mod output;
mod preparation;
mod request;
mod result;
mod roster;
mod typed_result;

pub(super) use roster::retain_installed_callbacks;

use abi::{SemanticInputOps, SourcePrefixEffectCut, SourcePrefixRootSeal};
#[cfg(not(test))]
use abi::{SemanticInputRegistration, SourcePrefixPolicy};
use command::{NativeEffectCommand, NativeEffectPosition};
use context::{NativeEffectContext, OriginalEffectExpectation};

// A held original journal is temporary; poisoning cannot make progress through
// another wake. Both failures preserve its command, reply credit and output.
fn try_callback_journal<T>(journal: &Mutex<T>) -> Result<MutexGuard<'_, T>, c_int> {
    journal.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => -libc::EAGAIN,
        TryLockError::Poisoned(_) => -libc::EOWNERDEAD,
    })
}

#[repr(C)]
struct AncestorEffectPolicy {
    version: u32,
    size: u32,
    digests: [[u8; 32]; 5],
    mapping: u32,
    controller: u32,
    callbacks: u32,
    reserved: u32,
    maximum_microstep: u64,
    maximum_span: u64,
}

#[repr(C)]
struct PrefixPolicy {
    version: u32,
    size: u32,
    original_effect: AncestorEffectPolicy,
    prefix_preparation_commitment: [u8; 32],
    prefix_policy_digest: [u8; 32],
    controller_edition: u32,
    maximum_prefixes: u32,
}

type RegisterPolicy = extern "C" fn(*const PrefixPolicy) -> c_int;
type RegisterAncestor = extern "C" fn(*const AncestorEffectPolicy) -> c_int;
#[cfg(not(test))]
type RegisterSemantic = extern "C" fn(*const SemanticInputRegistration) -> c_int;
#[cfg(not(test))]
type RegisterGetter =
    extern "C" fn(*const PrefixPolicy, command::OriginalCommandGetter, *mut c_void) -> c_int;
type ValidateRoot = extern "C" fn(*const SourcePrefixRootSeal, *const PrefixPolicy) -> c_int;
type QueryContext = extern "C" fn(
    *const SourcePrefixRootSeal,
    *mut c_void,
    *const SourcePrefixEffectCut,
    *mut NativeEffectContext,
) -> c_int;

struct SourceApi {
    register_policy: RegisterPolicy,
    register_ancestor: RegisterAncestor,
    register_roster: roster::RegisterRoster,
    query_initialization: roster::QueryInitialization,
    query_output_bound: output::QueryBound,
    #[cfg(not(test))]
    register_output: output::RegisterOutput,
    #[cfg(not(test))]
    register_semantic: RegisterSemantic,
    #[cfg(not(test))]
    register_getter: RegisterGetter,
    validate_root: ValidateRoot,
    query_begin: QueryContext,
    query_active: QueryContext,
    query_result: result::QueryResult,
    query_typed_result: typed_result::QueryResult,
    query_acknowledgement: request::QueryAcknowledgement,
    #[cfg(not(test))]
    register_request: request::RegisterGetter,
}

impl SourceApi {
    fn resolve() -> Option<Self> {
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                // SAFETY: Only the optional source export is resolved here;
                // each named signature matches the reviewed native declaration.
                let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if pointer.is_null() {
                    return None;
                }
                // SAFETY: The export has the exact concrete native ABI above.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(pointer) }
            }};
        }
        Some(Self {
            query_typed_result: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_result",
                typed_result::QueryResult
            ),
            query_acknowledgement: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_acknowledgement",
                request::QueryAcknowledgement
            ),
            #[cfg(not(test))]
            register_request: symbol!(
                c"qemu_plugin_register_crucible_node_prefix_request_getter",
                request::RegisterGetter
            ),
            query_output_bound: symbol!(
                c"qemu_plugin_crucible_node_query_prefix_output_bound",
                output::QueryBound
            ),
            #[cfg(not(test))]
            register_output: symbol!(
                c"qemu_plugin_register_crucible_node_prefix_output_reservation",
                output::RegisterOutput
            ),
            register_roster: symbol!(
                c"qemu_plugin_register_crucible_prefix_callback_roots",
                roster::RegisterRoster
            ),
            query_initialization: symbol!(
                c"qemu_plugin_crucible_prefix_query_initialization_callback",
                roster::QueryInitialization
            ),
            register_ancestor: symbol!(
                c"qemu_plugin_register_crucible_node_effect_policy",
                RegisterAncestor
            ),
            register_policy: symbol!(
                c"qemu_plugin_register_crucible_node_prefix_policy",
                RegisterPolicy
            ),
            #[cfg(not(test))]
            register_semantic: symbol!(
                c"qemu_plugin_register_crucible_node_prefix_semantic_input_owner",
                RegisterSemantic
            ),
            #[cfg(not(test))]
            register_getter: symbol!(
                c"qemu_plugin_register_crucible_node_prefix_command_getter",
                RegisterGetter
            ),
            validate_root: symbol!(
                c"qemu_plugin_crucible_node_validate_prefix_root",
                ValidateRoot
            ),
            query_begin: symbol!(
                c"qemu_plugin_crucible_node_query_begin_prefix_context",
                QueryContext
            ),
            query_active: symbol!(
                c"qemu_plugin_crucible_node_query_active_prefix_context",
                QueryContext
            ),
            query_result: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_initial_result",
                result::QueryResult
            ),
        })
    }
}

struct OriginalCommand {
    compute: NativeEffectCompute,
    digest: [u8; 32],
    credit: Option<NativeAdministrativeReplyCredit>,
    cursor: u64,
    cut_handle: usize,
    result: Option<crucible_protocol::node_control::NativeEffectProgress>,
    replied: bool,
    published: bool,
    cut_id: Option<u64>,
}

struct OwnedEpoch {
    _incarnation: u64,
}

struct State {
    root: usize,
    epoch: Box<OwnedEpoch>,
    acquired: bool,
    transport: Option<NativePreparationTransportState>,
    journal: CommandJournal,
    command: Option<OriginalCommand>,
    failed: bool,
    output: Box<[output::Reservation]>,
    requests: Vec<request::OriginalRequest>,
    preparation: preparation::Journal,
}

#[derive(Clone, Copy)]
struct ScopedContext {
    owner: usize,
    root: usize,
    epoch: usize,
    cut: usize,
    prospective: NativeEffectContext,
}

thread_local! {
    // Only source begin can stage this same-thread context. It is observed
    // through ACTIVE before callbacks; end takes it before any validation.
    static SCOPED_CONTEXT: Cell<Option<ScopedContext>> = const { Cell::new(None) };
}

/// Retains the concrete installed reducer and actual source callback userdata.
pub(crate) struct SemanticPrefixOwner {
    process_id: u32,
    preparation: NativePrefixPreparation,
    policy: PrefixPolicy,
    api: SourceApi,
    preparation_api: Option<preparation::SourceApi>,
    runtime: AtomicUsize,
    endpoint: OnceLock<Arc<InstalledEndpointCustody>>,
    state: Mutex<State>,
}

static OPS: SemanticInputOps = SemanticInputOps {
    version: 1,
    size: 40,
    prepare,
    validate_held,
    begin,
    end,
};

impl SemanticPrefixOwner {
    /// Retains complete preparation and resolves its required native source ABI.
    ///
    /// # Errors
    /// Rejects invalid original companions, journal capacity or missing source exports.
    pub(crate) fn new(
        preparation: NativePrefixPreparation,
        initial_contract: bool,
    ) -> Result<Arc<Self>, NativeCommandError> {
        preparation.validate()?;
        let initialization = &preparation
            .original_effect
            .original_root
            .administration
            .phase
            .initialization;
        let ancestor = AncestorEffectPolicy {
            version: 1,
            size: 200,
            digests: [
                initialization.preparation.scope.identity_digest()?,
                preparation.original_effect.identity_digest()?,
                initialization.realize_request_digest,
                preparation.original_effect.policy_digest,
                preparation
                    .original_effect
                    .original_root
                    .identity_digest()?,
            ],
            mapping: 3,
            controller: 8,
            callbacks: preparation.original_effect.maximum_callbacks,
            reserved: 0,
            maximum_microstep: preparation
                .original_effect
                .original_root
                .maximum_microstep
                .get(),
            maximum_span: preparation.original_effect.maximum_service_span.get(),
        };
        let policy = PrefixPolicy {
            version: 1,
            size: 280,
            original_effect: ancestor,
            prefix_preparation_commitment: preparation.identity_digest()?,
            prefix_policy_digest: preparation.policy_digest,
            controller_edition: 9,
            maximum_prefixes: preparation.maximum_prefixes,
        };
        let journal = CommandJournal::new(
            initialization.preparation.scope.clone(),
            initialization.preparation.boundary,
            initialization.preparation.maximum_commands.get() as usize,
        )?;
        let output = output::allocate(preparation.maximum_prefixes)?;
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(preparation.maximum_prefixes as usize * 2)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        Ok(Arc::new(Self {
            process_id: std::process::id(),
            preparation,
            policy,
            api: SourceApi::resolve().ok_or(NativeCommandError::Invalid(
                "native semantic source unavailable",
            ))?,
            preparation_api: if initial_contract {
                Some(
                    preparation::SourceApi::resolve().ok_or(NativeCommandError::Invalid(
                        "native initial preparation contract unavailable",
                    ))?,
                )
            } else {
                None
            },
            runtime: AtomicUsize::new(0),
            endpoint: OnceLock::new(),
            state: Mutex::new(State {
                root: 0,
                epoch: Box::new(OwnedEpoch { _incarnation: 1 }),
                acquired: false,
                transport: None,
                journal,
                command: None,
                failed: false,
                output,
                requests,
                preparation: preparation::Journal::default(),
            }),
        }))
    }

    /// Registers the unchanged original policy before native manifest sealing.
    ///
    /// # Errors
    /// Rejects changed preparation identity or a native registration refusal.
    pub(crate) fn register_policy(&self) -> Result<(), NativeCommandError> {
        if self.preparation.identity_digest()? != self.policy.prefix_preparation_commitment {
            return Err(NativeCommandError::Conflict);
        }
        if (self.api.register_ancestor)(&self.policy.original_effect) != 0
            || (self.api.register_policy)(&self.policy) != 0
        {
            return Err(NativeCommandError::Conflict);
        }
        if let Some(api) = &self.preparation_api
            && (api.register_contract)(1, &self.policy) != 0
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Publishes actual role/runtime ownership before the source retains callbacks.
    ///
    /// # Errors
    /// Rejects a foreign process, legacy producer or duplicate installation.
    #[cfg(not(test))]
    pub(crate) fn install(
        &self,
        runtime: &OwnedCallbackRuntimeState,
        endpoint: Arc<InstalledEndpointCustody>,
    ) -> Result<(), c_int> {
        if self.process_id != std::process::id() || !runtime.teardown_router.is_original_finite() {
            return Err(-libc::ESTALE);
        }
        let native = endpoint.native()?;
        self.endpoint.set(endpoint).map_err(|_| -libc::EALREADY)?;
        let address = std::ptr::from_ref(runtime) as usize;
        self.runtime
            .compare_exchange(0, address, Ordering::Release, Ordering::Acquire)
            .map_err(|_| -libc::EALREADY)?;
        let userdata = std::ptr::from_ref(self).cast_mut().cast();
        let registration = SemanticInputRegistration {
            version: 1,
            size: 40,
            original_prefix_policy: std::ptr::from_ref(&self.policy).cast::<SourcePrefixPolicy>(),
            endpoint_owner: native.cast(),
            userdata,
            ops: &OPS,
        };
        let status = (self.api.register_semantic)(&registration);
        if status != 0 {
            return Err(status);
        }
        let status = (self.api.register_getter)(&self.policy, get_command, userdata);
        if status != 0 {
            return Err(status);
        }
        let status = (self.api.register_request)(&self.policy, request::get_request, userdata);
        if status != 0 {
            return Err(status);
        }
        let operations = output::Operations::original(userdata);
        let status = (self.api.register_output)(&self.policy, &operations);
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }

    /// Retains the sole reader's immutable command and reply credit before effects.
    ///
    /// # Errors
    /// Rejects foreign inbox/preparation, widened budgets or conflicting retries.
    pub(crate) fn try_admit(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        let control =
            crate::native_node_control::registered_owner().ok_or(NativeCommandError::Conflict)?;
        if !control
            .original_administrative_actor()
            .is_some_and(|original| Arc::ptr_eq(original, actor))
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed || (self.preparation_api.is_some() && !state.preparation.acknowledged()) {
            return Err(NativeCommandError::Conflict);
        }
        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let crucible_protocol::node_control::NativeFrame::EffectCompute(compute) = frame else {
            return Err(NativeCommandError::Conflict);
        };
        compute.validate()?;
        if compute.effect_preparation != self.policy.prefix_preparation_commitment
            || compute.maximum_callbacks > self.policy.original_effect.callbacks
            || compute.maximum_service_span.get() > self.policy.original_effect.maximum_span
        {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        if let Some(original) = state.command.as_mut() {
            if original.compute != *compute {
                state.failed = true;
                return Err(NativeCommandError::Conflict);
            }
            original.published = false;
            return Ok(true);
        }
        // The genuine RR preparation hold can borrow this same inbox ledger.
        // Contention keeps the original packet and pre-dequeue reply allowance;
        // it must not turn an administrative retry into permanent quarantine.
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let digest = compute.command.identity_digest()?;
        state.journal.retain(compute.command.clone())?;
        state.command = Some(OriginalCommand {
            compute: *compute,
            digest,
            credit: Some(credit),
            cursor,
            cut_handle: 0,
            result: None,
            replied: false,
            published: false,
            cut_id: None,
        });
        Ok(true)
    }

    fn runtime(&self) -> Result<&OwnedCallbackRuntimeState, c_int> {
        if self.process_id != std::process::id() {
            return Err(-libc::ESTALE);
        }
        let address = self.runtime.load(Ordering::Acquire);
        if address == 0 {
            return Err(-libc::EAGAIN);
        }
        // SAFETY: Installation publishes this same process-life pinned runtime;
        // the irreversible native registration keeps its mapping alive.
        Ok(unsafe { &*(address as *const OwnedCallbackRuntimeState) })
    }

    fn hold(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: Option<*mut c_void>,
    ) -> Result<*mut c_void, c_int> {
        let runtime = self.runtime()?;
        self.endpoint.get().ok_or(-libc::EAGAIN)?.native()?;
        if crate::native_node_control::registered_owner()
            .is_none_or(|owner| owner.semantic_administration_failed())
        {
            return Err(-libc::ENOTRECOVERABLE);
        }
        if root.is_null() || (self.api.validate_root)(root, &self.policy) != 0 {
            return Err(-libc::ESTALE);
        }
        if runtime.setup.mapped_region().header().shutdown_requested() {
            return Err(-libc::ECANCELED);
        }
        let mut state = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => -libc::EAGAIN,
            TryLockError::Poisoned(_) => -libc::EOWNERDEAD,
        })?;
        if state.failed || (state.root != 0 && state.root != root as usize) {
            return Err(-libc::ESTALE);
        }
        let original_epoch = std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>();
        if epoch.is_some_and(|epoch| !state.acquired || epoch != original_epoch) {
            return Err(-libc::ESTALE);
        }
        state.root = root as usize;
        if state.transport.is_none() {
            let control = crate::native_node_control::registered_owner().ok_or(-libc::ESTALE)?;
            state.transport = control
                .prepare_runtime_epoch_transport(
                    runtime.setup.mapped_region(),
                    Arc::clone(&runtime.quiescence),
                    Arc::clone(&runtime.workers),
                )
                .map_err(|_| -libc::ENOTRECOVERABLE)?;
        }
        let transport = state.transport.as_mut().ok_or(-libc::EAGAIN)?;
        if !transport
            .try_retain(runtime.setup.mapped_region())
            .map_err(|_| -libc::ENOTRECOVERABLE)?
        {
            return Err(-libc::EAGAIN);
        }
        let callbacks = runtime.quiescence.snapshot();
        let workers = runtime
            .workers
            .try_snapshot()
            .map_err(|_| -libc::EOWNERDEAD)?
            .ok_or(-libc::EAGAIN)?;
        if !callbacks.hot_fork_held
            || callbacks.teardown_closed
            || callbacks.in_flight != 0
            || !workers.held
            || workers.parked_mask != workers.worker_mask
            || workers.pending_mask != 0
            || workers.operations_in_flight != 0
        {
            return Err(-libc::EAGAIN);
        }
        // These are execution holds of the actual exhaustive reducer. Future
        // packets remain inert until this same source admits a retained command;
        // this does not transfer kernel backlog into a capture image.
        state.acquired = true;
        Ok(original_epoch)
    }

    fn stage(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: *mut c_void,
        cut: *const SourcePrefixEffectCut,
    ) -> c_int {
        let runtime = match self.runtime() {
            Ok(runtime) => runtime,
            Err(error) => return error,
        };
        if runtime.setup.mapped_region().header().shutdown_requested()
            || crate::native_node_control::registered_owner()
                .is_none_or(|owner| owner.semantic_administration_failed())
        {
            return -libc::ECANCELED;
        }
        let mut context = NativeEffectContext::default();
        let result = (self.api.query_begin)(root, epoch, cut, &mut context);
        if result != 0 {
            return result;
        }
        let mut state = match try_callback_journal(&self.state) {
            Ok(state) => state,
            Err(error) => return error,
        };
        let actual_epoch = std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>();
        if !state.acquired || state.failed || state.root != root as usize || actual_epoch != epoch {
            return -libc::ESTALE;
        }
        if !state.output.iter().any(|slot| {
            slot.matches(root, epoch, cut) && slot.cut_id == context.effect_cut_id && !slot.finished
        }) {
            return -libc::ESTALE;
        }
        let Some(original) = state.command.as_mut() else {
            return -libc::EAGAIN;
        };
        if original
            .cut_id
            .is_some_and(|id| id != context.effect_cut_id && context.effect_cut_id == 1)
        {
            return -libc::ESTALE;
        }
        let expectation = OriginalEffectExpectation {
            scope: self.policy.original_effect.digests[0],
            effect_preparation: self.policy.prefix_preparation_commitment,
            grant_digest: original.compute.command.authorization_digest,
            command_sequence: original.compute.command.sequence.get(),
            effect_cut_id: context.effect_cut_id,
            start: original.compute.command.kind.start(),
            limit: original.compute.command.kind.limit(),
            maximum_microstep: self.policy.original_effect.maximum_microstep,
        };
        if context.validate_against(&expectation).is_err() {
            return -libc::ESTALE;
        }
        if context.effect_cut_id != 1
            && !state.requests.iter().any(|request| {
                request.matches_continuation_cut(context.effect_cut_id, cut as usize)
            })
        {
            return -libc::ESTALE;
        }

        // Complete every fallible original-cut check before installing TLS.
        // A refused begin must leave no staged callback or output context.
        let staged = ScopedContext {
            owner: std::ptr::from_ref(self) as usize,
            root: root as usize,
            epoch: epoch as usize,
            cut: cut as usize,
            prospective: context,
        };
        let vacant = SCOPED_CONTEXT.with(|scope| {
            if scope.get().is_some() {
                false
            } else {
                scope.set(Some(staged));
                true
            }
        });
        if !vacant {
            return -libc::EBUSY;
        }
        if context.effect_cut_id == 1 {
            // The command was checked above while this same state lock stayed
            // held; publishing the original handle cannot fail after TLS entry.
            if let Some(original) = state.command.as_mut() {
                original.cut_id = Some(context.effect_cut_id);
                original.cut_handle = cut as usize;
            }
        }
        0
    }

    fn revoke(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: *mut c_void,
        cut: *const SourcePrefixEffectCut,
    ) -> c_int {
        let staged = SCOPED_CONTEXT.with(Cell::take);
        let Some(staged) = staged else {
            return -libc::ESTALE;
        };
        if staged.owner != std::ptr::from_ref(self) as usize
            || staged.root != root as usize
            || staged.epoch != epoch as usize
            || staged.cut != cut as usize
        {
            return -libc::ESTALE;
        }
        if self.runtime().is_err() {
            return -libc::ESTALE;
        }
        0
    }

    /// Keeps an original pending acquisition or result recoverable after contention.
    ///
    /// This requests only the coalesced native administrative event. It does not
    /// dequeue another packet, execute a callback or replace an original cut.
    pub(crate) fn original_progress_pending(&self) -> bool {
        if self.process_id != std::process::id() || self.runtime.load(Ordering::Acquire) == 0 {
            return false;
        }
        let acknowledged = crate::native_node_control::registered_owner()
            .is_some_and(|control| control.semantic_initialization_acknowledged());
        if !acknowledged {
            return false;
        }
        match self.state.try_lock() {
            Ok(state) => {
                !state.failed
                    && (!state.acquired
                        || state.preparation.pending()
                        || state.requests.iter().any(|request| !request.published)
                        || state
                            .command
                            .as_ref()
                            .is_some_and(|command| command.result.is_none()))
            }
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Poisoned(_)) => false,
        }
    }

    /// Checks staged callbacks against the actual source-active context.
    ///
    /// An unstaged idle notification performs no guest work. A staged notification
    /// must match the same original native root, epoch, cut and evaluation.
    ///
    /// # Errors
    /// Rejects shutdown, failed administration, revoked native scope or changed context.
    pub(crate) fn observe_active_if_staged(&self) -> Result<(), c_int> {
        if SCOPED_CONTEXT.with(Cell::get).is_none() {
            return Ok(());
        }
        self.observe_active()
    }

    fn observe_active(&self) -> Result<(), c_int> {
        let runtime = self.runtime()?;
        if crate::native_node_control::registered_owner()
            .is_none_or(|owner| owner.semantic_administration_failed())
        {
            return Err(-libc::ENOTRECOVERABLE);
        }
        if runtime.setup.mapped_region().header().shutdown_requested() {
            return Err(-libc::ECANCELED);
        }
        let staged = SCOPED_CONTEXT.with(Cell::get).ok_or(-libc::ESTALE)?;
        if staged.owner != std::ptr::from_ref(self) as usize {
            return Err(-libc::ESTALE);
        }
        let mut actual = NativeEffectContext::default();
        let result = (self.api.query_active)(
            staged.root as *const SourcePrefixRootSeal,
            staged.epoch as *mut c_void,
            staged.cut as *const SourcePrefixEffectCut,
            &mut actual,
        );
        if result != 0 {
            return Err(result);
        }
        let mut original = staged.prospective;
        if actual.actual_raw_counter < original.actual_raw_counter {
            return Err(-libc::ESTALE);
        }
        original.actual_raw_counter = actual.actual_raw_counter;
        if actual != original {
            return Err(-libc::ESTALE);
        }
        Ok(())
    }
}

impl crate::native_node_control::NativeNodeControl {
    /// Retains the separate original controller-nine preparation and semantic owner.
    ///
    /// # Errors
    /// Rejects malformed original companions or an unavailable native semantic ABI.
    pub(crate) fn with_prefix_preparation(
        mut self,
        preparation: NativePrefixPreparation,
        initial_contract: bool,
    ) -> Result<Self, NativeCommandError> {
        if self.effect.is_some() || self.prefix.is_some() {
            return Err(NativeCommandError::Conflict);
        }
        self.prefix = Some(SemanticPrefixOwner::new(preparation, initial_contract)?);
        Ok(self)
    }
}

fn position(position: Position) -> NativeEffectPosition {
    NativeEffectPosition {
        time_ps: position.time_ps.get(),
        microstep: position.microstep.get(),
        phase: position.phase as u32,
        reserved: 0,
    }
}

/// Acquires only the exact source-validated root and actual retained runtime epoch.
///
/// # Safety
/// Source registration retains the exact owner userdata and writable output for
/// this synchronous call; native root addresses are never Rust-dereferenced.
unsafe extern "C" fn prepare(
    root: *const SourcePrefixRootSeal,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Native source supplies aligned writable output for this call.
    unsafe {
        output.write(std::ptr::null_mut());
    }
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The installed callback tuple retains this original Arc allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    let retained = owner.hold(root, None);
    match retained {
        Ok(epoch) => {
            // SAFETY: The same validated native output remains writable; the
            // retained epoch allocation is stable for the installed lifetime.
            unsafe {
                output.write(epoch);
            }
            0
        }
        Err(error) => error,
    }
}

/// Revalidates exact actual epoch identity while every modeled hold remains held.
///
/// # Safety
/// Source retains registered userdata/root/epoch synchronously; epoch is compared
/// to its retained allocation before use and never adopted from caller material.
unsafe extern "C" fn validate_held(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source registration retains the exact original owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    match owner.hold(root, Some(epoch)) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

/// Stages the prospective source context without opening any global admission.
///
/// # Safety
/// Source retains exact userdata and known root/epoch/cut; only its authentic
/// pending-context getter may supply copied prospective observations.
unsafe extern "C" fn begin(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source registration retains this exact original owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    owner.stage(root, epoch, cut)
}

/// Revokes scoped admission before validating completion or returning an error.
///
/// # Safety
/// Source retains the same registered userdata and source objects through end.
/// The TLS scope is taken before checking any argument or original ownership.
unsafe extern "C" fn end(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        SCOPED_CONTEXT.with(Cell::take);
        return -libc::EINVAL;
    }
    // SAFETY: Source registration retains this exact original owner allocation.
    unsafe { &*userdata.cast::<SemanticPrefixOwner>() }.revoke(root, epoch, cut)
}

/// Copies an already retained original command beside its actual reply credit.
///
/// # Safety
/// Source supplies original userdata and complete writable aligned native224
/// output, invoking only its genuine held known-epoch RR seam.
unsafe extern "C" fn get_command(
    epoch: *mut c_void,
    output: *mut NativeEffectCommand,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The native output is writable for the complete fixed224 extent.
    unsafe {
        std::ptr::write_bytes(output, 0, 1);
    }
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source registration retains this original owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    if owner.runtime().is_err() {
        return -libc::ESTALE;
    }
    let mut state = match owner.state.try_lock() {
        Ok(state) => state,
        Err(_) => return -libc::EAGAIN,
    };
    if state.failed
        || !state.acquired
        || epoch != std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>()
    {
        return -libc::ESTALE;
    }
    let Some(original) = &state.command else {
        return -libc::EAGAIN;
    };
    let native = NativeEffectCommand {
        version: 1,
        size: 224,
        kind: 1,
        reserved: 0,
        sequence: original.compute.command.sequence.get(),
        scope: owner.policy.original_effect.digests[0],
        effect_preparation: owner.policy.prefix_preparation_commitment,
        grant_digest: original.compute.command.authorization_digest,
        command_digest: original.digest,
        owned_epoch: epoch,
        start: position(original.compute.command.kind.start()),
        limit: position(original.compute.command.kind.limit()),
        maximum_callbacks: original.compute.maximum_callbacks,
        budget_reserved: 0,
        maximum_service_span: original.compute.maximum_service_span.get(),
    };
    // SAFETY: Source owns this aligned complete output; original journal and
    // credit stay retained after copying, including response loss and retry.
    unsafe {
        output.write(native);
    }
    0
}

#[cfg(test)]
#[path = "semantic_prefix/tests.rs"]
mod tests;
