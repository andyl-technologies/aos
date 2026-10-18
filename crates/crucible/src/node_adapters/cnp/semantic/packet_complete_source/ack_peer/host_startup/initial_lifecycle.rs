//! Spends the original installed host lifecycle action on its same SDK owner.
//!
//! The Source marker cannot be renewed by dropping the public Window or SDK.
//! Every effect phase is sticky before entry; original owners stay in their
//! existing slots. This module never exports a controller or launch guard.

use super::super::super::association::initial_lifecycle_storage::OriginalInitialSourceStorage;
use super::*;
use crate::node_adapters::cnp::semantic::process::OriginalHostInitialLifecycleGuardIdentity;
use crate::{
    node_adapters::cnp::{
        CnpSemanticLaunchGuard, CnpSemanticPreparation, InstalledCnpConformanceRole,
    },
    node_admission::InstalledConformancePlan,
};
use crucible_node_provider::{
    ProviderError,
    bodies::ResponseBody,
    client::{
        CnpController, OriginalHelloJournal, OriginalPacketHostInitialAttachmentScope,
        OriginalPacketHostInitialAttachmentSink, OriginalPacketHostInitialResponse,
        PacketNativeHostInitialLifecycleStorageData,
        original_packet_host_initial_lifecycle_counter_scratch_data,
        original_packet_host_initial_socket_counter_scratch_data,
    },
    connection::OriginalRetainedSupervisor,
    handshake::{ExtensionHandshake, OriginalExtensionRegistryOwner},
};
use std::{
    cell::RefCell,
    os::unix::{ffi::OsStrExt, net::UnixStream},
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketCompleteInitialLifecycleQuote {
    sdk: PacketNativeHostInitialLifecycleStorageData,
    source: OriginalInitialSourceStorage,
    guard_window: usize,
}

impl PacketCompleteInitialLifecycleQuote {
    pub(crate) fn requested_peak_data(self) -> Result<usize, RuntimeError> {
        sum(&[
            self.sdk
                .requested_peak_data()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            self.source.requested_peak_data()?,
            self.guard_window,
        ])
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InitialPhase {
    Issued,
    SocketStarted,
    SocketReady,
    HelloStarted,
    HelloReady,
    AttachmentStarted,
    Attached,
    Preparing,
    Prepared,
    Admitting,
    Completed,
}

pub(super) struct OriginalInitialLifecycleState {
    identity: PacketCompleteInitialLifecycleIdentity,
    quote: PacketCompleteInitialLifecycleQuote,
    phase: InitialPhase,
    hello_slot: Option<Rc<RefCell<Option<OriginalHelloJournal>>>>,
    discovery: Option<OriginalPacketHostInitialResponse>,
    realization: Option<OriginalPacketHostInitialResponse>,
}

pub(crate) struct PacketCompleteInitialLifecycleIdentity {
    origin: Weak<OriginalHostSdkOrigin>,
    guard: OriginalHostInitialLifecycleGuardIdentity,
    socket: [u8; 32],
    hello_slot: Weak<RefCell<Option<OriginalHelloJournal>>>,
}

impl PacketCompleteInitialLifecycleIdentity {
    pub(crate) fn authenticate_original_source_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        self.origin
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?
            .ensure_current()?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.original_initial_lifecycle_inputs_data()?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if !marker.complete
            || !marker.initial_lifecycle_issued
            || !Weak::ptr_eq(&marker.origin, &self.origin)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn retained_requested_storage_data() -> usize {
        // These are actual Weak backing views, conservatively repeated even
        // when the holder also owns their strong allocations.
        NodeRuntime::capture_shared_allocation_storage::<OriginalHostSdkOrigin>()
            + crate::node_adapters::cnp::semantic::process::OriginalHostLaunchIdentity::retained_requested_storage_bound_data()
            + NodeRuntime::capture_shared_allocation_storage::<RefCell<Option<OriginalHelloJournal>>>()
    }

    fn authenticate_sdk_data(
        &self,
        sdk: &PacketCompleteOriginalHostSdk,
    ) -> Result<Rc<PacketCompleteSemanticSource>, RuntimeError> {
        let source = sdk.member.original_source_data()?;
        self.authenticate_original_source_data(&source)?;
        let origin = sdk.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        origin.ensure_current()?;
        if !Weak::ptr_eq(&self.origin, &Rc::downgrade(origin)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let state = sdk
            .initial_lifecycle
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&state.identity.origin, &self.origin)
            || state.identity.socket != self.socket
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(source)
    }
}

impl PacketCompleteOriginalHostSdk {
    fn authenticate_initial_originals_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        launch: &PacketNative5SourceLaunch,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        let original = self.member.original_source_data()?;
        if !Rc::ptr_eq(&original, source) || !self.prepared || self.connecting {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.member.authenticate_original_plan_data(plan)?;
        source.authenticate_native_launch_data(launch)?;
        self.origin
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .ensure_current()?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.original_initial_lifecycle_inputs_data()?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if !marker.complete
            || !Weak::ptr_eq(
                &marker.origin,
                &Rc::downgrade(self.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?),
            )
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn original_initial_lifecycle_outstanding_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        launch: &PacketNative5SourceLaunch,
        plan: &InstalledConformancePlan,
        include_pending_host: bool,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_initial_originals_data(source, launch, plan)?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let prior = self.member.remaining_initial_lifecycle_commitments_data(
            include_pending_host && !self.connected && !marker.initial_lifecycle_issued,
        )?;
        let initial = if marker.initial_lifecycle_completed {
            0
        } else {
            marker
                .initial_lifecycle_quote
                .map(|quote| quote.requested_peak_data())
                .transpose()?
                .unwrap_or(0)
        };
        sum(&[prior, initial])
    }

    pub(crate) fn original_initial_lifecycle_quote_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        launch: &PacketNative5SourceLaunch,
        plan: &InstalledConformancePlan,
        guard: &CnpSemanticLaunchGuard,
        role: &InstalledCnpConformanceRole,
        socket: &Path,
        maximum: usize,
    ) -> Result<PacketCompleteInitialLifecycleQuote, RuntimeError> {
        self.authenticate_initial_originals_data(source, launch, plan)?;
        if self.initial_lifecycle.is_some() || self.connected {
            return Err(RuntimeError::DuplicateOperation);
        }
        validate_socket(socket)?;
        role.authenticate_original_initial_lifecycle_source_data(source, plan)?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if marker.initial_lifecycle_issued {
            return Err(RuntimeError::DuplicateOperation);
        }
        marker
            .launch
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retain_initial_lifecycle_data(guard, source)?;
        let sdk = self
            .sdk
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .quote_original_initial_lifecycle_storage_data(launch)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let quote = PacketCompleteInitialLifecycleQuote {
            sdk,
            source: source.original_initial_source_storage_data(
                usize::try_from(launch.limits.frame_bytes.get())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Some(&sdk),
                maximum,
            )?,
            guard_window: self.member.original_initial_guard_window_data(),
        };
        if quote.requested_peak_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_initial_originals_data(source, launch, plan)?;
        Ok(quote)
    }

    pub(crate) fn retain_original_initial_lifecycle_issue_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        launch: &PacketNative5SourceLaunch,
        guard: &CnpSemanticLaunchGuard,
        role: &InstalledCnpConformanceRole,
        socket: &Path,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
        quote: PacketCompleteInitialLifecycleQuote,
    ) -> Result<PacketCompleteInitialLifecycleIdentity, RuntimeError> {
        self.authenticate_initial_originals_data(source, launch, plan)?;
        role.authenticate_original_initial_lifecycle_source_data(source, plan)?;
        validate_socket(socket)?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let mut marker = birth
            .host_startup
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if marker.initial_lifecycle_issued || self.initial_lifecycle.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if registered_hello
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let identity = PacketCompleteInitialLifecycleIdentity {
            origin: Weak::clone(&marker.origin),
            guard: marker
                .launch
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .retain_initial_lifecycle_data(guard, source)?,
            socket: *blake3::hash(socket.as_os_str().as_bytes()).as_bytes(),
            hello_slot: Rc::downgrade(registered_hello),
        };
        // Source-owned sticky state precedes returning the action. The private
        // SDK state is installed by the mutable consume before the first effect.
        marker.initial_lifecycle_quote = Some(quote);
        marker.initial_lifecycle_issued = true;
        Ok(identity)
    }

    pub(crate) fn begin_original_initial_lifecycle_data(
        &mut self,
        identity: &PacketCompleteInitialLifecycleIdentity,
        quote: PacketCompleteInitialLifecycleQuote,
    ) -> Result<(), RuntimeError> {
        if self.initial_lifecycle.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let source = self.member.original_source_data()?;
        identity.authenticate_original_source_data(&source)?;
        let origin = self.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&identity.origin, &Rc::downgrade(origin)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.initial_lifecycle = Some(OriginalInitialLifecycleState {
            identity: PacketCompleteInitialLifecycleIdentity {
                origin: Weak::clone(&identity.origin),
                guard: identity.guard.clone(),
                socket: identity.socket,
                hello_slot: Weak::clone(&identity.hello_slot),
            },
            quote,
            phase: InitialPhase::Issued,
            hello_slot: None,
            discovery: None,
            realization: None,
        });
        Ok(())
    }

    pub(crate) fn acquire_original_initial_socket_into(
        &mut self,
        identity: &PacketCompleteInitialLifecycleIdentity,
        quote: PacketCompleteInitialLifecycleQuote,
        guard: &CnpSemanticLaunchGuard,
        socket: &Path,
        completed: &mut Option<UnixStream>,
    ) -> Result<(), RuntimeError> {
        if self.initial_lifecycle.is_none() {
            self.begin_original_initial_lifecycle_data(identity, quote)?;
        }
        let source = identity.authenticate_sdk_data(self)?;
        validate_socket(socket)?;
        if identity.socket != *blake3::hash(socket.as_os_str().as_bytes()).as_bytes()
            || completed.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let state = self
            .initial_lifecycle
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.phase != InitialPhase::Issued {
            return Err(RuntimeError::DuplicateOperation);
        }
        state.phase = InitialPhase::SocketStarted;
        let call = identity.guard.begin_socket(guard, &source)?;
        self.sdk
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .acquire_original_initial_socket_into(socket, completed)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        call.complete()?;
        identity.authenticate_sdk_data(self)?;
        self.initial_lifecycle
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .phase = InitialPhase::SocketReady;
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Counts the fixed Source, provider and guard initial-lifecycle counters.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow before the first data walk.
    pub fn original_initial_lifecycle_counter_scratch_data() -> Result<usize, RuntimeError> {
        sum(&[
            Self::original_initial_source_counter_scratch_data(),
            original_packet_host_initial_lifecycle_counter_scratch_data(),
            original_packet_host_initial_socket_counter_scratch_data(),
            crucible_node_provider::client::original_packet_host_descriptor_counter_scratch_data(),
            CnpSemanticLaunchGuard::original_initial_lifecycle_storage_counter_scratch_data(),
            InstalledCnpConformanceRole::retained_requested_storage_counter_scratch_data(),
            Self::original_report_startup_observer_scratch_data(),
            crucible_node_provider::connection::OriginalProtocolSupervisor::retention_counter_scratch_data(),
            // The retained witness owns only existing actor/supervisor Rc
            // aliases; its Option lives in the already admitted native root.
            // Its constructor result and mutable slot loan are separate scratch.
            size_of::<crucible_node_provider::connection::OriginalProtocolSupervisor>(),
            size_of::<Result<
                crucible_node_provider::connection::OriginalProtocolSupervisor,
                ProviderError,
            >>(),
            size_of::<std::cell::RefMut<
                'static,
                Option<crucible_node_provider::connection::OriginalProtocolSupervisor>,
            >>(),
            size_of::<Result<
                std::cell::RefMut<
                    'static,
                    Option<crucible_node_provider::connection::OriginalProtocolSupervisor>,
                >,
                std::cell::BorrowMutError,
            >>(),
            size_of::<&CnpController>(),
            size_of::<Result<&CnpController, RuntimeError>>(),
            size_of::<PacketCompleteInitialLifecycleIdentity>(),
            size_of::<PacketCompleteInitialLifecycleQuote>(),
            size_of::<OriginalInitialLifecycleState>(),
            // quote_data keeps its outer birth/marker loans while the nested
            // Source projection takes its own birth loan (counted there).
            // Issue uses the same outer birth plus a mutable marker loan in
            // a later phase, so take the larger actual marker header.
            size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>(),
            size_of::<std::cell::Ref<'static, Option<OriginalHostStartupMarker>>>()
                .max(size_of::<
                    std::cell::RefMut<'static, Option<OriginalHostStartupMarker>>,
                >()),
            size_of::<[usize; 3]>(),
            size_of::<blake3::Hasher>(),
        ])
    }
}

fn validate_socket(socket: &Path) -> Result<(), RuntimeError> {
    let raw = socket.as_os_str().as_bytes();
    if !socket.is_absolute() || raw.is_empty() || raw.len() >= 108 || raw.contains(&0) {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

fn sum(values: &[usize]) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or(RuntimeError::ResourceLimit)
    })
}

impl PacketCompleteInitialLifecycleIdentity {
    pub(crate) fn revoke(&self) {
        self.guard.revoke();
    }

    pub(crate) fn authenticate_original_guard_current(
        &self,
        guard: &CnpSemanticLaunchGuard,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_source_data(source)?;
        self.guard.authenticate_current(guard, source)
    }

    pub(crate) fn authenticate_original_preparation_current(
        &self,
        preparation: &CnpSemanticPreparation,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_guard_current(&preparation.guard, source)
    }
}

impl PacketCompleteOriginalHostSdk {
    pub(crate) fn connect_original_initial_lifecycle_into(
        &mut self,
        identity: &PacketCompleteInitialLifecycleIdentity,
        guard: &CnpSemanticLaunchGuard,
        stream: &mut Option<UnixStream>,
        operational: &Rc<dyn crucible_node_provider::connection::ConnectionSupervisor>,
        supervisor: &OriginalRetainedSupervisor,
    ) -> Result<(), RuntimeError> {
        let source = identity.authenticate_sdk_data(self)?;
        identity.guard.authenticate_current(guard, &source)?;
        let state = self
            .initial_lifecycle
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.phase != InitialPhase::SocketReady {
            return Err(RuntimeError::DuplicateOperation);
        }
        state.phase = InitialPhase::HelloStarted;
        self.connect_original_into(guard, stream, operational, supervisor)?;
        identity.authenticate_sdk_data(self)?;
        identity.guard.authenticate_current(guard, &source)?;
        self.initial_lifecycle
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .phase = InitialPhase::HelloReady;
        Ok(())
    }

    pub(crate) fn prepare_original_initial_lifecycle_into(
        &mut self,
        identity: &PacketCompleteInitialLifecycleIdentity,
        launch: &PacketNative5SourceLaunch,
        plan: &InstalledConformancePlan,
        guard: &mut Option<CnpSemanticLaunchGuard>,
        role: &mut Option<InstalledCnpConformanceRole>,
        supervisor: &OriginalRetainedSupervisor,
        planned_admit: &crucible_node_contract::Id,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
        completed: &mut Option<CnpSemanticPreparation>,
        admitted: &mut Option<ResponseBody>,
        registry: &mut Option<OriginalExtensionRegistryOwner>,
        currency: &mut impl FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let source = identity.authenticate_sdk_data(self)?;
        self.authenticate_initial_originals_data(&source, launch, plan)?;
        if completed.is_some()
            || admitted.is_some()
            || registry.is_some()
            || !Weak::ptr_eq(&identity.hello_slot, &Rc::downgrade(registered_hello))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual_guard = guard.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        identity.guard.authenticate_current(actual_guard, &source)?;
        role.as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_initial_lifecycle_source_data(&source, plan)?;
        let state = self
            .initial_lifecycle
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.phase != InitialPhase::HelloReady {
            return Err(RuntimeError::DuplicateOperation);
        }
        let _diagnostics = crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::begin();
        state.phase = InitialPhase::AttachmentStarted;
        state.hello_slot = Some(Rc::clone(registered_hello));
        let mut sink = InitialAttachmentSink {
            identity,
            source: &source,
            launch,
            guard,
            registered_hello,
            currency,
        };
        self.sdk
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .attach_original_initial_lifecycle_into(launch, &state.quote.sdk, supervisor, &mut sink)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        // Attachment already moved the real Controller into retained native
        // custody. Keep its supervisor/actor aliases there before any later
        // Source callback; collecting-node admission needs this SAME witness
        // before Capture's later Owned11 path can ever run.
        {
            let native = guard
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .custody()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            let controller = native
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let mut witness = native
                .protocol_supervisor
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if witness.is_some() {
                return Err(RuntimeError::DuplicateOperation);
            }
            *witness = Some(
                controller
                    .retain_original_protocol_supervisor()
                    .map_err(|_| RuntimeError::ForeignAuthority)?,
            );
        }
        state.phase = InitialPhase::Attached;

        // The registry alias comes from the same actual attached typed
        // Handshake and is retained before any later Source/authority callback.
        *registry = Some(
            guard
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .custody()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .original_extension_registry_metadata_owner()
                .map_err(|_| RuntimeError::OwnerUnavailable)?,
        );
        identity.guard.authenticate_current(
            guard.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            &source,
        )?;
        state.phase = InitialPhase::Preparing;
        let original_guard = guard.take().ok_or(RuntimeError::OwnerUnavailable)?;
        let original_role = match role.take() {
            Some(role) => role,
            None => {
                *guard = Some(original_guard);
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        match CnpSemanticPreparation::prepare_original_initial_selected(
            original_guard,
            original_role,
            &mut state.discovery,
            &mut state.realization,
        ) {
            Ok(preparation) => *completed = Some(preparation),
            Err(failure) => {
                *guard = Some(failure.guard);
                return Err(RuntimeError::OwnerUnavailable);
            }
        }
        state.phase = InitialPhase::Prepared;
        let preparation = completed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        // Preparation is in its retained slot before original realization
        // callbacks, association normalization, private MAC and once-Admit.
        preparation
            .reauthenticate()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        currency()?;
        identity.authenticate_original_preparation_current(preparation, &source)?;
        state.phase = InitialPhase::Admitting;
        preparation
            .call_original_initial_canonical_ack_admit_into(
                &source,
                planned_admit.clone(),
                admitted,
            )
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        preparation
            .retain_original_canonical_ack_world_admission(&source)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        currency()?;
        identity.authenticate_original_preparation_current(preparation, &source)?;
        preparation.authenticate_original_fresh_query_preparation_data(&source)?;
        state.phase = InitialPhase::Completed;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let mut marker = birth
            .host_startup
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&marker.origin, &identity.origin) {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Construction has genuinely finished and all actual result owners now
        // appear in the terminal census. Retire its future construction row,
        // even if the separate whole-policy requery subsequently quarantines it.
        marker.initial_lifecycle_completed = true;
        Ok(())
    }
}

struct InitialAttachmentSink<'a, F> {
    identity: &'a PacketCompleteInitialLifecycleIdentity,
    source: &'a Rc<PacketCompleteSemanticSource>,
    launch: &'a PacketNative5SourceLaunch,
    guard: &'a mut Option<CnpSemanticLaunchGuard>,
    registered_hello: &'a Rc<RefCell<Option<OriginalHelloJournal>>>,
    currency: &'a mut F,
}

impl<F: FnMut() -> Result<(), RuntimeError>> OriginalPacketHostInitialAttachmentSink
    for InitialAttachmentSink<'_, F>
{
    fn authenticate_original_attachment_data(
        &mut self,
        scope: &OriginalPacketHostInitialAttachmentScope<'_>,
    ) -> Result<(), ProviderError> {
        self.identity
            .authenticate_original_source_data(self.source)
            .map_err(raw_refusal)?;
        (self.currency)().map_err(raw_refusal)?;
        let guard = self
            .guard
            .as_ref()
            .ok_or(ProviderError::Correlation("original initial guard absent"))?;
        self.identity
            .guard
            .authenticate_current(guard, self.source)
            .map_err(raw_refusal)?;
        let native = guard.custody()?;
        let install = self.source.installation();
        let authority = scope.authority_data()?;
        if scope.selection_data()? != &self.launch.selection
            || authority.session_id() != &install.binding.authority.session_id
            || authority.incarnation_id() != &install.binding.authority.incarnation_id
            || scope.peer_pid_data()? != native.provider_pid()
            || scope.peer_executable_data()?
                != self
                    .source
                    .original_host_sdk_executable_data()
                    .map_err(raw_refusal)?
            || self
                .registered_hello
                .try_borrow()
                .map_err(|_| ProviderError::Correlation("original Hello slot busy"))?
                .is_some()
        {
            return Err(ProviderError::Correlation(
                "original initial attachment differs",
            ));
        }
        self.identity
            .authenticate_original_source_data(self.source)
            .map_err(raw_refusal)
    }

    fn retain_original_attachment_into(
        &mut self,
        controller: &mut Option<CnpController>,
        handshake: &mut Option<ExtensionHandshake>,
        hello: &mut Option<OriginalHelloJournal>,
    ) -> Result<(), ProviderError> {
        self.identity
            .authenticate_original_source_data(self.source)
            .map_err(raw_refusal)?;
        if hello.is_none() {
            return Err(ProviderError::Correlation("original initial Hello absent"));
        }
        let mut registered = self
            .registered_hello
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("original Hello slot busy"))?;
        if registered.is_some() {
            return Err(ProviderError::Correlation("original Hello slot occupied"));
        }
        self.guard
            .as_mut()
            .ok_or(ProviderError::Correlation("original initial guard absent"))?
            .attach_extensions_owned(controller, handshake)?;
        // No callback or fallible work separates these original owner moves.
        *registered = hello.take();
        Ok(())
    }
}

fn raw_refusal(_: RuntimeError) -> ProviderError {
    ProviderError::Correlation("original installed host lifecycle refused")
}

impl PacketCompleteInitialLifecycleIdentity {
    pub(crate) fn authenticate_original_preparation_data(
        &self,
        preparation: &CnpSemanticPreparation,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        registered_hello: &Rc<RefCell<Option<OriginalHelloJournal>>>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_source_data(source)?;
        if !Weak::ptr_eq(&self.hello_slot, &Rc::downgrade(registered_hello)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.guard.authenticate_data(&preparation.guard, source)?;
        preparation.authenticate_original_fresh_query_preparation_data(source)?;
        preparation.authenticate_original_fresh_query_plan_data(plan)
    }
}

impl PacketCompleteOriginalHostSdk {
    pub(crate) fn authenticate_original_initial_completed_data(
        &self,
        identity: &PacketCompleteInitialLifecycleIdentity,
    ) -> Result<(), RuntimeError> {
        let source = identity.authenticate_sdk_data(self)?;
        let state = self
            .initial_lifecycle
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.phase != InitialPhase::Completed
            || state.discovery.is_none()
            || state.realization.is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !marker
            .as_ref()
            .is_some_and(|marker| marker.initial_lifecycle_completed)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }
}

impl PacketCompleteOriginalHostSdk {
    /// Counts the same actual opaque SDK's retained descriptor slots as data.
    ///
    /// Partial Hello writer, reader and spare owners remain counted. This view
    /// creates no descriptor and supplies no socket or method authority.
    ///
    /// # Errors
    /// Refuses another creator/Source/origin, absent SDK or counter overflow.
    pub fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        let source = self.member.original_source_data()?;
        source.storage_origin_with_error::<RuntimeError>()?;
        self.origin
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .ensure_current()?;
        self.sdk
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_descriptor_count_data()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

impl PacketCompleteOriginalHostSdk {
    pub(crate) fn original_initial_lifecycle_pending_descriptor_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let source = self.member.original_source_data()?;
        self.origin
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .ensure_current()?;
        let birth = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let marker = birth
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(
            &marker.origin,
            &Rc::downgrade(self.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?),
        ) {
            return Err(RuntimeError::ForeignAuthority);
        }
        if marker.initial_lifecycle_completed {
            return Ok(0);
        }
        // Closed197+331 chronology: one acquired socket, then either one
        // temporary executable File before clone, or one cloned Hello reader.
        // Those phases are sequential; partial Hello can retain both sockets.
        // Source/authority transient opens are independently conjoined by the
        // actual holder resource row, with no subtraction of current owners.
        Ok(2)
    }
}

impl OriginalInitialLifecycleState {
    pub(super) fn retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut total = PacketCompleteInitialLifecycleIdentity::retained_requested_storage_data();
        if let Some(slot) = &self.hello_slot {
            total = sum(&[
                total,
                NodeRuntime::capture_shared_allocation_storage::<
                    RefCell<Option<OriginalHelloJournal>>,
                >(),
            ])?;
            let journal = slot.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(journal) = journal.as_ref() {
                total = sum(&[total, PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &journal.original_retained_metadata_facts().map_err(|_| RuntimeError::ForeignAuthority)?, maximum,
                )?])?;
            }
        }
        for original in [&self.discovery, &self.realization].into_iter().flatten() {
            total = sum(&[
                total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &original
                        .original_retained_metadata_facts()
                        .map_err(|_| RuntimeError::UnsupportedFacet)?,
                    maximum,
                )?,
            ])?;
        }
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }
}

impl PacketCompleteOriginalHostSdk {
    /// Borrows outstanding original commitments after this same lifecycle completes.
    ///
    /// This authenticates exact Source/launch/plan and completed private state
    /// without invoking live currentness or an authority callback. The actual
    /// current owners remain a separate row. Consumed initial construction is
    /// retired only by its original nonrenewing marker, never by caller labels.
    /// This DATA neither renews a window nor permits common construction.
    ///
    /// # Errors
    /// Refuses foreign, busy, incomplete or inconsistent original owners.
    pub fn original_completed_initial_commitments_storage_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        launch: &PacketNative5SourceLaunch,
        plan: &InstalledConformancePlan,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_initial_originals_data(source, launch, plan)?;
        let state = self
            .initial_lifecycle
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.phase != InitialPhase::Completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        {
            let birth = source
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let marker = birth
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .host_startup
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if !marker
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .initial_lifecycle_completed
            {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        self.original_initial_lifecycle_outstanding_data(source, launch, plan, false)
    }
}

#[path = "initial_lifecycle/settled17.rs"]
mod settled17;
