//! Consumes the installed host-construction action on the same original birth.
//!
//! The private Source marker is spent before the SDK partial owner is created.
//! The marker and holder retain one exact origin allocation; neither a data row
//! nor a reconstructed controller can replace it. No control-method permission
//! is inferred from successful SDK construction.

use std::{
    collections::BTreeMap,
    mem::size_of,
    rc::{Rc, Weak},
};

use crucible_node_format::ContentRef;
use crucible_node_transport::{
    client::{
        OriginalPacketHostStartup, PacketNativeHostStartupInputs,
        original_packet_host_startup_counter_scratch_data,
        original_packet_host_startup_storage_data,
    },
    reference_packet::service::PacketNative5SourceLaunch,
};

use super::*;
use crate::node_adapters::cnp::CnpSemanticSource;
use crate::{
    node_adapters::cnp::semantic::packet_complete_source::PacketCompleteSemanticSource,
    node_admission::{OriginalNativeHostStartupMember, OriginalNativeHostStartupQuote},
    node_contract::{NodeRuntime, RuntimeError},
};

type ContentBank = BTreeMap<ContentRef, Vec<u8>>;

#[path = "host_startup/metadata.rs"]
mod metadata;

#[path = "host_startup/initial_lifecycle.rs"]
mod initial_lifecycle;
pub(crate) use initial_lifecycle::{
    PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote,
};

/// Identifies the original process and thread of a Source-owned SDK attempt.
///
/// The Source marker and SDK holder retain the same allocation through Rc/Weak
/// handles. The provider SDK owns its separate internal origin marker.
struct OriginalHostSdkOrigin {
    pid: u32,
    thread: std::thread::ThreadId,
}

impl OriginalHostSdkOrigin {
    fn new() -> Self {
        Self {
            pid: std::process::id(),
            thread: std::thread::current().id(),
        }
    }

    fn ensure_current(&self) -> Result<(), RuntimeError> {
        if self.pid != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }

        Ok(())
    }
}

pub(super) struct OriginalHostStartupMarker {
    origin: Weak<OriginalHostSdkOrigin>,
    complete: bool,
    initial_lifecycle_issued: bool,
    initial_lifecycle_quote: Option<PacketCompleteInitialLifecycleQuote>,
    initial_lifecycle_completed: bool,
    launch: Option<crate::node_adapters::cnp::semantic::process::OriginalHostLaunchIdentity>,
}

impl OriginalHostStartupMarker {
    pub(super) fn retained_storage_data(&self) -> Result<usize, RuntimeError> {
        let facts = self.retained_capacity_data(None)?;
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            usize::MAX,
        )
    }
}

/// Retains a Source-authenticated original host SDK construction attempt.
///
/// This owner has no constructor, clone, decoder or controller extractor.
/// It supplies neither native completion nor preparation/capture rights.
#[must_use = "retain this original SDK attempt beside its same launch custody"]
pub struct PacketCompleteOriginalHostSdk {
    member: OriginalNativeHostStartupMember,
    origin: Option<Rc<OriginalHostSdkOrigin>>,
    sdk: Option<OriginalPacketHostStartup>,
    prepared: bool,
    connecting: bool,
    connected: bool,
    initial_lifecycle: Option<initial_lifecycle::OriginalInitialLifecycleState>,
}

impl PacketCompleteSemanticSource {
    /// Counts fixed Source and SDK constructor observer layouts before walking.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_host_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        [original_packet_host_startup_counter_scratch_data(),
            crate::node_adapters::cnp::CnpSemanticLaunchReservation::original_host_startup_counter_scratch_data(),
            Self::original_report_startup_observer_scratch_data(),
            size_of::<OriginalNativeHostStartupMember>(),
            size_of::<OriginalNativeHostStartupQuote>(),
            size_of::<PacketNativeHostStartupInputs<'static>>(),
            // The future origin and launch weak-view header quotes.
            size_of::<usize>(), size_of::<usize>(),
            size_of::<[u8; 32]>(), size_of::<blake3::Hasher>(),
            size_of::<std::cell::Ref<'static, OriginalAckPeerBirth>>(),
            size_of::<std::cell::RefMut<'static, Option<OriginalHostStartupMarker>>>(),
        ].into_iter().try_fold(0usize, |total, value| total.checked_add(value)
            .ok_or(RuntimeError::ResourceLimit))?
            .checked_add(crate::node_admission::NativeStartupRows::publication_phase_counter_scratch_data())
            .and_then(|bytes| bytes.checked_add(
                super::native_startup::OriginalNativeStartupFinalization::publication_rows_counter_scratch_data()
            ))
            .and_then(|bytes| bytes.checked_add(Self::original_native_host_barrier_authentication_scratch_data()))
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(crate) fn original_native_host_startup_quote_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        content: &Rc<ContentBank>,
        maximum: usize,
    ) -> Result<OriginalNativeHostStartupQuote, RuntimeError> {
        self.authenticate_native_launch_data(launch)?;
        self.original_complete_report_startup_retained_storage_precredit_data(maximum)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
        let native = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !native.complete
            || birth
                .host_startup
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        native.member.authenticate(self)?;
        let executable = self.original_host_sdk_executable_data()?;
        let sdk = original_packet_host_startup_storage_data(
            &PacketNativeHostStartupInputs {
                launch,
                registration: &birth.expected_host_registration,
                content,
                executable,
            },
            &birth.private_launch,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let marker_origin = OriginalHostStartupMarker::origin_capacity_requested_bound_data()?;
        let marker_launch = crate::node_adapters::cnp::semantic::process::OriginalHostLaunchIdentity::retained_capacity_requested_bound_data()?;
        let source_extra = size_of::<PacketCompleteOriginalHostSdk>()
            .checked_sub(size_of::<OriginalPacketHostStartup>())
            .ok_or(RuntimeError::ResourceLimit)?
            .checked_add(NodeRuntime::capture_shared_allocation_storage::<
                OriginalHostSdkOrigin,
            >())
            // Future weak views use the same header envelope as their census.
            .and_then(|bytes| bytes.checked_add(marker_origin))
            .and_then(|bytes| bytes.checked_add(marker_launch))
            .ok_or(RuntimeError::ResourceLimit)?;
        // Reuse the actual selected acquisition producer as a conservative
        // complete Source guard window. It names fixed stat/hash/path banks
        // and exact link/reference storage; baseline custody remains separate.
        let (guard_retained, guard_transient, guard_scratch) =
            crate::node_adapters::cnp::CnpSemanticLaunchReservation::
                quote_original_native_startup_acquisition_storage_data(executable, maximum)?;
        let source_guard_window = guard_retained
            .checked_add(guard_transient)
            .and_then(|bytes| bytes.checked_add(guard_scratch))
            // The existing private-directory fence may convert its actual
            // selected path (at most 4096 bytes) to a NUL-terminated OS path.
            .and_then(|bytes| bytes.checked_add(4097))
            .and_then(|bytes| bytes.checked_add(4 * size_of::<std::fs::Metadata>()))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<crucible_node_transport::client::ClientPeer>())
            })
            .and_then(|bytes| {
                bytes.checked_add(NodeRuntime::capture_reference_storage(executable).ok()?)
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        // Keep every native/report retained commitment, including the prior
        // conservative full native R sum. Their sequential temporary phases
        // share one same-Source peak; SDK constructor/Hello work remains summed
        // independently with that complete future commitment below.
        let publication = if birth.report_startup_required {
            birth
                .report_startup
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticated_rows_data(self)?
        } else {
            crate::node_admission::StartupRows::default()
        };
        // The completed same-Source native member already emitted its exact
        // selected initial row. Keep the broad member/current census intact;
        // do not charge future broad owners the actual native can never create.
        let publication = native.authenticated_publication_rows_data(self, publication)?;
        let native_and_publication_peak = native
            .member
            .rows
            .outstanding_peak_with_publication(publication, maximum)?;
        let prior_commitment_peak = native
            .member
            .host_launch_requested_bytes
            .checked_add(native.member.wire_requested_bytes)
            .and_then(|bytes| bytes.checked_add(native_and_publication_peak))
            .ok_or(RuntimeError::ResourceLimit)?;
        let quote = OriginalNativeHostStartupQuote::new(
            sdk,
            source_extra,
            source_guard_window,
            prior_commitment_peak,
        )?;
        if quote.requested_peak_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(quote)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_host_sdk_executable_data(
        &self,
    ) -> Result<&ContentRef, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let mut artifacts = self
            .installation()
            .provider
            .implementation
            .artifacts
            .iter()
            .filter(|artifact| artifact.role.as_str() == "executable");
        let executable = &artifacts
            .next()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .content;
        if artifacts.next().is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(executable)
    }

    pub(crate) fn prepare_original_native_host_sdk_into(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        content: &Rc<ContentBank>,
        member: OriginalNativeHostStartupMember,
        completed: &mut Option<PacketCompleteOriginalHostSdk>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        member.authenticate(self, content)?;
        let actual = self.original_native_host_startup_quote_data(launch, content, usize::MAX)?;
        if actual.prior_commitment_peak > member.quote.prior_commitment_peak
            || actual.sdk.retained_requested_bytes() > member.quote.sdk.retained_requested_bytes()
            || actual.sdk.maximum_simultaneous_transient_bytes()
                > member.quote.sdk.maximum_simultaneous_transient_bytes()
            || actual.sdk.declared_counter_scratch_bytes()
                > member.quote.sdk.declared_counter_scratch_bytes()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
        {
            let mut marker = birth
                .host_startup
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if marker.is_some() {
                return Err(RuntimeError::DuplicateOperation);
            }
            *marker = Some(OriginalHostStartupMarker {
                origin: Weak::new(),
                complete: false,
                initial_lifecycle_issued: false,
                initial_lifecycle_quote: None,
                initial_lifecycle_completed: false,
                launch: None,
            });
        }
        // The opaque member survives every subsequent refusal in this original
        // output slot. Re-query cannot issue a replacement after the marker.
        *completed = Some(PacketCompleteOriginalHostSdk {
            member,
            origin: None,
            sdk: None,
            prepared: false,
            connecting: false,
            connected: false,
            initial_lifecycle: None,
        });
        let original = completed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        original.origin = Some(Rc::new(OriginalHostSdkOrigin::new()));
        birth
            .host_startup
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .origin = Rc::downgrade(
            original
                .origin
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        );

        let nonce = blake3::derive_key(
            "source-owned.packet-native-host-sdk-challenge/1",
            &birth.key,
        );
        let inputs = PacketNativeHostStartupInputs {
            launch,
            registration: &birth.expected_host_registration,
            content,
            executable: self.original_host_sdk_executable_data()?,
        };
        OriginalPacketHostStartup::prepare_into(
            &inputs,
            &nonce,
            &birth.private_launch,
            original
                .member
                .quote
                .sdk
                .requested_peak_data()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            &mut original.sdk,
        )
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
        original.member.authenticate(self, content)?;
        let origin = original
            .origin
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        origin
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mut marker = birth
            .host_startup
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let marker = marker.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&marker.origin, &Rc::downgrade(origin)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        marker.complete = true;
        original.prepared = true;
        Ok(())
    }
}

impl PacketCompleteOriginalHostSdk {
    /// Observes its same actual Source member and retained SDK construction data.
    ///
    /// # Errors
    /// Refuses an expired source/plan/content/origin, partial SDK construction,
    /// conflicting metadata loans or requested-storage overrun.
    pub fn retained_requested_storage_precredit_data(
        &self,
        supervisor: Option<&crucible_node_transport::connection::OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let source = self.member.original_source_data()?;
        let content = self.member.original_content_data()?;
        self.member.authenticate(&source, &content)?;
        let origin = self.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        origin
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.prepared {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let sdk = self
            .sdk
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_requested_storage_data(supervisor)
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        let extra = size_of::<Self>()
            .checked_sub(size_of::<OriginalPacketHostStartup>())
            .and_then(|bytes| {
                bytes.checked_add(NodeRuntime::capture_shared_allocation_storage::<
                    OriginalHostSdkOrigin,
                >())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        let initial = self
            .initial_lifecycle
            .as_ref()
            .map(|state| state.retained_storage_precredit_data(maximum))
            .transpose()?
            .unwrap_or(0);
        let total = sdk
            .checked_add(initial)
            .and_then(|bytes| bytes.checked_add(extra))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.member.authenticate(&source, &content)?;
        Ok(total)
    }
}

impl OriginalAckPeerBirth {
    pub(super) fn bind_original_host_sdk_launch_data(
        &self,
        reservation: &crate::node_adapters::cnp::CnpSemanticLaunchReservation,
    ) -> Result<(), RuntimeError> {
        let mut marker = self
            .host_startup
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        // Old selected native-only launches have no SDK construction member.
        let Some(marker) = marker.as_mut() else {
            return Ok(());
        };
        if !marker.complete || marker.launch.is_some() || marker.origin.upgrade().is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        marker.launch = Some(reservation.original_host_launch_identity_data()?);
        Ok(())
    }
}

impl PacketCompleteOriginalHostSdk {
    /// Connects only the same selected reservation's genuine original Child.
    ///
    /// The full constructor action must already be complete in the installed
    /// holder. Original Source, read-owner, kernel, executable and registrar
    /// guards remain independent; no controller or method permit escapes.
    ///
    /// # Errors
    /// Refuses a foreign/repeated child, incomplete holder action, changed
    /// origin, failed Hello, unsupported backing or terminal currentness loss.
    /// Partial SDK owners remain here and uncertainty fences that read owner.
    pub fn connect_original_into(
        &mut self,
        actual: &crate::node_adapters::cnp::CnpSemanticLaunchGuard,
        stream: &mut Option<std::os::unix::net::UnixStream>,
        operational: &Rc<dyn crucible_node_transport::connection::ConnectionSupervisor>,
        supervisor: &crucible_node_transport::connection::OriginalRetainedSupervisor,
    ) -> Result<(), RuntimeError> {
        if !self.prepared || self.connecting || self.connected {
            return Err(RuntimeError::DuplicateOperation);
        }
        let source = self.member.original_source_data()?;
        let content = self.member.original_content_data()?;
        self.member.authenticate_for_connection(&source, &content)?;
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
        let origin = self.origin.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        origin
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !marker.complete || !Weak::ptr_eq(&marker.origin, &Rc::downgrade(origin)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let identity = marker
            .launch
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.connecting = true;
        let call = identity.begin(actual)?;
        let peer = call.peer_data()?;
        self.sdk
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .connect_into(
                stream,
                &peer,
                operational,
                supervisor,
                std::time::Duration::from_secs(60),
            )
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        self.member.authenticate_for_connection(&source, &content)?;
        // Terminal same-owner/kernel validation follows installed callbacks.
        call.complete()?;
        origin
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.connected = true;
        self.connecting = false;
        Ok(())
    }
}

#[path = "host_startup/settled17.rs"]
mod settled17;
