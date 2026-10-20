//! Retains one purpose-closed Client retirement and signed HELLO turn.
//!
//! The Security owner keeps the actual Session Journal, floor, endpoint and
//! transport through the sole native kernel. Its private context borrows either
//! the original J/Cache pair or the genuine postterminal C23 and originating B.
//! The completed association remains on that same original. No caller can
//! select this context from DATA or derive request authority from HELLO.

mod context;
use context::ClientSessionContextV1;

use std::error::Error;
use std::mem::size_of;
use std::path::{Component, Path};

use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1;
use aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, RecordBindingErrorCategory, SeqpacketSocket, StorageSeqpacketEndAttemptV1,
    StorageSeqpacketSessionOriginV1,
};

use crate::cache_residency::OriginalCreateStorageCacheLoanV1;
use crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1;
use crate::journal::broker_session_receiving::{
    CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1, StorageSessionGeometryRefusalV1,
    initialization_demand, storage_retained_current_replay_demand_v1,
    storage_retained_traffic_reconstruction_demand_v1,
    storage_client_checkpoint_verification_demand_v1,
    handshake_flight_demand, StorageHandshakeEndpointV1,
    fixed_handshake_receiving_demand, StorageHandshakePrivateFootprintV1,
};
use crate::journal::{
    CreateStorageWriterPositionOriginalV1, JournalError, ProtectedJournalPreopenReplayExtentV1,
    StorageNativeOpeningOwnerLinkV1,
};
use super::cache_receiving::{
    CacheControlOriginalsV1, CacheCurrentnessOriginalV1, OriginalCacheAssociationV1,
};
use super::production::OriginalCreateStorageReadyV1;
use super::*;

/// Reports a closed Client turn whose actual originals remain resident.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Create Storage Client turn is closed; its actual custody remains resident")]
pub struct CreateStorageClientSessionClosedV1;

/// Describes the actual shared selected endpoint revalidation footprint.
///
/// The Security owner's private actual-type supplier produces these four named
/// amounts. The closed arming entry compares them to the SAME J-admitted shape
/// before allocation. This DATA has no account, authority or admission effect.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageEndpointRevalidationShapeDataV1 {
    /// Additional temporary inline bytes outside actual upper owner sizeof terms.
    pub inline_bytes: usize,
    /// Actual retained buffers, paths and collection backing bytes.
    pub heap_bytes: usize,
    /// Simultaneous current/failed fresh descriptors under the real roster.
    pub file_descriptors: usize,
    /// Simultaneously retained metadata/control cells.
    pub metadata_cells: usize,
}

impl CreateStorageEndpointRevalidationShapeDataV1 {
    /// Converts the four passive actual-type extents with checked arithmetic.
    ///
    /// This creates comparison DATA only. It cannot reserve resources, change
    /// a ceiling, construct an original or admit any work. The genuine fixed
    /// role supplier remains responsible for its actual native geometry and
    /// same-original admission before allocation or IO.
    #[doc(hidden)]
    #[must_use]
    pub fn checked_demand_v1(self) -> Option<ResourceVector> {
        let memory = self.inline_bytes.checked_add(self.heap_bytes)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(self.file_descriptors).ok()?)
            .with(D::MetadataEntries, u64::try_from(self.metadata_cells).ok()?))
    }
}

/// Describes actual upper private carrier layouts without admitting any work.
///
/// The installed Security/Runtime caller derives these sizes from its actual
/// named Rust types. They cover inline layout only; raw HELLO/history/model and
/// Native descriptor growth have separate closed suppliers below. This DATA
/// cannot construct a genuine J loan, change a ceiling or make a payment.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct CreateStorageClientSessionShapeDataV1 {
    /// Size of the actual retained Runtime idle Session owner.
    pub runtime_idle_owner: usize,
    /// Size of the actual complete Security Session before retirement.
    pub old_security_session: usize,
    /// Size of the actual upper retirement attempt and all its Result slots.
    pub retirement_original: usize,
    /// Size of the actual retained narrow HELLO attempt.
    pub hello_original: usize,
    /// Size of the actual new retained Security Session.
    pub narrow_security_session: usize,
    /// Size of the actual upper retained send attempt.
    pub send_original: usize,
    /// Size of the actual upper retained receive attempt.
    pub receive_original: usize,
    /// Actual boxed retained handshake failure bytes from Security's own helper.
    pub retained_handshake_failure_bytes: usize,
    /// Actual retained handshake failure cells from Security's own helper.
    pub retained_handshake_failure_cells: usize,
    /// Actual client+broker HELLO bytes on the SAME pre-retirement checkpoint.
    /// This remains independent of an empty durable traffic prefix.
    pub retained_checkpoint_hello_bytes: usize,
    /// Actual shared selected endpoint revalidation geometry.
    pub endpoint_revalidation: CreateStorageEndpointRevalidationShapeDataV1,
    /// Actual shared selected process-evidence observations before HELLO work.
    pub process_evidence: CreateStorageEndpointRevalidationShapeDataV1,
    /// Actual separate main/sidecar floor named-currentness archive geometry.
    pub floor_revalidation: CreateStorageEndpointRevalidationShapeDataV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Fresh,
    Admitted,
    Retiring,
    Disposal,
    Retired,
    HelloAdmitted,
    HelloConnected,
    Complete,
    Failed,
}

impl Default for Phase {
    fn default() -> Self { Self::Fresh }
}

/// Actual ownership stays on the intake across short purpose borrows.
#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct ClientSessionOriginalsV1 {
    phase: Phase,
    pub(in crate::controller_resource_reservation::create_intake) provisioning_association: Option<Result<(), crate::CreateProvisioningClientSessionAssociationErrorV1>>,
    borrowed: bool,
    provisioning_cookie: Option<std::num::NonZeroU64>,
    closed: Option<CreateStorageClientSessionClosedV1>,
    association: Option<OriginalCacheAssociationV1>,
    upper_shape: Option<CreateStorageClientSessionShapeDataV1>,
    shared_peak: Option<Result<(), ResourceReservationErrorV1>>,
    peak_original_selected: bool,
    fixed_original_selected: bool,
    variable_original_selected: bool,
    endpoint_current: Option<Result<(), ResourceReservationErrorV1>>,
    endpoint_original_selected: bool,
    floor_current: Option<Result<(), ResourceReservationErrorV1>>,
    floor_original_selected: bool,
    hello_original_selected: bool,
    fixed_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    materialized_width: Option<Result<u64, JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    retained_replay: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    terminal_method: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    initialization: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    variable: Option<Result<(), ResourceReservationErrorV1>>,
    journal: Option<StorageNativeOpeningOwnerLinkV1>,
    old_origin: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    old_position: Option<super::super::history::CreateStorageWriterPositionV1>,
    preparation: ClientCurrentnessOriginalV1,
    capture_post: ClientCurrentnessOriginalV1,
    retirement_post: ClientCurrentnessOriginalV1,
    ended: Option<StorageSeqpacketEndAttemptV1>,
    end_binding: Option<Result<(), RecordBindingError>>,
    disposal_post: ClientCurrentnessOriginalV1,
    hello_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    hello_admission: Option<Result<(), ResourceReservationErrorV1>>,
    new_origin: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    different_origin: Option<Result<(), RecordBindingError>>,
    hello_join: Option<Result<(), ResourceReservationErrorV1>>,
    hello_before: ClientCurrentnessOriginalV1,
    hello_after: ClientCurrentnessOriginalV1,
    signed_profile: Option<Result<(), ResourceReservationErrorV1>>,
    completed_binding: Option<[u8; 32]>,
}

#[derive(Default)]
struct ClientCurrentnessOriginalV1 {
    control: CacheCurrentnessOriginalV1,
    session: CreateStorageWriterPositionOriginalV1,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
    socket: Option<Result<(), RecordBindingError>>,
}

impl ClientCurrentnessOriginalV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.control.failure().or_else(|| self.session.failure())
            .or_else(|| error(&self.binding)).or_else(|| error(&self.socket))
    }
}

#[derive(Debug, thiserror::Error)]
pub(in crate::controller_resource_reservation::create_intake) enum ClientSessionAssociationErrorV1 {
    #[error("actual completed Client association is unavailable or changed")]
    Closed,
    #[error("actual completed Client socket no longer matches")]
    Socket(#[source] RecordBindingError),
}

impl ClientSessionOriginalsV1 {
    fn close(&mut self) {
        self.phase = Phase::Failed;
        self.closed.get_or_insert(CreateStorageClientSessionClosedV1);
    }

    // Only actual later paid purposes under this same ready owner call this
    // comparison. It lends no writer/account and never creates a new original.
    pub(in crate::controller_resource_reservation::create_intake) fn require_completed_association_v1(
        &self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ClientSessionAssociationErrorV1> {
        if self.phase != Phase::Complete || self.failure().is_some()
            || self.completed_binding != Some(transcript.session_binding())
            || !aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(transcript)
            || !self.journal.as_ref().is_some_and(|link| link.matches_journal_v1(journal)) {
            return Err(ClientSessionAssociationErrorV1::Closed);
        }
        let origin = self.new_origin.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ClientSessionAssociationErrorV1::Closed)?;
        origin.require_same_socket(socket).map_err(ClientSessionAssociationErrorV1::Socket)
    }

    // The genuine C23 receiver alone consumes this completed Apply HELLO join.
    pub(in crate::controller_resource_reservation::create_intake) fn require_completed_provisioning_session_v1(
        &self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ClientSessionAssociationErrorV1> {
        self.require_completed_provisioning_data_v2(journal, transcript)?;
        let origin = self.new_origin.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ClientSessionAssociationErrorV1::Closed)?;
        origin.require_same_socket(socket).map_err(ClientSessionAssociationErrorV1::Socket)
    }

    // The native caller and later genuine Start borrower share this exact
    // passive association fold. It neither observes a socket nor grants IO.
    pub(in crate::controller_resource_reservation::create_intake)
    fn require_completed_provisioning_data_v2(
        &self,
        journal: &Journal,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ClientSessionAssociationErrorV1> {
        if self.phase != Phase::Complete || self.failure().is_some()
            || self.completed_binding != Some(transcript.session_binding())
            || !aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(transcript)
            || !self.journal.as_ref().is_some_and(|link| link.matches_journal_v1(journal)) {
            return Err(ClientSessionAssociationErrorV1::Closed);
        }
        Ok(())
    }

    // A distinct Start payer owns the returned complete native observation.
    // The same held origin is checked even if the passive association fails.
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_completed_provisioning_session_v2(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        upper: Result<(), ResourceReservationErrorV1>,
    ) -> Result<(), crate::StartResourceSessionCurrentnessErrorV4> {
        let data = upper.and_then(|()|
            self.require_completed_provisioning_data_v2(journal, transcript)
                .map_err(|_| ResourceReservationErrorV1::Conflict));
        let origin = self.new_origin.as_ref().and_then(|result| result.as_ref().ok());
        crate::StartResourceSessionCurrentnessErrorV4::observe_same_origin_v4(data, origin, socket)
    }

    // A completed operation's already-checked socket/transcript stay borrowed
    // at the upper caller. This pure comparison constrains its next receiving
    // sampler to the SAME intrinsic Journal without another native probe.
    pub(in crate::controller_resource_reservation::create_intake) fn require_completed_journal_v1(
        &self,
        journal: &Journal,
    ) -> Result<(), ClientSessionAssociationErrorV1> {
        if self.phase != Phase::Complete || self.failure().is_some()
            || !self.journal.as_ref().is_some_and(|link| link.matches_journal_v1(journal)) {
            return Err(ClientSessionAssociationErrorV1::Closed);
        }
        Ok(())
    }

    // A later genuine paid purpose checks the already resident endpoint
    // archive's actual shape. This neither arms it nor admits another turn.
    pub(super) fn require_completed_endpoint_shape_v1(
        &self,
        actual: CreateStorageEndpointRevalidationShapeDataV1,
    ) -> Result<(), ClientSessionAssociationErrorV1> {
        if self.phase != Phase::Complete || self.failure().is_some()
            || !self.upper_shape.is_some_and(|shape| shape.endpoint_revalidation == actual)
        {
            return Err(ClientSessionAssociationErrorV1::Closed);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn Error + 'static)>
    {
        self.failure_with_financial_v1(None)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure_with_financial_v1<'cause>(&'cause self, financial: Option<&'cause (dyn Error + 'static)>)
        -> Option<&'cause (dyn Error + 'static)>
    {
        let paid = |result: &'cause Option<Result<(), ResourceReservationErrorV1>>, selected: bool|
            error(result).map(|cause| if selected { financial.unwrap_or(cause) } else { cause });
        error(&self.provisioning_association).or_else(|| paid(&self.shared_peak, self.peak_original_selected)).or_else(|| error(&self.fixed_geometry)).or_else(|| paid(&self.fixed, self.fixed_original_selected))
            .or_else(|| self.preparation.failure())
            .or_else(|| error(&self.old_origin)).or_else(|| error(&self.metadata))
            .or_else(|| error(&self.materialized_width)).or_else(|| error(&self.extent))
            .or_else(|| error(&self.retained_replay)).or_else(|| error(&self.terminal_method))
            .or_else(|| error(&self.initialization)).or_else(|| paid(&self.variable, self.variable_original_selected))
            .or_else(|| self.capture_post.failure())
            .or_else(|| paid(&self.endpoint_current, self.endpoint_original_selected))
            .or_else(|| paid(&self.floor_current, self.floor_original_selected))
            .or_else(|| self.retirement_post.failure())
            .or_else(|| self.ended.as_ref().and_then(StorageSeqpacketEndAttemptV1::failure))
            .or_else(|| error(&self.end_binding)).or_else(|| self.disposal_post.failure())
            .or_else(|| error(&self.hello_geometry)).or_else(|| paid(&self.hello_admission, self.hello_original_selected))
            .or_else(|| error(&self.new_origin))
            .or_else(|| self.different_origin.as_ref().and_then(|result| result.as_ref().err())
                .filter(|cause| cause.category() != RecordBindingErrorCategory::OriginMismatch)
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| error(&self.hello_join)).or_else(|| self.hello_before.failure())
            .or_else(|| error(&self.signed_profile)).or_else(|| self.hello_after.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }
}

/// Borrows one genuine closed context for the shared retirement/HELLO kernel.
///
/// Its private constructor joins either original J/Cache or postterminal C23
/// to the same held Session. The Security caller retains the whole Session and
/// all partial flight owners through refusal. This finite borrower exposes no
/// raw writer, detached payer or request grant.
#[doc(hidden)]
#[must_use = "retain the genuine Client turn through actual IO and all independent posts"]
pub struct OriginalCreateStorageClientSessionV1<'turn, 'original, 'cache> {
    context: ClientSessionContextV1<'turn, 'original, 'cache>,
    completed: bool,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Borrows the finite original Client retirement/HELLO purpose once.
    ///
    /// This fixed entrance performs no IO or allocation. Only the same completed
    /// Cache Held and original J association can enter its subsequent paid work.
    ///
    /// # Errors
    /// Refuses another active/previous turn, failed originals or an incomplete
    /// Cache join. No history row or caller-built shape can construct this loan.
    #[doc(hidden)]
    pub fn borrow_client_session_once<'turn>(&'turn mut self)
        -> Result<OriginalCreateStorageClientSessionV1<'turn, 'original, 'cache>, CreateStorageClientSessionClosedV1>
    {
        if self.failure().is_some() || self.original.owner.client_session.borrowed
            || self.original.owner.client_session.phase != Phase::Fresh {
            return Err(CreateStorageClientSessionClosedV1);
        }
        let association = self.original.owner.cache_capture.currentness_association_v1()
            .map_err(|_| CreateStorageClientSessionClosedV1)?;
        self.original.owner.client_session.association = Some(association);
        self.original.owner.client_session.borrowed = true;
        Ok(OriginalCreateStorageClientSessionV1 {
            context: ClientSessionContextV1::Original {
                original: &mut self.original, cache: &mut self.cache,
            }, completed: false,
        })
    }
}

impl<'original, 'intake> crate::OriginalCreateProvisioningRootLoanV1<'original, 'intake> {
    /// Borrows this original's once-only postterminal Storage Client purpose.
    ///
    /// The Security constructor supplies its actual originating B and current
    /// Preparation Session; neither caller DATA nor a stored receipt can select
    /// this private context. All native effects remain in the shared kernel.
    ///
    /// # Errors
    /// Retains failed current/funding/completed-J association in the same C23
    /// destination and refuses any second borrower after entry or failure.
    #[doc(hidden)]
    pub fn borrow_storage_apply_client_once_v1<'turn>(
        &'turn mut self,
        initial: &'turn crate::ControllerInitialBrokerSessionReceivingV1,
        controller: &'turn Journal,
        session_journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        resident: ResourceVector,
    ) -> Result<OriginalCreateStorageClientSessionV1<'turn, 'original, 'intake>, CreateStorageClientSessionClosedV1> {
        let progress = self.client_progress_mut_v1();
        if progress.borrowed || progress.phase != Phase::Fresh {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.borrowed = true;
        let association = self.require_completed_preparation_session_v1(
            initial, controller, session_journal, socket, transcript, resident,
        );
        let progress = self.client_progress_mut_v1();
        progress.provisioning_association = Some(association);
        if !matches!(progress.provisioning_association, Some(Ok(()))) {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        let progress = self.client_progress_mut_v1();
        progress.journal = Some(session_journal.held_session_owner_link_v1());
        progress.provisioning_cookie = Some(socket.peer().socket_cookie());
        Ok(OriginalCreateStorageClientSessionV1 {
            context: ClientSessionContextV1::Provisioning {
                loan: self, controller, _initial: initial, resident,
            }, completed: false,
        })
    }
}

impl<'turn, 'original, 'cache> OriginalCreateStorageClientSessionV1<'turn, 'original, 'cache> {
    /// Builds the fixed HELLO selected by this genuine private purpose.
    ///
    /// # Errors
    /// Refuses a closed purpose or the existing canonical negotiation error.
    #[doc(hidden)]
    pub fn storage_client_hello_v1(&self) -> Result<
        aos_sandbox_broker_session_protocol::hello_message::BrokerClientHello,
        aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError,
    > {
        self.context.hello_v1()
    }

    /// Reports whether this purpose reuses its already-held positive archives.
    ///
    /// This is DATA from the private constructor, never a caller selector or
    /// permission to clear a failed endpoint or floor observation.
    #[doc(hidden)]
    #[must_use]
    pub fn requires_existing_currentness_archives_v1(&self) -> bool {
        self.context.is_provisioning_v1()
    }

    /// Borrows the actual original enrollment's node as comparison DATA.
    ///
    /// This projects no caller-supplied ID, renewed cutoff or policy authority.
    /// The closed shared HELLO caller compares the actual signed node to it.
    ///
    /// # Errors
    /// Refuses an incomplete/closed original J or an already failed Client turn.
    #[doc(hidden)]
    pub fn create_storage_node_data_v1(&self)
        -> Result<aos_sandbox_model::NodeId, CreateStorageClientSessionClosedV1>
    {
        if self.failure().is_some() {
            return Err(CreateStorageClientSessionClosedV1);
        }
        self.context.node_v1().map_err(|_| CreateStorageClientSessionClosedV1)
    }

    /// Borrows the SAME original accepted cutoff as comparison DATA.
    ///
    /// The actual accepted parent sampled this cutoff before this purpose.
    /// It is not a renewed boot Session deadline or a caller-supplied hint.
    ///
    /// # Errors
    /// Refuses missing/closed accepted identity or a failed Client turn.
    #[doc(hidden)]
    pub fn create_storage_original_cutoff_data_v1(&self)
        -> Result<u64, CreateStorageClientSessionClosedV1>
    {
        if self.failure().is_some() { return Err(CreateStorageClientSessionClosedV1); }
        self.context.cutoff_v1().map_err(|_| CreateStorageClientSessionClosedV1)
    }

    /// Pays fixed actual layouts and Native observation destinations before IO.
    ///
    /// # Errors
    /// Refuses missing/overflowed actual layout DATA or genuine J admission.
    /// The whole geometry/payment Results stay resident and close future work.
    #[doc(hidden)]
    pub fn admit_fixed_once(&mut self, upper: CreateStorageClientSessionShapeDataV1)
        -> Result<(), CreateStorageClientSessionClosedV1>
    {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::Fresh || progress.fixed.is_some() {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.upper_shape = Some(upper);
        let peak = self.context.require_peak_v1();
        let peak_selected = peak.is_err() && self.context.original_failure_present_v1();
        let progress = self.context.progress_mut_v1();
        progress.shared_peak = Some(peak);
        progress.peak_original_selected = peak_selected;
        if !matches!(progress.shared_peak, Some(Ok(()))) {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        let provisioning = self.context.is_provisioning_v1();
        let progress = self.context.progress_mut_v1();
        progress.fixed_geometry = Some(if provisioning {
            fixed_demand_for_context_v1(upper, true)
        } else { fixed_demand(upper) });
        let demand = progress.fixed_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied();
        let (result, selected) = match demand {
            Some(demand) => self.context.reserve_complete_v1(demand),
            None => (Err(ResourceReservationErrorV1::Conflict), false),
        };
        let progress = self.context.progress_mut_v1();
        progress.fixed = Some(result);
        progress.fixed_original_selected = selected;
        if matches!(progress.fixed, Some(Ok(()))) {
            progress.phase = Phase::Admitted;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Checks the exact genuine-J-paid endpoint shape before its closed arming.
    ///
    /// Security's sole Client arming entry supplies its actual private type
    /// geometry here, then allocates its passive observation archive. A changed
    /// caller amount cannot substitute for that real supplier or renew J.
    ///
    /// # Errors
    /// Refuses absent complete fixed/held-history admission, changed actual
    /// shape, prior financial/native failure or a different purpose phase.
    #[doc(hidden)]
    pub fn require_fixed_endpoint_preparation_v1(
        &mut self,
        actual: CreateStorageEndpointRevalidationShapeDataV1,
    ) -> Result<(), CreateStorageClientSessionClosedV1> {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::Retiring || progress.endpoint_current.is_some() || progress.failure().is_some()
            || !matches!(progress.fixed, Some(Ok(())))
            || !matches!(progress.variable, Some(Ok(())))
            || !progress.upper_shape.is_some_and(|shape| shape.endpoint_revalidation == actual) {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        let returned = self.context.require_current_v1();
        let selected = returned.is_err() && self.context.original_failure_present_v1();
        let progress = self.context.progress_mut_v1();
        progress.endpoint_current = Some(returned);
        progress.endpoint_original_selected = selected;
        if matches!(progress.endpoint_current, Some(Ok(()))) {
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Checks the exact genuine-J-paid floor shape before its closed arming.
    ///
    /// Security's sole floor arming entry supplies its actual private type
    /// geometry here, then allocates its passive observation archive. A changed
    /// caller amount cannot substitute for that real supplier or renew J.
    ///
    /// # Errors
    /// Refuses absent complete fixed/held-history admission, changed actual
    /// shape, prior financial/native failure or a different purpose phase.
    #[doc(hidden)]
    pub fn require_fixed_floor_preparation_v1(
        &mut self,
        actual: CreateStorageEndpointRevalidationShapeDataV1,
    ) -> Result<(), CreateStorageClientSessionClosedV1> {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::Retiring || progress.floor_current.is_some() || progress.failure().is_some()
            || !matches!(progress.fixed, Some(Ok(())))
            || !matches!(progress.variable, Some(Ok(())))
            || !progress.upper_shape.is_some_and(|shape| shape.floor_revalidation == actual) {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        let returned = self.context.require_current_v1();
        let selected = returned.is_err() && self.context.original_failure_present_v1();
        let progress = self.context.progress_mut_v1();
        progress.floor_current = Some(returned);
        progress.floor_original_selected = selected;
        if matches!(progress.floor_current, Some(Ok(()))) {
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Captures and admits the actual SAME held Client history before decoding.
    ///
    /// The Security owner passes its actual held writer/socket, never a reopened
    /// path or caller byte length. Independent already-paid currentness runs
    /// after metadata, geometry or variable-admission refusal.
    ///
    /// # Errors
    /// Retains native metadata, rooted names, socket, geometry, genuine J and
    /// independent C/Source/profile/clock failures in their chronological slots.
    #[doc(hidden)]
    pub fn capture_held_history_once(&mut self, journal: &Journal, socket: &SeqpacketSocket)
        -> Result<(), CreateStorageClientSessionClosedV1>
    {
        if self.context.progress_mut_v1().phase != Phase::Admitted {
            self.context.progress_mut_v1().close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        self.observe_site(journal, socket, Site::Preparation);
        let progress = self.context.progress_mut_v1();
        if progress.preparation.failure().is_some() {
            self.observe_site(journal, socket, Site::CapturePost);
            self.context.progress_mut_v1().close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.journal = Some(journal.held_session_owner_link_v1());
        progress.old_position = progress.preparation.session.position().ok();
        progress.old_origin = Some(socket.capture_storage_session_origin_v1());
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        progress.metadata = Some(metadata);
        progress.materialized_width = Some(journal.held_materialized_encoding_bytes_v1());
        progress.extent = match (progress.metadata.as_ref(), progress.materialized_width.as_ref()) {
            (Some(Ok(metadata)), Some(Ok(materialized))) => Some(
                crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                    limits, metadata.len().max(*materialized))),
            _ => None,
        };
        if let Some(Ok(extent)) = progress.extent.as_ref() {
            progress.retained_replay = Some(storage_retained_current_replay_demand_v1(extent));
            progress.terminal_method = Some((|| {
                let method = usize::try_from(extent.native_bytes).ok()
                    .and_then(AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let prior = storage_retained_traffic_reconstruction_demand_v1(extent)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                let request = usize::try_from(extent.native_bytes).ok()
                    .and_then(AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                // Request and terminal each retain a distinct actual preceding
                // traffic replay; neither borrows free credit from full replay.
                method.checked_add(prior).and_then(|value| value.checked_add(request))
                    .and_then(|value| value.checked_add(prior))
                    .map_err(|_| ResourceReservationErrorV1::Conflict)
            })());
            progress.initialization = Some(initialization_demand(extent));
        }
        let demand = (|| {
            if !matches!(progress.old_origin, Some(Ok(_))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let fixed = progress.fixed_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let retained_replay = progress.retained_replay.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let terminal_method = progress.terminal_method.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let initialization = progress.initialization.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = fixed.checked_add(retained_replay)
                .and_then(|value| value.checked_add(terminal_method))
                .and_then(|value| value.checked_add(initialization))
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(complete)
        })();
        let (result, selected) = match demand {
            Ok(demand) => self.context.reserve_complete_v1(demand),
            Err(cause) => (Err(cause), false),
        };
        let progress = self.context.progress_mut_v1();
        progress.variable = Some(result);
        progress.variable_original_selected = selected;
        // No positive-only J getter may suppress these already-paid posts.
        self.observe_site(journal, socket, Site::CapturePost);
        let progress = self.context.progress_mut_v1();
        if progress.failure().is_none() && matches!(progress.variable, Some(Ok(()))) {
            progress.phase = Phase::Retiring;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Runs the paid independent post after actual Security terminal qualification.
    ///
    /// The upper terminal remains Security-owned; this method grants no semantic
    /// authority and cannot substitute a digest for its canonical signed history.
    ///
    /// # Errors
    /// Refuses changed same-writer/socket/Cache/profile/clock/current positions.
    #[doc(hidden)]
    pub fn observe_retirement_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket)
        -> Result<(), CreateStorageClientSessionClosedV1>
    {
        if self.context.progress_mut_v1().phase != Phase::Retiring {
            self.context.progress_mut_v1().close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        self.observe_site(journal, socket, Site::RetirementPost);
        if self.failure().is_none() { Ok(()) } else {
            self.context.progress_mut_v1().close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Parks actual same-socket End and checks all fallible Native disposal posts.
    ///
    /// Security must still complete its exact terminal/floor/endpoint/peer posts
    /// before consuming the actual Session transport. The returned phase grants
    /// no replacement socket or Session and releases no ledger reservation.
    ///
    /// # Errors
    /// Retains incomplete/wrong-socket End, changed Journal/native names and all
    /// independent currentness failures. Refusal never returns a disposal phase.
    #[doc(hidden)]
    pub fn prepare_transport_disposal_once<'phase>(
        &'phase mut self, journal: &Journal, socket: &mut SeqpacketSocket,
    ) -> Result<CreateStorageClientPositiveDisposalV1<'phase, 'turn, 'original, 'cache>, CreateStorageClientSessionClosedV1> {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::Retiring || progress.ended.is_some()
            || progress.retirement_post.failure().is_some()
            || progress.retirement_post.binding.is_none() {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.ended = Some(socket.end_storage_session_retaining_v1());
        progress.end_binding = progress.ended.as_ref().map(|ended| ended.require_same_socket(socket));
        self.observe_site(journal, socket, Site::DisposalPost);
        let progress = self.context.progress_mut_v1();
        if progress.failure().is_some() || !progress.ended.as_ref().is_some_and(|end| end.is_complete()) {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.phase = Phase::Disposal;
        Ok(CreateStorageClientPositiveDisposalV1 { original: self, completed: false })
    }

    /// Admits the fixed three-record Client HELLO before a new connect or flight.
    ///
    /// # Errors
    /// Refuses missing actual old transport disposal, repeated entry, geometry
    /// overflow or genuine same-J admission. No request/Session grant is issued.
    #[doc(hidden)]
    pub fn admit_narrow_hello_once(&mut self) -> Result<(), CreateStorageClientSessionClosedV1> {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::Retired || progress.hello_admission.is_some() {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.hello_geometry = Some(handshake_flight_demand(StorageHandshakeEndpointV1::Client));
        let demand = (|| {
            let fixed = progress.fixed_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let retained_replay = progress.retained_replay.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let terminal_method = progress.terminal_method.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let initialization = progress.initialization.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let hello = progress.hello_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = fixed.checked_add(retained_replay).and_then(|value| value.checked_add(terminal_method))
                .and_then(|value| value.checked_add(initialization))
                .and_then(|value| value.checked_add(hello)).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(complete)
        })();
        let (result, selected) = match demand {
            Ok(demand) => self.context.reserve_complete_v1(demand),
            Err(cause) => (Err(cause), false),
        };
        let progress = self.context.progress_mut_v1();
        progress.hello_admission = Some(result);
        progress.hello_original_selected = selected;
        if matches!(progress.hello_admission, Some(Ok(()))) {
            progress.phase = Phase::HelloAdmitted;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Runs the paid negative entry post when no new usable socket exists.
    ///
    /// The upper closed Client entrant retains its actual connect/admission
    /// error and any partial native socket. This always closes the turn. The
    /// existing HelloBefore slot retains independent SAME-J/Cache/C/Source,
    /// rooted names/profile/clock Results without inventing a usable Socket.
    ///
    /// # Errors
    /// Always refuses after the already-paid independent observation; no
    /// positive Session/socket association, retry or completion can result.
    #[doc(hidden)]
    pub fn observe_failed_hello_entry_post_once(&mut self, journal: &Journal)
        -> Result<(), CreateStorageClientSessionClosedV1>
    {
        if self.context.progress_mut_v1().phase != Phase::HelloAdmitted {
            self.context.progress_mut_v1().close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        self.observe_site_with_optional_socket(journal, None, Site::HelloBefore);
        self.context.progress_mut_v1().close();
        Err(CreateStorageClientSessionClosedV1)
    }

    /// Captures the actual new socket while retaining the same old Journal owner.
    ///
    /// # Errors
    /// Refuses another Journal, an unchanged old socket, invalid new native
    /// origin or any actual already-paid independent currentness failure.
    #[doc(hidden)]
    pub fn capture_narrow_socket_once(&mut self, journal: &Journal, socket: &SeqpacketSocket)
        -> Result<(), CreateStorageClientSessionClosedV1>
    {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::HelloAdmitted || progress.new_origin.is_some() {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        progress.new_origin = Some(socket.capture_storage_session_origin_v1());
        // A successful capture above proves a current new socket. The old
        // intrinsic binding must differ; a failed capture is never evidence
        // that an arbitrary/closed descriptor became a new connection.
        progress.different_origin = progress.old_origin.as_ref().and_then(|result| result.as_ref().ok())
            .map(|old| old.require_same_socket(socket));
        progress.hello_join = Some(if matches!(progress.new_origin, Some(Ok(_)))
            && progress.different_origin.as_ref().is_some_and(|result| result.as_ref().err()
                .is_some_and(|cause| cause.category() == RecordBindingErrorCategory::OriginMismatch)) {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) });
        self.observe_site(journal, socket, Site::HelloBefore);
        let progress = self.context.progress_mut_v1();
        if matches!(progress.hello_join, Some(Ok(()))) && progress.failure().is_none() {
            progress.phase = Phase::HelloConnected;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Runs the single paid independent post after a failed connected HELLO.
    ///
    /// The actual upper failed reducer keeps the same writer/socket and raw
    /// failure. This uses its distinct HelloAfter destination and closes the
    /// operation unconditionally. It can never complete a signed association.
    ///
    /// # Errors
    /// Always refuses after observation. A previously entered final destination
    /// or closed operation performs no replacement IO and remains failed.
    #[doc(hidden)]
    pub fn observe_failed_narrow_hello_post_once(
        &mut self, journal: &Journal, socket: &SeqpacketSocket,
    ) -> Result<(), CreateStorageClientSessionClosedV1> {
        if self.context.progress_mut_v1().phase != Phase::HelloConnected {
            self.context.progress_mut_v1().close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        self.observe_site(journal, socket, Site::HelloAfter);
        self.context.progress_mut_v1().close();
        Err(CreateStorageClientSessionClosedV1)
    }

    /// Retains the verified exact narrow profile after the actual shared HELLO.
    ///
    /// Security still owns its complete signed transcript, subjects, checkpoint
    /// and same Journal/floor/endpoint. This pure profile comparison grants no
    /// first request and does not replace the existing monotone initial CAS.
    ///
    /// # Errors
    /// Refuses another signed profile, changed actual native association or any
    /// independent J/Cache/C/Source/profile/clock failure. The borrower remains
    /// unfinished on error; no original or ledger reservation is replaced.
    #[doc(hidden)]
    pub fn complete_narrow_hello_once(
        &mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), CreateStorageClientSessionClosedV1> {
        let progress = self.context.progress_mut_v1();
        if progress.phase != Phase::HelloConnected || progress.signed_profile.is_some() {
            progress.close();
            return Err(CreateStorageClientSessionClosedV1);
        }
        let correct_profile = self.context.matches_transcript_v1(transcript);
        let progress = self.context.progress_mut_v1();
        progress.signed_profile = Some(if correct_profile {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) });
        self.observe_site(journal, socket, Site::HelloAfter);
        let progress = self.context.progress_mut_v1();
        if progress.failure().is_none() && matches!(progress.signed_profile, Some(Ok(()))) {
            progress.completed_binding = Some(transcript.session_binding());
            progress.phase = Phase::Complete;
            self.completed = true;
            Ok(())
        } else {
            progress.close();
            Err(CreateStorageClientSessionClosedV1)
        }
    }

    /// Borrows the actual retained first Native cause without releasing owners.
    #[doc(hidden)]
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.context.failure_v1()
    }

    fn observe_site(&mut self, journal: &Journal, socket: &SeqpacketSocket, site: Site) {
        self.observe_site_with_optional_socket(journal, Some(socket), site);
    }

    fn observe_site_with_optional_socket(
        &mut self, journal: &Journal, socket: Option<&SeqpacketSocket>, site: Site,
    ) {
        self.context.observe_site_v1(journal, socket, site);
    }
}

#[derive(Clone, Copy)]
enum Site { Preparation, CapturePost, RetirementPost, DisposalPost, HelloBefore, HelloAfter }

/// Keeps the genuine borrower through actual transport disposal.
///
/// All fallible posts precede this phase. Its sole installed Security caller
/// must consume/drop the actual old socket, then invoke the infallible finish;
/// shutdown alone is insufficient. No account amount is refunded or reset.
#[doc(hidden)]
#[must_use = "dispose the actual old transport before infallibly finishing this phase"]
pub struct CreateStorageClientPositiveDisposalV1<'phase, 'turn, 'original, 'cache> {
    original: &'phase mut OriginalCreateStorageClientSessionV1<'turn, 'original, 'cache>,
    completed: bool,
}

impl CreateStorageClientPositiveDisposalV1<'_, '_, '_, '_> {
    /// Completes the private retirement after actual old socket disposal.
    ///
    /// This is an infallible custody move, not Native end validation, a policy
    /// grant, credit or permission to drop an earlier failed owner.
    #[doc(hidden)]
    pub fn complete_after_transport_disposal(mut self) {
        self.original.context.progress_mut_v1().phase = Phase::Retired;
        self.completed = true;
    }
}

impl Drop for CreateStorageClientPositiveDisposalV1<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed { self.original.context.progress_mut_v1().close(); }
    }
}

impl Drop for OriginalCreateStorageClientSessionV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.context.close_v1();
        }
    }
}

fn fixed_demand(upper_shape: CreateStorageClientSessionShapeDataV1)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    fixed_demand_for_context_v1(upper_shape, false)
}

fn fixed_demand_for_context_v1(upper_shape: CreateStorageClientSessionShapeDataV1, provisioning: bool)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    let upper = [upper_shape.runtime_idle_owner, upper_shape.old_security_session, upper_shape.retirement_original,
        upper_shape.hello_original, upper_shape.narrow_security_session, upper_shape.send_original, upper_shape.receive_original];
    if upper.contains(&0) { return Err(ResourceReservationErrorV1::Conflict); }
    // The short native borrower now contains the closed context enum. Price
    // both its actual return temporary and the caller's live stack destination.
    let borrower = size_of::<OriginalCreateStorageClientSessionV1<'_, '_, '_>>()
        .checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?;
    let native_inline = size_of::<ClientSessionOriginalsV1>()
        .checked_add(borrower).ok_or(ResourceReservationErrorV1::Conflict)?;
    let private_inline = upper.into_iter().try_fold(native_inline, |sum, bytes|
        sum.checked_add(bytes).ok_or(ResourceReservationErrorV1::Conflict))?;
    let resident = fixed_handshake_receiving_demand(StorageHandshakePrivateFootprintV1 {
        actual_inline_bytes: private_inline,
        actual_failure_bytes: upper_shape.retained_handshake_failure_bytes,
        actual_failure_cells: upper_shape.retained_handshake_failure_cells,
    }).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let roots = Path::new(CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1).components()
        .filter(|part| matches!(part, Component::Normal(_))).count()
        .checked_add(1).ok_or(ResourceReservationErrorV1::Conflict)?;
    // Six actual named sites retain their Vec backing/control results. A full
    // successful inner sample really drops its fresh Files; a failed primary
    // plus its one owed independent post is the simultaneous descriptor peak.
    let paths = roots.checked_mul(6 * 2 * size_of::<std::fs::File>())
        .and_then(|bytes| bytes.checked_add(6 * 2 * (aos_sandbox_journal::protected_storage::MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES + 5)))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let memory = paths;
    // The genuine closed entry proved the SAME original HistoryNames peak.
    // This purpose pays new cumulative backing/metadata, not the shared FD peak again.
    let shared = if provisioning { ResourceVector::ZERO } else {
        CacheCurrentnessOriginalV1::receiving_backing_demand_v1(6)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?
    };
    let files = u64::try_from(roots.checked_add(2).and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(1))
        .ok_or(ResourceReservationErrorV1::Conflict)?).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let metadata_cells = CreateStorageWriterPositionOriginalV1::controller_storage_client_receiving_metadata_cells_v1()
        .and_then(|cells| {
            if provisioning {
                cells.checked_mul(6)
            } else {
                cells.checked_add(2).and_then(|cells| cells.checked_mul(6))
                    .and_then(|cells| cells.checked_add(33))
            }.ok_or(JournalError::JournalTooLarge)
        })
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let native = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::OpenFiles, files)
        .with(D::MetadataEntries, u64::try_from(metadata_cells)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?);
    let endpoint = upper_shape.endpoint_revalidation.checked_demand_v1()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let floor = upper_shape.floor_revalidation.checked_demand_v1()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let process = upper_shape.process_evidence.checked_demand_v1()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let checkpoint = storage_client_checkpoint_verification_demand_v1(
        upper_shape.retained_checkpoint_hello_bytes,
    ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    resident.checked_add(native).and_then(|value| value.checked_add(shared))
        .and_then(|value| value.checked_add(endpoint))
        .and_then(|value| value.checked_add(floor))
        .and_then(|value| value.checked_add(process))
        .and_then(|value| value.checked_add(checkpoint))
        .map_err(|_| ResourceReservationErrorV1::Conflict)
}

fn error<E: Error + 'static, T>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn abandoned_native_phase_has_an_actual_retained_closed_cause() {
        let mut progress = ClientSessionOriginalsV1::default();
        assert!(progress.failure().is_none());

        progress.close();
        let first = progress.failure().unwrap()
            .downcast_ref::<CreateStorageClientSessionClosedV1>().unwrap()
            as *const CreateStorageClientSessionClosedV1;
        progress.close();

        assert_eq!(progress.phase, Phase::Failed);
        assert_eq!(progress.failure().unwrap()
            .downcast_ref::<CreateStorageClientSessionClosedV1>().unwrap() as *const _, first);
    }

    #[test]
    fn invoked_financial_refusal_borrows_the_same_original_after_closing() {
        let original = std::io::Error::other("retained original debit refusal");
        let mut progress = ClientSessionOriginalsV1::default();
        progress.endpoint_current = Some(Err(ResourceReservationErrorV1::Conflict));
        progress.endpoint_original_selected = true;

        progress.close();

        let selected = progress.failure_with_financial_v1(Some(&original)).unwrap();
        assert!(std::ptr::eq(selected.downcast_ref::<std::io::Error>().unwrap(), &original));
        assert!(progress.endpoint_current.as_ref().unwrap().is_err());
    }

    #[test]
    fn later_original_post_failure_cannot_replace_earlier_metadata_cause() {
        let directory = tempfile::tempdir().unwrap();
        let mut progress = ClientSessionOriginalsV1::default();
        progress.metadata = Some(std::fs::File::open(directory.path().join("absent-client-history"))
            .and_then(|file| file.metadata()));
        let first = progress.failure().unwrap().downcast_ref::<std::io::Error>().unwrap()
            as *const std::io::Error;
        let later = std::io::Error::other("later independently owed post refusal");

        progress.close();

        let selected = progress.failure_with_financial_v1(Some(&later)).unwrap();
        assert_eq!(selected.downcast_ref::<std::io::Error>().unwrap() as *const _, first);
        assert!(!std::ptr::eq(selected.downcast_ref::<std::io::Error>().unwrap(), &later));
    }

    #[test]
    fn closing_never_replaces_the_actual_earlier_native_metadata_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut progress = ClientSessionOriginalsV1::default();
        progress.metadata = Some(std::fs::File::open(directory.path().join("absent-client-history"))
            .and_then(|file| file.metadata()));
        let first = progress.failure().unwrap().downcast_ref::<std::io::Error>().unwrap()
            as *const std::io::Error;

        progress.close();

        assert_eq!(progress.failure().unwrap().downcast_ref::<std::io::Error>().unwrap()
            as *const _, first);
        assert!(progress.closed.is_some());
    }
}


impl ClientSessionOriginalsV1 {
    // Retains the paid planes of the real completed retirement/HELLO owner.
    // The fixed and reached native/schema bounds are deliberately conservative;
    // no old wire traffic becomes a new operation's debit or concurrency credit.
    pub(in crate::controller_resource_reservation::create_intake) fn completed_resident_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        use aos_sandbox_model::component_receiving::without_operation_traffic_v1;
        if self.phase != Phase::Complete || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let fixed = self.fixed_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let replay = self.retained_replay.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let terminal = self.terminal_method.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let initialization = self.initialization.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let hello = self.hello_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        [fixed, replay, terminal, initialization, hello].into_iter()
            .try_fold(ResourceVector::ZERO, |resident, plane| {
                resident.checked_add(without_operation_traffic_v1(*plane))
                    .map_err(Into::into)
            })
    }
}
