//! Retains enrolled Mount/Network request, native Session and sealed content.
//!
//! One actual request uses the shared record/admission engine. Its genuine
//! image-enrolled loan owns funding and purpose; the protected Session keeps
//! writer, keys, peer and transcript. This owner cannot be constructed from an
//! authenticated tuple, supplied response or a detached descriptor.

use super::*;
use std::os::fd::AsRawFd as _;
use aos_sandbox_broker::receiving::{FixedServiceOperationClosedV4, MountAttachmentAnchorReceivingLoanV4 as FixedServiceOperationLoanV4};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector, DecodeLimits, CanonicalAssignmentManifestV1};
use aos_sandbox_model::model::SandboxSpec;
use aos_sandbox_linux::immutable_file::{SealedMemfdReadOriginalV2, SealedMemfdReadClosedV2};
use aos_sandbox_protocol::semantics::network::{NetworkSemanticsError, preparation_content::{
    NetworkPreparationContentV2, network_preparation_models_receiving_obligations_v2,
    canonical_network_preparation_specification_v2,
}};
use crate::recovery::FixedServiceSessionPostOriginalV4;

/// Reports refusal while the original native and request owners stay resident.
#[derive(Debug, thiserror::Error)]
#[error("the original fixed-service request is closed")]
pub struct FixedServiceRequestClosedV4;

#[derive(Clone, Copy)]
enum Kind { MountAttachment, MountInventory, NetworkReceiving, NetworkPreparation, NetworkDestroy, NetworkInventory }

impl Kind {
    fn method(self) -> BrokerMethod {
        match self {
            Self::MountAttachment => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            Self::MountInventory => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            Self::NetworkPreparation => BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2,
            Self::NetworkDestroy => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            Self::NetworkInventory => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            Self::NetworkReceiving => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
        }
    }

    fn require_current(self, loan: &mut FixedServiceOperationLoanV4<'_>) -> Result<(), FixedServiceOperationClosedV4> {
        match self {
            Self::MountAttachment => loan.require_current_v4(),
            Self::MountInventory => loan.require_inventory_current_v4(),
            Self::NetworkReceiving | Self::NetworkPreparation | Self::NetworkDestroy | Self::NetworkInventory => loan.require_network_current_v4(),
        }
    }
}

#[derive(Clone, Copy)]
enum First { Funding, Before, Socket, SessionBefore, Readiness, Receipt, Replay, Content, SessionAfter, Order }

/// Keeps one actual enrolled request and both prearmed Session bookends.
///
/// The complete fixed price is joined before entry. `finish_native_once_v4`
/// remains independently owed after every entered outcome, after the domain
/// body and response attempt. The caller separately records its actual body
/// result and always finishes the genuine loan's native/paired afters.
pub struct FixedServiceRequestOriginalV4 {
    receipt: OriginalOutputServerReceiptV1,
    native: FixedServiceSessionPostOriginalV4,
    sealed: SealedMemfdReadOriginalV2,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    before: Option<Result<(), FixedServiceOperationClosedV4>>,
    socket: Option<Result<std::os::fd::RawFd, SeqpacketError>>,
    after_socket: Option<Result<std::os::fd::RawFd, SeqpacketError>>,
    native_before: Option<Result<(), BrokerSessionSecurityError>>,
    native_after: Option<Result<(), BrokerSessionSecurityError>>,
    current: Option<Result<(), FixedServiceOperationClosedV4>>,
    sealed_result: Option<Result<(), SealedMemfdReadClosedV2>>,
    content_shape: Option<Result<(usize, usize), NetworkSemanticsError>>,
    models: Option<Result<NetworkPreparationModelsDataV2, NetworkPreparationModelErrorV2>>,
    content_complete: bool,
    content_gate_failed: bool,
    cumulative: ResourceVector,
    kind: Option<Kind>,
    first: Option<First>,
    finished: bool,
    idle_wait: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    idle_poll: Option<Result<usize, rustix::io::Errno>>,
    idle_events: Option<rustix::event::PollFlags>,
}

impl FixedServiceRequestOriginalV4 {
    /// Creates inert result custody without opening a Session or admitting IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            receipt: OriginalOutputServerReceiptV1::empty(), native: Default::default(),
            sealed: SealedMemfdReadOriginalV2::new(), funding: None, before: None,
            socket: None, after_socket: None, native_before: None, native_after: None, current: None, sealed_result: None,
            content_shape: None, models: None, content_complete: false, content_gate_failed: false,
            cumulative: ResourceVector::ZERO, kind: None, first: None, finished: false, idle_wait: None, idle_poll: None, idle_events: None,
        }
    }

    /// Prices the compiled whole request and actual native/raw destinations.
    ///
    /// This is passive cost DATA, not a loan or role constructor. Dynamic
    /// held-history and sealed model extents are joined before their growth.
    /// Returns `None` on checked arithmetic overflow.
    #[must_use]
    pub fn fixed_receive_demand_v4() -> Option<ResourceVector> {
        let maximum = aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES;
        let (raw, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::fixed_service_request_receive_obligations_v4(maximum)?;
        let native = FixedServiceSessionPostOriginalV4::receiving_demand_v4()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(raw)?
            .checked_add(SealedMemfdReadOriginalV2::receiving_memory_bytes_v2()?)?
            .checked_add(std::mem::size_of::<rustix::event::PollFd<'static>>().checked_mul(3)?)?;
        native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::NetworkBytes, u64::try_from(maximum).ok()?)).ok()
    }

    /// Receives the sole Mount attachment request under its real enrolled loan.
    ///
    /// # Errors
    /// Retains funding, native, packet, authentication and exact-method refusal.
    pub fn receive_mount_attachment_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>, deadline: u64) -> Result<(), FixedServiceRequestClosedV4>
    { self.receive(&mut *session.inner, receiving, Some(deadline), Kind::MountAttachment) }

    /// Receives the finite later Mount62 under its actual fresh signed D.
    ///
    /// The closed domain original separately admits only the Reap verb. This
    /// uses the same enrolled receiving and prearmed Session/native bookends.
    ///
    /// # Errors
    /// Retains same-Session, paid native, authentication or purpose refusal.
    pub fn receive_mount_reap_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        self.receive(&mut *session.inner, receiving, None, Kind::MountAttachment)
    }

    /// Receives fresh Mount inventory under its distinct real enrolled loan.
    ///
    /// # Errors
    /// Retains funding, native, packet, authentication and exact-method refusal.
    pub fn receive_mount_inventory_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>, deadline: u64) -> Result<(), FixedServiceRequestClosedV4>
    { self.receive(&mut *session.inner, receiving, Some(deadline), Kind::MountInventory) }

    /// Receives descriptor-bearing Network63 under its real enrolled loan.
    ///
    /// # Errors
    /// Retains funding, native, packet, authentication and exact-method refusal.
    pub fn receive_network_preparation_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>, deadline: u64) -> Result<(), FixedServiceRequestClosedV4>
    { self.receive(&mut *session.inner, receiving, Some(deadline), Kind::NetworkPreparation) }

    /// Receives complete Network19 inventory under its distinct real loan.
    ///
    /// # Errors
    /// Retains funding, native, packet, authentication and exact-method refusal.
    pub fn receive_network_inventory_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>, deadline: u64) -> Result<(), FixedServiceRequestClosedV4>
    { self.receive(&mut *session.inner, receiving, Some(deadline), Kind::NetworkInventory) }

    /// Receives the next singleton inventory using its actual fresh signed D.
    ///
    /// # Errors
    /// Retains exact same-Session, paid native, signature or purpose refusal.
    pub fn receive_mount_maintenance_inventory_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        self.receive(&mut *session.inner, receiving, None, Kind::MountInventory)
    }

    /// Receives the next Network19 under the same fresh signed-request law.
    ///
    /// # Errors
    /// Retains same-Session, paid native, signature and exact-purpose refusal.
    pub fn receive_network_maintenance_inventory_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        self.receive(&mut *session.inner, receiving, None, Kind::NetworkInventory)
    }

    /// Authenticates the next normal Network request before selecting its purpose.
    ///
    /// This uses the same retained native receiver and Session authenticator.
    /// Only its genuine completed request selects 19,63 or9 on the neutral F
    /// interval; the original paired sample is narrowed to the actual signed D.
    ///
    /// # Errors
    /// Retains unknown method, signature, profile, descriptor or native failure.
    pub fn receive_network_request_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        self.receive(&mut *session.inner, receiving, None, Kind::NetworkReceiving)
    }

    /// Borrows only a positively finished actual inventory request for disposal.
    ///
    /// This comparison DATA grants no receiver or effect authority.
    #[must_use]
    pub fn completed_inventory_request_v5(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        if self.first.is_some() || !self.finished || !self.native.complete_v4()
            || !matches!(self.kind, Some(Kind::MountInventory | Kind::NetworkInventory)) {
            return None;
        }
        self.receipt.borrowed_authenticated_request_v4()
    }

    /// Borrows the same finished Network request after every Session post.
    #[must_use]
    pub fn completed_network_request_v5(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        if self.first.is_some() || !self.finished || !self.native.complete_v4()
            || !matches!(self.kind, Some(Kind::NetworkInventory | Kind::NetworkPreparation
                | Kind::NetworkDestroy)) {
            return None;
        }
        self.receipt.borrowed_authenticated_request_v4()
    }

    /// Disposes the actual positive Network SDK prefix after Domain retirement.
    ///
    /// # Errors
    /// Refuses failed posts, another ordinal, or an unfinished native send.
    pub fn dispose_completed_network_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
        response: &mut super::fixed_service_response::FixedServiceResponseOriginalV4,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        let request = self.completed_network_request_v5().ok_or(FixedServiceRequestClosedV4)?;
        receiving.require_completed_network_interval_v5(request.method() as u32)
            .map_err(|_| FixedServiceRequestClosedV4)?;
        response.require_completed_inventory_v5(&session.inner.transcript, request)
            .map_err(|_| FixedServiceRequestClosedV4)?;
        let method = request.method() as u32;
        drop(std::mem::replace(response, super::fixed_service_response::FixedServiceResponseOriginalV4::new()));
        drop(std::mem::replace(self, Self::new()));
        receiving.finish_network_disposal_once_v5(method).map_err(|_| FixedServiceRequestClosedV4)
    }

    /// Borrows the same positively finished Mount62 request after native posts.
    ///
    /// This lends comparison DATA for physical scratch retirement only. It
    /// grants no Source refund, new effect or domain completion capability.
    #[must_use]
    pub fn completed_mount_attachment_request_v5(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        if self.first.is_some() || !self.finished || !self.native.complete_v4()
            || !matches!(self.kind, Some(Kind::MountAttachment)) {
            return None;
        }
        self.receipt.borrowed_authenticated_request_v4()
    }

    /// Physically drops only the actual positive inventory SDK prefix.
    ///
    /// The Domain census must already be disposed by the same trusted runtime.
    /// Final Common retirement below keeps every prior cost and ordinal.
    ///
    /// # Errors
    /// Refuses failed/native-incomplete, foreign or ambiguous sent response.
    pub fn dispose_completed_inventory_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        receiving: &mut FixedServiceOperationLoanV4<'_>,
        response: &mut super::fixed_service_response::FixedServiceResponseOriginalV4,
    ) -> Result<(), FixedServiceRequestClosedV4> {
        let request = self.completed_inventory_request_v5().ok_or(FixedServiceRequestClosedV4)?;
        receiving.require_completed_inventory_interval_v5(request.method() as u32)
            .map_err(|_| FixedServiceRequestClosedV4)?;
        response.require_completed_inventory_v5(&session.inner.transcript, request)
            .map_err(|_| FixedServiceRequestClosedV4)?;
        let method = request.method() as u32;
        // Only these whole positive owners are replaced. A failing caller
        // retains every earlier prefix and cannot enter the next request.
        drop(std::mem::replace(response, super::fixed_service_response::FixedServiceResponseOriginalV4::new()));
        drop(std::mem::replace(self, Self::new()));
        receiving.finish_inventory_disposal_once_v5(method)
            .map_err(|_| FixedServiceRequestClosedV4)
    }

    fn receive(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut FixedServiceOperationLoanV4<'_>, deadline: Option<u64>, kind: Kind) -> Result<(), FixedServiceRequestClosedV4>
    {
        if self.kind.is_some() || self.first.is_some() || self.finished {
            self.first.get_or_insert(First::Order);
            return Err(FixedServiceRequestClosedV4);
        }
        self.kind = Some(kind);
        self.funding = Some(Self::fixed_receive_demand_v4().ok_or(FixedServiceOperationClosedV4::default())
            .and_then(|demand| receiving.require_additional_representation_v4(demand)));
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(First::Funding); return Err(FixedServiceRequestClosedV4); }
        self.before = Some(receiving.observe_before_once_v4());
        if !matches!(self.before, Some(Ok(()))) { self.first = Some(First::Before); return Err(FixedServiceRequestClosedV4); }
        self.socket = Some(session.socket.as_fd().map(|fd| fd.as_raw_fd()));
        let Some(Ok(fd)) = self.socket.as_ref() else {
            self.first = Some(First::Socket);
            return Err(FixedServiceRequestClosedV4);
        };
        self.native_before = Some(session.owner.begin_fixed_service_session_post_v4(
            &session.transcript, session.socket.peer(), *fd, &mut self.native));
        if !matches!(self.native_before, Some(Ok(()))) { self.first = Some(First::SessionBefore); return Err(FixedServiceRequestClosedV4); }
        if deadline.is_none() {
            self.idle_wait = Some(match session.socket.as_fd() {
                Ok(descriptor) => crate::dormant_handshake::wait_for_inventory_readiness_retaining_v5(
                    descriptor, &mut self.idle_poll, &mut self.idle_events),
                Err(_) => Err(crate::DormantBrokerSessionHandshakeErrorV1::Transport),
            });
            if !matches!(self.idle_wait, Some(Ok(()))) {
                self.first = Some(First::Readiness);
                return Err(FixedServiceRequestClosedV4);
            }
        }
        match deadline {
            Some(deadline) => self.receipt.receive_fixed_service_once_v4(
                session, deadline, receiving, &mut self.cumulative, kind.method()),
            None if matches!(kind, Kind::NetworkReceiving) => self.receipt.receive_network_request_continuation_once_v5(
                session, receiving, &mut self.cumulative),
            None if matches!(kind, Kind::MountAttachment) => self.receipt.receive_mount_reap_continuation_once_v5(
                session, receiving, &mut self.cumulative),
            None => self.receipt.receive_inventory_continuation_once_v5(
                session, receiving, &mut self.cumulative, kind.method()),
        }
        if !self.receipt.has_completed_admission_v1() {
            self.first = Some(First::Receipt);
            return Err(FixedServiceRequestClosedV4);
        }
        if self.receipt.borrowed_authenticated_request_v4().is_none() {
            // Exact pending/terminal replay remains on the original receipt.
            // It cannot be used as a fresh domain effect or sealed-file input.
            self.first = Some(First::Replay);
            return Err(FixedServiceRequestClosedV4);
        }
        if matches!(kind, Kind::NetworkReceiving) {
            self.kind = match self.receipt.borrowed_authenticated_request_v4().map(|request| request.method()) {
                Some(BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES) => Some(Kind::NetworkInventory),
                Some(BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2) => Some(Kind::NetworkPreparation),
                Some(BrokerMethod::BROKER_METHOD_NETWORK_APPLY) => Some(Kind::NetworkDestroy),
                _ => { self.first = Some(First::Receipt); return Err(FixedServiceRequestClosedV4); }
            };
        }
        // Currentness includes the actual authenticated method and opening
        // horizon; neither exists before the retained receipt completes.
        self.current = Some(kind.require_current(receiving));
        if matches!(self.current, Some(Ok(()))) { Ok(()) }
        else { self.first = Some(First::Before); Err(FixedServiceRequestClosedV4) }
    }

    /// Borrows only the actual successfully admitted original request.
    ///
    /// The returned value is comparison/input DATA. Domain authority must still
    /// use the actual loan and independently verified signed admission.
    #[must_use]
    pub fn borrow_authenticated_request_v4(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        if self.first.is_some() || self.finished || !self.native.before_complete_v4() { return None; }
        self.receipt.borrowed_authenticated_request_v4()
    }

    /// Validates the same original63 descriptor before any model growth.
    ///
    /// # Errors
    /// Retains exact sealed/mapping/model refusal and permanently closes
    /// positive preparation. No FD is cloned, reread or supplied externally.
    pub fn prepare_network_content_once_v2(&mut self, receiving: &mut FixedServiceOperationLoanV4<'_>)
        -> Result<(), FixedServiceRequestClosedV4>
    {
        let result = self.prepare_content(receiving);
        if result.is_err() { self.first.get_or_insert(First::Content); }
        result
    }

    fn prepare_content(&mut self, receiving: &mut FixedServiceOperationLoanV4<'_>)
        -> Result<(), FixedServiceRequestClosedV4>
    {
        if self.sealed_result.is_some() || self.first.is_some() || self.finished { return Err(FixedServiceRequestClosedV4); }
        let reference = self.borrow_authenticated_request_v4().and_then(|request| request.network_preparation_data_v2())
            .and_then(|meaning| meaning.preparation_content_reference_v2()).ok_or(FixedServiceRequestClosedV4)?;
        if receiving.require_network_current_v4().is_err() {
            self.content_gate_failed = true;
            return Err(FixedServiceRequestClosedV4);
        }
        // The mapping itself is a co-live memory liability, paid before the
        // sole retained descriptor is transferred into its native inspector.
        if receiving.require_additional_representation_v4(ResourceVector::ZERO.with(D::MemoryBytes, reference.content_bytes())).is_err() {
            self.content_gate_failed = true;
            return Err(FixedServiceRequestClosedV4);
        }
        let descriptor = self.receipt.take_network_descriptor_v4().ok_or(FixedServiceRequestClosedV4)?;
        self.sealed_result = Some(self.sealed.prepare_once(descriptor, reference.content_bytes(),
            NetworkPreparationContentV2::maximum_encoded_bytes() as u64));
        if !matches!(self.sealed_result, Some(Ok(()))) { return Err(FixedServiceRequestClosedV4); }
        self.content_shape = Some(self.sealed.with_bytes(|bytes, _| reference.verify(bytes)
            .map(|content| (content.manifest_bytes().len(), content.specification_bytes().len())))
            .map_err(|_| FixedServiceRequestClosedV4)?);
        let (manifest, specification) = self.content_shape.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(FixedServiceRequestClosedV4)?;
        let (bytes, names) = network_preparation_models_receiving_obligations_v2(manifest, specification)
            .ok_or(FixedServiceRequestClosedV4)?;
        let demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| FixedServiceRequestClosedV4)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| FixedServiceRequestClosedV4)?);
        if receiving.require_additional_representation_v4(demand).is_err() {
            self.content_gate_failed = true;
            return Err(FixedServiceRequestClosedV4);
        }
        if receiving.observe_frontier_clock_v4().is_err() {
            self.content_gate_failed = true;
            return Err(FixedServiceRequestClosedV4);
        }
        self.models = Some(self.sealed.with_bytes(|bytes, _| {
            let content = reference.verify(bytes)?;
            let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(content.manifest_bytes(), DecodeLimits::default())?;
            let specification = aos_sandbox_model::decode_sandbox_spec(content.specification_bytes(), DecodeLimits::default())?;
            let canonical_specification = canonical_network_preparation_specification_v2(&manifest, &specification)?;
            if canonical_specification != content.specification_bytes() { return Err(NetworkPreparationModelErrorV2::Canonical); }
            Ok(NetworkPreparationModelsDataV2 { manifest, specification, _canonical_specification: canonical_specification })
        }).map_err(|_| FixedServiceRequestClosedV4)?);
        if !matches!(self.models, Some(Ok(_))) { return Err(FixedServiceRequestClosedV4); }
        self.content_complete = true;
        Ok(())
    }

    /// Borrows the exact completed models as comparison DATA for the domain.
    #[must_use]
    pub fn network_models_v2(&self) -> Option<(&CanonicalAssignmentManifestV1, &SandboxSpec)> {
        if self.first.is_some() || self.finished || !self.content_complete { return None; }
        let models = self.models.as_ref()?.as_ref().ok()?;
        Some((&models.manifest, &models.specification))
    }

    /// Runs the already-prearmed independent Session after on either outcome.
    ///
    /// # Errors
    /// Retains every independent floor/endpoint/peer refusal. Call this after
    /// the domain/response result, before the loan's own unconditional afters.
    pub fn finish_native_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>)
        -> Result<(), FixedServiceRequestClosedV4>
    {
        let session = &mut *session.inner;
        if self.finished { self.first.get_or_insert(First::Order); return Err(FixedServiceRequestClosedV4); }
        if self.native_before.is_some() {
            self.after_socket = Some(session.socket.as_fd().map(|fd| fd.as_raw_fd()));
            let fd = self.after_socket.as_ref().and_then(|result| result.as_ref().ok()).copied().unwrap_or(-1);
            if self.after_socket.as_ref().is_some_and(Result::is_err) { self.first.get_or_insert(First::Socket); }
            self.native_after = Some(session.owner.finish_fixed_service_session_post_v4(
                &session.transcript, session.socket.peer(), fd, &mut self.native));
            if !matches!(self.native_after, Some(Ok(()))) { self.first.get_or_insert(First::SessionAfter); }
        }
        self.finished = true;
        if self.first.is_none() { Ok(()) } else { Err(FixedServiceRequestClosedV4) }
    }

    /// Identifies only an actual earlier loan gate selected by this original.
    ///
    /// The caller may then borrow the SAME operation/Common failure. A later
    /// owed native or clock refusal must never replace an earlier domain cause.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        match self.first {
            Some(First::Funding | First::Before) => true,
            Some(First::Content) => self.content_gate_failed,
            Some(First::Receipt) => self.receipt.fixed_service_original_failure_selected_v4(),
            _ => false,
        }
    }

    /// Borrows the original chronological refusal without consuming custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Before => self.before.as_ref().and_then(|result| result.as_ref().err())
                .or_else(|| self.current.as_ref()?.as_ref().err()).map(|cause| cause as _),
            First::Readiness => self.idle_poll.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.idle_wait.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Socket => self.socket.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.after_socket.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)),
            First::SessionBefore | First::SessionAfter => self.native.failure(),
            First::Receipt => self.receipt.failure(),
            First::Content => self.sealed.failure()
                .or_else(|| self.sealed_result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.content_shape.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.models.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                .or(Some(&FixedServiceRequestClosedV4)),
            First::Replay | First::Order => Some(&FixedServiceRequestClosedV4),
        }
    }
}

impl Default for FixedServiceRequestOriginalV4 { fn default() -> Self { Self::new() } }

struct NetworkPreparationModelsDataV2 {
    manifest: CanonicalAssignmentManifestV1,
    specification: SandboxSpec,
    _canonical_specification: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
enum NetworkPreparationModelErrorV2 {
    #[error(transparent)]
    Semantics(#[from] NetworkSemanticsError),
    #[error(transparent)]
    Core(#[from] aos_sandbox_model::CanonicalCborError),
    #[error("sealed Network specification is not canonical")]
    Canonical,
}
