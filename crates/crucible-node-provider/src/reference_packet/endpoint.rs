//! Owning authenticated packet endpoint with complete prebuilt reply exchanges.
//!
//! This endpoint requires installed source and consuming-schema policy. Neither
//! its constructor nor a published CNP reply supplies behavioral acceptance,
//! common activation authority, native output consumption or preservation.
//! The operator keeps this complete owner outside unwind and contains the same
//! native process on any held error; dropping transport is not native cleanup.

use std::rc::Rc;

use crucible_node_contract::{ContentRef, Id, U64};

use super::control::{PacketControl, PacketControlSelection};
use crate::{
    ProviderError, blob::*, bodies::*, connection::*, envelope::*, handshake::ConnectionAuthority,
};

mod capture;
mod capture_allocation;
pub(crate) use capture_allocation::{
    OriginalNativeCaptureAllocationOwned12, original_capture_report_owner_layout_data,
};
pub(crate) use capture_quote::original_capture_report_quote_layout_data;
mod capture_candidate;
pub(crate) use capture_candidate::NativeCaptureCandidateOwnerData;
mod capture_outer_projection;
mod capture_owned11;
mod capture_publication;
mod capture_quote;
mod capture_report_obligations;
mod complete;
mod confirmation;
mod fresh_prepare;
mod fresh_publication;
mod fresh_restore;
pub use complete::{PacketCompleteEndpointRecovery, PacketCompleteEndpointRefusal};
pub(crate) use fresh_prepare::OriginalNativeFreshPrepareHeader;
pub(crate) use fresh_publication::{
    original_fresh_report_publication_counter_scratch_data,
    original_fresh_report_startup_publication_counter_scratch_data,
    original_fresh_report_startup_publication_data,
};
pub(crate) use fresh_restore::original_fresh_report_owner_layout_data;
mod prefix;
mod restoration_activation;
mod restoration_observation;
mod restore;
mod restore_commit;
mod restored_input17_closed;
mod restored_producer;
mod restored_suffix_observation;
pub(crate) use restore::PacketEndpointRestoreAllocation;
pub(crate) use restored_producer::original_restored_producer_endpoint_counter_scratch_data;

pub(crate) const EXCHANGES: usize = 256;
// This is the unchanged retained ordinary endpoint-prefix ceiling. The
// separate complete Capture transport has an independent selected bound.
pub(crate) const MAXIMUM_PACKET_TRANSPORT_BYTES: usize = 32 * 1024 * 1024;
const CONTENT: usize = 65_536;
const STORED_CONTENT: usize = 4 * 1024 * 1024;

/// Returns the defining receiver recipe used by both actual Endpoint constructors.
///
/// The future native upload projection borrows this exact finite recipe before
/// child birth. It creates no receiver, quota reservation or current-state proof.
/// Actual constructors pass their authenticated negotiated chunk ceiling; actual
/// per-occurrence quotes still authenticate the installed receiver and all axes.
pub(crate) const fn original_capture17_upload_receiver_limits_data(chunk: usize) -> BlobLimits {
    BlobLimits {
        reserved_bytes: STORED_CONTENT,
        content_bytes: CONTENT,
        chunk_bytes: chunk,
        transfers_per_origin: 256,
        tombstones_per_origin: 256,
        chunks_per_transfer: 256,
        operation_pins: EXCHANGES,
    }
}

/// Authenticates source installation separately from wire syntax and acceptance.
///
/// Implementations belong to the independent local installer. They verify the
/// exact actual peer/implementation/contracts and source-selected semantic
/// schema; a vendor-supplied manifest or callback success cannot install one.
/// Qualification and common admission remain independent mandatory host gates.
pub trait PacketEndpointPolicy: BlobSchemaVerifier {
    /// Checks original negotiated authority against the complete installed source.
    ///
    /// # Errors
    /// Refuses changed implementation, realization, original native peer,
    /// contracts, limits or unsupported source selection.
    fn authenticate_source(
        &self,
        authority: &ConnectionAuthority,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError>;

    /// Authenticates the installed complete native snapshot definition.
    ///
    /// # Errors
    /// Refuses unless the concrete installer supplies the selected full schema.
    fn authenticate_owned11_snapshot_definition(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "native owned11 snapshot definition not installed",
        ))
    }

    /// Authenticates the explicitly installed boot6 four-owner snapshot edition.
    ///
    /// # Errors
    /// Refuses unless the concrete installer supplies the complete outer13 schema.
    fn authenticate_startup_capture_snapshot_definition(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "native startup Capture snapshot definition not installed",
        ))
    }

    /// Authenticates the full original-invocation four-owner outer14 schema.
    ///
    /// # Errors
    /// Refuses unless the concrete installer supplies the exact full definition.
    /// This check alone never supplies the private original invocation purpose.
    fn authenticate_invocation_capture_snapshot_definition(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "invocation Capture snapshot definition not installed",
        ))
    }

    /// Selects the independently installed consuming schema for an exact upload.
    ///
    /// # Errors
    /// Refuses unavailable or out-of-scope content. Successful digest checks
    /// alone cannot select this schema or grant consuming byte access.
    fn consuming_schema(
        &self,
        content: &ContentRef,
        original: &Envelope,
    ) -> Result<ContentRef, ProviderError>;
}

enum Transport<S: ProviderStream> {
    Connected(Connection<S>),
    Prepared(PreparedExchange<S>, prefix::Acknowledgements),
}

/// Retains one authenticated connection, native packet owner and complete ledger.
///
/// Its borrowed step keeps all originals outside callbacks and unwinds. A held
/// failure forbids another step. Operational supervision must keep this entire
/// capsule until genuine native containment or exact custody reconciliation.
#[must_use = "retain native packet custody independently of transport status"]
pub struct PacketEndpoint<S: ProviderStream> {
    transport: Option<Transport<S>>,
    native: PacketControl,
    authority: ConnectionAuthority,
    policy: Rc<dyn PacketEndpointPolicy>,
    uploads: BlobReceiver,
    pins: Vec<OperationContentPin>,
    records: Vec<ExchangeRecord>,
    next_sequence: u64,
    transport_credit: usize,
    held: bool,
    complete: Option<complete::CompleteEndpointState>,
    capture: Option<capture::CaptureFlight<S>>,
    capture_allocation_attempt: Option<Box<capture_publication::NativeCaptureAllocationAttempt>>,
    fresh_restore_attempt: Option<Rc<std::cell::RefCell<fresh_restore::NativeFreshRestoreAttempt>>>,
    pending_capture: Option<capture::PendingCapture>,
    after_confirmation: Option<confirmation::AfterConfirmation<S>>,
    canonical_ack_boot: Option<Rc<std::cell::RefCell<super::service::ack_emitter::NativeAckBoot>>>,
    canonical_ack_admission: Option<super::service::ack_emitter::VerifiedCanonicalAckAdmission>,
    restore_commit: Option<restore_commit::RestoreCommitFlight<S>>,
    restore_protocol_attempted: bool,
    restore_prepare_admission: Option<super::service::ack_emitter::VerifiedCompleteRestorePrepare>,
}

/// Returns the same original unopened connection and native owner on refusal.
#[must_use = "retain and authentically contain the refused original native owner"]
pub struct PacketEndpointRefusal<S: ProviderStream> {
    connection: Connection<S>,
    native: PacketControl,
    error: ProviderError,
}

impl<S: ProviderStream> PacketEndpointRefusal<S> {
    /// Borrows the actual refusal without inferring absence of native custody.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Moves complete original custody to the operator's retained capsule.
    pub fn into_parts(self) -> (Connection<S>, PacketControl, ProviderError) {
        (self.connection, self.native, self.error)
    }
}

// Only the concrete original DeadlineStream service installs this entry.
// Generic stream callers cannot supply an alternate capture implementation.
type OriginalSelectedCapture<S> = fn(
    &mut PacketEndpoint<S>,
    &Envelope,
    &super::service::OriginalNativeServiceCaptureContext<'_>,
    &crate::client::ExchangeDeadline,
) -> Result<(), ProviderError>;

type OriginalSelectedReport<S> = fn(
    &mut PacketEndpoint<S>,
    Envelope,
    &ObserveRequest,
    &super::service::OriginalNativeServiceCaptureContext<'_>,
    &super::service::ack_emitter::OriginalNativeReportStartupAllocation,
) -> Result<(), ProviderError>;

type OriginalSelectedNext<S> = fn(
    &mut PacketEndpoint<S>,
    &super::service::OriginalNativeServiceCaptureContext<'_>,
) -> Result<Option<ReceivedFrame>, ProviderError>;

type OriginalSelectedFreshData<S> = fn(
    &mut PacketEndpoint<S>,
    &super::service::OriginalNativeServiceCaptureContext<'_>,
) -> Result<(), ProviderError>;

type OriginalSelectedRestore<S> = fn(
    &mut PacketEndpoint<S>,
    &Envelope,
    &RequestBody,
    &super::service::OriginalNativeServiceCaptureContext<'_>,
    &crate::client::ExchangeDeadline,
) -> Result<bool, ProviderError>;

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Takes genuine original native custody and an independently admitted stream.
    ///
    /// The policy is mandatory. Selected source2 and unopened actual native gate
    /// are checked before blob storage or native callbacks. This constructor
    /// cannot issue an acceptance token, common Ready or preserved-world claim.
    ///
    /// # Errors
    /// Returns the complete original owner for a wrong direction/source scope,
    /// revoked authority, changed peer tuple or unavailable finite storage.
    pub fn new(
        mut connection: Connection<S>,
        native: PacketControl,
        policy: Rc<dyn PacketEndpointPolicy>,
        supervisor: Rc<dyn BlobSupervisor>,
    ) -> Result<Self, Box<PacketEndpointRefusal<S>>> {
        let prepare = || -> Result<_, ProviderError> {
            let authority = connection.provider_authority()?;
            policy.authenticate_source(authority, native.endpoint_scope()?)?;
            let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("packet chunk allowance"))?
                .min(4096);
            let uploads = BlobReceiver::new(
                authority.session_id().clone(),
                authority.incarnation_id().clone(),
                original_capture17_upload_receiver_limits_data(chunk),
                supervisor,
            )?;
            let original_authority = authority.clone();
            if native.is_complete_original_source() {
                connection.bind_native5_blob_receiver(&uploads)?;
            }
            Ok((original_authority, uploads))
        };
        let (authority, uploads) = match prepare() {
            Ok(scope) => scope,
            Err(error) => {
                return Err(Box::new(PacketEndpointRefusal {
                    connection,
                    native,
                    error,
                }));
            }
        };
        Ok(Self {
            transport: Some(Transport::Connected(connection)),
            native,
            authority,
            policy,
            uploads,
            pins: Vec::new(),
            records: Vec::new(),
            next_sequence: 2,
            transport_credit: 0,
            held: false,
            complete: None,
            capture: None,
            capture_allocation_attempt: None,
            fresh_restore_attempt: None,
            pending_capture: None,
            after_confirmation: None,
            canonical_ack_boot: None,
            canonical_ack_admission: None,
            restore_commit: None,
            restore_protocol_attempted: false,
            restore_prepare_admission: None,
        })
    }

    /// Borrows the same actual native owner for independent original inspection.
    pub fn native(&self) -> &PacketControl {
        &self.native
    }

    /// Borrows all completed original transport exchanges without cloning them.
    pub fn exchanges(&self) -> &[ExchangeRecord] {
        &self.records
    }

    /// Borrows a retained incomplete exchange without creating retry authority.
    pub fn incomplete_exchange(&self) -> Option<&ExchangeRecord> {
        match &self.transport {
            Some(Transport::Prepared(exchange, _)) => Some(exchange.record()),
            _ => None,
        }
    }

    /// Reports only local dispatch fencing, without claiming native containment.
    pub fn is_held(&self) -> bool {
        self.held
    }

    // Original creator checks precede deadline locks, thread-local actor checks
    // and all native or transport callbacks in inherited complete-source state.
    pub(crate) fn ensure_complete_origin(&self) -> Result<(), ProviderError> {
        if let Some(state) = &self.complete {
            state.ensure_origin()?;
        }
        Ok(())
    }

    /// Drives one original request and its complete prebuilt proof prefix.
    ///
    /// The operator invokes this method on the same retained owner outside its
    /// unwind boundary. Every successful native callback is preceded by complete
    /// reply/proof preparation. A partial publication, invalid transfer reply or
    /// callback unwind keeps native custody, original bytes and received prefix.
    /// EOF holds this owner; it is not native EOF, reclamation or future closure.
    ///
    /// # Errors
    /// Refuses held scope, exhausted whole ledger, malformed traffic, unavailable
    /// source content, native disagreement or incomplete original publication.
    pub fn step(&mut self) -> Result<(), ProviderError> {
        self.step_with_complete_context(None)
    }

    pub(crate) fn step_with_complete_context(
        &mut self,
        context: Option<(
            &crate::handshake::Handshake,
            &crate::client::ExchangeDeadline,
        )>,
    ) -> Result<(), ProviderError> {
        self.step_with_original_context(context, None, None, None, None, None, None, None)
    }

    pub(crate) fn step_with_selected_context(
        &mut self,
        handshake: &crate::handshake::ExtensionHandshake,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.authenticate_selected_registration(handshake)?;
        deadline.remaining()?;
        self.step_with_original_context(None, Some(deadline), None, None, None, None, None, None)
    }

    fn step_with_original_context(
        &mut self,
        context: Option<(
            &crate::handshake::Handshake,
            &crate::client::ExchangeDeadline,
        )>,
        selected_deadline: Option<&crate::client::ExchangeDeadline>,
        service_context: Option<&super::service::OriginalNativeServiceCaptureContext<'_>>,
        selected_capture: Option<OriginalSelectedCapture<S>>,
        selected_restore: Option<OriginalSelectedRestore<S>>,
        selected_report: Option<OriginalSelectedReport<S>>,
        selected_next: Option<OriginalSelectedNext<S>>,
        selected_fresh_data: Option<OriginalSelectedFreshData<S>>,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.held {
            return Err(ProviderError::Conflict("packet endpoint held"));
        }
        // This sticky guard precedes receive, source policy and all callbacks.
        // Only complete publication restores eligibility for the next original.
        self.held = true;
        if self.canonical_ack_boot.is_some() {
            selected_deadline
                .ok_or(ProviderError::Correlation(
                    "native ACK requires original service cut",
                ))?
                .remaining()?;
        }
        self.reserve()?;
        if self.requires_original_fresh_prepare()? {
            if !self.receive_original_fresh_prepare()? {
                return Err(ProviderError::Frame("fresh Prepare peer closed"));
            }
            // The actual frame remains in the endpoint slot while the concrete
            // service verifier borrows Endpoint mutably. This temporary handle
            // owns the same Rc allocation, never a cloned Envelope or token.
            let original_owner = Rc::clone(self.fresh_restore_attempt.as_ref().ok_or(
                ProviderError::Correlation("fresh Prepare original owner absent"),
            )?);
            let original_loan = original_owner
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("fresh Prepare owner borrowed"))?;
            let frame = original_loan
                .prepare_input
                .as_ref()
                .ok_or(ProviderError::Correlation("fresh Prepare input absent"))?;
            let ReceivedBody::Request(body) = &frame.body else {
                return Err(ProviderError::Correlation(
                    "fresh Prepare requires original request",
                ));
            };
            let restore = selected_restore.ok_or(ProviderError::Correlation(
                "fresh Prepare concrete service verifier absent",
            ))?;
            if !restore(
                self,
                &frame.envelope,
                body.as_ref(),
                service_context
                    .ok_or(ProviderError::Correlation("fresh Prepare service absent"))?,
                selected_deadline
                    .ok_or(ProviderError::Correlation("fresh Prepare deadline absent"))?,
            )? {
                return Err(ProviderError::Correlation(
                    "fresh Prepare original was not handled",
                ));
            }
            return Ok(());
        }
        if let Some(witness) = self.prepare_original_restored_producer_receive()? {
            if selected_restore.is_none() || service_context.is_none() {
                return Err(ProviderError::Correlation(
                    "restored Producer concrete service absent",
                ));
            }
            return self.receive_and_dispatch_original_restored_producer(
                witness,
                selected_deadline.ok_or(ProviderError::Correlation(
                    "restored Producer deadline absent",
                ))?,
            );
        }
        if let Some(witness) = self.prepare_original_restored_suffix_observation_receive()? {
            if selected_restore.is_none() || service_context.is_none() {
                return Err(ProviderError::Correlation(
                    "recurring Observe concrete service absent",
                ));
            }
            return self.receive_and_dispatch_original_restored_suffix_observation(
                witness,
                selected_deadline.ok_or(ProviderError::Correlation(
                    "recurring Observe deadline absent",
                ))?,
            );
        }
        if let Some(read) = self.prepare_original_restoration_observation_receive()? {
            if selected_restore.is_none() || service_context.is_none() {
                return Err(ProviderError::Correlation(
                    "restored Observe concrete service absent",
                ));
            }
            return self.receive_and_dispatch_original_restoration_observation(
                read,
                selected_deadline.ok_or(ProviderError::Correlation(
                    "restored Observe deadline absent",
                ))?,
            );
        }
        let fresh_query = self.prepare_original_fresh_query_receive()?;
        let original_report_query = if self.capture_allocation_attempt.is_none()
            && self.native.requires_original_capture_report_query()?
        {
            let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
                return Err(ProviderError::Conflict(
                    "native report original connection absent",
                ));
            };
            let token = connection.original_native_owned11_admission()?;
            Some(token.retain_original_report_startup_allocation(
                connection,
                super::service::report_startup::PacketNativeReportStartupPurpose::OriginalObserve12,
            )?)
        } else {
            None
        };
        let frame =
            if fresh_query {
                self.receive_original_fresh_query()?
            } else if self.capture_allocation_attempt.is_some() {
                let receive = selected_next.ok_or(ProviderError::Correlation(
                    "native Report next original receiver absent",
                ))?;
                receive(
                    self,
                    service_context.ok_or(ProviderError::Correlation(
                        "native Report next original service absent",
                    ))?,
                )?
            } else {
                match self.transport.as_mut() {
                    Some(Transport::Connected(connection)) => {
                        let birth_read = self.canonical_ack_boot.as_ref().map(|boot|
                    super::service::ack_emitter::NativeAckBoot::original_birth_read_scope(
                        boot,&self.native,self.records.len(),
                    )).transpose()?.flatten();
                        if let Some(scope) = birth_read.as_ref() {
                            connection.receive_original_native_birth_request(scope)?
                        } else if let Some(scope) = original_report_query.as_ref() {
                            connection.receive_original_native_report_query(scope)?
                        } else {
                            connection.receive()?
                        }
                    }
                    _ => {
                        return Err(ProviderError::Conflict(
                            "packet original exchange unavailable",
                        ));
                    }
                }
            }
            .ok_or(ProviderError::Frame("packet endpoint original peer closed"))?;
        // Transport grammar is insufficient to select a native action owner.
        // The original literal is already retained; keep the sticky held state
        // and refuse before any generic fresh/restore/upload/control effect.
        restored_input17_closed::require_legacy_dispatch_data(&frame.envelope)?;
        if fresh_query {
            // The endpoint retains the complete actual result before any
            // frontier/hash/currentness check or report transformation.
            self.retain_original_fresh_query_frontier(frame)?;
            let census = selected_fresh_data.ok_or(ProviderError::Correlation(
                "fresh report concrete service census absent",
            ))?;
            return census(
                self,
                service_context.ok_or(ProviderError::Correlation(
                    "fresh report actual service absent",
                ))?,
            );
        }
        let ReceivedBody::Request(body) = frame.body else {
            return Err(ProviderError::Correlation(
                "packet endpoint requires original request",
            ));
        };
        let request = frame.envelope;
        if let Some(scope) = original_report_query.as_ref() {
            let RequestBody::Observe(observed) = body.as_ref() else {
                return Err(ProviderError::Correlation(
                    "native report requires actual Observe",
                ));
            };
            let report = selected_report.ok_or(ProviderError::Correlation(
                "native report original service publisher absent",
            ))?;
            return report(
                self,
                request,
                observed,
                service_context.ok_or(ProviderError::Correlation(
                    "native report original service context absent",
                ))?,
                scope,
            );
        }

        let activation_method = matches!(request.method, Method::Activate | Method::WorldActivate);
        let upload_method = matches!(
            request.method,
            Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
        );
        let (requires_restoration_activation, completed_restoration) =
            if activation_method || upload_method {
                self.canonical_ack_boot
                    .as_ref()
                    .map(|boot| {
                        let owner = boot.try_borrow().map_err(|_| {
                            ProviderError::Conflict("restoration activation boot borrowed")
                        })?;
                        Ok::<_, ProviderError>((
                            owner.requires_restoration_activation_data()?,
                            owner.has_completed_restoration_for_activation_data()?,
                        ))
                    })
                    .transpose()?
                    .unwrap_or((false, false))
            } else {
                (false, false)
            };
        if requires_restoration_activation
            && (activation_method || (upload_method && completed_restoration))
        {
            if selected_restore.is_none()
                || service_context.is_none()
                || selected_deadline.is_none()
            {
                return Err(ProviderError::Correlation(
                    "restoration activation concrete service absent",
                ));
            }
            if upload_method {
                return self.dispatch_selected_restoration_upload(
                    request,
                    selected_deadline.ok_or(ProviderError::Correlation(
                        "restoration upload deadline absent",
                    ))?,
                );
            }
            return self.dispatch_selected_restoration_activation(
                request,
                selected_deadline.ok_or(ProviderError::Correlation(
                    "restoration activation deadline absent",
                ))?,
            );
        }
        if request.extensions.contains_key(
            super::service::complete_restore::activation::PACKET_RESTORATION_ACTIVATION_FEATURE,
        ) || request.extensions.contains_key(
            super::service::complete_restore::activation::upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        ) {
            return Err(ProviderError::Correlation("restoration activation private target absent"));
        }

        if request.extensions.contains_key(
            super::service::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE,
        ) {
            return Err(ProviderError::Correlation("restored Observe once receiver absent"));
        }
        if let Some(restore) = selected_restore {
            if restore(
                self,
                &request,
                body.as_ref(),
                service_context.ok_or(ProviderError::Correlation(
                    "native restore actual service context absent",
                ))?,
                selected_deadline.ok_or(ProviderError::Correlation(
                    "native restore original cut absent",
                ))?,
            )? {
                return Ok(());
            }
        } else if self.restore_protocol_attempted {
            return Err(ProviderError::Correlation(
                "native restore owning route absent",
            ));
        }

        if let Some(boot) = self.canonical_ack_boot.as_ref() {
            if matches!(body.as_ref(), RequestBody::Begin(begin) if begin.kind == BeginKind::Capture)
            {
                let service = service_context.ok_or(ProviderError::Correlation(
                    "native whole11 requires original service context",
                ))?;
                let capture = selected_capture.ok_or(ProviderError::Correlation(
                    "native whole11 requires original typed service transport",
                ))?;
                let deadline = selected_deadline.ok_or(ProviderError::Correlation(
                    "native whole11 original service cut absent",
                ))?;
                return capture(self, &request, service, deadline);
            }
            if request.method == Method::Admit {
                let complete = self.complete.as_ref().ok_or(ProviderError::Correlation(
                    "native ACK original Hello absent",
                ))?;
                let owner = boot
                    .try_borrow()
                    .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
                let policy = owner
                    .policy
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "native ACK installed policy absent",
                    ))?
                    .clone();
                drop(owner);
                let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
                    return Err(ProviderError::Correlation(
                        "native assigned Admit original connection absent",
                    ));
                };
                self.canonical_ack_admission =
                    Some(super::service::ack_emitter::NativeAckBoot::verify_admit(
                        boot,
                        policy,
                        &self.authority,
                        &complete.hello,
                        &request,
                        connection,
                    )?);
                self.canonical_ack_admission
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "native ACK verified slot absent",
                    ))?
                    .authenticate_installation(connection)?;
                let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
                    return Err(ProviderError::Correlation(
                        "native ACK installation original connection absent",
                    ));
                };
                selected_deadline
                    .ok_or(ProviderError::Correlation("native ACK original cut absent"))?
                    .remaining()?;
                connection
                    .install_original_canonical_ack_admission(&mut self.canonical_ack_admission)?;
            }
        }
        let control_admit = if self.canonical_ack_boot.is_some() && request.method == Method::Admit
        {
            let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
                return Err(ProviderError::Correlation(
                    "native ACK Control connection absent",
                ));
            };
            Some(connection.retain_original_canonical_ack_control_admit(&request)?)
        } else {
            None
        };
        if self.complete.is_some()
            && matches!(body.as_ref(), RequestBody::Begin(begin) if begin.kind == BeginKind::Capture)
        {
            let (handshake, deadline) = context.ok_or(ProviderError::Correlation(
                "native5 Capture requires original service negotiation custody",
            ))?;
            return self.capture_original(&request, handshake, deadline);
        }
        if self.complete.is_some()
            && request.method == Method::Poll
            && request.extensions.contains_key(
                super::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION,
            )
        {
            return self.confirm_original_after(request);
        }
        if let Some(reply) = self.upload(&request, body.as_ref())? {
            self.prepare(&request, &reply)?;
        } else {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            let mut prepare = |reply: &super::control::PacketControlReply| {
                prefix::prepare(transport, sequence, credit, authority, &request, reply)
            };
            if let Some(handoff) = control_admit {
                self.native
                    .dispatch_original_canonical_ack_admit_with_preflight(
                        &request,
                        handoff,
                        &mut prepare,
                    )?;
            } else {
                self.native
                    .dispatch_with_preflight(&request, &mut prepare)?;
            }
        }
        let (exchange, acknowledgements) = match self.transport.as_mut() {
            Some(Transport::Prepared(exchange, acknowledgements)) => (exchange, acknowledgements),
            _ => return Err(ProviderError::Conflict("packet prepared prefix absent")),
        };
        let birth_publication = self
            .canonical_ack_boot
            .as_ref()
            .map(|boot| {
                super::service::ack_emitter::NativeAckBoot::original_birth_publication_scope(
                    boot,
                    &self.native,
                    self.records.len(),
                )
            })
            .transpose()?
            .flatten();
        if let Some(scope) = birth_publication.as_ref() {
            exchange.publish_original_native_birth(scope, &mut |original, received| {
                acknowledgements.validate(original, received)
            })?;
        } else {
            exchange
                .publish(&mut |original, received| acknowledgements.validate(original, received))?;
        }
        drop(birth_publication);
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "packet original prefix disappeared",
            ));
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        if request.method == Method::Admit {
            if let (Some(boot), Some(Transport::Connected(connection))) =
                (self.canonical_ack_boot.as_ref(), self.transport.as_ref())
            {
                super::service::ack_emitter::NativeAckBoot::complete_original_native_birth(
                    boot,
                    connection,
                    &self.records,
                )?;
            }
        }
        self.held = false;
        Ok(())
    }

    pub(crate) fn bind_original_canonical_ack_boot(
        &mut self,
        boot: Rc<std::cell::RefCell<super::service::ack_emitter::NativeAckBoot>>,
        policy: Rc<super::service::Native5Policy>,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.canonical_ack_boot.is_some() || !self.records.is_empty() || self.held {
            return Err(ProviderError::Conflict(
                "native ACK boot binding follows activity",
            ));
        }
        let mut owner = boot
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
        owner.ensure_origin()?;
        if policy.ack_emitter_selection()
            != Some(
                super::service::ack_emitter::PacketNative5AckEmitterSelection::CanonicalSdkBlob5,
            )
        {
            return Err(ProviderError::Correlation("native ACK boot policy differs"));
        }
        owner.policy = Some(policy);
        drop(owner);
        self.canonical_ack_boot = Some(boot);
        Ok(())
    }

    pub(crate) fn authenticate_selected_registration(
        &self,
        handshake: &crate::handshake::ExtensionHandshake,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        handshake.verify_authority(&self.authority)
    }

    fn reserve(&mut self) -> Result<(), ProviderError> {
        if self.records.len() >= EXCHANGES || self.pins.len() >= EXCHANGES {
            return Err(ProviderError::ResourceExhausted(
                "packet complete exchange ledger",
            ));
        }
        self.records
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet exchange record slot"))?;
        self.pins
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet upload pin slot"))?;
        Ok(())
    }

    fn prepare(
        &mut self,
        request: &Envelope,
        reply: &super::control::PacketControlReply,
    ) -> Result<(), ProviderError> {
        prefix::prepare(
            &mut self.transport,
            &mut self.next_sequence,
            &mut self.transport_credit,
            &self.authority,
            request,
            reply,
        )
    }

    fn upload(
        &mut self,
        envelope: &Envelope,
        request: &RequestBody,
    ) -> Result<Option<super::control::PacketControlReply>, ProviderError> {
        let result = match request {
            RequestBody::BlobBegin(begin) => {
                let progress = self
                    .uploads
                    .begin(self.key(&begin.transfer_id), begin.content.clone())?;
                prefix::completed(BlobBeginResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                    maximum_chunk_bytes: progress.maximum_chunk_bytes,
                })?
            }
            RequestBody::BlobChunk(chunk) => {
                let progress = self.uploads.chunk(
                    &self.key(&chunk.transfer_id),
                    chunk.offset,
                    &chunk.bytes,
                )?;
                prefix::completed(BlobChunkResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                })?
            }
            RequestBody::BlobFinish(finish) => {
                let verified = self.uploads.finish(&self.key(&finish.transfer_id))?;
                let content = verified.content().clone();
                let schema = self.policy.consuming_schema(&content, envelope)?;
                let owner = envelope
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "packet original install identity",
                    ))?
                    .clone();
                let pin =
                    self.uploads
                        .pin_operation(&verified, owner, schema, self.policy.as_ref())?;
                pin.with_bytes(|bytes| self.native.install_content(content.clone(), bytes))??;
                self.pins.push(pin);
                prefix::completed(BlobFinishResult {
                    transfer_id: finish.transfer_id.clone(),
                    content,
                })?
            }
            _ => return Ok(None),
        };
        Ok(Some(super::control::PacketControlReply {
            body: result,
            evidence: Vec::new(),
        }))
    }

    fn key(&self, transfer: &Id) -> TransferKey {
        TransferKey {
            origin: RequestOrigin::Controller,
            session: self.authority.session_id().clone(),
            incarnation: self.authority.incarnation_id().clone(),
            transfer: transfer.clone(),
        }
    }
}

impl PacketEndpoint<crate::client::DeadlineStream> {
    /// Waits before a new exchange while preserving the original ledger and gate.
    pub(super) fn wait_for_request(&mut self) -> Result<(), ProviderError> {
        if self.held {
            return Err(ProviderError::Conflict("packet endpoint held"));
        }
        let result = match self.transport.as_mut() {
            Some(Transport::Connected(connection)) => connection.wait_for_request(),
            _ => Err(ProviderError::Conflict(
                "packet original exchange unavailable",
            )),
        };
        if result.is_err() {
            self.held = true;
        }

        result
    }
}

impl PacketEndpoint<crate::client::DeadlineStream> {
    pub(crate) fn step_with_selected_service_context(
        &mut self,
        handshake: &crate::handshake::ExtensionHandshake,
        deadline: &crate::client::ExchangeDeadline,
        service: &super::service::OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if !self.complete.as_ref().is_some_and(|state| {
            matches!(
                state.profile,
                Some(super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            )
        }) {
            return self.step_with_selected_context(handshake, deadline);
        }
        self.authenticate_selected_registration(handshake)?;
        deadline.remaining()?;
        self.step_with_original_context(
            None,
            Some(deadline),
            Some(service),
            Some(Self::capture_original_owned11),
            Some(Self::restore_original_transfer),
            Some(Self::publish_original_capture_allocation_observe),
            Some(Self::receive_original_capture_allocation_next),
            Some(Self::retain_original_fresh_current_census),
        )
    }
}

mod capture_startup;

mod confirmation_startup;

#[path = "endpoint/capture_invocation.rs"]
mod capture_invocation;

pub(crate) use capture_quote::original_invocation_capture_report_additional_scratch_data;

pub(crate) use restored_suffix_observation::original_restored_suffix_observation_endpoint_counter_scratch_data;

mod settled17;

pub(crate) use settled17::{
    CurrentEndpoint17Data, CurrentEndpoint17GroupIds, read_endpoint17_data,
    read_endpoint17_fields_data,
};

pub(crate) use fresh_publication::HistoricalFreshReportPublication17;
pub(crate) use fresh_restore::{
    HistoricalFreshCurrentCensus17, HistoricalFreshQueryInput17, HistoricalFreshRestoreAttempt17,
};

mod native_wholegraph17;
pub(in crate::reference_packet) use native_wholegraph17::{
    NativeCurrentGraph17ActionPlan, NativeCurrentGraph17Borrowed,
};

pub(crate) use settled17::read_rooted_endpoint17_fields_data;
pub(crate) use settled17::{
    BorrowedCommitFlight17Lineage, BorrowedHello17Lineage, BorrowedNativeEndpoint17LogicalData,
    BorrowedSpentFresh17, borrow_native17_endpoint_logical_data,
};
pub(crate) use settled17::{BorrowedTerminal17, BorrowedTerminal17Location};

pub(crate) use settled17::authenticate_native17_retained_terminal_data;

mod settled_capture_cut17;

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Checks actual Blob custody at the settled Capture/output safe point.
    ///
    /// Completed immutable evidence and discharged wrappers remain retained.
    /// This DATA predicate grants no Source, native, transport or Capture right.
    /// It never inspects or drains modeled event/input queues.
    ///
    /// # Errors
    /// Refuses unresolved ordinary uploads, quarantine, unsettled operation pins,
    /// foreign/stale pin wrappers, conflicting ledger loans or inconsistent
    /// retained custody. Every original owner remains untouched on refusal.
    pub(in crate::reference_packet) fn authenticate_settled_capture17_custody_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.uploads.authenticate_settled_capture17_custody_data()?;
        for pin in &self.pins {
            pin.authenticate_settled_capture17_custody_data(&self.uploads)?;
        }
        Ok(())
    }
}

mod observation17;

pub(crate) use observation17::native_observation17_endpoint_counter_scratch_data;

mod capture17;
pub(crate) use capture17::{
    native_capture17_endpoint_receive_counter_scratch_data,
    native_capture17_upload_endpoint_counter_scratch_data,
};
