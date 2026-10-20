//! Retains a selected fresh query and its independently admitted Prepare scope.
//!
//! The original endpoint owns this attempt before receiving. Received raw and
//! typed owners move into its slot before frontier checks. The real baseline
//! constructor and full current native census/publication remain prerequisites;
//! this cut returns an explicit held refusal while either is unavailable.
//! A retained frontier is DATA, never a completed query or Prepare credential.

use super::*;
use crate::reference_packet::service::{
    ack_emitter::{OriginalNativePrepareStartupAllocation, OriginalNativeReportStartupAllocation},
    fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    report_startup::PacketNativeReportStartupPurpose,
};

/// Holds only actual received custody and public fixed commitments.
#[derive(Default)]
pub(super) struct FreshQueryInput {
    pub(super) frame: Option<ReceivedFrame>,
    pub(super) commitments: Option<[[u8; 32]; 5]>,
}

impl FreshQueryInput {
    fn retain_once(&mut self, frame: ReceivedFrame) -> Result<(), ProviderError> {
        if self.frame.is_some() {
            return Err(refused());
        }
        self.frame = Some(frame);
        Ok(())
    }
}

pub(super) struct NativeFreshRestoreAttempt {
    pub(super) creator: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) startup: OriginalNativeReportStartupAllocation,
    pub(super) prepare: OriginalNativePrepareStartupAllocation,
    pub(super) input: FreshQueryInput,
    pub(super) current: Option<NativeFreshCurrentCensus>,
    pub(super) prepare_input: Option<ReceivedFrame>,
    pub(super) publication: super::fresh_publication::NativeFreshReportPublication,
}

/// Returns the actual heap payload layout of the retained Fresh attempt.
///
/// The endpoint Rc handle inline bytes belong to baseline. The RefCell payload
/// and selected shared header are new retained requested backing. The
/// caller separately charges real received Envelope/typed backing, report raw
/// bank/proof/cache/prefix and full fixed Prepare requested owners. No stand-in
/// PacketService layout or numeric row is returned as permission.
pub(crate) fn original_fresh_report_owner_layout_data() -> usize {
    let payload = std::mem::size_of::<std::cell::RefCell<NativeFreshRestoreAttempt>>();
    crate::retained_metadata::requested_storage::shared_header_storage_data(
        1,
        std::mem::align_of::<std::cell::RefCell<NativeFreshRestoreAttempt>>(),
    )
    .ok()
    .and_then(|header| payload.checked_add(header))
    .unwrap_or(usize::MAX)
}

impl NativeFreshRestoreAttempt {
    pub(super) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        self.startup.authenticate_current(connection)?;
        self.prepare.authenticate_current(connection)
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Selects only the same completed-Admit native fresh query occurrence.
    pub(super) fn prepare_original_fresh_query_receive(&mut self) -> Result<bool, ProviderError> {
        self.ensure_complete_origin()?;
        if self.restore_protocol_attempted {
            // This only skips the once-only query selector. Actual input and
            // Commit readers authenticate their retained verified owners; an
            // error keeps Endpoint held before this dispatcher can run again.
            return Ok(false);
        }
        if self.fresh_restore_attempt.is_some() {
            // A completed query enters the separate retained Prepare route;
            // an incomplete query never selects another receive occurrence.
            return Err(refused());
        }
        let Some(boot) = self.canonical_ack_boot.as_ref() else {
            return Ok(false);
        };
        let selected = {
            let owner = boot.try_borrow().map_err(|_| refused())?;
            owner.ensure_origin()?;
            if owner.permits_original_invocation_without_fresh_query_data()? {
                // Original provenance skips only this mandatory-target selector.
                // Control Arm/Observe/Capture retain their independent scopes.
                return Ok(false);
            }
            owner.policy.as_ref().is_some_and(|policy| {
                policy.fresh_restore_allocation_selection()
                    == Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            })
        };
        if !selected || !self.native.original_fresh_report_window_data()? {
            return Ok(false);
        }
        if !self.held
            || self.restore_protocol_attempted
            || self.restore_prepare_admission.is_some()
            || self.capture.is_some()
            || self.capture_allocation_attempt.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
            || self.restore_commit.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let token = connection.original_native_owned11_admission()?;
        let startup = token.retain_original_report_startup_allocation(
            connection,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
        )?;
        // Unchanged Native276 gate: no report selector/row or ACK self-admits
        // baseline construction. This refuses before a new attempt allocation.
        startup.authenticate_complete_native_baseline(connection)?;
        startup.authenticate_compiled_headers(
            connection,
            super::fresh_publication::original_fresh_report_publication_counter_scratch_data(),
            original_fresh_report_owner_layout_data(),
        )?;
        // Independent188 action admits the full fixed counter/decode/Prepare
        // owners. Its boot claim is spent before fallible construction and is
        // retained through Query errors, never renewed from transferNone.
        let prepare = token.retain_original_prepare_startup_allocation(connection)?;
        prepare.authenticate_current(connection)?;
        self.fresh_restore_attempt = Some(Rc::new(std::cell::RefCell::new(
            NativeFreshRestoreAttempt {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                startup,
                prepare,
                input: FreshQueryInput::default(),
                current: None,
                prepare_input: None,
                publication: super::fresh_publication::NativeFreshReportPublication::new(),
            },
        )));
        Ok(true)
    }

    pub(super) fn receive_original_fresh_query(
        &mut self,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let attempt = self
            .fresh_restore_attempt
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        attempt.authenticate_current(connection)?;
        connection.receive_original_native_report_query(&attempt.startup)
    }

    pub(super) fn retain_original_fresh_query_frontier(
        &mut self,
        frame: ReceivedFrame,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        let mut attempt = self
            .fresh_restore_attempt
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        // The owner survives malformed method/data, frontier refusal and unwind.
        attempt.input.retain_once(frame)?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        attempt.authenticate_current(connection)?;
        let retained = attempt.input.frame.as_ref().ok_or_else(refused)?;
        if !matches!(&retained.body, ReceivedBody::Request(body) if matches!(body.as_ref(), RequestBody::Observe(_)))
        {
            return Err(refused());
        }
        let record = self.records.last().ok_or_else(refused)?;
        let commitments = {
            let frontier = attempt.startup.authenticate_fresh_query_frontier_data(
                connection,
                &retained.envelope,
                self.next_sequence,
                record,
            )?;
            let (nonce, ack, query, admit, response) = frontier.commitments_data()?;
            // The actual admission ID must match Control's retained immutable
            // selection before any report body can be constructed.
            let token = connection.original_native_owned11_admission()?;
            self.native.authenticate_original_fresh_admission_data(
                &token.policy,
                frontier.admission_id_data()?,
            )?;
            [*nonce, *ack, *query, *admit, *response]
        };
        attempt.input.commitments = Some(commitments);
        attempt
            .prepare
            .original_fixed_prepare_storage_data(connection)?;
        attempt.authenticate_current(connection)?;
        Ok(())
    }
}

/// Retains only numeric facts from one actual same-owner census.
///
/// It is not a report, completed query, grant or portable identity roster.
pub(super) struct NativeFreshCurrentCensus {
    pub(super) facts: crate::retained_metadata::RetainedProtocolMetadataFacts,
    pub(super) retained_requested_bytes: usize,
    pub(super) shared_edges: usize,
    pub(super) shared_roots: usize,
    pub(super) banks: [crate::protocol_snapshot::ProtocolSnapshotAllocationFacts; 2],
    pub(super) declared_counter_scratch_bytes: usize,
}

impl FreshQueryInput {
    pub(super) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { frame, commitments } = self;
        let frame = frame.as_ref().ok_or_else(refused)?;
        observer.observe(&frame.envelope)?;
        let ReceivedBody::Request(body) = &frame.body else {
            return Err(refused());
        };
        observer.boxed_value(body.as_ref())?;
        let RequestBody::Observe(observed) = body.as_ref() else {
            return Err(refused());
        };
        let ObserveRequest {
            binding_hash,
            owner_generation,
            after_observation_sequence,
            maximum_items,
            extensions,
        } = observed;
        observer.observe(binding_hash)?;
        observer.observe(owner_generation)?;
        observer.observe(after_observation_sequence)?;
        observer.observe(maximum_items)?;
        observer.observe(extensions)?;
        // Fixed primitive commitments own no child heap; their complete inline
        // layout is included in the actual attempt allocation above.
        observer.observe(&commitments.is_some())
    }
}

impl PacketEndpoint<crate::client::DeadlineStream> {
    /// Stores the real current census before the later report transformation.
    pub(super) fn retain_original_fresh_current_census(
        &mut self,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        let current = self.quote_original_fresh_current_census(service)?;
        {
            let mut attempt = self
                .fresh_restore_attempt
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| refused())?;
            if attempt.current.is_some() {
                return Err(refused());
            }
            attempt.current = Some(current);
        }
        self.publish_original_fresh_report(service)
    }

    fn quote_original_fresh_current_census(
        &mut self,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<NativeFreshCurrentCensus, ProviderError> {
        self.ensure_complete_origin()?;
        let Self {
            transport,
            native,
            authority,
            policy,
            uploads,
            pins,
            records,
            next_sequence: _,
            transport_credit: _,
            held,
            complete,
            capture,
            capture_allocation_attempt,
            pending_capture,
            after_confirmation,
            canonical_ack_boot,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
            fresh_restore_attempt,
        } = self;
        if !*held
            || capture.is_some()
            || capture_allocation_attempt.is_some()
            || pending_capture.is_some()
            || after_confirmation.is_some()
            || canonical_ack_admission.is_some()
            || restore_commit.is_some()
            || *restore_protocol_attempted
            || restore_prepare_admission.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = transport.as_mut() else {
            return Err(refused());
        };
        let attempt_handle = fresh_restore_attempt.as_ref().ok_or_else(refused)?;
        let attempt = attempt_handle.try_borrow().map_err(|_| refused())?;
        attempt.authenticate_current(connection)?;
        attempt
            .startup
            .authenticate_complete_native_baseline(connection)?;
        let scratch = {
            let boot = canonical_ack_boot
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| refused())?;
            if boot.requires_invocation_codec_data()? {
                original_invocation_fresh_current_counter_scratch_data()
            } else {
                original_fresh_current_counter_scratch_data()
            }
        };
        attempt.startup.authenticate_compiled_headers(
            connection,
            scratch,
            original_fresh_report_owner_layout_data(),
        )?;
        if attempt.current.is_some()
            || attempt.input.commitments.is_none()
            || !attempt.publication.is_unstarted()
        {
            return Err(refused());
        }
        let complete = complete.as_ref().ok_or_else(refused)?;
        let banks = complete.original_fresh_report_bank_data()?;
        let boot = canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let context = service.with_original_endpoint_roots(boot, policy);
        let mut roots = crate::retained_metadata::NativeCaptureMetadataRoots::new();
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        // Authenticate/walk Connection and scope owners before taking the
        // registrar loan. No token/currentness helper runs under that lock.
        connection
            .observe_original_current_connection_unique_metadata(&mut roots, &mut observer)?;
        // Native284 preserves the real mutable authority/expiry containment
        // check. Only after that call may a token reference and blob/service
        // loans borrow this same Connection immutably.
        let token = connection.original_native_owned11_admission()?;
        uploads
            .borrowed_owned11_protocol_view(&token.authority)?
            .observe_unique_capture_metadata(&mut roots, &mut observer)?;
        authority.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        complete
            .hello
            .observe_unique_capture_metadata(&mut roots, &mut observer)?;
        observer.vector::<OperationContentPin>(pins.capacity())?;
        for pin in pins {
            pin.observe_unique_capture_metadata(uploads, &mut roots, &mut observer)?;
        }
        observer.vector::<ExchangeRecord>(records.capacity())?;
        for record in records {
            record.observe_unique_capture_metadata(connection, &mut roots, &mut observer)?;
        }
        native.observe_original_fresh_report_metadata(&token.policy, &mut roots, &mut observer)?;
        if !roots.observe_shared(
            &mut observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeFreshReportAttempt,
            attempt_handle.as_ref(),
        )? {
            return Err(refused());
        }
        attempt
            .startup
            .observe_unique_capture_metadata(connection, &mut roots, &mut observer)?;
        attempt
            .prepare
            .observe_unique_startup_metadata(connection, &mut roots, &mut observer)?;
        attempt.input.observe_retained_metadata(&mut observer)?;
        {
            let service_owner =
                context.borrow_current_original_protocol_data(connection, uploads)?;
            service_owner.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        }
        let (shared_edges, shared_roots) = roots.finish()?;
        let facts = observer.finish();
        let backing = crate::retained_metadata::requested_metadata_backing_storage_data(&facts)?;
        // Snapshot allocation facts cover encoded, literal, descriptor and both
        // metadata banks. Their inline headers are already inside the service.
        let retained_requested_bytes = [
            std::mem::size_of::<super::super::service::PacketSourceService>(),
            banks[0].allocated_bytes,
            banks[1].allocated_bytes,
            backing,
        ]
        .into_iter()
        .try_fold(0usize, |a, b| a.checked_add(b))
        .ok_or_else(refused)?;
        attempt.authenticate_current(connection)?;
        attempt
            .startup
            .authenticate_complete_native_baseline(connection)?;
        if complete.original_fresh_report_bank_data()? != banks
            || !native.original_fresh_report_window_data()?
        {
            return Err(refused());
        }
        Ok(NativeFreshCurrentCensus {
            facts,
            retained_requested_bytes,
            shared_edges,
            shared_roots,
            banks,
            declared_counter_scratch_bytes: scratch,
        })
    }
}

/// Names concrete local work headers before acquiring the startup loan.
pub(crate) fn original_fresh_current_counter_scratch_data() -> usize {
    use std::mem::size_of;
    [
        super::super::service::OriginalNativeCaptureContext::startup_protocol_counter_scratch_data(
        ),
        OriginalNativeReportStartupAllocation::fresh_query_frontier_counter_scratch_data(),
        size_of::<crate::retained_metadata::NativeCaptureMetadataRoots>(),
        size_of::<crate::retained_metadata::MetadataObserver>(),
        size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
        size_of::<NativeFreshCurrentCensus>(),
        size_of::<std::cell::Ref<'static, NativeFreshRestoreAttempt>>(),
        size_of::<std::cell::RefMut<'static, NativeFreshRestoreAttempt>>(),
        size_of::<Rc<std::cell::RefCell<NativeFreshRestoreAttempt>>>(),
        size_of::<[crate::protocol_snapshot::ProtocolSnapshotAllocationFacts; 2]>(),
        size_of::<super::super::service::OriginalNativeCaptureContext<'static>>(),
        size_of::<OriginalSelectedFreshData<crate::client::DeadlineStream>>(),
        size_of::<[usize; 8]>(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native fresh query retained attempt differs")
}

#[cfg(test)]
#[path = "fresh_restore_tests.rs"]
mod tests;

/// Adds only the explicit invocation views; the old numeric getter stays exact.
pub(crate) fn original_invocation_fresh_current_counter_scratch_data() -> usize {
    original_fresh_current_counter_scratch_data().saturating_add(
        super::super::service::OriginalNativeCaptureContext::invocation_additional_counter_scratch_data(),
    )
}

mod settled17;
pub(crate) use settled17::{
    HistoricalFreshCurrentCensus17, HistoricalFreshQueryInput17, HistoricalFreshRestoreAttempt17,
};
