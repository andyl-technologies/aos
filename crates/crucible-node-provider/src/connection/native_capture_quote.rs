//! Counts actual SDK roots for the source-selected native Capture report.
//!
//! The actual Observe caller contributes model, Control, endpoint and report
//! owners. These SDK facts are current data plus named original-bank growth
//! components. They neither authorize Capture nor predict its full future body.

use super::native_startup_protocol::NativeCurrentConnectionView;
use super::*;
use crate::protocol_snapshot::{
    MetadataAliasAllocationFacts, MetadataRecordAllocationFacts, OriginalProtocolStorageFacts,
    ProtocolCaptureCut, ProtocolSnapshotAllocationFacts, ProtocolSnapshotReservation,
};
use crate::reference_packet::service::OriginalNativeCaptureContext;
use crate::retained_metadata::{
    MetadataObserver, NativeCaptureMetadataRoots, aliases::MetadataSharedKind,
};
use std::cell::RefCell;

/// Describes one actual original snapshot reservation before capture binds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct NativeCaptureSdkSnapshotBankQuote {
    pub(crate) allocation: ProtocolSnapshotAllocationFacts,
    pub(crate) records: MetadataRecordAllocationFacts,
    pub(crate) aliases: MetadataAliasAllocationFacts,
    pub(crate) required_record_rows: usize,
    pub(crate) required_alias_rows: usize,
    pub(crate) current_encoded_extent: usize,
}

/// Reports current retained SDK owners and separately named future bank terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct NativeCaptureSdkStateData {
    pub(crate) original_storage: OriginalProtocolStorageFacts,
    pub(crate) before: NativeCaptureSdkSnapshotBankQuote,
    pub(crate) after: NativeCaptureSdkSnapshotBankQuote,
    pub(crate) frame_bank_views: usize,
    pub(crate) maximum_literal_encoding_growth_bytes: usize,
    pub(crate) maximum_descriptor_encoding_growth_bytes: usize,
    pub(crate) future_capture_receive:
        super::native_capture_receive::NativeCaptureFutureReceiveQuote,
}

struct NativeCaptureSdkAssociation {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    codec: Rc<Native5CodecOwner>,
    bank: Rc<RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
    observe_cut: crate::operational_time::OperationalDeadline,
}

/// Owns only the live data-walk roster until the actual native aggregate finishes.
pub(crate) struct NativeCaptureSdkStateQuote {
    association: NativeCaptureSdkAssociation,
    data: NativeCaptureSdkStateData,
    roots: NativeCaptureMetadataRoots,
    observer: MetadataObserver<'static>,
}

/// Retains actual source-local association and closed numeric completed facts.
///
/// The private pointer roster is dropped at completion and never retained here.
pub(crate) struct NativeCaptureSdkCompletedQuote {
    association: NativeCaptureSdkAssociation,
    data: NativeCaptureSdkStateData,
    retained: crate::retained_metadata::RetainedProtocolMetadataFacts,
    strong_edges: usize,
    unique_shared_roots: usize,
}

impl NativeCaptureSdkStateQuote {
    pub(crate) fn native_metadata_mut(
        &mut self,
    ) -> (
        &mut NativeCaptureMetadataRoots,
        &mut MetadataObserver<'static>,
    ) {
        (&mut self.roots, &mut self.observer)
    }

    pub(crate) fn finish_original(
        self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<NativeCaptureSdkCompletedQuote, ProviderError> {
        self.association
            .authenticate_current(connection, blobs, context)?;
        let (strong_edges, unique_shared_roots) = self.roots.finish()?;
        let retained = self.observer.finish();
        if retained.shared_backing_views != unique_shared_roots {
            return Err(refused());
        }
        Ok(NativeCaptureSdkCompletedQuote {
            association: self.association,
            data: self.data,
            retained,
            strong_edges,
            unique_shared_roots,
        })
    }

    pub(crate) const fn requested_scratch_bytes() -> usize {
        std::mem::size_of::<Self>()
    }
}

impl NativeCaptureSdkAssociation {
    fn authenticate_target(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || connection
                .native5_codec
                .as_ref()
                .is_none_or(|codec| !Rc::ptr_eq(codec, &self.codec))
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &self.bank))
        {
            return Err(refused());
        }
        context.authenticate_original(connection, blobs)
    }

    fn authenticate_current(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_target(connection, blobs, context)?;
        let loan = context.borrow_current_original_protocol_data(connection, blobs)?;
        if self.observe_cut.remaining().is_none() || loan.original_cut() != self.observe_cut {
            return Err(refused());
        }
        Ok(())
    }
}

impl NativeCaptureSdkCompletedQuote {
    pub(crate) fn authenticate_current(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.association
            .authenticate_current(connection, blobs, context)
    }

    /// Rechecks target identity across later operations without renewing Observe.
    pub(crate) fn authenticate_same_target_data(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.association
            .authenticate_target(connection, blobs, context)
    }

    pub(crate) fn sdk_data(&self) -> &NativeCaptureSdkStateData {
        &self.data
    }
    pub(crate) const fn retained_metadata(
        &self,
    ) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
        self.retained
    }
    pub(crate) const fn shared_counts(&self) -> (usize, usize) {
        (self.strong_edges, self.unique_shared_roots)
    }

    pub(crate) const fn completed_owner_layout_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Exposes only the numeric report component, not this owner's alias class.
    ///
    /// The endpoint's new complete codec must separately preserve the three
    /// actual shared handles. This borrowed data view cannot stand in for them.
    pub(crate) fn borrowed_data_view(&self) -> Result<impl serde::Serialize + '_, ProviderError> {
        self.association.actor.ensure_current()?;
        Ok((
            "source-private.native-capture-sdk-quote-data/12",
            &self.data,
            metadata_values(self.retained),
            self.strong_edges,
            self.unique_shared_roots,
            "opaque-original-observe-cut",
        ))
    }

    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.association.actor.ensure_current()?;
        roots.observe_shared(
            observer,
            MetadataSharedKind::ProtocolOwner,
            self.association.actor.as_ref(),
        )?;
        if roots.observe_shared(
            observer,
            MetadataSharedKind::Codec,
            self.association.codec.as_ref(),
        )? {
            let Native5CodecOwner::NativePacket(policy) = self.association.codec.as_ref() else {
                return Err(refused());
            };
            if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
                policy.observe_unique_capture_metadata(roots, observer)?;
            }
        }
        if roots.observe_shared(
            observer,
            MetadataSharedKind::FrameBank,
            self.association.bank.as_ref(),
        )? {
            self.association
                .bank
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_owned11_metadata(observer)?;
        }
        // All remaining fields are inline numeric records and the opaque cut.
        // Observing each scalar contributes traversal work, not extra heap banks.
        observer.observe(&metadata_values(self.retained))?;
        observer.observe(&[self.strong_edges, self.unique_shared_roots])?;
        observe_sdk_data(&self.data, observer)
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Counts the actual SDK portion of a native Capture allocation report.
    ///
    /// Current actor/codec/class and original bank checks precede the service's
    /// registrar and supervisor guards. Under that loan only typed observation
    /// and bounded serialization run: there is no transport, containment or
    /// registration callback. Actual snapshot banks retain partial rows on error.
    /// No snapshot issuer/cut is bound and no encoded/literal copy is published.
    ///
    /// The Observe request itself is part of the current correlation state.
    /// Model/Control/endpoint/report owners and the future Capture request,
    /// response/prefix, transient copies and whole simultaneous admission remain
    /// the caller's explicit terms. Original bank growth is not an entire future
    /// native-state bound.
    pub(crate) fn quote_original_native_capture_sdk_state(
        &mut self,
        before: &mut ProtocolSnapshotReservation,
        after: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<NativeCaptureSdkStateQuote, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        self.original_native_owned11_admission()?;
        if !before.unused_for_after_preflight()
            || !after.unused_for_after_preflight()
            || !before.uses_owned11_encoding()
            || !after.uses_owned11_encoding()
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(refused());
        }
        self.preflight_protocol_reservation(before)?;
        self.preflight_protocol_reservation(after)?;
        before.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::NativeIncomingCapture,
            false,
        )?;
        after.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::HostSettled,
            false,
        )?;
        let selected = self
            .original_native5_protocol_metadata_limits()?
            .ok_or_else(refused)?;
        let (original_storage, literal_growth, descriptor_growth) = {
            let bank = self
                .original_frames
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            if !bank.complete() {
                return Err(refused());
            }
            let (literal, descriptors) = bank.maximum_encoding_growth(true)?;
            (
                bank.storage_facts(allowance(self.authority.limits().frame_bytes.get())?),
                literal,
                descriptors,
            )
        };
        // Validate the complete supported current owner family before taking
        // service guards. This validation walk is not reported as unique facts.
        if context.requires_original_native_startup_codec(self, blobs)? {
            self.observe_original_current_connection_metadata(&mut MetadataObserver::new())?;
        } else {
            self.observe_original_restore_connection_metadata(&mut MetadataObserver::new())?;
        }
        let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
        let service = context.borrow_current_original_protocol_data(self, blobs)?;
        let association = NativeCaptureSdkAssociation {
            actor: Rc::clone(&self.protocol_owner),
            codec: Rc::clone(self.native5_codec.as_ref().ok_or_else(refused)?),
            bank: Rc::clone(self.original_frames.as_ref().ok_or_else(refused)?),
            observe_cut: service.original_cut(),
        };
        let mut observer = MetadataObserver::new();
        let mut roots = NativeCaptureMetadataRoots::new();
        service.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        let connection = NativeCurrentConnectionView::borrow_original(self)?;
        connection.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        receiver.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        // These three strong handles are really owned by this data-walk capsule.
        // Their payloads have already been visited through the original roots.
        roots.observe_shared_edge(
            &mut observer,
            MetadataSharedKind::ProtocolOwner,
            association.actor.as_ref(),
        )?;
        roots.observe_shared_edge(
            &mut observer,
            MetadataSharedKind::Codec,
            association.codec.as_ref(),
        )?;
        roots.observe_shared_edge(
            &mut observer,
            MetadataSharedKind::FrameBank,
            association.bank.as_ref(),
        )?;
        let data = (
            service.current_protocol_format_data(),
            &connection,
            &receiver,
            &service,
        );
        let before_quote = before.quote_original_native_owned11(&data, |observer| {
            connection.observe(observer)?;
            receiver.observe_owned11_metadata(observer)?;
            service.observe_current_protocol_metadata_data(observer)
        })?;
        let after_quote = after.quote_original_native_owned11(&data, |observer| {
            connection.observe(observer)?;
            receiver.observe_owned11_metadata(observer)?;
            service.observe_current_protocol_metadata_data(observer)
        })?;
        if before_quote.selected_rows as u64 != selected.native_before_rows.get()
            || after_quote.selected_rows as u64 != selected.native_after_rows.get()
            || before_quote.frame_bank_views != after_quote.frame_bank_views
        {
            return Err(refused());
        }
        let frame_bank_views = before_quote.frame_bank_views;
        let maximum_literal_encoding_growth_bytes = literal_growth
            .checked_mul(frame_bank_views)
            .ok_or_else(credit)?;
        let maximum_descriptor_encoding_growth_bytes = descriptor_growth
            .checked_mul(frame_bank_views)
            .ok_or_else(credit)?;
        Ok(NativeCaptureSdkStateQuote {
            association, roots, observer,
            data: NativeCaptureSdkStateData {
            original_storage,
            before: bank_quote(before, before_quote.required_record_rows, before_quote.required_alias_rows, before_quote.encoded_extent)?,
            after: bank_quote(after, after_quote.required_record_rows, after_quote.required_alias_rows, after_quote.encoded_extent)?,
            frame_bank_views,
            maximum_literal_encoding_growth_bytes,
            maximum_descriptor_encoding_growth_bytes,
            future_capture_receive: super::native_capture_receive::NativeCaptureFutureReceiveQuote::from_negotiated_frame(original_storage.maximum_frame_bytes)?.with_original_guard_data(&self.guard)?,
            },
        })
    }
}

fn bank_quote(
    bank: &ProtocolSnapshotReservation,
    required_record_rows: usize,
    required_alias_rows: usize,
    current_encoded_extent: usize,
) -> Result<NativeCaptureSdkSnapshotBankQuote, ProviderError> {
    Ok(NativeCaptureSdkSnapshotBankQuote {
        allocation: bank.original_allocation_facts()?,
        records: bank
            .original_metadata_record_allocation_facts()?
            .ok_or_else(refused)?,
        aliases: bank
            .original_alias_allocation_facts()?
            .ok_or_else(refused)?,
        required_record_rows,
        required_alias_rows,
        current_encoded_extent,
    })
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native Capture SDK quote original state differs")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("native Capture SDK quote literal bank borrowed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native Capture SDK quote layout overflow")
}

fn metadata_values(facts: crate::retained_metadata::RetainedProtocolMetadataFacts) -> [usize; 14] {
    let crate::retained_metadata::RetainedProtocolMetadataFacts {
        string_capacity_bytes,
        string_banks,
        vector_capacity_bytes,
        vector_banks,
        boxed_value_bytes,
        shared_value_bytes,
        shared_backing_views,
        tree_containers,
        tree_entries,
        maximum_tree_key_value_bytes,
        maximum_tree_entry_alignment,
        maximum_shared_value_alignment,
        observed_nodes,
        capacity_records,
    } = facts;
    [
        string_capacity_bytes,
        string_banks,
        vector_capacity_bytes,
        vector_banks,
        boxed_value_bytes,
        shared_value_bytes,
        shared_backing_views,
        tree_containers,
        tree_entries,
        maximum_tree_key_value_bytes,
        maximum_tree_entry_alignment,
        maximum_shared_value_alignment,
        observed_nodes,
        capacity_records,
    ]
}

fn observe_sdk_data(
    data: &NativeCaptureSdkStateData,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let NativeCaptureSdkStateData {
        original_storage,
        before,
        after,
        frame_bank_views,
        maximum_literal_encoding_growth_bytes,
        maximum_descriptor_encoding_growth_bytes,
        future_capture_receive,
    } = data;
    let OriginalProtocolStorageFacts {
        maximum_frame_bytes,
        maximum_history_bytes,
        maximum_frames_per_direction,
        byte_capacity,
        descriptor_capacity,
        descriptor_bytes,
        allocated_bytes,
        retained_bytes,
        incoming_frames,
        outgoing_frames,
        all_io_complete,
    } = original_storage;
    observer.observe(&[
        *maximum_frame_bytes,
        *maximum_history_bytes,
        *maximum_frames_per_direction,
        *byte_capacity,
        *descriptor_capacity,
        *descriptor_bytes,
        *allocated_bytes,
        *retained_bytes,
        *incoming_frames,
        *outgoing_frames,
    ])?;
    observer.observe(all_io_complete)?;
    for bank in [before, after] {
        observe_snapshot_bank(bank, observer)?;
    }
    observer.observe(&[
        *frame_bank_views,
        *maximum_literal_encoding_growth_bytes,
        *maximum_descriptor_encoding_growth_bytes,
    ])?;
    future_capture_receive.observe_metadata(observer)
}

fn observe_snapshot_bank(
    bank: &NativeCaptureSdkSnapshotBankQuote,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let NativeCaptureSdkSnapshotBankQuote {
        allocation,
        records,
        aliases,
        required_record_rows,
        required_alias_rows,
        current_encoded_extent,
    } = bank;
    let ProtocolSnapshotAllocationFacts {
        maximum_encoded_bytes,
        encoded_capacity,
        encoded_length,
        literal,
        allocated_bytes,
    } = allocation;
    observer.observe(&[
        *maximum_encoded_bytes,
        *encoded_capacity,
        *encoded_length,
        *allocated_bytes,
    ])?;
    if let Some(crate::protocol_snapshot::ProtocolSnapshotLiteralAllocationFacts {
        maximum_history_bytes,
        maximum_frames_per_direction,
        byte_capacity,
        descriptor_capacity,
        descriptor_bytes,
        retained_bytes,
        allocated_bytes,
    }) = literal
    {
        observer.observe(&[
            *maximum_history_bytes,
            *maximum_frames_per_direction,
            *byte_capacity,
            *descriptor_capacity,
            *descriptor_bytes,
            *retained_bytes,
            *allocated_bytes,
        ])?;
    }
    let MetadataRecordAllocationFacts {
        maximum_rows,
        capacity_rows,
        retained_rows,
        allocated_bytes,
    } = records;
    observer.observe(&[
        *maximum_rows,
        *capacity_rows,
        *retained_rows,
        *allocated_bytes,
    ])?;
    let MetadataAliasAllocationFacts {
        maximum_rows,
        row_capacity,
        lookup_capacity,
        retained_rows,
        row_bytes,
        lookup_bytes,
    } = aliases;
    observer.observe(&[
        *maximum_rows,
        *row_capacity,
        *lookup_capacity,
        *retained_rows,
        *row_bytes,
        *lookup_bytes,
    ])?;
    observer.observe(&[
        *required_record_rows,
        *required_alias_rows,
        *current_encoded_extent,
    ])
}

mod owner;

impl NativeCaptureSdkCompletedQuote {
    /// Borrows the actual completed owner's full data and three shared roots.
    ///
    /// The containing new native-state12 encoder must walk this view with the
    /// SAME connection/service record+alias banks. Numeric report data alone
    /// cannot satisfy this owning class. The original Observe cut is retained
    /// by this owner and represented only as historical opaque-cut data.
    pub(crate) fn borrowed_owned12_protocol_view<'a>(
        &'a self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<impl serde::Serialize + 'a + use<'a>, ProviderError> {
        self.authenticate_same_target_data(connection, blobs, context)?;
        owner::borrow_original(self)
    }

    pub(crate) fn observe_owned12_metadata(
        &self,
        connection: &Connection<crate::client::DeadlineStream>,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_same_target_data(connection, blobs, context)?;
        owner::observe_original(self, observer)
    }
}
