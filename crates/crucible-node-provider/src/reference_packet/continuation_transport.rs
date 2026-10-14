//! Owns finite Capture reply transfers on the original authenticated connection.
//!
//! Preparation retains every prospective frame before publication. At most 32
//! outgoing requests enter correlation at once; completed windows return the
//! same connection to the next window. Every original frame and actual reply
//! remains owned on refusal or unwind. This transport mechanism grants no
//! native capture, restoration, source installation or content authority.

use std::collections::{BTreeMap, VecDeque};

use crucible_node_contract::{ContentRef, Id};

use crate::{ProviderError, bodies::*, connection::*, envelope::*};

mod confirmation;
mod confirmation_frames;
mod frames;
pub(crate) use confirmation::PacketAfterConfirmationPrefix;
pub(crate) use confirmation_frames::outgoing_confirmation_extent;

/// Bounds a complete Native5 snapshot transfer independently of legacy endpoints.
pub const MAXIMUM_CAPTURE_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
/// Bounds the independent unchanged-cut anchor accompanying that snapshot.
pub const MAXIMUM_CAPTURE_ANCHOR_BYTES: usize = 8192;
/// Bounds complete encoded originals, correlation copies and reply extents.
pub const MAXIMUM_CAPTURE_TRANSPORT_BYTES: usize = 512 * 1024 * 1024;
/// Bounds simultaneous requests without refunding lifetime journal identities.
pub const MAXIMUM_CAPTURE_WINDOW_REQUESTS: usize = 32;

/// Retains a complete prospective Capture prefix and its genuine transport history.
///
/// An independent source owner must retain its native state beside this owner.
/// Failure is sticky, including unwind: neither another preparation nor another
/// publication may resend any original window. No API replaces the connection.
#[must_use = "retain the original prefix alongside its independent native owner"]
pub struct PacketCapturePrefix<S: ProviderStream> {
    transport: Option<CaptureTransport<S>>,
    source: Option<CaptureSource>,
    windows: VecDeque<Vec<Envelope>>,
    records: Vec<ExchangeRecord>,
    contents: BTreeMap<Id, ContentRef>,
    maximum_chunk: u64,
    charged_bytes: usize,
    next_sequence: u64,
    state: PrefixState,
}

struct CaptureSource {
    response: Envelope,
    snapshot: (ContentRef, Vec<u8>),
    anchor: (ContentRef, Vec<u8>),
    control: Option<(ContentRef, Vec<u8>)>,
}

enum CaptureTransport<S: ProviderStream> {
    Connected(Connection<S>),
    Prepared(PreparedExchange<S>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrefixState {
    Unprepared,
    Prepared,
    Publishing,
    Complete,
    Failed,
}

impl<S: ProviderStream> PacketCapturePrefix<S> {
    /// Retains the original connection before invoking any preparation callback.
    pub fn new(connection: Connection<S>) -> Self {
        Self {
            transport: Some(CaptureTransport::Connected(connection)),
            source: None,
            windows: VecDeque::new(),
            records: Vec::new(),
            contents: BTreeMap::new(),
            maximum_chunk: 0,
            charged_bytes: 0,
            next_sequence: 0,
            state: PrefixState::Unprepared,
        }
    }

    /// Precharges and retains the exact Capture reply, snapshot and independent anchor.
    ///
    /// The caller supplies an already source-authenticated prospective completed
    /// response. This method verifies syntax, references and finite transport
    /// geometry, then registers only the first original window. The response sequence
    /// supplies the next provider sequence; the completed response receives the
    /// final sequence and its own window AFTER every actual Blob reply. It writes no
    /// bytes and performs no native effect. The journal leaf settling Capture is
    /// deliberately absent: it is retained locally after this prefix completes.
    ///
    /// # Errors
    /// Refuses reuse, wrong Capture scope or result, changed full references,
    /// insufficient negotiated credit, oversized bodies or sequence exhaustion.
    /// All supplied originals and the same connection remain owned on failure.
    ///
    /// # Panics
    /// Installed schema or supervision callbacks may panic. This borrowed owner
    /// retains the original first exchange and source bodies across unwind.
    pub fn prepare(
        &mut self,
        response: Envelope,
        snapshot: (ContentRef, Vec<u8>),
        anchor: (ContentRef, Vec<u8>),
    ) -> Result<(), ProviderError> {
        self.prepare_source(response, snapshot, anchor, None)
    }

    /// Retains and exports the separately promised original control snapshot.
    ///
    /// The complete Capture result must name this exact control object once.
    /// Every proof acknowledgement still precedes the terminal Capture reply.
    ///
    /// # Errors
    /// Refuses reuse, mismatched owner-state references, insufficient finite
    /// transport credit or any refusal also described by [`Self::prepare`].
    /// Supplied originals and the same connection remain retained on failure.
    ///
    /// # Panics
    /// Installed schema and supervision callbacks may panic. This owner retains
    /// the complete original source bodies and active window across unwind.
    pub fn prepare_complete(
        &mut self,
        response: Envelope,
        snapshot: (ContentRef, Vec<u8>),
        anchor: (ContentRef, Vec<u8>),
        control: (ContentRef, Vec<u8>),
    ) -> Result<(), ProviderError> {
        self.prepare_source(response, snapshot, anchor, Some(control))
    }

    fn prepare_source(
        &mut self,
        response: Envelope,
        snapshot: (ContentRef, Vec<u8>),
        anchor: (ContentRef, Vec<u8>),
        control: Option<(ContentRef, Vec<u8>)>,
    ) -> Result<(), ProviderError> {
        if self.state != PrefixState::Unprepared {
            return Err(ProviderError::Conflict(
                "capture prefix preparation already attempted",
            ));
        }
        self.state = PrefixState::Failed;
        self.source = Some(CaptureSource {
            response,
            snapshot,
            anchor,
            control,
        });
        let Some(CaptureTransport::Connected(connection)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict(
                "capture original connection unavailable",
            ));
        };
        let authority = connection.provider_authority()?;
        let source = self
            .source
            .as_ref()
            .ok_or(ProviderError::Conflict("capture source absent"))?;
        let plan = frames::plan(authority, source)?;
        self.windows = plan.windows;
        self.contents = plan.contents;
        self.maximum_chunk = plan.chunk;
        self.charged_bytes = plan.charged_bytes;
        self.next_sequence = plan.next_sequence;
        // Authenticate every future frame before the independent native effect.
        // The windows already reside in this owner if a verifier unwinds.
        for window in &self.windows {
            for original in window {
                connection.preflight_original_capture_frame(original)?;
            }
        }
        self.records
            .try_reserve_exact(self.windows.len())
            .map_err(|_| ProviderError::ResourceExhausted("capture whole exchange record slots"))?;
        self.prepare_next_window()?;
        self.state = PrefixState::Prepared;
        Ok(())
    }

    fn prepare_next_window(&mut self) -> Result<(), ProviderError> {
        let originals = self
            .windows
            .pop_front()
            .ok_or(ProviderError::Conflict("capture next window absent"))?;
        let Some(CaptureTransport::Connected(connection)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "capture original connection reserved",
            ));
        };
        // Install custody before schema or supervision callbacks can unwind.
        self.transport = Some(CaptureTransport::Prepared(
            connection.unprepared_exchange(originals),
        ));
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict("capture prepared window absent"));
        };
        exchange.prepare_in_place()
    }

    /// Bounds the after-suffix encoding on the same unpublished first window.
    ///
    /// This counts the entire finite literal bank and descriptor population.
    /// It neither predicts acknowledgements nor proves that the whole suffix
    /// fits those banks; the source separately authenticates that admission.
    ///
    /// # Errors
    /// Refuses a different phase, published bytes, foreign owner, changed bank,
    /// absent original blob binding or insufficient selected after credit.
    pub fn preflight_after_protocol_capacity(
        &self,
        after: &crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
    ) -> Result<crate::protocol_snapshot::Native5AfterProtocolCapacityFacts, ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict("capture after preflight phase"));
        }
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "capture after original window absent",
            ));
        };
        exchange.preflight_native5_after_protocol_capacity(after, blobs)
    }

    /// Publishes each original window once and retains every actual acknowledgement.
    ///
    /// # Errors
    /// Refuses a repeated attempt, I/O or correlation failure, invalid Blob
    /// replies or later-window preparation failure. The active incomplete window,
    /// completed history and unsent suffix remain retained without retry authority.
    ///
    /// # Panics
    /// Installed callbacks may panic. The active original exchange remains in
    /// this borrowed owner, and its connection is fenced by the exchange guard.
    pub fn publish(&mut self) -> Result<(), ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict(
                "capture prefix publication already attempted",
            ));
        }
        self.state = PrefixState::Publishing;
        let result = self.publish_original_windows();
        self.state = if result.is_ok() {
            PrefixState::Complete
        } else {
            PrefixState::Failed
        };
        result
    }

    fn publish_original_windows(&mut self) -> Result<(), ProviderError> {
        loop {
            let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_mut() else {
                return Err(ProviderError::Conflict(
                    "capture original window unavailable",
                ));
            };
            let contents = &self.contents;
            let chunk = self.maximum_chunk;
            exchange.publish(&mut |original, received| {
                validate_ack(contents, chunk, original, received)
            })?;
            let Some(CaptureTransport::Prepared(exchange)) = self.transport.take() else {
                return Err(ProviderError::Conflict(
                    "capture completed window disappeared",
                ));
            };
            let (connection, record) = exchange.into_parts();
            self.records.push(record);
            self.transport = Some(CaptureTransport::Connected(connection));
            if self.windows.is_empty() {
                return Ok(());
            }
            self.prepare_next_window()?;
        }
    }

    /// Moves the same connection after complete publication, retaining history here.
    ///
    /// # Errors
    /// Refuses an incomplete prefix or a second custody transfer. Completion
    /// concerns transport only and supplies no native capture authority.
    pub fn take_completed_connection(&mut self) -> Result<Connection<S>, ProviderError> {
        if self.state != PrefixState::Complete {
            return Err(ProviderError::Conflict("capture prefix incomplete"));
        }
        match self.transport.take() {
            Some(CaptureTransport::Connected(connection)) => Ok(connection),
            original => {
                self.transport = original;
                Err(ProviderError::Conflict(
                    "capture connection already transferred",
                ))
            }
        }
    }

    /// Borrows complete original records without cloning or issuing capture authority.
    pub fn records(&self) -> &[ExchangeRecord] {
        &self.records
    }

    /// Borrows the active incomplete window, including its received prefix.
    pub fn incomplete_window(&self) -> Option<&ExchangeRecord> {
        match &self.transport {
            Some(CaptureTransport::Prepared(exchange)) => Some(exchange.record()),
            _ => None,
        }
    }

    /// Reports the precharged whole-prefix extent, including maximum reply buffers.
    pub fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }

    /// Gives the original provider sequence immediately after the complete prefix.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Reports transport completion only, without granting native preservation.
    pub fn is_complete(&self) -> bool {
        self.state == PrefixState::Complete
    }
}

fn validate_ack(
    contents: &BTreeMap<Id, ContentRef>,
    chunk: u64,
    original: &Envelope,
    received: &ReceivedFrame,
) -> Result<(), ProviderError> {
    let ReceivedBody::Response(response) = &received.body else {
        return Err(ProviderError::Correlation(
            "capture prefix requires response",
        ));
    };
    if !matches!(response.shape, ResponseShape::Completed { .. }) {
        return Err(ProviderError::Correlation(
            "capture prefix acknowledgement incomplete",
        ));
    }
    let agrees = match (
        decode_request(original.method, &original.body)?,
        &response.result,
    ) {
        (RequestBody::BlobBegin(request), Some(MethodResult::BlobBegin(result))) => {
            result.transfer_id == request.transfer_id
                && result.next_offset.get() == 0
                && result.maximum_chunk_bytes.get() >= chunk.min(request.content.length.get())
        }
        (RequestBody::BlobChunk(request), Some(MethodResult::BlobChunk(result))) => {
            result.transfer_id == request.transfer_id
                && request
                    .offset
                    .checked_add(crucible_node_contract::U64::new(
                        request.bytes.as_slice().len() as u64,
                    ))?
                    == result.next_offset
        }
        (RequestBody::BlobFinish(request), Some(MethodResult::BlobFinish(result))) => {
            result.transfer_id == request.transfer_id
                && contents.get(&request.transfer_id) == Some(&result.content)
        }
        _ => false,
    };
    if !agrees {
        return Err(ProviderError::Correlation(
            "capture prefix acknowledgement changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

impl PacketCapturePrefix<crate::client::DeadlineStream> {
    pub(crate) fn preflight_owned11_after_protocol_capacity(
        &self,
        after: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &super::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<crate::connection::NativeOwned11AfterProtocolCapacityFacts, ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict(
                "capture owned11 after preflight phase",
            ));
        }
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "capture owned11 original window absent",
            ));
        };
        exchange.preflight_native_owned11_after_protocol_capacity(after, blobs, context)
    }
}
