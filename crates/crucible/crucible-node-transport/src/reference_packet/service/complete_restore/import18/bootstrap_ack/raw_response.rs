//! Retains an unparsed Bootstrap response and its independently parsed tree.
//!
//! ```text
//! header[received] || body[received] -> closed raw preflight -> strict Value
//! ```
//!
//! These private-field DATA owners grant no correlation, signing or completion
//! authority. The actual original Session authenticates their journal occurrence.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crate::transport::RetainedFrame;
use std::mem::size_of;

/// Preserves independently derived raw-bank, parser and containment demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapRawResponseRowData {
    pub(crate) axes: [usize; 3],
    pub(crate) maximum_body_bytes: usize,
}

impl PacketNativeImport18BootstrapRawResponseRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }

    /// Returns the concrete body-bank capacity requested before receiving.
    pub const fn maximum_body_bytes_data(self) -> usize {
        self.maximum_body_bytes
    }
}

/// Preserves the raw component and its independently quoted Controller guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapReceiveRowData {
    pub(crate) component: PacketNativeImport18BootstrapRawResponseRowData,
    pub(crate) axes: [usize; 3],
}

impl PacketNativeImport18BootstrapReceiveRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }

    /// Returns the actual raw component, including its concrete body-bank capacity.
    pub const fn raw_component_data(self) -> PacketNativeImport18BootstrapRawResponseRowData {
        self.component
    }
}

/// Preserves actual header/body prefixes and a separately constructed strict tree.
pub struct PacketNativeImport18BootstrapRawResponseData {
    pub(crate) owner: ProtocolCaptureOwner,
    pub(crate) row: PacketNativeImport18BootstrapRawResponseRowData,
    pub(crate) header: [u8; 4],
    pub(crate) header_received: usize,
    pub(crate) body: Vec<u8>,
    pub(crate) body_received: usize,
    pub(crate) slot: Option<usize>,
    pub(crate) frame: Option<RetainedFrame>,
    pub(crate) complete: bool,
    pub(crate) preflighted: bool,
    pub(crate) parsed: bool,
    pub(crate) failed: bool,
}

/// Borrows physical receipt and parse progress without lending protocol authority.
pub struct PacketNativeImport18BootstrapRawResponseHistoryData<'a> {
    /// Borrows the exact saved independently admitted component row.
    pub row: &'a PacketNativeImport18BootstrapRawResponseRowData,
    /// Preserves the original header, including its initialized unread suffix.
    pub header: &'a [u8; 4],
    /// Counts actual header bytes read before any later refusal.
    pub header_received: usize,
    /// Borrows the actual body bank, including its initialized unread suffix.
    pub body: &'a [u8],
    /// Counts actual body bytes read before any later refusal.
    pub body_received: usize,
    /// Preserves an initialized incoming original slot after either outcome.
    pub slot: Option<usize>,
    /// Borrows the separately parsed strict tree after either outcome.
    pub value: Option<&'a serde_json::Value>,
    /// Reports complete physical receipt independently of parsing.
    pub complete: bool,
    /// Reports successful allocation-free closed grammar inspection.
    pub preflighted: bool,
    /// Reports successful strict parsing independently of later guards.
    pub parsed: bool,
    /// Reports a refused once-only attempt while preserving its actual outputs.
    pub failed: bool,
}

impl PacketNativeImport18BootstrapRawResponseData {
    /// Borrows actual receipt and parser outputs without cloning or decoding them.
    ///
    /// # Errors
    /// Refuses foreign process or thread custody.
    pub fn borrowed_history_data(
        &self,
    ) -> Result<PacketNativeImport18BootstrapRawResponseHistoryData<'_>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(PacketNativeImport18BootstrapRawResponseHistoryData {
            row: &self.row,
            header: &self.header,
            header_received: self.header_received,
            body: self
                .frame
                .as_ref()
                .map_or(self.body.as_slice(), |frame| frame.bytes.as_slice()),
            body_received: self.body_received,
            slot: self.slot,
            value: self.frame.as_ref().map(|frame| &frame.value),
            complete: self.complete,
            preflighted: self.preflighted,
            parsed: self.parsed,
            failed: self.failed,
        })
    }

    /// Counts actual surviving banks and tree backing after either outcome.
    ///
    /// The enclosing holder independently includes its real Session and journal;
    /// this owner contains no second shared journal edge to discount.
    ///
    /// # Errors
    /// Refuses foreign custody, checked traversal exhaustion or storage overflow.
    pub fn retained_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_retained_into_data(&mut observer)?;
        size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or(ProviderError::ResourceExhausted(
                "Bootstrap raw response backing",
            ))
    }

    /// Adds every actual raw/parser bank to the enclosing metadata census.
    ///
    /// # Errors
    /// Refuses foreign custody or checked metadata traversal exhaustion.
    pub(crate) fn observe_retained_into_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            owner,
            row: _,
            header: _,
            header_received: _,
            body,
            body_received: _,
            slot: _,
            frame,
            complete: _,
            preflighted: _,
            parsed: _,
            failed: _,
        } = self;
        owner.ensure_current()?;
        observer.observe(body)?;
        if let Some(frame) = frame {
            observer.observe(&frame.bytes)?;
            observer.observe(&frame.value)?;
        }
        Ok(())
    }
}
