//! Checked established public watch events and bound opaque cursors.

use aos_proto::aos::sandbox::v1::{Event, EventKind};
use buffa::Message as _;

use super::model::{
    InvalidQueryModel, OpaqueResponseBytesV1, OpaqueResponseKindV1, QueryBindingV1,
    MAXIMUM_PUBLIC_RESOURCE_BYTES,
};
use super::registry::checked_timestamp;
use super::resource::{checked_conditions, checked_results, PublicResourceTypeV1};

/// Maximum observation extensions in one public event.
pub const MAXIMUM_EVENT_EXTENSIONS: usize = 64;
/// Maximum bytes in one optional opaque observation extension.
pub const MAXIMUM_EVENT_EXTENSION_BYTES: usize = 1024 * 1024;

/// Reports an invalid established public watch event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidWatchEvent {
    /// A required identity, sequence, cursor, or watermark is absent.
    #[error("watch event contains an unspecified field")]
    Unspecified,
    /// An open event-kind enum is unknown or unspecified.
    #[error("watch event kind is unknown")]
    UnknownKind,
    /// Snapshot-complete watermark fields contradict the event kind.
    #[error("watch event watermark is inconsistent with its kind")]
    InvalidWatermark,
    /// Extensions are oversized or include unsupported required semantics.
    #[error("watch event extensions exceed supported bounded semantics")]
    InvalidExtensions,
    /// A required extension has no registered implementation in base v1.
    #[error("watch event requires an unsupported observation extension")]
    UnsupportedRequiredExtension,
    /// The encoded event exceeds its byte ceiling.
    #[error("watch event exceeds its encoded byte ceiling")]
    EventTooLarge,
    /// An opaque response field is malformed.
    #[error("watch event contains an invalid opaque field")]
    InvalidOpaque,
    /// A timestamp, condition, or resource reference is invalid.
    #[error("watch event contains an invalid nested public resource")]
    InvalidNestedResource,
}

impl From<InvalidQueryModel> for InvalidWatchEvent {
    fn from(_: InvalidQueryModel) -> Self {
        Self::InvalidOpaque
    }
}

/// Stores a server-issued cursor bound to complete local query semantics.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundWatchCursorV1 {
    binding: QueryBindingV1,
    bytes: OpaqueResponseBytesV1,
}

impl BoundWatchCursorV1 {
    pub(crate) fn from_checkpoint(
        binding: QueryBindingV1,
        bytes: Vec<u8>,
    ) -> Result<Self, InvalidWatchEvent> {
        Ok(Self {
            binding,
            bytes: OpaqueResponseBytesV1::from_response(bytes, OpaqueResponseKindV1::WatchCursor)?,
        })
    }

    /// Returns the complete local query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns server-issued cursor bytes for a matching resume request.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Stores a server-issued bootstrap watermark bound to the query semantics.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundWatchWatermarkV1 {
    binding: QueryBindingV1,
    bytes: OpaqueResponseBytesV1,
}

impl BoundWatchWatermarkV1 {
    pub(crate) fn from_response(
        binding: QueryBindingV1,
        bytes: Vec<u8>,
    ) -> Result<Self, InvalidWatchEvent> {
        Ok(Self {
            binding,
            bytes: OpaqueResponseBytesV1::from_response(
                bytes,
                OpaqueResponseKindV1::WatchWatermark,
            )?,
        })
    }

    /// Returns the complete local query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns server-issued watermark bytes for matching bootstrap state.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Stores a fully checked established public event.
#[derive(Clone, PartialEq)]
pub struct CheckedWatchEventV1 {
    event_id: [u8; 16],
    sequence: u64,
    kind: EventKind,
    cursor: BoundWatchCursorV1,
    watermark: Option<BoundWatchWatermarkV1>,
    wire: Event,
    public_wire: Event,
}

impl std::fmt::Debug for CheckedWatchEventV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedWatchEventV1")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("encoded_bytes", &self.wire.compute_size())
            .finish_non_exhaustive()
    }
}

impl CheckedWatchEventV1 {
    /// Checks one public event under the normalized query binding that received it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWatchEvent`] for sentinel identities, unknown kinds,
    /// inconsistent watermark fields, required extensions, or byte-bound
    /// violations.
    pub fn from_response(binding: QueryBindingV1, wire: Event) -> Result<Self, InvalidWatchEvent> {
        if wire.compute_size() as usize > MAXIMUM_PUBLIC_RESOURCE_BYTES {
            return Err(InvalidWatchEvent::EventTooLarge);
        }
        let event_id: [u8; 16] = wire
            .event_id
            .as_slice()
            .try_into()
            .map_err(|_| InvalidWatchEvent::Unspecified)?;
        if event_id == [0; 16] || wire.sequence == 0 {
            return Err(InvalidWatchEvent::Unspecified);
        }
        let kind = wire
            .kind
            .as_known()
            .filter(|value| *value != EventKind::EVENT_KIND_UNSPECIFIED)
            .ok_or(InvalidWatchEvent::UnknownKind)?;
        if wire.extensions.iter().any(|extension| extension.required) {
            return Err(InvalidWatchEvent::UnsupportedRequiredExtension);
        }
        if wire.extensions.len() > MAXIMUM_EVENT_EXTENSIONS
            || wire.extensions.iter().any(|extension| {
                extension.schema_version == 0
                    || extension.payload.len() > MAXIMUM_EVENT_EXTENSION_BYTES
                    || extension.type_url.is_empty()
                    || extension.type_url.len() > 512
                    || extension.type_url.chars().any(char::is_control)
            })
        {
            return Err(InvalidWatchEvent::InvalidExtensions);
        }
        if !wire.extensions.windows(2).all(|pair| {
            (&pair[0].type_url, pair[0].schema_version)
                < (&pair[1].type_url, pair[1].schema_version)
        }) {
            return Err(InvalidWatchEvent::InvalidExtensions);
        }
        if !wire.operation_id.is_empty()
            && (wire.operation_id.len() != 16 || wire.operation_id.as_slice() == [0; 16])
        {
            return Err(InvalidWatchEvent::Unspecified);
        }
        checked_timestamp(
            wire.observed_at
                .as_option()
                .ok_or(InvalidWatchEvent::Unspecified)?,
        )
        .map_err(|_| InvalidWatchEvent::InvalidNestedResource)?;
        checked_conditions(&wire.conditions)
            .map_err(|_| InvalidWatchEvent::InvalidNestedResource)?;

        let checked_resource = wire
            .resource
            .as_option()
            .map(|resource| checked_results(std::slice::from_ref(resource)))
            .transpose()
            .map_err(|_| InvalidWatchEvent::InvalidNestedResource)?
            .and_then(|mut resources| resources.pop());
        let has_resource = checked_resource.is_some();
        let structural_fields_are_valid = match kind {
            EventKind::EVENT_KIND_RESOURCE_CREATED
            | EventKind::EVENT_KIND_RESOURCE_UPDATED
            | EventKind::EVENT_KIND_RESOURCE_DELETED => has_resource,
            EventKind::EVENT_KIND_OPERATION_UPDATED => {
                checked_resource.as_ref().is_some_and(|resource| {
                    resource.resource_type() == PublicResourceTypeV1::Operation
                        && resource.resource_id().as_slice() == wire.operation_id
                })
            }
            EventKind::EVENT_KIND_AUDIT => true,
            EventKind::EVENT_KIND_SNAPSHOT_COMPLETE => {
                !has_resource && wire.operation_id.is_empty() && wire.conditions.is_empty()
            }
            EventKind::EVENT_KIND_UNSPECIFIED => false,
        };
        if !structural_fields_are_valid {
            return Err(InvalidWatchEvent::InvalidNestedResource);
        }
        let cursor = BoundWatchCursorV1 {
            binding,
            bytes: OpaqueResponseBytesV1::from_response(
                wire.resume_cursor.clone(),
                OpaqueResponseKindV1::WatchCursor,
            )?,
        };
        let watermark = if kind == EventKind::EVENT_KIND_SNAPSHOT_COMPLETE {
            Some(BoundWatchWatermarkV1::from_response(
                binding,
                wire.bootstrap_watermark.clone(),
            )?)
        } else {
            if !wire.bootstrap_watermark.is_empty() {
                return Err(InvalidWatchEvent::InvalidWatermark);
            }
            None
        };
        let mut public_wire = wire.clone();
        public_wire
            .extensions
            .retain(|extension| extension.safe_for_opaque_display);
        Ok(Self {
            event_id,
            sequence: wire.sequence,
            kind,
            cursor,
            watermark,
            wire,
            public_wire,
        })
    }

    /// Returns the stable event identity.
    #[must_use]
    pub const fn event_id(&self) -> [u8; 16] {
        self.event_id
    }

    /// Returns the stream sequence supplied by the server.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the checked event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Returns the cursor after fully applying this event.
    #[must_use]
    pub const fn cursor(&self) -> &BoundWatchCursorV1 {
        &self.cursor
    }

    /// Returns the snapshot watermark only for snapshot-complete events.
    #[must_use]
    pub const fn watermark(&self) -> Option<&BoundWatchWatermarkV1> {
        self.watermark.as_ref()
    }

    /// Returns the checked public event with nondisplay extensions removed.
    #[must_use]
    pub const fn as_proto(&self) -> &Event {
        &self.public_wire
    }

    /// Consumes the wrapper and returns the checked public event projection.
    #[must_use]
    pub fn into_proto(self) -> Event {
        self.public_wire
    }

    pub(crate) fn encoded_byte_cost(&self) -> usize {
        self.wire.compute_size() as usize
    }
}
