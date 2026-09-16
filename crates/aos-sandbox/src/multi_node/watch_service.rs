//! Dormant ordered-watch producer and consumer adapters.
//!
//! These in-memory adapters enforce bootstrap, gap, predecessor, and sequence
//! rules. They expose no RPC handler, stream, task, listener, or readiness bit.

use std::collections::VecDeque;

use aos_proto::ProstMessage as _;
use aos_proto::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    CanonicalNodeSemanticCodecV1, InvalidMultiNodeProtocol, MAX_WATCH_EVENTS, NodeWatchBindingV1,
    NodeWatchBootstrapV1, NodeWatchCursorV1, NodeWatchEventBodyV1, NodeWatchEventV1,
    stable_watch_event_uid,
};

/// Maximum source-only retained history admitted by the dormant adapter.
pub const MAX_DORMANT_WATCH_HISTORY: usize = 65_536;

/// Produces exact ordered event batches from a validated bootstrap.
pub struct DormantOrderedWatchServiceV1 {
    cursor: NodeWatchCursorV1,
    retained: VecDeque<NodeWatchEventV1>,
    maximum_retained_events: usize,
    codec: CanonicalNodeSemanticCodecV1,
}

impl DormantOrderedWatchServiceV1 {
    /// Constructs an unregistered ordered-watch producer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::InvalidFrameLimits`] for a zero or
    /// excessive retention bound.
    pub fn new(
        bootstrap: NodeWatchBootstrapV1,
        maximum_retained_events: usize,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if maximum_retained_events == 0 || maximum_retained_events > MAX_DORMANT_WATCH_HISTORY {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        Ok(Self {
            cursor: bootstrap.cursor(),
            retained: VecDeque::new(),
            maximum_retained_events,
            codec: CanonicalNodeSemanticCodecV1::new(),
        })
    }

    /// Appends one exact node-local event after its predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for sequence overflow, cross-node
    /// content, or noncanonical protobuf semantic bytes.
    pub fn publish(
        &mut self,
        body: NodeWatchEventBodyV1,
    ) -> Result<NodeWatchCursorV1, InvalidMultiNodeProtocol> {
        if self.retained.len() == self.maximum_retained_events {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        let sequence = self
            .cursor
            .event_sequence()
            .checked_add(1)
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        let predecessor = self.cursor.last_event_uid();
        let canonical = self.codec.encode_watch_event_body(&body)?;
        let canonical_digest = ObjectDigest::from_bytes(Sha256::digest(&canonical).into());
        let event_uid = stable_watch_event_uid(
            self.cursor.binding(),
            self.cursor.lineage(),
            sequence,
            predecessor,
            canonical_digest,
        );
        let cursor = NodeWatchCursorV1::new(
            self.cursor.node(),
            self.cursor.lineage(),
            self.cursor.binding(),
            sequence,
            event_uid,
        )?;
        let event =
            NodeWatchEventV1::from_authenticated_history(cursor, predecessor, body, &self.codec)?;
        self.retained.push_back(event);
        self.cursor = cursor;
        Ok(cursor)
    }

    /// Reads a bounded batch strictly after an exact cursor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for zero/excessive limits, a future
    /// cursor, or a substituted event UID at a retained sequence.
    pub fn read_after(
        &self,
        after: NodeWatchCursorV1,
        maximum_events: u16,
    ) -> Result<DormantWatchReadOutcomeV1, InvalidMultiNodeProtocol> {
        if maximum_events == 0 || usize::from(maximum_events) > MAX_WATCH_EVENTS {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        if after.node() != self.cursor.node()
            || after.lineage() != self.cursor.lineage()
            || after.binding() != self.cursor.binding()
        {
            return Ok(DormantWatchReadOutcomeV1::ResyncRequired(
                self.cursor.binding(),
            ));
        }
        if after.event_sequence() > self.cursor.event_sequence() {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
        }
        if after.event_sequence() == self.cursor.event_sequence() {
            if after.last_event_uid() != self.cursor.last_event_uid() {
                return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
            }
            return Ok(DormantWatchReadOutcomeV1::Events(Vec::new()));
        }
        let Some(first) = self.retained.front() else {
            return Ok(DormantWatchReadOutcomeV1::ResyncRequired(
                self.cursor.binding(),
            ));
        };
        let expected_first = after
            .event_sequence()
            .checked_add(1)
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        if expected_first < first.cursor().event_sequence() {
            return Ok(DormantWatchReadOutcomeV1::ResyncRequired(
                self.cursor.binding(),
            ));
        }
        let events = self
            .retained
            .iter()
            .filter(|event| event.cursor().event_sequence() > after.event_sequence())
            .take(usize::from(maximum_events))
            .cloned()
            .collect::<Vec<_>>();
        if events.first().is_some_and(|event| {
            event.cursor().event_sequence() != expected_first
                || event.predecessor_event_uid() != after.last_event_uid()
        }) {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
        }
        Ok(DormantWatchReadOutcomeV1::Events(events))
    }

    /// Consumes and produces the generated ordered-watch protobuf carriers.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] when the generated cursor is
    /// incomplete, noncanonical, outside the retained history, or asks for an
    /// invalid batch size.
    pub fn read_generated(
        &self,
        request: wire::OrderedWatchRequest,
    ) -> Result<wire::OrderedWatchBatch, InvalidMultiNodeProtocol> {
        let signed_request = request.clone();
        let after = super::protocol::semantic_codec_v1::protobuf_cursor_model(
            request
                .cursor
                .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        )?;
        let maximum_events = u16::try_from(request.maximum_events)
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        let canonical_request = wire::OrderedWatchRequest {
            cursor: Some(super::protocol::semantic_codec_v1::protobuf_cursor(after)),
            maximum_events: u32::from(maximum_events),
        };
        if canonical_request != signed_request {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }

        let batch = match self.read_after(after, maximum_events)? {
            DormantWatchReadOutcomeV1::Events(events) => wire::OrderedWatchBatch {
                next_cursor: Some(events.last().map_or_else(
                    || super::protocol::semantic_codec_v1::protobuf_cursor(after),
                    |event| super::protocol::semantic_codec_v1::protobuf_cursor(event.cursor()),
                )),
                events: events
                    .iter()
                    .map(super::protocol::semantic_codec_v1::protobuf_ordered_event)
                    .collect(),
                resync_binding: None,
            },
            DormantWatchReadOutcomeV1::ResyncRequired(binding) => wire::OrderedWatchBatch {
                events: Vec::new(),
                next_cursor: None,
                resync_binding: Some(super::protocol::semantic_codec_v1::protobuf_binding(
                    binding,
                )),
            },
        };
        if let Some(binding) = batch.resync_binding.clone()
            && {
                let binding = super::protocol::semantic_codec_v1::protobuf_binding_model(binding)?;
                binding != self.cursor.binding() || !resync_binding_follows_cursor(binding, after)
            }
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        validate_generated_batch(&batch)?;
        Ok(batch)
    }

    /// Returns the latest producer cursor.
    #[must_use]
    pub const fn cursor(&self) -> NodeWatchCursorV1 {
        self.cursor
    }
}

/// Reports an ordered event page or a typed resynchronization edge.
#[must_use]
pub enum DormantWatchReadOutcomeV1 {
    /// Contains events strictly after the requested cursor.
    Events(Vec<NodeWatchEventV1>),
    /// Requires a fresh authenticated inventory under this binding.
    ResyncRequired(NodeWatchBindingV1),
}

/// Consumes ordered event pages after one validated bootstrap.
pub struct DormantOrderedWatchClientV1 {
    cursor: NodeWatchCursorV1,
}

impl DormantOrderedWatchClientV1 {
    /// Constructs a consumer at a complete authenticated bootstrap watermark.
    #[must_use]
    pub const fn new(bootstrap: NodeWatchBootstrapV1) -> Self {
        Self {
            cursor: bootstrap.cursor(),
        }
    }

    /// Applies one producer outcome atomically to the local cursor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for a gap, reordered sequence,
    /// predecessor substitution, or changed node/boot/binding.
    pub fn apply(
        &mut self,
        outcome: DormantWatchReadOutcomeV1,
    ) -> Result<DormantWatchClientOutcomeV1, InvalidMultiNodeProtocol> {
        let events = match outcome {
            DormantWatchReadOutcomeV1::Events(events) => events,
            DormantWatchReadOutcomeV1::ResyncRequired(binding) => {
                if binding.coordinator_epoch() != self.cursor.binding().coordinator_epoch()
                    || binding.audience_digest() != self.cursor.binding().audience_digest()
                    || binding.disclosure_domain_digest()
                        != self.cursor.binding().disclosure_domain_digest()
                    || !resync_binding_follows_cursor(binding, self.cursor)
                {
                    return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
                }
                return Ok(DormantWatchClientOutcomeV1::ResyncRequired { binding });
            }
        };
        let mut next = self.cursor;
        for event in &events {
            let cursor = event.cursor();
            let expected_sequence = next
                .event_sequence()
                .checked_add(1)
                .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
            if cursor.node() != next.node()
                || cursor.lineage() != next.lineage()
                || cursor.binding() != next.binding()
                || cursor.event_sequence() != expected_sequence
                || event.predecessor_event_uid() != next.last_event_uid()
            {
                return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
            }
            next = cursor;
        }
        self.cursor = next;
        Ok(DormantWatchClientOutcomeV1::Advanced {
            events: events.len(),
            cursor: next,
        })
    }

    /// Applies one generated ordered-watch batch under authenticated evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] when typed fields are incomplete,
    /// a body is not bound to the authenticated context, or ordering changes.
    pub fn apply_generated(
        &mut self,
        batch: wire::OrderedWatchBatch,
        context: super::AuthenticatedEvidenceContextV1,
    ) -> Result<DormantWatchClientOutcomeV1, InvalidMultiNodeProtocol> {
        validate_generated_batch(&batch)?;
        let signed_batch = batch.clone();
        if let Some(binding) = batch.resync_binding {
            if !batch.events.is_empty() || batch.next_cursor.is_some() {
                return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
            }
            let binding = super::protocol::semantic_codec_v1::protobuf_binding_model(binding)?;
            if binding.coordinator_epoch() != context.coordinator_epoch()
                || binding.audience_digest() != context.audience_digest()
                || binding.disclosure_domain_digest() != context.disclosure_domain_digest()
                || context.node() != self.cursor.node()
                || context.lineage() != self.cursor.lineage()
                || !resync_binding_follows_cursor(binding, self.cursor)
            {
                return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
            }
            let canonical_batch = wire::OrderedWatchBatch {
                events: Vec::new(),
                next_cursor: None,
                resync_binding: Some(super::protocol::semantic_codec_v1::protobuf_binding(
                    binding,
                )),
            };
            if canonical_batch != signed_batch {
                return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
            }
            return Ok(DormantWatchClientOutcomeV1::ResyncRequired { binding });
        }
        if batch.events.len() > MAX_WATCH_EVENTS {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let events = batch
            .events
            .into_iter()
            .map(|event| {
                super::protocol::semantic_codec_v1::protobuf_ordered_event_model(
                    event,
                    context,
                    &CanonicalNodeSemanticCodecV1::new(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_next = events.last().map_or(self.cursor, |event| event.cursor());
        let next = super::protocol::semantic_codec_v1::protobuf_cursor_model(
            batch
                .next_cursor
                .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?,
        )?;
        if next != expected_next {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
        }
        let canonical_batch = wire::OrderedWatchBatch {
            events: events
                .iter()
                .map(super::protocol::semantic_codec_v1::protobuf_ordered_event)
                .collect(),
            next_cursor: Some(super::protocol::semantic_codec_v1::protobuf_cursor(next)),
            resync_binding: None,
        };
        if canonical_batch != signed_batch {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        self.apply(DormantWatchReadOutcomeV1::Events(events))
    }

    /// Returns the last fully applied cursor.
    #[must_use]
    pub const fn cursor(&self) -> NodeWatchCursorV1 {
        self.cursor
    }
}

fn resync_binding_follows_cursor(binding: NodeWatchBindingV1, cursor: NodeWatchCursorV1) -> bool {
    let prior = cursor.binding();
    binding.query_digest() == prior.query_digest()
        && binding.authorization_digest() == prior.authorization_digest()
        && binding.schema() == prior.schema()
        && binding.history_floor_sequence() >= prior.history_floor_sequence()
        && (binding.history_floor_sequence() != prior.history_floor_sequence()
            || binding.history_floor_event_uid() == prior.history_floor_event_uid())
        && binding.bootstrap_watermark() >= cursor.event_sequence()
        && (binding != prior || binding.bootstrap_watermark() > cursor.event_sequence())
}

fn validate_generated_batch(
    batch: &wire::OrderedWatchBatch,
) -> Result<(), InvalidMultiNodeProtocol> {
    if batch.encoded_len() == 0
        || batch.encoded_len() > super::MAX_NODE_RESPONSE_BYTES as usize
        || (batch.resync_binding.is_some()
            && (!batch.events.is_empty() || batch.next_cursor.is_some()))
        || (batch.resync_binding.is_none() && batch.next_cursor.is_none())
    {
        return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
    }
    Ok(())
}

/// Reports consumer progress without activating a stream.
#[must_use]
pub enum DormantWatchClientOutcomeV1 {
    /// The page was applied through this exact cursor.
    Advanced {
        /// Number of applied events.
        events: usize,
        /// Last fully applied cursor.
        cursor: NodeWatchCursorV1,
    },
    /// The producer required a fresh authenticated bootstrap.
    ResyncRequired {
        /// Authenticated binding required by the replacement bootstrap.
        binding: NodeWatchBindingV1,
    },
}
