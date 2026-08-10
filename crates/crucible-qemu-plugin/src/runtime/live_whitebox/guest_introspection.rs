//! Guest-buffer rendezvous for the shared-memory introspection rings.

use crucible_protocol::guest_introspection_doorbell::{
    GUEST_INTROSPECTION_DOORBELL_MAGIC, GuestIntrospectionDoorbellFrame,
    GuestIntrospectionDoorbellKind,
};
use crucible_shmem::{DetachedPluginGuestIntrospectionRings, GuestIntrospectionEntry};
use thiserror::Error;

use super::app_random::LiveGuestMemoryWriter;
use super::*;
use crate::{WhiteboxGuestInput, WhiteboxGuestInputCapability};

pub(super) fn is_exchange(payload: &[u8]) -> bool {
    payload.starts_with(&GUEST_INTROSPECTION_DOORBELL_MAGIC)
}

pub(super) struct LiveGuestIntrospectionState {
    rings: DetachedPluginGuestIntrospectionRings,
    input_capability: WhiteboxGuestInputCapability,
    next_response_sequence: u64,
    next_request_sequence: u64,
}

impl LiveGuestIntrospectionState {
    pub(super) const fn new(
        rings: DetachedPluginGuestIntrospectionRings,
        input_capability: WhiteboxGuestInputCapability,
    ) -> Self {
        Self {
            rings,
            input_capability,
            next_response_sequence: 1,
            next_request_sequence: 1,
        }
    }
}

trait PluginGuestIntrospectionIo {
    fn peek_request(&mut self) -> Result<Option<GuestIntrospectionEntry>, PluginIoError>;
    fn commit_request(&mut self, expected_sequence: u64) -> Result<(), PluginIoError>;
    fn enqueue_response(&mut self, entry: GuestIntrospectionEntry) -> Result<(), PluginIoError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
enum PluginIoError {
    #[error("guest introspection response ring is full")]
    Full,
    #[error("guest introspection transport failed: {message}")]
    Fatal { message: String },
}

impl PluginIoError {
    fn fatal(error: impl ToString) -> Self {
        Self::Fatal {
            message: error.to_string(),
        }
    }
}

impl PluginGuestIntrospectionIo for DetachedPluginGuestIntrospectionRings {
    fn peek_request(&mut self) -> Result<Option<GuestIntrospectionEntry>, PluginIoError> {
        self.peek_request().map_err(PluginIoError::fatal)
    }

    fn commit_request(&mut self, expected_sequence: u64) -> Result<(), PluginIoError> {
        self.commit_request(expected_sequence)
            .map_err(PluginIoError::fatal)
    }

    fn enqueue_response(&mut self, entry: GuestIntrospectionEntry) -> Result<(), PluginIoError> {
        self.enqueue_response(entry).map_err(|error| match error {
            crucible_shmem::SpscRingError::QueueFull { .. } => PluginIoError::Full,
            error => PluginIoError::fatal(error),
        })
    }
}

impl LiveWhiteboxState {
    pub(super) fn handle_guest_introspection(
        &mut self,
        _reader: &mut LiveGuestMemoryReader,
        event: WhiteboxDoorbellTrapEvent,
        payload: &[u8],
    ) -> Result<(), LiveWhiteboxError> {
        let exchange = GuestIntrospectionDoorbellFrame::decode(payload).map_err(callback_error)?;
        let routed = route_exchange(
            &mut self.guest_introspection.rings,
            &mut self.guest_introspection.next_response_sequence,
            self.guest_introspection.next_request_sequence,
            exchange,
        )
        .map_err(callback_error)?;
        let reply = routed.reply.encode().map_err(callback_error)?;
        let mut writer = LiveGuestMemoryWriter::new(self.apis, event.current_icount());
        let input = WhiteboxGuestInput::new(
            event.current_icount(),
            event.payload_range(),
            reply.to_vec(),
        );
        self.doorbell
            .inject_guest_input(
                &self.guest_introspection.input_capability,
                &mut writer,
                event.current_icount(),
                &input,
            )
            .map_err(callback_error)?;
        if let Some(sequence) = routed.delivered_request_sequence {
            self.guest_introspection.next_request_sequence =
                commit_delivered_request(&mut self.guest_introspection.rings, sequence)
                    .map_err(callback_error)?;
        }
        Ok(())
    }
}

fn commit_delivered_request(
    rings: &mut impl PluginGuestIntrospectionIo,
    sequence: u64,
) -> Result<u64, PluginIoError> {
    rings.commit_request(sequence)?;
    sequence
        .checked_add(1)
        .ok_or_else(|| PluginIoError::fatal("request sequence overflow"))
}

struct RoutedExchange {
    reply: GuestIntrospectionDoorbellFrame,
    delivered_request_sequence: Option<u64>,
}

fn route_exchange(
    rings: &mut impl PluginGuestIntrospectionIo,
    next_response_sequence: &mut u64,
    next_request_sequence: u64,
    exchange: GuestIntrospectionDoorbellFrame,
) -> Result<RoutedExchange, PluginIoError> {
    match exchange.kind() {
        GuestIntrospectionDoorbellKind::Poll => {}
        GuestIntrospectionDoorbellKind::Response => {
            let record = exchange.record().ok_or_else(|| {
                PluginIoError::fatal("response exchange omitted its validated record")
            })?;
            record
                .validate_guest_response()
                .map_err(PluginIoError::fatal)?;
            let encoded = record.encode().map_err(PluginIoError::fatal)?;
            let following_sequence = next_response_sequence
                .checked_add(1)
                .ok_or_else(|| PluginIoError::fatal("response sequence overflow"))?;
            let entry = GuestIntrospectionEntry::new(*next_response_sequence, &encoded)
                .map_err(PluginIoError::fatal)?;
            match rings.enqueue_response(entry) {
                Ok(()) => {}
                Err(PluginIoError::Full) => {
                    return Ok(RoutedExchange {
                        reply: GuestIntrospectionDoorbellFrame::retry(),
                        delivered_request_sequence: None,
                    });
                }
                Err(error @ PluginIoError::Fatal { .. }) => return Err(error),
            }
            *next_response_sequence = following_sequence;
        }
        GuestIntrospectionDoorbellKind::Idle
        | GuestIntrospectionDoorbellKind::Request
        | GuestIntrospectionDoorbellKind::Retry => {
            return Err(PluginIoError::fatal(
                "guest supplied a plugin-to-guest exchange kind",
            ));
        }
    }

    match rings.peek_request()? {
        Some(entry) => {
            if entry.sequence() != next_request_sequence {
                return Err(PluginIoError::fatal(format!(
                    "request sequence mismatch: expected {next_request_sequence}, actual {}",
                    entry.sequence()
                )));
            }
            let record = crucible_protocol::guest_introspection::GuestIntrospectionRecord::decode(
                entry.record().map_err(PluginIoError::fatal)?,
            )
            .map_err(PluginIoError::fatal)?;
            record
                .validate_host_request()
                .map_err(PluginIoError::fatal)?;
            Ok(RoutedExchange {
                reply: GuestIntrospectionDoorbellFrame::request(record),
                delivered_request_sequence: Some(entry.sequence()),
            })
        }
        None => Ok(RoutedExchange {
            reply: GuestIntrospectionDoorbellFrame::idle(),
            delivered_request_sequence: None,
        }),
    }
}

fn callback_error(source: impl ToString) -> LiveWhiteboxError {
    LiveWhiteboxError::Callback {
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crucible_protocol::guest_introspection::{
        GuestIntrospectionMessage, GuestIntrospectionRecord,
    };

    use super::*;

    #[derive(Default)]
    struct FakeRings {
        requests: VecDeque<GuestIntrospectionEntry>,
        responses: Vec<GuestIntrospectionEntry>,
        response_full: bool,
    }

    impl PluginGuestIntrospectionIo for FakeRings {
        fn peek_request(&mut self) -> Result<Option<GuestIntrospectionEntry>, PluginIoError> {
            Ok(self.requests.front().copied())
        }

        fn commit_request(&mut self, expected_sequence: u64) -> Result<(), PluginIoError> {
            let entry = self
                .requests
                .front()
                .ok_or_else(|| PluginIoError::fatal("commit found no request"))?;
            if entry.sequence() != expected_sequence {
                return Err(PluginIoError::fatal("commit sequence mismatch"));
            }
            self.requests.pop_front();
            Ok(())
        }

        fn enqueue_response(
            &mut self,
            entry: GuestIntrospectionEntry,
        ) -> Result<(), PluginIoError> {
            if self.response_full {
                return Err(PluginIoError::Full);
            }
            self.responses.push(entry);
            Ok(())
        }
    }

    fn close_record(channel_id: u64) -> GuestIntrospectionRecord {
        match GuestIntrospectionRecord::new(channel_id, GuestIntrospectionMessage::Close) {
            Ok(record) => record,
            Err(error) => panic!("valid close record failed: {error}"),
        }
    }

    fn entry(sequence: u64, record: &GuestIntrospectionRecord) -> GuestIntrospectionEntry {
        let encoded = match record.encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("valid record failed to encode: {error}"),
        };
        match GuestIntrospectionEntry::new(sequence, &encoded) {
            Ok(entry) => entry,
            Err(error) => panic!("valid entry failed to encode: {error}"),
        }
    }

    fn output_record(channel_id: u64) -> GuestIntrospectionRecord {
        match GuestIntrospectionRecord::new(
            channel_id,
            GuestIntrospectionMessage::Output {
                stream: crucible_protocol::guest_introspection::GuestOutputStream::Stdout,
                bytes: vec![1],
            },
        ) {
            Ok(record) => record,
            Err(error) => panic!("valid output record failed: {error}"),
        }
    }

    #[test]
    fn poll_delivers_at_most_one_host_request() {
        let mut rings = FakeRings::default();
        rings.requests.push_back(entry(1, &close_record(9)));
        let mut next_sequence = 1;
        let reply = match route_exchange(
            &mut rings,
            &mut next_sequence,
            1,
            GuestIntrospectionDoorbellFrame::poll(),
        ) {
            Ok(reply) => reply,
            Err(error) => panic!("poll failed: {error}"),
        };
        assert_eq!(reply.reply.kind(), GuestIntrospectionDoorbellKind::Request);
        assert_eq!(reply.reply.record(), Some(&close_record(9)));
        assert_eq!(reply.delivered_request_sequence, Some(1));
        assert_eq!(rings.requests.len(), 1);
        assert_eq!(commit_delivered_request(&mut rings, 1), Ok(2));
        assert!(rings.requests.is_empty());
        assert!(rings.responses.is_empty());
    }

    #[test]
    fn response_is_published_before_the_next_request_is_delivered() {
        let mut rings = FakeRings::default();
        rings.requests.push_back(entry(1, &close_record(10)));
        let mut next_sequence = 4;
        let reply = match route_exchange(
            &mut rings,
            &mut next_sequence,
            1,
            GuestIntrospectionDoorbellFrame::response(output_record(8)),
        ) {
            Ok(reply) => reply,
            Err(error) => panic!("response exchange failed: {error}"),
        };
        assert_eq!(reply.reply.record(), Some(&close_record(10)));
        assert_eq!(next_sequence, 5);
        assert_eq!(rings.responses.len(), 1);
        assert_eq!(rings.responses[0].sequence(), 4);
        let response = match rings.responses[0].record() {
            Ok(bytes) => GuestIntrospectionRecord::decode(bytes),
            Err(error) => panic!("published response entry was malformed: {error}"),
        };
        assert_eq!(response, Ok(output_record(8)));
    }

    #[test]
    fn guest_cannot_send_plugin_reply_kinds() {
        let mut rings = FakeRings::default();
        let mut next_sequence = 1;
        let error = route_exchange(
            &mut rings,
            &mut next_sequence,
            1,
            GuestIntrospectionDoorbellFrame::idle(),
        );
        assert!(error.is_err());
        assert!(rings.responses.is_empty());
    }

    #[test]
    fn full_response_ring_requests_retry_without_consuming_request() {
        let mut rings = FakeRings {
            response_full: true,
            ..FakeRings::default()
        };
        rings.requests.push_back(entry(1, &close_record(10)));
        let mut next_sequence = 4;
        let reply = route_exchange(
            &mut rings,
            &mut next_sequence,
            1,
            GuestIntrospectionDoorbellFrame::response(output_record(8)),
        )
        .unwrap_or_else(|error| panic!("backpressure failed: {error}"));
        assert_eq!(reply.reply.kind(), GuestIntrospectionDoorbellKind::Retry);
        assert_eq!(next_sequence, 4);
        assert_eq!(rings.requests.len(), 1);
        assert!(rings.responses.is_empty());
    }

    #[test]
    fn route_rejects_sequence_gaps_and_embedded_direction_reversal() {
        let mut rings = FakeRings::default();
        rings.requests.push_back(entry(2, &close_record(10)));
        let mut next_sequence = 1;
        assert!(
            route_exchange(
                &mut rings,
                &mut next_sequence,
                1,
                GuestIntrospectionDoorbellFrame::poll(),
            )
            .is_err()
        );
        assert_eq!(rings.requests.len(), 1);

        let mut rings = FakeRings::default();
        assert!(
            route_exchange(
                &mut rings,
                &mut next_sequence,
                1,
                GuestIntrospectionDoorbellFrame::response(close_record(8)),
            )
            .is_err()
        );
        assert!(rings.responses.is_empty());
    }
}
