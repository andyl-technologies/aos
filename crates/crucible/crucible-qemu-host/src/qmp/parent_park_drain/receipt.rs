//! Parses factual native custody without constructing publisher authority.

use super::{QmpCommandKind, QmpError};
use crucible_qemu_protocol::boundary_action::ActionBinding;
use crucible_qemu_protocol::parent_park_return::ParentParkReturn;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HexIdentity([u8; 32]);

impl Serialize for HexIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut bytes = [0_u8; 64];
        for (index, byte) in self.0.iter().enumerate() {
            bytes[2 * index] = DIGITS[(byte >> 4) as usize];
            bytes[2 * index + 1] = DIGITS[(byte & 15) as usize];
        }
        let text = std::str::from_utf8(&bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'input> Deserialize<'input> for HexIdentity {
    fn deserialize<D: serde::Deserializer<'input>>(decoder: D) -> Result<Self, D::Error> {
        struct IdentityVisitor;
        impl serde::de::Visitor<'_> for IdentityVisitor {
            type Value = HexIdentity;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("64 hexadecimal identity digits")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<HexIdentity, E> {
                if text.len() != 64 {
                    return Err(E::custom(
                        "identity length differs from 64 hexadecimal digits",
                    ));
                }
                let mut bytes = [0; 32];
                for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                    let digit = |byte: u8| match byte {
                        b'0'..=b'9' => Some(byte - b'0'),
                        b'a'..=b'f' => Some(byte - b'a' + 10),
                        b'A'..=b'F' => Some(byte - b'A' + 10),
                        _ => None,
                    };
                    bytes[index] =
                        (digit(pair[0]).ok_or_else(|| E::custom("nonhexadecimal identity"))? << 4)
                            | digit(pair[1]).ok_or_else(|| E::custom("nonhexadecimal identity"))?;
                }
                Ok(HexIdentity(bytes))
            }
        }
        decoder.deserialize_str(IdentityVisitor)
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct WireBinding {
    source_capability: HexIdentity,
    source_reservation: HexIdentity,
    account_incarnation: u64,
    process_incarnation: u64,
    request_correlation: u64,
    command_frontier: u64,
    loan_sequence: u64,
}

impl WireBinding {
    pub(super) fn new(binding: ActionBinding) -> Self {
        Self {
            source_capability: HexIdentity(binding.cap),
            source_reservation: HexIdentity(binding.reservation),
            account_incarnation: binding.account_generation,
            process_incarnation: binding.process_generation,
            request_correlation: binding.park_request.unwrap_or(0),
            command_frontier: binding.frontier,
            loan_sequence: binding.loan_sequence,
        }
    }

    fn matches(&self, binding: ActionBinding) -> bool {
        self == &Self::new(binding)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct WireClosure {
    binding: WireBinding,
    completed_requests: u64,
    stopped_generation: u64,
    native_generation: u64,
    plugin_owner_generation: u64,
    connection_epoch: u64,
    status: i32,
    post_status: i32,
    operation_status: i32,
    physical_status: i32,
    final_original0_status: i32,
    final_original1_status: i32,
    writer_status: i32,
    writer_first_status: i32,
    writer_post_status: i32,
    publisher_cohort_return_proven: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct WireResult {
    status: i32,
    post_status: i32,
    return_status: i32,
    received: bool,
    entered: bool,
    pending: bool,
    native_returned: bool,
    terminal_published: bool,
    mapped_metadata_bytes: u64,
    completed_requests: u64,
    lifetime_first_status: i32,
    lifetime_post_status: i32,
    closed_request: Option<WireClosure>,
}

/// Records a matching local closure observed on the request's original QMP client.
///
/// Private construction prevents a deserialized JSON object from being used as
/// this evidence. Closure returns native request resources; Host publisher
/// memberships and the standing Source require their separate real settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpParentParkClosedRequest {
    binding: ActionBinding,
    completed_requests: u64,
    stopped_generation: u64,
    native_generation: u64,
    plugin_owner_generation: u64,
    connection_epoch: u64,
    status: i32,
    post_status: i32,
    operation_status: i32,
    physical_status: i32,
    final_original_statuses: [i32; 2],
    writer_status: i32,
    writer_first_status: i32,
    writer_post_status: i32,
}

impl QmpParentParkClosedRequest {
    /// Returns the native monotonic local-closure ordinal.
    #[must_use]
    pub const fn completed_requests(&self) -> u64 {
        self.completed_requests
    }

    /// Corroborates the independently read terminal mapping for this exact request.
    ///
    /// # Errors
    /// Refuses another binding, generation or disposition, or malformed terminal
    /// bytes. Neither matching evidence nor negative statuses complete an Original.
    pub fn corroborate_return(
        &self,
        binding: ActionBinding,
        returned: &ParentParkReturn,
    ) -> Result<(), QmpError> {
        returned.encode().map_err(|_| QmpError::InvalidBound {
            operation: "parent Park mapped return encoding",
        })?;
        if binding != self.binding
            || returned.binding != self.binding
            || returned.stopped_generation != self.stopped_generation
            || returned.native_generation != self.native_generation
            || returned.first != self.status
            || returned.post != self.post_status
            || returned.original_statuses != self.final_original_statuses
            || returned.operation_status != self.operation_status
            || returned.return_status != self.physical_status
        {
            return Err(QmpError::InvalidBound {
                operation: "parent Park closure differs from mapped return",
            });
        }
        Ok(())
    }
}

/// Reports native custody independently of the producing operations' success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpParentParkResult {
    /// Retained first operation refusal, or zero.
    pub status: i32,
    /// Independent Source post refusal, or zero.
    pub post_status: i32,
    /// Current settlement result, including a pending result.
    pub return_status: i32,
    /// Whether Source retained the original initiating request.
    pub received: bool,
    /// Whether native exclusion and plugin acquisition actually entered.
    pub entered: bool,
    /// Whether the paused-main-loop continuation is still queued.
    pub pending: bool,
    /// Whether the native per-request resources physically returned.
    pub native_returned: bool,
    /// Whether the terminal writer published and locally returned.
    pub terminal_published: bool,
    /// Page-rounded requested temporary mapping extent, retained after return.
    pub mapped_metadata_bytes: u64,
    /// Monotonic native local-closure count.
    pub completed_requests: u64,
    /// First Source refusal across this process's closed requests.
    pub lifetime_first_status: i32,
    /// First independent Source post refusal across closures.
    pub lifetime_post_status: i32,
    /// Same-connection checked local closure, present only after actual return.
    pub closed_request: Option<QmpParentParkClosedRequest>,
    /// Whether the actual Host publisher returned all retained memberships.
    ///
    /// QMP decoding leaves this false. Only the installed Node's separate
    /// mapped-return settlement sets it after consuming the physical selector.
    pub host_memberships_returned: bool,
    /// Independent typed refusal from actual Host membership settlement.
    pub host_return_after: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    /// Independent retained Cleanup refusal observed after decoding physical state.
    pub cleanup_after: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
}

impl QmpParentParkResult {
    /// Reports semantic failure independently of factual pending or closed custody.
    ///
    /// The documented pending return result is not a failure or a held grant.
    #[must_use]
    pub fn has_operation_failure(&self) -> bool {
        let pending_return = self.pending
            && self.closed_request.is_none()
            && self.return_status == -libc::EINPROGRESS;
        self.status < 0
            || self.post_status < 0
            || (self.return_status < 0 && !pending_return)
            || self.lifetime_first_status < 0
            || self.lifetime_post_status < 0
            || self.cleanup_after.is_some()
            || self.host_return_after.is_some()
            || self.closed_request.is_some_and(|closed| {
                [
                    closed.status,
                    closed.post_status,
                    closed.operation_status,
                    closed.physical_status,
                    closed.final_original_statuses[0],
                    closed.final_original_statuses[1],
                    closed.writer_status,
                    closed.writer_first_status,
                    closed.writer_post_status,
                ]
                .iter()
                .any(|status| *status < 0)
            })
    }
}

/// Retains the first selector before transport, including uncertain begin writes.
pub(in crate::qmp) struct ParentParkSession {
    pub(super) state: RetainedRequest,
    pub(super) frame: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct RetainedRequest {
    pub(super) binding: ActionBinding,
    pub(super) stopped: u64,
    pub(super) previous_completed: u64,
    pub(super) closed: Option<QmpParentParkClosedRequest>,
    pub(super) begin_attempted: bool,
    pub(super) connection_epoch: Option<u64>,
}

impl RetainedRequest {
    pub(super) fn parse(
        &mut self,
        wire_result: WireResult,
        kind: QmpCommandKind,
    ) -> Result<QmpParentParkResult, QmpError> {
        let invalid = || QmpError::UnexpectedResponse {
            command: kind,
            response: String::from("parent Park result differs from its retained request"),
        };
        if [
            wire_result.status,
            wire_result.post_status,
            wire_result.return_status,
            wire_result.lifetime_first_status,
            wire_result.lifetime_post_status,
        ]
        .iter()
        .any(|s| *s > 0)
            || wire_result.completed_requests < self.previous_completed
            || (wire_result.terminal_published && !wire_result.native_returned)
        {
            return Err(invalid());
        }
        let closed = if let Some(closure) = wire_result.closed_request {
            let expected_completed = self.previous_completed.checked_add(1).ok_or_else(invalid)?;
            let identity_matches = kind == QmpCommandKind::ParentParkReturn
                && closure.binding.matches(self.binding)
                && closure.stopped_generation == self.stopped
                && closure.native_generation != u64::MAX
                && closure.plugin_owner_generation != u64::MAX
                && closure.connection_epoch != 0
                && self
                    .connection_epoch
                    .is_none_or(|epoch| epoch == closure.connection_epoch)
                && closure.completed_requests == expected_completed
                && wire_result.completed_requests == expected_completed;
            if !identity_matches {
                return Err(invalid());
            }

            // The requested mapping extent can remain in the factual report
            // after its debit returned; it is not a remaining-live counter.
            if !wire_result.received
                || wire_result.pending
                || !wire_result.native_returned
                || !wire_result.terminal_published
                || closure.publisher_cohort_return_proven
            {
                return Err(invalid());
            }
            let statuses = [
                closure.status,
                closure.post_status,
                closure.operation_status,
                closure.physical_status,
                closure.final_original0_status,
                closure.final_original1_status,
                closure.writer_status,
                closure.writer_first_status,
                closure.writer_post_status,
            ];
            if statuses.iter().any(|status| *status > 0) {
                return Err(invalid());
            }

            let closed = QmpParentParkClosedRequest {
                binding: self.binding,
                completed_requests: closure.completed_requests,
                stopped_generation: closure.stopped_generation,
                native_generation: closure.native_generation,
                plugin_owner_generation: closure.plugin_owner_generation,
                connection_epoch: closure.connection_epoch,
                status: closure.status,
                post_status: closure.post_status,
                operation_status: closure.operation_status,
                physical_status: closure.physical_status,
                final_original_statuses: [
                    closure.final_original0_status,
                    closure.final_original1_status,
                ],
                writer_status: closure.writer_status,
                writer_first_status: closure.writer_first_status,
                writer_post_status: closure.writer_post_status,
            };
            if self.closed.is_some_and(|saved| saved != closed) {
                return Err(invalid());
            }
            self.connection_epoch = Some(closure.connection_epoch);
            self.closed = Some(closed);
            Some(closed)
        } else {
            if self.closed.is_some() || wire_result.completed_requests != self.previous_completed {
                return Err(invalid());
            }
            None
        };
        Ok(QmpParentParkResult {
            status: wire_result.status,
            post_status: wire_result.post_status,
            return_status: wire_result.return_status,
            received: wire_result.received,
            entered: wire_result.entered,
            pending: wire_result.pending,
            native_returned: wire_result.native_returned,
            terminal_published: wire_result.terminal_published,
            mapped_metadata_bytes: wire_result.mapped_metadata_bytes,
            completed_requests: wire_result.completed_requests,
            lifetime_first_status: wire_result.lifetime_first_status,
            lifetime_post_status: wire_result.lifetime_post_status,
            closed_request: closed,
            cleanup_after: None,
            host_memberships_returned: false,
            host_return_after: None,
        })
    }
}

impl std::fmt::Debug for ParentParkSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParentParkSession")
            .field("request", &self.state)
            .field("buffer_bytes", &self.frame.len())
            .finish()
    }
}
