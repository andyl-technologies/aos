//! Typed later-operation park/drain requests on the existing QMP connection.
//!
//! These request fields correlate a retained owner; they do not issue one. The
//! closed daemon provider retains both actual Quiescence operations, the same
//! process event and complete exclusive world before import or acquisition.
//!
//! ```text
//! command: crucible-parent-park-drain
//! schema-version: 1; action: acquire | query | relinquish
//! acquire: request-correlation, stopped-generation, basis-fdname, cancellation-fdname
//! query/relinquish: request-correlation, stopped-generation, generation
//! sealed basis: CRUCPDR1 + BE schema/length + actor CRUCPAU1/80 + family CRUCPAU1/80
//! ```
//!
//! The wrapped body is exactly 176 bytes. Receipt retention describes actual
//! native cleanup custody; it does not assert that disposed plugin gates remain
//! held. The accepting native command and authentic plugin owner are separate
//! source-qualified counterparts.

use serde::Deserialize;
use serde_json::{Value, json};

use super::{QmpClient, QmpCommandKind, QmpDescriptorName, QmpError, QmpTimeoutStream};
use crucible_linux_resource::host_supervision::HostOperationGuard;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ParentParkDrainAction {
    Acquire,
    Query,
    Relinquish,
}

impl ParentParkDrainAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Query => "query",
            Self::Relinquish => "relinquish",
        }
    }
}

/// Reports the native owner's actual retention state after one bounded action.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QmpParentParkDrainState {
    /// The actual native hold remains acquired.
    Held,
    /// A refusal retained native custody for physical containment.
    TerminalRetained,
    /// Native relinquishment physically closed this phase's hold.
    Relinquished,
}

/// Retains native first and independent post statuses without implying a grant.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpParentParkDrainReceipt {
    /// Exact park/drain receipt encoding version.
    pub schema_version: u32,
    action: ParentParkDrainAction,
    /// Correlation retained by the same acquisition across subsequent actions.
    pub request_correlation: u64,
    /// Actual native owner incarnation, independent of the stop coordinate.
    pub generation: u64,
    /// The ordinary stopped coordinate revalidated by the action.
    pub stopped_generation: u64,
    /// Actual native retention state.
    pub state: QmpParentParkDrainState,
    /// First native refusal, or zero on acceptance.
    pub first_status: i32,
    /// Independent native original refusal, or zero.
    pub post_status: i32,
    /// Whether native still retains the phase owner.
    pub retained: bool,
}

pub(crate) enum ParentParkDrainRequest<'a> {
    Acquire {
        correlation: u64,
        stopped: u64,
        basis: &'a QmpDescriptorName,
        cancellation: &'a QmpDescriptorName,
    },
    Query {
        correlation: u64,
        stopped: u64,
        generation: u64,
    },
    Relinquish {
        correlation: u64,
        stopped: u64,
        generation: u64,
    },
}

impl ParentParkDrainRequest<'_> {
    fn identity(&self) -> (ParentParkDrainAction, u64, u64, Option<u64>) {
        match self {
            Self::Acquire {
                correlation,
                stopped,
                ..
            } => (ParentParkDrainAction::Acquire, *correlation, *stopped, None),
            Self::Query {
                correlation,
                stopped,
                generation,
            } => (
                ParentParkDrainAction::Query,
                *correlation,
                *stopped,
                Some(*generation),
            ),
            Self::Relinquish {
                correlation,
                stopped,
                generation,
            } => (
                ParentParkDrainAction::Relinquish,
                *correlation,
                *stopped,
                Some(*generation),
            ),
        }
    }

    pub(super) fn request(&self) -> Value {
        let (action, correlation, stopped, generation) = self.identity();
        let mut arguments = json!({
            "schema-version": 1,
            "action": action.wire_name(),
            "request-correlation": correlation,
            "stopped-generation": stopped,
        });
        if let Some(generation) = generation {
            arguments["generation"] = json!(generation);
        }
        if let Self::Acquire {
            basis,
            cancellation,
            ..
        } = self
        {
            arguments["basis-fdname"] = json!(basis.as_str());
            arguments["cancellation-fdname"] = json!(cancellation.as_str());
        }
        json!({"execute":"crucible-parent-park-drain", "arguments":arguments})
    }

    fn validate(&self) -> Result<(), QmpError> {
        let (_, correlation, stopped, generation) = self.identity();
        if correlation == 0
            || stopped == 0
            || stopped == u64::MAX
            || generation.is_some_and(|value| value == 0 || value == u64::MAX)
        {
            return Err(QmpError::InvalidBound {
                operation: "parent park/drain identity",
            });
        }
        if let Self::Acquire {
            basis,
            cancellation,
            ..
        } = self
            && basis.as_str() == cancellation.as_str()
        {
            return Err(QmpError::InvalidBound {
                operation: "parent park/drain imports must be distinct",
            });
        }
        Ok(())
    }

    fn receipt(&self, value: &Value) -> Result<QmpParentParkDrainReceipt, QmpError> {
        let invalid = || QmpError::UnexpectedResponse {
            command: QmpCommandKind::ParentParkDrain,
            response: value.to_string(),
        };
        let receipt: QmpParentParkDrainReceipt =
            serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        let (action, correlation, stopped, generation) = self.identity();
        if receipt.schema_version != 1
            || receipt.action != action
            || receipt.request_correlation != correlation
            || receipt.stopped_generation != stopped
            || receipt.generation == 0
            || receipt.generation == u64::MAX
            || generation.is_some_and(|expected| receipt.generation != expected)
            || receipt.first_status > 0
            || receipt.post_status > 0
        {
            return Err(invalid());
        }
        let refused = receipt.first_status < 0 || receipt.post_status < 0;
        let consistent = match receipt.state {
            QmpParentParkDrainState::Held => {
                receipt.retained && !refused && action != ParentParkDrainAction::Relinquish
            }
            QmpParentParkDrainState::TerminalRetained => receipt.retained && refused,
            QmpParentParkDrainState::Relinquished => {
                !receipt.retained && !refused && action == ParentParkDrainAction::Relinquish
            }
        };
        if !consistent {
            return Err(invalid());
        }
        Ok(receipt)
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(crate) fn parent_park_drain_under_originals(
        &mut self,
        request: &ParentParkDrainRequest<'_>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkDrainReceipt, QmpError> {
        request.validate()?;
        let response = self.exchange_under_pair(
            super::command::QmpCommand::ParentParkDrain { request },
            actor,
            family,
        )?;
        match request.receipt(&response.value) {
            Ok(receipt) => Ok(receipt),
            Err(first) => {
                // A malformed accepted shape may follow a real acquisition or
                // release. Retain custody and prevent a second command.
                self.poisoned = true;
                self.stream.get_mut().poison_qmp_stream();
                Err(first)
            }
        }
    }
}

// A family guard's ordinary wait does not inspect its entered subscription.
// Both subscriptions and both actual policies therefore gate every I/O slice.
fn checked_wait_slice(
    guard: &HostOperationGuard,
) -> Result<std::time::Duration, crucible_linux_resource::host_supervision::HostSupervisionError> {
    guard.check_original_quiescence_cancellation()?;
    let slice = guard.wait_slice()?;
    guard.check_original_quiescence_cancellation()?;
    Ok(slice)
}

pub(super) fn paired_wait_slice(
    actor: &HostOperationGuard,
    family: &HostOperationGuard,
    operation: &'static str,
) -> Result<std::time::Duration, QmpError> {
    // Observe both real owners even when the first one refuses. The enclosing
    // provider records their independent raw postcuts in its retained owner.
    let actor_slice = checked_wait_slice(actor);
    let family_slice = checked_wait_slice(family);
    actor_slice
        .and_then(|actor| family_slice.map(|family| actor.min(family)))
        .map_err(|error| QmpError::OperationalSupervision {
            operation,
            message: error.to_string(),
        })
}

pub(super) fn complete_pair(
    actor: &HostOperationGuard,
    family: &HostOperationGuard,
    operation: &'static str,
) -> Result<(), QmpError> {
    let actor_progress = actor.progress(1);
    let family_progress = family.progress(1);
    let post = paired_wait_slice(actor, family, operation);
    actor_progress
        .and(family_progress)
        .map_err(|error| QmpError::OperationalSupervision {
            operation,
            message: error.to_string(),
        })?;
    post.map(|_| ())
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    fn pair_deadline<'a>(
        &self,
        actor: &'a HostOperationGuard,
        family: &'a HostOperationGuard,
    ) -> super::QmpOperationDeadline<'a> {
        // No ambient start, replacement guard or fresh wall-clock allowance.
        super::QmpOperationDeadline {
            supervision: None,
            timeout: self.io_timeout_policy.command_timeout,
            shared: None,
            borrowed: Some(actor),
            paired: Some(family),
            _lifetime: std::marker::PhantomData,
        }
    }

    fn poison_parent_park_drain(&mut self) {
        self.poisoned = true;
        self.stream.get_mut().poison_qmp_stream();
    }

    fn exchange_under_pair(
        &mut self,
        command: super::command::QmpCommand<'_>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<super::QmpCommandReturn, QmpError> {
        self.ensure_usable()?;
        let kind = command.kind();
        let deadline = self.pair_deadline(actor, family);
        deadline.remaining(kind.wire_name())?;
        if let Err(first) = self.write_json_line(kind.wire_name(), command.request(), &deadline) {
            self.poison_parent_park_drain();
            return Err(first);
        }
        let response = match self.read_command_response(kind, &deadline) {
            Ok(response) => response,
            Err(first) => {
                // Only an explicit complete command rejection proves no
                // accepted phase owner remains behind an uncertain cursor.
                if !matches!(first, QmpError::Command { .. }) {
                    self.poison_parent_park_drain();
                }
                return Err(first);
            }
        };
        if let Err(first) = deadline.complete(kind.wire_name()) {
            self.poison_parent_park_drain();
            return Err(first);
        }
        Ok(response)
    }

    pub(crate) fn parent_park_stopped_generation(
        &mut self,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<u64, QmpError> {
        let response = self.exchange_under_pair(
            super::command::QmpCommand::QueryPausedCpu {
                vcpu: 0,
                generation: None,
            },
            actor,
            family,
        )?;
        let observation = super::paused_cpu::parse_paused_cpu(&response.value, 0, None)?;
        Ok(observation.generation)
    }

    pub(crate) fn install_parent_park_descriptor_under_originals(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<(), QmpError> {
        self.ensure_usable()?;
        let deadline = self.pair_deadline(actor, family);
        let command = super::command::QmpCommand::GetFd { name };
        let kind = command.kind();
        deadline.remaining(kind.wire_name())?;
        let result = self
            .write_json_line_with_descriptor(
                kind.wire_name(),
                command.request(),
                descriptor,
                &deadline,
            )
            .and_then(|()| self.read_command_response(kind, &deadline))
            .and_then(|_| deadline.complete(kind.wire_name()));
        if result.is_err() {
            // Descriptor import refusal also leaves monitor ownership
            // uncertain; the retained provider disposes or contains it.
            self.poison_parent_park_drain();
        }
        result
    }
}

/// Wraps the two real entered bases without replacing either identity or end.
///
/// The caller keeps both owning operations and their same process event alive.
/// Native admission pins this complete pair once; subsequent queries carry no
/// replacement basis. Encoding does not issue a native or family owner.
pub(crate) fn encode_parent_park_drain_basis(
    actor: &HostOperationGuard,
    family: &HostOperationGuard,
) -> Result<[u8; 176], crucible_linux_resource::host_supervision::HostSupervisionError> {
    let actor_basis = actor.serialize_original_quiescence_basis()?;
    let family_basis = family.serialize_original_quiescence_basis()?;

    let mut pair = [0_u8; 176];
    pair[..8].copy_from_slice(b"CRUCPDR1");
    pair[8..12].copy_from_slice(&1_u32.to_be_bytes());
    pair[12..16].copy_from_slice(&176_u32.to_be_bytes());
    pair[16..96].copy_from_slice(&actor_basis);
    pair[96..176].copy_from_slice(&family_basis);

    // Publication follows both independent raw cuts, including subscription
    // revocation racing the second serializer. Partial bytes stay local.
    let actor_after = checked_wait_slice(actor);
    let family_after = checked_wait_slice(family);
    actor_after.and(family_after)?;
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    use crucible_linux_resource::host_services::HostServiceAllocator;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    use super::*;

    // These real guard/subscriber fixtures qualify the host protocol cuts.
    // Scripted receipts do not supply a native parked owner or deployed phase.
    struct Pair {
        actor: HostOperationGuard,
        family: HostOperationGuard,
        actor_event: OwnedFd,
        family_event: OwnedFd,
        _actor_owner: HostOperationSupervisor,
        _family_owner: HostOperationSupervisor,
        _account: HostServiceAllocator,
    }

    impl Pair {
        fn new() -> Self {
            let actor_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
                .expect("actor fixture supervisor");
            let family_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
                .expect("family fixture supervisor");
            let actor = actor_owner
                .begin(HostOperationClass::Quiescence)
                .expect("entered actor fixture");
            let family = family_owner
                .begin(HostOperationClass::Quiescence)
                .expect("entered family fixture");
            let account =
                HostServiceAllocator::new(1, 2, 8192).expect("subscriber fixture account");
            let subscribe = |guard: &HostOperationGuard| {
                let event = rustix::event::eventfd(
                    0,
                    rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
                )
                .expect("actual nonblocking event");
                let credit = account
                    .reserve_resources(
                        0,
                        1,
                        HostOperationGuard::original_quiescence_cancellation_bytes(),
                    )
                    .expect("subscriber precharge");
                let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3).expect("same event alias");
                guard
                    .retain_original_quiescence_cancellation(alias, credit)
                    .expect("retain entered subscriber");
                event
            };
            let actor_event = subscribe(&actor);
            let family_event = subscribe(&family);
            Self {
                actor,
                family,
                actor_event,
                family_event,
                _actor_owner: actor_owner,
                _family_owner: family_owner,
                _account: account,
            }
        }
    }

    struct Stream<'event> {
        input: Cursor<Vec<u8>>,
        written: Vec<u8>,
        cancel_on_park_write: Option<&'event OwnedFd>,
    }

    impl<'event> Stream<'event> {
        fn new(receipt: Value, cancellation: Option<&'event OwnedFd>) -> Self {
            let response = json!({"return": receipt});
            Self {
                input: Cursor::new(
                    format!("{{\"QMP\":{{\"version\":{{}},\"capabilities\":[]}}}}\n{{\"return\":{{}}}}\n{response}\n")
                        .into_bytes(),
                ),
                written: Vec::new(),
                cancel_on_park_write: cancellation,
            }
        }
    }

    impl Read for Stream<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Stream<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(bytes);
            if self
                .written
                .windows(26)
                .any(|bytes| bytes == b"crucible-parent-park-drain")
                && let Some(event) = self.cancel_on_park_write.take()
            {
                rustix::io::write(event, &1_u64.to_ne_bytes())?;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for Stream<'_> {
        fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn held_receipt() -> Value {
        json!({
            "schema-version":1, "action":"query", "request-correlation":9,
            "generation":7, "stopped-generation":11, "state":"held",
            "first-status":0, "post-status":0, "retained":true,
        })
    }

    fn query() -> ParentParkDrainRequest<'static> {
        ParentParkDrainRequest::Query {
            correlation: 9,
            stopped: 11,
            generation: 7,
        }
    }

    #[test]
    fn same_process_event_alias_revokes_both_real_subscribers_without_consumption() {
        let actor_owner =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let family_owner =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let actor = actor_owner.begin(HostOperationClass::Quiescence).unwrap();
        let family = family_owner.begin(HostOperationClass::Quiescence).unwrap();
        let event = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .unwrap();
        let account = HostServiceAllocator::new(1, 2, 8192).unwrap();
        for guard in [&actor, &family] {
            let credit = account
                .reserve_resources(
                    0,
                    1,
                    HostOperationGuard::original_quiescence_cancellation_bytes(),
                )
                .unwrap();
            let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3).unwrap();
            guard
                .retain_original_quiescence_cancellation(alias, credit)
                .unwrap();
        }
        let mut client = QmpClient::connect(Stream::new(held_receipt(), None)).unwrap();
        let before = client.stream.get_ref().written.len();

        rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
        let outcome = client.parent_park_drain_under_originals(&query(), &actor, &family);

        assert!(outcome.is_err());
        assert!(actor.check_original_quiescence_cancellation().is_err());
        assert!(family.check_original_quiescence_cancellation().is_err());
        assert_eq!(client.stream.get_ref().written.len(), before);
        let mut bytes = [0; 8];
        assert_eq!(rustix::io::read(&event, &mut bytes).unwrap(), 8);
        assert_eq!(u64::from_ne_bytes(bytes), 1);
        assert!(
            rustix::fs::fcntl_getfl(&event)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn pair_wrapper_keeps_each_entered_identity_literal() {
        let pair = Pair::new();
        let actor = pair.actor.serialize_original_quiescence_basis().unwrap();
        let family = pair.family.serialize_original_quiescence_basis().unwrap();

        let encoded = encode_parent_park_drain_basis(&pair.actor, &pair.family).unwrap();

        assert_eq!(&encoded[..8], b"CRUCPDR1");
        assert_eq!(&encoded[8..16], &[0, 0, 0, 1, 0, 0, 0, 176]);
        assert_eq!(&encoded[16..96], &actor);
        assert_eq!(&encoded[96..176], &family);
        assert_ne!(&encoded[32..64], &encoded[112..144]);
    }

    #[test]
    fn either_original_revocation_refuses_before_another_write() {
        for revoke_actor in [false, true] {
            let pair = Pair::new();
            let event = if revoke_actor {
                &pair.actor_event
            } else {
                &pair.family_event
            };
            let mut client = QmpClient::connect(Stream::new(held_receipt(), None)).unwrap();
            let before = client.stream.get_ref().written.len();
            rustix::io::write(event, &1_u64.to_ne_bytes()).unwrap();

            let error =
                client.parent_park_drain_under_originals(&query(), &pair.actor, &pair.family);

            assert!(matches!(
                error,
                Err(QmpError::OperationalSupervision { .. })
            ));
            assert_eq!(client.stream.get_ref().written.len(), before);
        }
    }

    #[test]
    fn family_revocation_during_command_keeps_uncertainty_sticky() {
        let pair = Pair::new();
        let mut client =
            QmpClient::connect(Stream::new(held_receipt(), Some(&pair.family_event))).unwrap();

        let first = client.parent_park_drain_under_originals(&query(), &pair.actor, &pair.family);
        let written = client.stream.get_ref().written.len();
        let second = client.parent_park_drain_under_originals(&query(), &pair.actor, &pair.family);

        assert!(matches!(
            first,
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert!(client.poisoned);
        assert!(second.is_err());
        assert_eq!(client.stream.get_ref().written.len(), written);
    }

    #[test]
    fn typed_receipt_acceptance_and_shape_refusal_use_actual_routing() {
        let pair = Pair::new();
        let mut accepted = QmpClient::connect(Stream::new(held_receipt(), None)).unwrap();
        let receipt = accepted
            .parent_park_drain_under_originals(&query(), &pair.actor, &pair.family)
            .unwrap();
        assert_eq!(receipt.state, QmpParentParkDrainState::Held);
        assert_eq!(receipt.generation, 7);
        assert!(!accepted.poisoned);

        let mut malformed = held_receipt();
        malformed["retained"] = json!(false);
        let mut refused = QmpClient::connect(Stream::new(malformed, None)).unwrap();
        let first = refused.parent_park_drain_under_originals(&query(), &pair.actor, &pair.family);
        let written = refused.stream.get_ref().written.len();
        let second = refused.parent_park_drain_under_originals(&query(), &pair.actor, &pair.family);

        assert!(matches!(first, Err(QmpError::UnexpectedResponse { .. })));
        assert!(refused.poisoned);
        assert!(second.is_err());
        assert_eq!(refused.stream.get_ref().written.len(), written);
    }
}
