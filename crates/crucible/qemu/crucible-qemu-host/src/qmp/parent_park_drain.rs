//! Retains one paired Park request on its original QMP connection.
//!
//! Begin schedules actual native work; it grants no held state. Return reports
//! physical closure independently of semantic success. The first selector and
//! stopped coordinate remain retained across every uncertain transport result.

use super::{QmpClient, QmpCommandKind, QmpDescriptorName, QmpError, QmpTimeoutStream};
use crucible_host_resources::host_supervision::{HostOperationClass, HostOperationGuard};
use crucible_qemu_protocol::boundary_action::ActionBinding;
use serde::Serialize;

mod receipt;
mod transport;
pub(super) use receipt::ParentParkSession;
use receipt::RetainedRequest;
use receipt::WireBinding;
pub use receipt::{QmpParentParkClosedRequest, QmpParentParkResult};
pub(crate) use transport::decoder_extent;

pub(crate) enum ParentParkRequest<'a> {
    Begin {
        binding: ActionBinding,
        stopped: u64,
        basis: &'a QmpDescriptorName,
        cancellation: &'a QmpDescriptorName,
    },
    Return {
        binding: ActionBinding,
    },
}

impl ParentParkRequest<'_> {
    pub(super) const fn kind(&self) -> QmpCommandKind {
        match self {
            Self::Begin { .. } => QmpCommandKind::ParentParkBegin,
            Self::Return { .. } => QmpCommandKind::ParentParkReturn,
        }
    }

    fn binding(&self) -> ActionBinding {
        match self {
            Self::Begin { binding, .. } | Self::Return { binding } => *binding,
        }
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, QmpError> {
        #[derive(Serialize)]
        struct Envelope<T> {
            execute: &'static str,
            arguments: T,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "kebab-case")]
        struct Begin<'a> {
            binding: WireBinding,
            stopped_generation: u64,
            basis_fdname: &'a str,
            cancellation_fdname: &'a str,
        }
        #[derive(Serialize)]
        struct Return {
            binding: WireBinding,
        }
        let mut writer = std::io::Cursor::new(output);
        let result = match self {
            Self::Begin {
                binding,
                stopped,
                basis,
                cancellation,
            } => serde_json::to_writer(
                &mut writer,
                &Envelope {
                    execute: self.kind().wire_name(),
                    arguments: Begin {
                        binding: WireBinding::new(*binding),
                        stopped_generation: *stopped,
                        basis_fdname: basis.as_str(),
                        cancellation_fdname: cancellation.as_str(),
                    },
                },
            ),
            Self::Return { binding } => serde_json::to_writer(
                &mut writer,
                &Envelope {
                    execute: self.kind().wire_name(),
                    arguments: Return {
                        binding: WireBinding::new(*binding),
                    },
                },
            ),
        };
        result.map_err(|_| QmpError::InvalidBound {
            operation: "parent Park fixed request encoding",
        })?;
        usize::try_from(writer.position()).map_err(|_| QmpError::InvalidBound {
            operation: "parent Park encoded request length",
        })
    }

    fn validate(&self) -> Result<(), QmpError> {
        let binding = self.binding();
        if binding.cap == [0; 32]
            || binding.reservation == [0; 32]
            || binding.account_generation == 0
            || binding.process_generation == 0
            || binding
                .park_request
                .is_none_or(|correlation| correlation == 0 || correlation == u64::MAX)
            || binding.token != 0
            || binding.capture.is_some()
            || binding.loan_sequence == 0
            || binding.loan_sequence == u64::MAX
            || binding.loan_sequence & 1 != 0
        {
            return Err(QmpError::InvalidBound {
                operation: "parent Park binding",
            });
        }
        if let Self::Begin {
            stopped,
            basis,
            cancellation,
            ..
        } = self
            && (*stopped == 0 || *stopped == u64::MAX || basis.as_str() == cancellation.as_str())
        {
            return Err(QmpError::InvalidBound {
                operation: "parent Park stopped coordinate/imports",
            });
        }
        Ok(())
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(crate) fn prepare_parent_park_begin(
        &mut self,
        binding: ActionBinding,
        stopped: u64,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<(), QmpError> {
        self.ensure_usable()?;
        ParentParkRequest::Return { binding }.validate()?;
        if stopped == 0 || stopped == u64::MAX {
            return Err(QmpError::InvalidBound {
                operation: "parent Park stopped coordinate",
            });
        }
        self.pair_deadline(actor, family)
            .remaining("retain parent Park request before descriptor import")?;
        let (previous_completed, connection_epoch) = match &self.parent_park_session {
            None => (0, None),
            Some(previous) => {
                let closed = previous
                    .state
                    .closed
                    .as_ref()
                    .ok_or(QmpError::InvalidBound {
                        operation: "prior parent Park request remains owned",
                    })?;
                if binding.loan_sequence <= previous.state.binding.loan_sequence
                    || binding.park_request <= previous.state.binding.park_request
                {
                    return Err(QmpError::InvalidBound {
                        operation: "parent Park replay/nonadvancing selector",
                    });
                }
                (closed.completed_requests(), previous.state.connection_epoch)
            }
        };
        // This same client owns the selector before the first possible byte.
        // A failed write cannot be retried as a fresh begin.
        let frame = if let Some(previous) = self.parent_park_session.as_mut() {
            std::mem::take(&mut previous.frame)
        } else {
            let mut frame = Vec::new();
            frame
                .try_reserve_exact(super::QMP_MAX_LINE_BYTES)
                .map_err(|_| QmpError::InvalidBound {
                    operation: "parent Park paid buffer allocation",
                })?;
            frame.resize(super::QMP_MAX_LINE_BYTES, 0);
            frame
        };
        self.parent_park_session = Some(ParentParkSession {
            frame,
            state: RetainedRequest {
                binding,
                stopped,
                previous_completed,
                closed: None,
                begin_attempted: false,
                connection_epoch,
            },
        });
        Ok(())
    }

    pub(crate) fn parent_park_begin_under_originals(
        &mut self,
        request: &ParentParkRequest<'_>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkResult, QmpError> {
        request.validate()?;
        let ParentParkRequest::Begin {
            binding, stopped, ..
        } = request
        else {
            return Err(QmpError::InvalidBound {
                operation: "parent Park begin request",
            });
        };
        if !self.parent_park_session.as_ref().is_some_and(|saved| {
            saved.state.binding == *binding
                && saved.state.stopped == *stopped
                && !saved.state.begin_attempted
        }) {
            self.prepare_parent_park_begin(*binding, *stopped, actor, family)?;
        }
        // The prepared selector already preceded getfd. Begin itself also has
        // a one-way attempted cut before any byte may enter the stream.
        self.parent_park_session
            .as_mut()
            .ok_or(QmpError::InvalidBound {
                operation: "parent Park prepared selector",
            })?
            .state
            .begin_attempted = true;
        let deadline = self.pair_deadline(actor, family);
        let result = self.exchange_parent_park(request, &deadline)?;
        if let Err(first) = deadline.complete(request.kind().wire_name()) {
            self.poison_parent_park_drain();
            return Err(first);
        }
        Ok(result)
    }

    pub(crate) fn parent_park_return_under_originals(
        &mut self,
        binding: ActionBinding,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkResult, QmpError> {
        let request = ParentParkRequest::Return { binding };
        request.validate()?;
        if !self
            .parent_park_session
            .as_ref()
            .is_some_and(|session| session.state.binding == binding)
        {
            return Err(QmpError::InvalidBound {
                operation: "parent Park return requires same connection selector",
            });
        }
        let deadline = self.pair_deadline(actor, family);
        // The caller preserves both independent posts after retaining the
        // decoded receipt. A late Original refusal cannot erase local closure.
        self.exchange_parent_park(&request, &deadline)
    }

    pub(crate) fn parent_park_return_under_cleanup(
        &mut self,
        binding: ActionBinding,
        cleanup: &HostOperationGuard,
    ) -> Result<QmpParentParkResult, QmpError> {
        let request = ParentParkRequest::Return { binding };
        request.validate()?;
        self.ensure_usable()?;
        cleanup
            .verify_operation_class(HostOperationClass::Cleanup)
            .map_err(|error| QmpError::OperationalSupervision {
                operation: "parent Park retained Cleanup",
                message: error.to_string(),
            })?;
        if !self
            .parent_park_session
            .as_ref()
            .is_some_and(|session| session.state.binding == binding)
        {
            return Err(QmpError::InvalidBound {
                operation: "parent Park return requires same connection selector",
            });
        }
        let deadline = super::QmpOperationDeadline {
            supervision: None,
            timeout: self.io_timeout_policy.command_timeout,
            shared: None,
            checkpoint_original: None,
            checkpoint_loan: None,
            borrowed: Some(cleanup),
            paired: None,
            _lifetime: std::marker::PhantomData,
        };
        let mut result = self.exchange_parent_park(&request, &deadline)?;
        // Physical evidence is stored before observing the independent post.
        result.cleanup_after = cleanup.wait_slice().err();
        Ok(result)
    }
}

// A family guard's ordinary wait does not inspect its entered subscription.
// Both subscriptions and both actual policies therefore gate every I/O slice.
fn checked_wait_slice(
    guard: &HostOperationGuard,
) -> Result<std::time::Duration, crucible_host_resources::host_supervision::HostSupervisionError> {
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
    // A QMP response proves neither a physical borrower return nor a required
    // unit of either lender's work. Keep their real clocks and progress intact;
    // only the separately authenticated physical journal can settle this pair.
    paired_wait_slice(actor, family, operation).map(|_| ())
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
            checkpoint_original: None,
            checkpoint_loan: None,
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
) -> Result<[u8; 176], crucible_host_resources::host_supervision::HostSupervisionError> {
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
mod tests;
