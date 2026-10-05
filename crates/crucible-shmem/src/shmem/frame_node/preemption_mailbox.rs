//! Scheduler-to-plugin preemption mailbox operations and typed wire values.

use super::*;

impl NodeSlot {
    /// Publishes one scheduler-commanded preemption before its RUN ceiling.
    ///
    /// The command fields are written before the sequence is release-published.
    /// The plugin acquire-loads that sequence before reading the fields, applies
    /// the command through QEMU, and acknowledges the same sequence only after
    /// QEMU accepts it. At most one command may be outstanding per node.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionMailboxError`] when a prior command is unconsumed or
    /// the command's authorization window is invalid.
    pub fn publish_preemption_command(
        &self,
        command: SchedulerPreemptionCommand,
    ) -> Result<u32, PreemptionMailboxError> {
        command.validate()?;
        let published = self.preemption_published_sequence.load(Ordering::Acquire);
        let consumed = self.preemption_consumed_sequence.load(Ordering::Acquire);
        if published != consumed {
            return Err(PreemptionMailboxError::CommandOutstanding {
                published_sequence: published,
                consumed_sequence: consumed,
            });
        }

        let (kind, arg0, arg1) = command.kind.to_wire();
        self.preemption_at_tick
            .store(command.at_tick, Ordering::Relaxed);
        self.preemption_deadline_tick
            .store(command.deadline_tick, Ordering::Relaxed);
        self.preemption_ceiling_tick
            .store(command.ceiling_tick, Ordering::Relaxed);
        self.preemption_arg0.store(arg0, Ordering::Relaxed);
        self.preemption_arg1.store(arg1, Ordering::Relaxed);
        self.preemption_kind.store(kind, Ordering::Relaxed);
        let sequence = published.wrapping_add(1);
        self.preemption_published_sequence
            .store(sequence, Ordering::Release);
        Ok(sequence)
    }

    /// Reports whether the preemption sequences currently differ.
    ///
    /// This advisory observation reads only the publication and consumption
    /// sequences. It neither validates command fields nor acquires consumer
    /// ownership. A consumer must acquire its admission guard and reread
    /// [`Self::pending_preemption_command`] before applying a command: another
    /// consumer can acknowledge this observation or a producer can publish a
    /// replacement before admission.
    #[must_use]
    pub fn has_pending_preemption_command(&self) -> bool {
        let published = self.preemption_published_sequence.load(Ordering::Acquire);
        let consumed = self.preemption_consumed_sequence.load(Ordering::Acquire);
        published != consumed
    }

    /// Acquire-loads the next scheduler preemption, if one is outstanding.
    ///
    /// The caller must exclude other consumers while decoding, applying, and
    /// acknowledging the command. Until that acknowledgement, the producer may
    /// not replace its payload. [`Self::has_pending_preemption_command`] provides
    /// an advisory sequence observation before consumer ownership is acquired.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionMailboxError`] when shared-memory command material is
    /// malformed or its authorization window is invalid.
    pub fn pending_preemption_command(
        &self,
    ) -> Result<Option<PublishedPreemptionCommand>, PreemptionMailboxError> {
        let published = self.preemption_published_sequence.load(Ordering::Acquire);
        let consumed = self.preemption_consumed_sequence.load(Ordering::Acquire);
        if published == consumed {
            return Ok(None);
        }
        let kind = SchedulerPreemptionKind::from_wire(
            self.preemption_kind.load(Ordering::Relaxed),
            self.preemption_arg0.load(Ordering::Relaxed),
            self.preemption_arg1.load(Ordering::Relaxed),
        )?;
        let command = SchedulerPreemptionCommand {
            at_tick: self.preemption_at_tick.load(Ordering::Relaxed),
            deadline_tick: self.preemption_deadline_tick.load(Ordering::Relaxed),
            ceiling_tick: self.preemption_ceiling_tick.load(Ordering::Relaxed),
            kind,
        };
        command.validate()?;
        Ok(Some(PublishedPreemptionCommand {
            sequence: published,
            command,
        }))
    }

    /// Acknowledges a preemption only after QEMU accepts its injection.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionMailboxError`] when `sequence` is not the currently
    /// published, outstanding command.
    pub fn acknowledge_preemption_command(
        &self,
        sequence: u32,
    ) -> Result<(), PreemptionMailboxError> {
        let published = self.preemption_published_sequence.load(Ordering::Acquire);
        let consumed = self.preemption_consumed_sequence.load(Ordering::Acquire);
        if sequence != published || consumed == published {
            return Err(PreemptionMailboxError::AcknowledgeMismatch {
                requested_sequence: sequence,
                published_sequence: published,
                consumed_sequence: consumed,
            });
        }
        self.preemption_consumed_sequence
            .store(sequence, Ordering::Release);
        Ok(())
    }

    /// Returns the plugin-consumed preemption sequence.
    #[must_use]
    pub fn consumed_preemption_sequence(&self) -> u32 {
        self.preemption_consumed_sequence.load(Ordering::Acquire)
    }
}

/// Scheduler-side shape of one commanded preemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerPreemptionCommand {
    /// Exact node logical tick at which QEMU must apply the command.
    pub at_tick: u64,
    /// Inclusive lower bound authorized by the scheduler.
    pub deadline_tick: u64,
    /// Inclusive upper bound authorized by the scheduler.
    pub ceiling_tick: u64,
    /// Command-specific vCPU switch or interrupt data.
    pub kind: SchedulerPreemptionKind,
}

impl SchedulerPreemptionCommand {
    fn validate(self) -> Result<(), PreemptionMailboxError> {
        if self.deadline_tick > self.ceiling_tick {
            return Err(PreemptionMailboxError::InvalidWindow {
                deadline_tick: self.deadline_tick,
                ceiling_tick: self.ceiling_tick,
            });
        }
        if self.at_tick < self.deadline_tick || self.at_tick > self.ceiling_tick {
            return Err(PreemptionMailboxError::CommandOutsideWindow {
                at_tick: self.at_tick,
                deadline_tick: self.deadline_tick,
                ceiling_tick: self.ceiling_tick,
            });
        }
        Ok(())
    }
}

/// Kind-specific payload of a scheduler-commanded preemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerPreemptionKind {
    /// Switches from one vCPU to another.
    VcpuSwitch {
        /// vCPU running before the command.
        from_vcpu: u32,
        /// vCPU selected by the command.
        to_vcpu: u32,
    },
    /// Delivers one interrupt to a target vCPU.
    InterruptAt {
        /// Target vCPU.
        target_vcpu: u32,
        /// Interrupt vector.
        irq: u32,
    },
}

impl SchedulerPreemptionKind {
    const fn to_wire(self) -> (u8, u32, u32) {
        match self {
            Self::VcpuSwitch { from_vcpu, to_vcpu } => {
                (PREEMPTION_KIND_VCPU_SWITCH, from_vcpu, to_vcpu)
            }
            Self::InterruptAt { target_vcpu, irq } => {
                (PREEMPTION_KIND_INTERRUPT_AT, target_vcpu, irq)
            }
        }
    }

    fn from_wire(kind: u8, arg0: u32, arg1: u32) -> Result<Self, PreemptionMailboxError> {
        match kind {
            PREEMPTION_KIND_VCPU_SWITCH => Ok(Self::VcpuSwitch {
                from_vcpu: arg0,
                to_vcpu: arg1,
            }),
            PREEMPTION_KIND_INTERRUPT_AT => Ok(Self::InterruptAt {
                target_vcpu: arg0,
                irq: arg1,
            }),
            _ => Err(PreemptionMailboxError::UnknownKind { kind }),
        }
    }
}

/// One acquire-loaded preemption paired with its mailbox sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedPreemptionCommand {
    /// Sequence that the plugin must acknowledge after successful application.
    pub sequence: u32,
    /// Scheduler-authored command material.
    pub command: SchedulerPreemptionCommand,
}

/// Failure while publishing, reading, or acknowledging the preemption mailbox.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PreemptionMailboxError {
    /// A host attempted to overwrite an unconsumed command.
    #[error(
        "preemption command {published_sequence} remains outstanding at consumed sequence {consumed_sequence}"
    )]
    CommandOutstanding {
        /// Latest host-published sequence.
        published_sequence: u32,
        /// Latest plugin-consumed sequence.
        consumed_sequence: u32,
    },
    /// The authorization window is reversed.
    #[error("preemption deadline {deadline_tick} is past ceiling {ceiling_tick}")]
    InvalidWindow {
        /// Inclusive lower bound.
        deadline_tick: u64,
        /// Inclusive upper bound.
        ceiling_tick: u64,
    },
    /// The command tick is outside its inclusive authorization window.
    #[error("preemption at {at_tick} is outside [{deadline_tick}, {ceiling_tick}]")]
    CommandOutsideWindow {
        /// Commanded tick.
        at_tick: u64,
        /// Inclusive lower bound.
        deadline_tick: u64,
        /// Inclusive upper bound.
        ceiling_tick: u64,
    },
    /// Shared memory carried an unknown command-kind discriminator.
    #[error("preemption mailbox contains unknown kind {kind}")]
    UnknownKind {
        /// Unknown raw discriminator.
        kind: u8,
    },
    /// A plugin attempted to acknowledge the wrong or already consumed command.
    #[error(
        "preemption acknowledge {requested_sequence} does not match published {published_sequence} and consumed {consumed_sequence}"
    )]
    AcknowledgeMismatch {
        /// Sequence supplied by the plugin.
        requested_sequence: u32,
        /// Latest host-published sequence.
        published_sequence: u32,
        /// Latest plugin-consumed sequence.
        consumed_sequence: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> SchedulerPreemptionCommand {
        SchedulerPreemptionCommand {
            at_tick: 75,
            deadline_tick: 50,
            ceiling_tick: 100,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 0,
                irq: 41,
            },
        }
    }

    #[test]
    fn pending_hint_does_not_decode_or_validate_command_fields() {
        let slot = NodeSlot::new(KIND_VM);
        let sequence = slot.publish_preemption_command(command()).unwrap();

        // Unowned observers must not decode fields that another consumer can
        // release for replacement. Admission still requires the validated read.
        slot.preemption_kind.store(u8::MAX, Ordering::Relaxed);
        assert!(slot.has_pending_preemption_command());
        assert_eq!(
            slot.pending_preemption_command(),
            Err(PreemptionMailboxError::UnknownKind { kind: u8::MAX })
        );

        slot.preemption_kind
            .store(command().kind.to_wire().0, Ordering::Relaxed);
        slot.preemption_deadline_tick.store(101, Ordering::Relaxed);
        assert!(slot.has_pending_preemption_command());
        assert_eq!(
            slot.pending_preemption_command(),
            Err(PreemptionMailboxError::InvalidWindow {
                deadline_tick: 101,
                ceiling_tick: 100,
            })
        );

        slot.acknowledge_preemption_command(sequence).unwrap();
        assert!(!slot.has_pending_preemption_command());
        assert_eq!(slot.pending_preemption_command(), Ok(None));
    }

    #[test]
    fn pending_hint_handles_publication_sequence_wrap() {
        let slot = NodeSlot::new(KIND_VM);
        slot.preemption_published_sequence
            .store(u32::MAX, Ordering::Release);
        slot.preemption_consumed_sequence
            .store(u32::MAX, Ordering::Release);
        assert!(!slot.has_pending_preemption_command());

        let sequence = slot.publish_preemption_command(command()).unwrap();

        assert_eq!(sequence, 0);
        assert!(slot.has_pending_preemption_command());
        assert_eq!(
            slot.pending_preemption_command(),
            Ok(Some(PublishedPreemptionCommand {
                sequence,
                command: command(),
            }))
        );

        slot.acknowledge_preemption_command(sequence).unwrap();
        assert!(!slot.has_pending_preemption_command());
    }
}
