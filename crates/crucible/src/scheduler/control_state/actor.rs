//! Message-owned scheduler actor state and control requests.

use super::*;

/// A read-only copy of the state owned by the scheduler actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerActorStateSnapshot {
    /// The current frontier configuration.
    pub configuration: Configuration,
    /// Per-node counters in canonical scheduler-node order.
    pub node_counters: Vec<(SchedulerNodeId, NodeCounter)>,
    /// Number of cross-node events still owned by the scheduler.
    pub pending_event_count: usize,
    /// Number of control operations waiting for the next quantum boundary.
    pub pending_control_count: usize,
    /// Decision-RNG cursor positions owned by the scheduler.
    pub decision_rng_cursor: DecisionRngState,
    /// Boundary-applied control operations in scheduler application order.
    pub control_applications: Vec<SchedulerControlApplication>,
    /// Explorer-supplied preemptions applied by completed RESOLVE phases.
    pub preemption_applications: Vec<SchedulerPreemptionApplication>,
    /// Number of quantum boundaries at which the scheduler yielded to control.
    pub boundary_yields: u64,
}

/// A message-only scheduler actor that owns the authoritative scheduler state.
#[derive(Debug)]
pub struct SchedulerActor {
    pub(super) scheduler: SingleScheduler,
    pub(super) inbox: Receiver<SchedulerActorMessage>,
    pub(super) deferred: VecDeque<SchedulerActorMessage>,
}

/// A clonable sender for scheduler actor messages.
#[derive(Clone, Debug)]
pub struct SchedulerActorHandle {
    pub(super) inbox: Sender<SchedulerActorMessage>,
}

/// A typed reply receiver for scheduler actor requests.
#[derive(Debug)]
pub struct SchedulerActorReply<T> {
    pub(super) receiver: Receiver<T>,
}

pub(super) enum SchedulerActorMessage {
    QueueControl(ControlOperation),
    DriveQuantum {
        request: QuantumRequest,
        reply: Sender<Result<QuantumOutcome, SchedulerError>>,
    },
    Snapshot {
        reply: Sender<SchedulerActorStateSnapshot>,
    },
}

impl fmt::Debug for SchedulerActorMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueControl(operation) => formatter
                .debug_tuple("QueueControl")
                .field(operation)
                .finish(),
            Self::DriveQuantum { request, .. } => formatter
                .debug_struct("DriveQuantum")
                .field("request", request)
                .finish_non_exhaustive(),
            Self::Snapshot { .. } => formatter.debug_struct("Snapshot").finish_non_exhaustive(),
        }
    }
}

impl SchedulerActor {
    /// Builds a scheduler actor and the handle used to send it messages.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler cannot be built from
    /// `scenario`.
    pub fn new(
        scenario: SchedulerLivenessScenario,
    ) -> Result<(SchedulerActorHandle, Self), SchedulerError> {
        let (sender, receiver) = mpsc::channel();
        Ok((
            SchedulerActorHandle { inbox: sender },
            Self {
                scheduler: SingleScheduler::new(scenario)?,
                inbox: receiver,
                deferred: VecDeque::new(),
            },
        ))
    }

    /// Processes one queued actor message, if one is available.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError`] when the actor mailbox is closed or when
    /// a caller drops a reply receiver before the actor sends the result.
    pub fn run_once(&mut self) -> Result<bool, SchedulerActorError> {
        if let Some(message) = self.deferred.pop_front() {
            self.apply_message(message)?;
            return Ok(true);
        }

        match self.inbox.try_recv() {
            Ok(message) => {
                self.apply_message(message)?;
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(SchedulerActorError::MailboxClosed),
        }
    }

    fn apply_message(&mut self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        match message {
            SchedulerActorMessage::QueueControl(operation) => {
                self.scheduler.queue_control(operation);
                Ok(())
            }
            SchedulerActorMessage::DriveQuantum { request, reply } => {
                self.drain_boundary_messages_before_quantum()?;
                reply
                    .send(self.scheduler.drive_quantum(request))
                    .map_err(|_| SchedulerActorError::ReplyDropped)
            }
            SchedulerActorMessage::Snapshot { reply } => reply
                .send(self.scheduler.actor_state_snapshot())
                .map_err(|_| SchedulerActorError::ReplyDropped),
        }
    }

    fn drain_boundary_messages_before_quantum(&mut self) -> Result<(), SchedulerActorError> {
        loop {
            match self.inbox.try_recv() {
                Ok(SchedulerActorMessage::QueueControl(operation)) => {
                    self.scheduler.queue_control(operation);
                }
                Ok(message) => {
                    self.deferred.push_back(message);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        Ok(())
    }
}

impl SchedulerActorHandle {
    /// Queues a control operation for the scheduler actor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn queue_control(&self, operation: ControlOperation) -> Result<(), SchedulerActorError> {
        self.send(SchedulerActorMessage::QueueControl(operation))
    }

    /// Requests one scheduler quantum through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn drive_quantum(
        &self,
        request: QuantumRequest,
    ) -> Result<SchedulerActorReply<Result<QuantumOutcome, SchedulerError>>, SchedulerActorError>
    {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::DriveQuantum {
            request,
            reply: sender,
        })?;
        Ok(SchedulerActorReply { receiver })
    }

    /// Requests a read-only scheduler state snapshot through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn snapshot(
        &self,
    ) -> Result<SchedulerActorReply<SchedulerActorStateSnapshot>, SchedulerActorError> {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::Snapshot { reply: sender })?;
        Ok(SchedulerActorReply { receiver })
    }

    fn send(&self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        self.inbox
            .send(message)
            .map_err(|_| SchedulerActorError::MailboxClosed)
    }
}

impl<T> SchedulerActorReply<T> {
    /// Receives a scheduler actor reply.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::ReplyDropped`] when the actor drops before
    /// replying to the request.
    pub fn recv(self) -> Result<T, SchedulerActorError> {
        self.receiver
            .recv()
            .map_err(|_| SchedulerActorError::ReplyDropped)
    }
}

/// An error produced by the scheduler actor mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerActorError {
    /// The actor mailbox is closed.
    MailboxClosed,
    /// A request reply was dropped before delivery.
    ReplyDropped,
    /// The scheduler rejected a queued operation before applying it.
    Scheduler(SchedulerError),
}

impl fmt::Display for SchedulerActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxClosed => formatter.write_str("scheduler actor mailbox is closed"),
            Self::ReplyDropped => formatter.write_str("scheduler actor reply was dropped"),
            Self::Scheduler(error) => {
                write!(formatter, "scheduler rejected actor message: {error}")
            }
        }
    }
}

impl Error for SchedulerActorError {}
