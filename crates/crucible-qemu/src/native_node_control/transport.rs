//! Private prepared socket handover and bounded recoverable native requests.

use std::{collections::BTreeMap, os::unix::net::UnixDatagram};

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    CommandJournal, CommandJournalDisposition, ExecutionCommand, NativeChannel, NativeChannelError,
    NativeCommandError, NativeControlEdition, NativeCpuParkFacts, NativeFrame, NativePreparation,
    NativeStopFacts, NativeStopKind, ReceiptAcknowledgement,
};

/// Reports physical transport failure or conflicting original native material.
#[derive(Debug, thiserror::Error)]
pub enum NativeQemuControlError {
    /// The private bounded channel failed its codec or physical transport.
    #[error(transparent)]
    Transport(#[from] NativeChannelError),
    /// Original request or native fact correlation failed closed.
    #[error(transparent)]
    Protocol(#[from] NativeCommandError),
}

/// Owns the distinct provider socket and immutable prepared scope commitment.
pub struct NativeLaunchEndpoint {
    socket: UnixDatagram,
    scope_digest: [u8; 32],
    edition: NativeControlEdition,
    initialization: Option<crucible_protocol::node_control::NativeInitializationPreparation>,
}

impl NativeLaunchEndpoint {
    /// Returns the preparation commitment to pin in the native plugin arguments.
    pub fn scope_digest(&self) -> &[u8; 32] {
        &self.scope_digest
    }

    /// Returns the exact edition to pin in the native launch configuration.
    pub fn edition(&self) -> NativeControlEdition {
        self.edition
    }

    /// Returns the original construction preparation pinned before native startup.
    pub fn initialization(
        &self,
    ) -> Option<&crucible_protocol::node_control::NativeInitializationPreparation> {
        self.initialization.as_ref()
    }

    /// Transfers the owned socket to the supervised inherited-descriptor launcher.
    ///
    /// The launcher must retain custody until child exec, keep it distinct from
    /// all existing descriptors and pass the pinned scope digest unchanged.
    pub fn into_socket(self) -> UnixDatagram {
        self.socket
    }
}

/// Retains original native commands and facts independently of socket retries.
pub struct NativeQemuControlTransport {
    pub(super) channel: NativeChannel,
    pub(super) journal: CommandJournal,
    pub(super) source_fault: Option<crucible_protocol::node_control::SourceFaultFacts>,
    pub(super) facts: BTreeMap<u64, NativeStopFacts>,
    pub(super) prepared_scope_hash: [u8; 32],
    prepared_boundary: crucible_node_contract::Position,
    pub(super) cpu_park: Option<NativeCpuParkFacts>,
    pub(super) timer_objects: BTreeMap<u64, super::timers::TimerAssembly>,
    pub(super) initialization: Option<super::initialization::InitializationJournal>,
    pub(super) writer_objects: BTreeMap<u64, super::writers::WriterAssembly>,
}

impl NativeQemuControlTransport {
    /// Creates a private pair with the complete inactive preparation already queued.
    ///
    /// Preparation creates no execution authority. Only an independently
    /// admitted provider may submit commands after authentic complete activation.
    ///
    /// # Errors
    /// Rejects invalid or unbounded preparation and socket or framing failures.
    pub fn prepare(
        preparation: NativePreparation,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        Self::prepare_for_edition(preparation, NativeControlEdition::Original)
    }

    /// Prepares a private descriptor pair with an explicitly pinned wire edition.
    ///
    /// The provider must verify the actual native implementation's edition and
    /// selected capabilities before launch. Selection itself qualifies neither
    /// execution, complete writer closure nor state preservation.
    ///
    /// # Errors
    /// Rejects invalid preparation or bounded socket and codec failures.
    pub fn prepare_for_edition(
        preparation: NativePreparation,
        edition: NativeControlEdition,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        Self::prepare_channel(
            preparation.clone(),
            edition,
            NativeFrame::Prepare(Box::new(preparation)),
            None,
        )
    }

    pub(super) fn prepare_channel(
        preparation: NativePreparation,
        edition: NativeControlEdition,
        first_frame: NativeFrame,
        initialization: Option<crucible_protocol::node_control::NativeInitializationPreparation>,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        let scope_digest = preparation.scope.identity_digest()?;
        let maximum_commands = usize::try_from(preparation.maximum_commands.get())
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let prepared_boundary = preparation.boundary;
        let journal = CommandJournal::new(
            preparation.scope.clone(),
            preparation.boundary,
            maximum_commands,
        )?;
        let (channel, provider) = NativeChannel::supervised_pair_for_edition(edition)?;
        if !channel.send(&first_frame)? {
            return Err(NativeCommandError::ResourceLimit.into());
        }
        Ok((
            Self {
                channel,
                journal,
                source_fault: None,
                facts: BTreeMap::new(),
                prepared_scope_hash: scope_digest,
                prepared_boundary,
                cpu_park: None,
                timer_objects: BTreeMap::new(),
                writer_objects: BTreeMap::new(),
                initialization: initialization
                    .clone()
                    .map(super::initialization::InitializationJournal::new),
            },
            NativeLaunchEndpoint {
                socket: provider.into_prepared_socket(),
                scope_digest,
                edition,
                initialization,
            },
        ))
    }

    /// Requests the same retained CPU-only observation without granting work.
    ///
    /// Source query support is optional. Successful send proves neither receipt
    /// availability nor full all-owner readiness or native queue/input closure.
    ///
    /// # Errors
    /// Returns bounded framing or physical channel failures.
    pub fn request_cpu_park(&self) -> Result<bool, NativeQemuControlError> {
        Ok(self
            .channel
            .send(&NativeFrame::QueryCpuPark(self.prepared_scope_hash))?)
    }

    /// Returns historical initial CPU-only facts under their original scope.
    ///
    /// These bytes never prove current physical suspension, complete queues,
    /// input closure, captured state or permission to activate a world.
    pub fn prepared_cpu_park(&self) -> Option<&NativeCpuParkFacts> {
        self.cpu_park.as_ref()
    }

    /// Retains and transmits an independently authorized immutable original command.
    ///
    /// The caller must authenticate activation, staged input closure and owner
    /// custody before invoking this transport-only method. Successful send is
    /// never an execution or publication acknowledgement.
    ///
    /// # Errors
    /// Rejects conflicting retries, foreign scope, simultaneous owner commands,
    /// exhausted original-request allowances or physical transport failures.
    pub fn transmit_original(
        &mut self,
        command: ExecutionCommand,
    ) -> Result<(CommandJournalDisposition, bool), NativeQemuControlError> {
        if self.source_fault.is_some()
            || self
                .initialization
                .as_ref()
                .is_some_and(|journal| !journal.permits_execution())
        {
            return Err(NativeCommandError::Conflict.into());
        }
        if self.channel.edition() == NativeControlEdition::OwnedCustody
            && self.writer_observation(U64::new(0)).is_none()
        {
            return Err(NativeCommandError::Conflict.into());
        }
        let disposition = self.journal.retain(command.clone())?;
        let sent = self
            .channel
            .send(&NativeFrame::Command(Box::new(command)))?;
        Ok((disposition, sent))
    }

    /// Reads one original native fact or journal acknowledgement without blocking.
    ///
    /// # Errors
    /// Rejects unsolicited frame kinds, forged identities, changed repeated facts,
    /// out-of-range progress and malformed or physically failed transport.
    pub fn poll_original(&mut self) -> Result<Option<NativeFrame>, NativeQemuControlError> {
        let Some(frame) = self.channel.receive()? else {
            return Ok(None);
        };
        match &frame {
            NativeFrame::InitializationCut(_)
            | NativeFrame::InitializationStopped(_)
            | NativeFrame::InitializationAcknowledged(_) => {
                self.accept_initialization_frame(&frame)?
            }
            NativeFrame::SourceFault(facts) => self.accept_source_fault(facts)?,
            NativeFrame::TimerChunk(chunk) => self.accept_timer_chunk(chunk)?,
            NativeFrame::WriterChunk(chunk) => self.accept_writer_chunk(chunk)?,
            NativeFrame::CpuPark(facts) => {
                if facts.prepared_scope_hash != self.prepared_scope_hash
                    || facts.current_ps != self.prepared_boundary.time_ps
                    || self
                        .cpu_park
                        .as_ref()
                        .is_some_and(|original| original != facts)
                {
                    return Err(NativeCommandError::Conflict.into());
                }
                self.cpu_park = Some(facts.clone());
            }
            NativeFrame::Stopped(facts) => {
                if self.source_fault.is_some() {
                    return Err(NativeCommandError::Conflict.into());
                }
                let original = self
                    .journal
                    .original(facts.sequence)
                    .ok_or(NativeCommandError::Conflict)?;
                if facts.command_digest != original.identity_digest()?
                    || (facts.kind == NativeStopKind::HorizonPark
                        && facts.reached != original.kind.limit())
                    || self
                        .facts
                        .get(&facts.sequence.get())
                        .is_some_and(|old| old != facts)
                {
                    return Err(NativeCommandError::Conflict.into());
                }
                self.journal
                    .record_native_stop(facts.sequence, facts.reached)?;
                self.facts.insert(facts.sequence.get(), facts.clone());
            }
            NativeFrame::Acknowledged(ack) => {
                if self.source_fault.is_some() {
                    return Err(NativeCommandError::Conflict.into());
                }
                let original = self
                    .journal
                    .original(ack.sequence)
                    .ok_or(NativeCommandError::Conflict)?;
                if original.identity_digest()? != ack.command_digest {
                    return Err(NativeCommandError::Conflict.into());
                }
                self.journal
                    .acknowledge(ack.sequence, &ack.authorization_digest)?;
            }
            _ => return Err(NativeCommandError::Conflict.into()),
        }
        Ok(Some(frame))
    }

    /// Retransmits the original host commitment without releasing host custody.
    ///
    /// The caller must establish canonical commitment independently. Original
    /// host custody remains outstanding until the matching native journal reply
    /// is read; dropping a transmitted ACK never manufactures that reply.
    ///
    /// # Errors
    /// Rejects unstopped or unknown originals and physical transmission failures.
    pub fn transmit_acknowledgement(&self, sequence: U64) -> Result<bool, NativeQemuControlError> {
        if self.source_fault.is_some() {
            return Err(NativeCommandError::Conflict.into());
        }
        let original = self
            .journal
            .original(sequence)
            .ok_or(NativeCommandError::Conflict)?;
        if !self.facts.contains_key(&sequence.get()) {
            return Err(NativeCommandError::Conflict.into());
        }
        Ok(self
            .channel
            .send(&NativeFrame::Acknowledge(ReceiptAcknowledgement {
                sequence,
                command_digest: original.identity_digest()?,
                authorization_digest: original.authorization_digest,
            }))?)
    }

    /// Returns original retained native facts without complete source closure claims.
    pub fn original_facts(&self, sequence: U64) -> Option<&NativeStopFacts> {
        self.facts.get(&sequence.get())
    }
}

#[cfg(test)]
mod tests;
