//! Original construction journal custody and matching administrative replies.
//!
//! Applied initialization and its ACK settle only the finite original callback
//! cut. Neither record proves native source closure, readiness or activation.

use crucible_protocol::node_control::{
    CommandJournalDisposition, NativeCommandError, NativeControlEdition, NativeFrame,
    NativeInitializationAcknowledgement, NativeInitializationCommand, NativeInitializationCut,
    NativeInitializationPreparation, NativeInitializationQuery, NativeInitializationReceipt,
    NativeInitializationStatus,
};

use super::{NativeLaunchEndpoint, NativeQemuControlError, NativeQemuControlTransport};

pub(super) struct InitializationJournal {
    preparation: NativeInitializationPreparation,
    cut: Option<NativeInitializationCut>,
    command: Option<NativeInitializationCommand>,
    receipt: Option<NativeInitializationReceipt>,
    acknowledgement: Option<NativeInitializationAcknowledgement>,
    acknowledged: bool,
    failed: bool,
}

impl InitializationJournal {
    pub(super) fn new(preparation: NativeInitializationPreparation) -> Self {
        Self {
            preparation,
            cut: None,
            command: None,
            receipt: None,
            acknowledgement: None,
            acknowledged: false,
            failed: false,
        }
    }

    pub(super) fn permits_execution(&self) -> bool {
        !self.failed
            && self.acknowledged
            && self
                .receipt
                .as_ref()
                .is_some_and(|receipt| receipt.status == NativeInitializationStatus::Applied)
    }

    fn accept(&mut self, frame: &NativeFrame) -> Result<(), NativeCommandError> {
        match frame {
            NativeFrame::InitializationCut(cut) => {
                cut.validate_against(&self.preparation)?;
                if self
                    .cut
                    .as_ref()
                    .is_some_and(|original| original != cut.as_ref())
                {
                    return Err(NativeCommandError::Conflict);
                }
                self.cut = Some(*cut.clone());
            }
            NativeFrame::InitializationStopped(receipt) => {
                receipt.validate_against(
                    self.command.as_ref().ok_or(NativeCommandError::Conflict)?,
                    self.cut.as_ref().ok_or(NativeCommandError::Conflict)?,
                )?;
                if self
                    .receipt
                    .as_ref()
                    .is_some_and(|original| original != receipt.as_ref())
                {
                    return Err(NativeCommandError::Conflict);
                }
                if receipt.status == NativeInitializationStatus::EffectsUnknown {
                    self.failed = true;
                }
                self.receipt = Some(*receipt.clone());
            }
            NativeFrame::InitializationAcknowledged(ack) => {
                if self.failed || self.acknowledgement.as_ref() != Some(ack) {
                    return Err(NativeCommandError::Conflict);
                }
                self.acknowledged = true;
            }
            _ => return Err(NativeCommandError::Conflict),
        }
        Ok(())
    }
}

impl NativeQemuControlTransport {
    /// Pins construction authorization before the emulator creates startup objects.
    ///
    /// The installed provider must authenticate the original Realize envelope and
    /// policy before choosing this preparation. The launch endpoint carries the
    /// exact early argument and plugin pin fields; no preparation value is Ready.
    ///
    /// # Errors
    /// Rejects invalid preparation, socket creation or bounded framing failures.
    pub fn prepare_initialization(
        preparation: NativeInitializationPreparation,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        preparation.validate()?;
        Self::prepare_channel(
            preparation.preparation.clone(),
            NativeControlEdition::OwnedCustody,
            NativeFrame::PrepareInitialization(Box::new(preparation.clone())),
            Some(preparation),
        )
    }

    /// Requests the same retained source-selected startup cut without resampling.
    ///
    /// # Errors
    /// Rejects absent initialization, source faults or physical transport failure.
    pub fn request_initialization_cut(&self) -> Result<bool, NativeQemuControlError> {
        let journal = self
            .initialization
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        if self.source_fault.is_some() {
            return Err(NativeCommandError::Conflict.into());
        }
        Ok(self.channel.send(&NativeFrame::QueryInitialization(
            NativeInitializationQuery {
                prepared_scope_hash: self.prepared_scope_hash,
                initialization_commitment: journal.preparation.identity_digest()?,
            },
        ))?)
    }

    /// Returns the unchanged original construction cut, without readiness claims.
    pub fn initialization_cut(&self) -> Option<&NativeInitializationCut> {
        self.initialization.as_ref()?.cut.as_ref()
    }

    /// Retains and transmits one original finite construction command.
    ///
    /// # Errors
    /// Rejects changed retries, foreign cut fields, source faults, unknown effects
    /// without a retained original result or physical transport failures.
    pub fn transmit_initialization(
        &mut self,
        command: NativeInitializationCommand,
    ) -> Result<(CommandJournalDisposition, bool), NativeQemuControlError> {
        if self.source_fault.is_some() {
            return Err(NativeCommandError::Conflict.into());
        }
        let journal = self
            .initialization
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        command.validate_against(
            &journal.preparation,
            journal.cut.as_ref().ok_or(NativeCommandError::Conflict)?,
        )?;
        let disposition = if let Some(original) = &journal.command {
            if original != &command {
                return Err(NativeCommandError::Conflict.into());
            }
            if journal.acknowledged {
                CommandJournalDisposition::Acknowledged
            } else if journal.receipt.is_some() {
                CommandJournalDisposition::Stopped
            } else if journal.failed {
                return Err(NativeCommandError::Conflict.into());
            } else {
                CommandJournalDisposition::Outstanding
            }
        } else {
            if journal.failed {
                return Err(NativeCommandError::Conflict.into());
            }
            journal.command = Some(command.clone());
            CommandJournalDisposition::New
        };
        Ok((
            disposition,
            self.channel
                .send(&NativeFrame::Initialize(Box::new(command)))?,
        ))
    }

    /// Returns the original administrative result independently of ACK retries.
    pub fn initialization_receipt(&self) -> Option<&NativeInitializationReceipt> {
        self.initialization.as_ref()?.receipt.as_ref()
    }

    /// Transmits the original construction journal ACK while retaining custody.
    ///
    /// A send never substitutes for the matching original native reply.
    ///
    /// # Errors
    /// Rejects absent results, unknown effects, source faults or transport failures.
    pub fn transmit_initialization_acknowledgement(
        &mut self,
    ) -> Result<bool, NativeQemuControlError> {
        if self.source_fault.is_some() {
            return Err(NativeCommandError::Conflict.into());
        }
        let journal = self
            .initialization
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        if journal.failed || journal.receipt.is_none() {
            return Err(NativeCommandError::Conflict.into());
        }
        let command = journal
            .command
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        let ack = NativeInitializationAcknowledgement {
            prepared_scope_hash: command.prepared_scope_hash,
            initialization_commitment: command.initialization_commitment,
            sequence: command.sequence,
            command_digest: command.identity_digest()?,
        };
        journal.acknowledgement = Some(ack.clone());
        Ok(self
            .channel
            .send(&NativeFrame::AcknowledgeInitialization(ack))?)
    }

    /// Reports settlement of the original construction journal only.
    pub fn initialization_acknowledged(&self) -> bool {
        self.initialization
            .as_ref()
            .is_some_and(|journal| journal.acknowledged)
    }

    pub(super) fn accept_initialization_frame(
        &mut self,
        frame: &NativeFrame,
    ) -> Result<(), NativeQemuControlError> {
        let journal = self
            .initialization
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        let result = journal.accept(frame);
        if result.is_err() {
            journal.failed = true;
        }
        Ok(result?)
    }
}
