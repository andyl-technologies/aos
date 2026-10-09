//! Bounded original command custody independent of execution and socket retries.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Id, Position, U64};

use super::{ExecutionCommand, NativeCommandError, OwnerScope};

#[path = "journal_snapshot.rs"]
mod snapshot;

pub use snapshot::{
    CommandJournalSnapshot, NATIVE_COMMAND_JOURNAL_MAX_BYTES, NATIVE_COMMAND_JOURNAL_MAX_ENTRIES,
};

/// Reports whether immutable original command material already has custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandJournalDisposition {
    /// Retains a new original command; native admission remains separately required.
    New,
    /// Recovers the identical outstanding command without resubmission.
    Outstanding,
    /// Recovers a stopped command whose publication custody remains outstanding.
    Stopped,
    /// Recovers an acknowledged original command without re-execution.
    Acknowledged,
}

struct Entry {
    command: ExecutionCommand,
    stopped: Option<Position>,
    acknowledged: bool,
}

/// Retains one prepared owner's original commands across lost replies and retries.
///
/// This journal establishes correlation only. Its caller must authenticate the
/// original prepared channel, complete activation and staged input evidence
/// before native admission. Arbitrarily constructed strings do not authorize
/// execution, and stopping an entry does not prove native queue closure.
pub struct CommandJournal {
    scope: OwnerScope,
    cursor: Position,
    next_sequence: u64,
    maximum_entries: usize,
    entries: BTreeMap<u64, Entry>,
    operations: BTreeSet<Id>,
    grants: BTreeSet<Id>,
    outstanding: Option<u64>,
}

impl CommandJournal {
    /// Initializes bounded custody for an already authenticated prepared owner.
    ///
    /// # Errors
    /// Refuses invalid scope or a zero original-request allowance.
    pub fn new(
        scope: OwnerScope,
        boundary: Position,
        maximum_entries: usize,
    ) -> Result<Self, NativeCommandError> {
        scope.validate()?;
        if maximum_entries == 0 {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(Self {
            scope,
            cursor: boundary,
            next_sequence: 1,
            maximum_entries,
            entries: BTreeMap::new(),
            operations: BTreeSet::new(),
            grants: BTreeSet::new(),
            outstanding: None,
        })
    }

    /// Retains or recovers exact original command material before native admission.
    ///
    /// A conflicting retry never changes the retained request. Completed IDs and
    /// sequences remain tombstones; exhausting their finite allowance fails closed.
    ///
    /// # Errors
    /// Refuses foreign scope, conflicting reused identities, wrong sequence or
    /// cursor, concurrent owner commands and an exhausted journal allowance.
    pub fn retain(
        &mut self,
        command: ExecutionCommand,
    ) -> Result<CommandJournalDisposition, NativeCommandError> {
        command.validate()?;
        if command.scope != self.scope {
            return Err(NativeCommandError::Conflict);
        }
        let sequence = command.sequence.get();
        if let Some(entry) = self.entries.get(&sequence) {
            if entry.command != command {
                return Err(NativeCommandError::Conflict);
            }
            return Ok(if entry.acknowledged {
                CommandJournalDisposition::Acknowledged
            } else if entry.stopped.is_some() {
                CommandJournalDisposition::Stopped
            } else {
                CommandJournalDisposition::Outstanding
            });
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(NativeCommandError::ResourceLimit);
        }
        if self.outstanding.is_some()
            || sequence != self.next_sequence
            || command.kind.start() != self.cursor
            || self.operations.contains(&command.operation)
            || self.grants.contains(&command.grant)
        {
            return Err(NativeCommandError::Conflict);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(NativeCommandError::ResourceLimit)?;
        self.operations.insert(command.operation.clone());
        self.grants.insert(command.grant.clone());
        self.entries.insert(
            sequence,
            Entry {
                command,
                stopped: None,
                acknowledged: false,
            },
        );
        self.outstanding = Some(sequence);
        self.next_sequence = next_sequence;
        Ok(CommandJournalDisposition::New)
    }

    /// Reports whether this incarnation has retained no execution command.
    ///
    /// This journal fact grants no physical, input or native queue authority.
    pub fn is_pristine(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns exact original immutable material for native receipt validation.
    pub fn original(&self, sequence: U64) -> Option<&ExecutionCommand> {
        self.entries
            .get(&sequence.get())
            .map(|entry| &entry.command)
    }

    /// Records an authenticated native stop without releasing publication custody.
    ///
    /// The native adapter must validate actual stop, pending service credit and
    /// complete queue evidence before calling this correlation-only method.
    ///
    /// # Errors
    /// Refuses unknown identities, conflicting repeated stops and out-of-range
    /// progress. It never clamps overshoot or substitutes an intended ceiling.
    pub fn record_native_stop(
        &mut self,
        sequence: U64,
        reached: Position,
    ) -> Result<(), NativeCommandError> {
        let entry = self
            .entries
            .get_mut(&sequence.get())
            .ok_or(NativeCommandError::Conflict)?;
        if reached < entry.command.kind.start() || reached > entry.command.kind.limit() {
            return Err(NativeCommandError::Conflict);
        }
        if let Some(original) = entry.stopped {
            return if original == reached {
                Ok(())
            } else {
                Err(NativeCommandError::Conflict)
            };
        }
        if self.outstanding != Some(sequence.get()) {
            return Err(NativeCommandError::Conflict);
        }
        entry.stopped = Some(reached);
        Ok(())
    }

    /// Releases stopped native custody after the matching committed publication.
    ///
    /// Callers must authenticate the host's original canonical commitment before
    /// invoking this method; a successful stop is not a publication acknowledgement.
    ///
    /// # Errors
    /// Refuses unknown or unstopped commands and mismatched original authorization.
    pub fn acknowledge(
        &mut self,
        sequence: U64,
        authorization_digest: &[u8; 32],
    ) -> Result<(), NativeCommandError> {
        let entry = self
            .entries
            .get_mut(&sequence.get())
            .ok_or(NativeCommandError::Conflict)?;
        if &entry.command.authorization_digest != authorization_digest {
            return Err(NativeCommandError::Conflict);
        }
        let reached = entry.stopped.ok_or(NativeCommandError::Conflict)?;
        if entry.acknowledged {
            return Ok(());
        }
        if self.outstanding != Some(sequence.get()) {
            return Err(NativeCommandError::Conflict);
        }
        entry.acknowledged = true;
        self.cursor = reached;
        self.outstanding = None;
        Ok(())
    }
}
