//! Complete pointer-free original command custody images.
//!
//! These bytes preserve correlation data, including outstanding commands and
//! acknowledgement tombstones. Restoring the data creates no execution,
//! publication, readiness, physical-stop or fresh-world authority. A native
//! adapter must separately preserve its engine, buffers and writer custody.
//!
//! ```text
//! CNPJNL01 | u32 prepared-frame-length | Prepare frame
//!         | current Position | u64 next-sequence | u64 outstanding-or-zero
//!         | u32 entry-count | entries
//! entry = u32 command-frame-length | Command frame | u8 stopped
//!         | optional reached Position | u8 acknowledged
//! ```

use crucible_node_contract::U64;

use super::{
    CommandJournal, CommandJournalDisposition, ExecutionCommand, NativeCommandError, Position,
};
use crate::node_control::{
    NativeFrame, NativePreparation, codec::Cursor, decode_frame, encode_frame,
};

const MAGIC: &[u8; 8] = b"CNPJNL01";
const POSITION_BYTES: usize = 8 + 8 + 2;
const METADATA_BYTES: usize = POSITION_BYTES + 8 + 8 + 4;

/// Bounds a complete original command-journal image before allocation.
pub const NATIVE_COMMAND_JOURNAL_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Bounds retained original entries independently of caller-provided byte lengths.
pub const NATIVE_COMMAND_JOURNAL_MAX_ENTRIES: usize = 65_536;

/// Owns a complete locally validated original command-journal image.
///
/// This value is data, not native authority. It includes the exact original
/// owner scope and every original request and acknowledgement tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandJournalSnapshot {
    preparation: NativePreparation,
    cursor: Position,
    next_sequence: u64,
    outstanding: Option<u64>,
    entries: Vec<SnapshotEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotEntry {
    command: ExecutionCommand,
    stopped: Option<Position>,
    acknowledged: bool,
}

impl CommandJournal {
    /// Captures complete original correlation data without issuing native work.
    ///
    /// The caller must hold its real reader/writer gate while composing this
    /// image with native engine, input, output, timer and resource state. This
    /// method alone establishes neither physical suspension nor exact capture.
    ///
    /// # Errors
    /// Rejects excessive retained entries or a nonportable journal allowance.
    pub fn snapshot(&self) -> Result<CommandJournalSnapshot, NativeCommandError> {
        if self.maximum_entries == 0
            || self.maximum_entries > NATIVE_COMMAND_JOURNAL_MAX_ENTRIES
            || self.entries.len() > NATIVE_COMMAND_JOURNAL_MAX_ENTRIES
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        let preparation = NativePreparation {
            scope: self.scope.clone(),
            boundary: self
                .entries
                .first_key_value()
                .map_or(self.cursor, |(_, entry)| entry.command.kind.start()),
            maximum_commands: U64::new(self.maximum_entries as u64),
        };
        let preparation_bytes = encode_frame(&NativeFrame::Prepare(Box::new(preparation.clone())))?;
        let mut length = MAGIC.len() + 4 + preparation_bytes.len() + METADATA_BYTES;
        for entry in self.entries.values() {
            let command = crate::node_control::encode_command(&entry.command)?;
            let entry_length =
                4 + command.len() + 2 + usize::from(entry.stopped.is_some()) * POSITION_BYTES;
            length = length
                .checked_add(entry_length)
                .filter(|length| *length <= NATIVE_COMMAND_JOURNAL_MAX_BYTES)
                .ok_or(NativeCommandError::ResourceLimit)?;
        }
        Ok(CommandJournalSnapshot {
            preparation,
            cursor: self.cursor,
            next_sequence: self.next_sequence,
            outstanding: self.outstanding,
            entries: self
                .entries
                .values()
                .map(|entry| SnapshotEntry {
                    command: entry.command.clone(),
                    stopped: entry.stopped,
                    acknowledged: entry.acknowledged,
                })
                .collect(),
        })
    }
}

impl CommandJournalSnapshot {
    /// Returns the exact original inactive preparation, without fresh authority.
    pub fn preparation(&self) -> &NativePreparation {
        &self.preparation
    }

    /// Returns the original owner-local acknowledged cursor.
    pub fn cursor(&self) -> Position {
        self.cursor
    }

    /// Returns the original outstanding sequence, whether pending or stopped.
    pub fn outstanding_sequence(&self) -> Option<U64> {
        self.outstanding.map(U64::new)
    }

    /// Counts retained original requests, including acknowledged tombstones.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Encodes unchanged original custody as one bounded canonical data object.
    ///
    /// # Errors
    /// Rejects incoherent original state or a caller allowance above the format
    /// ceiling or below the actual complete object length. No prefix is returned.
    pub fn encode(&self, maximum_bytes: usize) -> Result<Vec<u8>, NativeCommandError> {
        if maximum_bytes > NATIVE_COMMAND_JOURNAL_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut bytes = Vec::new();
        append(&mut bytes, MAGIC, maximum_bytes)?;
        let prepare = encode_frame(&NativeFrame::Prepare(Box::new(self.preparation.clone())))?;
        length_prefixed(&mut bytes, &prepare, maximum_bytes)?;
        let mut metadata = Vec::new();
        crate::node_control::codec::position(&mut metadata, self.cursor);
        metadata.extend_from_slice(&self.next_sequence.to_be_bytes());
        metadata.extend_from_slice(&self.outstanding.unwrap_or(0).to_be_bytes());
        metadata.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        append(&mut bytes, &metadata, maximum_bytes)?;
        for entry in &self.entries {
            let command = encode_frame(&NativeFrame::Command(Box::new(entry.command.clone())))?;
            length_prefixed(&mut bytes, &command, maximum_bytes)?;
            let mut state = vec![u8::from(entry.stopped.is_some())];
            if let Some(position) = entry.stopped {
                crate::node_control::codec::position(&mut state, position);
            }
            state.push(u8::from(entry.acknowledged));
            append(&mut bytes, &state, maximum_bytes)?;
        }
        self.restore_correlation()?;
        Ok(bytes)
    }

    /// Decodes the complete bounded original journal without any native effects.
    ///
    /// # Errors
    /// Rejects excessive length/count, truncation, unknown flags, trailing bytes,
    /// changed owner/cursor, missing original stops and inconsistent acknowledgements.
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, NativeCommandError> {
        if maximum_bytes > NATIVE_COMMAND_JOURNAL_MAX_BYTES || bytes.len() > maximum_bytes {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(NativeCommandError::Conflict);
        }
        let NativeFrame::Prepare(preparation) = read_frame(&mut cursor)? else {
            return Err(NativeCommandError::Conflict);
        };
        let position = cursor.position()?;
        let next_sequence = cursor.u64()?;
        let outstanding = match cursor.u64()? {
            0 => None,
            value => Some(value),
        };
        let entry_count = cursor.u32()? as usize;
        if entry_count > NATIVE_COMMAND_JOURNAL_MAX_ENTRIES
            || entry_count > preparation.maximum_commands.get() as usize
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let NativeFrame::Command(command) = read_frame(&mut cursor)? else {
                return Err(NativeCommandError::Conflict);
            };
            let stopped = match cursor.u8()? {
                0 => None,
                1 => Some(cursor.position()?),
                _ => return Err(NativeCommandError::Conflict),
            };
            let acknowledged = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(NativeCommandError::Conflict),
            };
            entries.push(SnapshotEntry {
                command: *command,
                stopped,
                acknowledged,
            });
        }
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Conflict);
        }
        let snapshot = Self {
            preparation: *preparation,
            cursor: position,
            next_sequence,
            outstanding,
            entries,
        };
        snapshot.restore_correlation()?;
        Ok(snapshot)
    }

    /// Reconstructs the same correlation ledger without resubmitting native work.
    ///
    /// The original owner scope is intentionally preserved. This method does
    /// not rebind a child to fresh owner authority or restore engine state. A
    /// native capture/fork adapter must separately authenticate that whole cut.
    ///
    /// # Errors
    /// Rejects incoherent original requests, reused IDs, acknowledgements without
    /// actual original stops, changed cursor or outstanding sequence, and overflow.
    pub fn restore_correlation(&self) -> Result<CommandJournal, NativeCommandError> {
        self.preparation.validate()?;
        if self.entries.len() > NATIVE_COMMAND_JOURNAL_MAX_ENTRIES
            || self.entries.len() > self.preparation.maximum_commands.get() as usize
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut journal = CommandJournal::new(
            self.preparation.scope.clone(),
            self.preparation.boundary,
            self.preparation.maximum_commands.get() as usize,
        )?;
        for entry in &self.entries {
            if journal.retain(entry.command.clone())? != CommandJournalDisposition::New {
                return Err(NativeCommandError::Conflict);
            }
            if let Some(reached) = entry.stopped {
                journal.record_native_stop(entry.command.sequence, reached)?;
            }
            if entry.acknowledged {
                journal.acknowledge(entry.command.sequence, &entry.command.authorization_digest)?;
            }
        }
        if journal.cursor != self.cursor
            || journal.next_sequence != self.next_sequence
            || journal.outstanding != self.outstanding
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(journal)
    }
}

fn append(bytes: &mut Vec<u8>, suffix: &[u8], maximum: usize) -> Result<(), NativeCommandError> {
    if bytes
        .len()
        .checked_add(suffix.len())
        .is_none_or(|length| length > maximum)
    {
        return Err(NativeCommandError::ResourceLimit);
    }
    bytes.extend_from_slice(suffix);
    Ok(())
}

fn length_prefixed(
    bytes: &mut Vec<u8>,
    object: &[u8],
    maximum: usize,
) -> Result<(), NativeCommandError> {
    let length = u32::try_from(object.len()).map_err(|_| NativeCommandError::ResourceLimit)?;
    append(bytes, &length.to_be_bytes(), maximum)?;
    append(bytes, object, maximum)
}

fn read_frame(cursor: &mut Cursor<'_>) -> Result<NativeFrame, NativeCommandError> {
    let length = cursor.u32()? as usize;
    if length
        > crate::node_control::NODE_CONTROL_HEADER_BYTES
            + crate::node_control::NODE_CONTROL_MAX_BODY_BYTES
    {
        return Err(NativeCommandError::ResourceLimit);
    }
    decode_frame(cursor.take(length)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::node_control::{BoundaryPolicy, ExecutionKind, OwnerScope};
    use crucible_node_contract::{HashRef, Id, Phase};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn position(time: u64) -> Position {
        Position {
            time_ps: U64::new(time),
            microstep: U64::new(0),
            phase: Phase::BoundaryControl,
        }
    }

    fn hash(domain: &str) -> HashRef {
        HashRef {
            algorithm: "blake3-256".into(),
            domain: domain.into(),
            digest: "01".repeat(32),
        }
    }

    fn command() -> ExecutionCommand {
        ExecutionCommand {
            sequence: U64::new(1),
            scope: OwnerScope {
                session: id("session/a"),
                incarnation: id("incarnation/a"),
                activation: id("activation/1"),
                node: id("machine/a"),
                owner: id("owner/a"),
                world_generation: U64::new(1),
                owner_generation: U64::new(3),
                world_binding: hash("cnp.world-binding.v1"),
                owner_binding: hash("cnp.owner-binding.v1"),
            },
            operation: id("operation/1"),
            grant: id("grant/1"),
            input_epoch: id("input/epoch"),
            input_batch: id("batch/1"),
            input_batch_hash: hash("cnp.input-batch.v1"),
            closed_input_prefix: position(100),
            authorization_digest: [7; 32],
            kind: ExecutionKind::ExactRun {
                start: position(0),
                limit: position(100),
                boundary_policy: BoundaryPolicy::HorizonPark,
            },
        }
    }

    #[test]
    fn acknowledged_tombstone_and_lost_ack_custody_restore_without_native_resubmission() {
        let original = command();
        let mut journal =
            CommandJournal::new(original.scope.clone(), original.kind.start(), 4).unwrap();
        journal.retain(original.clone()).unwrap();
        journal
            .record_native_stop(original.sequence, original.kind.limit())
            .unwrap();
        let before_ack = journal.snapshot().unwrap();
        let bytes = before_ack.encode(4096).unwrap();
        let mut restored = CommandJournalSnapshot::decode(&bytes, 4096)
            .unwrap()
            .restore_correlation()
            .unwrap();
        assert_eq!(
            restored.retain(original.clone()).unwrap(),
            CommandJournalDisposition::Stopped
        );
        restored
            .acknowledge(original.sequence, &original.authorization_digest)
            .unwrap();
        let after_ack = restored.snapshot().unwrap();
        let mut restored = CommandJournalSnapshot::decode(&after_ack.encode(4096).unwrap(), 4096)
            .unwrap()
            .restore_correlation()
            .unwrap();
        assert_eq!(
            restored.retain(original).unwrap(),
            CommandJournalDisposition::Acknowledged
        );
        assert_eq!(restored.snapshot().unwrap(), after_ack);
    }

    #[test]
    fn outstanding_original_with_no_stop_is_preserved_as_pending() {
        let original = command();
        let mut journal =
            CommandJournal::new(original.scope.clone(), original.kind.start(), 4).unwrap();
        journal.retain(original.clone()).unwrap();
        let snapshot = journal.snapshot().unwrap();
        assert_eq!(snapshot.outstanding_sequence(), Some(original.sequence));
        let mut restored = CommandJournalSnapshot::decode(&snapshot.encode(4096).unwrap(), 4096)
            .unwrap()
            .restore_correlation()
            .unwrap();
        assert_eq!(
            restored.retain(original.clone()).unwrap(),
            CommandJournalDisposition::Outstanding
        );
        assert!(
            restored
                .acknowledge(original.sequence, &original.authorization_digest)
                .is_err()
        );
    }

    #[test]
    fn independent_restored_ledgers_keep_full_history_and_original_unacknowledged_stop() {
        let first = command();
        let mut journal = CommandJournal::new(first.scope.clone(), first.kind.start(), 4).unwrap();
        journal.retain(first.clone()).unwrap();
        journal
            .record_native_stop(first.sequence, first.kind.limit())
            .unwrap();
        journal
            .acknowledge(first.sequence, &first.authorization_digest)
            .unwrap();

        let mut second = first.clone();
        second.sequence = U64::new(2);
        second.operation = id("operation/2");
        second.grant = id("grant/2");
        second.closed_input_prefix = position(200);
        second.kind = ExecutionKind::ExactRun {
            start: position(100),
            limit: position(200),
            boundary_policy: BoundaryPolicy::HorizonPark,
        };
        journal.retain(second.clone()).unwrap();
        journal
            .record_native_stop(second.sequence, second.kind.limit())
            .unwrap();

        let snapshot = journal.snapshot().unwrap();
        let bytes = snapshot.encode(4096).unwrap();
        let saved = CommandJournalSnapshot::decode(&bytes, 4096).unwrap();
        assert_eq!(saved.encode(4096).unwrap(), bytes);
        assert_eq!(saved.entry_count(), 2);
        let mut left = saved.restore_correlation().unwrap();
        let mut right = saved.restore_correlation().unwrap();

        left.acknowledge(second.sequence, &second.authorization_digest)
            .unwrap();

        assert_eq!(left.snapshot().unwrap().cursor(), position(200));
        assert_eq!(right.snapshot().unwrap().cursor(), position(100));
        assert_eq!(
            right.retain(second.clone()).unwrap(),
            CommandJournalDisposition::Stopped
        );
        assert_eq!(
            left.retain(second).unwrap(),
            CommandJournalDisposition::Acknowledged
        );
        assert_eq!(
            left.retain(first.clone()).unwrap(),
            CommandJournalDisposition::Acknowledged
        );
        assert_eq!(
            right.retain(first).unwrap(),
            CommandJournalDisposition::Acknowledged
        );
        assert_eq!(journal.snapshot().unwrap(), snapshot);
    }

    #[test]
    fn truncated_changed_cursor_or_invented_ack_never_restore_custody() {
        let original = command();
        let mut journal =
            CommandJournal::new(original.scope.clone(), original.kind.start(), 4).unwrap();
        journal.retain(original).unwrap();
        let snapshot = journal.snapshot().unwrap();
        let bytes = snapshot.encode(4096).unwrap();
        for length in 0..bytes.len() {
            assert!(CommandJournalSnapshot::decode(&bytes[..length], 4096).is_err());
        }
        assert!(snapshot.encode(bytes.len() - 1).is_err());
        let mut invented = snapshot.clone();
        invented.entries[0].acknowledged = true;
        assert!(invented.restore_correlation().is_err());
        let mut moved = snapshot;
        moved.cursor.time_ps = U64::new(999);
        assert!(moved.restore_correlation().is_err());
    }
}
