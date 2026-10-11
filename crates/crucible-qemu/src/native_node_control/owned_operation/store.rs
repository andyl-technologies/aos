//! Retains one bounded working command and an append-only durable evidence chain.
//!
//! ```text
//! record0: scope32 | prefixPreparation32 | maxPrefixes:u32be | reserved0
//!          lifetimeBytes:u64be | lifetimeCommands:u64be
//! record1: previousReceiptDigest32 | completeComputeFrame:blob
//! record2: completeTerminalEvidence:blob
//! record3: terminalRecordDigest32 | originalNativeRetirementReceipt:blob
//! record4: receiptRecordDigest32 | originalNativeRetirementCommit:blob
//! ```
//!
//! Every record is checksummed and fsynced before its storage transition is
//! visible. The finite per-command quota is charged before guest command exposure;
//! unused quota is retained for the archive lifetime. No command tombstone is
//! evicted. Native confirmation remains mandatory outside this storage layer.

// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crucible_protocol::node_control::{
    NativeControlEdition, NativeEffectCompute, NativeFrame, decode_frame_for_edition,
    encode_frame_for_edition,
};

use super::codec::{Cursor, RECORD_OVERHEAD, Record, put_blob, read_record, write_record};
use super::{ArchiveError, TerminalEvidence};

const COMMAND_QUOTA: u64 = 65_536;
const HEADER_BYTES: u64 = RECORD_OVERHEAD + 88;

/// Declares the immutable finite archive lifetime before any command is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveBudget {
    /// Bounds total reserved durable bytes, including framing and native receipts.
    pub lifetime_bytes: u64,
    /// Bounds original commands whose complete evidence remains retained.
    pub lifetime_commands: u64,
    /// Bounds retained prefixes per original command, matching its preparation.
    pub maximum_prefixes: u32,
}

impl ArchiveBudget {
    fn validate(self) -> Result<(), ArchiveError> {
        let reserved = self
            .lifetime_commands
            .checked_mul(COMMAND_QUOTA)
            .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
            .ok_or(ArchiveError::Budget)?;
        if self.lifetime_commands == 0
            || !(2..=64).contains(&self.maximum_prefixes)
            || self.lifetime_bytes < reserved
        {
            return Err(ArchiveError::Budget);
        }
        Ok(())
    }
}

/// Reports storage progress without asserting native retirement or dispatch authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnoverState {
    /// Holds no unfinished original; the native retirement fence is checked separately.
    Vacant,
    /// Retains a durably reserved command that may already have effects.
    CommandReserved {
        /// Identifies the durably reserved original command.
        sequence: u64,
    },
    /// Retains terminal history while native retirement remains unconfirmed locally.
    TerminalArchived {
        /// Identifies the original command whose terminal evidence is stored.
        sequence: u64,
        /// Correlates the complete terminal storage record without granting authority.
        terminal_digest: [u8; 32],
    },
    /// Retains a durable native receipt whose authenticity is checked by the adapter.
    ReceiptStored {
        /// Identifies the original command whose receipt is stored.
        sequence: u64,
        /// Correlates the receipt storage record without authenticating its source.
        receipt_digest: [u8; 32],
    },
    /// Retains durable native commit confirmation; every prior command stays archived.
    RetirementCommitted {
        /// Identifies the original command whose confirmation is stored.
        sequence: u64,
        /// Correlates the commit storage record without releasing a native slot.
        commit_digest: [u8; 32],
    },
    /// Keeps all original custody after uncertain local durability.
    Failed,
}

/// Retains complete historical bytes for recovery without reopening guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOriginal {
    /// Retains the complete portable Compute frame with its unchanged body.
    pub command_frame: Vec<u8>,
    /// Retains every original result/ACK and the native retirement proposal.
    pub terminal: Option<TerminalEvidence>,
    /// Retains the exact native retirement receipt when durably recorded.
    pub native_receipt: Option<Vec<u8>>,
    /// Retains native confirmation issued after the durable-receipt ACK.
    pub native_commit: Option<Vec<u8>>,
}

struct Pending {
    sequence: u64,
    original: NativeEffectCompute,
    stored: StoredOriginal,
    terminal_digest: Option<[u8; 32]>,
    receipt_digest: Option<[u8; 32]>,
    bytes: u64,
}

/// Owns the archive file lock, finite budget and one original working command.
pub struct Archive {
    file: File,
    path: PathBuf,
    scope: [u8; 32],
    preparation: [u8; 32],
    budget: ArchiveBudget,
    commands: u64,
    last_sequence: u64,
    last_receipt: [u8; 32],
    pending: Option<Pending>,
    failed: bool,
}

impl Archive {
    /// Creates and durably pins an exclusive archive before exposing any command.
    ///
    /// # Errors
    /// Rejects empty identities, invalid budgets, an existing path or failed lock,
    /// file creation or file/directory synchronization.
    pub fn create(
        path: impl AsRef<Path>,
        scope: [u8; 32],
        preparation: [u8; 32],
        budget: ArchiveBudget,
    ) -> Result<Self, ArchiveError> {
        budget.validate()?;
        if scope == [0; 32] || preparation == [0; 32] {
            return Err(ArchiveError::Conflict);
        }
        let path = path.as_ref().to_owned();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.try_lock()
            .map_err(|error| ArchiveError::Io(std::io::Error::other(error)))?;
        let mut archive = Self {
            file,
            path,
            scope,
            preparation,
            budget,
            commands: 0,
            last_sequence: 0,
            last_receipt: [0; 32],
            pending: None,
            failed: false,
        };
        let mut header = Vec::new();
        header.extend_from_slice(&scope);
        header.extend_from_slice(&preparation);
        header.extend_from_slice(&budget.maximum_prefixes.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes());
        header.extend_from_slice(&budget.lifetime_bytes.to_be_bytes());
        header.extend_from_slice(&budget.lifetime_commands.to_be_bytes());
        archive.append(0, 0, &header)?;
        let parent = archive.path.parent().ok_or(ArchiveError::Conflict)?;
        File::open(parent)?.sync_all()?;
        Ok(archive)
    }

    /// Restores original turnover state without replaying commands or adopting authority.
    ///
    /// # Errors
    /// Rejects a concurrent owner, a changed preparation/budget, a torn or corrupt
    /// tail, an invalid receipt chain or any record outside its original bounds.
    pub fn restore(
        path: impl AsRef<Path>,
        expected_scope: [u8; 32],
        expected_preparation: [u8; 32],
        expected_budget: ArchiveBudget,
    ) -> Result<Self, ArchiveError> {
        expected_budget.validate()?;
        let path = path.as_ref().to_owned();
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.try_lock()
            .map_err(|error| ArchiveError::Io(std::io::Error::other(error)))?;
        if file.metadata()?.len() > expected_budget.lifetime_bytes {
            return Err(ArchiveError::Budget);
        }
        let header = read_record(&mut file)?.ok_or(ArchiveError::Corrupt)?;
        let mut cursor = Cursor(&header.payload);
        let scope: [u8; 32] = cursor
            .take(32)?
            .try_into()
            .map_err(|_| ArchiveError::Corrupt)?;
        let preparation: [u8; 32] = cursor
            .take(32)?
            .try_into()
            .map_err(|_| ArchiveError::Corrupt)?;
        let maximum_prefixes = cursor.u32()?;
        let reserved = cursor.u32()?;
        let budget = ArchiveBudget {
            maximum_prefixes,
            lifetime_bytes: cursor.u64()?,
            lifetime_commands: cursor.u64()?,
        };
        cursor.finish()?;
        if header.kind != 0
            || header.sequence != 0
            || reserved != 0
            || scope != expected_scope
            || preparation != expected_preparation
            || budget != expected_budget
        {
            return Err(ArchiveError::Conflict);
        }
        let mut archive = Self {
            file,
            path,
            scope,
            preparation,
            budget,
            commands: 0,
            last_sequence: 0,
            last_receipt: [0; 32],
            pending: None,
            failed: false,
        };
        while let Some(record) = read_record(&mut archive.file)? {
            archive.apply_record(record)?;
        }
        Ok(archive)
    }

    /// Returns the immutable archival prefix quota without granting a native budget.
    pub fn maximum_prefixes(&self) -> u32 {
        self.budget.maximum_prefixes
    }

    /// Reports the retained storage fence without authorizing another native command.
    pub fn state(&self) -> TurnoverState {
        if self.failed {
            return TurnoverState::Failed;
        }
        if let Some(pending) = &self.pending {
            if let Some(receipt_digest) = pending.receipt_digest {
                return TurnoverState::ReceiptStored {
                    sequence: pending.sequence,
                    receipt_digest,
                };
            }
            if let Some(terminal_digest) = pending.terminal_digest {
                return TurnoverState::TerminalArchived {
                    sequence: pending.sequence,
                    terminal_digest,
                };
            }
            return TurnoverState::CommandReserved {
                sequence: pending.sequence,
            };
        }
        if self.last_sequence != 0 {
            TurnoverState::RetirementCommitted {
                sequence: self.last_sequence,
                commit_digest: self.last_receipt,
            }
        } else {
            TurnoverState::Vacant
        }
    }

    /// Reserves durable capacity and the exact original command before guest exposure.
    ///
    /// The caller must separately hold the genuine native admission/retirement
    /// fence. This storage method supplies no permission to dispatch its bytes.
    ///
    /// # Errors
    /// Rejects budget exhaustion, an unfinished command, old sequence replay,
    /// foreign scope/preparation or a changed same-original reservation.
    pub fn reserve(&mut self, original: &NativeEffectCompute) -> Result<(), ArchiveError> {
        self.check_live()?;
        original.validate()?;
        if original.command.scope.identity_digest()? != self.scope
            || original.effect_preparation != self.preparation
        {
            return Err(ArchiveError::Conflict);
        }
        let command_frame = encode_frame_for_edition(
            NativeControlEdition::PrefixEffect,
            &NativeFrame::EffectCompute(Box::new(original.clone())),
        )?;
        if command_frame.len() > 4096 {
            return Err(ArchiveError::Budget);
        }
        if let Some(pending) = &self.pending {
            if pending.original == *original && pending.stored.command_frame == command_frame {
                return Ok(());
            }
            return Err(ArchiveError::Conflict);
        }
        if original.command.sequence.get() <= self.last_sequence {
            return Err(ArchiveError::Conflict);
        }
        if self.commands >= self.budget.lifetime_commands {
            return Err(ArchiveError::Budget);
        }
        let mut payload = self.last_receipt.to_vec();
        put_blob(&mut payload, &command_frame)?;
        let sequence = original.command.sequence.get();
        let digest = self.append(1, sequence, &payload)?;
        self.apply_record(Record {
            kind: 1,
            sequence,
            payload,
            digest,
        })
    }

    /// Durably retains complete terminal history before any native retirement request.
    ///
    /// # Errors
    /// Rejects missing originals, incomplete/foreign prefixes or ACKs, changed
    /// historical bytes, nonterminal effects or failed bounded durable storage.
    pub fn archive_terminal(
        &mut self,
        evidence: &TerminalEvidence,
    ) -> Result<[u8; 32], ArchiveError> {
        self.check_live()?;
        let pending = self.pending.as_ref().ok_or(ArchiveError::Conflict)?;
        evidence.validate(&pending.original, self.budget.maximum_prefixes)?;
        if let Some(previous) = &pending.stored.terminal {
            if previous == evidence {
                return pending.terminal_digest.ok_or(ArchiveError::Conflict);
            }
            return Err(ArchiveError::Conflict);
        }
        let payload = evidence.encode()?;
        let sequence = pending.sequence;
        if pending.bytes
            + payload.len() as u64
            + RECORD_OVERHEAD
            + 2 * (4096 + RECORD_OVERHEAD + 36)
            > COMMAND_QUOTA
        {
            return Err(ArchiveError::Budget);
        }
        let digest = self.append(2, sequence, &payload)?;
        self.apply_record(Record {
            kind: 2,
            sequence,
            payload,
            digest,
        })?;
        Ok(digest)
    }

    /// Durably records the exact native retirement receipt against the original archive.
    ///
    /// The owning adapter authenticates the receipt through the native original
    /// operation before calling this method. Copying bytes here cannot establish
    /// native slot reclamation. Another command requires both source confirmation
    /// and this durable host transition.
    ///
    /// # Errors
    /// Rejects a foreign terminal digest, empty/oversized receipt, missing terminal
    /// evidence or a filesystem failure. Uncertain writes permanently fence this owner.
    pub fn record_native_receipt(
        &mut self,
        terminal_digest: [u8; 32],
        original_native_receipt: &[u8],
    ) -> Result<(), ArchiveError> {
        self.check_live()?;
        let pending = self.pending.as_ref().ok_or(ArchiveError::Conflict)?;
        if pending.terminal_digest != Some(terminal_digest)
            || original_native_receipt.is_empty()
            || original_native_receipt.len() > 4096
        {
            return Err(ArchiveError::Conflict);
        }
        if let Some(previous) = &pending.stored.native_receipt {
            return if previous == original_native_receipt {
                Ok(())
            } else {
                Err(ArchiveError::Conflict)
            };
        }
        let sequence = pending.sequence;
        let mut payload = terminal_digest.to_vec();
        put_blob(&mut payload, original_native_receipt)?;
        if pending.bytes + payload.len() as u64 + RECORD_OVERHEAD > COMMAND_QUOTA {
            return Err(ArchiveError::Budget);
        }
        let digest = self.append(3, sequence, &payload)?;
        self.apply_record(Record {
            kind: 3,
            sequence,
            payload,
            digest,
        })
    }

    /// Durably retains native commit confirmation before host working-slot turnover.
    ///
    /// Native emits this confirmation only after consuming the exact receipt ACK
    /// and committing its own retired frontier. This method stores correlation;
    /// the adapter must authenticate that native transition independently.
    ///
    /// # Errors
    /// Rejects missing/foreign receipt identity, empty or oversized confirmation,
    /// changed native bytes or insufficient finite storage.
    pub fn record_native_commit(
        &mut self,
        receipt_digest: [u8; 32],
        original_native_commit: &[u8],
    ) -> Result<(), ArchiveError> {
        self.check_live()?;
        let pending = self.pending.as_ref().ok_or(ArchiveError::Conflict)?;
        if pending.receipt_digest != Some(receipt_digest)
            || original_native_commit.is_empty()
            || original_native_commit.len() > 4096
        {
            return Err(ArchiveError::Conflict);
        }
        let sequence = pending.sequence;
        let mut payload = receipt_digest.to_vec();
        put_blob(&mut payload, original_native_commit)?;
        if pending.bytes + payload.len() as u64 + RECORD_OVERHEAD > COMMAND_QUOTA {
            return Err(ArchiveError::Budget);
        }
        let digest = self.append(4, sequence, &payload)?;
        self.apply_record(Record {
            kind: 4,
            sequence,
            payload,
            digest,
        })
    }

    /// Copies the unfinished original for exact recovery without exposing new work.
    pub fn pending_original(&self) -> Option<StoredOriginal> {
        self.pending.as_ref().map(|pending| pending.stored.clone())
    }

    fn append(
        &mut self,
        kind: u32,
        sequence: u64,
        payload: &[u8],
    ) -> Result<[u8; 32], ArchiveError> {
        self.check_live()?;
        let result = (|| {
            let length = self.file.seek(SeekFrom::End(0))?;
            if length
                .checked_add(payload.len() as u64 + RECORD_OVERHEAD)
                .is_none_or(|total| total > self.budget.lifetime_bytes)
            {
                return Err(ArchiveError::Budget);
            }
            let digest = write_record(&mut self.file, kind, sequence, payload)?;
            self.file.sync_all()?;
            Ok(digest)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn check_live(&self) -> Result<(), ArchiveError> {
        if self.failed {
            Err(ArchiveError::Failed)
        } else {
            Ok(())
        }
    }

    fn apply_record(&mut self, record: Record) -> Result<(), ArchiveError> {
        let bytes = RECORD_OVERHEAD + record.payload.len() as u64;
        match record.kind {
            1 => {
                if self.pending.is_some()
                    || record.sequence <= self.last_sequence
                    || self.commands >= self.budget.lifetime_commands
                {
                    return Err(ArchiveError::Corrupt);
                }
                let mut cursor = Cursor(&record.payload);
                if cursor.take(32)? != self.last_receipt {
                    return Err(ArchiveError::Corrupt);
                }
                let command_frame = cursor.blob(4096)?.to_vec();
                cursor.finish()?;
                let NativeFrame::EffectCompute(original) =
                    decode_frame_for_edition(NativeControlEdition::PrefixEffect, &command_frame)?
                else {
                    return Err(ArchiveError::Corrupt);
                };
                if original.command.sequence.get() != record.sequence
                    || original.command.scope.identity_digest()? != self.scope
                    || original.effect_preparation != self.preparation
                {
                    return Err(ArchiveError::Corrupt);
                }
                self.commands += 1;
                self.pending = Some(Pending {
                    sequence: record.sequence,
                    original: *original,
                    stored: StoredOriginal {
                        command_frame,
                        terminal: None,
                        native_receipt: None,
                        native_commit: None,
                    },
                    terminal_digest: None,
                    receipt_digest: None,
                    bytes,
                });
            }
            2 => {
                let pending = self.pending.as_mut().ok_or(ArchiveError::Corrupt)?;
                if record.sequence != pending.sequence || pending.terminal_digest.is_some() {
                    return Err(ArchiveError::Corrupt);
                }
                let terminal =
                    TerminalEvidence::decode(&record.payload, self.budget.maximum_prefixes)?;
                terminal.validate(&pending.original, self.budget.maximum_prefixes)?;
                pending.bytes = pending
                    .bytes
                    .checked_add(bytes)
                    .ok_or(ArchiveError::Budget)?;
                if pending.bytes > COMMAND_QUOTA {
                    return Err(ArchiveError::Budget);
                }
                pending.stored.terminal = Some(terminal);
                pending.terminal_digest = Some(record.digest);
            }
            3 => {
                let pending = self.pending.as_mut().ok_or(ArchiveError::Corrupt)?;
                let mut cursor = Cursor(&record.payload);
                let terminal_digest = cursor.take(32)?;
                let receipt = cursor.blob(4096)?;
                cursor.finish()?;
                if record.sequence != pending.sequence
                    || receipt.is_empty()
                    || pending
                        .terminal_digest
                        .as_ref()
                        .map(|digest| digest.as_slice())
                        != Some(terminal_digest)
                    || pending.bytes + bytes > COMMAND_QUOTA
                    || pending.receipt_digest.is_some()
                {
                    return Err(ArchiveError::Corrupt);
                }
                pending.bytes += bytes;
                pending.stored.native_receipt = Some(receipt.to_vec());
                pending.receipt_digest = Some(record.digest);
            }
            4 => {
                let pending = self.pending.as_ref().ok_or(ArchiveError::Corrupt)?;
                let mut cursor = Cursor(&record.payload);
                let receipt_digest = cursor.take(32)?;
                let commit = cursor.blob(4096)?;
                cursor.finish()?;
                if record.sequence != pending.sequence
                    || commit.is_empty()
                    || pending
                        .receipt_digest
                        .as_ref()
                        .map(|digest| digest.as_slice())
                        != Some(receipt_digest)
                    || pending.bytes + bytes > COMMAND_QUOTA
                {
                    return Err(ArchiveError::Corrupt);
                }
                self.last_sequence = record.sequence;
                self.last_receipt = record.digest;
                self.pending = None;
            }
            _ => return Err(ArchiveError::Corrupt),
        }
        Ok(())
    }

    /// Retrieves complete stored history while keeping old sequences fenced.
    ///
    /// This scan uses one additional bounded original image. Its copied records
    /// may serve historical host replies; they never reenter native execution.
    ///
    /// # Errors
    /// Rejects unknown sequences, changed durable bytes, uncertain tails or I/O failure.
    pub fn historical(&mut self, sequence: u64) -> Result<StoredOriginal, ArchiveError> {
        self.check_live()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut found = None;
        while let Some(record) = read_record(&mut self.file)? {
            if record.sequence != sequence {
                continue;
            }
            match record.kind {
                1 => {
                    let mut cursor = Cursor(&record.payload);
                    cursor.take(32)?;
                    let command_frame = cursor.blob(4096)?.to_vec();
                    cursor.finish()?;
                    found = Some(StoredOriginal {
                        command_frame,
                        terminal: None,
                        native_receipt: None,
                        native_commit: None,
                    });
                }
                2 => {
                    let stored = found.as_mut().ok_or(ArchiveError::Corrupt)?;
                    stored.terminal = Some(TerminalEvidence::decode(
                        &record.payload,
                        self.budget.maximum_prefixes,
                    )?);
                }
                3 => {
                    let stored = found.as_mut().ok_or(ArchiveError::Corrupt)?;
                    let mut cursor = Cursor(&record.payload);
                    cursor.take(32)?;
                    stored.native_receipt = Some(cursor.blob(4096)?.to_vec());
                    cursor.finish()?;
                }
                4 => {
                    let stored = found.as_mut().ok_or(ArchiveError::Corrupt)?;
                    let mut cursor = Cursor(&record.payload);
                    cursor.take(32)?;
                    stored.native_commit = Some(cursor.blob(4096)?.to_vec());
                    cursor.finish()?;
                }
                _ => return Err(ArchiveError::Corrupt),
            }
        }
        found.ok_or(ArchiveError::Conflict)
    }
}
