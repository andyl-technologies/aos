//! Append-only log of committed lifecycle exits beside `run-state.json`.
//!
//! Completed exits are history: after commit they are only counted and
//! validated, never consumed. Keeping them out of `run-state.json` bounds that
//! file by node count while the exit history grows on disk. The log holds one
//! canonical compact JSON line per exit, in commit order:
//!
//! ```text
//! {"transaction":1,"node":"node-a","process":{"process_id":7,"start_time_ticks":9,"executable":"/aos/vm"},"generation":1,"transition":"Crash","action_sha256":"<64 hex>","evidence_sha256":"<64 hex>","expected_exit_code":70,"observed_exit_code":70}
//! ```
//!
//! Run state records the committed prefix as `exit_log`: its record count,
//! byte length, and a SHA-256 chain where `chain[0]` is 32 zero bytes and
//! `chain[i + 1] = SHA-256(domain || chain[i] || line[i])`, each line including
//! its newline.
//!
//! Commit protocol: the writer truncates the file to the recorded prefix,
//! appends the new lines, and syncs the file (and its directory when the file
//! is new) before renaming the run state that records the longer prefix. A
//! crash between the two steps leaves an unreferenced tail, which the next
//! append or a recovery takeover truncates. Readers verify only the recorded
//! prefix, so a live owner's in-progress append never invalidates a reader.

use super::*;
use sha2::{Digest as _, Sha256};
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom};

pub(in crate::vm_lifecycle) const PRODUCTION_LIFECYCLE_EXIT_LOG_FILE: &str =
    "lifecycle-exits.jsonl";
pub(in crate::vm_lifecycle) const PRODUCTION_LIFECYCLE_EXIT_LOG_VERSION: u32 = 1;

const EXIT_LOG_CHAIN_DOMAIN: &[u8] = b"crucible.production-lifecycle-exit-log.v1\0";
const EMPTY_EXIT_LOG_CHAIN: [u8; 32] = [0; 32];

/// Longest accepted exit line. A record carries one executable path, one node
/// name, and fixed-width fields, so anything longer is corrupt.
const MAX_EXIT_LINE_BYTES: u64 = 65_536;

impl ProductionLifecycleExitLog {
    /// Returns the reference to an empty log.
    pub(in crate::vm_lifecycle) fn empty() -> Self {
        Self {
            version: PRODUCTION_LIFECYCLE_EXIT_LOG_VERSION,
            records: 0,
            bytes: 0,
            chain_sha256: ContentHash {
                bytes: EMPTY_EXIT_LOG_CHAIN,
            }
            .to_hex(),
        }
    }

    /// Validates the reference independently of the log contents.
    pub(super) fn validate(&self) -> Result<(), DurableRunStateError> {
        let empty = self.records == 0;
        if self.version != PRODUCTION_LIFECYCLE_EXIT_LOG_VERSION
            || decode_chain(&self.chain_sha256).is_none()
            || empty != (self.bytes == 0)
            || (empty && decode_chain(&self.chain_sha256) != Some(EMPTY_EXIT_LOG_CHAIN))
        {
            return Err(String::from("lifecycle exit-log reference is not canonical").into());
        }
        Ok(())
    }
}

/// Canonical lines for pending exits and the log reference that includes them.
pub(super) struct StagedLifecycleExits {
    pub(super) lines: Vec<u8>,
    pub(super) next: ProductionLifecycleExitLog,
}

/// Encodes `exits` after `committed` without touching the file.
///
/// Staging is pure so the caller can admit and measure the run state that
/// records the longer prefix before any durable effect.
pub(super) fn stage_lifecycle_exits(
    committed: &ProductionLifecycleExitLog,
    exits: &[ProductionLifecycleCompletedExit],
) -> Result<StagedLifecycleExits, DurableRunStateError> {
    let mut chain = decode_chain(&committed.chain_sha256)
        .ok_or_else(|| String::from("committed lifecycle exit-log chain is not canonical"))?;

    let mut counter = CountingJournalWriter::default();
    for exit in exits {
        if !completed_exit_strings_are_canonical(exit) {
            return Err(String::from("completed lifecycle exit strings must be UTF-8 JSON strings without escape sequences").into());
        }
        serde_json::to_writer(&mut counter, exit)
            .map_err(|error| format!("measure completed lifecycle exit: {error}"))?;
        counter.length = counter
            .length
            .checked_add(1)
            .ok_or_else(|| String::from("completed lifecycle exit length overflow"))?;
    }
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(counter.length)
        .map_err(|_| format!("reserve {} completed lifecycle exit bytes", counter.length))?;

    for exit in exits {
        let start = lines.len();
        serde_json::to_writer(
            FixedJournalWriter {
                destination: &mut lines,
            },
            exit,
        )
        .map_err(|error| format!("encode completed lifecycle exit: {error}"))?;
        FixedJournalWriter {
            destination: &mut lines,
        }
        .write_all(b"\n")
        .map_err(|error| format!("encode completed lifecycle exit: {error}"))?;
        chain = extend_chain(&chain, &lines[start..]);
    }

    let appended_records = u64::try_from(exits.len()).unwrap_or(u64::MAX);
    let appended_bytes = u64::try_from(lines.len()).unwrap_or(u64::MAX);
    let next = ProductionLifecycleExitLog {
        version: PRODUCTION_LIFECYCLE_EXIT_LOG_VERSION,
        records: committed
            .records
            .checked_add(appended_records)
            .ok_or_else(|| String::from("lifecycle exit-log record count overflow"))?,
        bytes: committed
            .bytes
            .checked_add(appended_bytes)
            .ok_or_else(|| String::from("lifecycle exit-log byte length overflow"))?,
        chain_sha256: ContentHash { bytes: chain }.to_hex(),
    };
    Ok(StagedLifecycleExits { lines, next })
}

/// Durably appends staged lines after exactly the committed prefix.
///
/// Truncating first discards a tail left by a crash or by a failed earlier
/// attempt, so a retried append produces the same bytes as a first attempt.
pub(super) fn append_lifecycle_exits(
    path: &Path,
    committed: &ProductionLifecycleExitLog,
    staged: &StagedLifecycleExits,
) -> Result<(), DurableRunStateError> {
    let created = !path
        .try_exists()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .len();
    if length < committed.bytes {
        return Err(format!(
            "{} is shorter than its committed {}-byte prefix",
            path.display(),
            committed.bytes
        )
        .into());
    }

    file.set_len(committed.bytes)
        .and_then(|()| file.seek(SeekFrom::Start(committed.bytes)))
        .and_then(|_| file.write_all(&staged.lines))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("append {}: {error}", path.display()))?;

    // A new directory entry must be durable before run state references it.
    if created {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("flush {}: {error}", parent.display()))?;
    }
    Ok(())
}

/// Truncates a tail beyond the committed prefix before taking over a run.
///
/// # Errors
///
/// Returns [`DurableRunStateError`] when the log is shorter than its committed
/// prefix or cannot be truncated durably.
pub(in crate::vm_lifecycle) fn truncate_lifecycle_exit_log_tail(
    directory: &Path,
    committed: &ProductionLifecycleExitLog,
) -> Result<(), DurableRunStateError> {
    let path = directory.join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE);
    let length = match path.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && committed.bytes == 0 => {
            return Ok(());
        }
        Err(error) => return Err(format!("inspect {}: {error}", path.display()).into()),
    };
    if length < committed.bytes {
        return Err(format!(
            "{} is shorter than its committed {}-byte prefix",
            path.display(),
            committed.bytes
        )
        .into());
    }
    if length > committed.bytes {
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| {
                file.set_len(committed.bytes)?;
                file.sync_all()
            })
            .map_err(|error| format!("truncate {}: {error}", path.display()))?;
    }
    Ok(())
}

/// Streams the committed log prefix once and verifies every record, the
/// ordering and uniqueness rules, the record count, and the chain.
///
/// Memory stays bounded by one line and one transaction's node names.
pub(super) fn verify_lifecycle_exit_log(
    directory: &Path,
    journal: &ProductionLifecycleJournal,
    limits: FaultResourceLimits,
) -> Result<(), DurableRunStateError> {
    let committed = &journal.exit_log;
    let path = directory.join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && committed.bytes == 0 => {
            return Ok(());
        }
        Err(error) => return Err(format!("open {}: {error}", path.display()).into()),
    };
    let length = file
        .metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .len();
    if length < committed.bytes {
        return Err(format!(
            "{} is shorter than its committed {}-byte prefix",
            path.display(),
            committed.bytes
        )
        .into());
    }

    let mut reader = BufReader::new(file.take(committed.bytes));
    let mut line = Vec::new();
    let mut canonical = Vec::new();
    let mut chain = EMPTY_EXIT_LOG_CHAIN;
    let mut records = 0_u64;
    let mut transaction = 0_u64;
    let mut transaction_nodes = std::collections::BTreeSet::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_EXIT_LINE_BYTES)
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        let Some((b'\n', body)) = line.split_last() else {
            return Err(format!(
                "{} record {records} is unterminated or exceeds {MAX_EXIT_LINE_BYTES} bytes",
                path.display()
            )
            .into());
        };
        let exit: ProductionLifecycleCompletedExit = serde_json::from_slice(body)
            .map_err(|error| format!("decode {} record {records}: {error}", path.display()))?;

        canonical.clear();
        serde_json::to_writer(&mut canonical, &exit)
            .map_err(|error| format!("encode {} record {records}: {error}", path.display()))?;
        if canonical != body
            || !completed_exit_strings_are_canonical(&exit)
            || !recovery::valid_completed_exit(&exit, journal.transaction)
            || exit.transaction < transaction
        {
            return Err(format!(
                "{} record {records} for {} is not a canonical completed exit",
                path.display(),
                exit.node
            )
            .into());
        }

        // Records are appended in transaction order, so a duplicate node can
        // only appear within the current transaction's run of records.
        if exit.transaction > transaction {
            transaction = exit.transaction;
            transaction_nodes.clear();
        }
        if u64::try_from(transaction_nodes.len()).unwrap_or(u64::MAX) >= limits.nodes
            || !transaction_nodes.insert(exit.node)
        {
            return Err(format!(
                "{} transaction {transaction} repeats a node or exceeds the node limit",
                path.display()
            )
            .into());
        }

        chain = extend_chain(&chain, &line);
        records = records
            .checked_add(1)
            .ok_or_else(|| String::from("lifecycle exit-log record count overflow"))?;
    }

    if records != committed.records || decode_chain(&committed.chain_sha256) != Some(chain) {
        return Err(format!(
            "{} does not match its committed record count or chain",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn completed_exit_strings_are_canonical(exit: &ProductionLifecycleCompletedExit) -> bool {
    borrowed_json_string_is_canonical(&exit.node)
        && borrowed_process_identity_is_canonical(&exit.process)
        && borrowed_json_string_is_canonical(&exit.transition)
        && borrowed_json_string_is_canonical(&exit.action_sha256)
        && borrowed_json_string_is_canonical(&exit.evidence_sha256)
}

fn extend_chain(chain: &[u8; 32], line: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EXIT_LOG_CHAIN_DOMAIN);
    hasher.update(chain);
    hasher.update(line);
    hasher.finalize().into()
}

fn decode_chain(hex: &str) -> Option<[u8; 32]> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != 32 {
        return None;
    }
    let mut chain = [0_u8; 32];
    for (output, pair) in chain.iter_mut().zip(pairs) {
        *output = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(chain)
}

#[cfg(test)]
#[path = "exit_log_tests.rs"]
mod tests;
