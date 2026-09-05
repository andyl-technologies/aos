//! Exercises exact-owner journal creation, compaction, replay, and denial.

use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use aos_sandbox::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};

const OWNER: u32 = 1000;
const NAME: &str = "state.journal";

pub(super) fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        return Err("usage: service-journal-probe write|deny DIRECTORY".into());
    }
    if arguments[1] != "write" && arguments[1] != "deny" {
        return Err("unknown fixture operation".into());
    }
    let directory = Path::new(&arguments[2]);
    let opened =
        Journal::open_protected_at_for_uid(directory, NAME, JournalLimits::default(), OWNER);
    if arguments[1] == "deny" {
        if !matches!(opened, Err(JournalError::ProtectedBoundary)) {
            return Err("unsafe journal opening did not fail at the protected boundary".into());
        }
        println!("service-journal-denial:PASS");
        return Ok(());
    }
    let (mut journal, _) = opened?;
    let record = JournalRecord::put(
        RecordNamespace::DesiredState,
        b"key".to_vec(),
        b"value".to_vec(),
    );
    journal.commit(&JournalTransaction::new([1; 16], vec![record])?)?;
    if !matches!(
        Journal::open_protected_at_for_uid(directory, NAME, JournalLimits::default(), OWNER),
        Err(JournalError::AlreadyLocked)
    ) {
        return Err("second journal opening did not fail at the live lock".into());
    }
    journal.compact()?;
    drop(journal);

    let (reopened, _) =
        Journal::open_protected_at_for_uid(directory, NAME, JournalLimits::default(), OWNER)?;
    if reopened.get(RecordNamespace::DesiredState, b"key") != Some(b"value".as_slice()) {
        return Err("compacted service journal failed replay".into());
    }
    for entry in std::fs::read_dir(directory)? {
        let metadata = entry?.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != OWNER
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("service journal file ownership or protection differs".into());
        }
    }
    println!("service-journal-write-replay-compact:PASS");
    Ok(())
}
