//! VM-only qualification of the protected Mount journal's cold replay boundary.
//!
//! The test runs each operation in a new root process. Its namespace-40 record
//! is a journal-layer marker, not a Mount source-acquisition protocol record.

use std::error::Error;
use std::path::Path;

use aos_sandbox::journal::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};

const ROOT: &str = "/var/lib/aos/sandbox-mount";
const JOURNAL: &str = "mount.journal";
const KEY: &[u8] = b"vm-journal-boundary";
const VALUE: &[u8] = b"committed-before-restart";

fn main() {
    if let Err(error) = run() {
        eprintln!("Mount journal VM qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    match arguments.as_slice() {
        [_, operation] if operation == "commit" => commit(),
        [_, operation] if operation == "replay" => replay(false),
        [_, operation] if operation == "replay-partial-tail" => replay(true),
        [_, operation] if operation == "deny-open" => deny_open(),
        _ => Err(
            "usage: aos-sandbox-mount-journal-vm-probe commit|replay|replay-partial-tail|deny-open"
                .into(),
        ),
    }
}

fn open() -> Result<(Journal, aos_sandbox::journal::RecoveryReport), Box<dyn Error>> {
    Ok(Journal::open_protected_at(
        Path::new(ROOT),
        JOURNAL,
        JournalLimits::default(),
    )?)
}

fn commit() -> Result<(), Box<dyn Error>> {
    let (mut journal, report) = open()?;
    if report.committed_transactions != 0 || !journal.is_materialized_empty() {
        return Err("Mount journal was not empty before qualification".into());
    }

    let transaction = JournalTransaction::new(
        [1; 16],
        vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition,
            KEY.to_vec(),
            VALUE.to_vec(),
        )],
    )?;
    journal.commit(&transaction)?;
    if journal.get(RecordNamespace::MountSourceAcquisition, KEY) != Some(VALUE) {
        return Err("namespace-40 commit was not visible to its owner".into());
    }

    println!("mount-uid0-namespace40-commit:PASS");
    Ok(())
}

fn replay(expect_truncation: bool) -> Result<(), Box<dyn Error>> {
    let (journal, report) = open()?;
    if report.committed_transactions != 1
        || report.committed_records != 1
        || (report.truncated_bytes != 0) != expect_truncation
        || journal.get(RecordNamespace::MountSourceAcquisition, KEY) != Some(VALUE)
    {
        return Err("cold replay changed the committed namespace-40 prefix".into());
    }

    println!("mount-uid0-namespace40-cold-replay:PASS");
    Ok(())
}

fn deny_open() -> Result<(), Box<dyn Error>> {
    if open().is_ok() {
        return Err("unsafe or locked Mount journal was opened".into());
    }

    println!("mount-uid0-protected-open-denied:PASS");
    Ok(())
}
