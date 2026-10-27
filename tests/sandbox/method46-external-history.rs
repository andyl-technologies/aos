//! Prepares native initial-floor history DATA outside the installed system.
//!
//! The ordinary Journal engine commits and deletes a broker-session record.
//! Its resulting empty map has nonempty, replayable history. The debug-only
//! fixture opener checks the final private directory but grants no installed
//! Source authority. Installed producers must independently reopen the supplied
//! bytes under their fixed trusted ancestry, ownership and MAC policy.
//!
//! ```text
//! aos-method46-external-history FRESH_DIRECTORY
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use aos_sandbox_controller_domain::journal::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("external METHOD46 history preparation refused: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 1 {
        return Err("expected a fresh output directory".into());
    }
    prepare(Path::new(&arguments[0]))
}

fn prepare(directory: &Path) -> Result<()> {
    // Exclusive directory creation prevents replacement of a prior history.
    DirBuilder::new().mode(0o700).create(directory)?;
    let uid = fs::metadata(directory)?.uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory,
        "session.journal",
        JournalLimits::default(),
        uid,
    )?;

    {
        let namespace = RecordNamespace::BrokerSessionTraffic;
        let mut writer = journal.claim_protected_authority(namespace)?;
        writer.commit(&JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                namespace,
                b"external-initial-history".to_vec(),
                b"deleted-before-installation".to_vec(),
            )],
        )?)?;
        writer.commit(&JournalTransaction::new(
            [2; 16],
            vec![JournalRecord::delete(
                namespace,
                b"external-initial-history".to_vec(),
            )],
        )?)?;
    }
    let next_sequence = journal.snapshot_sequence();
    if next_sequence <= 1 || journal.all_records().next().is_some() {
        return Err("expected committed deletion and nonempty native history".into());
    }
    drop(journal);

    // Reopen existing bytes without creation or repair before exporting DATA.
    let (mut reopened, _) = Journal::open_existing_protected_at_uid(
        directory,
        "session.journal",
        JournalLimits::default(),
        uid,
    )?;
    if reopened.snapshot_sequence() != next_sequence || reopened.all_records().next().is_some() {
        return Err("native replay changed the prepared cut".into());
    }
    reopened.claim_protected_authority(RecordNamespace::BrokerSessionTraffic)?;
    drop(reopened);

    // This independently calculated empty-map head is comparison DATA for the
    // operator. It cannot substitute for the installed Source's held history.
    let mut head = Sha256::new();
    head.update(b"aos.sandbox.broker-session.tpm-floor.head.v1\0");
    head.update([47]);
    head.update(next_sequence.to_be_bytes());
    head.update(0u64.to_be_bytes());
    let head: [u8; 32] = head.finalize().into();
    let metadata = serde_json::json!({
        "namespace": 47,
        "next_sequence": next_sequence,
        "head": head,
        "live_records": 0,
    });
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("expected-cut.json"))?;
    output.write_all(&serde_json::to_vec_pretty(&metadata)?)?;
    output.sync_all()?;
    File::open(directory)?.sync_all()?;
    File::open(
        directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
