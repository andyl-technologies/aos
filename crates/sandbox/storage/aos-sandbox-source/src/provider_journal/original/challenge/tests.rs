//! UNRUN physical-parser DATA vectors; no fixed owner/Session authority fixtures.

use super::*;

fn checkpoint(sequence: u64, state: u8) -> SourceOriginalChallengeCheckpointV5 {
    SourceOriginalChallengeCheckpointV5 {
        key: [b"AOSZHK01".as_slice(), &[9; 32]].concat(),
        value: vec![state; 296],
        transaction: [state; 16],
        begin_sequence: sequence - 2,
        commit_sequence: sequence,
        begin_offset: sequence * 100,
        durable_end: sequence * 100 + 80,
    }
}

#[test]
fn prefix_commitment_excludes_future_rows_and_binds_actual_inode_and_bytes() {
    let issued = checkpoint(3, 1);
    let spent = checkpoint(6, 2);
    let first = challenge_prefix_digest((11, 12), 3, std::slice::from_ref(&issued));

    assert_eq!(first, challenge_prefix_digest((11, 12), 3, &[issued.clone(), spent.clone()]));
    assert_ne!(first, challenge_prefix_digest((11, 13), 3, &[issued.clone()]));
    assert_ne!(first, challenge_prefix_digest((11, 12), 6, &[issued.clone(), spent]));

    let mut changed = issued;
    changed.value[40] ^= 1;
    assert_ne!(first, challenge_prefix_digest((11, 12), 3, &[changed]));
}

#[test]
fn actual_generic_replay_preserves_both_checkpoints_without_minting_fixed_scope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("history.journal");
    let (mut journal, _) = Journal::open(&path, super::super::super::JournalLimits::default()).unwrap();
    let key = checkpoint(3, 1).key;
    for state in [1, 2] {
        let transaction = JournalTransaction::new([state; 16], vec![
            super::super::super::JournalRecord::put(RecordNamespace::SourceProviderAuthority,
                key.clone(), vec![state; 296]),
        ]).unwrap();
        journal.commit(&transaction).unwrap();
    }
    drop(journal);

    let (mut journal, _) = Journal::open(&path, super::super::super::JournalLimits::default()).unwrap();
    let history = &journal.source_challenge_history;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].frame_sequences(), (1, 3));
    assert_eq!(history[1].frame_sequences(), (4, 6));
    assert_eq!(history[0].value(), &[1; 296]);
    assert_eq!(history[1].value(), &[2; 296]);
    assert!(journal.source_original_challenge_history_v5().is_err());
}

#[test]
fn actual_checksum_damage_cannot_be_recovered_as_challenge_history() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("damaged.journal");
    let (mut journal, _) = Journal::open(&path, super::super::super::JournalLimits::default()).unwrap();
    journal.commit(&JournalTransaction::new([1; 16], vec![
        super::super::super::JournalRecord::put(RecordNamespace::SourceProviderAuthority,
            checkpoint(3, 1).key, vec![1; 296]),
    ]).unwrap()).unwrap();
    drop(journal);

    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert!(Journal::open(&path, super::super::super::JournalLimits::default()).is_err());
}
