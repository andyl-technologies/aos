//! Imports canonical Policy location DATA and checks the existing authority budget.

pub(super) use aos_sandbox_policy::journal_keys::{
    MAXIMUM_POLICY_BINDINGS, POLICY_AUTHORITY_JOURNAL, POLICY_BINDING_KEY_PREFIX,
    POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT, policy_state_journal_limits,
};

pub(super) fn policy_authority_journal_limits() -> crate::journal::JournalLimits {
    aos_sandbox_broker::receiving::root_authority_journal_limits_data_v1()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::journal::{JournalRecord, JournalTransaction};

    use super::*;
    use crate::journal::{Journal, JournalError, RecordNamespace};

    #[test]
    fn root_authority_budget_reserves_the_binding_hold_record() {
        let limits = policy_authority_journal_limits();
        assert_eq!(
            limits.maximum_materialized_records,
            3 * MAXIMUM_POLICY_BINDINGS
                + 19
                + super::super::cache_root_settlement::SETTLEMENT_ARCHIVE_WINDOW as usize
        );
        assert_eq!(limits.maximum_materialized_records, 13_331);
        assert!(
            limits.maximum_record_bytes >= super::super::binding_v2::CLOSED_POLICY_BINDING_BYTES_V2
        );
    }

    #[test]
    fn root_authority_preflights_and_commits_the_full_record_budget() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private test directory");
        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let limits = policy_authority_journal_limits();
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory.path(), "authority.journal", limits, uid)
                .expect("protected authority journal");
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("protected claim");

        let mut filled = 0;
        let mut transaction_number = 1_u64;
        while filled < limits.maximum_materialized_records - 2 {
            let count = (limits.maximum_materialized_records - 2 - filled).min(256);
            let records = (filled..filled + count)
                .map(|index| {
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        format!("budget-{index:05}").into_bytes(),
                        vec![1],
                    )
                })
                .collect();
            let mut id = [0; 16];
            id[8..].copy_from_slice(&transaction_number.to_be_bytes());
            authority
                .commit(&JournalTransaction::new(id, records).expect("budget transaction"))
                .expect("fill reserved budget");
            filled += count;
            transaction_number += 1;
        }

        let challenge = JournalTransaction::new(
            [0xa0; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"terminal-challenge".to_vec(),
                vec![1],
            )],
        )
        .expect("terminal challenge transaction");
        let terminal = JournalTransaction::new(
            [0xa1; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"terminal-receipt".to_vec(),
                vec![1],
            )],
        )
        .expect("terminal receipt transaction");
        let planned = [challenge.clone(), terminal.clone()];
        let preflight = authority
            .preflight_transactions(&planned)
            .expect("room for both terminal records");
        authority
            .validate_preflight_for_effect(&preflight, &planned)
            .expect("same protected cut");
        authority
            .commit(&challenge)
            .expect("terminal challenge budget");
        authority.commit(&terminal).expect("full record budget");
        assert_eq!(filled + planned.len(), limits.maximum_materialized_records);

        let overflow = JournalTransaction::new(
            [0xa2; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"one-record-too-many".to_vec(),
                vec![1],
            )],
        )
        .expect("overflow transaction");
        assert!(matches!(
            authority.preflight_transactions(&[overflow.clone()]),
            Err(JournalError::LimitExceeded("materialized record count"))
        ));
        assert!(matches!(
            authority.commit(&overflow),
            Err(JournalError::LimitExceeded("materialized record count"))
        ));
    }

}
