//! Owns Network's private semantic journal over the shared canonical mechanics.
//!
//! The four catalogs and worker replay ledger retain their own MAC/transition
//! models. This adapter owns only their actual native writer, resident index,
//! fixed captured append custody and original failures. It cannot construct a
//! Controller/Root/Source owner, Session, receiving loan or effect grant.

mod append;
mod error;
mod opening;
mod receiving;
mod replay;
mod schema;

pub(crate) use aos_sandbox_broker::canonical_journal::{CommitResult, RecoveryReport};
pub(crate) use aos_sandbox_core::RecordNamespace;
pub(crate) use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction,
};
pub use append::JournalNativePostFailureOriginalV1;
pub use error::{NetworkJournalAppendReceivingDemandErrorV1, NetworkJournalErrorV1};
pub(crate) use error::{
    NetworkJournalAppendReceivingDemandErrorV1 as JournalAppendReceivingDemandErrorV1,
    NetworkJournalErrorV1 as JournalError,
};
pub(crate) use opening::*;
pub(crate) use receiving::{
    ProtectedJournalPreopenReplayExtentV1, protected_journal_preopen_replay_extent_for_prefix_v1,
};

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::captured::CapturedAppendDataOwnerV1;
use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1,
};
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_journal::protected_storage::ProtectedFailure;

use schema::Schema;

// All production entry points use the five canonical Network basenames. None
// can select the fixed deployment main/sidecar names denied by Domain's old
// OriginalCompactionSelection::capture. This preserves its actual Other DATA;
// this adapter exposes no compaction effect entry point.
#[derive(Clone, Copy)]
enum NetworkCompactionSelectionV1 {
    Other,
}

pub(crate) struct Journal {
    held: CanonicalOrdinaryHeldJournalV1<NetworkCompactionSelectionV1>,
    captured: Option<CapturedAppendDataOwnerV1<JournalError>>,
    interval: Option<std::sync::Arc<append::JournalNativeIntervalOriginalV1>>,
    identity: Option<CanonicalJournalInstanceDataV1>,
    schema: Schema,
}

impl Journal {
    fn from_held(
        held: CanonicalOrdinaryHeldJournalV1<NetworkCompactionSelectionV1>,
        schema: Schema,
        captured: Option<(&'static str, &'static str, u32)>,
    ) -> Self {
        let identity = held.instance_data_v1().cloned();
        Self {
            held,
            captured: captured.map(|(directory, name, uid)| {
                CapturedAppendDataOwnerV1::new(directory, name, uid)
            }),
            interval: None,
            identity,
            schema,
        }
    }

    fn read_view(&self) -> CanonicalWriterReadViewV1<'_, NetworkCompactionSelectionV1> {
        self.held.read_view_v1()
    }

    pub(crate) fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.read_view().historical_view().get(namespace, key)
    }

    pub(crate) fn records(
        &self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.read_view()
            .state()
            .iter()
            .filter_map(move |((actual, key), value)| {
                (*actual == namespace).then_some((key.as_slice(), value.as_slice()))
            })
    }

    pub(crate) fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> {
        self.read_view()
            .state()
            .iter()
            .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))
    }

    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.held.next_sequence_data_v1()
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.read_view().is_poisoned()
            || self.interval.is_some()
            || self
                .captured
                .as_ref()
                .is_some_and(CapturedAppendDataOwnerV1::is_closed)
        {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    pub(crate) fn retained_native_append_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.interval
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| {
                self.captured
                    .as_ref()
                    .and_then(CapturedAppendDataOwnerV1::failure)
            })
    }

    pub(crate) fn validate_held_owned_at_for_uid_retaining(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        original: &mut WriterCurrentnessOriginalsV1<JournalError>,
    ) -> Result<(), JournalError> {
        original.begin(false)?;
        let result = (|| {
            self.ensure_healthy()?;
            let view = self.read_view();
            if view.protected_name() != Some(name) || view.protected_uid() != Some(uid) {
                return Err(JournalError::BOUNDARY);
            }
            view.observe_directory_binding_into(directory, uid, original)?;
            self.ensure_healthy()?;
            view.observe_names_into(original)
        })();
        original.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker::canonical_journal::coordinator::{
        CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
    };

    fn transaction(
        id: u8,
        namespace: RecordNamespace,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> JournalTransaction {
        let record = match value {
            Some(value) => JournalRecord::put(namespace, key, value),
            None => JournalRecord::delete(namespace, key),
        };
        JournalTransaction::new([id; 16], vec![record]).unwrap()
    }

    // These hostile canonical rows deliberately bypass only Network's schema.
    // Cold reopen must still reach the same per-COMMIT semantic veto.
    fn append_native(journal: &mut Journal, transaction: &JournalTransaction) {
        let mut stage = journal.held.prepare_append_once(transaction).unwrap();
        assert!(stage.failure().is_none());
        journal.held.append_coordinates_once(&mut stage).unwrap();
        journal.held.expected_append_length_once(&mut stage).unwrap();
        journal.held.append_prepared_once(&mut stage).unwrap();
        while journal.held.apply_next_record_once(&mut stage).unwrap() {}
        journal.held.publish_append_once(&mut stage).unwrap();
        journal.held.finish_append_after_posts_once(&mut stage).unwrap();
    }

    #[test]
    fn reserved_raw_handle_prefixes_refuse_before_live_native_entry_and_on_cold_replay() {
        for prefix in [
            b"\0aos-source-first-successor-v2\0".as_slice(),
            b"\0aos-source-tree-genesis-".as_slice(),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("network-lifecycle-state.journal");
            let limits = JournalLimits::default();
            let (mut journal, _) =
                Journal::open_test_with_schema(&path, limits, Schema::Lifecycle).unwrap();
            let mut handle = [9; 32];
            handle[..prefix.len()].copy_from_slice(prefix);
            let transaction = transaction(
                1,
                RecordNamespace::NetworkResourceInventory,
                handle.to_vec(),
                Some(vec![4]),
            );

            let refused = journal.commit(&transaction);

            assert!(refused.is_err());
            assert_eq!(journal.snapshot_sequence(), 1);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            assert!(journal.interval.is_none());
            assert!(journal.ensure_healthy().is_ok());

            // Write a hostile but canonically framed COMMIT through the sole
            // native encoder. Cold replay must reach the same semantic veto.
            append_native(&mut journal, &transaction);
            let durable = std::fs::metadata(&path).unwrap().len();
            drop(journal);

            assert!(Journal::open_test_with_schema(&path, limits, Schema::Lifecycle).is_err());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), durable);
        }
    }

    #[test]
    fn transient_foreign_rows_cannot_evade_the_per_commit_closed_schema() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-lifecycle-state.journal");
        let limits = JournalLimits::default();
        let (mut journal, _) = Journal::open(&path, limits).unwrap();
        let key = vec![8; 17];
        append_native(
            &mut journal,
            &transaction(
                1,
                RecordNamespace::Operation,
                key.clone(),
                Some(vec![3]),
            ),
        );
        append_native(&mut journal, &transaction(2, RecordNamespace::Operation, key, None));
        assert!(journal.read_view().state().is_empty());
        let durable = std::fs::metadata(&path).unwrap().len();
        drop(journal);

        let refused = Journal::open_test_with_schema(&path, limits, Schema::Lifecycle);

        assert!(refused.is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), durable);
    }

    #[test]
    fn closed_key_comparison_does_not_move_the_catalog_mac_frontier() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-lifecycle-state.journal");
        let limits = JournalLimits::default();
        let (mut journal, _) =
            Journal::open_test_with_schema(&path, limits, Schema::Lifecycle).unwrap();
        let key = vec![8; 32];
        let malformed_mac_record = vec![4];
        journal
            .commit(&transaction(
                1,
                RecordNamespace::NetworkResourceInventory,
                key.clone(),
                Some(malformed_mac_record.clone()),
            ))
            .unwrap();
        drop(journal);

        let (journal, _) =
            Journal::open_test_with_schema(&path, limits, Schema::Lifecycle).unwrap();

        // The later typed catalog remains responsible for authenticating this
        // record; native/key replay alone must not claim that MAC comparison.
        assert_eq!(
            journal.get(RecordNamespace::NetworkResourceInventory, &key),
            Some(malformed_mac_record.as_slice())
        );
    }
}
