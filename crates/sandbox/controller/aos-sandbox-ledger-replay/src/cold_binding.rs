//! Binds the same cold DATA recipe inside each private finite role adapter.
//!
//! This one lexical binding contains no native opener or financial account.
//! Real Source/F adapters wrap their actual canonical cursor privately and
//! implement the emitted private stage trait to debit their same original
//! before each semantic COMMIT and EOF. External callers receive no trait or
//! callback through a public role API; all returned remainder is historical DATA.

/// Defines the sole fixed no-history binding in a private receiving module.
///
/// The emitted `FixedColdNativeStageV1` is crate-private and supplies neither
/// IO authority nor admission. Actual protected constructors select their own
/// fixed concrete adapter and override both semantic preallocation stages.
/// The comparison-only canonical cursor binding has no payer or fit claim.
#[macro_export]
macro_rules! define_cold_replay_binding_v1 {
    () => {
        use std::collections::BTreeMap;
        use std::error::Error;

        use aos_sandbox_broker::canonical_journal::{
            CanonicalJournalMechanicalErrorV1 as JournalError,
            coordinator::indexed_replay::{CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1},
        };
        use aos_sandbox_model::{RecordNamespace, ResourceVector};
        use aos_sandbox_journal::{protected_storage::FileIdentity, replay::NativeReplayCoordinates};
        use aos_sandbox_protocol::domain_ledger::{
            DomainLedgerDataError,
            transaction::{JournalLimits, JournalRecord, JournalTransaction, validate_transaction},
        };

        use $crate::genesis::SourceGenesisReceiptDataErrorV1;
        use $crate::replay::RootReplayOwnerEdgeV1 as RootOwnerEdge;
        use $crate::replay::source_original::cache::SourceOriginalReplayDataV5;
        use $crate::replay::{root_local_recovery, root_original_inventory, root_original_native};

        mod source_tree_successor {
            use super::*;
            use $crate::replay::source_tree_successor as data;

            pub(super) use data::State;
            pub(super) type SourceReplayFamilyOriginalsV1 = data::SourceReplayFamilyOriginalsV1<
                JournalError,
                DomainLedgerDataError,
                SourceGenesisReceiptDataErrorV1,
            >;
            pub(super) type SourceReplayTransactionOriginalsV1 = data::SourceReplayTransactionOriginalsV1<
                JournalError,
                DomainLedgerDataError,
                SourceGenesisReceiptDataErrorV1,
            >;

            pub(super) fn validate_replayed_transaction(
                state: &State,
                transaction: &JournalTransaction,
                limits: JournalLimits,
            ) -> Result<bool, JournalError> {
                data::validate_replayed_transaction::<
                    JournalError,
                    DomainLedgerDataError,
                    SourceGenesisReceiptDataErrorV1,
                >(state, transaction, limits)
            }

            pub(super) fn validate_replayed_state(
                state: &State,
                compacted: bool,
            ) -> Result<(), JournalError> {
                data::validate_replayed_state::<
                    JournalError,
                    DomainLedgerDataError,
                    SourceGenesisReceiptDataErrorV1,
                >(state, compacted)
            }

            pub(super) fn validate_replayed_state_with_originals(
                state: &State,
                compacted: bool,
                original: Option<&mut SourceReplayFamilyOriginalsV1>,
            ) -> Result<(), JournalError> {
                data::validate_replayed_state_with_originals::<
                    JournalError,
                    DomainLedgerDataError,
                    SourceGenesisReceiptDataErrorV1,
                >(state, compacted, original)
            }

            pub(super) fn require_sequence_headroom(
                state: &State,
                sequence: u64,
            ) -> Result<(), JournalError> {
                data::require_sequence_headroom(state, sequence)
            }
        }

        mod source_original_native {
            $crate::define_source_no_history_replay_data_v1!();
        }

        fn validate_reserved_capacity(
            state: &source_tree_successor::State,
            materialized_bytes: usize,
            records: &[JournalRecord],
            reservation: Option<[u8; 32]>,
            journal_bytes: u64,
            transactions: usize,
            limits: JournalLimits,
            edge: Option<RootOwnerEdge>,
        ) -> Result<(), JournalError> {
            use aos_sandbox_broker::domain_transaction_custody::pressure::{
                CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
            };

            // The shared semantic after-materialization recipe passes no live edge or
            // settlement. This cold binding cannot adopt an effect-owner selector.
            if edge.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            validate_reserved_capacity_data_v1(
                state,
                materialized_bytes,
                records,
                CapacityDeletionSelectorDataV1::Reservation(reservation),
                journal_bytes,
                transactions,
                limits,
            )
            .map_err(JournalError::from)
        }

        fn source_native_family_fixed_footprint_v1() -> Option<(usize, usize)> {
            let (family, _) = source_tree_successor::SourceReplayFamilyOriginalsV1::boxed_footprint_v1()?;
            let (transaction, _) =
                source_tree_successor::SourceReplayTransactionOriginalsV1::boxed_footprint_v1()?;
            Some((family.checked_add(transaction)?, 0))
        }

        fn is_q04_lower_history_record_v1(record: &JournalRecord) -> bool {
            $crate::semantic_recipe::is_q04_lower_history_record_data_v1(record)
        }

        mod delete_batch {
            use super::*;
            use aos_sandbox_protocol::domain_ledger::{
                controller_history_relation::validate_delete_batch_admission_records_v1,
                delete_batch::{self as codec, DeleteBatchViewV1},
            };

            enum PreflightTransactionViewV1<'a> {
                Ordinary(&'a [JournalTransaction]),
            }

            impl PreflightTransactionViewV1<'_> {
                fn len(&self) -> usize {
                    match self {
                        Self::Ordinary(rows) => rows.len(),
                    }
                }

                fn transaction(&self, index: usize) -> &JournalTransaction {
                    match self {
                        Self::Ordinary(rows) => &rows[index],
                    }
                }
            }

            $crate::define_delete_replay_data_recipe_v1!();
        }

        mod semantic {
            use super::*;

            $crate::define_semantic_replay_data_recipe_v1!();

            mod driver {
                use super::*;

                $crate::define_semantic_replay_data_recipe_v1!(retained);
            }

            pub(crate) use driver::{
                SelectedReplayNativeV1, SelectedSemanticRemainderDataV1, SelectedSemanticReplayOriginalV1,
            };
        }

        pub(crate) use semantic::{
            SelectedReplayNativeV1 as FixedColdNativeStageV1,
            SelectedSemanticRemainderDataV1 as FixedColdSemanticRemainderDataV1,
            SelectedSemanticReplayOriginalV1 as FixedColdSemanticOriginalV1,
        };

        pub(crate) fn move_cold_remainder_data_v1(
            value: FixedColdSemanticRemainderDataV1,
        ) -> $crate::cold::ColdReplayRemainderDataV1 {
            $crate::cold::ColdReplayRemainderDataV1 {
                challenge_history: value.source_challenge_history,
                original_replay: value.source_original_replay.0,
                history_compacted: value.source_history_compacted,
                q04_lower_history_present: value.q04_lower_history_present,
            }
        }
    };
}
