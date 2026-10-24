//! Runs the sole full prospective schedule with finite native Policy roles.
//!
//! The private forecast sum distinguishes a real mutation lender from the
//! actual readonly Authority suffix forecast. Neither can be manufactured from
//! a successful DATA result. Every map/encoder/model plane is paid before clone.

use super::{ErrorV1, PolicyMutationGateV1, RootPolicyJournalV1, delete, policy};
use crate::native::authority::AuthorityForecastGateV1;
use aos_sandbox_broker::canonical_journal::preflight::schedule::{
    CanonicalPreflightWorkingModelsDataV1, role_control_receiving_bytes_v1,
};
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as Mechanical, CanonicalPreflightDataOriginalV1,
    CanonicalReplayExtentDataV1,
};
use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::replay::root_original_inventory;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

pub(super) enum PolicyPreflightGateV1<'borrow, 'gate, 'flight, 'origin, 'packet, 'startup> {
    Mutation(&'borrow mut PolicyMutationGateV1<'gate, 'flight, 'origin, 'packet, 'startup>),
    Forecast(&'borrow AuthorityForecastGateV1<'gate>),
    Genesis(&'borrow mut crate::native::authority::RootGenesisAdvisoryCutV1<'gate>),
    Successor(&'borrow mut crate::native::authority::RootSuccessorAdvisoryCutV1<'gate>),
}

impl PolicyPreflightGateV1<'_, '_, '_, '_, '_, '_> {
    fn before_models_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), ErrorV1> {
        match self {
            Self::Mutation(gate) => gate.require_before_models_v1(journal, transactions),
            Self::Forecast(original) => original.preflight_v1(journal, transactions),
            Self::Genesis(original) => original.require_before_models_v1(journal, transactions),
            Self::Successor(original) => original.require_before_models_v1(journal, transactions),
        }
    }

    pub(super) fn require_q04_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), ErrorV1> {
        match self {
            Self::Mutation(gate) => gate.require_q04_transition_v1(state, transaction, index),
            Self::Forecast(original) => original.require_q04_transition_v1(transaction, index),
            Self::Genesis(_) | Self::Successor(_) => {
                aos_sandbox_ledger_replay::ordinary_mutation::require_no_root_q04_mutation_v1(
                    state,
                    transaction,
                )
                .map_err(ErrorV1::from)
            }
        }
    }
}

pub(super) fn require_capacity_v1(
    journal: &RootPolicyJournalV1,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    materialized_bytes: usize,
    expected_length: u64,
    transactions: usize,
    capacity: &super::genesis::CapacityCoordinatesV1,
) -> Result<(), ErrorV1> {
    validate_reserved_capacity_data_v1(
        state,
        materialized_bytes,
        transaction.records(),
        CapacityDeletionSelectorDataV1::Reservation(capacity.settling_reservation),
        expected_length,
        transactions,
        journal.limits(),
    )
    .map_err(Mechanical::from)
    .map_err(ErrorV1::from)
}

impl RootPolicyJournalV1 {
    pub(super) fn admit_append_semantics_v1(
        &self,
        transaction: &JournalTransaction,
        gate: &PolicyMutationGateV1<'_, '_, '_, '_, '_>,
    ) -> Result<(), ErrorV1> {
        use aos_sandbox_journal::transaction::NativeRecordKeyIndexV1;
        let append =
            aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(
                transaction,
            )
            .map_err(Mechanical::from)?;
        let encoded = self
            .captured_native_bytes
            .checked_add(append)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        let rows = encoded / aos_sandbox_journal::framing::HEADER_BYTES;
        let semantic =
            aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                encoded, rows,
            )?;
        let mut keys = 0usize;
        let mut largest_key = 0usize;
        let mut largest_value = 0usize;
        for record in transaction.records() {
            keys = keys
                .checked_add(record.key().len())
                .ok_or_else(ErrorV1::geometry)?;
            largest_key = largest_key.max(record.key().len());
            largest_value = largest_value.max(record.value().map_or(0, <[u8]>::len));
        }
        // This is the logical validator before native entry. The later
        // Root prepare supplier independently pays its real retained encoder.
        let validator = NativeRecordKeyIndexV1::dynamic_bytes_v1(
            transaction.records().len(),
            keys,
            largest_key,
        )
        .and_then(|bytes| bytes.checked_add(largest_value))
        .ok_or_else(ErrorV1::geometry)?;
        // The genuine Authority append scope already paid its enum before
        // construction. Other actual roles retain their existing local term.
        let gate_carriers = match gate {
            PolicyMutationGateV1::Authority(_) => 0,
            _ => std::mem::size_of::<PolicyMutationGateV1<'_, '_, '_, '_, '_>>()
                .checked_mul(3).ok_or_else(ErrorV1::geometry)?,
        };
        let controls = std::mem::size_of::<(
            Result<(), ErrorV1>,
            Result<(), Mechanical>,
            Result<u64, aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>,
            &PolicyMutationGateV1<'_, '_, '_, '_, '_>,
            ResourceVector,
            Result<ResourceVector, Mechanical>,
            Result<ResourceVector, ErrorV1>,
            super::genesis::CapacityCoordinatesV1,
            Result<super::genesis::CapacityCoordinatesV1, ErrorV1>,
            super::genesis::GenesisSourceBorrowV1<'_, '_>,
            Option<[u8; 32]>,
            Result<Option<[u8; 32]>, ErrorV1>,
            usize,
            usize,
            usize,
            u64,
            usize,
            Option<usize>,
            Result<usize, ErrorV1>,
        )>()
        .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(gate_carriers))
        .and_then(|bytes| bytes.checked_add(validator))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(ErrorV1::geometry)?;
        let demand = semantic
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            .map_err(|_| ErrorV1::geometry())?;
        match gate {
            PolicyMutationGateV1::StartupCredential(original) => original.debit_v1(self, demand),
            _ => self.admit_role_observation_v1(demand),
        }
    }

    fn admit_complete_preflight_v1(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), ErrorV1> {
        // This byte coordinate came from the actual opening, less its repaired
        // tail, and advances only with this owner's actual durable append. It
        // performs no extra early metadata IO. The original metadata sample
        // remains after prospective clone in the shared lexical schedule.
        let incoming = CanonicalPreflightDataOriginalV1::receiving_data_v1(
            self.captured_native_bytes,
            transactions,
        )?;
        let future = CanonicalReplayExtentDataV1::new(self.limits(), incoming.future_native_bytes)
            .map_err(Mechanical::from_ordinary_native_v1)?;
        let native = future
            .dominant_native_receiving_demand_v1()
            .map_err(Mechanical::from_ordinary_native_v1)?;
        let canonical = future
            .dominant_semantic_receiving_demand_v1()
            .map_err(Mechanical::from_ordinary_native_v1)?;
        let encoded =
            usize::try_from(incoming.future_native_bytes).map_err(|_| ErrorV1::geometry())?;
        let rows = encoded / aos_sandbox_journal::framing::HEADER_BYTES;
        let semantic =
            aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                encoded, rows,
            )?;
        let controls = role_control_receiving_bytes_v1::<ErrorV1>()
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<(
                        CanonicalReplayExtentDataV1,
                        Result<
                            CanonicalReplayExtentDataV1,
                            aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1,
                        >,
                        Result<ResourceVector, ErrorV1>,
                        ResourceVector,
                        PolicyPreflightGateV1<'_, '_, '_, '_, '_, '_>,
                        super::genesis::CapacityCoordinatesV1,
                        Result<super::genesis::CapacityCoordinatesV1, ErrorV1>,
                        super::genesis::GenesisSourceBorrowV1<'_, '_>,
                        Option<[u8; 32]>,
                        Result<Option<[u8; 32]>, ErrorV1>,
                    )>()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        let demand = incoming
            .additional
            .checked_add(native)
            .and_then(|demand| demand.checked_add(canonical))
            .and_then(|demand| demand.checked_add(semantic))
            .and_then(|demand| {
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            })
            .map_err(|_| ErrorV1::geometry())?;
        self.admit_role_observation_v1(demand)
    }

    pub(in crate::native) fn preflight_q04_stage_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), ErrorV1> {
        let bytes = std::mem::size_of::<Result<(), ErrorV1>>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        self.admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        self.preflight_transactions(std::slice::from_ref(transaction))
    }

    pub(in crate::native) fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), ErrorV1> {
        let mut ordinary = PolicyMutationGateV1::Ordinary;
        self.preflight_with_role_gate_v1(transactions, &mut ordinary)
    }

    pub(in crate::native) fn preflight_with_role_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: &mut PolicyMutationGateV1<'_, '_, '_, '_, '_>,
    ) -> Result<(), ErrorV1> {
        self.preflight_native_scope_v1(transactions, PolicyPreflightGateV1::Mutation(gate))
    }

    pub(in crate::native) fn preflight_authority_forecast_v1(
        &self,
        transactions: &[JournalTransaction],
        original: &AuthorityForecastGateV1<'_>,
    ) -> Result<(), ErrorV1> {
        self.preflight_native_scope_v1(transactions, PolicyPreflightGateV1::Forecast(original))
    }

    pub(in crate::native) fn preflight_genesis_advisory_v1(
        &self,
        transactions: &[JournalTransaction],
        original: &mut crate::native::authority::RootGenesisAdvisoryCutV1<'_>,
    ) -> Result<(), ErrorV1> {
        self.preflight_native_scope_v1(transactions, PolicyPreflightGateV1::Genesis(original))
    }

    pub(in crate::native) fn preflight_genesis_successor_v1(
        &self,
        transactions: &[JournalTransaction],
        original: &mut crate::native::authority::RootSuccessorAdvisoryCutV1<'_>,
    ) -> Result<(), ErrorV1> {
        self.preflight_native_scope_v1(transactions, PolicyPreflightGateV1::Successor(original))
    }

    fn preflight_native_scope_v1(
        &self,
        transactions: &[JournalTransaction],
        mut gate: PolicyPreflightGateV1<'_, '_, '_, '_, '_, '_>,
    ) -> Result<(), ErrorV1> {
        self.ensure_healthy()?;
        for transaction in transactions {
            match &mut gate {
                PolicyPreflightGateV1::Mutation(PolicyMutationGateV1::RootOpen(original)) => {
                    original.require_prechecked_root_history_successor_v1(transaction)?;
                }
                _ => {
                    aos_sandbox_ledger_replay::ordinary_mutation::require_no_create_storage_mutation(
                        self.read_view().state(),
                        transaction,
                    )?;
                }
            }
        }
        aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
            self.read_view(),
            self.read_view().state(),
        )?;
        gate.before_models_v1(self, transactions)?;
        delete::bound_preview(self.read_view().state(), transactions, self.limits())?;
        self.admit_complete_preflight_v1(transactions)?;
        let read = self.read_view();
        aos_sandbox_broker::canonical_prospective_preflight_data_v1! {
            error ErrorV1;
            transactions transactions;
            count transactions.len();
            transaction(index) &transactions[index];
            models models = CanonicalPreflightWorkingModelsDataV1 {
                state: read.state().clone(),
                idempotency: read.idempotency_index().clone(),
                transaction_ids: read.transaction_ids().clone(),
                materialized_bytes: read.materialized_bytes(),
                next_sequence: read.next_sequence(),
                committed_transactions: read.committed_transactions(),
            };
            limits self.limits();
            retained None;
            preview {}
            metadata read.metadata();
            before_transaction(transaction) {
                let capacity = policy::require_forecast_v1(self, &models.state, transaction, index, &mut gate)?;
                capacity.require_presence_v1(transaction)?;
            }
            delete {
                delete::validate(&models.state, transaction, models.next_sequence, self.limits())?;
            }
            after_frames(frame_count) {
                root_original_inventory::require_append_sequence_headroom(&models.state,
                    transaction, models.next_sequence.checked_add(frame_count)
                        .ok_or_else(ErrorV1::geometry)?)?;
            }
            reserved(expected_length) {
                require_capacity_v1(self, &models.state, transaction, models.materialized_bytes,
                    expected_length, models.committed_transactions.checked_add(1)
                        .ok_or_else(ErrorV1::geometry)?, &capacity)?;
                if gate.has_successor_v1() {
                    aos_sandbox_ledger_replay::replay::source_tree_successor::require_sequence_headroom(
                        &root_original_inventory::materialize(&models.state, transaction),
                        models.next_sequence.checked_add(frame_count)
                            .ok_or(Mechanical::SequenceExhausted)?,
                    )?;
                }
            }
        }
    }
}
