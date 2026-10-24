//! Writes the complete nonrenewing ledger as inert historical DATA.

use super::*;
use crate::protocol_snapshot::restored_suffix_history::{
    HistoricalRestoredSuffixLedger, HistoricalRestoredSuffixLedgerStage,
};

impl OriginalRestoredSuffixBudget {
    /// Copies all scalar ledger state, including failure and independently spent axes.
    pub(crate) fn historical_data(&self) -> Result<HistoricalRestoredSuffixLedger, ProviderError> {
        let Self {
            admitted,
            originals,
            ingress_retained,
            action_retained,
            stage,
        } = self;
        HistoricalRestoredSuffixLedger::from_actual_data(
            *admitted,
            *originals,
            *ingress_retained,
            *action_retained,
            match stage {
                Stage::Idle => HistoricalRestoredSuffixLedgerStage::Idle,
                Stage::Ingress => HistoricalRestoredSuffixLedgerStage::Ingress,
                Stage::Action => HistoricalRestoredSuffixLedgerStage::Action,
                Stage::Failed => HistoricalRestoredSuffixLedgerStage::Failed,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_spent_and_failed_ledger_roundtrip_never_refunds() {
        fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeStartupAllocationRow {
            PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(retained),
                maximum_simultaneous_transient_bytes: U64::new(transient),
                declared_counter_scratch_bytes: U64::new(scratch),
            }
        }
        let mut actual =
            OriginalRestoredSuffixBudget::new_data(PacketRestoredSuffixReservationData {
                maximum_originals: U64::new(3),
                ingress: row(30, 20, 30),
                actions: row(30, 40, 50),
            })
            .unwrap();
        let row = row(10, 20, 30);
        actual.begin_ingress_data(row).unwrap();
        actual
            .begin_action_data(PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(10),
                maximum_simultaneous_transient_bytes: U64::new(40),
                declared_counter_scratch_bytes: U64::new(50),
            })
            .unwrap();
        actual.complete_publication_data().unwrap();
        actual.begin_ingress_data(row).unwrap();
        actual.interrupt_data();
        let historical = actual.historical_data().unwrap();
        assert_eq!(historical.originals_data(), 2);
        assert_eq!(historical.remaining_originals_data().unwrap(), 1);
        assert_eq!(historical.ingress_retained_data(), 20);
        assert_eq!(historical.action_retained_data(), 10);
        assert_eq!(
            historical.stage_data(),
            HistoricalRestoredSuffixLedgerStage::Failed
        );
        let value = serde_json::to_value(&historical).unwrap();
        let bytes = crucible_node_format::canonical::canonical_json(&value).unwrap();
        let decoded: HistoricalRestoredSuffixLedger = serde_json::from_slice(&bytes).unwrap();
        decoded.validate_data().unwrap();
        assert_eq!(decoded, historical);
        assert!(actual.begin_ingress_data(row).is_err());
    }
}
