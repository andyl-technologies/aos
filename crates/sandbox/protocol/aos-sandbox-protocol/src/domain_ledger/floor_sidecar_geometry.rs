//! Computes the existing finite TPM-floor sidecar representation as DATA.
//!
//! The sidecar has three materialized keys: checkpoint, intent and an exact
//! prepared main transaction. This module neither opens those names nor admits
//! replay, provisioning, a physical TPM operation or a floor currentness claim.

use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::geometry::maximum_prepared_bytes;

use super::transaction::JournalLimits;

mod append;
pub use append::{FloorSidecarAppendGeometryDataV2, finalization_record_shapes_v2,
    preparation_record_shapes_v2};

mod capture;
pub use capture::{FloorSidecarDecodeShapeV1, SIDECAR_DECODE_OBSERVATIONS_V1};

/// Names the established protected floor sidecar, without selecting a directory.
pub const SIDECAR_NAME_V1: &str = "session-floor.journal";
/// Names the existing canonical checkpoint member.
pub const CHECKPOINT_KEY_V1: &[u8] = b"checkpoint";
/// Names the existing canonical intent member.
pub const INTENT_KEY_V1: &[u8] = b"intent";
/// Names the existing exact prepared-main-transaction member.
pub const TRANSACTION_KEY_V1: &[u8] = b"transaction";
/// Counts the existing fixed Broker, Host and Online checkpoint encodings.
pub const CHECKPOINT_BYTES_V1: usize = 156;
/// Counts the existing intent header and two complete checkpoints.
pub const INTENT_BYTES_V1: usize = 12 + 2 * CHECKPOINT_BYTES_V1;

/// Derives the established sidecar's limits from the SAME main journal limits.
///
/// The arithmetic and evaluation order match the existing Security sidecar
/// engine. These values describe bounded representation only. A genuine owner
/// must separately associate both physical journals and prepay every frontier.
///
/// # Errors
/// Refuses invalid main native geometry before checked preparation, record,
/// transaction, materialized-view and transaction-count arithmetic overflow.
pub fn sidecar_limits_v1(main: JournalLimits) -> Result<JournalLimits, FrameError> {
    let encoded = maximum_prepared_bytes(main.into())?;
    let prepared_record_bytes = encoded
        .checked_add(TRANSACTION_KEY_V1.len() + 7)
        .ok_or(FrameError::JournalTooLarge)?;
    let record_bytes = prepared_record_bytes
        .max(INTENT_BYTES_V1 + INTENT_KEY_V1.len() + 7)
        .max(CHECKPOINT_BYTES_V1 + CHECKPOINT_KEY_V1.len() + 7);
    let transaction_bytes = prepared_record_bytes
        .checked_add(INTENT_BYTES_V1 + INTENT_KEY_V1.len() + 7)
        .ok_or(FrameError::JournalTooLarge)?
        .max(
            CHECKPOINT_BYTES_V1 + CHECKPOINT_KEY_V1.len() + INTENT_KEY_V1.len()
                + TRANSACTION_KEY_V1.len() + 21,
        );
    let materialized_bytes = encoded
        .checked_add(
            CHECKPOINT_BYTES_V1 + INTENT_BYTES_V1 + CHECKPOINT_KEY_V1.len()
                + INTENT_KEY_V1.len() + TRANSACTION_KEY_V1.len(),
        )
        .ok_or(FrameError::JournalTooLarge)?;
    let maximum_transactions = main.maximum_transactions
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or(FrameError::JournalTooLarge)?;

    Ok(JournalLimits {
        maximum_journal_bytes: main.maximum_journal_bytes,
        maximum_record_bytes: record_bytes,
        maximum_key_bytes: TRANSACTION_KEY_V1.len(),
        maximum_records_per_transaction: 3,
        maximum_transaction_bytes: transaction_bytes,
        maximum_transactions,
        maximum_materialized_bytes: materialized_bytes,
        maximum_materialized_records: 3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_main() -> JournalLimits {
        JournalLimits {
            maximum_journal_bytes: 4096,
            maximum_record_bytes: 7,
            maximum_key_bytes: 1,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 7,
            maximum_transactions: 2,
            maximum_materialized_bytes: 1,
            maximum_materialized_records: 1,
        }
    }

    #[test]
    fn three_key_sidecar_preserves_existing_preparation_and_native_bounds() {
        let limits = sidecar_limits_v1(small_main()).unwrap();

        assert_eq!(limits.maximum_journal_bytes, 4096);
        assert_eq!(limits.maximum_record_bytes, 337);
        assert_eq!(limits.maximum_key_bytes, 11);
        assert_eq!(limits.maximum_records_per_transaction, 3);
        assert_eq!(limits.maximum_transaction_bytes, 398);
        assert_eq!(limits.maximum_transactions, 5);
        assert_eq!(limits.maximum_materialized_bytes, 550);
        assert_eq!(limits.maximum_materialized_records, 3);
    }

    #[test]
    fn invalid_main_precedes_later_sidecar_transaction_count_overflow() {
        let mut main = small_main();
        main.maximum_transactions = usize::MAX;
        main.maximum_journal_bytes = 1;
        assert!(matches!(sidecar_limits_v1(main), Err(FrameError::LimitExceeded("invalid journal configuration"))));

        main.maximum_journal_bytes = 4096;
        assert!(matches!(sidecar_limits_v1(main), Err(FrameError::JournalTooLarge)));
    }
}
