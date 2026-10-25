//! Checks the original-custody projection against the actual suffix constructor.

use super::*;
use crate::client::ClientContent;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn original_debit_reduces_only_bank_bytes_at_both_supported_request_ceilings() -> TestResult {
    let mut quotes = Vec::new();
    for requests in [256, 4096] {
        let content = ClientContent::new(8192, 8, 4096)?;
        let mut legacy = ClientCustody::new(requests, content)?;
        let full = legacy.compact_runtime_journal_retained_storage_data(usize::MAX)?;

        // Numeric debit states are DATA fixtures. Actual socket traffic and
        // the same-owner move are exercised by the runtime controller control.
        for debit in [0, 1, 4096, 8191] {
            legacy.retained_bytes = debit;
            let before = legacy.runtime_journal_bytes_data();
            let quote = legacy.compact_runtime_journal_retained_storage_data(usize::MAX)?;
            let [ceiling, remaining, bank] = legacy.compact_runtime_journal_limits_data()?;
            let suffix = CompactClientJournal::new(ceiling, remaining, bank)?;

            assert_eq!(quote, suffix.retained_storage_data(usize::MAX)?);
            assert_eq!(full - quote, 9 * debit);
            assert_eq!(
                [ceiling, remaining, bank],
                [requests, 8192 - debit, 9 * (8192 - debit)]
            );
            assert_eq!(
                legacy.compact_runtime_journal_retained_storage_data(quote)?,
                quote
            );
            assert!(
                legacy
                    .compact_runtime_journal_retained_storage_data(quote - 1)
                    .is_err()
            );
            assert_eq!(legacy.runtime_journal_bytes_data(), before);
        }
        quotes.push(full);
    }

    // The ordinary 4096 ceiling must not silently inherit the Source profile's
    // smaller 256 ceiling. Both keep independently priced endpoint maps.
    assert!(quotes[1] > quotes[0]);
    assert!(ClientCustody::compact_runtime_journal_retained_counter_scratch_data() > 0);
    Ok(())
}

#[test]
fn exhausted_or_inconsistent_legacy_credit_cannot_price_a_fresh_runtime_journal() -> TestResult {
    let content = ClientContent::new(8192, 8, 4096)?;
    let mut legacy = ClientCustody::new(256, content)?;
    for debit in [8192, 8193, usize::MAX] {
        legacy.retained_bytes = debit;
        let before = legacy.runtime_journal_bytes_data();

        assert!(
            legacy
                .compact_runtime_journal_retained_storage_data(usize::MAX)
                .is_err()
        );

        assert_eq!(legacy.runtime_journal_bytes_data(), before);
        assert_eq!(legacy.maximum_requests, 256);
    }
    Ok(())
}
