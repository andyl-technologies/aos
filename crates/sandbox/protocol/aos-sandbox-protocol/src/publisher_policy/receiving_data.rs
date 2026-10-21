//! Prices Publisher indexes from historical rows before semantic model growth.
//!
//! These formulas preserve the native callers' exact namespace roster and
//! checked overflow order. They establish no protected provenance, current
//! policy, capability acceptance or admission.

use crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2;
use aos_sandbox_model::RecordNamespace;

/// Bounds only named/index entries from the actual protected namespace rows.
///
/// A capability row can insert one handle digest and one distinct parent into
/// the registry's handle/fanout maps. A policy row enters at most one replay
/// family: the largest insertion is an outer project plus one inner revision
/// in the project-authorization or Git account/coverage maps. Other families
/// insert at most one entry. Counting two per row covers those actual indexes
/// before either semantic decoder runs, including malformed prefixes. Existing
/// Journal indexes, RuntimeAuthority indexes and model bytes are paid separately.
/// The largest authority value additionally bounds the sequential Core grant-ID
/// validation set: every encoded grant consumes at least one input byte. That
/// set is dropped inside each capability construction before another record's
/// validation begins; it does not multiply by namespace row count.
pub fn authorization_namespace_entries_v1(rows: HistoricalLedgerRowsDataV2<'_>) -> Option<usize> {
    namespace_entries(
        rows.all_records()
            .map(|(namespace, _, value)| (namespace, value.len())),
    )
}

/// Bounds the same actual named policy indexes without loading capabilities.
///
/// The current-policy selector never constructs a capability registry. Filtering
/// before the shared roster keeps unrelated authority/grant names out of its fee.
pub fn policy_namespace_entries_v2(rows: HistoricalLedgerRowsDataV2<'_>) -> Option<usize> {
    namespace_entries(
        rows.all_records()
            .filter(|(namespace, _, _)| *namespace == RecordNamespace::PublisherPolicy)
            .map(|(namespace, _, value)| (namespace, value.len())),
    )
}

/// Prices the concrete historical-row and count-result forwarding controls.
///
/// The actual caller includes this memory-only term before model admission;
/// these Rust representations create no named namespace entries. Returns
/// `None` if their checked sum is not representable.
#[must_use]
pub fn namespace_receiving_control_bytes_v1() -> Option<usize> {
    // Constructor, function argument and caller coexist as by-value row views.
    std::mem::size_of::<HistoricalLedgerRowsDataV2<'_>>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
}

fn namespace_entries(rows: impl Iterator<Item = (RecordNamespace, usize)>) -> Option<usize> {
    let mut entries = 0_usize;
    let mut grant_validation_peak = 0_usize;
    for (namespace, bytes) in rows {
        match namespace {
            RecordNamespace::PublisherAuthority => {
                entries = entries.checked_add(2)?;
                grant_validation_peak = grant_validation_peak.max(bytes);
            }
            RecordNamespace::PublisherPolicy => entries = entries.checked_add(2)?,
            _ => {}
        }
    }
    entries.checked_add(grant_validation_peak)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_only_namespace_pays_both_registry_indexes() {
        let rows = std::iter::repeat((RecordNamespace::PublisherAuthority, 200)).take(4096);
        assert_eq!(namespace_entries(rows), Some(8192 + 200));
    }

    #[test]
    fn publisher_policy_nested_indexes_are_distinct_from_existing_cold_maps() {
        assert_eq!(
            namespace_entries(
                [
                    (RecordNamespace::PublisherAuthority, 20),
                    (RecordNamespace::PublisherAuthority, 300),
                    (RecordNamespace::PublisherPolicy, 1000),
                    (RecordNamespace::Operation, 5000),
                ]
                .into_iter()
            ),
            Some(6 + 300)
        );
    }

    #[test]
    fn arithmetic_refuses_an_unrepresentable_named_validation_peak() {
        assert_eq!(
            namespace_entries([(RecordNamespace::PublisherAuthority, usize::MAX),].into_iter()),
            None
        );
    }
}
