//! Shares the complete current cleanup-assignment selection over actual C rows.
//!
//! This pure adapter calls the sole RuntimeAuthority/Publication/gate decoders.
//! Root supplies its independently completed native C view; Controller supplies
//! its actual healthy protected writer only inside a paid C17 interval. Neither
//! this DATA nor a saved lease quartet provides a verified live lease or grant.

use aos_sandbox_model::SandboxId;
use aos_sandbox_protocol::domain_ledger::{readonly::HistoricalLedgerRowsDataV2, runtime_authority_history::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityLimits, ledger_read, crosslinks},
    ownership_gate::{OwnershipGatePlanV1, OwnershipGateStatusV1}};
use aos_sandbox_protocol::publication::{PublicationHistoryV1, RecoveredOwnershipLeaseV1,
    RecoveredBrokerDispatchTemplateV1};
use crate::journal::JournalError;

/// Quotes the same current quartet selectors without entering the compiler.
///
/// Every possible selected row is charged from its actual captured extent;
/// the Runtime scan additionally retains its real nested indices. Publication
/// and activated Gate use their sole existing assignment/draft codec geometry.
/// This does not bill compiler outputs or create a verified lease.
pub(crate) fn current_cleanup_assignment_receiving_demand_v2(
    state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{DecodeLimits, RecordNamespace, ResourceDimension as D, ResourceVector};
    use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1 as Assignment;
    use std::mem::size_of;

    let mut demand = aos_sandbox_protocol::domain_ledger::runtime_authority_history::
        namespace_scan_map_receiving_demand_v2(state)?;
    for ((namespace, _), value) in state {
        let (bytes, entries) = match namespace {
            RecordNamespace::RuntimeAuthority => {
                let (dynamic, entries) = Assignment::receiving_dynamic_footprint_v1(value.len(), DecodeLimits::default())?;
                // Complete scan and current binding lookup are distinct decode
                // planes. Their actual input extent includes canonical bytes
                // and the reencoding used by the existing format decoder.
                (dynamic.checked_add(Assignment::receiving_construction_bytes_v1()?)?
                    .checked_add(value.len().checked_mul(3)?)?.checked_mul(2)?, entries.checked_mul(2)?)
            }
            RecordNamespace::AuthorityPublication => (
                aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(value.len())?,
                aos_sandbox_protocol::publication::decoding_receiving_namespace_entries_v1(value.len())?,
            ),
            RecordNamespace::OwnershipGate => (
                aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(value.len())?
                    .checked_add(value.len().checked_mul(3)?)?
                    .checked_add(size_of::<OwnershipGatePlanV1>().checked_mul(3)?)?,
                aos_sandbox_protocol::publication::decoding_receiving_namespace_entries_v1(value.len())?,
            ),
            _ => continue,
        };
        demand = demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, u64::try_from(entries).ok()?)).ok()?;
    }
    demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(size_of::<CurrentCleanupAssignmentDataV2>().checked_mul(3)?
            .checked_add(aos_sandbox_protocol::domain_ledger::runtime_authority_history::current_assignment::
                current_assignment_links_control_bytes_v2()?)?).ok()?)).ok()
}

type Cause = Box<dyn std::error::Error + Send + Sync>;

pub(crate) struct CurrentCleanupAssignmentDataV2 {
    pub(crate) binding: RuntimeAuthorityBindingV1,
    pub(crate) history: PublicationHistoryV1,
    pub(crate) recovered_lease: RecoveredOwnershipLeaseV1,
    pub(crate) templates: Vec<RecoveredBrokerDispatchTemplateV1>,
    pub(crate) gate: OwnershipGatePlanV1,
}

pub(crate) fn current_cleanup_assignment_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>,
    sandbox: SandboxId,
) -> Result<CurrentCleanupAssignmentDataV2, Cause> {
    ledger_read::scan_namespace_rows_data_v2(rows, RuntimeAuthorityLimits::default())?;
    let binding = ledger_read::current_rows_data_v2(rows, sandbox)?
        .ok_or(JournalError::ProtectedBoundary)?;
    let publication = aos_sandbox_protocol::publication::ledger_read::current_rows_data_v2(rows, sandbox)?
        .ok_or(JournalError::ProtectedBoundary)?;
    aos_sandbox_protocol::domain_ledger::runtime_authority_history::current_assignment::
        require_current_assignment_history_data_v2(&binding, publication.history())
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let OwnershipGateStatusV1::Activated { plan, .. } = crosslinks::runtime_gate_rows_data_v2(rows, binding.operation())?
        else { return Err(JournalError::ProtectedBoundary.into()); };
    let (history, recovered_lease, templates) = publication.into_parts();
    Ok(CurrentCleanupAssignmentDataV2 { binding, history, recovered_lease, templates, gate: plan })
}

#[cfg(test)]
mod receiving_tests {
    use super::*;
    use aos_sandbox_model::{RecordNamespace, ResourceDimension as D};
    use std::collections::BTreeMap;

    #[test]
    fn quartet_quote_counts_its_actual_namespace_without_compiler_output_planes() {
        let mut rows = BTreeMap::new();
        let empty = current_cleanup_assignment_receiving_demand_v2(&rows).unwrap();
        assert_eq!(empty.get(D::MetadataEntries), 0);
        assert_eq!(empty.get(D::OpenFiles), 0);

        rows.insert((RecordNamespace::AuthorityPublication, b"current".to_vec()), vec![1; 256]);
        let publication = current_cleanup_assignment_receiving_demand_v2(&rows).unwrap();
        assert!(publication.get(D::MemoryBytes) > empty.get(D::MemoryBytes));
        assert!(publication.get(D::MetadataEntries) > 0);

        // An unrelated captured row is already owned by the read model. It
        // creates neither an assignment selector nor a compiler output here.
        rows.insert((RecordNamespace::Operation, vec![2; 16]), vec![3; 8192]);
        assert_eq!(current_cleanup_assignment_receiving_demand_v2(&rows).unwrap(), publication);
    }
}
