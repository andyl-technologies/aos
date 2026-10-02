//! Same-writer held issuance history, future geometry and exact readback.
//!
//! The actual original-startup route alone selects these mechanics. Core lends
//! its native COMMIT edges; the existing Storage reducer supplies the only row
//! grammar. No DATA snapshot is an append, signing or descriptor-send permit.
//! Legacy constructors keep their original limits and decoder.

use std::collections::BTreeMap;

use aos_sandbox::journal::encoded_transaction_append_bytes;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldOwnerV1 as Owner,
    suffix::NativeHeldCompletionSuffixV1,
};

use super::held_completion::{
    MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2, StorageHeldIssuanceRowV2,
    StorageHeldStepV1, StorageIssuanceValueV1, decoded_native_rows,
    original_native_row, reduce, remaining_capacity_profile,
    require_native_replayed_edge,
};
use super::*;

type Values = BTreeMap<[u8; 48], Vec<u8>>;
type Result<T> = std::result::Result<T, StorageNativeIssuanceErrorV1>;
const STATE_DIRECTORY: &str = "/var/lib/aos/sandbox-storage";

/// A current same-parser cut, private to the owner that still holds its writer.
struct Geometry {
    limits: JournalLimits,
    physical: u64,
    transactions: usize,
    next: u64,
}

impl StorageNativeIssuanceLedgerV1 {
    pub(crate) fn uses_original_held_route(&self) -> bool {
        matches!(self.custody, NativeIssuanceCustodyV1::RootOwnedHeld)
    }

    // Only the prearmed genuine-startup attempt can reach this construction.
    // Both the returned writer and trust owner reside there before any checks.
    pub(crate) fn park_original_held_writer(
        attempt: &mut crate::runtime::StorageOriginalNativeConstructionV1,
        state_directory: &Path,
        authority_directory: &Path,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
    ) -> Result<()> {
        attempt.require_native_open()?;
        if state_directory != Path::new(STATE_DIRECTORY) {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        let journal = Journal::open_existing_protected_at(
            state_directory, JOURNAL_FILE, held_limits(),
        )?.0;
        attempt.park_native_writer(journal);
        let trust = crate::live_export_request_trust::StorageLiveExportRequestTrustV1::open_root_owned(authority_directory)?;
        attempt.park_native_trust(trust);
        key.recheck().map_err(|cause| StorageNativeIssuanceErrorV1::Credential(Box::new(cause)))?;

        // Checked moves contain no observation, allocation or effect. The same
        // writer enters its owner before replay/capacity can reject that owner.
        let state_directory = state_directory.to_path_buf();
        let journal = attempt.take_native_writer()?;
        let ledger = Self {
            journal,
            state_directory,
            custody: NativeIssuanceCustodyV1::RootOwnedHeld,
        };
        attempt.park_native_ledger(ledger);
        Ok(())
    }

    pub(crate) fn validate_original_held_cold(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        trust: &crate::live_export_request_trust::StorageLiveExportRequestTrustV1,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
    ) -> Result<()> {
        self.validate_boundary()?;
        let (values, geometry) = self.held_state()?;
        require_funding(&values, &geometry, None)?;
        self.require_original_held_roles(trust, key)?;
        self.validate_active_holds(coordinator)
    }

    fn held_state(&self) -> Result<(Values, Geometry)> {
        if !self.uses_original_held_route() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        let result = (|| {
            let mut history = self.journal.capture_storage_native_issuance_history_v1()?;
            let geometry = Geometry {
                limits: history.opened_limits(),
                physical: history.physical_bytes(),
                transactions: history.committed_transactions(),
                next: history.next_sequence(),
            };
            let mut cursor = history.replay()?;
            let mut final_values = Values::new();
            while let Some(edge) = cursor.next_edge()? {
                final_values.clear();
                // Each short loan retains only two converted maps. Aggregate
                // charging precedes copies; BTreeMap/parser allocations remain
                // ordinary allocations, not an allocator-custody guarantee.
                let before = convert_prefix(edge.before(), geometry.limits)?;
                let after = convert_prefix(edge.after(), geometry.limits)?;
                require_native_replayed_edge(&before, &after, edge.begin_sequence(), edge.transaction())?;
                final_values = after;
            }
            cursor.finish()?;
            drop(cursor);
            drop(history);

            Ok((final_values, geometry))
        })();
        let bookend = self.journal.validate_held_root_owned_at(&self.state_directory, JOURNAL_FILE);
        match (result, bookend) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(bookend)) => Err(bookend.into()),
            (Err(primary), Err(bookend)) => Err(StorageNativeIssuanceErrorV1::HeldBookend {
                primary: Box::new(primary), bookend,
            }),
        }
    }

    pub(crate) fn require_original_held_roles(
        &mut self,
        trust: &crate::live_export_request_trust::StorageLiveExportRequestTrustV1,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
    ) -> Result<()> {
        trust.validate_current()?;
        key.recheck().map_err(|cause| StorageNativeIssuanceErrorV1::Credential(Box::new(cause)))?;
        let (values, geometry) = self.held_state()?;
        require_funding(&values, &geometry, None)?;
        for value in decoded_native_rows(&values)?.values() {
            let original = original_native_row(value);
            trust.verify_native(&original.request)?;
            if let StorageIssuanceValueV1::Held(row) = value {
                for control in row.suffix().controls() {
                    trust.verify_held_archive(control, key.verifier())?;
                }
                if let Some(prepared) = row.suffix().prepared() {
                    trust.verify_stored_held_preparation(prepared, key.verifier())?;
                }
            }
        }
        trust.validate_current()?;
        key.recheck().map_err(|cause| StorageNativeIssuanceErrorV1::Credential(Box::new(cause)))?;
        self.journal.validate_held_root_owned_at(&self.state_directory, JOURNAL_FILE)?;
        Ok(())
    }

    pub(super) fn held_original_rows(&self) -> Result<Vec<NativeIssuanceRowV1>> {
        let (values, _) = self.held_state()?;
        let decoded = decoded_native_rows(&values)?;
        let mut rows = Vec::new();
        rows.try_reserve(decoded.len())?;
        for value in decoded.values() {
            rows.push(original_native_row(value).clone());
        }
        Ok(rows)
    }

    pub(crate) fn held_offer_funding(&mut self) -> Result<()> {
        self.validate_boundary()?;
        let (values, geometry) = self.held_state()?;
        require_funding(&values, &geometry, None)
    }

    // The stored exact before row is also the unsigned2 byte witness source.
    pub(crate) fn held_row_readback(
        &mut self,
        expected: &StorageHeldIssuanceRowV2,
    ) -> Result<u64> {
        self.validate_boundary()?;
        let (values, geometry) = self.held_state()?;
        require_funding(&values, &geometry, None)?;
        if values.get(&expected.key()).map(Vec::as_slice)
            != Some(expected.to_canonical_bytes()?.as_slice())
        {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        Ok(geometry.next)
    }

    pub(crate) fn store_original_held_row(
        &mut self,
        row: &StorageHeldIssuanceRowV2,
        step: StorageHeldStepV1,
        attempted: &mut Option<JournalTransaction>,
    ) -> Result<u64> {
        self.validate_boundary()?;
        let (before, geometry) = self.held_state()?;
        let mut after = before.clone();
        after.insert(row.key(), row.to_canonical_bytes()?);
        let reduction = reduce(&before, &after, geometry.next, step)?;
        let transaction = reduction.transaction.ok_or(StorageNativeIssuanceErrorV1::Conflict)?;
        // Park the complete actual transaction before preflight or commit.
        // Its real append plus AFTER-state debt, not BEFORE debt, is charged.
        *attempted = Some(transaction);
        let transaction = attempted.as_ref().ok_or(StorageNativeIssuanceErrorV1::Conflict)?;
        require_funding(&after, &geometry, Some(transaction))?;
        self.journal.preflight_transactions(std::slice::from_ref(transaction))?;
        self.validate_boundary()?;
        self.journal.claim_protected_authority(RecordNamespace::AuthorityPublication)?.commit(transaction)?;
        self.held_row_readback(row)
    }

    pub(crate) fn original_held_interest(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        held: &StorageHeldSnapshotReadbackWithMountV1,
        reply: &StorageNativeAcquireReplyV3,
        root: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        current: &StorageHeldSnapshotCatalogCutV1,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
    ) -> Result<StorageHeldIssuanceRowV2> {
        authenticated.recheck()?;
        held.readback.cut.ensure_unchanged(current)
            .map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?;
        if held.observe_root().map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?
            != *reply.acceptance().acceptance().descriptor()
        {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        if !self.uses_original_held_route() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        authenticated.require_original_root_prepared(root, key.verifier())?;
        let original = NativeIssuanceRowV1 {
            request: authenticated.request().clone(),
            acceptance: reply.acceptance().acceptance().clone(),
            retirement: None,
        };
        validate_hold_cut(&original, current)?;
        let row = StorageHeldIssuanceRowV2::new(
            original.request, original.acceptance, None,
            NativeHeldCompletionSuffixV1::new(Owner::Storage, 0, root.scope().flight, None, vec![root.clone()])
                .map_err(held_completion::StorageHeldCompletionErrorV1::from)?,
        )?;
        Ok(row)
    }
}

fn convert_prefix(
    prefix: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<Values> {
    if prefix.len() > limits.maximum_materialized_records || prefix.len() > MAXIMUM_ISSUANCES {
        return Err(StorageNativeIssuanceErrorV1::Noncanonical);
    }
    let mut charged = 0_usize;
    for ((namespace, key), value) in prefix {
        charged = charged.checked_add(key.len()).and_then(|n| n.checked_add(value.len()))
            .filter(|n| *n <= limits.maximum_materialized_bytes)
            .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
        if *namespace != RecordNamespace::AuthorityPublication || key.len() != 48
            || value.len() > MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2
        {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
    }
    let mut values = Values::new();
    for ((_, key), value) in prefix {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(value.len())?;
        bytes.extend_from_slice(value);
        let key = key.as_slice().try_into().map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
        if values.insert(key, bytes).is_some() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
    }
    Ok(values)
}

fn require_funding(after: &Values, cut: &Geometry, prospective: Option<&JournalTransaction>) -> Result<()> {
    let profile = remaining_capacity_profile(after)?;
    let append = prospective.map(encoded_transaction_append_bytes).transpose()?.unwrap_or(0);
    let prospective_count = usize::from(prospective.is_some());
    let remaining_count = prospective_count.checked_add(profile.remaining_transactions)
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
    let count = cut.transactions.checked_add(remaining_count)
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
    let bytes = cut.physical.checked_add(append).and_then(|n| n.checked_add(profile.remaining_append_bytes))
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
    let frames = u64::try_from(remaining_count).ok().and_then(|n| n.checked_mul(3))
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
    let last = cut.next.checked_add(frames).filter(|n| *n < u64::MAX)
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
    let largest = match prospective.and_then(|tx| tx.records().first()) {
        Some(record) => record.key().len().checked_add(record.value().map_or(0, <[u8]>::len))
            .and_then(|n| n.checked_add(7))
            .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?,
        None => 0,
    };
    let record_bytes = largest.max(profile.maximum_record_bytes);
    let limits = cut.limits;
    if bytes > limits.maximum_journal_bytes || record_bytes > limits.maximum_record_bytes
        || 48 > limits.maximum_key_bytes || 1 > limits.maximum_records_per_transaction
        || record_bytes > limits.maximum_transaction_bytes || count > limits.maximum_transactions
        || profile.peak_materialized_bytes > limits.maximum_materialized_bytes
        || after.len() > limits.maximum_materialized_records || last == u64::MAX
    {
        return Err(StorageNativeIssuanceErrorV1::Noncanonical);
    }
    Ok(())
}

fn held_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2 + 48 + 7,
        maximum_key_bytes: 48,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2 + 48 + 7,
        maximum_transactions: MAXIMUM_ISSUANCES * 8,
        maximum_materialized_bytes: 128 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_ISSUANCES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_cut() -> Geometry {
        Geometry { limits: held_limits(), physical: 0, transactions: 0, next: 1 }
    }

    #[test]
    fn empty_history_geometry_is_data_not_an_admission() {
        require_funding(&Values::new(), &empty_cut(), None).unwrap();
        let mut exhausted = empty_cut();
        exhausted.next = u64::MAX;

        assert!(require_funding(&Values::new(), &exhausted, None).is_err());
    }

    #[test]
    fn opened_key_and_record_count_ceilings_are_not_replaced_by_profile_data() {
        let mut cut = empty_cut();
        cut.limits.maximum_key_bytes = 47;
        assert!(require_funding(&Values::new(), &cut, None).is_err());

        cut = empty_cut();
        cut.limits.maximum_records_per_transaction = 0;
        assert!(require_funding(&Values::new(), &cut, None).is_err());
    }

    #[test]
    fn actual_extent_and_committed_count_are_charged_even_with_no_remaining_rows() {
        let mut cut = empty_cut();
        cut.physical = cut.limits.maximum_journal_bytes;
        cut.transactions = cut.limits.maximum_transactions;
        require_funding(&Values::new(), &cut, None).unwrap();

        cut.physical += 1;
        assert!(require_funding(&Values::new(), &cut, None).is_err());
        cut.physical -= 1;
        cut.transactions += 1;
        assert!(require_funding(&Values::new(), &cut, None).is_err());
    }

    #[test]
    fn prefix_copy_refuses_foreign_namespace_and_overlength_before_growth() {
        let mut prefix = BTreeMap::new();
        prefix.insert((RecordNamespace::AuthorityPublication, vec![1; 47]), vec![1]);
        assert!(convert_prefix(&prefix, held_limits()).is_err());

        prefix.clear();
        prefix.insert((RecordNamespace::AuthorityPublication, vec![1; 48]), vec![1; 5]);
        let mut limits = held_limits();
        limits.maximum_materialized_bytes = 52;
        assert!(convert_prefix(&prefix, limits).is_err());
    }
}
