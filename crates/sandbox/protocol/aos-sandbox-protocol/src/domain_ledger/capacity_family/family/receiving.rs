//! Retains completed capacity families at the existing full-state decoder.
//!
//! These are passive parser destinations. The actual caller retains its
//! returned Result and input map, pays before growth, and preserves the genuine
//! namespace/owner guards. No family or index can construct an authority loan.

use std::collections::BTreeSet;
use std::mem::size_of;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1;

use super::{CanonicalCapacityFamily, CapacityDataError, State, canonical_reservation_rows_into};

/// Keeps reached family models and the real owning duplicate-identity index.
///
/// An unknown later row retains all earlier completed families. A duplicate
/// identity also retains that actual newly decoded family. The caller owns
/// the complete returned error; this capture never clones or reconstructs it.
#[derive(Default)]
#[must_use = "retain this parser reservoir beside its original returned Result"]
pub struct CanonicalCapacityReadCaptureV1 {
    families: Vec<CanonicalCapacityFamily>,
    identities: BTreeSet<[u8; 32]>,
    current: Option<CanonicalCapacityFamily>,
    entered: bool,
    complete: bool,
    reentered: bool,
}

impl CanonicalCapacityReadCaptureV1 {
    /// Creates empty destinations without allocating or observing a map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn decode_once(&mut self, state: &State) -> Result<(), CapacityDataError> {
        if self.entered {
            self.reentered = true;
            return Err(CapacityDataError::ProtectedBoundary);
        }
        self.entered = true;
        canonical_reservation_rows_into(
            state.iter().filter_map(|((namespace, key), value)| {
                (*namespace == RecordNamespace::GlobalCapacityReservation)
                    .then_some((key.as_slice(), value.as_slice()))
            }),
            &mut self.families,
            &mut self.identities,
            Some(&mut self.current),
        )?;
        self.complete = true;
        Ok(())
    }

    /// Applies the same complete canonical scan before the legacy-family check.
    ///
    /// # Errors
    /// Returns the original decoder/duplicate error or the existing closed
    /// nonlegacy refusal. The caller keeps that owning Result beside this value.
    pub fn require_legacy_once_v1(&mut self, state: &State) -> Result<(), CapacityDataError> {
        self.decode_once(state)?;
        if self.families.iter().any(|family| family.legacy().is_none()) {
            return Err(CapacityDataError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Checks ownership only after the same complete canonical scan.
    ///
    /// # Errors
    /// Returns the original decoder/duplicate error or a reentry refusal.
    /// A false comparison grants no owner or currentness authority.
    pub fn all_owned_by_once_v1(&mut self, state: &State, namespace: RecordNamespace)
        -> Result<bool, CapacityDataError>
    {
        self.decode_once(state)?;
        Ok(self.families.iter().all(|family| family.owner_namespace() == namespace))
    }

    /// Borrows reached decoded models as nonauthorizing diagnostic DATA.
    #[must_use]
    pub fn retained_families_v1(&self) -> &[CanonicalCapacityFamily] {
        &self.families
    }

    /// Reports the actual owning index size, including after a later refusal.
    #[must_use]
    pub fn retained_identity_count_v1(&self) -> usize {
        self.identities.len()
    }

    /// Reports whether a duplicate's actual decoded model remains resident.
    #[must_use]
    pub fn has_current_family_v1(&self) -> bool {
        self.current.is_some()
    }

    /// Counts the decoded family rows and their owning identity-index entries.
    ///
    /// A duplicate's current model is covered by the admitted input-row bound;
    /// the index contains at most one identity for each completed family.
    #[must_use]
    pub fn receiving_named_entries_v2(rows: usize) -> Option<usize> {
        rows.checked_mul(2)
    }

    /// Supplies requested model/index/backing geometry without observing state.
    ///
    /// The genuine held native prefix bounds actual capacity rows. Their input
    /// bytes stay separately owned; nested encoded/provenance scratch is paid
    /// by the same native semantic-prefix supplier, not inferred free here.
    #[must_use]
    pub fn receiving_obligations_v1(rows: usize) -> Option<(usize, usize)> {
        // Geometric Vec growth, including old/new backing during reallocation.
        let backing = rows.checked_mul(3)?.checked_mul(size_of::<CanonicalCapacityFamily>())?;
        let index = conservative_btree_node_bytes_v1::<[u8; 32], ()>(rows)?;
        let bytes = size_of::<Self>().checked_mul(2)?.checked_add(backing)?.checked_add(index)?;
        // Six owner fields. Decode12 names state, closure namespace/key/value,
        // row iterator, row key/value, ordinary temporary, selected slot,
        // identity and decoder/return destinations. Selection4 names the
        // namespace, predicate borrow, comparison and returned Result. Each
        // family additionally has model/index-identity/node namespaces3.
        let cells = 6usize.checked_add(12)?.checked_add(4)?
            .checked_add(rows.checked_mul(3)?)?;
        Some((bytes, cells))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::capacity_family::native_held::{
        NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
    };

    fn canonical_record() -> crate::domain_ledger::transaction::JournalRecord {
        NativeHeldCapacityRecordV3::new(NativeHeldCapacityRequestV3 {
            purpose: NativeHeldCapacityPurposeV3::Root,
            owner_id: [1; 32], owner_digest: [2; 32], operation_id: [3; 16],
            artifact_digest: [4; 32], checkpoint_digest: [5; 32], chain_head_digest: [6; 32],
            future_transactions: 1, terminal_records: 1, terminal_bytes: 1,
            poison_records: 1, poison_bytes: 1,
        }, [7; 16]).unwrap().to_journal_record()
    }

    #[test]
    fn later_malformed_row_keeps_completed_model_and_owning_identity_index() {
        let record = canonical_record();
        let mut state = State::new();
        state.insert((RecordNamespace::GlobalCapacityReservation, record.key().to_vec()),
            record.value().unwrap().to_vec());
        state.insert((RecordNamespace::GlobalCapacityReservation, b"zz-unknown".to_vec()), vec![0]);
        let mut original = CanonicalCapacityReadCaptureV1::new();

        let returned = original.require_legacy_once_v1(&state);
        assert!(matches!(returned, Err(CapacityDataError::MalformedRecord("capacity family header"))));
        assert_eq!(original.retained_families_v1().len(), 1);
        assert_eq!(original.retained_identity_count_v1(), 1);
        let model = &original.retained_families_v1()[0] as *const CanonicalCapacityFamily;
        assert!(original.require_legacy_once_v1(&State::new()).is_err());

        assert_eq!(&original.retained_families_v1()[0] as *const CanonicalCapacityFamily, model);
        assert_eq!(original.retained_identity_count_v1(), 1);
        assert!(!original.has_current_family_v1());
    }

    #[test]
    fn duplicate_row_keeps_the_actual_rejected_decoded_family() {
        let record = canonical_record();
        let pair = (record.key(), record.value().unwrap());
        let mut original = CanonicalCapacityReadCaptureV1::new();

        let returned = canonical_reservation_rows_into([pair, pair],
            &mut original.families, &mut original.identities, Some(&mut original.current));

        assert!(matches!(returned, Err(CapacityDataError::MalformedRecord("duplicate global capacity reservation"))));
        assert_eq!(original.retained_families_v1().len(), 1);
        assert_eq!(original.retained_identity_count_v1(), 1);
        assert!(original.has_current_family_v1());
        assert_eq!(original.current.as_ref().unwrap().identity(),
            original.retained_families_v1()[0].identity());
    }

    #[test]
    fn whole_canonical_owner_comparison_matches_the_ordinary_decoder() {
        let record = canonical_record();
        let mut state = State::new();
        state.insert((RecordNamespace::GlobalCapacityReservation, record.key().to_vec()),
            record.value().unwrap().to_vec());
        let expected = crate::domain_ledger::capacity_family::all_reservations_owned_by(
            &state, RecordNamespace::MountSourceAcquisition).unwrap();
        let mut original = CanonicalCapacityReadCaptureV1::new();

        let actual = original.all_owned_by_once_v1(&state,
            RecordNamespace::MountSourceAcquisition).unwrap();

        assert!(expected);
        assert_eq!(actual, expected);
        assert_eq!(original.retained_families_v1().len(), 1);
        assert_eq!(original.retained_identity_count_v1(), 1);
        assert!(original.complete);
    }
}
