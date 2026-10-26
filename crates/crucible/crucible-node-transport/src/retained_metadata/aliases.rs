//! Records original shared-owner edges without serializing process addresses.
//!
//! The precharged lookup compares borrowed backing addresses only during the
//! exclusive source walk. Encoded rows carry a closed kind and local first-group
//! index. They preserve historical aliases but cannot identify or enroll a live
//! original actor, registrar or policy in another process.
//!
//! ```json
//! [["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0]]
//! ```

use crate::ProviderError;
use serde::{Serialize, Serializer, ser::SerializeSeq};

/// Identifies a closed shared backing category in the whole-eleven graph.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MetadataSharedKind {
    /// Names an actual reconstructed historical policy allocation.
    HistoricalImportPolicy,
    /// Names an actual reconstructed historical Boot allocation.
    HistoricalImportBoot,
    /// Names an actual reconstructed historical literal-bank allocation.
    HistoricalImportFrames,
    /// Names an actual reconstructed historical blob-ledger allocation.
    HistoricalImportBlobLedger,
    /// Names an actual reconstructed historical selected-extension slice.
    HistoricalImportExtensions,

    /// Names one actual retained native restore-response allocation.
    NativeRestoreResponse,
    /// Names one same-process physical restoration hold, never a portable gate.
    NativeRestoredPhysicalHold,
    /// Names one retained native complete Commit attempt allocation.
    NativeRestoreCommitAttempt,
    /// Names one retained six-input native restoration custody allocation.
    NativeRestoreInputCustody,
    /// Names the independent once restored observation attempt allocation.
    NativeRestorationObservationAttempt,
    /// Names a separately spent recurring Observe attempt under startup16.
    NativeRestoredSuffixObservationAttempt,
    /// Names an independently owned closed Producer raw/typed receive partial.
    NativeRestoredProducerAttempt,
    /// Names one separately funded recurring native17 action attempt.
    NativeRestoredSettledActionAttempt,
    /// Names an original protocol-capture actor header.
    ProtocolOwner,
    /// Names the original registrar's epoch counter backing.
    RegistrarEpoch,
    /// Names the original registrar's registration gate backing.
    RegistrarGate,
    /// Names one immutable selected-extension slice backing.
    SelectedExtensions,
    /// Names an immutable codec enum backing.
    Codec,
    /// Names an immutable native policy backing.
    NativePolicy,
    /// Names an original Hello literal bank backing.
    HelloBank,
    /// Names one content Vec backing; content-eight edges separately verify it.
    ContentBytes,
    /// Names an original connection frame-bank backing.
    FrameBank,
    /// Names a retained verified private native boot backing.
    NativeBoot,
    /// Names a successful inherited bootstrap literal-bank backing.
    PrivateBootstrapBank,
    /// Names the actual empty installed native extension registry.
    InstalledRegistry,
    /// Names the actual native failure supervisor backing.
    NativeSupervisor,
    /// Names an actual native blob ledger backing.
    BlobLedger,
    /// Names the actual source-installed host supervisor backing.
    HostSupervisor,
    /// Names one original mutable operational deadline backing.
    OperationalDeadline,
    /// Names the actual prepared archive-mapping identity retained by restore.
    ArchivedMapping,
    /// Names the actual native Control capture identity allocation.
    NativeControlIdentity,
    /// Names the actual private retained fresh-query/Prepare attempt cell.
    NativeFreshReportAttempt,
    /// Names the real verified native Prepare attempt during input admission.
    NativeRestorePrepareAttempt,
    /// Names one actual separately funded native restoration activation cell.
    NativeRestorationActivationAttempt,
    /// Names one actual separately funded native world-content upload cell.
    NativeRestorationUploadAttempt,
}

impl MetadataSharedKind {
    /// Counts this closed wire kind and the largest local group index.
    pub(crate) fn maximum_row_encoded_bytes_data(self) -> Result<usize, ProviderError> {
        let integer = crate::connection::serialized_credit(&usize::MAX, 64)?;
        self.name()
            .len()
            .checked_add(integer)
            .and_then(|bytes| bytes.checked_add(5))
            .ok_or_else(credit)
    }

    fn name(self) -> &'static str {
        match self {
            Self::HistoricalImportPolicy => "historical-import-policy",
            Self::HistoricalImportBoot => "historical-import-boot",
            Self::HistoricalImportFrames => "historical-import-frames",
            Self::HistoricalImportBlobLedger => "historical-import-blob-ledger",
            Self::HistoricalImportExtensions => "historical-import-extensions",

            Self::NativeRestoreResponse => "native_restore_response",
            Self::NativeRestoredPhysicalHold => "native-restored-physical-hold",
            Self::NativeRestoreCommitAttempt => "native-restore-commit-attempt",
            Self::NativeRestoreInputCustody => "native-restore-input-custody",
            Self::NativeRestorationObservationAttempt => "native-restoration-observation-attempt",
            Self::NativeRestoredSuffixObservationAttempt => {
                "native-restored-suffix-observe-attempt"
            }
            Self::NativeRestoredProducerAttempt => "native-restored-producer-attempt",
            Self::NativeRestoredSettledActionAttempt => "native-restored-settled-action-attempt",
            Self::ProtocolOwner => "protocol-owner",
            Self::RegistrarEpoch => "registrar-epoch",
            Self::RegistrarGate => "registrar-gate",
            Self::SelectedExtensions => "selected-extensions",
            Self::Codec => "codec",
            Self::NativePolicy => "native-policy",
            Self::HelloBank => "hello-bank",
            Self::ContentBytes => "content-bytes",
            Self::FrameBank => "frame-bank",
            Self::NativeBoot => "native-boot",
            Self::PrivateBootstrapBank => "private-bootstrap-bank",
            Self::InstalledRegistry => "installed-registry",
            Self::NativeSupervisor => "native-supervisor",
            Self::BlobLedger => "blob-ledger",
            Self::HostSupervisor => "host-supervisor",
            Self::OperationalDeadline => "operational-deadline",
            Self::ArchivedMapping => "archived-mapping",
            Self::NativeControlIdentity => "native-control-identity",
            Self::NativeFreshReportAttempt => "native-fresh-report-attempt",
            Self::NativeRestorePrepareAttempt => "native-restore-prepare-attempt",
            Self::NativeRestorationActivationAttempt => "native-restoration-activation-attempt",
            Self::NativeRestorationUploadAttempt => "native-restoration-upload-attempt",
        }
    }
}

#[derive(Clone, Copy)]
struct AliasKey {
    kind: MetadataSharedKind,
    address: *const (),
}

#[derive(Clone, Copy)]
struct AliasRow {
    kind: MetadataSharedKind,
    first: usize,
}

/// Reports actual alias row and private temporary lookup allocations separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataAliasAllocationFacts {
    /// States the selected finite shared-view ceiling.
    pub maximum_rows: usize,
    /// Reports actual allocated encoded-row capacity.
    pub row_capacity: usize,
    /// Reports actual allocated private lookup-key capacity.
    pub lookup_capacity: usize,
    /// Counts retained historical shared edges.
    pub retained_rows: usize,
    /// Reports the encoded row vector backing bytes.
    pub row_bytes: usize,
    /// Reports the private walk-only lookup vector backing bytes.
    pub lookup_bytes: usize,
}

// The installed owner remains failed if either backing cannot be constructed.
// Existing successful constructors start Ready and retain their prior behavior.
enum ReservationState {
    Unallocated,
    Failed,
    Ready,
}

/// Owns precharged local alias rows and private walk-only lookup storage.
pub struct MetadataAliasBank {
    rows: Vec<AliasRow>,
    keys: Vec<AliasKey>,
    maximum: usize,
    comparisons: usize,
    reservation: ReservationState,
}

impl MetadataAliasBank {
    /// Bounds a row for kinds already present in this same typed alias walk.
    ///
    /// A stable full-family suffix may remove edges or change group numbers,
    /// but must not introduce another shared-root kind. Callers establish that
    /// family invariant independently; this number creates no alias permission.
    pub(crate) fn maximum_existing_kind_row_encoding_data(&self) -> Result<usize, ProviderError> {
        let name = self
            .rows
            .iter()
            .map(|row| row.kind.name().len())
            .max()
            .unwrap_or(0);
        let integer = crate::connection::serialized_credit(&usize::MAX, 64)?;
        name.checked_add(integer)
            .and_then(|bytes| bytes.checked_add(5))
            .ok_or_else(credit)
    }

    /// Reserves both fixed-capacity banks before any source state copies.
    ///
    /// # Errors
    /// Refuses zero or more than131072 rows, overflow or failed reservation.
    pub fn reserve(maximum: usize) -> Result<Self, ProviderError> {
        Self::reservation_requested_bytes(maximum)?;
        let mut rows = Vec::new();
        let mut keys = Vec::new();
        rows.try_reserve_exact(maximum).map_err(|_| credit())?;
        keys.try_reserve_exact(maximum).map_err(|_| credit())?;
        Ok(Self {
            rows,
            keys,
            maximum,
            comparisons: 0,
            reservation: ReservationState::Ready,
        })
    }

    /// Creates a validated alias-bank owner without allocating either backing.
    ///
    /// Callers install this owner before reserving so a later lookup-allocation
    /// refusal retains the earlier row allocation in the enclosing operation.
    ///
    /// # Errors
    /// Refuses zero or excessive row allowance or checked layout overflow.
    pub fn unallocated(maximum_rows: usize) -> Result<Self, ProviderError> {
        Self::reservation_requested_bytes(maximum_rows)?;
        Ok(Self {
            rows: Vec::new(),
            keys: Vec::new(),
            maximum: maximum_rows,
            comparisons: 0,
            reservation: ReservationState::Unallocated,
        })
    }

    /// Reserves both installed backings once under their exact byte quote.
    ///
    /// A refusal keeps both actual capacities in this owner and permanently
    /// closes reservation. Alias recording is enabled only after both succeed.
    /// The enclosing owner separately admits the simultaneous requested bytes;
    /// these data-only banks provide no source or native admission.
    ///
    /// # Errors
    /// Refuses a repeated attempt, insufficient backing allowance, allocation
    /// failure or actual capacity beyond either defining finite request.
    pub fn reserve_retained_data(&mut self) -> Result<(), ProviderError> {
        self.reserve_retained_with_backing_data(Self::reservation_requested_bytes(self.maximum)?)
    }

    fn reserve_retained_with_backing_data(
        &mut self,
        admitted_bytes: usize,
    ) -> Result<(), ProviderError> {
        if !matches!(self.reservation, ReservationState::Unallocated) {
            return Err(credit());
        }
        self.reservation = ReservationState::Failed;

        let row_bytes = self
            .maximum
            .checked_mul(std::mem::size_of::<AliasRow>())
            .ok_or_else(credit)?;
        if row_bytes > admitted_bytes {
            return Err(credit());
        }
        self.rows
            .try_reserve_exact(self.maximum)
            .map_err(|_| credit())?;
        if self.rows.capacity() > self.maximum {
            return Err(credit());
        }

        // Debit the retained first backing before attempting the second. A
        // lookup refusal must leave that earlier allocation inside this owner.
        let remaining = admitted_bytes
            .checked_sub(self.rows.capacity() * std::mem::size_of::<AliasRow>())
            .ok_or_else(credit)?;
        let key_bytes = self
            .maximum
            .checked_mul(std::mem::size_of::<AliasKey>())
            .ok_or_else(credit)?;
        if key_bytes > remaining {
            return Err(credit());
        }
        self.keys
            .try_reserve_exact(self.maximum)
            .map_err(|_| credit())?;
        if self.keys.capacity() > self.maximum {
            return Err(credit());
        }

        self.reservation = ReservationState::Ready;
        Ok(())
    }

    /// Quotes both requested vector backings before any alias-bank allocation.
    ///
    /// The selected row count is data only. The installed source separately
    /// admits this term with its simultaneous owners before calling reserve,
    /// then checks the actual retained capacities. Allocator rounding, container
    /// headers and traversal stack are independent terms.
    ///
    /// # Errors
    /// Refuses zero, more than 131072 rows or checked typed-layout overflow.
    pub fn reservation_requested_bytes(maximum_rows: usize) -> Result<usize, ProviderError> {
        if maximum_rows == 0 || maximum_rows > 131072 {
            return Err(credit());
        }
        let per_row = std::mem::size_of::<AliasRow>()
            .checked_add(std::mem::size_of::<AliasKey>())
            .ok_or_else(credit)?;
        maximum_rows.checked_mul(per_row).ok_or_else(credit)
    }

    /// Reports actual requested storage of both precharged vectors.
    pub fn allocated_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<AliasRow>()
            + self.keys.capacity() * std::mem::size_of::<AliasKey>()
    }

    /// Counts every recorded shared view, including repeated group edges.
    pub fn retained_rows(&self) -> usize {
        self.rows.len()
    }

    /// Reports actual row and temporary key capacities independently.
    pub fn capacity_rows(&self) -> (usize, usize) {
        (self.rows.capacity(), self.keys.capacity())
    }

    /// Reports actual row and lookup geometry without exposing lookup addresses.
    ///
    /// Both vectors retain independent rows, including empty, spare or failed
    /// backing. The enclosing owner already contains the bank's inline header.
    /// No alias group, native owner or traversal completion follows from DATA.
    pub fn retained_capacity_data(&self) -> [super::records::MetadataCapacityRecord; 2] {
        use super::records::{MetadataCapacityRecord, MetadataRecordKind};
        let Self {
            rows,
            keys,
            maximum: _,
            comparisons: _,
            reservation: _,
        } = self;
        [
            MetadataCapacityRecord {
                kind: MetadataRecordKind::Vector,
                extent: rows.capacity(),
                element_bytes: std::mem::size_of::<AliasRow>(),
                alignment: std::mem::align_of::<AliasRow>(),
            },
            MetadataCapacityRecord {
                kind: MetadataRecordKind::Vector,
                extent: keys.capacity(),
                element_bytes: std::mem::size_of::<AliasKey>(),
                alignment: std::mem::align_of::<AliasKey>(),
            },
        ]
    }

    /// Names the actual bank, private vector loans and returned row controls.
    pub const fn retained_capacity_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&Vec<AliasRow>>()
            + std::mem::size_of::<&Vec<AliasKey>>()
            + std::mem::size_of::<[super::records::MetadataCapacityRecord; 2]>()
    }

    /// Reads the two actual precharged vector capacities without copying rows.
    pub fn allocation_facts(&self) -> MetadataAliasAllocationFacts {
        let (row_capacity, lookup_capacity) = self.capacity_rows();
        MetadataAliasAllocationFacts {
            maximum_rows: self.maximum,
            row_capacity,
            lookup_capacity,
            retained_rows: self.retained_rows(),
            row_bytes: self.rows.capacity() * std::mem::size_of::<AliasRow>(),
            lookup_bytes: self.keys.capacity() * std::mem::size_of::<AliasKey>(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.rows.clear();
        self.keys.clear();
        self.comparisons = 0;
    }

    pub(crate) fn retain<T: ?Sized>(
        &mut self,
        kind: MetadataSharedKind,
        backing: &T,
    ) -> Result<(), ProviderError> {
        if !matches!(self.reservation, ReservationState::Ready)
            || self.rows.len() >= self.maximum
            || self.rows.len() == self.rows.capacity()
        {
            return Err(credit());
        }
        // Addresses are comparison keys only. Neither serialization nor callers
        // can obtain them, and no raw pointer is ever dereferenced here.
        let address = std::ptr::from_ref(backing).cast::<()>();
        let mut existing = None;
        for (index, key) in self.keys.iter().enumerate() {
            self.comparisons = self.comparisons.checked_add(1).ok_or_else(credit)?;
            if self.comparisons > 64 * 1024 * 1024 {
                return Err(credit());
            }
            if key.kind == kind && key.address == address {
                existing = Some(index);
                break;
            }
        }
        let first = if let Some(index) = existing {
            index
        } else {
            if self.keys.len() == self.keys.capacity() {
                return Err(credit());
            }
            let index = self.keys.len();
            self.keys.push(AliasKey { kind, address });
            index
        };
        self.rows.push(AliasRow { kind, first });
        Ok(())
    }

    pub(crate) fn finish_lookup(&mut self) {
        // Historical numeric edges remain; transient process addresses do not.
        self.keys.clear();
    }
}

impl Serialize for MetadataAliasBank {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.rows.len()))?;
        for row in &self.rows {
            rows.serialize_element(&(row.kind.name(), row.first))?;
        }
        rows.end()
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("whole protocol alias roster")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "alias fixtures preserve original backing identity and spare allocation"
)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn shared_alias_and_equal_distinct_empty_backings_have_different_groups() {
        let first = Rc::new(Vec::<u8>::with_capacity(19));
        let alias = first.clone();
        let distinct = Rc::new(Vec::<u8>::with_capacity(19));
        let mut bank = MetadataAliasBank::reserve(4).unwrap();
        let capacities = bank.capacity_rows();
        bank.retain(MetadataSharedKind::ContentBytes, first.as_ref())
            .unwrap();
        bank.retain(MetadataSharedKind::ContentBytes, alias.as_ref())
            .unwrap();
        bank.retain(MetadataSharedKind::ContentBytes, distinct.as_ref())
            .unwrap();
        bank.finish_lookup();

        assert_eq!(bank.capacity_rows(), capacities);
        assert_eq!(bank.keys.len(), 0);
        assert_eq!(
            serde_json::to_vec(&bank).unwrap(),
            br#"[["content-bytes",0],["content-bytes",0],["content-bytes",1]]"#
        );
        assert_eq!(bank.allocation_facts().retained_rows, 3);
    }

    #[test]
    fn fixed_row_exhaustion_preserves_prior_edges_and_capacities() {
        let first = Rc::new(7u64);
        let second = Rc::new(7u64);
        let mut bank = MetadataAliasBank::reserve(1).unwrap();
        bank.retain(MetadataSharedKind::RegistrarEpoch, first.as_ref())
            .unwrap();
        let before = serde_json::to_vec(&bank).unwrap();
        let allocation = bank.allocation_facts();
        assert!(
            bank.retain(MetadataSharedKind::RegistrarEpoch, second.as_ref())
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&bank).unwrap(), before);
        assert_eq!(bank.allocation_facts(), allocation);
    }
}

/// Reports exact inline layouts of the retained alias row and walk lookup key.
///
/// Allocation headers, alignment and allocator geometry remain separate facts.
pub(crate) const fn original_metadata_alias_layouts() -> (usize, usize) {
    (
        std::mem::size_of::<AliasRow>(),
        std::mem::size_of::<AliasKey>(),
    )
}

impl MetadataAliasBank {
    pub(crate) fn retained_rows_of_kind(&self, kind: MetadataSharedKind) -> usize {
        self.rows.iter().filter(|row| row.kind == kind).count()
    }
}

// crucible-lint: allow panic-shortcut -- exact actual wire widths are fixture observations.
#[cfg(test)]
#[test]
#[expect(
    clippy::unwrap_used,
    reason = "actual alias-row serialization is the test observation"
)]
fn maximum_alias_row_width_matches_actual_current_kind_and_usize() {
    let kind = MetadataSharedKind::NativeControlIdentity;
    let row = serde_json::to_vec(&(kind.name(), usize::MAX)).unwrap();
    assert_eq!(kind.maximum_row_encoded_bytes_data().unwrap(), row.len());
    let smaller = serde_json::to_vec(&(kind.name(), 0usize)).unwrap();
    assert!(smaller.len() <= row.len());
}

impl MetadataAliasBank {
    /// Borrows the complete alias-bank state without encoding process addresses.
    ///
    /// Lookup positions retain only their closed kind and local order. They
    /// cannot recreate live backing identities or continue a native walk.
    pub(crate) fn borrowed_settled17_bank_data(&self) -> impl Serialize + '_ {
        (
            self.maximum,
            self.rows.capacity(),
            self.keys.capacity(),
            self,
            crate::protocol_snapshot::Sequence(|| self.keys.iter().map(|key| key.kind.name())),
            self.comparisons,
        )
    }

    /// Records both actual typed vector capacities without observing addresses.
    ///
    /// # Errors
    /// Refuses metadata bank exhaustion or checked capacity overflow.
    pub(crate) fn observe_settled17_bank_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<AliasRow>(self.rows.capacity())?;
        observer.vector::<AliasKey>(self.keys.capacity())
    }
}

/// Reports alias row/key size and alignment for their exact historical banks.
pub(crate) const fn settled17_alias_bank_layouts_data() -> [(usize, usize); 2] {
    [
        (
            std::mem::size_of::<AliasRow>(),
            std::mem::align_of::<AliasRow>(),
        ),
        (
            std::mem::size_of::<AliasKey>(),
            std::mem::align_of::<AliasKey>(),
        ),
    ]
}

impl MetadataAliasBank {
    /// Reports initialized walk-only lookup entries without exposing addresses.
    pub(crate) fn current17_initialized_lookup_entries_data(&self) -> usize {
        self.keys.len()
    }

    /// Observes the actual row and lookup capacities as historical storage DATA.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked native-layout overflow.
    pub(crate) fn observe_current17_storage_data(
        &self,
        observer: &mut super::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Self::observe_current17_capacities_data(
            self.rows.capacity(),
            self.keys.capacity(),
            observer,
        )
    }

    /// Observes copied capacities from a defining active-recorder cut.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked native-layout overflow.
    pub(crate) fn observe_current17_capacities_data(
        rows: usize,
        lookups: usize,
        observer: &mut super::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<AliasRow>(rows)?;
        observer.vector::<AliasKey>(lookups)
    }
}

#[cfg(test)]
mod retained_owner_tests {
    use super::*;

    #[test]
    fn installed_alias_owner_reserves_once_and_preserves_completed_edges()
    -> Result<(), ProviderError> {
        assert!(MetadataAliasBank::unallocated(0).is_err());
        assert!(MetadataAliasBank::unallocated(131_073).is_err());
        let mut bank = MetadataAliasBank::unallocated(7)?;
        assert_eq!(bank.capacity_rows(), (0, 0));
        assert_eq!(bank.allocated_bytes(), 0);
        assert!(
            bank.retain(MetadataSharedKind::RegistrarEpoch, &3u64)
                .is_err()
        );

        bank.reserve_retained_data()?;
        assert_eq!(bank.capacity_rows(), (7, 7));
        assert_eq!(
            bank.allocated_bytes(),
            MetadataAliasBank::reservation_requested_bytes(7)?
        );
        bank.retain(MetadataSharedKind::RegistrarEpoch, &3u64)?;
        let rows = bank.rows.as_ptr();
        let keys = bank.keys.as_ptr();
        let facts = bank.allocation_facts();
        assert!(bank.reserve_retained_data().is_err());
        assert_eq!(bank.allocation_facts(), facts);
        assert_eq!(bank.rows.as_ptr(), rows);
        assert_eq!(bank.keys.as_ptr(), keys);
        assert_eq!(bank.rows[0].first, 0);
        assert_eq!(bank.keys.len(), 1);
        Ok(())
    }

    #[test]
    fn late_lookup_debit_refusal_retains_row_allocation_and_actual_census()
    -> Result<(), ProviderError> {
        let mut bank = MetadataAliasBank::unallocated(7)?;
        let required = MetadataAliasBank::reservation_requested_bytes(7)?;

        // This admits the actual row bank but falls one byte short of its
        // independently required lookup bank. No allocator failure is faked.
        assert!(
            bank.reserve_retained_with_backing_data(required - 1)
                .is_err()
        );
        assert!(matches!(bank.reservation, ReservationState::Failed));
        assert_eq!(bank.capacity_rows(), (7, 0));
        assert!(bank.rows.is_empty() && bank.keys.is_empty());
        let pointer = bank.rows.as_ptr();
        let allocation = bank.allocation_facts();
        assert_eq!(allocation.row_bytes, 7 * std::mem::size_of::<AliasRow>());
        assert_eq!(allocation.lookup_bytes, 0);

        let mut observer = crate::retained_metadata::MetadataObserver::new();
        bank.observe_current17_storage_data(&mut observer)?;
        let facts = observer.finish();
        assert_eq!(facts.vector_banks, 2);
        assert_eq!(facts.vector_capacity_bytes, bank.allocated_bytes());
        assert_eq!(facts.vector_capacity_bytes, allocation.row_bytes);

        bank.clear();
        assert!(bank.reserve_retained_data().is_err());
        assert!(
            bank.retain(MetadataSharedKind::RegistrarEpoch, &3u64)
                .is_err()
        );
        assert_eq!(bank.rows.as_ptr(), pointer);
        assert_eq!(bank.allocation_facts(), allocation);
        Ok(())
    }
}

#[cfg(test)]
mod bank_capacity_data_tests {
    use super::super::records::MetadataRecordKind;
    use super::*;

    #[test]
    fn original_alias_backing_keeps_both_private_layouts_and_edges() -> Result<(), ProviderError> {
        let mut bank = MetadataAliasBank::reserve(7)?;
        let original = 23u64;
        bank.retain(MetadataSharedKind::RegistrarEpoch, &original)?;
        bank.retain(MetadataSharedKind::RegistrarEpoch, &original)?;
        let pointers = (bank.rows.as_ptr(), bank.keys.as_ptr());
        let capacities = bank.capacity_rows();
        let comparisons = bank.comparisons;

        let rows = bank.retained_capacity_data();

        for row in rows {
            row.validate_data()?;
            assert_eq!(row.kind, MetadataRecordKind::Vector);
        }
        assert_eq!((rows[0].extent, rows[1].extent), capacities);
        assert_eq!(rows[0].element_bytes, std::mem::size_of::<AliasRow>());
        assert_eq!(rows[0].alignment, std::mem::align_of::<AliasRow>());
        assert_eq!(rows[1].element_bytes, std::mem::size_of::<AliasKey>());
        assert_eq!(rows[1].alignment, std::mem::align_of::<AliasKey>());
        assert_eq!(
            rows.into_iter()
                .map(|row| row.extent * row.element_bytes)
                .sum::<usize>(),
            bank.allocated_bytes()
        );
        assert_eq!((bank.rows.as_ptr(), bank.keys.as_ptr()), pointers);
        assert_eq!(bank.comparisons, comparisons);
        assert_eq!(bank.retained_rows(), 2);
        assert_eq!(bank.keys.len(), 1);
        assert!(bank.rows.iter().all(|row| row.first == 0));
        Ok(())
    }

    #[test]
    fn refused_alias_backing_stays_failed_after_capacity_observation() -> Result<(), ProviderError>
    {
        let mut bank = MetadataAliasBank::unallocated(7)?;
        let before = bank.retained_capacity_data();
        assert!(bank.reserve_retained_with_backing_data(0).is_err());

        let after = bank.retained_capacity_data();

        assert_eq!(before, after);
        assert!(
            after
                .into_iter()
                .all(|row| row.extent == 0 && row.element_bytes > 0)
        );
        assert!(matches!(bank.reservation, ReservationState::Failed));
        assert!(bank.reserve_retained_data().is_err());
        assert_eq!(bank.retained_rows(), 0);
        Ok(())
    }
}
