//! Records actual metadata capacities in a caller-precharged edition-eleven bank.
//!
//! The exhaustive typed walker supplies rows in its fixed field traversal order.
//! Decoding these rows yields data only: source and native associations are never
//! reconstructed from allocation numbers. Hidden tree/control-block geometry and
//! compiler/thread stack require independent admission.
//!
//! ```json
//! [["string",64,1,1],["vector",16,8,8],["tree",2,48,8],["shared",80,1,8]]
//! ```

use crate::ProviderError;
use serde::{Serialize, Serializer, ser::SerializeSeq};

mod packet_runtime;
pub use packet_runtime::{
    PACKET_RUNTIME_METADATA_RECORD_FORMAT, PacketRuntimeMetadataRecordBank,
    PacketRuntimeMetadataReservationData, ValidatedPacketRuntimeMetadataRecords,
};

const MAXIMUM_ROWS: usize = 131_072;

/// Names the explicit four-field capacity roster required by current whole11.
///
/// Older three-field rosters lack actual alignment and must not be enrolled by
/// a complete-state factory using this implementation/schema identity.
pub const METADATA_CAPACITY_RECORD_FORMAT: &str = "source-private.capacity-record-alignment/11";

/// Names one capacity or container observation in the typed metadata walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataRecordKind {
    /// Records an original String or Id byte capacity.
    String,
    /// Records an original Vec or Bytes element capacity.
    Vector,
    /// Records an initialized tree population and entry layout.
    Tree,
    /// Records a shared backing view, without deduplication credit.
    Shared,
    /// Records one independently owned boxed value.
    Boxed,
}

impl MetadataRecordKind {
    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Vector => "vector",
            Self::Tree => "tree",
            Self::Shared => "shared",
            Self::Boxed => "boxed",
        }
    }
}

/// Records original capacity or population with its actual element layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataCapacityRecord {
    /// Identifies the typed observation category.
    pub kind: MetadataRecordKind,
    /// Reports original capacity, entry population or backing byte extent.
    pub extent: usize,
    /// Reports the actual element or entry layout; byte extents use one.
    pub element_bytes: usize,
    /// Reports actual element or payload alignment, even when its size is zero.
    pub alignment: usize,
}

impl MetadataCapacityRecord {
    /// Checks the defining scalar layout without interpreting it as ownership.
    ///
    /// # Errors
    /// Refuses unsupported alignment, a non-byte String/shared/boxed record or
    /// an overflowing capacity times element size.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if !self.alignment.is_power_of_two()
            || self.alignment > isize::MAX as usize
            || (self.kind == MetadataRecordKind::String && self.alignment != 1)
        {
            return Err(invalid());
        }
        if self.kind != MetadataRecordKind::Vector
            && self.kind != MetadataRecordKind::Tree
            && self.element_bytes != 1
        {
            return Err(invalid());
        }
        self.extent
            .checked_mul(self.element_bytes)
            .ok_or_else(invalid)?;
        Ok(())
    }
}

impl Serialize for MetadataCapacityRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            &self.kind.name(),
            self.extent,
            self.element_bytes,
            self.alignment,
        )
            .serialize(serializer)
    }
}

// A retained constructor marks failure before its first fallible allocation.
// Neither clearing rows nor repeating reservation can reopen that attempt.
enum ReservationState {
    Unallocated,
    Failed,
    Ready,
}

/// Retains a finite caller-precharged record bank without growth during walking.
pub struct MetadataRecordBank {
    rows: Vec<MetadataCapacityRecord>,
    maximum_rows: usize,
    reservation: ReservationState,
}

impl MetadataRecordBank {
    /// Reserves record storage before snapshot copying or child construction.
    ///
    /// # Errors
    /// Refuses zero or excessive row allowance, layout overflow or allocation
    /// failure. This reservation supplies no source or native admission.
    pub fn reserve(maximum_rows: usize) -> Result<Self, ProviderError> {
        if maximum_rows == 0 || maximum_rows > MAXIMUM_ROWS {
            return Err(credit());
        }
        maximum_rows
            .checked_mul(std::mem::size_of::<MetadataCapacityRecord>())
            .ok_or_else(credit)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(maximum_rows).map_err(|_| credit())?;
        Ok(Self {
            rows,
            maximum_rows,
            reservation: ReservationState::Ready,
        })
    }

    /// Creates a validated record-bank owner without allocating its backing.
    ///
    /// Callers install this owner before reserving so a refused construction
    /// retains its actual storage until the enclosing operation resolves.
    ///
    /// # Errors
    /// Refuses zero or excessive row allowance or checked layout overflow.
    pub fn unallocated(maximum_rows: usize) -> Result<Self, ProviderError> {
        Self::reservation_requested_bytes(maximum_rows)?;
        Ok(Self {
            rows: Vec::new(),
            maximum_rows,
            reservation: ReservationState::Unallocated,
        })
    }

    /// Quotes the exact requested record-vector backing before allocation.
    ///
    /// The enclosing owner admits this term with its simultaneous allocations.
    /// Container headers and allocator geometry remain separate terms.
    ///
    /// # Errors
    /// Refuses zero or excessive row allowance or checked layout overflow.
    pub fn reservation_requested_bytes(maximum_rows: usize) -> Result<usize, ProviderError> {
        if maximum_rows == 0 || maximum_rows > MAXIMUM_ROWS {
            return Err(credit());
        }
        maximum_rows
            .checked_mul(std::mem::size_of::<MetadataCapacityRecord>())
            .ok_or_else(credit)
    }

    /// Reserves the installed owner's backing once under its exact byte quote.
    ///
    /// A refusal keeps every allocated backing in this owner and permanently
    /// closes reservation. Walking is enabled only after full success. This
    /// method supplies storage DATA, without source or native admission.
    ///
    /// # Errors
    /// Refuses a repeated attempt, insufficient backing allowance, allocation
    /// failure or actual capacity beyond the defining finite request.
    pub fn reserve_retained_data(&mut self) -> Result<(), ProviderError> {
        self.reserve_retained_with_backing_data(Self::reservation_requested_bytes(
            self.maximum_rows,
        )?)
    }

    fn reserve_retained_with_backing_data(
        &mut self,
        admitted_bytes: usize,
    ) -> Result<(), ProviderError> {
        if !matches!(self.reservation, ReservationState::Unallocated) {
            return Err(credit());
        }
        self.reservation = ReservationState::Failed;

        let requested = Self::reservation_requested_bytes(self.maximum_rows)?;
        if requested > admitted_bytes {
            return Err(credit());
        }
        self.rows
            .try_reserve_exact(self.maximum_rows)
            .map_err(|_| credit())?;
        if self.rows.capacity() > self.maximum_rows {
            return Err(credit());
        }

        self.reservation = ReservationState::Ready;
        Ok(())
    }

    /// Reports actual retained record capacity in bytes, including spare rows.
    pub fn allocated_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<MetadataCapacityRecord>()
    }

    /// Reports the finite selected row allowance.
    pub fn maximum_rows(&self) -> usize {
        self.maximum_rows
    }

    /// Reports actual row capacity, including unused precharged storage.
    pub fn capacity_rows(&self) -> usize {
        self.rows.capacity()
    }

    /// Reports the actual record-vector geometry, including unused backing.
    ///
    /// The enclosing owner already contains this bank's inline header. The row
    /// describes backing only, even after failed reservation, and neither reads
    /// recorded contents nor establishes traversal completion.
    pub fn retained_capacity_data(&self) -> MetadataCapacityRecord {
        let Self {
            rows,
            maximum_rows: _,
            reservation: _,
        } = self;
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: rows.capacity(),
            element_bytes: std::mem::size_of::<MetadataCapacityRecord>(),
            alignment: std::mem::align_of::<MetadataCapacityRecord>(),
        }
    }

    /// Observes this bank's actual backing without interpreting recorded rows.
    pub(crate) fn observe_retained_capacity_data(
        &self,
        observer: &mut super::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            rows,
            maximum_rows,
            reservation,
        } = self;
        observer.vector::<MetadataCapacityRecord>(rows.capacity())?;
        observer.observe(maximum_rows)?;
        match reservation {
            ReservationState::Unallocated | ReservationState::Failed | ReservationState::Ready => {}
        }
        Ok(())
    }

    /// Names the actual bank, vector loan and returned capacity-row controls.
    pub const fn retained_capacity_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&Vec<MetadataCapacityRecord>>()
            + std::mem::size_of::<MetadataCapacityRecord>()
    }

    /// Borrows the complete recorded traversal without copying rows.
    pub fn rows(&self) -> &[MetadataCapacityRecord] {
        &self.rows
    }

    pub(crate) fn clear(&mut self) {
        self.rows.clear();
    }

    pub(crate) fn append(&mut self, row: MetadataCapacityRecord) -> Result<(), ProviderError> {
        if !matches!(self.reservation, ReservationState::Ready)
            || self.rows.len() >= self.maximum_rows
            || self.rows.len() >= self.rows.capacity()
        {
            return Err(credit());
        }
        self.rows.push(row);
        Ok(())
    }
}

impl Serialize for MetadataRecordBank {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.rows.len()))?;
        for row in &self.rows {
            sequence.serialize_element(row)?;
        }
        sequence.end()
    }
}

/// Retains fully checked borrowed capacity rows without allocating an owner.
pub struct ValidatedMetadataRecords<'a> {
    input: &'a [u8],
    rows: usize,
    backing_capacity_bytes: usize,
}

impl<'a> ValidatedMetadataRecords<'a> {
    /// Validates the full closed roster before any metadata ownership copy.
    ///
    /// String and vector extents contribute to the explicit backing allowance.
    /// Tree and shared observations retain their separate physical admission
    /// obligations; this data validator does not calculate allocator geometry.
    ///
    /// # Errors
    /// Refuses malformed or trailing grammar, invalid layouts, overflow,
    /// excessive rows or insufficient String/vector backing credit.
    pub fn validate(
        input: &'a [u8],
        maximum_rows: usize,
        maximum_backing_capacity_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_rows > MAXIMUM_ROWS {
            return Err(credit());
        }
        let mut cursor = Cursor::new(input);
        let (rows, backing_capacity_bytes) =
            cursor.records(maximum_rows, maximum_backing_capacity_bytes)?;
        if cursor.position != input.len() {
            return Err(invalid());
        }
        Ok(Self {
            input,
            rows,
            backing_capacity_bytes,
        })
    }

    /// Reports the admitted row population.
    pub fn row_count(&self) -> usize {
        self.rows
    }

    /// Reports separately admitted String and vector backing capacities.
    pub fn backing_capacity_bytes(&self) -> usize {
        self.backing_capacity_bytes
    }

    /// Replays the validated immutable roster in typed traversal order.
    pub fn rows(&self) -> MetadataRecordRows<'a> {
        MetadataRecordRows {
            cursor: Cursor {
                input: self.input,
                position: 1,
            },
            remaining: self.rows,
            first: true,
        }
    }
}

/// Replays checked capacity data without creating strings or metadata owners.
#[derive(Clone)]
pub struct MetadataRecordRows<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
    first: bool,
}

impl<'a> MetadataRecordRows<'a> {
    pub(crate) fn encoded_position(&self) -> usize {
        self.cursor.position
    }

    /// Borrows consumed row bytes independently of their position in the bank.
    ///
    /// The start comes from an earlier `encoded_position` on this row cursor.
    /// Subsequent rows consume a bank separator before their own encoding. That
    /// one leading comma is outside the selected span; separators between its
    /// rows remain part of the shared-view identity.
    pub(crate) fn encoded_between(&self, start: usize) -> Result<&'a [u8], ProviderError> {
        let encoded = self
            .cursor
            .input
            .get(start..self.cursor.position)
            .ok_or_else(invalid)?;
        Ok(encoded.strip_prefix(b",").unwrap_or(encoded))
    }
}

impl Iterator for MetadataRecordRows<'_> {
    type Item = Result<MetadataCapacityRecord, ProviderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let result = (|| {
            if !self.first {
                self.cursor.literal(b",")?;
            }
            self.cursor.row()
        })();
        self.first = false;
        self.remaining -= 1;
        Some(result)
    }
}

#[derive(Clone)]
struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ProviderError> {
        let end = self
            .position
            .checked_add(expected.len())
            .ok_or_else(invalid)?;
        if self.input.get(self.position..end) != Some(expected) {
            return Err(invalid());
        }
        self.position = end;
        Ok(())
    }

    fn number(&mut self) -> Result<usize, ProviderError> {
        let first = self.peek().ok_or_else(invalid)?;
        if !first.is_ascii_digit() {
            return Err(invalid());
        }
        self.position += 1;
        let mut value = usize::from(first - b'0');
        while let Some(next) = self.peek().filter(u8::is_ascii_digit) {
            if first == b'0' {
                return Err(invalid());
            }
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(usize::from(next - b'0')))
                .ok_or_else(invalid)?;
            self.position += 1;
        }
        Ok(value)
    }

    fn records(
        &mut self,
        maximum_rows: usize,
        maximum_backing_capacity_bytes: usize,
    ) -> Result<(usize, usize), ProviderError> {
        let mut rows = 0usize;
        let mut backing_capacity_bytes = 0usize;
        self.literal(b"[")?;
        while self.peek() != Some(b']') {
            if rows != 0 {
                self.literal(b",")?;
            }
            let row = self.row()?;
            rows = rows.checked_add(1).ok_or_else(credit)?;
            if rows > maximum_rows {
                return Err(credit());
            }
            if matches!(
                row.kind,
                MetadataRecordKind::String | MetadataRecordKind::Vector
            ) {
                backing_capacity_bytes = backing_capacity_bytes
                    .checked_add(
                        row.extent
                            .checked_mul(row.element_bytes)
                            .ok_or_else(credit)?,
                    )
                    .ok_or_else(credit)?;
                if backing_capacity_bytes > maximum_backing_capacity_bytes {
                    return Err(credit());
                }
            }
        }
        self.literal(b"]")?;
        Ok((rows, backing_capacity_bytes))
    }

    fn row(&mut self) -> Result<MetadataCapacityRecord, ProviderError> {
        self.literal(b"[\"")?;
        let kind = if self
            .input
            .get(self.position..)
            .is_some_and(|tail| tail.starts_with(b"string\""))
        {
            self.literal(b"string\"")?;
            MetadataRecordKind::String
        } else if self
            .input
            .get(self.position..)
            .is_some_and(|tail| tail.starts_with(b"vector\""))
        {
            self.literal(b"vector\"")?;
            MetadataRecordKind::Vector
        } else if self
            .input
            .get(self.position..)
            .is_some_and(|tail| tail.starts_with(b"tree\""))
        {
            self.literal(b"tree\"")?;
            MetadataRecordKind::Tree
        } else if self
            .input
            .get(self.position..)
            .is_some_and(|tail| tail.starts_with(b"shared\""))
        {
            self.literal(b"shared\"")?;
            MetadataRecordKind::Shared
        } else if self
            .input
            .get(self.position..)
            .is_some_and(|tail| tail.starts_with(b"boxed\""))
        {
            self.literal(b"boxed\"")?;
            MetadataRecordKind::Boxed
        } else {
            return Err(invalid());
        };
        self.literal(b",")?;
        let extent = self.number()?;
        self.literal(b",")?;
        let element_bytes = self.number()?;
        self.literal(b",")?;
        let alignment = self.number()?;
        self.literal(b"]")?;
        let record = MetadataCapacityRecord {
            kind,
            extent,
            element_bytes,
            alignment,
        };
        record.validate_data()?;
        Ok(record)
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("owned metadata capacity roster")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("owned metadata capacity roster")
}

impl MetadataRecordBank {
    /// Observes the actual retained capacity without visiting a growing walk.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked native-layout overflow.
    pub(crate) fn observe_current17_storage_data(
        &self,
        observer: &mut super::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<MetadataCapacityRecord>(self.rows.capacity())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "capacity-row span fixture assertions")]
mod encoded_span_tests {
    use super::*;

    #[test]
    fn first_and_later_single_row_spans_have_the_same_identity() {
        let input = br#"[["shared",24,1,8],["shared",24,1,8],["shared",24,1,8]]"#;
        let bank = ValidatedMetadataRecords::validate(input, 3, 0).unwrap();
        let mut rows = bank.rows();
        let mut first = None;
        for _ in 0..3 {
            let start = rows.encoded_position();
            assert_eq!(rows.encoded_between(start).unwrap(), b"");
            rows.next().unwrap().unwrap();
            let span = rows.encoded_between(start).unwrap();
            assert_eq!(span, br#"["shared",24,1,8]"#);
            if let Some(first) = first {
                assert_eq!(span, first);
            } else {
                first = Some(span);
            }
        }
        assert!(rows.next().is_none());
        assert!(rows.encoded_between(usize::MAX).is_err());
    }

    #[test]
    fn multi_row_spans_keep_internal_separators_and_complete_row_bytes() {
        let input = br#"[["shared",24,1,8],["vector",19,1,1],["shared",24,1,8],["vector",19,1,1],["vector",20,1,1]]"#;
        let bank = ValidatedMetadataRecords::validate(input, 5, 58).unwrap();
        let mut rows = bank.rows();
        let first_start = rows.encoded_position();
        rows.next().unwrap().unwrap();
        rows.next().unwrap().unwrap();
        let first = rows.encoded_between(first_start).unwrap();
        assert_eq!(first, br#"["shared",24,1,8],["vector",19,1,1]"#);

        let later_start = rows.encoded_position();
        rows.next().unwrap().unwrap();
        rows.next().unwrap().unwrap();
        assert_eq!(rows.encoded_between(later_start).unwrap(), first);
        rows.next().unwrap().unwrap();
        assert_eq!(
            rows.encoded_between(later_start).unwrap(),
            br#"["shared",24,1,8],["vector",19,1,1],["vector",20,1,1]"#,
        );
        assert!(rows.next().is_none());
    }
}

#[cfg(test)]
mod retained_owner_tests {
    use super::*;

    fn row() -> MetadataCapacityRecord {
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: 19,
            element_bytes: 1,
            alignment: 1,
        }
    }

    #[test]
    fn installed_record_owner_has_no_backing_until_reservation_succeeds()
    -> Result<(), ProviderError> {
        assert!(MetadataRecordBank::unallocated(0).is_err());
        assert!(MetadataRecordBank::unallocated(MAXIMUM_ROWS + 1).is_err());
        let mut bank = MetadataRecordBank::unallocated(7)?;
        assert_eq!(bank.maximum_rows(), 7);
        assert_eq!(bank.capacity_rows(), 0);
        assert_eq!(bank.allocated_bytes(), 0);
        assert!(bank.append(row()).is_err());

        bank.reserve_retained_data()?;
        assert_eq!(bank.capacity_rows(), 7);
        assert_eq!(
            bank.allocated_bytes(),
            MetadataRecordBank::reservation_requested_bytes(7)?
        );
        bank.append(row())?;
        let pointer = bank.rows.as_ptr();
        let capacity = bank.capacity_rows();
        assert!(bank.reserve_retained_data().is_err());
        assert_eq!(bank.rows(), &[row()]);
        assert_eq!(bank.rows.as_ptr(), pointer);
        assert_eq!(bank.capacity_rows(), capacity);

        let mut observer = crate::retained_metadata::MetadataObserver::new();
        bank.observe_current17_storage_data(&mut observer)?;
        let facts = observer.finish();
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.vector_capacity_bytes, bank.allocated_bytes());
        Ok(())
    }

    #[test]
    fn refused_record_debit_is_sticky_and_cannot_be_reopened_by_clear() -> Result<(), ProviderError>
    {
        let mut bank = MetadataRecordBank::unallocated(7)?;
        let required = MetadataRecordBank::reservation_requested_bytes(7)?;
        assert!(
            bank.reserve_retained_with_backing_data(required - 1)
                .is_err()
        );
        assert!(matches!(bank.reservation, ReservationState::Failed));
        assert_eq!(bank.allocated_bytes(), 0);

        bank.clear();
        assert!(bank.reserve_retained_data().is_err());
        assert!(bank.append(row()).is_err());
        assert_eq!(bank.capacity_rows(), 0);
        assert!(bank.rows().is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod bank_capacity_data_tests {
    use super::*;

    #[test]
    fn original_record_backing_keeps_spare_rows_and_contents() -> Result<(), ProviderError> {
        let mut bank = MetadataRecordBank::reserve(7)?;
        let row = MetadataCapacityRecord {
            kind: MetadataRecordKind::String,
            extent: 37,
            element_bytes: 1,
            alignment: 1,
        };
        bank.append(row)?;
        let pointer = bank.rows.as_ptr();

        let geometry = bank.retained_capacity_data();

        geometry.validate_data()?;
        assert_eq!(geometry.kind, MetadataRecordKind::Vector);
        assert_eq!(geometry.extent, bank.capacity_rows());
        assert_eq!(
            geometry.element_bytes,
            std::mem::size_of::<MetadataCapacityRecord>()
        );
        assert_eq!(
            geometry.alignment,
            std::mem::align_of::<MetadataCapacityRecord>()
        );
        assert_eq!(
            geometry.extent * geometry.element_bytes,
            bank.allocated_bytes()
        );
        assert_eq!(bank.rows(), &[row]);
        assert_eq!(bank.rows.as_ptr(), pointer);
        assert!(geometry.extent > bank.rows.len());
        Ok(())
    }

    #[test]
    fn refused_record_backing_stays_failed_after_capacity_observation() -> Result<(), ProviderError>
    {
        let mut bank = MetadataRecordBank::unallocated(7)?;
        let before = bank.retained_capacity_data();
        assert!(bank.reserve_retained_with_backing_data(0).is_err());

        let after = bank.retained_capacity_data();

        assert_eq!(before, after);
        assert_eq!(after.extent, 0);
        assert_ne!(after.element_bytes, 0);
        assert!(matches!(bank.reservation, ReservationState::Failed));
        assert!(bank.reserve_retained_data().is_err());
        Ok(())
    }
}
