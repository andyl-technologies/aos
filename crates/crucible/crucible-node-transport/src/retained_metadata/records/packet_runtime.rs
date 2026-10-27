//! Retains and reads the packet runtime's separately selected physical record bank.
//!
//! ```json
//! {"capacity_rows":2,"format":"source-private.packet-runtime-metadata-bank/18","maximum_rows":2,"reservation":"ready","rows":[["string",4,1,1]]}
//! ```
//!
//! The enclosing Source independently admits allocation and authenticates its
//! complete historical object. This physical DATA cannot issue a Source action,
//! prove traversal completion or reconstruct live authority. Legacy record
//! constructors and readers retain their original population limit and grammar.

use super::*;
use crate::client::PacketRuntimeFutureStorageData;
use serde::ser::SerializeStruct;
use std::{alloc::Layout, mem::size_of};

/// Names the distinct physical bank header while preserving four-field rows.
pub const PACKET_RUNTIME_METADATA_RECORD_FORMAT: &str =
    "source-private.packet-runtime-metadata-bank/18";

/// Reports allocation history without granting traversal or Source authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRuntimeMetadataReservationData {
    /// Reports an installed owner whose backing has not been requested.
    Unallocated,
    /// Reports a permanently closed failed reservation, including retained backing.
    Failed,
    /// Reports completed backing reservation, independently of walk completion.
    Ready,
}

impl PacketRuntimeMetadataReservationData {
    fn name(self) -> &'static str {
        match self {
            Self::Unallocated => "unallocated",
            Self::Failed => "failed",
            Self::Ready => "ready",
        }
    }
}

/// Owns the quoted packet runtime record population through failed construction.
///
/// Its transparent header has the exact layout already priced by the SDK row.
/// The quote supplies a population restriction only. The actual Source must
/// authenticate and spend its admission before requesting this owner's backing.
#[repr(transparent)]
pub struct PacketRuntimeMetadataRecordBank {
    bank: MetadataRecordBank,
}

impl PacketRuntimeMetadataRecordBank {
    /// Creates the quoted empty owner before its first allocation attempt.
    ///
    /// # Errors
    /// Refuses a zero population or an invalid record-vector allocation layout.
    pub fn unallocated(funding: &PacketRuntimeFutureStorageData) -> Result<Self, ProviderError> {
        let maximum_rows = funding.metadata_capacity_rows_data();
        record_bytes(maximum_rows)?;
        Ok(Self {
            bank: MetadataRecordBank {
                rows: Vec::new(),
                maximum_rows,
                reservation: ReservationState::Unallocated,
            },
        })
    }

    /// Quotes exact vector backing independently of headers and allocator rounding.
    ///
    /// # Errors
    /// Refuses zero rows or record-vector allocation layout overflow.
    pub fn reservation_requested_bytes_data(
        funding: &PacketRuntimeFutureStorageData,
    ) -> Result<usize, ProviderError> {
        record_bytes(funding.metadata_capacity_rows_data())
    }

    /// Reserves the installed bank once without changing its selected population.
    ///
    /// Failure remains sticky and retains every actual allocation. A Source
    /// admission is independently required; copied funding DATA supplies none.
    ///
    /// # Errors
    /// Refuses a repeated attempt, invalid layout, allocation failure or actual
    /// capacity exceeding the quoted request.
    pub fn reserve_retained_data(&mut self) -> Result<(), ProviderError> {
        let requested = record_bytes(self.bank.maximum_rows)?;
        self.reserve_with_backing_data(requested)
    }

    fn reserve_with_backing_data(&mut self, admitted_bytes: usize) -> Result<(), ProviderError> {
        if !matches!(self.bank.reservation, ReservationState::Unallocated) {
            return Err(credit());
        }
        self.bank.reservation = ReservationState::Failed;
        if record_bytes(self.bank.maximum_rows)? > admitted_bytes {
            return Err(credit());
        }
        self.bank
            .rows
            .try_reserve_exact(self.bank.maximum_rows)
            .map_err(|_| credit())?;
        if self.bank.rows.capacity() > self.bank.maximum_rows {
            return Err(credit());
        }
        self.bank.reservation = ReservationState::Ready;
        Ok(())
    }

    /// Returns the unchanged quoted row restriction.
    pub fn maximum_rows(&self) -> usize {
        self.bank.maximum_rows()
    }

    /// Returns actual backing capacity, including unused slots after refusal.
    pub fn capacity_rows(&self) -> usize {
        self.bank.capacity_rows()
    }

    /// Returns actual retained vector backing in bytes.
    pub fn allocated_bytes(&self) -> usize {
        self.bank.allocated_bytes()
    }

    /// Borrows completed rows or the prefix retained by a refused walk.
    pub fn rows(&self) -> &[MetadataCapacityRecord] {
        self.bank.rows()
    }

    /// Returns allocation state without asserting a complete metadata traversal.
    pub fn reservation_state_data(&self) -> PacketRuntimeMetadataReservationData {
        match self.bank.reservation {
            ReservationState::Unallocated => PacketRuntimeMetadataReservationData::Unallocated,
            ReservationState::Failed => PacketRuntimeMetadataReservationData::Failed,
            ReservationState::Ready => PacketRuntimeMetadataReservationData::Ready,
        }
    }

    /// Appends checked capacity DATA without growing or clearing the bank.
    ///
    /// The enclosing Source derives each row from its actual private typed
    /// owners. Numeric rows authenticate no owner and grant no Source action.
    /// A refusal preserves all earlier rows and backing.
    ///
    /// # Errors
    /// Refuses malformed scalar layout, an unready bank or exhausted slots.
    pub fn append_capacity_record_data(
        &mut self,
        record: MetadataCapacityRecord,
    ) -> Result<(), ProviderError> {
        record.validate_data()?;
        self.recording_bank_data()?.append(record)
    }

    pub(crate) fn recording_bank_data(&mut self) -> Result<&mut MetadataRecordBank, ProviderError> {
        if !matches!(self.bank.reservation, ReservationState::Ready) {
            return Err(credit());
        }
        Ok(&mut self.bank)
    }

    /// Names installed-owner, allocation-result and physical writer view controls.
    ///
    /// Encoding buffers, the enclosing serializer and physical machine frames
    /// require separate admission. This declaration provides no allocation right.
    pub const fn counter_scratch_bytes_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&PacketRuntimeFutureStorageData>()
            + size_of::<PacketRuntimeMetadataReservationData>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<&mut MetadataRecordBank, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Layout>()
            + size_of::<Result<Layout, std::alloc::LayoutError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&Vec<MetadataCapacityRecord>>()
            + size_of::<&usize>()
            + size_of::<&ReservationState>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<&MetadataCapacityRecord>()
            + 2 * size_of::<usize>()
    }
}

impl Serialize for PacketRuntimeMetadataRecordBank {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let MetadataRecordBank {
            rows: _,
            maximum_rows,
            reservation: _,
        } = &self.bank;
        let mut fields = serializer.serialize_struct("PacketRuntimeMetadataRecordBank18", 5)?;
        fields.serialize_field("capacity_rows", &self.bank.capacity_rows())?;
        fields.serialize_field("format", PACKET_RUNTIME_METADATA_RECORD_FORMAT)?;
        fields.serialize_field("maximum_rows", maximum_rows)?;
        fields.serialize_field("reservation", self.reservation_state_data().name())?;
        fields.serialize_field("rows", &self.bank)?;
        fields.end()
    }
}

/// Borrows validated physical bank history without reconstructing a live bank.
pub struct ValidatedPacketRuntimeMetadataRecords<'a> {
    records: ValidatedMetadataRecords<'a>,
    maximum_rows: usize,
    capacity_rows: usize,
    reservation: PacketRuntimeMetadataReservationData,
}

impl<'a> ValidatedPacketRuntimeMetadataRecords<'a> {
    /// Checks the complete versioned bank and independent physical restrictions.
    ///
    /// `maximum_rows` is the enclosing Source's selected restriction. The two
    /// backing restrictions separately bound record slots and observed original
    /// String/Vec capacities. Tree/shared geometry and complete Source history
    /// remain independently required. This performs no allocation or callbacks.
    ///
    /// # Errors
    /// Refuses legacy, malformed, trailing, impossible or overflowing history,
    /// a row restriction mismatch, or either independent backing overrun.
    pub fn validate(
        input: &'a [u8],
        maximum_rows: usize,
        maximum_record_backing_bytes: usize,
        maximum_observed_backing_bytes: usize,
    ) -> Result<Self, ProviderError> {
        record_bytes(maximum_rows)?;
        let mut cursor = Cursor::new(input);
        cursor.literal(b"{\"capacity_rows\":")?;
        let capacity_rows = cursor.number()?;
        let capacity_bytes = Layout::array::<MetadataCapacityRecord>(capacity_rows)
            .map_err(|_| credit())?
            .size();
        if capacity_bytes > maximum_record_backing_bytes {
            return Err(credit());
        }
        cursor.literal(
            b",\"format\":\"source-private.packet-runtime-metadata-bank/18\",\"maximum_rows\":",
        )?;
        if cursor.number()? != maximum_rows {
            return Err(invalid());
        }
        cursor.literal(b",\"reservation\":\"")?;
        let reservation = if cursor
            .input
            .get(cursor.position..)
            .is_some_and(|tail| tail.starts_with(b"unallocated\""))
        {
            cursor.literal(b"unallocated\"")?;
            PacketRuntimeMetadataReservationData::Unallocated
        } else if cursor
            .input
            .get(cursor.position..)
            .is_some_and(|tail| tail.starts_with(b"failed\""))
        {
            cursor.literal(b"failed\"")?;
            PacketRuntimeMetadataReservationData::Failed
        } else {
            cursor.literal(b"ready\"")?;
            PacketRuntimeMetadataReservationData::Ready
        };
        cursor.literal(b",\"rows\":")?;
        let start = cursor.position;
        let (rows, backing_capacity_bytes) =
            cursor.records(maximum_rows, maximum_observed_backing_bytes)?;
        let records = ValidatedMetadataRecords {
            input: &input[start..cursor.position],
            rows,
            backing_capacity_bytes,
        };
        cursor.literal(b"}")?;
        if cursor.position != input.len()
            || match reservation {
                PacketRuntimeMetadataReservationData::Unallocated => {
                    capacity_rows != 0 || rows != 0
                }
                PacketRuntimeMetadataReservationData::Failed => {
                    rows != 0 || (capacity_rows != 0 && capacity_rows <= maximum_rows)
                }
                PacketRuntimeMetadataReservationData::Ready => capacity_rows != maximum_rows,
            }
        {
            return Err(invalid());
        }
        Ok(Self {
            records,
            maximum_rows,
            capacity_rows,
            reservation,
        })
    }

    /// Returns the verified selected row restriction as historical DATA.
    pub fn maximum_rows(&self) -> usize {
        self.maximum_rows
    }

    /// Returns the verified actual record-vector capacity.
    pub fn capacity_rows(&self) -> usize {
        self.capacity_rows
    }

    /// Returns physical reservation history without issuing a live reservation.
    pub fn reservation_state_data(&self) -> PacketRuntimeMetadataReservationData {
        self.reservation
    }

    /// Returns the validated initialized record population.
    pub fn row_count(&self) -> usize {
        self.records.row_count()
    }

    /// Returns observed original String/Vec backing, excluding record slots.
    pub fn observed_backing_capacity_bytes_data(&self) -> usize {
        self.records.backing_capacity_bytes()
    }

    /// Replays borrowed rows in the exact recorded traversal order.
    pub fn rows(&self) -> MetadataRecordRows<'a> {
        self.records.rows()
    }

    /// Names the defining cursor, header, row and checked validation controls.
    pub const fn counter_scratch_bytes_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<ValidatedMetadataRecords<'static>>()
            + size_of::<Cursor<'static>>()
            + size_of::<MetadataRecordRows<'static>>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<Result<MetadataCapacityRecord, ProviderError>>()
            + size_of::<PacketRuntimeMetadataReservationData>()
            + size_of::<Layout>()
            + size_of::<Result<Layout, std::alloc::LayoutError>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<Option<u8>>()
            + size_of::<Result<usize, ProviderError>>()
            + 2 * size_of::<&[u8]>()
            + 9 * size_of::<usize>()
    }
}

fn record_bytes(rows: usize) -> Result<usize, ProviderError> {
    if rows == 0 {
        return Err(credit());
    }
    Layout::array::<MetadataCapacityRecord>(rows)
        .map(|layout| layout.size())
        .map_err(|_| credit())
}

#[cfg(test)]
mod tests;
