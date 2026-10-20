//! Retains actual fresh import18 capture-bank construction before publication.
//!
//! The Source owns its spent attempt and every partially allocated bank before
//! reservation. Only a completely successful owner moves into capture_banks;
//! partial Some slots are custody, never completion, a ticket or native credit.

use super::*;
use crate::node_contract::RuntimeError;
use std::{
    cell::{BorrowError, Ref, RefCell},
    mem::size_of,
};

/// Quotes the actual selected fresh Source banks before their first allocation.
#[derive(Clone, Copy)]
pub struct OriginalImport18CaptureBankConstructionData {
    source: *const PacketCompleteSemanticSource,
    process: u32,
    thread: std::thread::ThreadId,
    limits: PacketCompleteCaptureBankLimits,
    metadata_rows: usize,
    storage_extents: Import18CaptureBankStorageExtents,
    axes: (usize, usize, usize),
}

/// Keeps immutable allocation inputs separate from any Source permission.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Import18CaptureBankStorageExtents {
    native_snapshot: usize,
    native_control: usize,
    history_bytes: usize,
    lifetime_frames: usize,
}

type Import18CaptureBankGeometry = (
    PacketCompleteCaptureBankLimits,
    Import18CaptureBankStorageExtents,
);

impl OriginalImport18CaptureBankConstructionData {
    /// Returns independent retained, constructor temporary and fixed controls.
    pub const fn requested_storage_data(&self) -> (usize, usize, usize) {
        self.axes
    }

    fn authenticate_current_geometry_data(
        &self,
        limits: &PacketCompleteCaptureBankLimits,
        storage_extents: &Import18CaptureBankStorageExtents,
    ) -> Result<(), RuntimeError> {
        if self.limits.host_protocol_bytes != limits.host_protocol_bytes
            || self.limits.semantic_bytes != limits.semantic_bytes
            || self.limits.ancestry_bytes != limits.ancestry_bytes
            || self.limits.journal_bytes != limits.journal_bytes
            || self.storage_extents != *storage_extents
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

/// Keeps the actual once row and uninitialized reservation outputs in the Source.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Import18CaptureBankReservation
{
    row: OriginalImport18CaptureBankConstructionData,
    started: bool,
    complete: bool,
    failed: bool,
    published: bool,
    banks: Option<PacketCompleteCaptureBanks>,
}

/// Copies only modeled construction history; it cannot reconstruct a live row.
#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Import18CaptureBankHistoryData
{
    pub attempted: bool,
    pub owner: Option<Import18CaptureBankOwnerHistoryData>,
}

#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Import18CaptureBankOwnerHistoryData
{
    pub started: bool,
    pub complete: bool,
    pub failed: bool,
    pub published: bool,
    pub row_axes: (usize, usize, usize),
    pub limits: [usize; 4],
    pub metadata_rows: usize,
    pub partial_capacities: Option<[usize; 7]>,
}

impl Import18CaptureBankReservation {
    fn retaining(row: OriginalImport18CaptureBankConstructionData) -> Self {
        Self {
            row,
            started: true,
            complete: false,
            failed: true,
            published: false,
            banks: None,
        }
    }

    fn history_data(&self) -> Import18CaptureBankOwnerHistoryData {
        let partial_capacities = self.banks.as_ref().map(|banks| {
            [
                banks
                    .semantic
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks
                    .ancestry
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks
                    .journal
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks.native_banks[0]
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks.native_banks[1]
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks.native_banks[2]
                    .as_ref()
                    .map_or(0, CnpSemanticSnapshotReservation::allocated_bytes),
                banks
                    .protocol
                    .as_ref()
                    .map_or(0, ProtocolSnapshotReservation::allocated_bytes),
            ]
        });
        Import18CaptureBankOwnerHistoryData {
            started: self.started,
            complete: self.complete,
            failed: self.failed,
            published: self.published,
            row_axes: self.row.axes,
            limits: [
                self.row.limits.host_protocol_bytes,
                self.row.limits.semantic_bytes,
                self.row.limits.ancestry_bytes,
                self.row.limits.journal_bytes,
            ],
            metadata_rows: self.row.metadata_rows,
            partial_capacities,
        }
    }

    fn retained_backing_data<E: StorageError>(&self, maximum: usize) -> Result<usize, E> {
        let mut bytes = size_of::<Self>();
        if bytes > maximum {
            return Err(E::limit("import18 bank owner header exceeds bound"));
        }
        if let Some(banks) = &self.banks {
            // No bytes/records have ever been encoded in this constructor. All
            // actual partial reservations remain empty but may own capacity.
            if banks.semantic_snapshot.is_some()
                || banks.ancestry_record.is_some()
                || banks.journal_record.is_some()
                || banks.capture_response.is_some()
                || banks.confirmation_response.is_some()
                || banks.settled_protocol.is_some()
                || banks.protocol_payload.is_some()
                || banks.native_objects.iter().any(Option::is_some)
                || banks.native_after_object.is_some()
                || banks.native_after_bank.is_some()
            {
                return Err(E::refused(
                    "partial import18 reservation contains encoded state",
                ));
            }
            for bank in [
                &banks.semantic,
                &banks.ancestry,
                &banks.journal,
                &banks.native_banks[0],
                &banks.native_banks[1],
                &banks.native_banks[2],
            ] {
                if let Some(bank) = bank {
                    bytes = bytes
                        .checked_add(bank.allocated_bytes())
                        .filter(|n| *n <= maximum)
                        .ok_or_else(|| E::limit("partial import18 bank capacity exceeds bound"))?;
                }
            }
            if let Some(protocol) = &banks.protocol {
                bytes = bytes
                    .checked_add(protocol.allocated_bytes())
                    .filter(|n| *n <= maximum)
                    .ok_or_else(|| E::limit("partial import18 protocol capacity exceeds bound"))?;
            }
        }
        Ok(bytes)
    }
}

impl PacketCompleteCaptureBanks {
    fn empty_import18_data() -> Self {
        Self {
            protocol_detached: false,
            transferred: false,
            semantic: None,
            semantic_snapshot: None,
            ancestry: None,
            ancestry_record: None,
            journal: None,
            journal_record: None,
            capture_response: None,
            confirmation_response: None,
            protocol: None,
            settled_protocol: None,
            protocol_payload: None,
            native_banks: [None, None, None],
            native_objects: [None, None, None],
            native_after_bank: None,
            native_after_object: None,
        }
    }
}

impl PacketCompleteSemanticSource {
    fn authenticate_import18_bank_prebirth_data(&self) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.ack_birth_attempted || self.complete_bytes_launch_reserved.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn current_import18_capture_bank_geometry_data(
        &self,
    ) -> Result<Import18CaptureBankGeometry, RuntimeError> {
        let selected = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_selected_storage(),
            CompletePacketOriginal::Reactive(source) => source.complete_selected_storage(),
        }
        .ok_or(RuntimeError::UnsupportedFacet)?;
        let profile = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_capture_profile.as_ref(),
            CompletePacketOriginal::Reactive(source) => source.complete_capture_profile.as_ref(),
        }
        .ok_or(RuntimeError::UnsupportedFacet)?;
        let PacketNative5CaptureProfile::OwnedProtocol11 {
            host_protocol_bytes,
            ..
        } = profile
        else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let limits = PacketCompleteCaptureBankLimits {
            host_protocol_bytes: extent(host_protocol_bytes.get())?,
            semantic_bytes: self.installation().maximum_semantic_bytes,
            ancestry_bytes: self.installation().maximum_result_bytes,
            journal_bytes: self.installation().maximum_authorization_bytes,
        };
        let storage_extents = Import18CaptureBankStorageExtents {
            native_snapshot: extent(selected.storage.snapshot_bytes.get())?,
            native_control: extent(selected.storage.control_snapshot_bytes.get())?,
            history_bytes: extent(selected.storage.frame_bank_bytes.get())?,
            lifetime_frames: extent(selected.storage.frames_per_direction.get())?,
        };
        if [
            limits.semantic_bytes,
            limits.ancestry_bytes,
            limits.journal_bytes,
        ]
        .contains(&0)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((limits, storage_extents))
    }

    /// Quotes all actual bank families for its explicit import18 declaration.
    ///
    /// `metadata_rows` is independently supplied by the actual installed policy;
    /// it never widens the unchanged Provider constructor limits. All other byte
    /// demands derive from this Source's immutable profile/storage/installation.
    /// The caller admits its complete existing owners plus this row separately.
    ///
    /// # Errors
    /// Refuses foreign/non-import18 or already attempted sources, another profile,
    /// invalid limits, arithmetic overflow or a complete row beyond `maximum`.
    pub fn original_import18_capture_bank_construction_data(
        self: &std::rc::Rc<Self>,
        metadata_rows: usize,
        maximum: usize,
    ) -> Result<OriginalImport18CaptureBankConstructionData, RuntimeError> {
        self.authenticate_import18_bank_prebirth_data()?;
        if !self.is_original_native_import18_declaration_data()?
            || self.native_import18_bank_attempted.get()
            || self
                .capture_banks
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || self
                .native_import18_bank_reservation
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let (limits, storage_extents) = self.current_import18_capture_bank_geometry_data()?;
        let protocol = ProtocolSnapshotReservation::owned11_retained_reservation_construction_data(
            limits.host_protocol_bytes,
            storage_extents.history_bytes,
            storage_extents.lifetime_frames,
            metadata_rows,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let retained = sum(
            [
                size_of::<Import18CaptureBankReservation>(),
                limits.semantic_bytes,
                limits.ancestry_bytes,
                limits.journal_bytes,
                storage_extents.native_snapshot,
                storage_extents.native_control,
                8192,
                protocol.0,
            ],
            maximum,
        )?;
        let semantic_initializer = size_of::<CnpSemanticSnapshotReservation>()
            .checked_add(size_of::<Option<CnpSemanticSnapshotReservation>>())
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<
                    crate::node_adapters::cnp::semantic::retained_storage::StorageOrigin,
                >())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        // Each named reserve_into call has its own actual retained initializer
        // and Option assignment. No allocator or compiler-copy factor is used.
        let transient = sum(
            [
                // The retaining literal return and Box::new argument each
                // carry the real owner, in addition to its retained Box payload.
                size_of::<Import18CaptureBankReservation>(),
                size_of::<Import18CaptureBankReservation>(),
                size_of::<OriginalImport18CaptureBankConstructionData>(),
                size_of::<Box<Import18CaptureBankReservation>>(),
                size_of::<Option<Box<Import18CaptureBankReservation>>>(),
                // Empty-bank return/Some installation and the later complete
                // take/Result/local publication are distinct move windows.
                size_of::<PacketCompleteCaptureBanks>(),
                size_of::<Option<PacketCompleteCaptureBanks>>(),
                size_of::<PacketCompleteCaptureBanks>(),
                size_of::<Option<PacketCompleteCaptureBanks>>(),
                size_of::<Result<PacketCompleteCaptureBanks, RuntimeError>>(),
                protocol.1,
                semantic_initializer,
                semantic_initializer,
                semantic_initializer,
                semantic_initializer,
                semantic_initializer,
                semantic_initializer,
            ],
            maximum,
        )?;
        let scratch = Self::original_import18_capture_bank_counter_scratch_data();
        let original_maximum = extent(
            self.installation()
                .realize
                .resource_limits
                .memory_bytes
                .get(),
        )?;
        sum(
            [retained, transient, scratch],
            maximum.min(original_maximum),
        )?;
        Ok(OriginalImport18CaptureBankConstructionData {
            source: std::rc::Rc::as_ptr(self),
            process: self.process,
            thread: self.thread,
            limits,
            metadata_rows,
            storage_extents,
            axes: (retained, transient, scratch),
        })
    }

    /// Reserves into its actual retained once owner, publishing only on success.
    ///
    /// The installed caller admits the complete row and all prior owners before
    /// entry. Failure leaves the same attempt, row and all capacities in Source;
    /// neither another label nor a fresh output slot can renew this occurrence.
    /// No native operation, authorization, model adoption or I/O occurs here.
    ///
    /// # Errors
    /// Refuses foreign/changed or reused rows, borrowed custody, actual capacities
    /// beyond their demand, or allocation failure; partial Some never means ready.
    pub fn reserve_original_import18_capture_banks_data(
        &mut self,
        row: &OriginalImport18CaptureBankConstructionData,
    ) -> Result<(), RuntimeError> {
        self.authenticate_import18_bank_prebirth_data()?;
        if self.native_import18_bank_attempted.get()
            || self.native_import18_bank_reservation.get_mut().is_some()
            || self.capture_banks.get_mut().is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        if row.source != std::ptr::from_ref(self)
            || row.process != self.process
            || row.thread != self.thread
            || !self.is_original_native_import18_declaration_data()?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (limits, storage_extents) = self.current_import18_capture_bank_geometry_data()?;
        row.authenticate_current_geometry_data(&limits, &storage_extents)?;
        // Install this Source-local fence before the new Box allocation or any
        // reservation. Even an unwound initializer cannot renew this Source.
        self.native_import18_bank_attempted.set(true);
        *self.native_import18_bank_reservation.get_mut() =
            Some(Box::new(Import18CaptureBankReservation::retaining(*row)));
        let owner = self
            .native_import18_bank_reservation
            .get_mut()
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
        let banks = owner.banks.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            row.limits.semantic_bytes,
            row.limits.semantic_bytes,
            &mut banks.semantic,
        )?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            row.limits.ancestry_bytes,
            row.limits.ancestry_bytes,
            &mut banks.ancestry,
        )?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            row.limits.journal_bytes,
            row.limits.journal_bytes,
            &mut banks.journal,
        )?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            row.storage_extents.native_snapshot,
            row.storage_extents.native_snapshot,
            &mut banks.native_banks[0],
        )?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            row.storage_extents.native_control,
            row.storage_extents.native_control,
            &mut banks.native_banks[1],
        )?;
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            8192,
            8192,
            &mut banks.native_banks[2],
        )?;
        ProtocolSnapshotReservation::reserve_complete_owned11_into(
            row.limits.host_protocol_bytes,
            row.storage_extents.history_bytes,
            row.storage_extents.lifetime_frames,
            row.metadata_rows,
            &mut banks.protocol,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        owner.retained_backing_data::<RuntimeError>(row.axes.0)?;
        // No fallible operation separates taking the complete banks and the
        // actual Source write. The spent row/header stays in its original owner.
        let banks = owner.banks.take().ok_or(RuntimeError::OwnerUnavailable)?;
        *self.capture_banks.get_mut() = Some(banks);
        owner.published = true;
        owner.complete = true;
        owner.failed = false;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_import18_capture_bank_partial_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let owner = self
            .native_import18_bank_reservation
            .try_borrow()
            .map_err(E::unknown)?;
        owner
            .as_ref()
            .map_or(Ok(0), |owner| owner.retained_backing_data::<E>(maximum))
    }

    /// Copies the exact bank-construction occurrence, including a missing owner.
    ///
    /// The outer attempted flag precedes even the Box initializer. Partial bank
    /// capacities remain distinct from absence or published/moved banks; this
    /// projection recreates neither live Source pointers nor permission.
    ///
    /// # Errors
    /// Refuses foreign creation or a currently borrowed attempt holder.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_import18_capture_bank_history_data(
        &self,
    ) -> Result<Import18CaptureBankHistoryData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let held = self
            .native_import18_bank_reservation
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let owner = held.as_ref().map(|owner| owner.history_data());
        Ok(Import18CaptureBankHistoryData {
            attempted: self.native_import18_bank_attempted.get(),
            owner,
        })
    }

    /// Names the passive occurrence projection and its short borrowed holder.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_import18_capture_bank_history_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<Ref<'static, Option<Box<Import18CaptureBankReservation>>>>()
            + size_of::<
                Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, BorrowError>,
            >()
            + size_of::<
                Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, RuntimeError>,
            >()
            + size_of::<Import18CaptureBankHistoryData>()
            + size_of::<Import18CaptureBankOwnerHistoryData>()
            + size_of::<Option<Import18CaptureBankOwnerHistoryData>>()
            + size_of::<Result<Import18CaptureBankHistoryData, RuntimeError>>()
            + size_of::<&Box<Import18CaptureBankReservation>>()
            + size_of::<Option<&Box<Import18CaptureBankReservation>>>()
            + size_of::<&Import18CaptureBankReservation>()
            + size_of::<&PacketCompleteCaptureBanks>()
            + size_of::<Option<&PacketCompleteCaptureBanks>>()
            + size_of::<&CnpSemanticSnapshotReservation>()
            + size_of::<Option<&CnpSemanticSnapshotReservation>>()
            + size_of::<&ProtocolSnapshotReservation>()
            + size_of::<Option<&ProtocolSnapshotReservation>>()
            + size_of::<[usize; 7]>()
            + size_of::<Option<[usize; 7]>>()
            + size_of::<[usize; 4]>()
            + origin_counter_scratch_data()
    }

    /// Names the defining prequote/reservation and partial-census fixed controls.
    pub fn original_import18_capture_bank_counter_scratch_data() -> usize {
        ProtocolSnapshotReservation::owned11_retained_reservation_counter_scratch_data()
            + semantic_reservation_counter_scratch_data()
            + Self::original_import18_capture_bank_history_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&std::rc::Rc<Self>>()
            + size_of::<OriginalImport18CaptureBankConstructionData>()
            + size_of::<Result<OriginalImport18CaptureBankConstructionData, RuntimeError>>()
            + size_of::<&OriginalImport18CaptureBankConstructionData>()
            + size_of::<PacketCompleteCaptureBankLimits>() * 2
            + size_of::<&PacketCompleteCaptureBankLimits>()
            + size_of::<Import18CaptureBankStorageExtents>() * 2
            + size_of::<&Import18CaptureBankStorageExtents>()
            + size_of::<Import18CaptureBankGeometry>()
            + size_of::<Result<Import18CaptureBankGeometry, RuntimeError>>()
            + size_of::<&RefCell<Option<Box<Import18CaptureBankReservation>>>>()
            + size_of::<&mut RefCell<Option<Box<Import18CaptureBankReservation>>>>()
            + size_of::<&RefCell<Option<PacketCompleteCaptureBanks>>>()
            + size_of::<&mut RefCell<Option<PacketCompleteCaptureBanks>>>()
            + size_of::<&mut Option<Box<Import18CaptureBankReservation>>>()
            + size_of::<&mut Box<Import18CaptureBankReservation>>()
            + size_of::<Option<&mut Box<Import18CaptureBankReservation>>>()
            + size_of::<Result<&mut Box<Import18CaptureBankReservation>, RuntimeError>>()
            + size_of::<&mut PacketCompleteCaptureBanks>()
            + size_of::<Option<&mut PacketCompleteCaptureBanks>>()
            + size_of::<Result<&mut PacketCompleteCaptureBanks, RuntimeError>>()
            + size_of::<&Import18CaptureBankReservation>()
            + size_of::<&Option<CnpSemanticSnapshotReservation>>()
            + size_of::<&CnpSemanticSnapshotReservation>()
            + size_of::<Option<&CnpSemanticSnapshotReservation>>()
            + size_of::<&ProtocolSnapshotReservation>()
            + size_of::<Option<&ProtocolSnapshotReservation>>()
            + size_of::<Ref<'static, Option<Box<Import18CaptureBankReservation>>>>()
            + size_of::<
                Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, BorrowError>,
            >()
            + size_of::<
                Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, RuntimeError>,
            >()
            + size_of::<Ref<'static, Option<PacketCompleteCaptureBanks>>>()
            + size_of::<Result<Ref<'static, Option<PacketCompleteCaptureBanks>>, BorrowError>>()
            + size_of::<Result<Ref<'static, Option<PacketCompleteCaptureBanks>>, RuntimeError>>()
            + size_of::<
                Ref<
                    'static,
                    Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                >,
            >()
            + size_of::<
                Result<
                    Ref<
                        'static,
                        Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                    >,
                    BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    Ref<
                        'static,
                        Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                    >,
                    RuntimeError,
                >,
            >()
            + size_of::<&PacketNative5StorageSelection>()
            + size_of::<Option<&PacketNative5StorageSelection>>()
            + size_of::<Result<&PacketNative5StorageSelection, RuntimeError>>()
            + size_of::<&PacketNative5CaptureProfile>()
            + size_of::<Option<&PacketNative5CaptureProfile>>()
            + size_of::<Result<&PacketNative5CaptureProfile, RuntimeError>>()
            + size_of::<&crucible_node_contract::U64>()
            // Quote metadata_rows/maximum, retained/transient/scratch,
            // semantic_initializer/original_maximum; then census bytes/maximum.
            // Checked-add/filter and extent conversion have their own views.
            + size_of::<usize>() * (7 + 2)
            + size_of::<Option<usize>>()
            + size_of::<Option<&usize>>()
            + size_of::<u64>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<std::num::TryFromIntError>()
            + sum_counter_scratch_data::<8>()
            + sum_counter_scratch_data::<17>()
            + sum_counter_scratch_data::<3>()
            + size_of::<[usize; 3]>()
            + size_of::<&[usize; 3]>()
            + size_of::<&usize>()
            + size_of::<[&Option<CnpSemanticSnapshotReservation>; 6]>()
            + size_of::<std::array::IntoIter<&Option<CnpSemanticSnapshotReservation>, 6>>()
            + size_of::<std::slice::Iter<'static, Option<InputPayload>>>()
            + size_of::<&Option<InputPayload>>()
            + size_of::<Option<&Option<InputPayload>>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(usize, usize, usize), crucible_node_provider::ProviderError>>()
            + size_of::<(usize, usize, usize)>()
            + origin_counter_scratch_data()
    }
}

fn extent(value: u64) -> Result<usize, RuntimeError> {
    usize::try_from(value).map_err(|_| RuntimeError::ResourceLimit)
}

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    terms.into_iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

/// Names direct controls of the actual semantic reserve_into body. Its owned
/// initializer/Some/Vec/origin values are constructor T above, not S credit.
fn semantic_reservation_counter_scratch_data() -> usize {
    size_of::<&mut Option<CnpSemanticSnapshotReservation>>()
        + size_of::<&mut CnpSemanticSnapshotReservation>()
        + size_of::<Option<&mut CnpSemanticSnapshotReservation>>()
        + size_of::<Result<&mut CnpSemanticSnapshotReservation, RuntimeError>>()
        + size_of::<usize>() * 2
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<Result<(), RuntimeError>>()
        + origin_counter_scratch_data()
}

fn origin_counter_scratch_data() -> usize {
    size_of::<std::thread::Thread>()
        + size_of::<std::thread::ThreadId>()
        + size_of::<u32>()
        + size_of::<bool>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<bool, RuntimeError>>()
}

/// Names this actual const-N sum's argument, moved array, iterator and closure
/// controls. Each call site supplies its real term count, never a scalar maximum.
fn sum_counter_scratch_data<const N: usize>() -> usize {
    size_of::<[usize; N]>() * 2
        + size_of::<std::array::IntoIter<usize, N>>()
        + size_of::<usize>() * 3
        + size_of::<&usize>() * 2
        + size_of::<Option<usize>>()
        + size_of::<Option<&usize>>()
        + size_of::<Result<usize, RuntimeError>>()
}

#[cfg(test)]
#[path = "import18_reservation/tests.rs"]
mod tests;
