//! Source-private protocol byte snapshots without native installation authority.
//!
//! Reservations precede child construction. Capturing borrows complete actual
//! state twice under one exclusive actor: a bounded count, then a bounded
//! write into the same precharged buffer. Some metadata serializers allocate
//! scratch; source admission must charge that peak alongside original storage.
//! Decoding never produces an installed capture, process lease, semantic seal
//! or fresh-adoption permission.

/// Provides bounded source-private compact byte data without authority.
pub mod compact_bytes;

/// Provides bounded typed historical reconstruction for explicit edition eleven.
pub mod owned11;

pub use crate::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind, ValidatedMetadataRecords,
};

mod payload;
pub use payload::OriginalProtocolPayloadOwner;

/// Borrows byte storage under an explicitly selected source-private edition.
pub(crate) struct ProtocolBytes<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) compact: bool,
}

impl serde::Serialize for ProtocolBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.compact {
            compact_bytes::BorrowedCompactBytes::new(self.bytes).serialize(serializer)
        } else {
            self.bytes.serialize(serializer)
        }
    }
}

pub use crate::retained_metadata::aliases::MetadataAliasAllocationFacts;
use crate::retained_metadata::aliases::MetadataAliasBank;
use crate::{ProviderError, handshake::ConnectionAuthority};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::{self, Write};
use std::rc::Rc;

/// Selects the actual correlation cut retained by a source-private capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolCaptureCut {
    /// Requires no outstanding transport correlations after the full prefix.
    HostSettled,
    /// Retains exactly the current incoming Capture before its response.
    NativeIncomingCapture,
}

/// Reports retained allocation facts from one current installed native-five bank.
///
/// Numeric facts grant no source selection, capture, release or adoption right.
/// The source factory must join actual native owners and its original budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct OriginalProtocolStorageFacts {
    /// States the genuinely negotiated maximum encoded frame body length.
    pub maximum_frame_bytes: usize,
    /// Bounds shared literal bytes across both lifetime directions.
    pub maximum_history_bytes: usize,
    /// Bounds each direction's nonrenewing lifetime frame population.
    pub maximum_frames_per_direction: usize,
    /// Reports actual allocated byte capacity rather than logical usage.
    pub byte_capacity: usize,
    /// Reports actual allocated descriptor population across both directions.
    pub descriptor_capacity: usize,
    /// Reports actual descriptor allocation in bytes.
    pub descriptor_bytes: usize,
    /// Reports complete charged byte and descriptor allocation.
    pub allocated_bytes: usize,
    /// Counts literal bytes retained under the same original bank.
    pub retained_bytes: usize,
    /// Counts original incoming lifetime slots, including incomplete ones.
    pub incoming_frames: usize,
    /// Counts original outgoing lifetime slots, including incomplete ones.
    pub outgoing_frames: usize,
    /// Reports complete physical I/O for all retained slots, not semantic success.
    pub all_io_complete: bool,
}

/// Reports one independently reserved literal snapshot copy's actual storage.
///
/// These numbers describe the copy bank, not either endpoint's live archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProtocolSnapshotLiteralAllocationFacts {
    /// Bounds retained bytes across both lifetime directions.
    pub maximum_history_bytes: usize,
    /// Bounds each direction's lifetime descriptor count.
    pub maximum_frames_per_direction: usize,
    /// Reports the actual byte vector capacity.
    pub byte_capacity: usize,
    /// Reports the actual combined descriptor vector capacity.
    pub descriptor_capacity: usize,
    /// Reports the descriptor vector's allocated bytes.
    pub descriptor_bytes: usize,
    /// Reports actual retained literal bytes.
    pub retained_bytes: usize,
    /// Reports byte and descriptor allocations together.
    pub allocated_bytes: usize,
}

/// Reports the actual encoded buffer and independent literal copy allocations.
///
/// The facts provide no source selection, Capture, settlement or adoption right.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProtocolSnapshotAllocationFacts {
    /// States the selected encoded snapshot ceiling.
    pub maximum_encoded_bytes: usize,
    /// Reports the actual encoded vector capacity.
    pub encoded_capacity: usize,
    /// Reports bytes currently retained in the encoded vector.
    pub encoded_length: usize,
    /// Describes an independently precharged literal copy when present.
    pub literal: Option<ProtocolSnapshotLiteralAllocationFacts>,
    /// Reports all encoded, literal and descriptor allocations together.
    pub allocated_bytes: usize,
}

/// Reports the actual independently precharged metadata record bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MetadataRecordAllocationFacts {
    /// States the finite selected traversal row ceiling.
    pub maximum_rows: usize,
    /// Reports actual allocated row capacity, including spare storage.
    pub capacity_rows: usize,
    /// Counts recorded rows currently retained in the bank.
    pub retained_rows: usize,
    /// Reports actual requested row storage bytes, separate from physical peak.
    pub allocated_bytes: usize,
}

fn metadata_record_facts(bank: &MetadataRecordBank) -> MetadataRecordAllocationFacts {
    MetadataRecordAllocationFacts {
        maximum_rows: bank.maximum_rows(),
        capacity_rows: bank.capacity_rows(),
        retained_rows: bank.rows().len(),
        allocated_bytes: bank.allocated_bytes(),
    }
}

/// Reports a same-original native snapshot's physical antecedent correspondence.
///
/// These borrowed numeric facts grant no successful Capture, semantic settlement,
/// transfer, fresh installation or Ready permission. The source still verifies
/// the precise terminal Capture outcome, complete three-object suffix and signed
/// source-to-target context; a terminal refusal can also have a settled transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalNative5CaptureAntecedentFacts {
    /// States the exact retained opaque snapshot's encoded length.
    pub snapshot_bytes: usize,
    /// Describes the frozen physical frame bank before the Capture response.
    pub captured: OriginalProtocolStorageFacts,
    /// Describes the same live bank after transport correlations settled.
    pub current: OriginalProtocolStorageFacts,
}

/// Reports a conservative after-prefix encoding admission for one original bank.
///
/// These numbers prove only capacity for admitted data, not actual future bytes,
/// acknowledgement, a completed snapshot, semantic settlement or installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Native5AfterProtocolCapacityFacts {
    /// Counts the current complete borrowed endpoint/blob encoding.
    pub current_encoded_bytes: usize,
    /// Bounds encoding of the entire selected original raw byte bank.
    pub maximum_literal_encoded_bytes: usize,
    /// Bounds all nonrenewing original frame descriptors at their selected limit.
    pub maximum_descriptor_encoded_bytes: usize,
    /// Credits maximum decimal growth of current numeric counters.
    pub maximum_counter_growth_bytes: usize,
    /// Bounds the complete encoded body after a settled suffix.
    pub maximum_after_encoded_bytes: usize,
    /// States the actual same-profile reserved after-body ceiling.
    pub reserved_after_encoded_bytes: usize,
}

pub(crate) struct ProtocolCaptureOwner {
    pid: u32,
    thread: std::thread::ThreadId,
}

impl ProtocolCaptureOwner {
    pub(crate) fn new() -> Self {
        Self {
            pid: std::process::id(),
            thread: std::thread::current().id(),
        }
    }
    pub(crate) fn ensure_current(&self) -> Result<(), ProviderError> {
        if self.pid != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "protocol capture owner changed process or thread",
            ));
        }
        Ok(())
    }
}

/// Owns finite snapshot byte capacity charged before child construction.
pub struct ProtocolSnapshotReservation {
    bytes: Vec<u8>,
    maximum: usize,
    compact: bool,
    owned11_records: Option<MetadataRecordBank>,
    owned11_aliases: Option<MetadataAliasBank>,
    original_assigned_cut: Option<crate::operational_time::OperationalDeadline>,
    original_restore_cut: Option<crate::operational_time::OperationalDeadline>,
    original_hello:
        Option<Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>>,
    complete: bool,
    literal: Option<crate::transport::original_frames::OriginalFrameReservation>,
    codec: Option<Rc<crate::connection::Native5CodecOwner>>,
    issuer: Option<(
        ConnectionAuthority,
        Rc<ProtocolCaptureOwner>,
        ProtocolCaptureCut,
        crate::operational_time::OperationalDeadline,
    )>,
}

impl ProtocolSnapshotReservation {
    /// Reports every present original association retained by this reservation.
    ///
    /// Encoded, literal-copy, record and alias-bank capacities remain separate
    /// existing allocation facts. Partial reservations include any retained
    /// authority, codec and full original Hello bank. The bound issuer's actual
    /// creator is checked first; an unbound reservation has no issuer permission
    /// and its owning source capsule must supply its own original-origin guard.
    ///
    /// # Errors
    /// Refuses a foreign bound creator, conflicting Hello borrow or checked
    /// metadata traversal/layout overflow. It does not require live native rights.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            bytes: _,
            maximum: _,
            compact: _,
            owned11_records: _,
            owned11_aliases: _,
            original_assigned_cut: _,
            original_restore_cut: _,
            original_hello,
            complete: _,
            literal: _,
            codec,
            issuer,
        } = self;
        if let Some((authority, owner, _, _)) = issuer {
            return original_association_metadata(
                owner,
                authority,
                codec.as_ref(),
                original_hello.as_ref(),
            );
        }
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        if let Some(codec) = codec {
            observer.shared_value(codec.as_ref())?;
            codec.observe_retained_metadata(&mut observer)?;
        }
        if let Some(hello) = original_hello {
            observer.shared_value(hello.as_ref())?;
            let bank = hello.try_borrow().map_err(|_| {
                ProviderError::Conflict("original reserved Hello metadata borrowed")
            })?;
            bank.observe_owned11_metadata(&mut observer)?;
        }
        Ok(observer.finish())
    }

    /// Reads actual row and temporary lookup capacities for the original alias bank.
    ///
    /// # Errors
    /// Refuses another bound original process or thread.
    pub fn original_alias_allocation_facts(
        &self,
    ) -> Result<Option<MetadataAliasAllocationFacts>, ProviderError> {
        if let Some((_, owner, _, _)) = &self.issuer {
            owner.ensure_current()?;
        }
        Ok(self
            .owned11_aliases
            .as_ref()
            .map(MetadataAliasBank::allocation_facts))
    }

    /// Allocates a positive bounded snapshot buffer before native effects.
    ///
    /// # Errors
    /// Refuses zero, more than 512 MiB, or allocator failure.
    pub fn reserve(maximum: usize) -> Result<Self, ProviderError> {
        if maximum == 0 || maximum > crate::transport::original_frames::MAX_ORIGINAL_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "protocol snapshot reservation",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| ProviderError::ResourceExhausted("protocol snapshot bytes"))?;
        Ok(Self {
            bytes,
            maximum,
            compact: false,
            owned11_records: None,
            owned11_aliases: None,
            original_assigned_cut: None,
            original_restore_cut: None,
            original_hello: None,
            complete: false,
            literal: None,
            issuer: None,
            codec: None,
        })
    }

    /// Reserves the encoded snapshot and an independent complete literal copy.
    ///
    /// Both byte and descriptor banks precede child construction. The selected
    /// source profile must charge these copies in addition to both endpoint
    /// archives, prefix ownership and temporary decoding/metadata storage.
    ///
    /// # Errors
    /// Refuses invalid limits or allocator failure without native effects.
    pub fn reserve_complete(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
    ) -> Result<Self, ProviderError> {
        let mut original = Self::reserve(maximum)?;
        original.literal = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(
                history_bytes,
                lifetime_frames,
            )?,
        );
        Ok(original)
    }

    /// Reserves compact-seven encoded storage and its independent literal copy.
    ///
    /// This allocates data banks only. Capturing must authenticate the same
    /// installed immutable source profile and its exact role-specific bound.
    ///
    /// # Errors
    /// Refuses invalid positive ceilings or byte/descriptor allocation failure.
    pub fn reserve_complete_compact(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
    ) -> Result<Self, ProviderError> {
        let mut original = Self::reserve_complete(maximum, history_bytes, lifetime_frames)?;
        original.compact = true;
        Ok(original)
    }

    /// Reserves complete edition-eleven bytes, literal history and metadata rows.
    ///
    /// Every bank precedes snapshot copies. The actual installed sealed source
    /// must separately select OwnedProtocol11 and its exact role-specific bound.
    ///
    /// # Errors
    /// Refuses invalid byte/frame/row ceilings, overflow or allocation failure.
    pub fn reserve_complete_owned11(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
        maximum_metadata_rows: usize,
    ) -> Result<Self, ProviderError> {
        let records = MetadataRecordBank::reserve(maximum_metadata_rows)?;
        let aliases = MetadataAliasBank::reserve(maximum_metadata_rows)?;
        let mut original = Self::reserve_complete(maximum, history_bytes, lifetime_frames)?;
        original.compact = true;
        original.owned11_records = Some(records);
        original.owned11_aliases = Some(aliases);
        Ok(original)
    }

    /// Quotes the actual four backing families requested by a fresh owned11 bank.
    ///
    /// This data counter allocates nothing and grants no native construction.
    /// The caller admits all simultaneous original owners first and rechecks
    /// actual capacities after the reservation. Inline headers are separate.
    ///
    /// # Errors
    /// Refuses the same positive constructor limits or checked layout overflow.
    pub(crate) fn original_owned11_reservation_requested_storage_data(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
        maximum_metadata_rows: usize,
    ) -> Result<usize, ProviderError> {
        use crate::transport::original_frames::{
            MAX_ORIGINAL_FRAME_BYTES, MAX_ORIGINAL_FRAMES_PER_DIRECTION, original_frame_slot_layout,
        };
        if maximum == 0
            || maximum > MAX_ORIGINAL_FRAME_BYTES
            || !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&history_bytes)
            || lifetime_frames == 0
            || lifetime_frames > MAX_ORIGINAL_FRAMES_PER_DIRECTION
            || maximum_metadata_rows == 0
            || maximum_metadata_rows > 131_072
        {
            return Err(ProviderError::ResourceExhausted(
                "native owned11 birth bank",
            ));
        }
        let aliases = MetadataAliasBank::reservation_requested_bytes(maximum_metadata_rows)?;
        maximum
            .checked_add(history_bytes)
            .and_then(|bytes| {
                lifetime_frames
                    .checked_mul(2)
                    .and_then(|frames| frames.checked_mul(original_frame_slot_layout()))
                    .and_then(|frames| bytes.checked_add(frames))
            })
            .and_then(|bytes| {
                maximum_metadata_rows
                    .checked_mul(std::mem::size_of::<MetadataCapacityRecord>())
                    .and_then(|records| bytes.checked_add(records))
            })
            .and_then(|bytes| bytes.checked_add(aliases))
            .ok_or(ProviderError::ResourceExhausted(
                "native owned11 birth bank",
            ))
    }

    pub(crate) fn uses_owned11_encoding(&self) -> bool {
        self.owned11_records.is_some()
    }

    pub(crate) fn record_owned_metadata(
        &mut self,
        walk: impl FnOnce(&mut crate::retained_metadata::MetadataObserver) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let records = self
            .owned11_records
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "owned protocol metadata bank absent",
            ))?;
        let aliases = self
            .owned11_aliases
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "owned protocol alias bank absent",
            ))?;
        let mut observer =
            crate::retained_metadata::MetadataObserver::recording_with_aliases(records, aliases);
        walk(&mut observer)?;
        Ok(())
    }

    pub(crate) fn retain_owned_hello(
        &mut self,
        bank: Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
    ) {
        self.original_hello = Some(bank);
    }

    pub(crate) fn retain_original_restore_cut(
        &mut self,
        cut: Option<crate::operational_time::OperationalDeadline>,
    ) {
        self.original_restore_cut = cut;
    }

    pub(crate) fn retain_original_assigned_cut(
        &mut self,
        cut: Option<crate::operational_time::OperationalDeadline>,
    ) {
        self.original_assigned_cut = cut;
    }

    pub(crate) fn encode_owned11<T: Serialize>(&mut self, data: &T) -> Result<(), ProviderError> {
        let records = self
            .owned11_records
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "owned protocol metadata bank absent",
            ))?;
        let aliases = self
            .owned11_aliases
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "owned protocol alias bank absent",
            ))?;
        aliases.finish_lookup();
        let view = ("source-private.cnp-protocol/11", data, records, &*aliases);
        Self::encode_buffer(&mut self.bytes, self.maximum, &view)?;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn unused_for_after_preflight(&self) -> bool {
        self.bytes.is_empty() && self.issuer.is_none() && self.codec.is_none() && !self.complete
    }

    pub(crate) fn uses_compact_encoding(&self) -> bool {
        self.compact
    }

    pub(crate) fn validate_source_encoding(
        &self,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
        cut: ProtocolCaptureCut,
        controller: bool,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::service::PacketNative5CaptureProfile;
        let Some(codec) = codec else {
            return if self.compact {
                Err(ProviderError::Correlation(
                    "compact snapshot source codec absent",
                ))
            } else {
                Ok(())
            };
        };
        let profile = codec.capture_profile();
        match profile {
            PacketNative5CaptureProfile::OriginalArrays6
                if !self.compact && !self.uses_owned11_encoding() =>
            {
                Ok(())
            }
            PacketNative5CaptureProfile::CompactBytes7 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            } if self.compact && !self.uses_owned11_encoding() => {
                let selected = match (controller, cut) {
                    (true, ProtocolCaptureCut::HostSettled) => host_protocol_bytes,
                    (false, ProtocolCaptureCut::NativeIncomingCapture) => {
                        native_before_protocol_bytes
                    }
                    (false, ProtocolCaptureCut::HostSettled) => native_after_protocol_bytes,
                    _ => return Err(ProviderError::Correlation("compact source cut unsupported")),
                };
                if selected.get() != self.maximum as u64 {
                    return Err(ProviderError::Correlation(
                        "compact reservation differs from installed source profile",
                    ));
                }
                Ok(())
            }
            PacketNative5CaptureProfile::OwnedProtocol11 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            } if self.compact && self.uses_owned11_encoding() => {
                let selected = match (controller, cut) {
                    (true, ProtocolCaptureCut::HostSettled) => host_protocol_bytes,
                    (false, ProtocolCaptureCut::NativeIncomingCapture) => {
                        native_before_protocol_bytes
                    }
                    (false, ProtocolCaptureCut::HostSettled) => native_after_protocol_bytes,
                    _ => {
                        return Err(ProviderError::Correlation(
                            "owned protocol source cut unsupported",
                        ));
                    }
                };
                if selected.get() != self.maximum as u64 {
                    return Err(ProviderError::Correlation(
                        "owned reservation differs from installed source profile",
                    ));
                }
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "snapshot edition differs from installed source profile",
            )),
        }
    }

    pub(crate) fn validate_literal_reservation(
        &self,
        original: &crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        let target = self.literal.as_ref().ok_or(ProviderError::Correlation(
            "complete snapshot requires precharged original literal copy",
        ))?;
        original.validate_empty_copy(target)
    }

    pub(crate) fn retain_literal_history(
        &mut self,
        original: &crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        let target = self.literal.as_mut().ok_or(ProviderError::Correlation(
            "complete snapshot requires precharged original literal copy",
        ))?;
        if let Err(error) = original.copy_into_empty(target) {
            self.complete = false;
            return Err(error);
        }
        Ok(())
    }

    /// Reports actual record storage retained by this precharged reservation.
    ///
    /// # Errors
    /// Refuses a changed original process/thread after issuer binding.
    pub fn original_metadata_record_allocation_facts(
        &self,
    ) -> Result<Option<MetadataRecordAllocationFacts>, ProviderError> {
        if let Some((_, owner, _, _)) = &self.issuer {
            owner.ensure_current()?;
        }
        Ok(self.owned11_records.as_ref().map(metadata_record_facts))
    }

    /// Reports all actual precharged snapshot bank backing to the source budget.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
            + self
                .owned11_aliases
                .as_ref()
                .map_or(0, MetadataAliasBank::allocated_bytes)
            + self
                .owned11_records
                .as_ref()
                .map_or(0, MetadataRecordBank::allocated_bytes)
            + self
                .literal
                .as_ref()
                .map_or(0, |literal| literal.allocated_bytes())
    }

    /// Reports allocation-free facts for this same reserved snapshot bank.
    ///
    /// An unbound reservation can be inspected before child construction. Once
    /// bound, the original process and thread are checked before reading either
    /// bank. This does not invoke callbacks, serialize state or grant permission.
    ///
    /// # Errors
    /// Refuses inspection from a different bound process or thread.
    pub fn original_allocation_facts(
        &self,
    ) -> Result<ProtocolSnapshotAllocationFacts, ProviderError> {
        if let Some((_, owner, _, _)) = &self.issuer {
            owner.ensure_current()?;
        }

        Ok(ProtocolSnapshotAllocationFacts {
            maximum_encoded_bytes: self.maximum,
            encoded_capacity: self.bytes.capacity(),
            encoded_length: self.bytes.len(),
            literal: self
                .literal
                .as_ref()
                .map(|literal| literal.snapshot_allocation_facts()),
            allocated_bytes: self.allocated_bytes(),
        })
    }

    pub(crate) fn encode(&mut self, state: &impl Serialize) -> Result<(), ProviderError> {
        Self::encode_buffer(&mut self.bytes, self.maximum, state)?;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn encode_buffer(
        bytes: &mut Vec<u8>,
        maximum: usize,
        state: &impl Serialize,
    ) -> Result<(), ProviderError> {
        if !bytes.is_empty() {
            return Err(ProviderError::Conflict(
                "protocol snapshot reservation already used",
            ));
        }
        struct Count {
            used: usize,
            maximum: usize,
        }
        impl Write for Count {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.used = self
                    .used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| io::Error::other("protocol snapshot complete credit"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count { used: 0, maximum };
        serde_json::to_writer(&mut count, state)
            .map_err(|_| ProviderError::ResourceExhausted("complete borrowed protocol snapshot"))?;
        struct Bounded<'a> {
            bytes: &'a mut Vec<u8>,
            maximum: usize,
        }
        impl Write for Bounded<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() > self.maximum - self.bytes.len() {
                    return Err(io::Error::other("protocol snapshot writer limit"));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Bounded {
            bytes,
            maximum: count.used,
        };
        serde_json::to_writer(&mut writer, state)
            .map_err(|_| ProviderError::Frame("protocol snapshot bounded encoding"))?;
        if bytes.len() != count.used {
            return Err(ProviderError::Conflict(
                "protocol snapshot state changed during capture",
            ));
        }
        Ok(())
    }

    pub(crate) fn bind(
        &mut self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
        deadline: crate::operational_time::OperationalDeadline,
    ) -> Result<(), ProviderError> {
        owner.ensure_current()?;
        if self.issuer.is_some() {
            return Err(ProviderError::Conflict(
                "protocol snapshot attempt already bound",
            ));
        }
        self.issuer = Some((authority.clone(), owner.clone(), cut, deadline));
        Ok(())
    }

    pub(crate) fn retain_native5_codec(
        &mut self,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    ) -> Result<(), ProviderError> {
        if self.issuer.is_none() || self.codec.is_some() || !self.bytes.is_empty() {
            return Err(ProviderError::Conflict(
                "original snapshot codec binding already used",
            ));
        }
        self.codec = codec.cloned();
        Ok(())
    }

    pub(crate) fn validate_issuer(
        &self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        owner.ensure_current()?;
        let Some((original, issuer, original_cut, _)) = &self.issuer else {
            return Err(ProviderError::Correlation(
                "protocol snapshot has no original issuer",
            ));
        };
        if !self.complete
            || self.bytes.is_empty()
            || !original.same_registration(authority)
            || !Rc::ptr_eq(issuer, owner)
            || *original_cut != cut
        {
            return Err(ProviderError::Correlation(
                "protocol snapshot changed original issuer or cut",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish_from_slot(
        slot: &mut Option<Self>,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
    ) -> Result<OriginalProtocolSnapshot, ProviderError> {
        // The caller retains both banks through every fallible validation. The
        // following transfer invokes no callback and performs no revalidation.
        slot.as_ref()
            .ok_or(ProviderError::Correlation("original snapshot slot absent"))?
            .validate_issuer(authority, owner, cut)?;

        let mut original = slot
            .take()
            .ok_or(ProviderError::Correlation("original snapshot slot absent"))?;
        let Some((authority, owner, original_cut, deadline)) = original.issuer.take() else {
            *slot = Some(original);
            return Err(ProviderError::Correlation(
                "protocol snapshot issuer absent",
            ));
        };

        Ok(OriginalProtocolSnapshot {
            maximum: original.maximum,
            compact: original.compact,
            owned11_records: original.owned11_records,
            owned11_aliases: original.owned11_aliases,
            original_assigned_cut: original.original_assigned_cut,
            original_restore_cut: original.original_restore_cut,
            original_hello: original.original_hello,
            bytes: original.bytes,
            authority,
            owner,
            cut: original_cut,
            deadline,
            literal: original.literal,
            codec: original.codec,
        })
    }

    #[cfg(test)]
    pub(crate) fn finish(
        self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
    ) -> Result<OriginalProtocolSnapshot, ProviderError> {
        Self::finish_from_slot(&mut Some(self), authority, owner, cut)
    }
}

/// Retains bytes issued by the actual controller and its original authority.
///
/// Private construction distinguishes this owner result from arbitrary decoded
/// data. It grants no native adoption or readiness; the source must authenticate
/// its complete semantic and process custody and literal Hello originals.
pub struct OriginalProtocolSnapshot {
    maximum: usize,
    compact: bool,
    owned11_records: Option<MetadataRecordBank>,
    owned11_aliases: Option<MetadataAliasBank>,
    original_assigned_cut: Option<crate::operational_time::OperationalDeadline>,
    original_restore_cut: Option<crate::operational_time::OperationalDeadline>,
    original_hello:
        Option<Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>>,
    codec: Option<Rc<crate::connection::Native5CodecOwner>>,
    bytes: Vec<u8>,
    authority: ConnectionAuthority,
    owner: Rc<ProtocolCaptureOwner>,
    cut: ProtocolCaptureCut,
    deadline: crate::operational_time::OperationalDeadline,
    literal: Option<crate::transport::original_frames::OriginalFrameReservation>,
}

impl OriginalProtocolSnapshot {
    /// Reports actual retained issuer/codec/registrar and original Hello backing.
    ///
    /// Encoded bytes, metadata/alias banks and frozen literal storage are
    /// reported independently by the existing allocation accessors. The shared
    /// original Hello header and its actual Vec/Slot capacities are included
    /// here; repeated shared views receive no alias discount.
    ///
    /// # Errors
    /// Refuses foreign origin, a borrowed Hello bank or traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            maximum: _,
            compact: _,
            owned11_records: _,
            owned11_aliases: _,
            original_assigned_cut: _,
            original_restore_cut: _,
            original_hello,
            codec,
            bytes: _,
            authority,
            owner,
            cut: _,
            deadline: _,
            literal: _,
        } = self;
        original_association_metadata(owner, authority, codec.as_ref(), original_hello.as_ref())
    }

    /// Reads actual alias banks retained by the original snapshot.
    ///
    /// # Errors
    /// Refuses another original process or thread.
    pub fn original_alias_allocation_facts(
        &self,
    ) -> Result<Option<MetadataAliasAllocationFacts>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self
            .owned11_aliases
            .as_ref()
            .map(MetadataAliasBank::allocation_facts))
    }

    /// Reports the explicit owning edition retained by this original issuer.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn uses_owned11_encoding(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.owned11_records.is_some())
    }

    /// Reports actual metadata record storage retained by this original owner.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn original_metadata_record_allocation_facts(
        &self,
    ) -> Result<Option<MetadataRecordAllocationFacts>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.owned11_records.as_ref().map(metadata_record_facts))
    }

    /// Authenticates the same retained original Hello allocation.
    ///
    /// Byte equality cannot substitute another journal or recreate this owner.
    ///
    /// # Errors
    /// Refuses a changed original process/thread, missing bank, incomplete Hello
    /// or another journal allocation. This grants no live registration right.
    pub fn authenticate_original_hello(
        &self,
        journal: &crate::client::OriginalHelloJournal,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        journal.original_literal_frame_digests()?;
        let bank = self
            .original_hello
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "owned protocol retained Hello absent",
            ))?;
        journal.authenticate_original_literal_bank(bank)
    }

    /// Reports retention of the original restore physical cut.
    ///
    /// This provenance observation cannot renew a deadline or create cut authority.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn retains_original_restore_cut(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.original_restore_cut.is_some())
    }

    /// Reports retention of the original assigned physical cut.
    ///
    /// This provenance observation cannot renew a deadline or create cut authority.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn retains_original_assigned_cut(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.original_assigned_cut.is_some())
    }

    /// Reports the source-bound compact edition of this original snapshot.
    ///
    /// # Errors
    /// Refuses inspection from a different original process or thread.
    pub fn uses_compact_encoding(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.compact)
    }

    /// Reports the actual allocation of this source-issued original snapshot.
    ///
    /// These data-only facts preserve the selected encoded ceiling separately
    /// from its actual capacity and the independently frozen literal copy.
    ///
    /// # Errors
    /// Refuses inspection from a different original process or thread.
    pub fn original_allocation_facts(
        &self,
    ) -> Result<ProtocolSnapshotAllocationFacts, ProviderError> {
        self.owner.ensure_current()?;
        Ok(ProtocolSnapshotAllocationFacts {
            maximum_encoded_bytes: self.maximum,
            encoded_capacity: self.bytes.capacity(),
            encoded_length: self.bytes.len(),
            literal: self
                .literal
                .as_ref()
                .map(|literal| literal.snapshot_allocation_facts()),
            allocated_bytes: self.bytes.capacity()
                + self
                    .owned11_aliases
                    .as_ref()
                    .map_or(0, MetadataAliasBank::allocated_bytes)
                + self
                    .owned11_records
                    .as_ref()
                    .map_or(0, MetadataRecordBank::allocated_bytes)
                + self
                    .literal
                    .as_ref()
                    .map_or(0, |literal| literal.allocated_bytes()),
        })
    }

    /// Borrows exact source-private snapshot bytes without reencoding frames.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the independently frozen original literal frames when reserved.
    pub fn literal_frames(
        &self,
    ) -> Option<impl Iterator<Item = crate::transport::original_frames::OriginalFrame<'_>>> {
        self.literal.as_ref().map(|literal| literal.frames())
    }

    /// Copies frozen historical frames into an empty precharged data bank.
    ///
    /// This preserves raw old-scope bytes, directional counts, lifetime IDs and
    /// exact original byte/descriptor capacities. It does not install a stream,
    /// rebind any envelope, replay a request or grant native adoption/readiness.
    /// The source factory must separately install complete decoded state after
    /// genuine fresh Hello and its private semantic/native settlement proof.
    ///
    /// # Errors
    /// Refuses a copied process/thread owner, absent precharged original copy,
    /// pending native Capture, a used target or differing complete allocation.
    /// Refusal leaves both original snapshot and target history unchanged.
    pub fn prepare_historical_frame_data(
        &self,
        target: &mut crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != ProtocolCaptureCut::HostSettled {
            return Err(ProviderError::Correlation(
                "pending native Capture requires source-owned settlement",
            ));
        }
        let literal = self.literal.as_ref().ok_or(ProviderError::Correlation(
            "original snapshot literal copy was not reserved",
        ))?;
        literal.copy_into_empty(target)
    }

    /// Reports the authenticated correlation cut used by the original capture.
    pub fn cut(&self) -> ProtocolCaptureCut {
        self.cut
    }

    /// Reports exhaustion of the retained original physical cut without renewing it.
    pub fn original_physical_cut_expired(&self) -> bool {
        self.deadline.is_expired()
    }

    pub(crate) fn authenticate_native_capture_antecedent(
        &self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        codec: &Rc<crate::connection::Native5CodecOwner>,
        current: &crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<OriginalNative5CaptureAntecedentFacts, ProviderError> {
        owner.ensure_current()?;
        self.owner.ensure_current()?;
        if self.cut != ProtocolCaptureCut::NativeIncomingCapture
            || !self.same_owner(owner, authority)
            || self
                .codec
                .as_ref()
                .is_none_or(|original| !Rc::ptr_eq(original, codec))
            || self.deadline.is_expired()
        {
            return Err(ProviderError::Correlation(
                "native capture antecedent owner or cut differs",
            ));
        }
        let captured = self.literal.as_ref().ok_or(ProviderError::Correlation(
            "native capture antecedent literal copy absent",
        ))?;
        captured.authenticate_exact_prefix_of(current)?;
        let maximum_frame = usize::try_from(authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native antecedent frame limit"))?;
        Ok(OriginalNative5CaptureAntecedentFacts {
            snapshot_bytes: self.bytes.len(),
            captured: captured.storage_facts(maximum_frame),
            current: current.storage_facts(maximum_frame),
        })
    }

    pub(crate) fn same_owner(
        &self,
        owner: &Rc<ProtocolCaptureOwner>,
        authority: &ConnectionAuthority,
    ) -> bool {
        owner.ensure_current().is_ok()
            && self.owner.ensure_current().is_ok()
            && Rc::ptr_eq(&self.owner, owner)
            && self.authority.same_registration(authority)
    }
}

/// Retains actual old and fresh registrations for source-owned adoption checks.
///
/// Preparation validates two opaque original actors and genuine live fresh
/// Hello registration at a settled host cut. Pending native Capture remains closed
/// until the source factory supplies its private verified settlement.
/// It installs no history, counter, native state or Ready
/// permission. Source5 must join its complete verified settlement and models.
pub struct PreparedFreshProtocolMapping {
    original_body: blake3::Hash,
    original_length: usize,
    original_deadline: crate::operational_time::OperationalDeadline,
    original: ConnectionAuthority,
    original_owner: Rc<ProtocolCaptureOwner>,
    fresh: ConnectionAuthority,
    fresh_owner: Rc<ProtocolCaptureOwner>,
    cut: ProtocolCaptureCut,
    original_codec: Option<Rc<crate::connection::Native5CodecOwner>>,
    fresh_codec: Option<Rc<crate::connection::Native5CodecOwner>>,
}

impl PreparedFreshProtocolMapping {
    #[cfg(test)]
    pub(crate) fn prepare(
        original: &OriginalProtocolSnapshot,
        fresh: &ConnectionAuthority,
        fresh_owner: &Rc<ProtocolCaptureOwner>,
    ) -> Result<Self, ProviderError> {
        Self::prepare_with_codec(original, fresh, fresh_owner, None)
    }

    pub(crate) fn prepare_with_codec(
        original: &OriginalProtocolSnapshot,
        fresh: &ConnectionAuthority,
        fresh_owner: &Rc<ProtocolCaptureOwner>,
        fresh_codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    ) -> Result<Self, ProviderError> {
        original.owner.ensure_current()?;
        fresh_owner.ensure_current()?;
        fresh.ensure_live()?;
        match (original.codec.as_ref(), fresh_codec) {
            (None, None) => {}
            (Some(original), Some(fresh)) => {
                original.authenticate_durable_controller_grammar(fresh)?;
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "fresh protocol codec family changed",
                ));
            }
        }
        if original.codec.is_some()
            && (original.authority.limits() != fresh.limits()
                || original.authority.selected_features() != fresh.selected_features()
                || original.authority.selected_extensions() != fresh.selected_extensions()
                || original.authority.envelope_extensions() != fresh.envelope_extensions())
        {
            return Err(ProviderError::Correlation(
                "fresh protocol negotiation changed",
            ));
        }
        if original.authority.same_registration(fresh)
            || original.authority.connection_id() == fresh.connection_id()
            || original.authority.session_id() == fresh.session_id()
            || original.authority.incarnation_id() == fresh.incarnation_id()
            || original.literal.is_none()
            || original.cut != ProtocolCaptureCut::HostSettled
        {
            return Err(ProviderError::Correlation(
                "fresh protocol mapping requires new scope and settled frozen original history",
            ));
        }
        Ok(Self {
            original_body: blake3::hash(&original.bytes),
            original_length: original.bytes.len(),
            original_deadline: original.deadline,
            original: original.authority.clone(),
            original_owner: original.owner.clone(),
            fresh: fresh.clone(),
            fresh_owner: fresh_owner.clone(),
            cut: original.cut,
            original_codec: original.codec.clone(),
            fresh_codec: fresh_codec.cloned(),
        })
    }

    pub(crate) fn validate_target(
        &self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    ) -> Result<(), ProviderError> {
        owner.ensure_current()?;
        self.fresh_owner.ensure_current()?;
        self.fresh.ensure_live()?;
        authority.ensure_live()?;
        if !self.fresh.same_registration(authority)
            || !Rc::ptr_eq(&self.fresh_owner, owner)
            || !same_codec_owner(self.fresh_codec.as_ref(), codec)
        {
            return Err(ProviderError::Correlation(
                "fresh protocol mapping target owner changed",
            ));
        }
        Ok(())
    }

    /// Borrows both complete actual immutable source-five policies.
    ///
    /// The source factory authenticates their full live admission, coordinator
    /// and target association against its opaque restoration context. These
    /// retained policy views are data and grant no state installation or Ready.
    ///
    /// # Errors
    /// Refuses another actor, revoked target registration or legacy codecs.
    pub fn original_native5_codec_views(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.original_owner.ensure_current()?;
        self.fresh_owner.ensure_current()?;
        self.fresh.ensure_live()?;
        let original = self
            .original_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("original native5 codec absent"))?;
        let target = self
            .fresh_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("target native5 codec absent"))?;
        Ok((original.protocol_view(), target.protocol_view()))
    }

    /// Rechecks the same retained actual actors and fresh registration.
    ///
    /// # Errors
    /// Refuses process/thread drift, revoked fresh Hello or substituted original
    /// issuer/cut/codec, changed captured body, or substituted original physical
    /// cut. The source's signed restoration context must still independently
    /// bind the exact captured reference/ticket before any installation.
    /// This check supplies no semantic settlement or native permission.
    pub fn validate_original(
        &self,
        original: &OriginalProtocolSnapshot,
    ) -> Result<(), ProviderError> {
        self.original_owner.ensure_current()?;
        self.fresh_owner.ensure_current()?;
        self.fresh.ensure_live()?;
        if self.original_length != original.bytes.len()
            || self.original_body != blake3::hash(&original.bytes)
            || self.original_deadline != original.deadline
            || !self.original.same_registration(&original.authority)
            || !Rc::ptr_eq(&self.original_owner, &original.owner)
            || self.cut != original.cut
            || !same_codec_owner(self.original_codec.as_ref(), original.codec.as_ref())
        {
            return Err(ProviderError::Correlation(
                "fresh mapping original owner changed",
            ));
        }
        Ok(())
    }
}

fn same_codec_owner(
    original: Option<&Rc<crate::connection::Native5CodecOwner>>,
    retained: Option<&Rc<crate::connection::Native5CodecOwner>>,
) -> bool {
    match (original, retained) {
        (None, None) => true,
        (Some(original), Some(retained)) => Rc::ptr_eq(original, retained),
        _ => false,
    }
}

pub(crate) struct Sequence<F>(pub(crate) F);
impl<F, I> Serialize for Sequence<F>
where
    F: Fn() -> I,
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for item in (self.0)() {
            sequence.serialize_element(&item)?;
        }
        sequence.end()
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These snapshot controls deliberately panic on invalid fixtures.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native5_original_pending_capture_mapping_requires_source_owned_settlement() {
        let (_old_handshake, old) = crate::handshake::tests::authority();
        let (_fresh_handshake, fresh) =
            crate::handshake::tests::authority_with_scope("pending-target");
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let fresh_owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve_complete(1024, 1024, 2).unwrap();
        reserve
            .bind(
                &old,
                &owner,
                ProtocolCaptureCut::NativeIncomingCapture,
                deadline,
            )
            .unwrap();
        reserve
            .encode(&json!({"incoming":"original Capture"}))
            .unwrap();
        let snapshot = reserve
            .finish(&old, &owner, ProtocolCaptureCut::NativeIncomingCapture)
            .unwrap();

        assert!(PreparedFreshProtocolMapping::prepare(&snapshot, &fresh, &fresh_owner).is_err());
        let mut history =
            crate::transport::original_frames::OriginalFrameReservation::reserve(1024, 2).unwrap();
        assert!(
            snapshot
                .prepare_historical_frame_data(&mut history)
                .is_err()
        );
        assert_eq!(history.frames().count(), 0);
        assert!(fresh.ensure_live().is_ok());
        assert!(!snapshot.bytes().is_empty());
    }

    #[test]
    fn native5_original_snapshot_foreign_process_owner_refuses_before_issuer_or_copy() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut owner = ProtocolCaptureOwner::new();
        owner.pid = owner.pid.wrapping_add(1);
        let owner = Rc::new(owner);
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(1024).unwrap();
        assert!(
            reserve
                .bind(
                    &authority,
                    &owner,
                    ProtocolCaptureCut::HostSettled,
                    deadline
                )
                .is_err()
        );
        assert!(reserve.issuer.is_none());
        assert!(reserve.bytes.is_empty());
    }

    #[test]
    fn native5_original_snapshot_credit_precedes_copy_and_failed_attempt_stays_bound() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(2).unwrap();
        reserve
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        assert!(reserve.encode(&json!({"large": [1,2,3]})).is_err());
        assert!(reserve.bytes.is_empty());
        assert!(
            reserve
                .bind(
                    &authority,
                    &owner,
                    ProtocolCaptureCut::HostSettled,
                    deadline
                )
                .is_err()
        );
        assert!(
            reserve
                .finish(&authority, &owner, ProtocolCaptureCut::HostSettled)
                .is_err()
        );
    }

    #[test]
    fn native5_original_snapshot_cannot_be_claimed_by_another_owner_or_cut() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(1024).unwrap();
        reserve
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        reserve.encode(&json!({"exact": "original"})).unwrap();
        assert!(
            reserve
                .finish(
                    &authority,
                    &Rc::new(ProtocolCaptureOwner::new()),
                    ProtocolCaptureCut::HostSettled
                )
                .is_err()
        );
    }
    #[test]
    fn native5_original_snapshot_copy_geometry_refuses_before_issuer_or_encoding() {
        let source =
            crate::transport::original_frames::OriginalFrameReservation::reserve(1024, 2).unwrap();
        let mut absent = ProtocolSnapshotReservation::reserve(4096).unwrap();
        assert!(absent.validate_literal_reservation(&source).is_err());
        assert!(absent.retain_literal_history(&source).is_err());
        assert!(absent.issuer.is_none());
        assert!(absent.bytes.is_empty());
        assert!(!absent.complete);

        let different = ProtocolSnapshotReservation::reserve_complete(4096, 2048, 2).unwrap();
        assert!(different.validate_literal_reservation(&source).is_err());
        assert!(different.issuer.is_none());
        assert!(different.bytes.is_empty());
        let exact = ProtocolSnapshotReservation::reserve_complete(4096, 1024, 2).unwrap();
        exact.validate_literal_reservation(&source).unwrap();
        assert!(exact.issuer.is_none());
        assert_eq!(source.frames().count(), 0);
    }

    #[test]
    fn native5_original_mapping_rejects_another_body_from_the_same_original_actor() {
        let (_old_handshake, old) = crate::handshake::tests::authority();
        let (_new_handshake, fresh) = crate::handshake::tests::authority_with_scope("body-target");
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let fresh_owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut original_snapshots = Vec::new();
        for body in [
            serde_json::json!({"actual":"first"}),
            serde_json::json!({"actual":"second"}),
        ] {
            let mut reservation =
                ProtocolSnapshotReservation::reserve_complete(1024, 1024, 2).unwrap();
            reservation
                .bind(&old, &owner, ProtocolCaptureCut::HostSettled, deadline)
                .unwrap();
            reservation.encode(&body).unwrap();
            original_snapshots.push(
                reservation
                    .finish(&old, &owner, ProtocolCaptureCut::HostSettled)
                    .unwrap(),
            );
        }
        let mapping =
            PreparedFreshProtocolMapping::prepare(&original_snapshots[0], &fresh, &fresh_owner)
                .unwrap();
        mapping.validate_original(&original_snapshots[0]).unwrap();
        assert!(mapping.validate_original(&original_snapshots[1]).is_err());
        assert_eq!(original_snapshots[0].bytes(), b"{\"actual\":\"first\"}");
        assert!(fresh.ensure_live().is_ok());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod reservation_allocation_tests {
    use super::*;

    #[test]
    fn native5_snapshot_reservation_facts_report_both_actual_independent_banks() {
        let ordinary = ProtocolSnapshotReservation::reserve(1024).unwrap();
        let ordinary_facts = ordinary.original_allocation_facts().unwrap();
        assert_eq!(ordinary_facts.encoded_capacity, ordinary.bytes.capacity());
        assert_eq!(ordinary_facts.literal, None);
        assert_eq!(ordinary_facts.allocated_bytes, ordinary.allocated_bytes());

        let mut complete = ProtocolSnapshotReservation::reserve_complete(4096, 2048, 3).unwrap();
        let before = complete.original_allocation_facts().unwrap();
        let literal = before.literal.unwrap();
        assert_eq!(before.encoded_capacity, complete.bytes.capacity());
        assert_eq!(literal.byte_capacity, 2048);
        assert_eq!(literal.descriptor_capacity, 6);
        assert!(literal.descriptor_bytes > 0);
        assert_eq!(literal.maximum_frames_per_direction, 3);
        assert_eq!(
            before.allocated_bytes,
            before.encoded_capacity + literal.allocated_bytes
        );

        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        complete
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        complete
            .encode(&serde_json::json!({"state":"original"}))
            .unwrap();
        let encoded = complete.original_allocation_facts().unwrap();
        assert!(encoded.encoded_length > 0);
        assert_eq!(encoded.encoded_capacity, before.encoded_capacity);
        assert_eq!(encoded.literal, before.literal);

        complete.issuer.as_mut().unwrap().1 = Rc::new(ProtocolCaptureOwner {
            pid: std::process::id().wrapping_add(1),
            thread: std::thread::current().id(),
        });
        assert!(complete.original_allocation_facts().is_err());
        assert_eq!(complete.allocated_bytes(), before.allocated_bytes);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod owning_finish_tests {
    use super::*;

    #[test]
    fn native5_original_finish_refusal_keeps_same_encoded_and_literal_allocations() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut original = ProtocolSnapshotReservation::reserve_complete(4096, 1024, 3).unwrap();
        original
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        original
            .encode(&serde_json::json!({"state":"original"}))
            .unwrap();
        let facts = original.original_allocation_facts().unwrap();
        let pointer = original.bytes.as_ptr();
        let body = original.bytes.clone();
        let mut slot = Some(original);

        assert!(
            ProtocolSnapshotReservation::finish_from_slot(
                &mut slot,
                &authority,
                &owner,
                ProtocolCaptureCut::NativeIncomingCapture
            )
            .is_err()
        );
        let retained = slot.as_ref().unwrap();
        assert_eq!(retained.bytes.as_ptr(), pointer);
        assert_eq!(retained.bytes, body);
        assert_eq!(retained.original_allocation_facts().unwrap(), facts);

        let snapshot = ProtocolSnapshotReservation::finish_from_slot(
            &mut slot,
            &authority,
            &owner,
            ProtocolCaptureCut::HostSettled,
        )
        .unwrap();
        assert!(slot.is_none());
        assert_eq!(snapshot.bytes.as_ptr(), pointer);
        assert_eq!(snapshot.bytes(), body);
        assert_eq!(snapshot.original_allocation_facts().unwrap(), facts);
        assert_eq!(
            snapshot
                .original_allocation_facts()
                .unwrap()
                .maximum_encoded_bytes,
            4096
        );
        assert!(
            ProtocolSnapshotReservation::finish_from_slot(
                &mut slot,
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled
            )
            .is_err()
        );
    }
}

/// Exposes actual retained protocol metadata capacity facts.
pub use crate::retained_metadata::RetainedProtocolMetadataFacts;

pub(crate) fn protocol_capture_owner_layout() -> usize {
    std::mem::size_of::<ProtocolCaptureOwner>()
}

mod native_metadata_quote;
pub(crate) use native_metadata_quote::NativeProtocolMetadataQuote;

impl ProtocolSnapshotReservation {
    pub(crate) const fn maximum_bytes(&self) -> usize {
        self.maximum
    }
}

mod archived_mapping;
pub use archived_mapping::PreparedArchivedProtocolMapping;

pub(crate) use archived_mapping::{
    ArchivedProtocolMappingIdentity, ArchivedProtocolMappingInput, ArchivedProtocolMappingTarget,
    RestorationMappingClass,
};

mod native_archived_mapping;
pub(crate) use native_archived_mapping::{
    NativeArchivedMappingInput, PreparedArchivedNativeProtocolMapping,
};

fn original_association_metadata(
    owner: &Rc<ProtocolCaptureOwner>,
    authority: &ConnectionAuthority,
    codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    hello: Option<
        &Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
    >,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    owner.ensure_current()?;
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    observer.shared_value(owner.as_ref())?;
    authority.observe_retained_metadata(&mut observer)?;
    if let Some(codec) = codec {
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(&mut observer)?;
    }
    if let Some(hello) = hello {
        observer.shared_value(hello.as_ref())?;
        let bank = hello
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original Hello metadata borrowed"))?;
        bank.observe_owned11_metadata(&mut observer)?;
    }
    Ok(observer.finish())
}

mod original_creator;
pub(crate) use original_creator::OriginalProtocolCreatorView;

mod host_metadata_quote;
pub use host_metadata_quote::OriginalOwned11StateQuote;

/// Preserves complete suffix ledger/history as inert versioned data, never a live permit.
pub mod restored_suffix_history;

/// Reads exact restoration-stage history as DATA, independently of live Capture.
pub mod native_restoration_stage_history;

/// Provides the separate current native17 reader and explicit immutable-DAG bounds.
pub mod restored_settled17;

pub(crate) mod settled_reservation17;

pub mod restored_journal17;

pub(crate) mod native_wholegraph17;

/// Reads current logical Connection17 state without creating live protocol owners.
pub mod current_connection17;

/// Reads the complete current Controller17 logical DATA component.
pub mod current_controller17;

#[path = "protocol_snapshot/current_sdk_capture17.rs"]
mod current_sdk_capture17;
#[path = "protocol_snapshot/current_transport17.rs"]
mod current_transport17;

#[path = "protocol_snapshot/current_native_connection17.rs"]
mod current_native_connection17;

/// Lends schema-neutral JSON field DATA without constructing historical owners.
pub mod borrowed_json;

/// Quotes additional owned JSON Value reparsing without parsing or authority.
pub mod raw_value_reparse;
