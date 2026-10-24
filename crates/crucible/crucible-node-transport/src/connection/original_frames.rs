//! Literal frame archive installation and actual partial-write progress.

use super::*;
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};

impl<S: ProviderStream> Connection<S> {
    /// Selects the immutable baseline packet codec and installs precharged bytes.
    ///
    /// This crate-private seam is selected only by the installed source factory.
    /// A mutable caller-supplied verifier cannot opt into exact protocol capture.
    pub(crate) fn install_native5_frame_bank(
        &mut self,
        reservation: OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        self.check_authority()?;
        if self.original_frames.is_some() || !self.guard.unused() {
            return Err(ProviderError::Correlation(
                "native5 bank requires original unused connection",
            ));
        }
        self.install_packet_schema()?;
        let bank = Rc::new(std::cell::RefCell::new(reservation));
        self.reader.install_originals(bank.clone());
        self.original_frames = Some(bank);
        Ok(())
    }

    /// Installs one immutable connected input codec and its precharged archive.
    ///
    /// Binding, owner and negotiated Input4 features are checked on the same
    /// unused original connection before taking the caller's bank. This selects
    /// transport retention only; full Native5 codec capture remains separate.
    pub(crate) fn install_native5_connected_frame_bank(
        &mut self,
        reservation: &mut Option<OriginalFrameReservation>,
        binding: &crucible_node_format::NodeBinding,
        owner: &crucible_node_format::OwnerBinding,
    ) -> Result<(), ProviderError> {
        self.check_authority()?;
        if self.original_frames.is_some()
            || !self.guard.unused()
            || reservation
                .as_ref()
                .is_none_or(|bank| bank.frames().next().is_some())
        {
            return Err(ProviderError::Correlation(
                "connected archive requires unused original bank and connection",
            ));
        }
        self.install_connected_packet_schema(binding, owner)?;
        let original = reservation
            .take()
            .ok_or(ProviderError::Correlation("connected original bank absent"))?;
        let bank = Rc::new(std::cell::RefCell::new(original));
        self.reader.install_originals(bank.clone());
        self.original_frames = Some(bank);
        Ok(())
    }

    /// Captures the actual endpoint with its precharged source-owned buffer.
    ///
    /// The source retains literal Hello and semantic/native state separately.
    /// An incoming Capture remains pending in this snapshot before its reply.
    ///
    /// # Errors
    /// Refuses absent/incomplete banks, mutable codecs, unsupported cuts,
    /// revoked registration, outstanding unrelated correlations or byte credit.
    pub fn capture_native_protocol_state(
        &mut self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        if reservation.uses_owned11_encoding() {
            return Err(ProviderError::Correlation(
                "native owning protocol boot/admission owner view not installed",
            ));
        }
        self.protocol_capture_preflight(cut)?;
        self.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(
            self.native5_codec.as_ref(),
            cut,
            self.role == EndpointRole::Controller,
        )?;
        reservation.bind(
            &self.authority,
            &self.protocol_owner,
            cut,
            deadline.original_cut(),
        )?;
        reservation.retain_native5_codec(self.native5_codec.as_ref())?;
        if reservation.uses_compact_encoding() {
            reservation.encode(&(
                "source-private.native-cnp/7",
                self.original_native5_capture_profile()?,
                self.protocol_view_with_encoding(true),
            ))?;
        } else {
            reservation.encode(&self.protocol_view())?;
        }
        self.retain_frozen_protocol_frames(reservation)
    }

    /// Binds the actual blob ledger before the endpoint's first control frame.
    ///
    /// This retains an opaque local owner identity, never a pointer on the wire.
    /// It grants no source selection, semantic capture or native installation.
    ///
    /// # Errors
    /// Refuses a used endpoint, absent frame bank, a previous ledger binding,
    /// revoked authority or a receiver outside the genuine connection scope.
    pub fn bind_native5_blob_receiver(
        &mut self,
        blobs: &crate::blob::BlobReceiver,
    ) -> Result<(), ProviderError> {
        self.check_authority()?;
        if !self.guard.unused() || self.original_frames.is_none() || self.native5_blobs.is_some() {
            return Err(ProviderError::Correlation(
                "native5 blob owner requires original unused archived endpoint",
            ));
        }
        blobs.original_protocol_view(&self.authority)?;
        self.native5_blobs = Some(blobs.protocol_owner());
        Ok(())
    }

    /// Captures the exact endpoint and its same-scope original blob ledger.
    ///
    /// The borrowed ledger remains read-locked through sizing and encoding, so
    /// no transfer, tombstone, pin or credit can change between those passes.
    /// Native source state and literal Hello custody remain separately sealed.
    ///
    /// # Errors
    /// Refuses foreign or mutably borrowed blob custody, partial protocol cuts,
    /// absent immutable codecs, revoked authority or insufficient complete credit.
    pub fn capture_native_protocol_state_with_blobs(
        &mut self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
        deadline: &crate::client::ExchangeDeadline,
        blobs: &crate::blob::BlobReceiver,
    ) -> Result<(), ProviderError> {
        if reservation.uses_owned11_encoding() {
            return Err(ProviderError::Correlation(
                "native owning protocol boot/admission owner view not installed",
            ));
        }
        self.protocol_capture_preflight(cut)?;
        if self
            .native5_blobs
            .as_ref()
            .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "native5 snapshot requires the original pre-bound blob owner",
            ));
        }
        let original_blobs = blobs.original_protocol_view(&self.authority)?;
        self.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(
            self.native5_codec.as_ref(),
            cut,
            self.role == EndpointRole::Controller,
        )?;
        reservation.bind(
            &self.authority,
            &self.protocol_owner,
            cut,
            deadline.original_cut(),
        )?;
        reservation.retain_native5_codec(self.native5_codec.as_ref())?;
        if reservation.uses_compact_encoding() {
            reservation.encode(&(
                "source-private.native-cnp/7",
                self.original_native5_capture_profile()?,
                self.protocol_view_with_encoding(true),
                original_blobs.with_compact_encoding(true),
            ))?;
        } else {
            reservation.encode(&(
                "source-private.native-cnp/5",
                self.protocol_view(),
                original_blobs,
            ))?;
        }
        self.retain_frozen_protocol_frames(reservation)
    }

    /// Admits encoding capacity after a finite original Capture suffix without I/O.
    ///
    /// The same original codec/blob owner and exact after-profile reservation are
    /// rechecked. Counting the current body plus the entire selected literal and
    /// descriptor banks conservatively covers every successfully settled suffix
    /// within those banks; it never predicts acknowledgements or issues an owner.
    /// The source separately proves prospective sends and incoming raw extents
    /// fit the live bank and prevents uncredited blob/codec changes during I/O.
    ///
    /// # Errors
    /// Refuses a nonprovider/copy/fenced actor, foreign or borrowed blob ledger,
    /// unsupported current cut, used or mismatched reserved after bank, overflow
    /// or insufficient whole encoding credit. All original state is retained.
    pub fn preflight_native5_after_protocol_capacity(
        &self,
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
    ) -> Result<crate::protocol_snapshot::Native5AfterProtocolCapacityFacts, ProviderError> {
        self.preflight_native5_after_protocol_capacity_inner(reservation, blobs, None)
    }

    pub(super) fn preflight_native5_after_protocol_capacity_inner(
        &self,
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        prepared: Option<&[Envelope]>,
    ) -> Result<crate::protocol_snapshot::Native5AfterProtocolCapacityFacts, ProviderError> {
        use crate::protocol_snapshot::{Native5AfterProtocolCapacityFacts, ProtocolCaptureCut};
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider || !reservation.unused_for_after_preflight() {
            return Err(ProviderError::Correlation(
                "after preflight requires original provider and unused bank",
            ));
        }
        match prepared {
            None => self
                .guard
                .protocol_cut(ProtocolCaptureCut::NativeIncomingCapture)?,
            Some(originals) => self.guard.authenticate_prepared_capture_suffix(originals)?,
        }
        if self
            .native5_blobs
            .as_ref()
            .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "after preflight requires same original blob owner",
            ));
        }
        let original_blobs = blobs.original_protocol_view(&self.authority)?;
        reservation.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::HostSettled,
            false,
        )?;
        let current = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("after original bank absent"))?
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("after original bank mutably borrowed"))?;
        reservation.validate_literal_reservation(&current)?;
        let selected = reservation
            .original_allocation_facts()?
            .maximum_encoded_bytes;
        let compact = reservation.uses_compact_encoding();
        let current_encoded_bytes = if compact {
            super::serialized_credit(
                &(
                    "source-private.native-cnp/7",
                    self.original_native5_capture_profile()?,
                    self.protocol_view_with_encoding(true),
                    original_blobs.with_compact_encoding(true),
                ),
                selected,
            )?
        } else {
            super::serialized_credit(
                &(
                    "source-private.native-cnp/5",
                    self.protocol_view(),
                    original_blobs,
                ),
                selected,
            )?
        };
        let (maximum_literal_encoded_bytes, maximum_descriptor_encoded_bytes) =
            current.maximum_encoding_growth(compact)?;
        // Four bank counters and two sequence counters cannot grow by more than
        // 20 decimal bytes each on this source's supported 64-bit target.
        let maximum_counter_growth_bytes = 6 * 20;
        let maximum_after_encoded_bytes = current_encoded_bytes
            .checked_add(maximum_literal_encoded_bytes)
            .and_then(|n| n.checked_add(maximum_descriptor_encoded_bytes))
            .and_then(|n| n.checked_add(maximum_counter_growth_bytes))
            .filter(|n| *n <= selected)
            .ok_or(ProviderError::ResourceExhausted(
                "complete after protocol encoding credit",
            ))?;
        Ok(Native5AfterProtocolCapacityFacts {
            current_encoded_bytes,
            maximum_literal_encoded_bytes,
            maximum_descriptor_encoded_bytes,
            maximum_counter_growth_bytes,
            maximum_after_encoded_bytes,
            reserved_after_encoded_bytes: selected,
        })
    }

    /// Takes a completed capture issued by this exact endpoint and registration.
    ///
    /// # Errors
    /// Refuses an empty, incomplete or foreign issuer buffer or changed cut.
    /// This owner result grants no native installation or fresh-adoption right.
    pub fn take_native_protocol_snapshot(
        &mut self,
        reservation: &mut Option<crate::protocol_snapshot::ProtocolSnapshotReservation>,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolSnapshot, ProviderError> {
        if reservation
            .as_ref()
            .is_some_and(|bank| bank.uses_owned11_encoding())
        {
            self.native_owned11_preflight(cut)?;
        } else {
            self.protocol_capture_preflight(cut)?;
        }
        crate::protocol_snapshot::ProtocolSnapshotReservation::finish_from_slot(
            reservation,
            &self.authority,
            &self.protocol_owner,
            cut,
        )
    }

    /// Retains a completed original snapshot in the caller's owning result slot.
    ///
    /// Failure leaves the same reservation in its original slot. Success fills
    /// the empty result slot before the source performs any later guard or copy;
    /// no fallible revalidation occurs after the reservation moves.
    ///
    /// # Errors
    /// Refuses an occupied result, absent or incomplete reservation, foreign
    /// original issuer, changed registration or incompatible current cut.
    pub fn take_native_protocol_snapshot_into(
        &mut self,
        reservation: &mut Option<crate::protocol_snapshot::ProtocolSnapshotReservation>,
        completed: &mut Option<crate::protocol_snapshot::OriginalProtocolSnapshot>,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "original snapshot result slot occupied",
            ));
        }
        let original = self.take_native_protocol_snapshot(reservation, cut)?;
        *completed = Some(original);
        Ok(())
    }

    /// Authenticates an opaque pending native snapshot against its ended original channel.
    ///
    /// The actual actor, registration and sealed native policy must be identical;
    /// every frozen literal byte, slot, request ID and capacity must be an exact
    /// prefix of the same current bank. Both histories must have complete I/O and
    /// current correlations must be settled. No allocation or callback occurs.
    ///
    /// This proves physical antecedent correspondence only. The source separately
    /// verifies the exact complete object/ACK suffix, terminal Capture result and
    /// signed fresh-target association before minting its private settlement.
    ///
    /// # Errors
    /// Refuses foreign/revoked actors, replaced or non-native codecs, wrong cuts,
    /// expired original physical allowance, changed literal history, incomplete
    /// I/O, outstanding correlations or an actively borrowed original bank.
    pub fn authenticate_native5_capture_antecedent(
        &self,
        snapshot: &crate::protocol_snapshot::OriginalProtocolSnapshot,
    ) -> Result<crate::protocol_snapshot::OriginalNative5CaptureAntecedentFacts, ProviderError>
    {
        self.authenticate_native5_source_codec()?;
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native capture antecedent codec absent",
            ))?;
        if self.role != EndpointRole::Provider
            || !matches!(codec.as_ref(), Native5CodecOwner::NativePacket(_))
        {
            return Err(ProviderError::Correlation(
                "native capture antecedent requires native endpoint",
            ));
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native capture antecedent bank absent",
            ))?
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("native antecedent bank in use"))?;
        snapshot.authenticate_native_capture_antecedent(
            &self.authority,
            &self.protocol_owner,
            codec,
            &bank,
        )
    }

    /// Prepares actual new-scope registration mapping without installing state.
    ///
    /// A source factory must still join complete Wire/Scheduling/native state,
    /// budgeted decoded fields and private pending-Capture settlement. No old
    /// frame is submitted under this fresh connection by preparation.
    ///
    /// # Errors
    /// Refuses used, unarchived, mutable-codec or revoked fresh connections,
    /// unchanged scope IDs, foreign actor identities or missing frozen originals.
    pub fn prepare_fresh_protocol_mapping(
        &mut self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
    ) -> Result<crate::protocol_snapshot::PreparedFreshProtocolMapping, ProviderError> {
        let owner = self.protocol_owner.clone();
        self.prepare_fresh_protocol_mapping_for_owner(original, &owner)
    }

    pub(crate) fn prepare_fresh_protocol_mapping_for_owner(
        &mut self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<crate::protocol_snapshot::PreparedFreshProtocolMapping, ProviderError> {
        owner.ensure_current()?;
        self.check_authority()?;
        if self.native5_codec.is_some() {
            self.authenticate_native5_source_codec()?;
        }
        if !self.guard.unused()
            || (!self.packet_schema && self.native5_codec.is_none())
            || self
                .original_frames
                .as_ref()
                .is_none_or(|bank| bank.borrow().frames().next().is_some())
        {
            return Err(ProviderError::Correlation(
                "fresh mapping requires original unused immutable archived connection",
            ));
        }
        crate::protocol_snapshot::PreparedFreshProtocolMapping::prepare_with_codec(
            original,
            &self.authority,
            owner,
            self.native5_codec.as_ref(),
        )
    }

    /// Rechecks the actual unused target that prepared a native-five codec mapping.
    ///
    /// This authenticates only SDK owner correspondence. The source factory
    /// separately authenticates the signed native and semantic target context;
    /// no captured bytes, counters or Ready permission are installed here.
    ///
    /// # Errors
    /// Refuses another original actor, target registration or immutable codec,
    /// a used target, unavailable source snapshot, or revoked authority.
    pub fn authenticate_fresh_native5_protocol_mapping(
        &self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        mapping: &crate::protocol_snapshot::PreparedFreshProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.authenticate_fresh_native5_mapping_for_owner(original, mapping, &self.protocol_owner)
    }

    pub(crate) fn authenticate_fresh_native5_mapping_for_owner(
        &self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        mapping: &crate::protocol_snapshot::PreparedFreshProtocolMapping,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if !self.guard.unused()
            || self
                .original_frames
                .as_ref()
                .is_none_or(|bank| match bank.try_borrow() {
                    Ok(bank) => bank.frames().next().is_some(),
                    Err(_) => true,
                })
        {
            return Err(ProviderError::Correlation(
                "fresh native5 mapped connection already used",
            ));
        }
        mapping.validate_original(original)?;
        mapping.validate_target(&self.authority, owner, self.native5_codec.as_ref())
    }

    pub(crate) fn original_native5_storage_facts(
        &self,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolStorageFacts, ProviderError> {
        self.authenticate_native5_source_codec()?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 original literal bank absent",
            ))?
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("native5 literal bank is mutably borrowed"))?;
        Ok(bank.storage_facts(allowance(self.authority.limits().frame_bytes.get())?))
    }

    pub(crate) fn preflight_protocol_reservation(
        &self,
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
    ) -> Result<(), ProviderError> {
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("original literal bank absent"))?
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("original literal bank is mutably borrowed"))?;
        reservation.validate_literal_reservation(&bank)
    }

    pub(crate) fn retain_frozen_protocol_frames(
        &self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
    ) -> Result<(), ProviderError> {
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("original literal bank absent"))?
            .borrow();
        reservation.retain_literal_history(&bank)
    }

    pub(crate) fn protocol_capture_preflight(
        &mut self,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        if self.original_canonical_ack_admission.is_some() {
            return Err(ProviderError::Correlation(
                "native admission complete owning edition not installed",
            ));
        }
        self.check_authority()?;
        if let Some(codec) = &self.native5_codec {
            codec.validate_installation(&self.authority)?;
        }
        if (!self.packet_schema && self.native5_codec.is_none())
            || self
                .original_frames
                .as_ref()
                .is_none_or(|bank| !bank.borrow().complete())
        {
            return Err(ProviderError::Correlation(
                "exact protocol capture requires immutable codec and complete literal bank",
            ));
        }
        self.guard.protocol_cut(cut)
    }

    pub(crate) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        self.protocol_view_with_encoding(false)
    }

    pub(crate) fn protocol_view_with_encoding(&self, compact: bool) -> impl serde::Serialize + '_ {
        struct View<'a, S: ProviderStream>(&'a Connection<S>, bool);
        impl<S: ProviderStream> serde::Serialize for View<'_, S> {
            fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
                use serde::ser::SerializeStruct;
                let c = self.0;
                let bank = c
                    .original_frames
                    .as_ref()
                    .ok_or_else(|| serde::ser::Error::custom("original bank absent"))?
                    .borrow();
                let mut state = serializer.serialize_struct("Native5Connection", 14)?;
                state.serialize_field("session", c.authority.session_id())?;
                state.serialize_field("incarnation", c.authority.incarnation_id())?;
                state.serialize_field("connection", c.authority.connection_id())?;
                state.serialize_field(
                    "epoch",
                    &crucible_node_format::U64::new(c.authority.epoch()),
                )?;
                state.serialize_field("limits", &c.authority.limits())?;
                state.serialize_field("features", c.authority.selected_features())?;
                state.serialize_field("extensions", &c.authority.selected_extensions())?;
                state.serialize_field("envelope_extensions", c.authority.envelope_extensions())?;
                state.serialize_field("correlations", &c.guard.protocol_view())?;
                state.serialize_field("frames", &bank.protocol_view_with_encoding(self.1))?;
                state.serialize_field("packet_schema", &c.packet_schema)?;
                if self.1 {
                    state.serialize_field(
                        "native5_codec",
                        &c.native5_codec
                            .as_ref()
                            .map(|codec| codec.compact_protocol_view()),
                    )?;
                } else {
                    state.serialize_field(
                        "native5_codec",
                        &c.native5_codec.as_ref().map(|codec| codec.protocol_view()),
                    )?;
                }
                state.serialize_field("fenced", &c.fenced)?;
                state.serialize_field(
                    "role",
                    &match c.role {
                        EndpointRole::Controller => "controller",
                        EndpointRole::Provider => "provider",
                    },
                )?;
                state.end()
            }
        }
        View(self, compact)
    }

    pub(crate) fn retain_original_request_id(
        &mut self,
        original: &Envelope,
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        if original.message != MessageKind::Request || self.original_frames.is_none() {
            return Ok(());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Frame("original request bank absent"))?;
        let slot = slot.ok_or(ProviderError::Frame("original request slot absent"))?;
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("original request ID absent"))?;
        bank.borrow_mut().retain_request(slot, id)
    }

    pub(crate) fn prepare_original_send(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<usize>, ProviderError> {
        let Some(bank) = &self.original_frames else {
            return Ok(None);
        };
        let length =
            u32::try_from(bytes.len()).map_err(|_| ProviderError::Frame("original send length"))?;
        let mut bank = bank.borrow_mut();
        let index = bank.begin(
            FrameDirection::Outgoing,
            bytes
                .len()
                .checked_add(4)
                .ok_or(ProviderError::ResourceExhausted("original frame length"))?,
        )?;
        bank.append(index, &length.to_be_bytes())?;
        bank.append(index, bytes)?;
        Ok(Some(index))
    }

    pub(crate) fn publish_original_send(
        &mut self,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        let length =
            u32::try_from(bytes.len()).map_err(|_| ProviderError::Frame("original send length"))?;
        let header = length.to_be_bytes();
        if let Some(index) = slot {
            let bank = self
                .original_frames
                .as_ref()
                .ok_or(ProviderError::Frame("original bank absent"))?;
            if !bank.borrow().matches_send(index, &header, bytes) {
                return Err(ProviderError::Conflict(
                    "original send prefix changed or already attempted",
                ));
            }
        } else if self.original_frames.is_some() {
            return Err(ProviderError::Frame("original send slot absent"));
        }
        let stream = self.reader.stream_mut();
        for part in [&header[..], bytes] {
            let mut used = 0;
            while used < part.len() {
                let count = match stream.write(&part[used..]) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                if let Some(index) = slot {
                    let bank = self
                        .original_frames
                        .as_ref()
                        .ok_or(ProviderError::Frame("original bank absent"))?;
                    bank.borrow_mut().advance(index, count)?;
                }
                used += count;
            }
        }
        if let Some(index) = slot {
            let bank = self
                .original_frames
                .as_ref()
                .ok_or(ProviderError::Frame("original bank absent"))?;
            bank.borrow_mut().finish(index)?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
// crucible-lint: allow panic-shortcut -- These transport controls deliberately panic on invalid fixtures.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Cursor, Error, ErrorKind};

    #[derive(Default)]
    struct Supervisor;
    impl ConnectionSupervisor for Supervisor {
        fn quarantine(&self, _: ConnectionIncident) {}
    }
    struct Schemas;
    impl BodySchemaVerifier for Schemas {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    struct PartialStream {
        sent: Vec<u8>,
        remaining: usize,
    }

    impl Read for PartialStream {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for PartialStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(Error::new(ErrorKind::BrokenPipe, "original cut"));
            }
            let count = bytes.len().min(self.remaining).min(2);
            self.sent.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl ProviderStream for PartialStream {
        fn fence(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native5_original_actual_unix_partial_prepared_write_retains_kernel_prefix() {
        use crucible_node_format::U64;
        let (_handshake, authority) =
            crate::handshake::tests::authority_with_frame_limit(1_048_576);
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut connection = Connection::new(
            stream,
            authority.clone(),
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        connection
            .install_native5_frame_bank(OriginalFrameReservation::reserve(2_097_152, 4).unwrap())
            .unwrap();
        let mut request = crate::envelope::tests::request();
        request.session_id = crate::envelope::Nullable(Some(authority.session_id().clone()));
        request.incarnation_id =
            crate::envelope::Nullable(Some(authority.incarnation_id().clone()));
        request.sequence = U64::new(2);
        request.method = Method::Discover;
        let profiles: Vec<String> = (0..4096)
            .map(|n| format!("profile{n:04}{}", "x".repeat(110)))
            .collect();
        request.body = serde_json::json!({"profile_ids":profiles,"extensions":{}})
            .as_object()
            .unwrap()
            .clone();
        let prepared = connection.prepare_send(request).unwrap();
        assert!(prepared.publish().is_err());
        assert!(connection.authenticate_native5_source_codec().is_err());
        let bank = connection.original_frames.as_ref().unwrap().borrow();
        let original = bank.frames().next().unwrap();
        assert!(original.transferred > 4);
        assert!(original.transferred < original.bytes.len());
        assert!(!original.complete);
        let mut kernel_prefix = vec![0; original.transferred];
        peer.read_exact(&mut kernel_prefix).unwrap();
        assert_eq!(kernel_prefix, original.bytes[..original.transferred]);
        assert!(connection.fenced);
        assert!(bank.frames().count() == 1);
    }

    #[test]
    fn native5_original_actual_unix_capture_preserves_response_bytes_and_correlations() {
        use crate::protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation};
        use crucible_node_format::U64;
        let (_handshake, authority) = crate::handshake::tests::authority();
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut connection = Connection::new(
            stream,
            authority.clone(),
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        connection
            .install_native5_frame_bank(OriginalFrameReservation::reserve(16384, 8).unwrap())
            .unwrap();
        let mut request = crate::envelope::tests::request();
        request.session_id = crate::envelope::Nullable(Some(authority.session_id().clone()));
        request.incarnation_id =
            crate::envelope::Nullable(Some(authority.incarnation_id().clone()));
        request.sequence = U64::new(2);
        connection.send(request.clone()).unwrap();
        assert!(
            connection
                .protocol_capture_preflight(ProtocolCaptureCut::HostSettled)
                .is_err()
        );
        let mut response = request.clone();
        response.message = MessageKind::Response;
        response.body = serde_json::json!({"status":"completed", "operation_state":"completed", "extensions":{},
            "result":{"operation_id":"operation-1", "operation_state":"running", "outcome":null,
            "observations":[], "next_observation_sequence":"0"}}).as_object().unwrap().clone();
        let mut raw = serde_json::to_vec(&response).unwrap();
        raw.extend_from_slice(b" \n");
        peer.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
        peer.write_all(&raw).unwrap();
        connection.receive().unwrap().unwrap();
        connection
            .protocol_capture_preflight(ProtocolCaptureCut::HostSettled)
            .unwrap();
        let deadline =
            crate::client::ExchangeDeadline::start(std::time::Duration::from_secs(2)).unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve_complete(65536, 16384, 8).unwrap();
        connection
            .capture_native_protocol_state(&mut reserve, ProtocolCaptureCut::HostSettled, &deadline)
            .unwrap();
        let mut slot = Some(reserve);
        let snapshot = connection
            .take_native_protocol_snapshot(&mut slot, ProtocolCaptureCut::HostSettled)
            .unwrap();
        assert!(slot.is_none());
        let decoded: serde_json::Value = serde_json::from_slice(snapshot.bytes()).unwrap();
        let bank_bytes: Vec<u8> = serde_json::from_value(decoded["frames"][6].clone()).unwrap();
        assert_eq!(&bank_bytes[bank_bytes.len() - raw.len()..], raw.as_slice());
        assert_eq!(decoded["correlations"][0], "source-private.correlations/6");
        assert_eq!(decoded["correlations"][3], "3");
        assert_eq!(decoded["correlations"][4], "3");
        assert!(decoded["correlations"][6].as_object().unwrap().is_empty());
        assert_eq!(decoded["frames"][7].as_array().unwrap().len(), 2);
        assert_eq!(snapshot.literal_frames().unwrap().count(), 2);

        // Scope labels alone cannot turn another registration into a fresh one.
        let (_same_handshake, same_authority) = crate::handshake::tests::authority();
        let (same_stream, _same_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut same_scope = Connection::new(
            same_stream,
            same_authority,
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        same_scope
            .install_native5_frame_bank(OriginalFrameReservation::reserve(16384, 8).unwrap())
            .unwrap();
        assert!(
            same_scope
                .prepare_fresh_protocol_mapping(&snapshot)
                .is_err()
        );

        let (fresh_handshake, fresh_authority) =
            crate::handshake::tests::authority_with_scope("fresh");
        let (fresh_stream, _fresh_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut fresh = Connection::new(
            fresh_stream,
            fresh_authority.clone(),
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        fresh
            .install_native5_frame_bank(OriginalFrameReservation::reserve(16384, 8).unwrap())
            .unwrap();
        let mapping = fresh.prepare_fresh_protocol_mapping(&snapshot).unwrap();
        mapping.validate_original(&snapshot).unwrap();
        assert_eq!(
            fresh
                .original_frames
                .as_ref()
                .unwrap()
                .borrow()
                .frames()
                .count(),
            0
        );
        assert_eq!(
            serde_json::to_value(fresh.guard.protocol_view()).unwrap()[3],
            "2"
        );

        // A different actor can issue bytes under the same registration; those
        // bytes still cannot replace the retained original owner of this mapping.
        let foreign_owner = Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new());
        let mut foreign_reserve =
            ProtocolSnapshotReservation::reserve_complete(65536, 16384, 8).unwrap();
        foreign_reserve
            .bind(
                &authority,
                &foreign_owner,
                ProtocolCaptureCut::HostSettled,
                crate::operational_time::OperationalDeadline::after(
                    std::time::Duration::from_secs(2),
                )
                .unwrap(),
            )
            .unwrap();
        foreign_reserve
            .encode(&serde_json::json!({"foreign":"owner"}))
            .unwrap();
        let foreign_snapshot = foreign_reserve
            .finish(&authority, &foreign_owner, ProtocolCaptureCut::HostSettled)
            .unwrap();
        assert!(mapping.validate_original(&foreign_snapshot).is_err());

        let mut fresh_request = request.clone();
        fresh_request.session_id =
            crate::envelope::Nullable(Some(fresh_authority.session_id().clone()));
        fresh_request.incarnation_id =
            crate::envelope::Nullable(Some(fresh_authority.incarnation_id().clone()));
        fresh.send(fresh_request).unwrap();
        assert!(fresh.prepare_fresh_protocol_mapping(&snapshot).is_err());
        drop(fresh_handshake);
        assert!(mapping.validate_original(&snapshot).is_err());

        let mut fresh_history = OriginalFrameReservation::reserve(16384, 8).unwrap();
        snapshot
            .prepare_historical_frame_data(&mut fresh_history)
            .unwrap();
        assert_eq!(fresh_history.frames().count(), 2);
        assert_eq!(
            fresh_history.frames().next().unwrap().bytes,
            snapshot.literal_frames().unwrap().next().unwrap().bytes
        );
        let duplicate_slot = fresh_history.begin(FrameDirection::Outgoing, 4).unwrap();
        assert!(
            fresh_history
                .retain_request(duplicate_slot, request.request_id.0.as_ref().unwrap())
                .is_err()
        );
        let mut insufficient = OriginalFrameReservation::reserve(8192, 8).unwrap();
        assert!(
            snapshot
                .prepare_historical_frame_data(&mut insufficient)
                .is_err()
        );
        assert_eq!(insufficient.frames().count(), 0);

        let sent_before = connection
            .original_frames
            .as_ref()
            .unwrap()
            .borrow()
            .frames()
            .count();
        let mut duplicate = request.clone();
        duplicate.sequence = U64::new(3);
        assert!(matches!(
            connection.send(duplicate),
            Err(ProviderError::Conflict(_))
        ));
        assert_eq!(
            serde_json::to_value(connection.guard.protocol_view()).unwrap()[3],
            "3"
        );
        assert_eq!(
            connection
                .original_frames
                .as_ref()
                .unwrap()
                .borrow()
                .frames()
                .count(),
            sent_before + 1
        );
        assert_eq!(snapshot.literal_frames().unwrap().count(), 2);
    }

    #[test]
    fn native5_original_partial_send_and_changed_prefix_keep_exact_slot() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut connection = Connection::new(
            PartialStream {
                sent: Vec::new(),
                remaining: 6,
            },
            authority,
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        connection
            .install_native5_frame_bank(OriginalFrameReservation::reserve(8192, 4).unwrap())
            .unwrap();
        let bytes = b"{\"original\":1}";
        let slot = connection.prepare_original_send(bytes).unwrap();
        assert!(
            connection
                .publish_original_send(b"{\"changed!\":1}", slot)
                .is_err()
        );
        assert!(connection.reader.stream_mut().sent.is_empty());
        assert!(connection.publish_original_send(bytes, slot).is_err());
        let original_bank = connection.original_frames.as_ref().unwrap().clone();
        let bank = original_bank.borrow();
        let frames: Vec<_> = bank.frames().collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].transferred, 6);
        assert!(!frames[0].complete);
        assert_eq!(&frames[0].bytes[4..], bytes);
        assert_eq!(&connection.reader.stream_mut().sent, &frames[0].bytes[..6]);
    }

    #[test]
    fn native5_original_partial_read_and_malformed_wire_are_literal() {
        for wire in [
            vec![0, 0, 0],
            vec![0, 0, 0, 5, b'{', b'1'],
            vec![0, 0, 0, 2, b'!', b'!'],
        ] {
            let bank = Rc::new(RefCell::new(
                OriginalFrameReservation::reserve(1024, 4).unwrap(),
            ));
            let mut reader = FrameReader::new(Cursor::new(wire.clone()), 128).unwrap();
            reader.install_originals(bank.clone());
            assert!(reader.read().is_err());
            assert!(reader.read().is_err());
            let bank = bank.borrow();
            let frame = bank.frames().next().unwrap();
            assert_eq!(frame.bytes, wire);
            assert_eq!(frame.transferred, wire.len());
            assert_eq!(frame.complete, wire.len() == 6 && wire[4] == b'!');
        }
    }

    #[test]
    fn native5_original_lifetime_slots_refuse_without_read_or_refund() {
        let bank = Rc::new(RefCell::new(
            OriginalFrameReservation::reserve(1024, 1).unwrap(),
        ));
        let wire = vec![0, 0, 0, 2, b'{', b'}', 0, 0, 0, 2, b'{', b'}'];
        let mut reader = FrameReader::new(Cursor::new(wire), 128).unwrap();
        reader.install_originals(bank.clone());
        assert!(reader.read().unwrap().is_some());
        assert!(reader.read().is_err());
        assert_eq!(reader.stream_mut().position(), 6);
        assert_eq!(bank.borrow().frames().count(), 1);
    }
    #[test]
    fn native5_original_storage_facts_refuse_legacy_marker_without_consuming_bank() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut connection = Connection::new(
            stream,
            authority,
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )
        .unwrap();
        assert!(connection.authenticate_native5_source_codec().is_err());
        assert!(connection.original_native5_storage_facts().is_err());
        connection
            .install_native5_frame_bank(OriginalFrameReservation::reserve(65536, 2).unwrap())
            .unwrap();
        assert!(connection.original_native5_storage_facts().is_err());
        let bank = connection.original_frames.as_ref().unwrap().borrow();
        assert_eq!(bank.frames().count(), 0);
        assert_eq!(
            bank.allocated_bytes(),
            bank.storage_facts(65536).allocated_bytes
        );
    }
}
