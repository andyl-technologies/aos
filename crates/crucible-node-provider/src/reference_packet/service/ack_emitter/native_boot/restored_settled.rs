//! Retains the private Capture17 reserve and every irrevocably spent original.
//!
//! The actual prefix owner is consumed by this constructor. Its rows remain
//! unusable until the same imported five-role geometry has been recounted and
//! matched. Old startup16 is a different owner and is neither read nor renewed.

use super::boot::NativeAckBoot;
use super::bootstrap_settled::OriginalRestoredSettledBootstrap;
use crate::ProviderError;
use crate::envelope::Envelope;
use crate::reference_packet::service::native_startup::{
    NativeCaptureOutputCut17, NativeRestoredSettledActionCurrent17,
};
use crate::reference_packet::service::native_startup::{
    NativeRestoredSettledActionAttempt, OriginalRestoredSuffixBudget,
    PacketNativeInvocationPurposeData, PacketNativeStartupAllocationRow,
    PacketRestoredSettledNativeCarrierData, PacketRestoredSettledNativeConstructionInputs,
    PacketRestoredSettledNativeExistingRowsData, PacketRestoredSettledNativeStorageData,
    PacketRestoredSuffixReservationData, authenticate_original_native_settled_final_rows_data,
    original_native_settled_construction_storage_data,
    original_restored_settled_action_ingress_row_data,
    original_restored_settled_native_storage_data,
};
use std::{cell::RefCell, rc::Rc};

/// Keeps the real inherited reserve beside native once-attempt custody.
pub(super) struct NativeRestoredSettledCaptureOwner {
    creator: u32,
    thread: std::thread::ThreadId,
    boot: std::rc::Weak<RefCell<NativeAckBoot>>,
    carrier: PacketRestoredSettledNativeCarrierData,
    existing_rows: PacketRestoredSettledNativeExistingRowsData,
    purpose: PacketNativeInvocationPurposeData,
    final_native_birth: PacketNativeStartupAllocationRow,
    final_restore_prepare: Option<PacketNativeStartupAllocationRow>,
    sealed: Option<PacketRestoredSettledNativeStorageData>,
    budget: OriginalRestoredSuffixBudget,
    attempts: Vec<Rc<RefCell<NativeRestoredSettledActionAttempt>>>,
    current: Option<usize>,
    failed: bool,
}

impl NativeRestoredSettledCaptureOwner {
    /// Consumes the actual prefix occurrence before retaining the native owner.
    ///
    /// The caller installs the returned owner in the SAME retained Boot before
    /// closing bootstrap. A refusal leaves the bootstrap spent/failed; no public
    /// carrier, archived key or scalar reservation can call this constructor.
    pub(super) fn retain_from_bootstrap_into(
        bootstrap: &mut OriginalRestoredSettledBootstrap,
        boot: &Rc<RefCell<NativeAckBoot>>,
        key: &[u8],
        birth: &[u8],
        raw8: &[u8],
        existing_rows: &PacketRestoredSettledNativeExistingRowsData,
        purpose: PacketNativeInvocationPurposeData,
        destination: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            bootstrap.interrupt();
            return Err(refused());
        }
        let carrier = bootstrap.begin_claim(key, birth, raw8, existing_rows)?;
        let maximum = usize::try_from(carrier.maximum_originals.get()).map_err(|_| refused())?;
        let attempt_slots = maximum
            .checked_mul(std::mem::size_of::<
                Rc<RefCell<NativeRestoredSettledActionAttempt>>,
            >())
            .ok_or_else(exhausted)?;
        // Every per-original ingress row already includes its Rc vector slot.
        // Reserving the complete bank now does not borrow action/import credit.
        if u64::try_from(attempt_slots).map_err(|_| exhausted())?
            > carrier.ingress.retained_requested_bytes.get()
        {
            return Err(exhausted());
        }
        let mut fields = crate::protocol_snapshot::owned11::typed::Fields::object(raw8)?;
        fields.named("capture_reservation")?;
        fields.named("existing_rows")?;
        if fields.named("schema_version")? != b"8" {
            return Err(refused());
        }
        let raw7 = fields.named("suffix")?;
        fields.finish()?;
        let raw5 = super::bootstrap_suffix::nested_launch5(raw7)?;
        let maximum_construction = usize::try_from(
            bootstrap
                .data
                .suffix
                .invocation
                .native_birth
                .requested_peak_data()?,
        )
        .map_err(|_| exhausted())?;
        let construction = original_native_settled_construction_storage_data(
            &purpose,
            raw5,
            &bootstrap.data.suffix.suffix_reservation,
            existing_rows,
            &carrier,
            maximum_construction,
        )?;
        PacketRestoredSettledNativeStorageData::authenticate_initial_owner_admission_data(
            existing_rows,
            &carrier,
            &construction,
            &bootstrap.data.suffix.invocation.native_birth,
        )?;
        let budget = OriginalRestoredSuffixBudget::new_data(PacketRestoredSuffixReservationData {
            maximum_originals: carrier.maximum_originals,
            ingress: carrier.ingress,
            actions: carrier.actions,
        })?;
        *destination = Some(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            boot: Rc::downgrade(boot),
            carrier,
            existing_rows: *existing_rows,
            purpose,
            final_native_birth: bootstrap.data.suffix.invocation.native_birth,
            final_restore_prepare: bootstrap.data.suffix.invocation.restore_prepare,
            sealed: None,
            budget,
            attempts: Vec::new(),
            current: None,
            failed: true,
        });
        let owner = destination.as_mut().ok_or_else(refused)?;
        // The full vector is independently prepaid by the defining constructor.
        // No append may grow this bank while an original is being accepted.
        owner
            .attempts
            .try_reserve_exact(maximum)
            .map_err(|_| exhausted())?;
        owner.failed = false;
        Ok(())
    }

    /// Seals only the complete actual import geometry and the same launch row.
    ///
    /// This happens after the actual transferred archive has been validated,
    /// before any auxiliary upload/Capture read. A mismatch permanently poisons
    /// the private reserve; no remaining row is expanded to make it fit.
    pub(super) fn seal_import_data(
        &mut self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        input: &PacketRestoredSettledNativeConstructionInputs<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.sealed.is_some() || self.current.is_some() || !self.attempts.is_empty() {
            self.interrupt();
            return Err(refused());
        }
        self.failed = true;
        if input.existing_rows != &self.existing_rows {
            return Err(refused());
        }
        self.sealed = Some(original_restored_settled_native_storage_data(input)?);
        let storage = self.sealed.as_ref().ok_or_else(refused)?;
        storage.authenticate_received_carrier_data(&self.carrier)?;
        let construction = original_native_settled_construction_storage_data(
            &self.purpose,
            input.canonical_launch5,
            &self.existing_rows.suffix,
            &self.existing_rows,
            &self.carrier,
            input.maximum_requested_bytes,
        )?;
        authenticate_original_native_settled_final_rows_data(
            &self.existing_rows,
            storage,
            &construction,
            &self.final_native_birth,
            &self.final_restore_prepare,
        )?;
        self.failed = false;
        Ok(())
    }

    /// Debits one closed receive owner before raw parsing can allocate or fail.
    pub(super) fn begin_receive_data(
        &mut self,
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<usize, ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current.is_some() || self.attempts.len() >= self.attempts.capacity() {
            self.interrupt();
            return Err(refused());
        }
        let frame = self
            .sealed
            .as_ref()
            .ok_or_else(refused)?
            .maximum_frame_bytes_data();
        self.failed = true;
        let ordinal = self
            .budget
            .begin_ingress_data(original_restored_settled_action_ingress_row_data(frame)?)?;
        let index = self.attempts.len();
        // Keep the actual spent child independently borrowable while the
        // parent's private ledger is debited. Each ingress prices this Rc,
        // RefCell and payload before allocation; no whole-Boot loan crosses IO.
        self.attempts.push(Rc::new(RefCell::new(
            NativeRestoredSettledActionAttempt::new_data(ordinal),
        )));
        self.current = Some(index);
        self.failed = false;
        Ok(index)
    }

    /// Moves the same received original into its spent slot before validation.
    pub(super) fn retain_original_data(
        &mut self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        index: usize,
        original: Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current != Some(index) {
            self.interrupt();
            return Err(refused());
        }
        self.failed = true;
        let frame = self
            .sealed
            .as_ref()
            .ok_or_else(refused)?
            .maximum_frame_bytes_data();
        let mut attempt = self
            .attempts
            .get(index)
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        attempt.retain_original_data(original)?;
        attempt.decode_body_data(frame)?;
        self.failed = false;
        Ok(())
    }

    /// Lends the same actual spent owner for a private native read scope.
    ///
    /// This is only an Rc correspondence loan. It creates no action/publication
    /// permission; callers must reauthenticate this exact index before effects.
    pub(super) fn retained_attempt_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        index: usize,
    ) -> Result<Rc<RefCell<NativeRestoredSettledActionAttempt>>, ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current != Some(index) {
            return Err(refused());
        }
        Ok(Rc::clone(self.attempts.get(index).ok_or_else(refused)?))
    }

    /// Borrows the actual sealed row; no numeric value creates this owner.
    pub(super) fn sealed_storage_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<&PacketRestoredSettledNativeStorageData, ProviderError> {
        self.authenticate_origin_data(boot)?;
        self.sealed.as_ref().ok_or_else(refused)
    }

    /// Rechecks the same current index and actual shared child before effects.
    pub(super) fn authenticate_retained_attempt_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        index: usize,
        attempt: &Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current != Some(index)
            || self
                .attempts
                .get(index)
                .is_none_or(|actual| !Rc::ptr_eq(actual, attempt))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Spends separately recounted current graph and output work before dispatch.
    ///
    /// Only the actual live Source-MAC/currentness route may supply the complete
    /// defining row. This method compares axes; it never manufactures its permit.
    pub(super) fn begin_action_data(
        &mut self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        index: usize,
        required: PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current != Some(index) {
            self.interrupt();
            return Err(refused());
        }
        self.failed = true;
        self.budget.begin_action_data(required)?;
        self.failed = false;
        Ok(())
    }

    /// Closes only a native publication already checked by its genuine caller.
    pub(super) fn complete_publication_data(
        &mut self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        index: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin_data(boot)?;
        if self.current != Some(index) {
            self.interrupt();
            return Err(refused());
        }
        self.failed = true;
        self.budget.complete_publication_data()?;
        self.current = None;
        self.failed = false;
        Ok(())
    }

    fn authenticate_origin_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.failed
            || !self.boot.ptr_eq(&Rc::downgrade(boot))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn interrupt(&mut self) {
        self.failed = true;
        self.budget.interrupt_data();
    }
}

pub(crate) const fn original_restored_settled_native_owner_header_data() -> usize {
    std::mem::size_of::<NativeRestoredSettledCaptureOwner>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 private reserve unavailable, mismatched or spent")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 fixed spent-attempt bank")
}

/// Borrows actual current reserve, complete spent ledger and every raw/typed slot.
///
/// The only omitted fields are process-private thread/Weak addresses, replaced
/// with closed roles intrinsically authenticated against the actual same Boot.
/// No state is retired, cleared, normalized or refunded by this writer.
struct NativeCaptureHistory<'a> {
    owner: &'a NativeRestoredSettledCaptureOwner,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    action_cut: Option<(
        usize,
        &'a NativeRestoredSettledActionCurrent17<'a>,
        &'a NativeCaptureOutputCut17<'a>,
    )>,
}

impl NativeRestoredSettledCaptureOwner {
    pub(super) fn borrowed_settled_history_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        // Preserve failed owners too. Current Capture eligibility and permission
        // are separate checks; historical serialization cannot reopen failure.
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.boot.ptr_eq(&Rc::downgrade(boot))
        {
            return Err(refused());
        }
        self.budget.historical_data()?;
        Ok(NativeCaptureHistory {
            owner: self,
            boot,
            action_cut: None,
        })
    }
}

struct NativeCaptureAttempts<'a> {
    attempts: &'a [Rc<RefCell<NativeRestoredSettledActionAttempt>>],
    action_cut: Option<(
        usize,
        &'a NativeRestoredSettledActionCurrent17<'a>,
        &'a NativeCaptureOutputCut17<'a>,
    )>,
}

impl serde::Serialize for NativeCaptureAttempts<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut rows = serializer.serialize_seq(Some(self.attempts.len()))?;
        for (index, attempt) in self.attempts.iter().enumerate() {
            if let Some((selected, view, cut)) = self
                .action_cut
                .filter(|(selected, _, _)| *selected == index)
            {
                view.authenticate_occurrence_data(selected, attempt)
                    .map_err(serde::ser::Error::custom)?;
                rows.serialize_element(&view.borrowed_with_output_cut_data(cut))?;
            } else {
                let actual = attempt.try_borrow().map_err(serde::ser::Error::custom)?;
                rows.serialize_element(&*actual)?;
            }
        }
        rows.end()
    }
}

impl serde::Serialize for NativeCaptureHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let NativeRestoredSettledCaptureOwner {
            creator,
            thread: _,
            boot,
            carrier,
            existing_rows,
            purpose,
            final_native_birth,
            final_restore_prepare,
            sealed,
            budget,
            attempts,
            current,
            failed,
        } = self.owner;
        if *creator != std::process::id()
            || self.owner.thread != std::thread::current().id()
            || !boot.ptr_eq(&Rc::downgrade(self.boot))
        {
            return Err(serde::ser::Error::custom(
                "native17 current reserve parent differs",
            ));
        }
        let mut fields =
            serializer.serialize_struct("NativeRestoredSettledCaptureHistory17", 14)?;
        fields.serialize_field(
            "schema",
            "source-private.native-restored-settled-capture-reserve/17",
        )?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("carrier", carrier)?;
        fields.serialize_field("existing_rows", existing_rows)?;
        fields.serialize_field("purpose", purpose)?;
        fields.serialize_field("final_native_birth", final_native_birth)?;
        fields.serialize_field("final_restore_prepare", final_restore_prepare)?;
        fields.serialize_field("sealed", sealed)?;
        fields.serialize_field(
            "ledger",
            &budget
                .historical_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "attempts",
            &NativeCaptureAttempts {
                attempts,
                action_cut: self.action_cut,
            },
        )?;
        fields.serialize_field("current", current)?;
        fields.serialize_field("failed", failed)?;
        fields.end()
    }
}

impl NativeRestoredSettledCaptureOwner {
    /// Appends the actual reserve and every raw-first attempt without bank reset.
    ///
    /// # Errors
    /// Refuses another originating Boot, borrowed attempt or exhausted aggregate banks.
    pub(super) fn observe_current_settled17_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.observe_current_settled17_payload_metadata_data(boot, None, observer)
    }

    fn observe_current_settled17_payload_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        action_cut: Option<(
            usize,
            &NativeRestoredSettledActionCurrent17<'_>,
            &NativeCaptureOutputCut17<'_>,
        )>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.borrowed_settled_history_data(boot)?;
        let Self {
            creator,
            thread: _,
            boot: _,
            carrier: _,
            existing_rows: _,
            purpose: _,
            final_native_birth: _,
            final_restore_prepare: _,
            sealed: _,
            budget: _,
            attempts,
            current,
            failed,
        } = self;
        observer.observe(creator)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeBoot,
            boot.as_ref(),
        )?;
        observer.vector::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>(attempts.capacity())?;
        for (index, attempt) in attempts.iter().enumerate() {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredSettledActionAttempt,attempt.as_ref())?;
            if let Some((selected, view, cut)) =
                action_cut.filter(|(selected, _, _)| *selected == index)
            {
                view.authenticate_occurrence_data(selected, attempt)?;
                view.observe_with_output_cut_metadata_data(cut, observer)?;
            } else {
                attempt
                    .try_borrow()
                    .map_err(|_| refused())?
                    .observe_settled_history_metadata_data(observer)?;
            }
        }
        observer.observe(current)?;
        observer.observe(failed)
    }
}

impl NativeRestoredSettledCaptureOwner {
    fn authenticate_action_cut_occurrence17_data(
        &self,
        view: &NativeRestoredSettledActionCurrent17<'_>,
    ) -> Result<usize, ProviderError> {
        let index = self.current.ok_or_else(refused)?;
        let actual = self.attempts.get(index).ok_or_else(refused)?;
        view.authenticate_occurrence_data(index, actual)?;
        Ok(index)
    }

    pub(super) fn borrowed_settled_history_with_action_cut17_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        view: &'a NativeRestoredSettledActionCurrent17<'a>,
        cut: &'a NativeCaptureOutputCut17<'a>,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        self.borrowed_settled_history_data(boot)?;
        let index = self.authenticate_action_cut_occurrence17_data(view)?;
        Ok(NativeCaptureHistory {
            owner: self,
            boot,
            action_cut: Some((index, view, cut)),
        })
    }

    pub(super) fn observe_current_settled17_with_action_cut_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        view: &NativeRestoredSettledActionCurrent17<'_>,
        cut: &NativeCaptureOutputCut17<'_>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let index = self.authenticate_action_cut_occurrence17_data(view)?;
        self.observe_current_settled17_payload_metadata_data(
            boot,
            Some((index, view, cut)),
            observer,
        )
    }
}
