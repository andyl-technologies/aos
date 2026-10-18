//! Owns one irrevocably admitted native Capture17 receive occurrence.
//!
//! Raw custody, ordinary transport validation and Source authentication remain
//! separate transitions. This owner does not construct a spent Capture action:
//! current-model comparison and the complete output/effect row are additional
//! mandatory joins. Every unfinished owner permanently poisons its actual slot.

use super::NativeAckBoot;
use crate::ProviderError;
use crate::connection::{Connection, ExchangeRecord, ProviderStream};
use crate::envelope::{Envelope, Method};
use crate::reference_packet::control::PacketControl;
use crate::reference_packet::service::native_startup::{
    NativeRestoredSettledActionAttempt, NativeRestoredSettledActionFamily17,
};
use std::{
    cell::{Cell, Ref, RefCell},
    mem::size_of,
    rc::Rc,
};

/// Keeps the actual Boot/index/Rc across the sole raw-first native receive.
pub(crate) struct OriginalNativeCapture17Read {
    boot: Rc<RefCell<NativeAckBoot>>,
    index: usize,
    attempt: Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    frame: usize,
    receiving: Cell<bool>,
    raw: Cell<bool>,
    incoming_slot: Cell<Option<usize>>,
    source_started: Cell<bool>,
    source_verified: Cell<bool>,
    complete: Cell<bool>,
}

impl NativeAckBoot {
    /// Spends real ingress before any ancestry walk or original receive.
    ///
    /// # Errors
    /// Refuses foreign/failed owners, exhausted nonrenewing ingress or absent
    /// genuine Initial15 ancestry. Cold17 adoption remains a separate supplier.
    pub(crate) fn retain_original_capture17_read_data<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalNativeCapture17Read, ProviderError> {
        let (frame, index, attempt) = {
            let mut owner = boot.try_borrow_mut().map_err(|_| refused())?;
            owner.ensure_origin()?;
            let state = owner.restored_settled.as_mut().ok_or_else(refused)?;
            let frame = state.sealed_storage_data(boot)?.maximum_frame_bytes_data();
            let index = state.begin_receive_data(boot)?;
            let attempt = match state.retained_attempt_data(boot, index) {
                Ok(attempt) => attempt,
                Err(error) => {
                    state.interrupt();
                    return Err(error);
                }
            };
            (frame, index, attempt)
        };
        let scope = OriginalNativeCapture17Read {
            boot: Rc::clone(boot),
            index,
            attempt,
            frame,
            receiving: Cell::new(false),
            raw: Cell::new(false),
            incoming_slot: Cell::new(None),
            source_started: Cell::new(false),
            source_verified: Cell::new(false),
            complete: Cell::new(false),
        };
        Self::authenticate_original_observation17_ancestry_data(
            boot, connection, control, records,
        )?;
        scope.authenticate_slot_data(connection)?;
        Ok(scope)
    }
}

impl OriginalNativeCapture17Read {
    fn authenticate_slot_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.complete.get() {
            return Err(refused());
        }
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(&self.boot, &admission.boot) {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        owner
            .restored_settled
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_retained_attempt_data(&self.boot, self.index, &self.attempt)
    }

    /// Starts one actual read under the same prepaid native occurrence.
    ///
    /// # Errors
    /// Refuses a second receive or changed native admission/retained slot.
    pub(crate) fn begin_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.receiving.replace(true) {
            return Err(refused());
        }
        self.authenticate_slot_data(connection)
    }

    /// Retains the original before closed decoding, policy or Source checks.
    ///
    /// # Errors
    /// Refuses repeated/raw-incomplete input or another typed family. Raw and
    /// initialized partial owners remain in this same spent native occurrence.
    pub(crate) fn retain_original_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: Envelope,
    ) -> Result<(), ProviderError> {
        if !self.receiving.get() || self.raw.replace(true) {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .retain_original_data(original)?;
        self.authenticate_slot_data(connection)?;
        let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
        attempt.decode_body_data(self.frame)?;
        if attempt.family_data()? != NativeRestoredSettledActionFamily17::Capture {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the actual raw original without creating an action grant.
    ///
    /// # Errors
    /// Refuses absent or conflicting retained custody.
    pub(crate) fn original_data(&self) -> Result<Ref<'_, Envelope>, ProviderError> {
        let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
        Ref::filter_map(attempt, |attempt| attempt.original_data().ok()).map_err(|_| refused())
    }

    /// Saves the exact complete incoming literal after ordinary guard receive.
    ///
    /// # Errors
    /// Refuses repeated completion, missing raw input or a changed actual frame.
    pub(crate) fn complete_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_slot_data(connection)?;
        if !self.raw.get() || self.incoming_slot.get().is_some() {
            return Err(refused());
        }
        let slot = {
            let original = self.original_data()?;
            connection.original_native_capture17_literal_slot_data(&original)?
        };
        self.incoming_slot.set(Some(slot));
        Ok(())
    }

    /// Verifies an independently assigned Capture or upload Source original.
    ///
    /// This proves only the actual Source-bearing original. Continuations and
    /// final confirmation require the separate completed same-Boot chronology;
    /// they cannot borrow this method as a replacement MAC/currentness grant.
    ///
    /// # Errors
    /// Refuses repeated verification, wrong incoming custody or unsupported
    /// phase, invalid actual Boot key, changed assigned fields or Source MAC.
    pub(crate) fn authenticate_assigned_source_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        self.authenticate_slot_data(connection)?;
        if self.source_started.replace(true) || !self.receiving.get() || !self.raw.get() {
            return Err(refused());
        }
        {
            let original = self.original_data()?;
            connection.authenticate_original_native_capture17_literal_data(
                &original,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
            connection.authenticate_native_capture17_incoming_data(&original)?;
        }
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
        let capture = attempt.capture_data_mut()?;
        match capture.original_data()?.method {
            Method::Begin => capture.authenticate_capture_source_data(key, self.frame)?,
            Method::BlobBegin => capture.authenticate_upload_source_data(key, self.frame)?,
            _ => return Err(refused()),
        }
        drop(attempt);
        drop(owner);
        self.authenticate_slot_data(connection)?;
        NativeAckBoot::with_original_capture17_ancestry_data(
            &self.boot,
            connection,
            control,
            records,
            |scope, first_original, first_terminal| {
                use crate::reference_packet::service::native_startup::NativeCapture17PhaseData;
                let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
                let child = attempt.capture_data()?;
                let request = match child.phase17_data()? {
                    NativeCapture17PhaseData::Capture { artifact, .. } => &artifact.request,
                    NativeCapture17PhaseData::UploadBegin { artifact, .. } => {
                        &artifact.request.capture
                    }
                    _ => return Err(refused()),
                };
                if &request.scope != scope {
                    return Err(refused());
                }
                control.authenticate_capture17_first_checkpoint_data(
                    first_original,
                    first_terminal,
                    &request.first_observation,
                )
            },
        )?;
        self.authenticate_slot_data(connection)?;
        self.source_verified.set(true);
        Ok(())
    }
}

impl Drop for OriginalNativeCapture17Read {
    fn drop(&mut self) {
        if self.complete.get() {
            return;
        }
        if let Ok(mut attempt) = self.attempt.try_borrow_mut() {
            attempt.interrupt_data();
        }
        if let Ok(mut owner) = self.boot.try_borrow_mut() {
            if let Some(state) = owner.restored_settled.as_mut() {
                state.interrupt();
            }
        }
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 requires its genuine retained native occurrence")
}

/// Names this actual owner, receive decoder and reused ancestry walk headers.
pub(crate) fn native_capture17_receive_scope_counter_scratch_data() -> usize {
    size_of::<OriginalNativeCapture17Read>()
        + size_of::<Ref<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<Ref<'static, NativeAckBoot>>()
        + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<Ref<'static, Envelope>>()
        + size_of::<&OriginalNativeCapture17Read>()
        + size_of::<&PacketControl>()
        + size_of::<&[ExchangeRecord]>()
        + size_of::<&crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope>()
        + size_of::<&crate::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureRequest>()
        + size_of::<Result<Ref<'static, Envelope>, ProviderError>>()
        + size_of::<Result<Ref<'static, NativeRestoredSettledActionAttempt>, ProviderError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>()
        + crate::connection::native_capture17_receive_counter_scratch_data()
        + crate::reference_packet::endpoint::native_capture17_endpoint_receive_counter_scratch_data()
        + crate::reference_packet::service::ack_emitter::original_observation17_checkpoint_owner_counter_scratch_data()
}
