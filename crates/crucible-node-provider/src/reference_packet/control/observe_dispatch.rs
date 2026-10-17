//! Owns the sticky Control fence through one produced Observe transformation.
//!
//! The exclusive Control borrow and jointly produced receipt are the phase
//! proof. Ordinary live observers continue refusing a fenced Control. This loan
//! permits only its own unchanged original/currency to be checked while held;
//! errors and unwind leave both the fence and cached produced owners retained.

use super::*;
use crate::envelope::MessageKind;

pub(super) struct OriginalObserveDispatch<'a> {
    control: &'a mut PacketControl,
    currency: &'a PacketLiveCaptureControlCurrency,
    original: &'a Envelope,
    receipt: Option<&'a ProducedOriginalObserveReceipt>,
    released: bool,
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native original Observe owned dispatch phase differs")
}

impl<'a> OriginalObserveDispatch<'a> {
    pub(super) fn begin(
        control: &'a mut PacketControl,
        currency: &'a PacketLiveCaptureControlCurrency,
        original: &'a Envelope,
        receipt: Option<&'a ProducedOriginalObserveReceipt>,
    ) -> Result<Self, ProviderError> {
        let was_fenced = control.fenced;
        control.fenced = true;
        let held = Self {
            control,
            currency,
            original,
            receipt,
            released: false,
        };
        if was_fenced {
            return Err(refused());
        }
        held.authenticate()?;
        Ok(held)
    }

    pub(super) fn control_data(&self) -> &PacketControl {
        &*self.control
    }

    pub(super) fn authenticate_observer_owner(
        &self,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        if self.released
            || !std::ptr::eq(control, &*self.control)
            || !control.fenced
            || self.original.message != MessageKind::Request
            || self.original.method != Method::Observe
            || self
                .original
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| !control.originals.contains_key(id))
        {
            return Err(refused());
        }
        self.receipt
            .ok_or_else(refused)?
            .authenticate_dispatch_original_data(self.original, self.currency)
    }

    pub(super) fn authenticate_currency_data(
        &self,
        currency: &PacketLiveCaptureControlCurrency,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(currency, self.currency) {
            return Err(refused());
        }
        self.authenticate_observer_owner(self.control)
    }

    fn authenticate(&self) -> Result<(), ProviderError> {
        self.currency.authenticate_owned_observe_dispatch(self)
    }

    pub(super) fn transform_and_install(
        mut self,
        preparation: &mut ReplyPreparation<'_>,
        transform: &mut dyn FnMut(
            &mut PacketControlReply,
            &ProducedOriginalObserveReceipt,
        ) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.authenticate()?;
        if preparation.attempted || self.control.native_effect_attempted {
            return Err(refused());
        }
        preparation.attempted = true;
        let id = self.original.request_id.0.as_ref().ok_or_else(refused)?;
        let receipt = self.receipt.ok_or_else(refused)?;
        let cached = &mut self.control.originals.get_mut(id).ok_or_else(refused)?.1;
        transform(cached, receipt)?;
        if cached.evidence.len() != 3 {
            return Err(ProviderError::Correlation(
                "native allocation Observe requires raw, wrapper and Report evidence",
            ));
        }

        let cached = &self.control.originals.get(id).ok_or_else(refused)?.1;
        for (reference, bytes) in &cached.evidence {
            content::install_original_content(
                &mut self.control.content,
                &mut self.control.content_bytes,
                self.control.connected_coordinator.is_some()
                    || self.control.complete_coordinator.is_some(),
                reference.clone(),
                bytes,
            )?;
        }
        self.authenticate()?;
        self.control.fenced = false;
        self.released = true;
        Ok(())
    }
}

impl Drop for OriginalObserveDispatch<'_> {
    fn drop(&mut self) {
        if !self.released {
            self.control.fenced = true;
        }
    }
}

/// Returns the actual borrowed dispatch-phase header, excluding compiler frames.
pub(crate) const fn original_observe_dispatch_scratch_data() -> usize {
    std::mem::size_of::<OriginalObserveDispatch<'static>>()
}
