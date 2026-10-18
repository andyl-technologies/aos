//! Moves a genuine native restoration token into the same fresh Connection.
//!
//! Fresh registration, codec, literal bank and correlation guard remain active.
//! The sealed historical graph is retained beside them through its exact mapping
//! Rc. A portable body or receipt cannot construct this installed acknowledgement.

use super::*;
use crate::protocol_snapshot::{
    PreparedArchivedNativeProtocolMapping, owned11::native::outer::HistoricalNativeState,
};
use crate::reference_packet::service::ack_emitter::VerifiedCompleteRestoration;
use std::cell::{Ref, RefCell};

pub(super) struct InstalledNativeCompleteRestoration {
    token: VerifiedCompleteRestoration,
    mapping: Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn install_original_complete_restoration(
        &mut self,
        token: &mut Option<VerifiedCompleteRestoration>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider || self.original_complete_restoration.is_some() {
            return Err(ProviderError::Conflict(
                "native complete restoration already installed or wrong role",
            ));
        }
        let verified = token.as_ref().ok_or(ProviderError::Correlation(
            "verified complete restoration absent",
        ))?;
        verified.authenticate_installation(self, mapping)?;
        {
            let data = mapping
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("complete restoration mapping borrowed"))?;
            self.authenticate_archived_native_protocol_mapping(&data)?;
            data.historical()?.authenticate_capture_correspondence()?;
        }
        // Borrow-before-take preserves the caller's exact token on every
        // authentication/borrow failure. Spending the genuine issuer's sticky
        // attempt precedes the first transfer; no callbacks or I/O follow it.
        token
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "verified complete restoration absent",
            ))?
            .begin_installation(self, mapping)?;
        self.original_complete_restoration = Some(InstalledNativeCompleteRestoration {
            token: token.take().ok_or(ProviderError::Correlation(
                "verified complete restoration absent",
            ))?,
            mapping: Rc::clone(mapping),
        });
        Ok(())
    }

    pub(crate) fn authenticate_installed_complete_restoration(
        &self,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let installed =
            self.original_complete_restoration
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native complete restoration not installed",
                ))?;
        if !Rc::ptr_eq(&installed.mapping, mapping) {
            return Err(ProviderError::Correlation(
                "native installed mapping differs",
            ));
        }
        installed.token.authenticate_current(self)
    }

    pub(crate) fn installed_complete_restoration_data(
        &self,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<Ref<'_, HistoricalNativeState>, ProviderError> {
        self.authenticate_installed_complete_restoration(mapping)?;
        let installed =
            self.original_complete_restoration
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native complete restoration not installed",
                ))?;
        let owner = installed
            .mapping
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native installed mapping borrowed"))?;
        Ref::filter_map(owner, |owner| owner.historical().ok())
            .map_err(|_| ProviderError::Correlation("native installed historical owner incomplete"))
    }
}

#[path = "complete_installation/settled.rs"]
mod settled_history;
