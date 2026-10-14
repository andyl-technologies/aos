//! Retains decoded archive data and its actual fresh native target before proof.
//!
//! Preparing this owner is data work. Only the genuine fresh boot/context MAC
//! verifier may issue the separate once-only installation token. No historical
//! private key, registrar descriptor or digest becomes a current authority.

use super::*;
use crucible_node_contract::ContentRef;
use owned11::{
    OriginalOwned11Fields as Fields,
    native::outer::{HistoricalNativeState, SealedHistoricalNativeState},
    original_owned11_invalid as invalid,
    state::{next, tag},
};

const MAXIMUM_NORMALIZATION_BYTES: usize = 65_536;

pub(crate) struct NativeArchivedMappingInput<'a> {
    pub(crate) historical: &'a mut Option<SealedHistoricalNativeState>,
    pub(crate) reference: &'a ContentRef,
    pub(crate) normalization: &'a [u8],
    pub(crate) nonce: [u8; 32],
}

pub(crate) struct PreparedArchivedNativeProtocolMapping {
    actor: Rc<ProtocolCaptureOwner>,
    authority: ConnectionAuthority,
    codec: Rc<crate::connection::Native5CodecOwner>,
    reference: ContentRef,
    nonce: [u8; 32],
    normalization: Vec<u8>,
    historical: Option<SealedHistoricalNativeState>,
}

impl PreparedArchivedNativeProtocolMapping {
    pub(crate) fn prepare_into(
        completed: &mut Option<Self>,
        input: NativeArchivedMappingInput<'_>,
        authority: &ConnectionAuthority,
        actor: &Rc<ProtocolCaptureOwner>,
        codec: &Rc<crate::connection::Native5CodecOwner>,
    ) -> Result<(), ProviderError> {
        actor.ensure_current()?;
        authority.ensure_live()?;
        if completed.is_some()
            || input.normalization.len() > MAXIMUM_NORMALIZATION_BYTES
            || input.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(invalid());
        }
        input
            .historical
            .as_ref()
            .ok_or_else(invalid)?
            .historical()?
            .authenticate_capture_correspondence()?;
        input.reference.verify(input.normalization)?;
        let mut fields = Fields::array(input.normalization)?;
        tag(&mut fields, "source-private.archived-protocol-mapping/11")?;
        next(&mut fields)?; // Full archive reference is independently bound by Source proof.
        let native_reference = next(&mut fields)?;
        let sealed_reference = input
            .historical
            .as_ref()
            .ok_or_else(invalid)?
            .body_reference();
        owned11::correspondence::content_reference(sealed_reference, native_reference)?;
        for class in [
            owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            owned11::outer::COMPLETE_CONNECTION_FORMAT,
            owned11::native::outer::COMPLETE_NATIVE_CONNECTION_FORMAT,
            owned11::native::outer::COMPLETE_NATIVE_SERVICE_FORMAT,
        ] {
            tag(&mut fields, class)?;
        }
        let raw_authority = next(&mut fields)?;
        let mut host_authority = Fields::array(raw_authority)?;
        tag(
            &mut host_authority,
            "source-private.connection-authority/11",
        )?;
        let host_connection = owned11::original_owned11_plain_string(next(&mut host_authority)?)?;
        if host_connection.is_empty() || host_connection.len() > 128 {
            return Err(invalid());
        }
        let session = owned11::original_owned11_plain_string(next(&mut host_authority)?)?;
        let incarnation = owned11::original_owned11_plain_string(next(&mut host_authority)?)?;
        if session != authority.session_id().as_str()
            || incarnation != authority.incarnation_id().as_str()
        {
            return Err(invalid());
        }
        // Host and native registrations have deliberately different connection
        // IDs and registrar epochs. The boot verifier authenticates this entire
        // retained host projection against its actual expected_host_registration;
        // this generic data loan never substitutes the native registration.
        for _ in 0..5 {
            next(&mut host_authority)?;
        }
        tag(
            &mut host_authority,
            "original-registration-backing-retained-by-opaque-source",
        )?;
        host_authority.finish()?;
        let mut nonce = Fields::array(next(&mut fields)?)?;
        for expected in input.nonce {
            if owned11::original_owned11_unsigned(next(&mut nonce)?)? != u64::from(expected) {
                return Err(invalid());
            }
        }
        nonce.finish()?;
        tag(&mut fields, "original-fresh-request-cut-retained")?;
        fields.finish()?;
        *completed = Some(Self {
            actor: Rc::clone(actor),
            authority: authority.clone(),
            codec: Rc::clone(codec),
            reference: input.reference.clone(),
            nonce: input.nonce,
            normalization: Vec::new(),
            historical: None,
        });
        let state = completed.as_mut().ok_or_else(invalid)?;
        state
            .normalization
            .try_reserve_exact(input.normalization.len())
            .map_err(|_| invalid())?;
        if state.normalization.capacity() != input.normalization.len() {
            return Err(invalid());
        }
        state.normalization.extend_from_slice(input.normalization);
        state.historical = input.historical.take();
        state
            .historical
            .as_ref()
            .ok_or_else(invalid)?
            .historical()?
            .authenticate_capture_correspondence()
    }

    pub(crate) fn mapping_reference(&self) -> &ContentRef {
        &self.reference
    }
    pub(crate) fn normalization_bytes(&self) -> &[u8] {
        &self.normalization
    }
    pub(crate) fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub(crate) fn historical(&self) -> Result<&HistoricalNativeState, ProviderError> {
        self.historical.as_ref().ok_or_else(invalid)?.historical()
    }

    pub(crate) fn host_authority_projection(&self) -> Result<&[u8], ProviderError> {
        let mut fields = Fields::array(&self.normalization)?;
        tag(&mut fields, "source-private.archived-protocol-mapping/11")?;
        for _ in 0..6 {
            next(&mut fields)?;
        }
        next(&mut fields)
    }
    pub(crate) fn authenticate_target(
        &self,
        authority: &ConnectionAuthority,
        actor: &Rc<ProtocolCaptureOwner>,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        actor.ensure_current()?;
        self.authority.ensure_live()?;
        authority.ensure_live()?;
        if !Rc::ptr_eq(&self.actor, actor)
            || !self.authority.same_registration(authority)
            || codec.is_none_or(|codec| !Rc::ptr_eq(codec, &self.codec))
            || self.historical.is_none()
        {
            return Err(invalid());
        }
        Ok(())
    }
}
