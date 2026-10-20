//! Retains the actual post-Hello canonical restoration uploader association.
//!
//! The opaque lease authenticates one controller, original connection, registrar
//! and sealed codec. It supplies no native header limit, segment or input-bank
//! allocation right. Source separately binds this actual writer association to
//! the fresh native keyed Prepare before any selected input publication.

use super::*;
use crate::{
    connection::Native5CodecOwner, handshake::RegistrationRead,
    protocol_snapshot::ProtocolCaptureOwner,
};
use std::rc::Rc;

/// Retains this controller's actual immutable canonical restoration uploader association.
///
/// The lease has no decoder, clone or portable representation. The source must
/// reauthenticate it against the same owning controller before dispatch. It
/// promises only the installed SDK success-or-no-send emitter, not peer
/// behavior, source Capture, native read limits or restoration authority.
pub struct OriginalCanonicalRestoreInputEmitter {
    controller: Rc<ProtocolCaptureOwner>,
    connection: Rc<ProtocolCaptureOwner>,
    registration: RegistrationRead,
    codec: Rc<Native5CodecOwner>,
}

impl OriginalCanonicalRestoreInputEmitter {
    /// Reports actual retained emitter association fields without granting rights.
    ///
    /// # Errors
    /// Refuses foreign actors, a revoked registrar or traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            controller,
            connection,
            registration,
            codec,
        } = self;
        controller.ensure_current()?;
        connection.ensure_current()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.shared_value(controller.as_ref())?;
        observer.shared_value(connection.as_ref())?;
        registration.observe_retained_metadata(&mut observer)?;
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    /// Rechecks the original actor, registrar and actual immutable writer owner.
    ///
    /// # Errors
    /// Refuses another original process/thread or controller, replaced connection
    /// or codec, revoked registrar, lost selection or a mutable loss callback.
    pub fn authenticate_original(&self, controller: &CnpController) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(ProviderError::Correlation(
                "canonical restoration input original controller changed",
            ));
        }
        controller.authenticate_native5_source_codec()?;
        if controller.original_native5_restore_input_emitter_selection()?
            != Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12) {
            return Err(ProviderError::Correlation("canonical restoration input original selection absent"));
        }
        self.registration.ensure_current()?;
        controller.session.authenticate_original_ack_emitter(
            &self.connection,
            &self.registration,
            &self.codec,
        )
    }
}

impl CnpController {
    /// Retains the same installed canonical restoration uploader association.
    ///
    /// Issuance clones only existing opaque owner, codec and registrar handles.
    /// The source separately charges this lease's inline fields/control blocks;
    /// it receives no native bound, source ticket or permission from a DTO.
    ///
    /// # Errors
    /// Refuses an absent selected codec, wrong actor, revoked original
    /// registration, replaced writer, mutable callback or fenced controller.
    pub fn retain_original_canonical_restore_input_emitter(
        &self,
    ) -> Result<OriginalCanonicalRestoreInputEmitter, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_native5_restore_input_emitter_selection()?
            != Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12) {
            return Err(ProviderError::Correlation("canonical restoration input selected mechanism absent"));
        }
        let (connection, registration, codec) = self.session.retain_original_ack_emitter()?;
        let lease = OriginalCanonicalRestoreInputEmitter {
            controller: self.protocol_owner.clone(),
            connection,
            registration,
            codec,
        };
        lease.authenticate_original(self)?;
        Ok(lease)
    }
}
