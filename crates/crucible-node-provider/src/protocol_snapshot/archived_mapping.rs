//! Binds historical archive data to an actual fresh controller without installing.
//!
//! The source verifies signed archive, complete local journal, Core ticket and
//! fresh world context before signing the distinct restore request. This mapping
//! retains actual fresh owners but carries no native installation permission.

use super::*;
use crucible_node_contract::ContentRef;

pub(crate) struct ArchivedProtocolMappingInput<'a> {
    pub(crate) host: &'a owned11::outer::SealedHistoricalControllerState,
    pub(crate) native: &'a owned11::native::outer::SealedHistoricalNativeState,
    pub(crate) archive_protocol: &'a ContentRef,
    pub(crate) native_protocol: &'a ContentRef,
    pub(crate) nonce: [u8; 32],
}

pub(crate) struct ArchivedProtocolMappingTarget<'a> {
    pub(crate) fresh: &'a ConnectionAuthority,
    pub(crate) controller_owner: &'a Rc<ProtocolCaptureOwner>,
    pub(crate) connection_owner: &'a Rc<ProtocolCaptureOwner>,
    pub(crate) codec: &'a Rc<crate::connection::Native5CodecOwner>,
    pub(crate) cut: crate::operational_time::OperationalDeadline,
}

/// Retains one actual fresh target and complete archive body bindings as data.
///
/// Unlike the same-process mapping, this owner needs no surviving old actor,
/// cut, codec Rc or original payload accompaniment. Historical portable fields
/// never recreate those associations. The genuine new boot verifier must issue
/// its separate once-only restoration token before the mechanical transfer.
pub(crate) struct ArchivedProtocolMappingIdentity;

/// Retains verified body commitments and one actual fresh target without installing.
///
/// Source/Core enrollment and a genuine native proof remain separate requirements.
pub struct PreparedArchivedProtocolMapping {
    identity: Rc<ArchivedProtocolMappingIdentity>,
    archive_protocol: ContentRef,
    native_protocol: ContentRef,
    nonce: [u8; 32],
    fresh: ConnectionAuthority,
    controller_owner: Rc<ProtocolCaptureOwner>,
    connection_owner: Rc<ProtocolCaptureOwner>,
    codec: Rc<crate::connection::Native5CodecOwner>,
    cut: crate::operational_time::OperationalDeadline,
}

impl PreparedArchivedProtocolMapping {
    /// Reports the actual retained mapping fields without serializing them.
    ///
    /// # Errors
    /// Refuses another creator/current actor or checked traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            identity,
            archive_protocol,
            native_protocol,
            nonce: _,
            fresh,
            controller_owner,
            connection_owner,
            codec,
            cut: _,
        } = self;
        controller_owner.ensure_current()?;
        connection_owner.ensure_current()?;
        fresh.ensure_live()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.shared_value(identity.as_ref())?;
        observer.observe(archive_protocol)?;
        observer.observe(native_protocol)?;
        fresh.observe_retained_metadata(&mut observer)?;
        observer.shared_value(controller_owner.as_ref())?;
        observer.shared_value(connection_owner.as_ref())?;
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    pub(crate) fn prepare(
        input: ArchivedProtocolMappingInput<'_>,
        target: ArchivedProtocolMappingTarget<'_>,
    ) -> Result<Self, ProviderError> {
        let ArchivedProtocolMappingInput {
            host,
            native,
            archive_protocol,
            native_protocol,
            nonce,
        } = input;
        let ArchivedProtocolMappingTarget {
            fresh,
            controller_owner,
            connection_owner,
            codec,
            cut,
        } = target;
        controller_owner.ensure_current()?;
        connection_owner.ensure_current()?;
        fresh.ensure_live()?;
        cut.remaining().ok_or(ProviderError::Correlation(
            "archived mapping original cut expired",
        ))?;
        if host.body_reference() != archive_protocol || native.body_reference() != native_protocol {
            return Err(ProviderError::Correlation(
                "archived mapping verified body owner differs",
            ));
        }
        let host = host.historical()?;
        let native = native.historical()?;
        host.require_complete_reader_state()?;
        native.authenticate_capture_correspondence()?;
        if host.session.authority.connection == *fresh.connection_id()
            || host.session.authority.session == *fresh.session_id()
            || host.session.authority.incarnation == *fresh.incarnation_id()
            || nonce.iter().all(|byte| *byte == 0)
        {
            return Err(ProviderError::Correlation(
                "archived mapping requires genuinely new target scope and nonce",
            ));
        }
        Ok(Self {
            identity: Rc::new(ArchivedProtocolMappingIdentity),
            archive_protocol: archive_protocol.clone(),
            native_protocol: native_protocol.clone(),
            nonce,
            fresh: fresh.clone(),
            controller_owner: Rc::clone(controller_owner),
            connection_owner: Rc::clone(connection_owner),
            codec: Rc::clone(codec),
            cut,
        })
    }

    pub(crate) fn retain_identity(&self) -> Rc<ArchivedProtocolMappingIdentity> {
        Rc::clone(&self.identity)
    }

    pub(crate) fn authenticate_identity(
        &self,
        identity: &Rc<ArchivedProtocolMappingIdentity>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.identity, identity) {
            return Err(ProviderError::Correlation(
                "assigned restore prepared mapping differs",
            ));
        }
        Ok(())
    }

    /// Borrows the exact full body commitment for historical controller data.
    pub const fn archive_protocol(&self) -> &ContentRef {
        &self.archive_protocol
    }

    /// Borrows the exact full body commitment for historical native service data.
    pub const fn native_protocol(&self) -> &ContentRef {
        &self.native_protocol
    }

    /// Borrows the source-selected fresh mapping nonce without granting a permit.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Borrows the closed normalization whose canonical bytes bind source proof.
    ///
    /// The source retains/counts its own normalization bank. Registration/actor
    /// identity and opaque cut are authenticated separately and are not portable.
    pub fn normalization_view(&self) -> impl Serialize + '_ {
        (
            "source-private.archived-protocol-mapping/11",
            &self.archive_protocol,
            &self.native_protocol,
            owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            owned11::outer::COMPLETE_CONNECTION_FORMAT,
            owned11::native::outer::COMPLETE_NATIVE_CONNECTION_FORMAT,
            owned11::native::outer::COMPLETE_NATIVE_SERVICE_FORMAT,
            self.fresh.historical_owned_view(),
            self.nonce,
            "original-fresh-request-cut-retained",
        )
    }

    pub(crate) fn authenticate_target(
        &self,
        fresh: &ConnectionAuthority,
        controller: &Rc<ProtocolCaptureOwner>,
        connection: &Rc<ProtocolCaptureOwner>,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.controller_owner.ensure_current()?;
        self.connection_owner.ensure_current()?;
        controller.ensure_current()?;
        connection.ensure_current()?;
        self.fresh.ensure_live()?;
        fresh.ensure_live()?;
        self.cut.remaining().ok_or(ProviderError::Correlation(
            "archived mapping original cut expired",
        ))?;
        if !self.fresh.same_registration(fresh)
            || !Rc::ptr_eq(&self.controller_owner, controller)
            || !Rc::ptr_eq(&self.connection_owner, connection)
            || codec.is_none_or(|codec| !Rc::ptr_eq(&self.codec, codec))
            || self.cut != cut
        {
            return Err(ProviderError::Correlation(
                "archived mapping fresh owner changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_registration_target(
        &self,
        fresh: &ConnectionAuthority,
        controller: &Rc<ProtocolCaptureOwner>,
        connection: &Rc<ProtocolCaptureOwner>,
        codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    ) -> Result<(), ProviderError> {
        self.controller_owner.ensure_current()?;
        self.connection_owner.ensure_current()?;
        controller.ensure_current()?;
        connection.ensure_current()?;
        self.fresh.ensure_live()?;
        fresh.ensure_live()?;
        if !self.fresh.same_registration(fresh)
            || !Rc::ptr_eq(&self.controller_owner, controller)
            || !Rc::ptr_eq(&self.connection_owner, connection)
            || codec.is_none_or(|codec| !Rc::ptr_eq(&self.codec, codec))
        {
            return Err(ProviderError::Correlation(
                "archive transfer mapping fresh registration changed",
            ));
        }
        Ok(())
    }
}
