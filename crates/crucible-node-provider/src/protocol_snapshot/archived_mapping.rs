//! Binds historical archive data to an actual fresh controller without installing.
//!
//! The source verifies signed archive, complete local journal, Core ticket and
//! fresh world context before signing the distinct restore request. This mapping
//! retains actual fresh owners but carries no native installation permission.

use super::*;
use crucible_node_contract::{ContentRef, Validate};

/// Describes only the exact historical native grammar retained by this mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestorationMappingClass {
    Legacy11,
    StartupCapture14,
    InvocationCapture15,
}

impl RestorationMappingClass {
    pub(super) fn normalization_format(self) -> &'static str {
        match self {
            Self::Legacy11 => "source-private.archived-protocol-mapping/11",
            Self::StartupCapture14 | Self::InvocationCapture15 => {
                "source-private.archived-protocol-mapping/12"
            }
        }
    }

    pub(super) fn native_formats(self) -> (&'static str, &'static str) {
        use owned11::native::outer::*;
        match self {
            Self::Legacy11 => (
                COMPLETE_NATIVE_CONNECTION_FORMAT,
                COMPLETE_NATIVE_SERVICE_FORMAT,
            ),
            Self::StartupCapture14 => (
                COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT,
                COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT,
            ),
            Self::InvocationCapture15 => (
                COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
                COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
            ),
        }
    }

    pub(super) fn authenticate_protocol_tags(
        self,
        fields: &mut owned11::OriginalOwned11Fields<'_>,
    ) -> Result<(), ProviderError> {
        for expected in [
            owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            owned11::outer::COMPLETE_CONNECTION_FORMAT,
            self.native_formats().0,
            self.native_formats().1,
        ] {
            owned11::state::tag(fields, expected)?;
        }
        Ok(())
    }
}

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
    class: RestorationMappingClass,
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
            class: _,
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
        Self::prepare_for_class(input, target, RestorationMappingClass::Legacy11)
    }

    pub(crate) fn prepare_selected(
        input: ArchivedProtocolMappingInput<'_>,
        target: ArchivedProtocolMappingTarget<'_>,
    ) -> Result<Self, ProviderError> {
        let class = input
            .native
            .original_selected_restoration_mapping_class_data()?;
        Self::prepare_for_class(input, target, class)
    }

    fn prepare_for_class(
        input: ArchivedProtocolMappingInput<'_>,
        target: ArchivedProtocolMappingTarget<'_>,
        class: RestorationMappingClass,
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
            class,
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

    /// Names exact borrowed normalization and decimal formatter scratch.
    ///
    /// This constructs only the same borrowing tuple used by normalization_view;
    /// it performs no serialization, cloning, current callback or allocation.
    /// Recursive/compiler frames and allocator physical overhead are separate.
    pub fn normalization_counter_scratch_data(&self) -> usize {
        Self::original_normalization_counter_scratch_data(&self.fresh)
    }

    /// Names the same normalization view before constructing its mapping owner.
    ///
    /// Only the actual authority's borrowed historical view is constructed. No
    /// archive reference, nonce, mapping, serialization or permission is created.
    /// Compiler/recursive frames and allocator physical overhead remain separate.
    pub fn original_normalization_counter_scratch_data(fresh: &ConnectionAuthority) -> usize {
        fn tuple_layout<A>(_: A) -> usize {
            std::mem::size_of::<(
                &str,
                &ContentRef,
                &ContentRef,
                &str,
                &str,
                &str,
                &str,
                A,
                [u8; 32],
                &str,
            )>()
        }
        tuple_layout(fresh.historical_owned_view())
            // Both actual class-format calls return an independent pair view.
            + 2 * std::mem::size_of::<(&'static str, &'static str)>()
            + std::mem::size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection>()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
            // U64's actual decimal serializer allocates at most twenty bytes.
            // Decimal fields are visited sequentially under this same window.
            + 20
    }

    /// Borrows the closed normalization whose canonical bytes bind source proof.
    ///
    /// The source retains/counts its own normalization bank. Registration/actor
    /// identity and opaque cut are authenticated separately and are not portable.
    pub fn normalization_view(&self) -> impl Serialize + '_ {
        (
            self.class.normalization_format(),
            &self.archive_protocol,
            &self.native_protocol,
            owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            owned11::outer::COMPLETE_CONNECTION_FORMAT,
            self.class.native_formats().0,
            self.class.native_formats().1,
            self.fresh.historical_owned_view(),
            self.nonce,
            "original-fresh-request-cut-retained",
        )
    }

    /// Checks the retained mapping's exact current parent allocations as DATA.
    ///
    /// The private mapping constructor already bound the complete archive/native
    /// bodies, normalization class, nonce and original request cut. This loan
    /// rechecks its actual controller, connection, registration and codec; equal
    /// portable fields cannot replace those owners. Assigned request identity,
    /// signed normalization and journal frontier remain separate SDK/Source joins.
    /// The retained cut is historical here: this check neither renews it nor
    /// supplies the live-cut proof required by `authenticate_target`.
    ///
    /// # Errors
    /// Refuses a foreign or revoked actor/registration, absent or replaced codec,
    /// malformed retained body commitments or a missing original mapping nonce.
    pub(crate) fn authenticate_history_target_data(
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
                "archived mapping historical parent changed",
            ));
        }

        self.archive_protocol.validate()?;
        self.native_protocol.validate()?;
        if self.nonce.iter().all(|byte| *byte == 0) {
            return Err(ProviderError::Correlation(
                "archived mapping original nonce absent",
            ));
        }
        Ok(())
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

#[cfg(test)]
mod selected_mapping_tests {
    use super::*;

    #[test]
    fn legacy_mapping_protocol_tags_preserve_the_original_literal() {
        let tags = [
            owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            owned11::outer::COMPLETE_CONNECTION_FORMAT,
            RestorationMappingClass::Legacy11.native_formats().0,
            RestorationMappingClass::Legacy11.native_formats().1,
        ];
        let bytes = serde_json::to_vec(&tags).unwrap();
        assert_eq!(bytes, br#"["source-private.controller-restorable-complete/11","source-private.connection-with-reader/11","source-private.native-connection-complete/11","source-private.native-service/11"]"#);
        assert_eq!(
            RestorationMappingClass::Legacy11.normalization_format(),
            "source-private.archived-protocol-mapping/11"
        );
        let mut fields = owned11::OriginalOwned11Fields::array(&bytes).unwrap();
        RestorationMappingClass::Legacy11
            .authenticate_protocol_tags(&mut fields)
            .unwrap();
        fields.finish().unwrap();
    }

    #[test]
    fn selected_mapping_protocol_tags_refuse_legacy_and_the_other_selected_class() {
        for class in [
            RestorationMappingClass::Legacy11,
            RestorationMappingClass::StartupCapture14,
            RestorationMappingClass::InvocationCapture15,
        ] {
            let bytes = serde_json::to_vec(&[
                owned11::outer::COMPLETE_CONTROLLER_FORMAT,
                owned11::outer::COMPLETE_CONNECTION_FORMAT,
                class.native_formats().0,
                class.native_formats().1,
            ])
            .unwrap();
            for expected in [
                RestorationMappingClass::Legacy11,
                RestorationMappingClass::StartupCapture14,
                RestorationMappingClass::InvocationCapture15,
            ] {
                let mut fields = owned11::OriginalOwned11Fields::array(&bytes).unwrap();
                let accepted = expected.authenticate_protocol_tags(&mut fields).is_ok();
                assert_eq!(accepted, class == expected);
                if accepted {
                    fields.finish().unwrap();
                }
            }
        }
    }
}

#[path = "archived_mapping/initial15_normalization.rs"]
mod initial15_normalization;
pub use initial15_normalization::Initial15MappingNormalizationConstructionData;
