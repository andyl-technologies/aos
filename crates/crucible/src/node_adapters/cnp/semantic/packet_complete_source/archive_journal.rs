//! Binds a complete local settlement journal to archived owners and protocol cuts.
//!
//! The journal is a separate acyclic object: it names immutable native bodies,
//! common semantic/ancestry bodies and the final host protocol leaf. It never
//! names the later signed archive index. Portable validation creates no live
//! Source, registrar, target context or installation permission.
//!
//! ```text
//! {schema:source-owned.packet-native-settled-journal/11,owner,participants,
//!  cut,ordinal,runtime,backend_implementation,semantic,ancestry,
//!  native_snapshot,native_control,native_anchor,native_after_protocol,
//!  host_protocol,confirmation_request,confirmation}
//! journal/12 additionally requires host_extension_registry; journal/11 forbids it.
//! ```

use super::archive_owner::ArchivedContentData;
use super::*;
use crate::{
    node_contract::{NativeStateKey, OriginalLineageRuntimeRecord},
    node_state::{NativeOwnerState, VerifiedStateContent},
};
use crucible_node_contract::{ImplementationIdentity, Position, U64};
use crucible_node_provider::{
    envelope::MessageKind,
    protocol_snapshot::owned11::{
        native::outer::{
            COMPLETE_NATIVE_CONNECTION_FORMAT, COMPLETE_NATIVE_SERVICE_FORMAT,
            HistoricalNativeState,
        },
        outer::{
            COMPLETE_CONNECTION_FORMAT, COMPLETE_CONTROLLER_FORMAT, HistoricalControllerState,
        },
    },
    reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
    retained_metadata::records::METADATA_CAPACITY_RECORD_FORMAT,
    transport::original_frames::FrameDirection,
};

/// Names the explicit local native settled-journal edition.
pub const PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA: &str =
    "source-owned.packet-native-settled-journal/11";

/// Names the explicit complete registry-bearing local journal edition.
pub const PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA: &str =
    "source-owned.packet-native-settled-journal/12";

/// Retains the complete reference-bearing local Capture/confirmation association.
///
/// Every named body is independently retained in the authenticated typed closure.
/// Decoding or hashing this value issues no archive, fresh target or Capture right.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteSettledJournal {
    /// Names the exact source-local journal grammar.
    pub schema: String,
    /// Names the unchanged original capture owner.
    pub owner: Id,
    /// Retains the complete sorted original participant roster.
    pub participants: IdSet,
    /// Preserves the original administrative semantic cut.
    pub cut: Position,
    /// Preserves the original event ordinal.
    pub ordinal: U64,
    /// Names the complete source Runtime7 object.
    pub runtime: ContentRef,
    /// Names the full installed backend/schema/class identity body.
    pub backend_implementation: ContentRef,
    /// Names the complete common semantic custody leaf.
    pub semantic: ContentRef,
    /// Names the complete first-sealed ancestry leaf.
    pub ancestry: ContentRef,
    /// Names the immutable pending native model/Control/endpoint snapshot.
    pub native_snapshot: ContentRef,
    /// Names its exact separately retained pending Control body.
    pub native_control: ContentRef,
    /// Names the exact unchanged-cut anchor.
    pub native_anchor: ContentRef,
    /// Names the actual native HostSettled leaf frozen before the fourth Poll.
    pub native_after_protocol: ContentRef,
    /// Names the actual full host complete state after the fourth Poll settles.
    pub host_protocol: ContentRef,
    /// Names the separately encoded full host registry and capacity/alias rosters.
    /// Old edition11 omits this field; edition12 requires a nonnullable reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_extension_registry: Option<ContentRef>,
    /// Names the distinct original confirmation Poll.
    pub confirmation_request: Id,
    /// Retains the exact original confirmation receipt and all four full refs.
    pub confirmation: PacketNativeAfterConfirmationReceipt,
}

#[derive(serde::Serialize)]
struct RegistryBackendIdentityView<'a> {
    schema: &'static str,
    native_snapshot_class: &'static str,
    implementation: &'a ImplementationIdentity,
    native_key: &'a NativeStateKey,
    journal: &'static str,
    ancestry_class: &'static str,
    capacity_records: &'static str,
    controller_class: &'static str,
    connection_class: &'static str,
    host_extension_registry_class: &'static str,
    native_connection_class: &'static str,
    native_service_class: &'static str,
}

impl PacketCompleteSettledJournal {
    /// Decodes bounded closed journal data without constructing any authority.
    ///
    /// # Errors
    /// Refuses malformed/oversized JSON, unknown fields or incomplete references.
    pub fn decode_data(bytes: &[u8], maximum_bytes: usize) -> Result<Self, OperationFailure> {
        let value = canonical::parse_json(bytes, maximum_bytes).map_err(unknown)?;
        let schema = value.get("schema").and_then(serde_json::Value::as_str);
        let registry = value.get("host_extension_registry");
        match (schema, registry) {
            (Some(PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA), None) => {}
            (Some(PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA), Some(reference))
                if !reference.is_null() => {}
            _ => {
                return Err(refused(
                    "complete journal registry edition or required field differs",
                ));
            }
        }
        let journal: Self = serde_json::from_value(value).map_err(unknown)?;
        journal.validate_data()?;
        Ok(journal)
    }

    /// Checks the exact grammar, participant order and four-body association.
    ///
    /// # Errors
    /// Refuses invalid values, repeated participants or changed confirmation refs.
    pub fn validate_data(&self) -> Result<(), OperationFailure> {
        self.confirmation.validate_data().map_err(unknown)?;
        self.participants.validate().map_err(unknown)?;
        self.cut.validate().map_err(unknown)?;
        let registry_class = match self.schema.as_str() {
            PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA => self.host_extension_registry.is_none(),
            PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA => self
                .host_extension_registry
                .as_ref()
                .is_some_and(|reference| {
                    reference.media_type == registry_capture::HOST_REGISTRY_MEDIA
                }),
            _ => false,
        };
        if !registry_class
            || self.participants.is_empty()
            || self.confirmation_request == self.confirmation.capture.capture_request_id
            || self.native_snapshot != self.confirmation.capture.native_snapshot_ref
            || self.native_control != self.confirmation.capture.native_control_ref
            || self.native_anchor != self.confirmation.capture.native_anchor_ref
            || self.native_after_protocol != self.confirmation.native_after_ref
        {
            return Err(refused("complete settled journal role association differs"));
        }
        for reference in self.dependencies() {
            reference.validate().map_err(unknown)?;
        }
        Ok(())
    }

    /// Borrows every fixed dependency occurrence without allocating a roster.
    pub fn dependencies(&self) -> impl Iterator<Item = &ContentRef> {
        [
            &self.runtime,
            &self.backend_implementation,
            &self.semantic,
            &self.ancestry,
            &self.native_snapshot,
            &self.native_control,
            &self.native_anchor,
            &self.native_after_protocol,
            &self.host_protocol,
        ]
        .into_iter()
        .chain(self.host_extension_registry.iter())
    }

    /// Authenticates exact signed owner membership and unchanged Runtime7 scope.
    ///
    /// This check runs before a Core ticket exists. The installed factory also
    /// validates complete common semantics, ancestry and native Control/model
    /// transition before accepting the archive source.
    ///
    /// # Errors
    /// Refuses another owner, cut/runtime, missing full evidence body or changed
    /// referenced bytes. A shared digest never substitutes for a full typed role.
    pub fn authenticate_owner_data(
        &self,
        owner: &NativeOwnerState,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_object: &ContentRef,
        content: &VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.authenticate_owner_from_content_data(
            owner,
            runtime,
            runtime_object,
            ArchivedContentData::Verified(content),
        )
    }

    pub(super) fn authenticate_owner_from_content_data(
        &self,
        owner: &NativeOwnerState,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_object: &ContentRef,
        content: ArchivedContentData<'_>,
    ) -> Result<(), OperationFailure> {
        self.validate_data()?;
        if owner.state != self.native_snapshot
            || self.owner != owner.owner
            || self.participants != owner.participants
            || self.cut != owner.cut
            || self.cut != runtime.capture_cut
            || self.ordinal != runtime.capture_ordinal
            || self.runtime != *runtime_object
            || !runtime
                .owners
                .iter()
                .any(|one| one.identity.owner == owner.owner)
        {
            return Err(refused("complete settled journal owner/runtime differs"));
        }
        for reference in self.dependencies() {
            if reference != runtime_object
                && reference != &owner.state
                && !owner.evidence.contains(reference)
            {
                return Err(refused(
                    "complete settled journal owner evidence role absent",
                ));
            }
            let bytes = content
                .get(reference)
                .ok_or_else(|| refused("complete settled journal full body absent"))?;
            reference.verify(bytes).map_err(unknown)?;
        }
        Ok(())
    }

    /// Checks the actual measured backend tuple and all four complete classes.
    ///
    /// The factory supplies its originally installed implementation, not a value
    /// decoded from this journal. The complete canonical tuple is independently
    /// retained as one immutable body in the signed source closure.
    ///
    /// # Errors
    /// Refuses a different full implementation, native key or complete class tuple.
    pub fn authenticate_backend_data(
        &self,
        installed: &ImplementationIdentity,
        key: &NativeStateKey,
        content: &VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.authenticate_backend_from_content_data(
            installed,
            key,
            ArchivedContentData::Verified(content),
        )
    }

    pub(super) fn authenticate_backend_from_content_data(
        &self,
        installed: &ImplementationIdentity,
        key: &NativeStateKey,
        content: ArchivedContentData<'_>,
    ) -> Result<(), OperationFailure> {
        let value = if self.schema == PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA {
            if key.schema.id.as_str() == "source-owned.packet-native-continuation/13" {
                if self.backend_implementation.media_type
                    != "application/vnd.source-owned.packet-complete-archive-backend.v16+json"
                    || key.schema
                        != super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14
                            .schema()?
                {
                    return Err(refused("complete startup backend schema differs"));
                }
                serde_json::to_value(Self::backend_registry_identity_view_for_class_data(
                    installed,
                    key,
                    super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14,
                ))
                .map_err(unknown)?
            } else if key.schema.id.as_str() == "source-owned.packet-native-continuation/14" {
                if self.backend_implementation.media_type
                    != "application/vnd.source-owned.packet-complete-archive-backend.v17+json"
                {
                    return Err(refused("complete invocation backend schema differs"));
                }
                crucible_node_provider::reference_packet::service::native_snapshot::authenticate_native_owned14_snapshot_schema_data(
                    &key.schema,
                )
                .map_err(unknown)?;
                serde_json::to_value(Self::backend_registry_identity_view_for_class_data(
                    installed,
                    key,
                    super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15,
                ))
                .map_err(unknown)?
            } else {
                Self::backend_registry_identity_data(installed, key)
            }
        } else {
            Self::backend_identity_data(installed, key)
        };
        let bytes = canonical::canonical_json(&value).map_err(unknown)?;
        self.backend_implementation
            .verify(&bytes)
            .map_err(unknown)?;
        if content.get(&self.backend_implementation) != Some(bytes.as_slice()) {
            return Err(refused("complete backend implementation body differs"));
        }
        Ok(())
    }

    /// Builds the complete inert measured tuple used by both capture and factory.
    pub fn backend_identity_data(
        installed: &ImplementationIdentity,
        key: &NativeStateKey,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema":"source-owned.packet-complete-archive-backend-before/14",
            "native_snapshot_class":"source-owned.packet-native-continuation/11",
            "implementation":installed,"native_key":key,
            "journal":PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA,
            "ancestry_class":PacketCompleteSemanticSource::REFERENCE_ANCESTRY_SCHEMA,
            "capacity_records":METADATA_CAPACITY_RECORD_FORMAT,
            "controller_class":COMPLETE_CONTROLLER_FORMAT,
            "connection_class":COMPLETE_CONNECTION_FORMAT,
            "native_connection_class":COMPLETE_NATIVE_CONNECTION_FORMAT,
            "native_service_class":COMPLETE_NATIVE_SERVICE_FORMAT,
        })
    }

    /// Requires the full registry-bearing class for complete archive enrollment.
    ///
    /// Edition11 remains historical data but cannot supply a complete target.
    ///
    /// # Errors
    /// Refuses old/unknown editions, absent registry data or another full media role.
    pub fn require_complete_registry_data(&self) -> Result<&ContentRef, OperationFailure> {
        self.validate_data()?;
        if self.schema != PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA {
            return Err(refused(
                "complete archive requires registry-bearing journal12",
            ));
        }
        self.host_extension_registry
            .as_ref()
            .ok_or_else(|| refused("complete journal registry reference absent"))
    }

    /// Borrows the exact selected registry-bearing backend tuple without JSON copies.
    ///
    /// Legacy11 retains the byte-identical v15 grammar; startup Capture14 uses
    /// the explicit v16 tuple; invocation Capture15 has its distinct v17 tuple.
    /// Each names its exact complete native connection/service classes.
    pub(super) fn backend_registry_identity_view_for_class_data<'a>(
        installed: &'a ImplementationIdentity,
        key: &'a NativeStateKey,
        class: super::archive_owner::CompleteNativeSnapshotClass,
    ) -> impl serde::Serialize + 'a {
        RegistryBackendIdentityView {
            schema: match class {
                super::archive_owner::CompleteNativeSnapshotClass::Legacy11 => "source-owned.packet-complete-archive-backend-before/15",
                super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14 => "source-owned.packet-complete-archive-backend-before/16",
                super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15 => "source-owned.packet-complete-archive-backend-before/17",
            },
            native_snapshot_class: class.schema_id(),
            implementation: installed,
            native_key: key,
            journal: PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA,
            ancestry_class: PacketCompleteSemanticSource::REFERENCE_ANCESTRY_SCHEMA,
            capacity_records: METADATA_CAPACITY_RECORD_FORMAT,
            controller_class: COMPLETE_CONTROLLER_FORMAT,
            connection_class: COMPLETE_CONNECTION_FORMAT,
            host_extension_registry_class:
                crucible_node_provider::handshake::ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT,
            native_connection_class: match class {
                super::archive_owner::CompleteNativeSnapshotClass::Legacy11 => COMPLETE_NATIVE_CONNECTION_FORMAT,
                super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14 => crucible_node_provider::protocol_snapshot::owned11::native::outer::COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT,
                super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15 => crucible_node_provider::protocol_snapshot::owned11::native::outer::COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
            },
            native_service_class: match class {
                super::archive_owner::CompleteNativeSnapshotClass::Legacy11 => COMPLETE_NATIVE_SERVICE_FORMAT,
                super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14 => crucible_node_provider::protocol_snapshot::owned11::native::outer::COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT,
                super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15 => crucible_node_provider::protocol_snapshot::owned11::native::outer::COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
            },
        }
    }

    /// Reports the actual borrowed tuple serializer header without constructing a schema.
    pub(super) fn backend_registry_identity_counter_scratch_data() -> usize {
        std::mem::size_of::<RegistryBackendIdentityView<'static>>()
    }

    /// Builds the explicitly registry-bearing measured backend data tuple.
    pub fn backend_registry_identity_data(
        installed: &ImplementationIdentity,
        key: &NativeStateKey,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema":"source-owned.packet-complete-archive-backend-before/15",
            "native_snapshot_class":"source-owned.packet-native-continuation/11",
            "implementation":installed,"native_key":key,
            "journal":PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA,
            "ancestry_class":PacketCompleteSemanticSource::REFERENCE_ANCESTRY_SCHEMA,
            "capacity_records":METADATA_CAPACITY_RECORD_FORMAT,
            "controller_class":COMPLETE_CONTROLLER_FORMAT,
            "connection_class":COMPLETE_CONNECTION_FORMAT,
            "host_extension_registry_class":crucible_node_provider::handshake::ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT,
            "native_connection_class":COMPLETE_NATIVE_CONNECTION_FORMAT,
            "native_service_class":COMPLETE_NATIVE_SERVICE_FORMAT,
        })
    }

    /// Verifies the exact native after boundary and complete host fourth suffix.
    ///
    /// The already admitted host/native historical owners remain inert. Their
    /// complete bank bytes and original ACKs are compared per direction, because
    /// native prefix slots are reserved before physical publication. Native after
    /// ends at the actual Capture terminal; the host additionally contains the
    /// independently validated fourth-object/Poll suffix.
    ///
    /// # Errors
    /// Refuses partial classes, changed literals/registration/assigned Admit,
    /// extra native suffix, missing terminal or incomplete fourth proof history.
    pub fn authenticate_protocol_data(
        &self,
        host: &HistoricalControllerState,
        native_after: &HistoricalNativeState,
    ) -> Result<(), OperationFailure> {
        self.validate_data()?;
        host.require_complete_reader_state().map_err(unknown)?;
        native_after
            .authenticate_capture_correspondence()
            .map_err(unknown)?;
        PacketCompleteSemanticSource::authenticate_archived_capture_settlement_transcript_data(
            host,
            &self.confirmation_request,
            &self.confirmation,
        )?;
        let native = &native_after.connection;
        let authority = &host.session.connection.authority;
        if authority.session != native.authority.session
            || authority.incarnation != native.authority.incarnation
            || authority.limits != native.authority.limits
            || authority.features != native.authority.features
            || authority.envelope_extensions != native.authority.envelope_extensions
            || authority.extensions != native.authority.extensions
            || host.assigned.is_none()
        {
            return Err(refused(
                "complete archived protocol role registrations differ",
            ));
        }
        // Local connection IDs intentionally differ between the two roles.
        let admitted = &native.admission.original;
        let admit_id = admitted
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("complete native original Admit ID absent"))?;
        let host_admit = host
            .custody
            .controller
            .get(admit_id)
            .ok_or_else(|| refused("complete host original Admit absent"))?;
        if host_admit.request != *admitted || host_admit.response.is_none() {
            return Err(refused("complete archived assigned Admit differs"));
        }
        let capture = host
            .custody
            .controller
            .get(&self.confirmation.capture.capture_request_id)
            .ok_or_else(|| refused("complete original Capture absent"))?;
        let terminal = capture
            .response
            .as_ref()
            .ok_or_else(|| refused("complete original Capture terminal absent"))?;
        let mut boundary = None;
        for (index, frame) in host.original_frames_data().enumerate() {
            if frame.direction == FrameDirection::Incoming && frame.bytes.len() >= 4 {
                let header: BoundaryHeader<'_> =
                    serde_json::from_slice(&frame.bytes[4..]).map_err(unknown)?;
                if header.message == MessageKind::Response
                    && header.request_id
                        == Some(self.confirmation.capture.capture_request_id.as_str())
                    && header.sequence.parse::<u64>().map_err(unknown)? == terminal.sequence.get()
                {
                    if boundary.replace(index).is_some() {
                        return Err(refused("complete Capture boundary repeated"));
                    }
                }
            }
        }
        let boundary =
            boundary.ok_or_else(|| refused("complete Capture literal boundary absent"))?;
        for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
            let mut expected = host
                .original_frames_data()
                .take(boundary + 1)
                .filter(|frame| frame.direction != direction);
            for actual in native
                .frames
                .frames()
                .filter(|frame| frame.direction == direction)
            {
                let expected = expected
                    .next()
                    .ok_or_else(|| refused("native after contains an extra literal frame"))?;
                if !actual.complete
                    || actual.transferred != actual.bytes.len()
                    || !expected.complete
                    || expected.transferred != expected.bytes.len()
                    || actual.bytes != expected.bytes
                {
                    return Err(refused(
                        "native after literal prefix differs from original host",
                    ));
                }
            }
            if expected.next().is_some() {
                return Err(refused("native after omits an original literal frame"));
            }
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct BoundaryHeader<'a> {
    message: MessageKind,
    #[serde(borrow)]
    request_id: Option<&'a str>,
    #[serde(borrow)]
    sequence: &'a str,
}

impl PacketCompleteSemanticSource {
    /// Binds the actual retained registry body into a complete local journal.
    ///
    /// This component step preserves every other journal field. Its backend
    /// reference must separately name `backend_registry_identity_data`, and the
    /// actual factory still verifies the full semantic, literal and signed Core
    /// closure. It does not complete Capture or issue restoration permission.
    /// The new reference remains in the caller's journal on a final fence failure.
    ///
    /// # Errors
    /// Refuses another actual capture scope, repeated binding, changed original
    /// host/native payloads, absent registry custody or insufficient simultaneous
    /// reference-copy storage. The caller supplies its other retained bytes.
    pub fn bind_original_complete_registry_journal_data(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        journal: &mut PacketCompleteSettledJournal,
        additional_retained_bytes: usize,
        maximum_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(&scope.realization()?)?;
        journal.validate_data()?;
        if journal.schema != PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA
            || journal.host_extension_registry.is_some()
            || journal.schema.capacity() < PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA.len()
        {
            return Err(refused(
                "complete registry journal binding unavailable or repeated",
            ));
        }
        {
            let registry = self.original_complete_registry_payload_data()?;
            registry
                .reference
                .verify(&registry.bytes)
                .map_err(unknown)?;
            if registry.reference.media_type != registry_capture::HOST_REGISTRY_MEDIA {
                return Err(refused("original registry body has another media role"));
            }
            let banks = self
                .capture_banks
                .try_borrow()
                .map_err(|_| refused("journal original capture banks are borrowed"))?;
            let banks = banks
                .as_ref()
                .ok_or_else(|| refused("journal original banks absent"))?;
            let (host, host_bytes) = banks
                .protocol_payload
                .as_ref()
                .ok_or_else(|| refused("journal original host payload absent"))?;
            host.validate_original_payload(host_bytes)
                .map_err(unknown)?;
            journal.host_protocol.verify(host_bytes).map_err(unknown)?;
            for (object, expected) in banks.native_objects.iter().zip([
                &journal.native_snapshot,
                &journal.native_control,
                &journal.native_anchor,
            ]) {
                let object = object
                    .as_ref()
                    .ok_or_else(|| refused("journal native object absent"))?;
                if &object.reference != expected {
                    return Err(refused(
                        "journal native object differs from original custody",
                    ));
                }
                expected.verify(&object.bytes).map_err(unknown)?;
            }
            let after = banks
                .native_after_object
                .as_ref()
                .ok_or_else(|| refused("journal original native after body absent"))?;
            if after.reference != journal.native_after_protocol {
                return Err(refused(
                    "journal after reference differs from original custody",
                ));
            }
            after.reference.verify(&after.bytes).map_err(unknown)?;
            retained_values::sum(
                [
                    additional_retained_bytes,
                    NodeRuntime::capture_reference_storage(&registry.reference).map_err(unknown)?,
                ],
                maximum_bytes,
            )?;

            journal.host_extension_registry = Some(registry.reference.clone());
            // The two explicit edition strings have the same extent. This
            // update uses the admitted original String allocation without growth.
            journal.schema.clear();
            journal
                .schema
                .push_str(PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA);
        }
        journal.validate_data()?;
        self.authenticate_witness_scope(&scope.realization()?)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed journal data controls fail on any unexpected decode or fixture error.
#[allow(clippy::unwrap_used)]
#[path = "archive_journal/registry_tests.rs"]
mod registry_tests;

#[cfg(test)]
mod selected_startup_backend_tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::{
        archive_owner::CompleteNativeSnapshotClass,
        tests::{coordinator, installation},
    };

    #[test]
    fn startup_backend_names_full14_without_relabeling_legacy_backend()
    -> Result<(), OperationFailure> {
        let installed = coordinator();
        let installation = installation(&installed, 0);
        let implementation = &installation.provider.implementation;
        let mut key = NativeStateKey {
            implementation: implementation.implementation_id.clone(),
            profile: Id::new("source-owned.packet-complete-original-lineage/5").map_err(unknown)?,
            schema: CompleteNativeSnapshotClass::Legacy11.schema()?,
        };
        let old = serde_json::to_value(
            PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
                implementation,
                &key,
                CompleteNativeSnapshotClass::Legacy11,
            ),
        )
        .map_err(unknown)?;
        assert_eq!(
            old,
            PacketCompleteSettledJournal::backend_registry_identity_data(implementation, &key)
        );
        key.schema = CompleteNativeSnapshotClass::StartupCapture14.schema()?;
        let selected = serde_json::to_value(
            PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
                implementation,
                &key,
                CompleteNativeSnapshotClass::StartupCapture14,
            ),
        )
        .map_err(unknown)?;
        assert_eq!(
            selected["schema"],
            "source-owned.packet-complete-archive-backend-before/16"
        );
        assert_eq!(
            selected["native_snapshot_class"],
            "source-owned.packet-native-continuation/13"
        );
        assert_eq!(
            selected["native_connection_class"],
            "source-private.native-connection-complete-startup/14"
        );
        assert_eq!(
            selected["native_service_class"],
            "source-private.native-service/14"
        );
        assert_eq!(
            old["native_snapshot_class"],
            "source-owned.packet-native-continuation/11"
        );
        assert_ne!(selected, old);
        Ok(())
    }
}

#[cfg(test)]
mod selected_invocation_backend_tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::{
        archive_owner::CompleteNativeSnapshotClass,
        tests::{coordinator, installation},
    };

    #[test]
    fn invocation_backend_names_full15_and_keeps_selected14_backend_distinct()
    -> Result<(), OperationFailure> {
        let installed = coordinator();
        let installation = installation(&installed, 0);
        let implementation = &installation.provider.implementation;
        let mut key = NativeStateKey {
            implementation: implementation.implementation_id.clone(),
            profile: Id::new("source-owned.packet-complete-original-lineage/5").map_err(unknown)?,
            schema: CompleteNativeSnapshotClass::StartupCapture14.schema()?,
        };
        let startup = serde_json::to_value(
            PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
                implementation,
                &key,
                CompleteNativeSnapshotClass::StartupCapture14,
            ),
        )
        .map_err(unknown)?;
        key.schema = CompleteNativeSnapshotClass::InvocationCapture15.schema()?;
        let invocation = serde_json::to_value(
            PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
                implementation,
                &key,
                CompleteNativeSnapshotClass::InvocationCapture15,
            ),
        )
        .map_err(unknown)?;

        assert_eq!(
            startup["schema"],
            "source-owned.packet-complete-archive-backend-before/16"
        );
        assert_eq!(
            startup["native_snapshot_class"],
            "source-owned.packet-native-continuation/13"
        );
        assert_eq!(
            invocation["schema"],
            "source-owned.packet-complete-archive-backend-before/17"
        );
        assert_eq!(
            invocation["native_snapshot_class"],
            "source-owned.packet-native-continuation/14"
        );
        assert_eq!(
            invocation["native_key"],
            serde_json::to_value(&key).map_err(unknown)?
        );
        assert_eq!(
            invocation["native_connection_class"],
            "source-private.native-connection-complete-invocation/15"
        );
        assert_eq!(
            invocation["native_service_class"],
            "source-private.native-service/15"
        );
        assert_ne!(startup, invocation);
        Ok(())
    }
}

#[path = "archive_journal/storage.rs"]
mod storage;
