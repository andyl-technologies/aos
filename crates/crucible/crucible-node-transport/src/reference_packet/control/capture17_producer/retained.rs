//! Serializes complete operational owners beside genuine Control identity links.
//!
//! Role markers are inert. The enclosing native graph records the real Control
//! Rc once; repeated fields use the same MetadataSharedKind identity edges.
//! These writers supply no Deserialize constructor or historical-to-live path.

use super::*;
use crate::retained_metadata::aliases::MetadataSharedKind;
use serde::{Serializer, ser::SerializeStruct};

const CONTROL_ROLE: &str = "current-native-control-identity";

struct Geometry<'a>(&'a Shape);
impl Serialize for Geometry<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Shape {
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCapture17Geometry", 11)?;
        fields.serialize_field(
            "dom_and_canonical_scratch_bytes",
            dom_and_canonical_scratch_bytes,
        )?;
        fields.serialize_field("retained_value_backing_bytes", retained_value_backing_bytes)?;
        fields.serialize_field(
            "projected_parser_requested_bytes",
            projected_parser_requested_bytes,
        )?;
        fields.serialize_field(
            "canonical_output_requested_bytes",
            canonical_output_requested_bytes,
        )?;
        fields.serialize_field(
            "serializer_temporary_requested_bytes",
            serializer_temporary_requested_bytes,
        )?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            declared_counter_scratch_bytes,
        )?;
        fields.serialize_field("maximum_encoded_bytes", maximum_encoded_bytes)?;
        fields.serialize_field("sequence_elements", sequence_elements)?;
        fields.serialize_field("sequence_containers", sequence_containers)?;
        fields.serialize_field("serialized_value_nodes", serialized_value_nodes)?;
        fields.serialize_field("serialized_capacity_records", serialized_capacity_records)?;
        fields.end()
    }
}

fn observe_geometry(
    value: &Shape,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let Shape {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = value;
    observer.observe(dom_and_canonical_scratch_bytes)?;
    observer.observe(retained_value_backing_bytes)?;
    observer.observe(projected_parser_requested_bytes)?;
    observer.observe(canonical_output_requested_bytes)?;
    observer.observe(serializer_temporary_requested_bytes)?;
    observer.observe(declared_counter_scratch_bytes)?;
    observer.observe(maximum_encoded_bytes)?;
    observer.observe(sequence_elements)?;
    observer.observe(sequence_containers)?;
    observer.observe(serialized_value_nodes)?;
    observer.observe(serialized_capacity_records)?;
    Ok(())
}

fn observe_row(
    value: &PacketNativeStartupAllocationRow,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeStartupAllocationRow {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes,
    } = value;
    observer.observe(retained_requested_bytes)?;
    observer.observe(maximum_simultaneous_transient_bytes)?;
    observer.observe(declared_counter_scratch_bytes)
}

impl Serialize for NativeCapture17RegistrationStorageData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            original,
            input,
            lengths,
            row,
            hash_row,
            request,
            unknown,
        } = self;
        let _ = owner;
        let mut fields =
            serializer.serialize_struct("NativeCapture17RegistrationStorageData", 9)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-registration-storage/17",
        )?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("input", input)?;
        fields.serialize_field("lengths", lengths)?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("hash_row", hash_row)?;
        fields.serialize_field("request_geometry", &Geometry(request))?;
        fields.serialize_field("unknown_geometry", &Geometry(unknown))?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17RegistrationStorageData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            original,
            input,
            lengths,
            row,
            hash_row,
            request,
            unknown,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(original)?;
        observer.observe(input)?;
        observer.observe(lengths)?;
        observe_row(row, observer)?;
        observe_row(hash_row, observer)?;
        observe_geometry(request, observer)?;
        observe_geometry(unknown, observer)?;
        Ok(())
    }
}

impl Serialize for NativeCapture17RegistrationAttempt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            hash,
            expected_binding,
            reservation,
            unknown_reply,
            phase,
        } = self;
        let _ = owner;
        let mut fields = serializer.serialize_struct("NativeCapture17RegistrationAttempt", 10)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-registration-attempt/17",
        )?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("admitted", admitted)?;
        fields.serialize_field("hash", hash)?;
        fields.serialize_field("expected_binding", expected_binding)?;
        fields.serialize_field(
            "reservation",
            &reservation
                .as_ref()
                .map(|value| value.borrowed_capture17_data()),
        )?;
        fields.serialize_field("unknown_reply", unknown_reply)?;
        fields.serialize_field("phase", phase)?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17RegistrationAttempt {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            hash,
            expected_binding,
            reservation,
            unknown_reply,
            phase,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(creator)?;
        observer.observe(original)?;
        observe_row(admitted, observer)?;
        observer.observe(hash)?;
        observer.observe(expected_binding)?;
        if let Some(value) = reservation {
            value.observe_capture17_metadata_data(observer)?;
        }
        observer.observe(unknown_reply)?;
        let _ = phase; // Closed enum has no owned backing.
        Ok(())
    }
}

impl Serialize for NativeCapture17TerminalStorageData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            original,
            terminals,
            row,
            body,
            envelope,
        } = self;
        let _ = owner;
        let mut fields = serializer.serialize_struct("NativeCapture17TerminalStorageData", 7)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-terminal-storage/17",
        )?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("terminals", terminals)?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("body_geometry", &Geometry(body))?;
        fields.serialize_field("envelope_geometry", &Geometry(envelope))?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17TerminalStorageData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            original,
            terminals,
            row,
            body,
            envelope,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(original)?;
        observer.observe(terminals)?;
        observe_row(row, observer)?;
        observe_geometry(body, observer)?;
        observe_geometry(envelope, observer)?;
        Ok(())
    }
}

impl Serialize for NativeCapture17ReplyAttempt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            snapshot,
            control,
            anchor,
            body,
            phase,
        } = self;
        let _ = owner;
        let mut fields = serializer.serialize_struct("NativeCapture17ReplyAttempt", 10)?;
        fields.serialize_field("schema", "source-private.native-capture-reply-attempt/17")?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("admitted", admitted)?;
        fields.serialize_field("snapshot", snapshot)?;
        fields.serialize_field("control", control)?;
        fields.serialize_field("anchor", anchor)?;
        fields.serialize_field("body", body)?;
        fields.serialize_field("phase", phase)?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17ReplyAttempt {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            snapshot,
            control,
            anchor,
            body,
            phase,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(creator)?;
        observer.observe(original)?;
        observe_row(admitted, observer)?;
        observer.observe(snapshot)?;
        observer.observe(control)?;
        observer.observe(anchor)?;
        observer.observe(body)?;
        let _ = phase; // Closed enum has no owned backing.
        Ok(())
    }
}

impl Serialize for NativeCapture17ConfirmationStorageData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            input,
            originals,
            row,
            hash_row,
            body,
            receipt,
            envelope,
            capture_original,
            capture_terminal,
        } = self;
        let _ = owner;
        let mut fields =
            serializer.serialize_struct("NativeCapture17ConfirmationStorageData", 11)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-confirmation-storage/17",
        )?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("input", input)?;
        fields.serialize_field("originals", originals)?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("hash_row", hash_row)?;
        fields.serialize_field("body_geometry", &Geometry(body))?;
        fields.serialize_field("receipt_geometry", &Geometry(receipt))?;
        fields.serialize_field("envelope_geometry", &Geometry(envelope))?;
        fields.serialize_field("capture_original_geometry", &Geometry(capture_original))?;
        fields.serialize_field("capture_terminal_geometry", &Geometry(capture_terminal))?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17ConfirmationStorageData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            input,
            originals,
            row,
            hash_row,
            body,
            receipt,
            envelope,
            capture_original,
            capture_terminal,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(input)?;
        observer.observe(originals)?;
        observe_row(row, observer)?;
        observe_row(hash_row, observer)?;
        observe_geometry(body, observer)?;
        observe_geometry(receipt, observer)?;
        observe_geometry(envelope, observer)?;
        observe_geometry(capture_original, observer)?;
        observe_geometry(capture_terminal, observer)?;
        Ok(())
    }
}

impl Serialize for NativeCapture17ConfirmationAttempt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            hash,
            capture_request_dom,
            capture_request_bytes,
            capture_request_ref,
            capture_terminal_dom,
            capture_terminal_bytes,
            capture_terminal_hash,
            body,
            receipt,
            phase,
        } = self;
        let _ = owner;
        let mut fields = serializer.serialize_struct("NativeCapture17ConfirmationAttempt", 15)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-confirmation-attempt/17",
        )?;
        fields.serialize_field("control_identity_role", &CONTROL_ROLE)?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("admitted", admitted)?;
        fields.serialize_field("hash", hash)?;
        fields.serialize_field("capture_request_dom", capture_request_dom)?;
        fields.serialize_field("capture_request_bytes", capture_request_bytes)?;
        fields.serialize_field("capture_request_ref", capture_request_ref)?;
        fields.serialize_field("capture_terminal_dom", capture_terminal_dom)?;
        fields.serialize_field("capture_terminal_bytes", capture_terminal_bytes)?;
        fields.serialize_field("capture_terminal_hash", capture_terminal_hash)?;
        fields.serialize_field("body", body)?;
        fields.serialize_field("receipt", receipt)?;
        fields.serialize_field("phase", phase)?;
        fields.end()
    }
}

impl ObserveMetadata for NativeCapture17ConfirmationAttempt {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner,
            creator,
            original,
            admitted,
            hash,
            capture_request_dom,
            capture_request_bytes,
            capture_request_ref,
            capture_terminal_dom,
            capture_terminal_bytes,
            capture_terminal_hash,
            body,
            receipt,
            phase,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, owner.as_ref())?;
        observer.observe(creator)?;
        observer.observe(original)?;
        observe_row(admitted, observer)?;
        observer.observe(hash)?;
        observer.observe(capture_request_dom)?;
        observer.observe(capture_request_bytes)?;
        observer.observe(capture_request_ref)?;
        observer.observe(capture_terminal_dom)?;
        observer.observe(capture_terminal_bytes)?;
        observer.observe(capture_terminal_hash)?;
        observer.observe(body)?;
        observer.observe(receipt)?;
        let _ = phase; // Closed enum has no owned backing.
        Ok(())
    }
}
