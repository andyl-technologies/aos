//! Prices the closed prospective Source DTO copies independently of the SDK.
//!
//! These objects have fixed typed fields containing String/Id/HashRef leaves,
//! ContentRef fields and exact32-byte Vecs represented by43 base64 characters.
//! They contain no dynamic typed sequence or map beyond the Envelope's existing
//! Value body/extensions. Their projected DOM backing therefore bounds a new
//! typed clone's requested heap. Inline typed headers, copy counts, current
//! model/receipt clones and output DOM/canonical banks are separate Source rows.

use super::*;

/// Reports one closed prospective typed owner's new backing and formatter work.
///
/// This inert DATA supplies no owner, original, completed state or reservation.
pub struct PacketRestoredObservation17SourceComponentStorageData {
    storage: OriginalSerializationStorageData,
    work: usize,
}

impl PacketRestoredObservation17SourceComponentStorageData {
    /// Returns a bound for a separately owned typed clone's requested heap.
    pub fn retained_heap_upper_bytes_data(&self) -> usize {
        self.storage.retained_value_backing_bytes
    }

    /// Returns independently bounded DOM, formatter and canonical work.
    pub fn serialization_work_bytes_data(&self) -> usize {
        self.work
    }
}

/// Reports all five distinct prospective Source owners without constructing them.
pub struct PacketRestoredObservation17SourceTypedStorageData {
    body: PacketRestoredObservation17SourceComponentStorageData,
    request: PacketRestoredObservation17SourceComponentStorageData,
    context: PacketRestoredObservation17SourceComponentStorageData,
    artifact: PacketRestoredObservation17SourceComponentStorageData,
    original: PacketRestoredObservation17SourceComponentStorageData,
}

impl PacketRestoredObservation17SourceTypedStorageData {
    /// Borrows the unchanged typed observation body geometry.
    pub fn body_data(&self) -> &PacketRestoredObservation17SourceComponentStorageData {
        &self.body
    }

    /// Borrows the independently retained Source request geometry.
    pub fn request_data(&self) -> &PacketRestoredObservation17SourceComponentStorageData {
        &self.request
    }

    /// Borrows the independently retained assigned context geometry.
    pub fn context_data(&self) -> &PacketRestoredObservation17SourceComponentStorageData {
        &self.context
    }

    /// Borrows the independently retained signed artifact geometry.
    pub fn artifact_data(&self) -> &PacketRestoredObservation17SourceComponentStorageData {
        &self.artifact
    }

    /// Borrows the independently retained complete Envelope geometry.
    pub fn original_data(&self) -> &PacketRestoredObservation17SourceComponentStorageData {
        &self.original
    }
}

/// Projects the five closed prospective Source owners without invoking Serialize.
///
/// The Source independently authenticates each borrowed scope/current-proof
/// field and prices the actual number of copies and inline owner headers. The
/// SDK assignment row owns different copies and cannot pay these Source fields.
///
/// # Errors
/// Refuses unsupported prospective fields, checked overflow or short bounds.
pub fn quote_restored_observation17_source_typed_storage_data(
    prospective: &PacketRestoredObservation17ProspectiveData<'_>,
    maximum: usize,
) -> Result<PacketRestoredObservation17SourceTypedStorageData, ProviderError> {
    fn component(
        maximum: usize,
        decimal_fields: usize,
        byte_fields: usize,
        project: impl FnOnce(&mut Projection) -> Result<(), ProviderError>,
    ) -> Result<PacketRestoredObservation17SourceComponentStorageData, ProviderError> {
        let mut out = Projection::new(maximum)?;
        project(&mut out)?;
        let mut storage = out.finish(maximum)?;
        // U64's actual custom Serialize creates one <=20-byte decimal String;
        // each typed proof/context Bytes formatter creates exactly43 bytes.
        storage.serializer_temporary_requested_bytes = decimal_fields
            .checked_mul(20)
            .and_then(|bytes| byte_fields.checked_mul(43)?.checked_add(bytes))
            .ok_or_else(exhausted)?;
        let work = storage.requested_total()?;
        if work > maximum {
            return Err(exhausted());
        }
        Ok(PacketRestoredObservation17SourceComponentStorageData { storage, work })
    }

    // Scope contains12 U64 fields. The request adds four reference lengths,
    // one frontier and three independent allocation axes. Context/artifact
    // each contain that whole request; their own proof Bytes remain distinct.
    let body = component(maximum, 3, 0, |out| observe(out, prospective.observe))?;
    let request = component(maximum, 20, 1, |out| prospective.request(out))?;
    let context = component(maximum, 20, 2, |out| prospective.context(out))?;
    let artifact = component(maximum, 20, 3, |out| prospective.artifact(out))?;
    // Envelope body/extensions already own JSON Values; only its actual U64
    // sequence invokes a custom formatter while serializing that Envelope.
    let original = component(maximum, 1, 0, |out| {
        Observation17OriginalData::Prospective(prospective).project(out)
    })?;
    Ok(PacketRestoredObservation17SourceTypedStorageData {
        body,
        request,
        context,
        artifact,
        original,
    })
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<PacketRestoredObservation17SourceComponentStorageData>()
        + size_of::<PacketRestoredObservation17SourceTypedStorageData>()
        + size_of::<Result<PacketRestoredObservation17SourceTypedStorageData, ProviderError>>()
        + 5 * size_of::<OriginalSerializationStorageData>()
        + size_of::<[usize; 5]>()
}

/// Projects independently repeated work on the actual complete current wrapper.
///
/// The Source supplies the exact immutable private-cache content bank. This
/// function checks borrowed JSON geometry only and creates no DTO/current-proof
/// correspondence. Its work bounds repeated validation of the typed wrapper,
/// including U64/Bytes formatter output represented in that same literal bank.
///
/// # Errors
/// Refuses malformed/unsupported JSON, excessive depth or a short finite bound.
pub fn quote_restored_observation17_current_wrapper_storage_data(
    current_wrapper: &[u8],
    maximum: usize,
) -> Result<PacketRestoredObservation17SourceComponentStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    retained_json_value(&mut out, current_wrapper, 0)?;
    let mut storage = out.finish(maximum)?;
    // A leaf formatter dies before the next typed field is serialized. Any
    // Bytes output occurs in the actual complete literal; independently retain
    // the <=20-byte numeric formatter bank even for a short decimal spelling.
    storage.serializer_temporary_requested_bytes = current_wrapper
        .len()
        .checked_add(20)
        .ok_or_else(exhausted)?;
    let work = storage.requested_total()?;
    if work > maximum {
        return Err(exhausted());
    }
    Ok(PacketRestoredObservation17SourceComponentStorageData { storage, work })
}

// crucible-lint: allow panic-shortcut -- compares borrowed DATA geometry with actual serializers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

    #[test]
    fn current_wrapper_geometry_accepts_signed_float_and_escaped_extension_fields() {
        let actual = serde_json::json!({
            "metadata": {"escaped\nkey/é": [-1, -1.25, 1.0e20, "quote\"/😀"]},
            "nested": [null, true, {"zero": 0}],
        });
        let bytes = crucible_node_contract::canonical::canonical_json(&actual).unwrap();
        let expected =
            actual_serialization_storage_data(&actual, Default::default(), usize::MAX).unwrap();
        let quote =
            quote_restored_observation17_current_wrapper_storage_data(&bytes, usize::MAX).unwrap();

        assert!(quote.retained_heap_upper_bytes_data() >= expected.retained_value_backing_bytes);
        assert!(quote.serialization_work_bytes_data() >= expected.requested_total().unwrap());
        for malformed in [b"[-]".as_slice(), b"[1e]", b"[01]", b"[1.]"] {
            assert!(
                quote_restored_observation17_current_wrapper_storage_data(malformed, usize::MAX)
                    .is_err()
            );
        }
        assert!(quote_restored_observation17_current_wrapper_storage_data(&bytes, 1).is_err());
    }
}
