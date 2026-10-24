//! Borrows immutable Capture ancestry from the actual completed live owners.
//!
//! Some full references live in their original SDK JSON fields. This private
//! view borrows those fields without reparsing an Index or allocating typed
//! replacements. It supplies quotation DATA; a funded Source effect separately
//! retains the owned seven-field DTO before encoding any new archive output.

use super::logical::OriginalSourceRestoredSettled17Read;
use crate::{
    node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource},
    node_admission::{
        OriginalRestoredCaptureImportedOwnerInputs, OriginalRestoredCaptureSigningInputs,
    },
    node_contract::RuntimeError,
};
use crucible_node_format::{ContentRef, Validate};
use crucible_node_transport::{
    client::{CnpController, CompletedOriginalCompleteRestoreTransfer},
    protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
    reference_packet::service::complete_restore::transfer::{
        PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION, PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
        PacketCompleteRestoreTransferPhase,
    },
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};

/// Borrows one already retained full reference, preserving its defining spelling.
///
/// The JSON variant is created only from a completed SDK once owner. It cannot
/// deserialize or construct a request, ticket, scope, Source or live read.
pub(crate) enum OriginalRestoredCaptureReference17Data<'a> {
    Typed(&'a ContentRef),
    Encoded(&'a Value),
}

impl OriginalRestoredCaptureReference17Data<'_> {
    /// Compares every full-reference component without building an owned DTO.
    pub(crate) fn matches_data(&self, expected: &ContentRef) -> Result<bool, RuntimeError> {
        match self {
            Self::Typed(actual) => Ok(*actual == expected),
            Self::Encoded(value) => {
                let (algorithm, domain, digest, length, media) = reference_fields(value)?;
                Ok(algorithm == expected.hash.algorithm
                    && domain == expected.hash.domain
                    && digest == expected.hash.digest
                    && length == expected.length.get()
                    && media == expected.media_type)
            }
        }
    }

    fn to_owned_data(&self) -> Result<ContentRef, RuntimeError> {
        match self {
            Self::Typed(reference) => Ok((*reference).clone()),
            Self::Encoded(value) => {
                reference_fields(value)?;
                let reference: ContentRef =
                    serde::Deserialize::deserialize(*value).map_err(|_| invalid())?;
                reference.validate().map_err(|_| invalid())?;
                Ok(reference)
            }
        }
    }
}

impl Serialize for OriginalRestoredCaptureReference17Data<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Typed(reference) => reference.serialize(serializer),
            Self::Encoded(value) => value.serialize(serializer),
        }
    }
}

/// Borrows exactly the seven genuine immutable ancestry roles for one Source.
///
/// No public constructor, Clone, Deserialize or authority conversion exists.
/// Inherited historical state remains an independent opaque cold-reader loan.
pub(crate) struct OriginalRestoredCaptureAncestry17Data<'a> {
    parts: [OriginalRestoredCaptureReference17Data<'a>; 7],
}

impl OriginalRestoredCaptureAncestry17Data<'_> {
    /// Borrows the original already-created Index identity without reserializing it.
    pub(crate) fn parent_archive_index_data(&self) -> &OriginalRestoredCaptureReference17Data<'_> {
        &self.parts[0]
    }

    /// Borrows every exact role in the defining ancestry order.
    pub(crate) fn references_data(&self) -> &[OriginalRestoredCaptureReference17Data<'_>; 7] {
        &self.parts
    }

    /// Quotes the independent owned DTO and every actual reference string copy.
    ///
    /// This counts requested clone extents, not historical capacities or credit.
    /// The defining Source row separately includes these fixed traversal views.
    ///
    /// # Errors
    /// Refuses malformed retained references or the independently supplied bound.
    pub(crate) fn owned_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut total = std::mem::size_of::<PacketRestoredSettledAncestry17>();
        for reference in &self.parts {
            let lengths = match reference {
                OriginalRestoredCaptureReference17Data::Typed(reference) => [
                    reference.hash.algorithm.len(),
                    reference.hash.domain.len(),
                    reference.hash.digest.len(),
                    reference.media_type.len(),
                ],
                OriginalRestoredCaptureReference17Data::Encoded(value) => {
                    let (algorithm, domain, digest, _, media) = reference_fields(value)?;
                    [algorithm.len(), domain.len(), digest.len(), media.len()]
                }
            };
            for length in lengths {
                total = total
                    .checked_add(length)
                    .filter(|bytes| *bytes <= maximum)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    /// Names the defining borrowed/full-reference/owned-conversion controls.
    pub(crate) fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        PacketRestoredSettledAncestry17::counter_scratch_data()
            + PacketCompleteSemanticSource::original_live_checkpoint17_cache_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<OriginalRestoredCaptureReference17Data<'static>>()
            + size_of::<Result<OriginalRestoredCaptureReference17Data<'static>, RuntimeError>>()
            + size_of::<Result<PacketRestoredSettledAncestry17, RuntimeError>>()
            + size_of::<CompletedOriginalCompleteRestoreTransfer<'static>>() * 2
            + size_of::<
                Result<
                    CompletedOriginalCompleteRestoreTransfer<'static>,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + size_of::<(&str, &str, &str, u64, &str)>()
            + size_of::<Result<(&str, &str, &str, u64, &str), RuntimeError>>()
            + size_of::<&ContentRef>() * 7
            + size_of::<&Value>() * 8
            + size_of::<&Map<String, Value>>() * 4
            + size_of::<Result<&Map<String, Value>, RuntimeError>>()
            + size_of::<Result<&Value, RuntimeError>>()
            + size_of::<Result<&str, RuntimeError>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<std::slice::Iter<'static, OriginalRestoredCaptureReference17Data<'static>>>(
            )
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<[&str; 7]>()
            + size_of::<std::array::IntoIter<&str, 7>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<&OriginalSourceRestoredSettled17Read>>()
    }

    /// Materializes the defining owned DTO after its genuine Source row is admitted.
    ///
    /// The caller retains this completed DTO before subsequent fallible encoding.
    /// This is a data clone, not evidence of admission or currentness; it does
    /// not hash an Index, issue a ticket or replay a historical operation.
    ///
    /// # Errors
    /// Refuses malformed full references or a defining ancestry contract error.
    pub(crate) fn to_owned_data(&self) -> Result<PacketRestoredSettledAncestry17, RuntimeError> {
        let result = PacketRestoredSettledAncestry17 {
            parent_archive_index: self.parts[0].to_owned_data()?,
            parent_manifest: self.parts[1].to_owned_data()?,
            first_semantic: self.parts[2].to_owned_data()?,
            first_journal: self.parts[3].to_owned_data()?,
            first_observation: self.parts[4].to_owned_data()?,
            restoration_commit: self.parts[5].to_owned_data()?,
            restoration_hold: self.parts[6].to_owned_data()?,
        };
        result.validate_data().map_err(|_| invalid())?;
        Ok(result)
    }
}

impl Serialize for OriginalRestoredCaptureAncestry17Data<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("PacketRestoredSettledAncestry17", 7)?;
        for (name, value) in [
            "parent_archive_index",
            "parent_manifest",
            "first_semantic",
            "first_journal",
            "first_observation",
            "restoration_commit",
            "restoration_hold",
        ]
        .into_iter()
        .zip(&self.parts)
        {
            fields.serialize_field(name, value)?;
        }
        fields.end()
    }
}

impl PacketCompleteSemanticSource {
    /// Lends quotation DATA from the same signed archive, ticket and frozen SDK owners.
    ///
    /// The private completed Source cache proves first/current correspondence;
    /// this callback adds the real Prepare/Commit pairs and their immutable
    /// ClientCustody membership. The actual Source read, Window claim and native
    /// effect remain independent. The callback is repeated under both Source
    /// and SDK fences, including when the caller returns an error.
    ///
    /// # Errors
    /// Refuses foreign or busy ownership, a noncompleted transfer, substituted
    /// archive/ticket/semantic/journal/current scope, missing Hold evidence,
    /// malformed closed reference fields or a failing callback or final fence.
    pub(crate) fn with_original_restored_capture_ancestry17_data<R>(
        &self,
        controller: &CnpController,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        inspect: impl FnOnce(
            &OriginalRestoredCaptureAncestry17Data<'_>,
            Option<&OriginalSourceRestoredSettled17Read>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        inputs.authenticate_current_data()?;
        if !std::ptr::eq(inputs.source, self) {
            return Err(RuntimeError::ForeignAuthority);
        }
        inputs.ticket.authenticate_source(inputs.archive)?;
        self.with_latest_original_checkpoint17_geometry_data(
            controller,
            inputs.world,
            |checkpoint| {
                let association = self
                    .ack_peer_association
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                original.authenticate_transfer_ready_data()?;
                let emitter = original
                    .emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let prepare = controller
                    .original_completed_complete_restore_transfer(
                        emitter,
                        PacketCompleteRestoreTransferPhase::Prepare,
                    )
                    .map_err(|_| invalid())?;
                let commit = controller
                    .original_completed_complete_restore_transfer(
                        emitter,
                        PacketCompleteRestoreTransferPhase::Commit,
                    )
                    .map_err(|_| invalid())?;
                authenticate_pair_membership(controller, &prepare)?;
                authenticate_pair_membership(controller, &commit)?;
                let prepare_value = prepare
                    .original()
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
                    .ok_or_else(invalid)?;
                let request = prepare_value.as_object().ok_or_else(invalid)?;
                let commit_value = commit
                    .original()
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION)
                    .and_then(Value::as_object)
                    .ok_or_else(invalid)?;
                if field(commit_value, "prepare")? != prepare_value {
                    return Err(invalid());
                }
                let restoration = field(request, "restoration")?
                    .as_object()
                    .ok_or_else(invalid)?;
                let parent_index = encoded_reference(field(restoration, "archive_index")?)?;
                let parent_manifest = inputs.archive.archive().artifact();
                let owner = inputs.ticket.owner()?;
                let journal = inputs
                    .ticket
                    .original_restoration_journal_reference_data()?;
                let scope = checkpoint.scope_data();
                for (name, expected) in [
                    ("capture_manifest", parent_manifest),
                    ("owner_state", &owner.state),
                    ("journal", journal),
                    ("source_runtime", inputs.archive.runtime_object()),
                ] {
                    if !encoded_reference(field(restoration, name)?)?.matches_data(expected)? {
                        return Err(invalid());
                    }
                }
                if !encoded_reference(field(request, "native_control")?)?
                    .matches_data(&scope.restoration.captured_control)?
                    || !encoded_reference(field(restoration, "mapping")?)?
                        .matches_data(&scope.restoration.mapping)?
                    || scope.source_runtime != *inputs.archive.runtime_object()
                    || scope.restoration.captured_owner_state != owner.state
                    || scope.restoration.captured_journal != *journal
                    || scope.restoration.commit_request != checkpoint.record_data().restore_commit
                    || scope.target.node != self.installation().descriptor.id
                    || prepare.original().node_id != commit.original().node_id
                    || prepare.original().session_id != commit.original().session_id
                    || prepare.original().incarnation_id != commit.original().incarnation_id
                {
                    return Err(invalid());
                }
                // The Hold is its own proof body. commit_response is the terminal
                // Envelope fullref and cannot stand in for this receipt body.
                let held = commit
                    .response()
                    .body
                    .get("result")
                    .and_then(Value::as_object)
                    .and_then(|result| result.get("closed_gate_receipt"))
                    .ok_or_else(invalid)?;
                let held = encoded_reference(held)?;
                let (semantic, inherited) = match &inputs.historical {
                    OriginalRestoredCaptureImportedOwnerInputs::InitialInvocation15(
                        observation,
                    ) => {
                        let transfer = &observation.activation.transfer;
                        transfer.ticket.authenticate_source(inputs.archive)?;
                        if !std::ptr::eq(transfer.archive, inputs.archive)
                            || transfer.journal_reference != journal
                            || transfer.journal.native_snapshot != owner.state
                        {
                            return Err(RuntimeError::ForeignAuthority);
                        }
                        (&transfer.journal.semantic, None)
                    }
                    OriginalRestoredCaptureImportedOwnerInputs::Settled17(cold) => {
                        if !std::ptr::eq(cold.source, self)
                            || !std::ptr::eq(cold.owner, owner)
                            || cold.input.journal.0 != journal
                        {
                            return Err(RuntimeError::ForeignAuthority);
                        }
                        (
                            cold.source_history.reference_data(),
                            Some(cold.source_history),
                        )
                    }
                };
                if !owner.evidence.contains(semantic)
                    || inputs.archive.content().get(semantic).is_none()
                {
                    return Err(invalid());
                }
                let ancestry = OriginalRestoredCaptureAncestry17Data {
                    parts: [
                        parent_index,
                        OriginalRestoredCaptureReference17Data::Typed(parent_manifest),
                        OriginalRestoredCaptureReference17Data::Typed(semantic),
                        OriginalRestoredCaptureReference17Data::Typed(journal),
                        OriginalRestoredCaptureReference17Data::Typed(
                            checkpoint.first_observation_data(),
                        ),
                        OriginalRestoredCaptureReference17Data::Typed(
                            &scope.restoration.commit_request,
                        ),
                        held,
                    ],
                };
                let result = inspect(&ancestry, inherited);
                authenticate_pair_membership(controller, &prepare)?;
                authenticate_pair_membership(controller, &commit)?;
                inputs.authenticate_current_data()?;
                self.storage_origin_with_error::<RuntimeError>()?;
                result
            },
        )
    }
}

fn authenticate_pair_membership(
    controller: &CnpController,
    pair: &CompletedOriginalCompleteRestoreTransfer<'_>,
) -> Result<(), RuntimeError> {
    let id = pair.original().request_id.0.as_ref().ok_or_else(invalid)?;
    let actual = controller.original(id).ok_or_else(invalid)?;
    if &actual.request != pair.original() || actual.response.as_ref() != Some(pair.response()) {
        return Err(invalid());
    }
    Ok(())
}

fn encoded_reference(
    value: &Value,
) -> Result<OriginalRestoredCaptureReference17Data<'_>, RuntimeError> {
    reference_fields(value)?;
    Ok(OriginalRestoredCaptureReference17Data::Encoded(value))
}

fn reference_fields(value: &Value) -> Result<(&str, &str, &str, u64, &str), RuntimeError> {
    let root = closed_object(value, &["hash", "length", "media_type"])?;
    let hash = closed_object(field(root, "hash")?, &["algorithm", "domain", "digest"])?;
    let algorithm = text(field(hash, "algorithm")?)?;
    let domain = text(field(hash, "domain")?)?;
    let digest = text(field(hash, "digest")?)?;
    let media = text(field(root, "media_type")?)?;
    let length = text(field(root, "length")?)?;
    if algorithm != "blake3-256"
        || domain != "cnp.blob.v1"
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || media.is_empty()
        || length.is_empty()
        || length.len() > 20
        || !length.bytes().all(|byte| byte.is_ascii_digit())
        || length.len() > 1 && length.starts_with('0')
    {
        return Err(invalid());
    }
    Ok((
        algorithm,
        domain,
        digest,
        length.parse().map_err(|_| invalid())?,
        media,
    ))
}

fn closed_object<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a Map<String, Value>, RuntimeError> {
    let root = value.as_object().ok_or_else(invalid)?;
    if root.len() != names.len() || names.iter().any(|name| !root.contains_key(*name)) {
        return Err(invalid());
    }
    Ok(root)
}

fn field<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a Value, RuntimeError> {
    value.get(name).ok_or_else(invalid)
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}

fn text(value: &Value) -> Result<&str, RuntimeError> {
    value.as_str().ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::CnpSemanticSource;
    use crucible_node_format::canonical;
    use serde_json::json;

    #[test]
    fn encoded_full_reference_comparison_preserves_each_component() {
        let reference = canonical::content_ref(b"retained body", "application/json").unwrap();
        let value = serde_json::to_value(&reference).unwrap();
        let borrowed = encoded_reference(&value).unwrap();
        assert!(borrowed.matches_data(&reference).unwrap());

        let mut changed = reference.clone();
        changed.length = crucible_node_format::U64::new(reference.length.get() + 1);
        assert!(!borrowed.matches_data(&changed).unwrap());
        changed = reference.clone();
        changed.media_type = "application/octet-stream".into();
        assert!(!borrowed.matches_data(&changed).unwrap());
        changed = reference.clone();
        changed.hash.digest.replace_range(0..1, "0");
        if changed.hash.digest == reference.hash.digest {
            changed.hash.digest.replace_range(0..1, "1");
        }
        assert!(!borrowed.matches_data(&changed).unwrap());
    }

    #[test]
    fn quotation_view_matches_owned_grammar_and_keeps_hold_distinct_from_terminal() {
        // These are DATA fixtures only. No SDK owner, Source, ticket, read or
        // claimed archive is constructed by the private serializer control.
        let index = canonical::content_ref(
            b"actual index",
            "application/vnd.crucible.native-signed-index-body.v3+json",
        )
        .unwrap();
        let body = canonical::content_ref(b"actual immutable body", "application/json").unwrap();
        let held = canonical::content_ref(b"actual Hold proof", "application/json").unwrap();
        let terminal =
            canonical::content_ref(b"Commit terminal Envelope", "application/json").unwrap();
        let index_value = serde_json::to_value(&index).unwrap();
        let held_value = serde_json::to_value(&held).unwrap();
        let view = OriginalRestoredCaptureAncestry17Data {
            parts: [
                encoded_reference(&index_value).unwrap(),
                OriginalRestoredCaptureReference17Data::Typed(&body),
                OriginalRestoredCaptureReference17Data::Typed(&body),
                OriginalRestoredCaptureReference17Data::Typed(&body),
                OriginalRestoredCaptureReference17Data::Typed(&body),
                OriginalRestoredCaptureReference17Data::Typed(&body),
                encoded_reference(&held_value).unwrap(),
            ],
        };
        let owned = view.to_owned_data().unwrap();
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::to_value(&owned).unwrap()
        );
        assert_eq!(owned.restoration_hold, held);
        assert_ne!(owned.restoration_hold, terminal);
        let bytes = view.owned_requested_storage_data(usize::MAX).unwrap();
        assert!(view.owned_requested_storage_data(bytes).is_ok());
        assert!(view.owned_requested_storage_data(bytes - 1).is_err());
    }

    #[test]
    fn closed_encoded_references_refuse_extra_fields_and_noncanonical_counters() {
        let reference = canonical::content_ref(b"actual body", "application/json").unwrap();
        let original = serde_json::to_value(&reference).unwrap();
        for length in [
            json!("01"),
            json!("+1"),
            json!("18446744073709551616"),
            json!(1),
        ] {
            let mut value = original.clone();
            value["length"] = length;
            assert!(encoded_reference(&value).is_err());
        }
        let mut value = original.clone();
        value["extra"] = json!(false);
        assert!(encoded_reference(&value).is_err());
        let mut value = original.clone();
        value["hash"]["extra"] = json!(false);
        assert!(encoded_reference(&value).is_err());
        let mut value = original;
        value["hash"]["digest"] = json!("F".repeat(64));
        assert!(encoded_reference(&value).is_err());
    }
}
