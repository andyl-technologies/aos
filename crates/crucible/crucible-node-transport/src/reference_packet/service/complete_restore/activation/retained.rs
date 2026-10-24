//! Observes actual retained activation evidence without reserializing its owners.

use super::*;
use crate::reference_packet::{
    control::PacketNative5UnderlyingRecord, service::complete_restore::PacketNativeRestoredRecord,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use std::mem::size_of;

/// Borrows the closed independent activation originals retained by Source.
pub enum RetainedRestorationActivationData<'a> {
    /// Borrows a separately retained ordinary phase body.
    Command(&'a PacketRestorationActivationCommand),
    /// Borrows an actual retained activation terminal, including raw/error data.
    Response(&'a crate::bodies::ResponseBody),
    /// Borrows the genuine constructed complete all-owner world manifest.
    Manifest(&'a crucible_node_format::ActivationManifest),
    /// Borrows the independently constructed unsigned request.
    Request(&'a PacketRestorationActivationRequest),
    /// Borrows the independently constructed MAC context.
    Context(&'a PacketRestorationActivationContext),
    /// Borrows a separately retained proof owner.
    Proof(&'a PacketRestorationActivationProof),
    /// Borrows the full normalized signed artifact.
    Artifact(&'a PacketRestorationActivationArtifact),
    /// Borrows an independently retained signed upload request.
    UploadRequest(&'a upload::PacketRestorationActivationUploadRequest),
    /// Borrows an independently retained upload MAC context.
    UploadContext(&'a upload::PacketRestorationActivationUploadContext),
    /// Borrows an independently retained full upload artifact.
    UploadArtifact(&'a upload::PacketRestorationActivationUploadArtifact),
}

impl RetainedRestorationActivationData<'_> {
    /// Reports every actual nested capacity of this independent typed original.
    ///
    /// Caller-owned inline enum/Option/DTO headers remain separate. Equal data
    /// in another owner is visited again without an alias or digest discount.
    ///
    /// # Errors
    /// Refuses checked layout overflow or the finite field/depth traversal cap.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

macro_rules! owned_observer {
    ($($ty:ty),+ $(,)?) => {
        $(impl $ty {
            /// Visits actual nested backing without serializing or authenticating it.
            pub(crate) fn observe_owned_metadata_data(
                &self,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                observer.observe(self)
            }
        })+
    };
}

owned_observer!(
    PacketRestorationActivationScope,
    PacketRestorationActivationRequest,
    PacketRestorationActivationContext,
    PacketRestorationActivationArtifact,
);

macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl crate::retained_metadata::ObserveMetadata for $ty {
            fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                let Self { $($field),+ } = self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
    };
}

fields!(
    PacketRestorationActivationAllocationRow,
    retained_requested_bytes,
    maximum_simultaneous_transient_bytes,
    declared_counter_scratch_bytes
);
fields!(
    PacketRestorationActivationTarget,
    native_pid,
    session,
    incarnation,
    node,
    owner,
    owner_generation,
    binding_hash,
    world,
    activation,
    generation,
    prepared_token,
    gate,
    admission,
    transaction
);
fields!(
    PacketRestorationActivationOriginals,
    captured_owner_state,
    captured_control,
    captured_journal,
    mapping,
    commit_request,
    commit_response,
    context_digest
);
fields!(
    PacketRestorationActivationScope,
    source_birth,
    source_runtime,
    scope_proof,
    target,
    restoration
);
fields!(
    PacketRestorationActivationRequest,
    schema,
    phase,
    scope,
    native_allocation
);
fields!(
    PacketRestorationActivationContext,
    request,
    assigned_request
);
fields!(
    PacketRestorationActivationProof,
    schema,
    algorithm,
    context_digest,
    mac
);
fields!(PacketRestorationActivationArtifact, request, proof);

impl crate::retained_metadata::ObserveMetadata for PacketRestorationActivationPhase {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Arm | Self::WorldActivate => Ok(()),
        }
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketRestorationActivationCommand {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Arm(body) => {
                let crate::bodies::ActivateRequest {
                    admission_id,
                    activation_id,
                    world_generation,
                    prepared_token,
                    world_binding_hash,
                    gate_id,
                    extensions,
                } = body;
                observer.observe(admission_id)?;
                observer.observe(activation_id)?;
                observer.observe(world_generation)?;
                observer.observe(prepared_token)?;
                observer.observe(world_binding_hash)?;
                observer.observe(gate_id)?;
                observer.observe(extensions)
            }
            Self::WorldActivate(body) => {
                let crate::bodies::WorldActivateRequest {
                    transaction_id,
                    activation_id,
                    world_generation,
                    prepared_token,
                    world_binding_hash,
                    gate_id,
                    activation_manifest,
                    extensions,
                } = body;
                observer.observe(transaction_id)?;
                observer.observe(activation_id)?;
                observer.observe(world_generation)?;
                observer.observe(prepared_token)?;
                observer.observe(world_binding_hash)?;
                observer.observe(gate_id)?;
                observer.observe(activation_manifest)?;
                observer.observe(extensions)
            }
        }
    }
}

/// Reports actual nested backing of the retained restored receipt and model proof.
///
/// The caller separately counts its inline Record/Option/enum slots. This walk
/// includes each real underlying Box, actual String/Vec capacities and nested
/// Value/tree capacities. Equal content in independent owners is counted twice.
/// No serializer, callback, copy or evidence/authentication operation is invoked.
///
/// # Errors
/// Refuses arithmetic overflow or the finite metadata walk's row/depth bound.
pub fn restoration_activation_retained_native_evidence_data(
    record: &PacketNativeRestoredRecord,
    underlying: Option<&PacketNative5UnderlyingRecord>,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observe_native_evidence_metadata_data(record, underlying, &mut observer)?;
    Ok(observer.finish())
}

/// Names fixed owning-walk and result views before observing retained evidence.
pub fn restoration_activation_retained_native_evidence_counter_scratch_data() -> usize {
    crate::retained_metadata::historical_serialization_counter_scratch_data()
        + size_of::<&mut crate::retained_metadata::records::MetadataRecordBank>()
        + size_of::<&mut crate::retained_metadata::aliases::MetadataAliasBank>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<&PacketNativeRestoredRecord>()
        + size_of::<Option<&PacketNative5UnderlyingRecord>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[&serde_json::Value; 64]>()
}

fields!(
    upload::PacketRestorationActivationUploadRequest,
    schema,
    scope,
    role,
    coordinator,
    manifest,
    maximum_frame_bytes,
    chunk_bytes,
    maximum_requests,
    native_allocation
);
fields!(
    upload::PacketRestorationActivationUploadContext,
    request,
    assigned_request
);
fields!(
    upload::PacketRestorationActivationUploadArtifact,
    request,
    proof
);
owned_observer!(
    upload::PacketRestorationActivationUploadRequest,
    upload::PacketRestorationActivationUploadContext,
    upload::PacketRestorationActivationUploadArtifact
);
impl crate::retained_metadata::ObserveMetadata for upload::PacketRestorationActivationUploadRole {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Coordinator | Self::Manifest => Ok(()),
        }
    }
}

pub(crate) fn observe_response(
    body: &crate::bodies::ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    use crate::bodies::*;
    let ResponseBody { shape, result } = body;
    match shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    match result {
        None => Ok(()),
        Some(MethodResult::Activate(value)) => {
            let ActivateResult {
                staged,
                gate_id,
                staged_owner_ids,
                activation_receipt,
            } = value;
            observer.observe(staged)?;
            observer.observe(gate_id)?;
            observer.observe(staged_owner_ids)?;
            observer.observe(activation_receipt)
        }
        Some(MethodResult::WorldActivate(value)) => {
            let WorldActivateResult {
                armed_owner_ids,
                gate_id,
                activation_receipt,
            } = value;
            observer.observe(armed_owner_ids)?;
            observer.observe(gate_id)?;
            observer.observe(activation_receipt)
        }
        _ => Err(super::invalid()),
    }
}

/// Names fixed borrowed terminal, manifest, result and observer views.
///
/// Independent typed/raw payloads and outer containing owners remain separately
/// charged. These fixed views authorize neither a Source read nor activation.
pub fn restoration_activation_retained_counter_scratch_data() -> usize {
    use crate::bodies::*;
    size_of::<&mut crate::retained_metadata::records::MetadataRecordBank>()
        + size_of::<&mut crate::retained_metadata::aliases::MetadataAliasBank>()
        + size_of::<RetainedRestorationActivationData<'static>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&ResponseBody>() + size_of::<&ResponseShape>()
        + size_of::<&Option<MethodResult>>() + size_of::<&ActivateResult>()
        + size_of::<&WorldActivateResult>() + size_of::<&crucible_node_format::ActivationManifest>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::PreparedOwner>>()
        + size_of::<(&Id, &Id, &U64, &Id, &Vec<HashRef>, &ContentRef, &crucible_node_format::Extensions)>()
        // Actual destructured field loans: three result variants and the nine
        // full manifest fields, including their own nested container handles.
        + size_of::<(&bool, &Id, &crucible_node_format::IdSet, &ContentRef)>()
        + size_of::<(&Id, &crucible_node_format::IdSet, &ContentRef)>()
        + size_of::<(&crucible_node_format::Version, &Id, &Id, &U64, &Id, &HashRef,
            &Vec<crucible_node_format::PreparedOwner>, &ContentRef, &crucible_node_format::Extensions)>()
        + 2 * size_of::<(&crate::bodies::OperationState, &serde_json::Map<String, serde_json::Value>, &crucible_node_format::Extensions)>()
        + size_of::<(&crate::bodies::OperationState, &crate::bodies::ErrorRecord, &crucible_node_format::Extensions)>()
}

#[cfg(test)]
mod manifest_owner_tests {
    use super::*;
    use crucible_node_format::{ActivationManifest, Extensions, PreparedOwner, canonical};

    #[test]
    fn manifest_raw_owner_walk_counts_actual_spare_owner_and_binding_banks() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let hash = canonical::json_hash("cnp.binding.v1", &"actual-binding-data").unwrap();
        let mut manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: Id::new("transaction").unwrap(),
            activation_id: Id::new("activation").unwrap(),
            world_generation: U64::new(2),
            gate_id: Id::new("gate").unwrap(),
            world_binding_hash: hash.clone(),
            owners: vec![PreparedOwner {
                owner_id: Id::new("owner").unwrap(),
                incarnation_id: Id::new("incarnation").unwrap(),
                owner_generation: U64::new(2),
                prepared_token: Id::new("prepared").unwrap(),
                binding_hashes: vec![hash],
                ready_receipt: reference.clone(),
                extensions: Extensions::new(),
            }],
            coordinator_state_ref: reference,
            extensions: Extensions::new(),
        };
        // Portable manifest data grants no world, Source or native permission.
        // Reserve moves existing owners without cloning their string backing.
        let before = RetainedRestorationActivationData::Manifest(&manifest)
            .original_retained_metadata_facts()
            .unwrap();
        let owners_before = manifest.owners.capacity();
        let hashes_before = manifest.owners[0].binding_hashes.capacity();
        manifest.owners.reserve_exact(5);
        manifest.owners[0].binding_hashes.reserve_exact(7);
        let expected = (manifest.owners.capacity() - owners_before) * size_of::<PreparedOwner>()
            + (manifest.owners[0].binding_hashes.capacity() - hashes_before) * size_of::<HashRef>();
        let after = RetainedRestorationActivationData::Manifest(&manifest)
            .original_retained_metadata_facts()
            .unwrap();
        assert!(expected > 0);
        assert_eq!(
            after.vector_capacity_bytes - before.vector_capacity_bytes,
            expected
        );
        assert_eq!(after.string_capacity_bytes, before.string_capacity_bytes);
        assert_eq!(after.tree_entries, before.tree_entries);
    }
}

fn observe_native_evidence_metadata_data(
    record: &PacketNativeRestoredRecord,
    underlying: Option<&PacketNative5UnderlyingRecord>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeRestoredRecord {
        schema,
        native_receipt,
        captured_owner_state,
        captured_journal,
        mapping,
        restore_commit,
        restore_response,
        context_digest,
        physical_gate_held,
    } = record;
    observer.observe(schema)?;
    observer.observe(native_receipt)?;
    observer.observe(captured_owner_state)?;
    observer.observe(captured_journal)?;
    observer.observe(mapping)?;
    observer.observe(restore_commit)?;
    observer.observe(restore_response)?;
    observer.observe(context_digest)?;
    observer.observe(physical_gate_held)?;
    match underlying {
        None => {}
        Some(PacketNative5UnderlyingRecord::Producer(record)) => {
            observer.boxed_value(record.as_ref())?;
            observer.observe(record.as_ref())?;
        }
        Some(PacketNative5UnderlyingRecord::Reactive(record)) => {
            observer.boxed_value(record.as_ref())?;
            observer.observe(record.as_ref())?;
        }
    }
    Ok(())
}

/// Records the actual restored receipt and optional underlying proof capacities.
///
/// Clears only these independent precharged banks. It performs no allocation or
/// live predicate; recorded rows cannot reconstruct an authenticated evidence owner.
///
/// # Errors
/// Refuses finite traversal/overflow or original record/alias bank exhaustion.
pub fn restoration_activation_record_native_evidence_metadata_data(
    record: &PacketNativeRestoredRecord,
    underlying: Option<&PacketNative5UnderlyingRecord>,
    records: &mut crate::retained_metadata::records::MetadataRecordBank,
    aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
    observe_native_evidence_metadata_data(record, underlying, &mut observer)?;
    Ok(observer.finish())
}

/// Bounds Bytes encoding temporaries from the complete actual evidence walk.
///
/// Encoded output, Value and canonical owners remain independent caller rows.
///
/// # Errors
/// Refuses finite traversal or checked base64 extent overflow.
pub fn restoration_activation_historical_native_evidence_transient_bytes_data(
    record: &PacketNativeRestoredRecord,
    underlying: Option<&PacketNative5UnderlyingRecord>,
) -> Result<usize, ProviderError> {
    crate::retained_metadata::historical_serialization_transient_data(
        restoration_activation_retained_native_evidence_data(record, underlying)?,
    )
}

impl RetainedRestorationActivationData<'_> {
    fn observe_historical_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Command(value) => observer.observe(*value)?,
            Self::Response(value) => observe_response(value, observer)?,
            Self::Manifest(value) => {
                let crucible_node_format::ActivationManifest {
                    schema_version,
                    transaction_id,
                    activation_id,
                    world_generation,
                    gate_id,
                    world_binding_hash,
                    owners,
                    coordinator_state_ref,
                    extensions,
                } = value;
                observer.observe(schema_version)?;
                observer.observe(transaction_id)?;
                observer.observe(activation_id)?;
                observer.observe(world_generation)?;
                observer.observe(gate_id)?;
                observer.observe(world_binding_hash)?;
                observer.vector::<crucible_node_format::PreparedOwner>(owners.capacity())?;
                for owner in owners {
                    let crucible_node_format::PreparedOwner {
                        owner_id,
                        incarnation_id,
                        owner_generation,
                        prepared_token,
                        binding_hashes,
                        ready_receipt,
                        extensions,
                    } = owner;
                    observer.observe(owner_id)?;
                    observer.observe(incarnation_id)?;
                    observer.observe(owner_generation)?;
                    observer.observe(prepared_token)?;
                    observer.observe(binding_hashes)?;
                    observer.observe(ready_receipt)?;
                    observer.observe(extensions)?;
                }
                observer.observe(coordinator_state_ref)?;
                observer.observe(extensions)?;
            }
            Self::Request(value) => observer.observe(*value)?,
            Self::Context(value) => observer.observe(*value)?,
            Self::Proof(value) => observer.observe(*value)?,
            Self::Artifact(value) => observer.observe(*value)?,
            Self::UploadRequest(value) => observer.observe(*value)?,
            Self::UploadContext(value) => observer.observe(*value)?,
            Self::UploadArtifact(value) => observer.observe(*value)?,
        }
        Ok(())
    }

    /// Records complete actual activation owner capacities into finite banks.
    ///
    /// Each owner needs its independent precharged record/alias pair. Both banks
    /// are cleared; exhaustion preserves partial rows and never grows storage.
    /// This reuses the identical owning traversal, without serializers or IO.
    ///
    /// # Errors
    /// Refuses unsupported children, traversal/overflow or finite bank exhaustion.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

/// Borrows actual command, full manifest or independent World-result history.
///
/// ```text
/// {kind:"command"|"manifest"|"world_result", data:actual_typed_fields}
/// ```
///
/// This wrapper has no decoder, owner extraction or live permission constructor.
pub enum HistoricalRestorationActivationData<'a> {
    /// Borrows an actual retained Arm or World command, including all extensions.
    Command(&'a PacketRestorationActivationCommand),
    /// Borrows the actual complete manifest and independent owner/ID capacities.
    Manifest(&'a crucible_node_format::ActivationManifest),
    /// Borrows an independently retained actual World result and its own banks.
    WorldResult(&'a crate::bodies::WorldActivateResult),
}

impl HistoricalRestorationActivationData<'_> {
    fn observe_historical_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Command(value) => RetainedRestorationActivationData::Command(value)
                .observe_historical_metadata_data(observer),
            Self::Manifest(value) => RetainedRestorationActivationData::Manifest(value)
                .observe_historical_metadata_data(observer),
            Self::WorldResult(value) => observer.observe(*value),
        }
    }

    /// Observes actual backing without deriving capacity from serialized lengths.
    ///
    /// # Errors
    /// Refuses checked traversal, depth or extent overflow.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Records the exact owning walk in this owner's independent finite banks.
    ///
    /// # Errors
    /// Refuses metadata traversal or either original bank capacity; partial rows
    /// remain retained and no growth or backend callback occurs.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Bounds actual Bytes serialization temporaries independently of output.
    ///
    /// # Errors
    /// Refuses checked metadata traversal or encoding extent overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.retained_metadata_data()?,
        )
    }

    /// Names complete wrapper, same-walk and actual borrowed serializer layouts.
    pub fn historical_counter_scratch_data() -> usize {
        restoration_activation_retained_counter_scratch_data()
            + crate::retained_metadata::historical_serialization_counter_scratch_data()
            + size_of::<HistoricalRestorationActivationData<'static>>()
            + size_of::<&HistoricalRestorationActivationData<'static>>()
            + size_of::<&RetainedRestorationActivationData<'static>>()
            + size_of::<HistoricalCommand<'static>>()
            + size_of::<&HistoricalCommand<'static>>()
            + size_of::<&&PacketRestorationActivationCommand>()
            + size_of::<&crate::bodies::ActivateRequest>()
            + size_of::<&crate::bodies::WorldActivateRequest>()
            + size_of::<&&crucible_node_format::ActivationManifest>()
            + size_of::<&&crate::bodies::WorldActivateResult>()
    }
}

impl serde::Serialize for HistoricalRestorationActivationData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("HistoricalRestorationActivationData", 2)?;
        match self {
            Self::Command(value) => {
                state.serialize_field("kind", "command")?;
                state.serialize_field("data", &HistoricalCommand(value))?;
            }
            Self::Manifest(value) => {
                state.serialize_field("kind", "manifest")?;
                state.serialize_field("data", value)?;
            }
            Self::WorldResult(value) => {
                state.serialize_field("kind", "world_result")?;
                state.serialize_field("data", value)?;
            }
        }
        state.end()
    }
}

struct HistoricalCommand<'a>(&'a PacketRestorationActivationCommand);

impl serde::Serialize for HistoricalCommand<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("HistoricalRestorationActivationCommand", 2)?;
        match self.0 {
            PacketRestorationActivationCommand::Arm(value) => {
                state.serialize_field("kind", "arm")?;
                state.serialize_field("data", value)?;
            }
            PacketRestorationActivationCommand::WorldActivate(value) => {
                state.serialize_field("kind", "world_activate")?;
                state.serialize_field("data", value)?;
            }
        }
        state.end()
    }
}

#[path = "retained/capture_scope17.rs"]
mod capture_scope17;
