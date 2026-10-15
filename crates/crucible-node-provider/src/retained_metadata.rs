//! Observes actual retained container capacities without copying protocol state.
//!
//! This source-private walker visits typed originals. It reports requested String,
//! Vec, Box and shared backing extents, plus tree populations and entry layouts.
//! These facts are not allocator-rounded heap measurements: callers separately
//! admit tree node/control-block layouts, alignment, traversal stack and native
//! peak. Shared backing is conservatively counted on every retained view; no
//! serialized identity or deduplication authority is inferred.

pub mod aliases;
pub mod records;

use crate::ProviderError;
use crate::bodies::RealizeRequest;
use crate::reference_packet::{
    control::PacketControlSelection,
    coordinator::{PacketConnectedHostSelection, PacketNative5CoordinatorInstallation},
};
use crucible_node_contract::*;
use records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, align_of_val, size_of, size_of_val},
};

/// Reports observed backing capacities and independently charged metadata terms.
///
/// Shared owners are conservatively counted per view. Tree facts describe actual
/// containers and initialized entries, not their hidden node allocation sizes.
/// An empty tree may retain a root; callers reserve its node allowance as well.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedProtocolMetadataFacts {
    /// Sums actual capacities of String and Id backing buffers.
    pub string_capacity_bytes: usize,
    /// Counts inspected String and Id backing buffers, including empty ones.
    pub string_banks: usize,
    /// Sums actual Vec capacities times their actual element layout.
    pub vector_capacity_bytes: usize,
    /// Counts inspected Vec and Bytes buffers, including empty ones.
    pub vector_banks: usize,
    /// Sums inline values retained in independently owned Boxes.
    pub boxed_value_bytes: usize,
    /// Sums inline values or slice elements behind retained Rc and Arc owners.
    pub shared_value_bytes: usize,
    /// Counts shared backing views whose control blocks need separate admission.
    pub shared_backing_views: usize,
    /// Counts tree containers, including possibly allocated empty roots.
    pub tree_containers: usize,
    /// Sums initialized tree entries across all observed containers.
    pub tree_entries: usize,
    /// Bounds one tree entry's actual key and value layout across this view.
    pub maximum_tree_key_value_bytes: usize,
    /// Reports the largest actual key/value alignment, including zero-sized keys.
    pub maximum_tree_entry_alignment: usize,
    /// Reports the largest actual shared payload or slice-element alignment.
    pub maximum_shared_value_alignment: usize,
    /// Counts visited fields and initialized rows for bounded traversal work.
    pub observed_nodes: usize,
    /// Counts exact capacity/container records required by this typed traversal.
    pub capacity_records: usize,
}

pub(crate) struct MetadataObserver<'a> {
    facts: RetainedProtocolMetadataFacts,
    json_depth: usize,
    records: Option<&'a mut MetadataRecordBank>,
    aliases: Option<&'a mut aliases::MetadataAliasBank>,
}

impl<'a> MetadataObserver<'a> {
    pub(crate) fn new() -> Self {
        Self {
            facts: RetainedProtocolMetadataFacts::default(),
            json_depth: 0,
            records: None,
            aliases: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn recording(records: &'a mut MetadataRecordBank) -> Self {
        records.clear();
        Self {
            facts: RetainedProtocolMetadataFacts::default(),
            json_depth: 0,
            records: Some(records),
            aliases: None,
        }
    }

    pub(crate) fn recording_with_aliases(
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut aliases::MetadataAliasBank,
    ) -> Self {
        records.clear();
        aliases.clear();
        Self {
            facts: RetainedProtocolMetadataFacts::default(),
            json_depth: 0,
            records: Some(records),
            aliases: Some(aliases),
        }
    }

    pub(crate) fn shared_original<T: ?Sized>(
        &mut self,
        kind: aliases::MetadataSharedKind,
        backing: &T,
    ) -> Result<(), ProviderError> {
        if let Some(aliases) = &mut self.aliases {
            aliases.retain(kind, backing)?;
        }
        let bytes = size_of_val(backing);
        let alignment = align_of_val(backing);
        self.record(MetadataRecordKind::Shared, bytes, 1, alignment)?;
        self.facts.maximum_shared_value_alignment =
            self.facts.maximum_shared_value_alignment.max(alignment);
        add(&mut self.facts.shared_value_bytes, bytes)?;
        add(&mut self.facts.shared_backing_views, 1)
    }

    fn record(
        &mut self,
        kind: MetadataRecordKind,
        extent: usize,
        element_bytes: usize,
        alignment: usize,
    ) -> Result<(), ProviderError> {
        add(&mut self.facts.capacity_records, 1)?;
        if self.facts.capacity_records > 131_072 {
            return Err(overflow());
        }
        if let Some(records) = &mut self.records {
            records.append(MetadataCapacityRecord {
                kind,
                extent,
                element_bytes,
                alignment,
            })?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> RetainedProtocolMetadataFacts {
        self.facts
    }

    pub(crate) fn observe<T: ObserveMetadata + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), ProviderError> {
        add(&mut self.facts.observed_nodes, 1)?;
        if self.facts.observed_nodes > 131_072 {
            return Err(ProviderError::ResourceExhausted(
                "retained metadata traversal rows",
            ));
        }
        value.observe_metadata(self)
    }

    pub(crate) fn shared_value<T: ?Sized>(&mut self, backing: &T) -> Result<(), ProviderError> {
        if self.aliases.is_some() {
            return Err(ProviderError::Correlation(
                "whole shared backing identity absent",
            ));
        }
        let bytes = size_of_val(backing);
        let alignment = align_of_val(backing);
        self.record(MetadataRecordKind::Shared, bytes, 1, alignment)?;
        self.facts.maximum_shared_value_alignment =
            self.facts.maximum_shared_value_alignment.max(alignment);
        add(&mut self.facts.shared_value_bytes, bytes)?;
        add(&mut self.facts.shared_backing_views, 1)
    }

    pub(crate) fn boxed_value<T: ?Sized>(&mut self, backing: &T) -> Result<(), ProviderError> {
        let bytes = size_of_val(backing);
        self.record(MetadataRecordKind::Boxed, bytes, 1, align_of_val(backing))?;
        add(&mut self.facts.boxed_value_bytes, bytes)
    }

    fn string(&mut self, capacity: usize) -> Result<(), ProviderError> {
        self.record(MetadataRecordKind::String, capacity, 1, 1)?;
        add(&mut self.facts.string_capacity_bytes, capacity)?;
        add(&mut self.facts.string_banks, 1)
    }

    pub(crate) fn vector<T>(&mut self, capacity: usize) -> Result<(), ProviderError> {
        self.record(
            MetadataRecordKind::Vector,
            capacity,
            size_of::<T>(),
            align_of::<T>(),
        )?;
        let bytes = capacity.checked_mul(size_of::<T>()).ok_or(overflow())?;
        add(&mut self.facts.vector_capacity_bytes, bytes)?;
        add(&mut self.facts.vector_banks, 1)
    }

    pub(crate) fn tree<K, V>(&mut self, entries: usize) -> Result<(), ProviderError> {
        self.record(
            MetadataRecordKind::Tree,
            entries,
            size_of::<K>()
                .checked_add(size_of::<V>())
                .ok_or(overflow())?,
            align_of::<K>().max(align_of::<V>()),
        )?;
        self.facts.maximum_tree_entry_alignment = self
            .facts
            .maximum_tree_entry_alignment
            .max(align_of::<K>().max(align_of::<V>()));
        add(&mut self.facts.tree_containers, 1)?;
        add(&mut self.facts.tree_entries, entries)?;
        self.facts.maximum_tree_key_value_bytes = self.facts.maximum_tree_key_value_bytes.max(
            size_of::<K>()
                .checked_add(size_of::<V>())
                .ok_or(overflow())?,
        );
        Ok(())
    }
}

fn overflow() -> ProviderError {
    ProviderError::ResourceExhausted("retained metadata extent overflow")
}

fn add(total: &mut usize, value: usize) -> Result<(), ProviderError> {
    *total = total.checked_add(value).ok_or(overflow())?;
    Ok(())
}

pub(crate) trait ObserveMetadata {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError>;
}

impl ObserveMetadata for String {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.string(self.capacity())
    }
}

impl ObserveMetadata for Id {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.string(self.allocated_capacity())
    }
}

impl ObserveMetadata for Bytes {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.vector::<u8>(self.allocation_capacity())
    }
}

impl<T: ObserveMetadata> ObserveMetadata for Vec<T> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.vector::<T>(self.capacity())?;
        for row in self {
            observer.observe(row)?;
        }
        Ok(())
    }
}

impl<T: ObserveMetadata> ObserveMetadata for Option<T> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if let Some(value) = self {
            observer.observe(value)?;
        }
        Ok(())
    }
}

impl<K: ObserveMetadata, V: ObserveMetadata> ObserveMetadata for BTreeMap<K, V> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.tree::<K, V>(self.len())?;
        for (key, value) in self {
            observer.observe(key)?;
            observer.observe(value)?;
        }
        Ok(())
    }
}

impl<T: ObserveMetadata> ObserveMetadata for BTreeSet<T> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.tree::<T, ()>(self.len())?;
        for value in self {
            observer.observe(value)?;
        }
        Ok(())
    }
}

impl ObserveMetadata for Value {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if observer.json_depth >= 64 {
            return Err(ProviderError::ResourceExhausted(
                "retained metadata JSON depth",
            ));
        }
        observer.json_depth += 1;
        let result = match self {
            Self::Null | Self::Bool(_) | Self::Number(_) => Ok(()),
            Self::String(value) => observer.observe(value),
            Self::Array(values) => observer.observe(values),
            Self::Object(values) => {
                observer.tree::<String, Value>(values.len())?;
                for (key, value) in values {
                    observer.observe(key)?;
                    observer.observe(value)?;
                }
                Ok(())
            }
        };
        observer.json_depth -= 1;
        result
    }
}

macro_rules! inline_only {
    ($($ty:ty),* $(,)?) => { $(impl ObserveMetadata for $ty {
        fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> { Ok(()) }
    })* };
}

inline_only!(u8, u16, u32, u64, usize, bool, U64);

// Exhaustive field destructuring makes a new retained field a compile-time gap.
macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => { impl ObserveMetadata for $ty {
        fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
            let Self { $($field),+ } = self;
            $(observer.observe($field)?;)+
            Ok(())
        }
    } };
}

impl<T: ObserveMetadata> ObserveMetadata for crate::envelope::Nullable<T> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.observe(&self.0)
    }
}

impl ObserveMetadata for serde_json::Map<String, Value> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.tree::<String, Value>(self.len())?;
        for (key, value) in self {
            observer.observe(key)?;
            observer.observe(value)?;
        }
        Ok(())
    }
}

inline_only!(crate::envelope::MessageKind, crate::envelope::Method);
fields!(
    crate::envelope::Envelope,
    protocol,
    message,
    session_id,
    incarnation_id,
    node_id,
    execution_owner_id,
    capture_owner_id,
    request_id,
    operation_id,
    sequence,
    method,
    body,
    extensions
);
fields!(crate::client::ClientOriginal, request, identity, response);

fields!(ArtifactIdentity, id, role, content, extensions);
fields!(
    BindingCompatibility,
    schema_version,
    node_id,
    descriptor_hash,
    implementation,
    profile_ref,
    configuration_ref,
    operating_contract,
    execution_owner,
    capture_owner,
    capabilities_ref,
    guarantees_ref,
    qualification_refs,
    extensions
);
fields!(ContentRef, hash, length, media_type);
fields!(
    ExtensionSelection,
    declaration,
    identifier,
    semantic_version,
    schema_digest
);
fields!(
    FacetSelection,
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions
);
fields!(HashRef, algorithm, domain, digest);
fields!(
    ImplementationIdentity,
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions
);
fields!(
    LaneDescriptor,
    id,
    direction,
    payload_schema,
    maximum_payload_bytes,
    maximum_pending_events,
    extensions
);
fields!(
    LiveAuthority,
    schema_version,
    session_id,
    incarnation_id,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    host_receipt,
    extensions
);
fields!(NodeBinding, compatibility, authority, extensions);
fields!(NodeBindingRef, node_id, binding_hash, extensions);
fields!(
    NodeDescriptor,
    schema_version,
    id,
    roles,
    model_ref,
    configuration_ref,
    initialization_ref,
    ports,
    extensions
);
fields!(
    NodeManifest,
    schema_version,
    profile_id,
    roles,
    configuration_schema,
    allowed_combinations_ref,
    port_templates_ref,
    state_formats,
    operation_facets,
    extensions
);
fields!(
    OperatingContract,
    schema_version,
    mode,
    scheduling_role,
    ordering_profile,
    policy_ref,
    resolution_ps,
    phase_ps,
    facets,
    extensions
);
fields!(
    OwnerBinding,
    schema_version,
    owner,
    owner_roles,
    node_bindings,
    ownership_ref,
    extensions
);
fields!(OwnerRef, id, participant_ids, state_domain_ids);
fields!(
    PacketConnectedHostSelection,
    descriptor,
    binding,
    owner,
    prepared_token,
    initial_node
);
fields!(
    PacketControlSelection,
    provider,
    realization,
    realize,
    prepared_token,
    admission,
    transaction,
    gate,
    world,
    admission_receipt
);
fields!(
    PacketNative5CoordinatorInstallation,
    schema,
    participants,
    host,
    template
);
fields!(
    PortDescriptor,
    id,
    lanes,
    interface_id,
    features,
    configuration_ref,
    extensions
);
fields!(
    ProviderManifest,
    schema_version,
    provider_id,
    implementation,
    protocol_versions,
    supported_profiles,
    extensions_supported,
    qualification_refs,
    extensions
);
fields!(
    RealizationManifest,
    schema_version,
    realization_id,
    provider_manifest,
    descriptors,
    bindings,
    owners,
    owner_bindings,
    extensions
);
fields!(
    RealizeRequest,
    realization_id,
    configuration,
    requested_node_ids,
    resource_limits,
    extensions
);
fields!(
    ResourceLimits,
    cpu_budget_ns,
    memory_bytes,
    writable_bytes,
    processes,
    descriptors,
    pending_events,
    content_bytes,
    maximum_operations,
    extensions
);
fields!(SchemaRef, id, version, definition, extensions);
fields!(SemanticVersion, major, minor, patch, prerelease, build);

impl ObserveMetadata for Direction {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Input | Self::Output => Ok(()),
        }
    }
}

impl ObserveMetadata for OperatingMode {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Exact | Self::Quantized => Ok(()),
        }
    }
}

impl ObserveMetadata for SchedulingRole {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Active | Self::EventDriven | Self::Autonomous => Ok(()),
        }
    }
}

fields!(crate::reference_service::InstalledContent, reference, bytes);
fields!(
    crate::handshake::Limits,
    frame_bytes,
    nesting,
    requests,
    journal_entries,
    blob_chunk_bytes
);

impl ObserveMetadata for crate::reference_packet::service::PacketNative5CaptureProfile {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::OriginalArrays6 => Ok(()),
            Self::CompactBytes7 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            }
            | Self::OwnedProtocol11 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            } => {
                observer.observe(native_before_protocol_bytes)?;
                observer.observe(native_after_protocol_bytes)?;
                observer.observe(host_protocol_bytes)
            }
        }
    }
}

impl ObserveMetadata for crate::reference_packet::service::PacketNative5ConfirmationSelection {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::AfterProtocolPoll5 => Ok(()),
        }
    }
}

impl ObserveMetadata for crate::reference_packet::service::PacketNative5AckEmitterSelection {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::CanonicalSdkBlob5 => Ok(()),
        }
    }
}

impl ObserveMetadata for crate::client::CanonicalAckCodecMetadataExtent {
    fn observe_metadata(&self, _observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::CanonicalAck512KiB => Ok(()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn original_metadata_observes_spare_ids_strings_vectors_and_empty_trees() {
        let mut identifier = String::with_capacity(128);
        identifier.push_str("original");
        let identifier = Id::new(identifier).unwrap();
        let mut text = String::with_capacity(96);
        text.push_str("text");
        let mut rows = Vec::with_capacity(7);
        rows.push(text);
        let mut tree = BTreeMap::new();
        let mut key = String::with_capacity(64);
        key.push_str("key");
        tree.insert(key, rows);
        let empty_tree = BTreeSet::<String>::new();
        let mut observer = MetadataObserver::new();

        observer.observe(&identifier).unwrap();
        observer.observe(&tree).unwrap();
        observer.observe(&empty_tree).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.string_capacity_bytes, 128 + 96 + 64);
        assert_eq!(facts.string_banks, 3);
        assert_eq!(facts.vector_capacity_bytes, 7 * size_of::<String>());
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.tree_containers, 2);
        assert_eq!(facts.tree_entries, 1);
        assert_eq!(
            facts.maximum_tree_key_value_bytes,
            size_of::<String>() + size_of::<Vec<String>>()
        );
        assert_eq!(identifier.allocated_capacity(), 128);
        assert_eq!(tree.values().next().unwrap().capacity(), 7);
    }

    #[test]
    fn original_metadata_observes_json_backing_without_serialization() {
        let empty = Value::Array(Vec::with_capacity(11));
        let mut string = String::with_capacity(80);
        string.push_str("retained");
        let value = Value::Array(vec![empty, Value::String(string)]);
        let before = &value as *const Value;
        let mut observer = MetadataObserver::new();

        observer.observe(&value).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.vector_capacity_bytes, 13 * size_of::<Value>());
        assert_eq!(facts.vector_banks, 2);
        assert_eq!(facts.string_capacity_bytes, 80);
        assert_eq!(before, &value as *const Value);
        assert_eq!(value[0].as_array().unwrap().capacity(), 11);
    }

    #[test]
    fn original_metadata_refuses_checked_extent_and_traversal_overflow() {
        let mut total = usize::MAX;
        assert!(add(&mut total, 1).is_err());
        assert_eq!(total, usize::MAX);
        let mut observer = MetadataObserver::new();
        observer.facts.observed_nodes = 131_072;
        assert!(observer.observe(&String::new()).is_err());
        assert_eq!(observer.facts.string_banks, 0);
        assert_eq!(observer.facts.vector_banks, 0);
    }

    #[test]
    fn empty_overaligned_backings_retain_actual_alignment_without_invented_size() {
        #[repr(align(256))]
        struct Aligned;

        let mut records = MetadataRecordBank::reserve(4).unwrap();
        let mut observer = MetadataObserver::recording(&mut records);
        observer.tree::<Aligned, ()>(0).unwrap();
        let empty: [Aligned; 0] = [];
        observer.shared_value(empty.as_slice()).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.maximum_tree_key_value_bytes, 0);
        assert_eq!(facts.maximum_tree_entry_alignment, 256);
        assert_eq!(facts.maximum_shared_value_alignment, 256);
        assert_eq!(facts.shared_value_bytes, 0);
        assert_eq!(facts.tree_containers, 1);
        assert_eq!(facts.shared_backing_views, 1);
        assert_eq!(records.rows()[0].alignment, 256);
        assert_eq!(records.rows()[1].alignment, 256);
    }

    #[test]
    fn capacity_roster_requires_explicit_power_of_two_alignment() {
        use records::ValidatedMetadataRecords;
        for bytes in [
            br#"[["tree",0,0]]"#.as_slice(),
            br#"[["tree",0,0,0]]"#.as_slice(),
            br#"[["shared",0,1,3]]"#.as_slice(),
            br#"[["string",0,1,8]]"#.as_slice(),
        ] {
            assert!(ValidatedMetadataRecords::validate(bytes, 4, 0).is_err());
        }
        let valid = br#"[["tree",0,0,256],["shared",0,1,256]]"#;
        let rows = ValidatedMetadataRecords::validate(valid, 4, 0).unwrap();
        assert_eq!(rows.rows().next().unwrap().unwrap().alignment, 256);
    }
}

impl<T: ObserveMetadata, const N: usize> ObserveMetadata for [T; N] {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        for value in self {
            observer.observe(value)?;
        }
        Ok(())
    }
}

mod complete_source;
pub use complete_source::{
    RetainedCompleteSourceDefinition, RetainedCompleteSourceMetadata,
    observe_retained_native_coordinator, observe_retained_native_launch,
};

mod native_record;
pub use native_record::RetainedPacketNativeRecord;

/// Reports the compiled inline metadata observer state layout.
///
/// This is not a native-stack bound. Compiler call frames, recursive traversal
/// stack, unwind machinery and allocator/tree/control-block storage remain
/// separate terms; no allocation or authority follows from this number.
pub const fn original_metadata_observer_layout_bytes() -> usize {
    std::mem::size_of::<MetadataObserver<'static>>()
}

impl ObserveMetadata for crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self { Self::CanonicalSdkRestoreInputs12 => Ok(()) }
    }
}

mod common_data;
pub use common_data::RetainedCommonProtocolData;

mod capture_data;
pub use capture_data::RetainedCaptureProtocolData;

#[path = "retained_metadata/serialization_storage.rs"]
pub(crate) mod serialization_storage;

pub(crate) mod requested_storage;
pub(crate) use requested_storage::requested_metadata_backing_storage_data;
