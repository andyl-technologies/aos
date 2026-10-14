//! Observes actual retained container capacities without copying protocol state.
//!
//! This source-private walker visits typed originals. It reports requested String,
//! Vec, Box and shared backing extents, plus tree populations and entry layouts.
//! These facts are not allocator-rounded heap measurements: callers separately
//! admit tree node/control-block layouts, alignment, traversal stack and native
//! peak. Shared backing is conservatively counted on every retained view; no
//! serialized identity or deduplication authority is inferred.

use crate::ProviderError;
use crate::bodies::RealizeRequest;
use crate::reference_packet::{
    control::PacketControlSelection,
    coordinator::{PacketConnectedHostSelection, PacketNative5CoordinatorInstallation},
};
use crucible_node_contract::*;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
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
    /// Counts visited fields and initialized rows for bounded traversal work.
    pub observed_nodes: usize,
}

pub(crate) struct MetadataObserver {
    facts: RetainedProtocolMetadataFacts,
    json_depth: usize,
}

impl MetadataObserver {
    pub(crate) fn new() -> Self {
        Self {
            facts: RetainedProtocolMetadataFacts::default(),
            json_depth: 0,
        }
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

    pub(crate) fn shared_value(&mut self, bytes: usize) -> Result<(), ProviderError> {
        add(&mut self.facts.shared_value_bytes, bytes)?;
        add(&mut self.facts.shared_backing_views, 1)
    }

    pub(crate) fn boxed_value(&mut self, bytes: usize) -> Result<(), ProviderError> {
        add(&mut self.facts.boxed_value_bytes, bytes)
    }

    fn string(&mut self, capacity: usize) -> Result<(), ProviderError> {
        add(&mut self.facts.string_capacity_bytes, capacity)?;
        add(&mut self.facts.string_banks, 1)
    }

    fn vector<T>(&mut self, capacity: usize) -> Result<(), ProviderError> {
        let bytes = capacity.checked_mul(size_of::<T>()).ok_or(overflow())?;
        add(&mut self.facts.vector_capacity_bytes, bytes)?;
        add(&mut self.facts.vector_banks, 1)
    }

    fn tree<K, V>(&mut self, entries: usize) -> Result<(), ProviderError> {
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
            } => {
                observer.observe(native_before_protocol_bytes)?;
                observer.observe(native_after_protocol_bytes)?;
                observer.observe(host_protocol_bytes)
            }
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
}
