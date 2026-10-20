//! Quotes the actual closed immutable installation Clone constructor family.
//!
//! The real template owner authenticates before and after this borrowed walk.
//! Existing declaration backing remains independently priced; this row adds
//! inline Clone returns, owned constructor inputs and typed control windows.
//! No clone, allocation grant, activation or Source18 readiness follows here.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_contract::*;
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, mem::size_of};

struct CloneQuote {
    transient: usize,
    scratch: usize,
    maximum: usize,
}

impl CloneQuote {
    fn add(&mut self, transient: usize, scratch: usize) -> Result<(), RuntimeError> {
        self.transient = self
            .transient
            .checked_add(transient)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.scratch = self
            .scratch
            .checked_add(scratch)
            .ok_or(RuntimeError::ResourceLimit)?;
        if self
            .transient
            .checked_add(self.scratch)
            .ok_or(RuntimeError::ResourceLimit)?
            > self.maximum
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    fn output<T>(&mut self) -> Result<(), RuntimeError> {
        self.add(size_of::<T>(), size_of::<&T>())
    }

    fn sequence<T: 'static>(&mut self, len: usize, trivial: bool) -> Result<(), RuntimeError> {
        let (transient, scratch) = NodeRuntime::capture_installation_sequence_clone_storage_data::<
            T,
        >(len, trivial, self.maximum)?;
        self.add(transient, scratch)
    }

    fn map(&mut self, len: usize) -> Result<(), RuntimeError> {
        let (transient, scratch) =
            NodeRuntime::capture_installation_map_clone_storage_data(len, self.maximum)?;
        self.add(transient, scratch)
    }
}

// This private trait is implemented only for the reached DTO and container
// closure below. It supplies no arbitrary user Clone implementation.
trait PortableClone: Sized + 'static {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError>;
}

macro_rules! record_clone {
    ($record:ty, $($field:ident),+ $(,)?) => {
        impl PortableClone for $record {
            fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
                quote.output::<Self>()?;
                let Self { $($field),+ } = self;
                $($field.clone_storage(quote)?;)+
                Ok(())
            }
        }
    };
}

macro_rules! copy_clone {
    ($($record:ty),+ $(,)?) => {$(
        impl PortableClone for $record {
            fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
                quote.output::<Self>()
            }
        }
    )+};
}

// Derived Copy Clone returns *self. It does not recursively call Clone on
// enum/newtype fields; no invented inner leaf Clone outputs are charged.
copy_clone!(
    u16,
    U64,
    bool,
    Direction,
    OperatingMode,
    SchedulingRole,
    Repeatability,
    CaptureScope,
    Continuation
);

impl PortableClone for Id {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.output::<Self>()?;
        // Id's private single String field is borrowed by its derived Clone.
        quote.add(size_of::<String>(), size_of::<&String>())?;
        quote.sequence::<u8>(self.as_str().len(), true)
    }
}

impl PortableClone for String {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.output::<Self>()?;
        quote.sequence::<u8>(self.len(), true)
    }
}

impl<T: PortableClone> PortableClone for Option<T> {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.output::<Self>()?;
        if let Some(value) = self {
            // Option::clone keeps this actual Some pattern loan separate from
            // the nested T::clone receiver supplied by the child producer.
            quote.add(0, size_of::<&T>())?;
            value.clone_storage(quote)?;
        }
        Ok(())
    }
}

impl<T: PortableClone> PortableClone for Vec<T> {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.sequence::<T>(self.len(), false)?;
        for value in self {
            value.clone_storage(quote)?;
        }
        Ok(())
    }
}

// FacetKind derives Clone+Copy and the pinned compiler automatically provides
// TrivialClone (core/clone.rs253-258). Its Vec clone copies bytes, with no
// per-element Clone call or fictitious per-element Clone return.
impl PortableClone for Vec<FacetKind> {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.sequence::<FacetKind>(self.len(), true)
    }
}

impl PortableClone for BTreeMap<String, Value> {
    fn clone_storage(&self, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
        quote.map(self.len())?;
        for (key, value) in self {
            key.clone_storage(quote)?;
            json_clone_storage(value, quote)?;
        }
        Ok(())
    }
}

// The quote's real fixed array is declared before traversal and included in
// caller prework. The original borrowed metadata observer already rejects JSON
// depth>64; this DFS requires exactly one iterator/value slot per JSON level.
// It therefore preserves every accepted width and all depth<=64 branches.
enum JsonFrame<'a> {
    Value(&'a Value),
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Iter<'a>),
}

fn push_json_frame<'a>(
    stack: &mut [Option<JsonFrame<'a>>; 64],
    length: &mut usize,
    frame: JsonFrame<'a>,
) -> Result<(), RuntimeError> {
    let target = stack.get_mut(*length).ok_or(RuntimeError::ResourceLimit)?;
    *target = Some(frame);
    *length = length.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

fn json_clone_storage(root: &Value, quote: &mut CloneQuote) -> Result<(), RuntimeError> {
    let mut stack: [Option<JsonFrame<'_>>; 64] = [const { None }; 64];
    let mut length = 0usize;
    push_json_frame(&mut stack, &mut length, JsonFrame::Value(root))?;
    while length != 0 {
        length -= 1;
        let frame = stack[length].take().ok_or(RuntimeError::InvalidReceipt)?;
        match frame {
            JsonFrame::Value(value) => {
                quote.output::<Value>()?;
                match value {
                    Value::Null => {}
                    Value::Bool(value) => {
                        quote.add(0, size_of::<&bool>())?; // derived enum pattern binding
                        value.clone_storage(quote)?;
                    }
                    Value::Number(_) => {
                        quote.add(0, size_of::<&Number>())?; // derived enum pattern binding
                        quote.output::<Number>()?;
                        // Number contains only private N. The enclosing Number
                        // size bounds that real field's Copy Clone return.
                        quote.add(size_of::<Number>(), size_of::<&Number>())?;
                    }
                    Value::String(value) => {
                        quote.add(0, size_of::<&String>())?; // derived enum pattern binding
                        value.clone_storage(quote)?;
                    }
                    Value::Array(values) => {
                        quote.add(0, size_of::<&Vec<Value>>())?; // derived enum pattern binding
                        quote.sequence::<Value>(values.len(), false)?;
                        push_json_frame(&mut stack, &mut length, JsonFrame::Array(values.iter()))?;
                    }
                    Value::Object(values) => {
                        quote.add(0, size_of::<&Map<String, Value>>())?; // derived enum pattern binding
                        quote.output::<Map<String, Value>>()?;
                        quote.map(values.len())?;
                        push_json_frame(&mut stack, &mut length, JsonFrame::Object(values.iter()))?;
                    }
                }
            }
            JsonFrame::Array(mut values) => {
                if let Some(value) = values.next() {
                    push_json_frame(&mut stack, &mut length, JsonFrame::Array(values))?;
                    push_json_frame(&mut stack, &mut length, JsonFrame::Value(value))?;
                }
            }
            JsonFrame::Object(mut values) => {
                if let Some((key, value)) = values.next() {
                    key.clone_storage(quote)?;
                    push_json_frame(&mut stack, &mut length, JsonFrame::Object(values))?;
                    push_json_frame(&mut stack, &mut length, JsonFrame::Value(value))?;
                }
            }
        }
    }
    Ok(())
}

record_clone!(
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

record_clone!(
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

record_clone!(
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

record_clone!(NodeBinding, compatibility, authority, extensions);

record_clone!(
    CapabilityProfile,
    schema_version,
    facets,
    devices_ref,
    requirements_ref,
    extensions
);

record_clone!(
    FacetSelection,
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions
);

record_clone!(
    GuaranteeProfile,
    schema_version,
    repeatability,
    capture_scope,
    continuation,
    durable_restart,
    isolated_fork,
    conditional_replay,
    limitations_ref,
    extensions
);

record_clone!(
    OwnerBinding,
    schema_version,
    owner,
    owner_roles,
    node_bindings,
    ownership_ref,
    extensions
);

record_clone!(
    RealizeRequest,
    realization_id,
    configuration,
    requested_node_ids,
    resource_limits,
    extensions
);

record_clone!(
    ImplementationIdentity,
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions
);

record_clone!(ArtifactIdentity, id, role, content, extensions);

record_clone!(
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

record_clone!(
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

record_clone!(OwnerRef, id, participant_ids, state_domain_ids);

record_clone!(
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

record_clone!(NodeBindingRef, node_id, binding_hash, extensions);

record_clone!(
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

record_clone!(SchemaRef, id, version, definition, extensions);

record_clone!(
    PortDescriptor,
    id,
    lanes,
    interface_id,
    features,
    configuration_ref,
    extensions
);

record_clone!(
    LaneDescriptor,
    id,
    direction,
    payload_schema,
    maximum_payload_bytes,
    maximum_pending_events,
    extensions
);

record_clone!(ContentRef, hash, length, media_type);

record_clone!(HashRef, algorithm, domain, digest);

impl CnpSemanticInstallation {
    /// Defines inline Clone construction/control storage for this actual owner.
    ///
    /// The outer installation return and all partial/new backing remain priced
    /// by the unchanged template declaration row. This adds reached inner
    /// constructors only, without cloning or retaining another authority.
    ///
    /// # Errors
    /// Refuses unsupported locked geometry, checked overflow or row exhaustion.
    pub(in crate::node_adapters::cnp::semantic) fn complete_template_clone_construction_data(
        &self,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        // The locked default/std serde_json representation has Copy private N
        // and a BTreeMap-backed object. A feature/toolchain upgrade must supply
        // its actual changed constructor closure instead of reusing this row.
        if size_of::<Number>() != 16
            || size_of::<Map<String, Value>>() != size_of::<BTreeMap<String, Value>>()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let Self {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            facets,
            receipt_schema,
            maximum_operations: _,
            maximum_result_bytes: _,
            maximum_authorization_bytes: _,
            maximum_semantic_bytes: _,
        } = self;
        let mut quote = CloneQuote {
            transient: 0,
            scratch: 0,
            maximum,
        };
        provider.clone_storage(&mut quote)?;
        profile.clone_storage(&mut quote)?;
        descriptor.clone_storage(&mut quote)?;
        binding.clone_storage(&mut quote)?;
        capabilities.clone_storage(&mut quote)?;
        exact_facet.clone_storage(&mut quote)?;
        guarantees.clone_storage(&mut quote)?;
        owner.clone_storage(&mut quote)?;
        realize.clone_storage(&mut quote)?;
        admission.clone_storage(&mut quote)?;
        transaction.clone_storage(&mut quote)?;
        gate.clone_storage(&mut quote)?;
        admission_receipt.clone_storage(&mut quote)?;
        world_binding_hash.clone_storage(&mut quote)?;
        facets.clone_storage(&mut quote)?;
        receipt_schema.clone_storage(&mut quote)?;
        // The actual helper destructures all20 fields, including4Copy limits.
        quote.add(0, size_of::<&Self>() + size_of::<[usize; 20]>())?;
        Ok((quote.transient, quote.scratch))
    }
}

fn record_counter<T>(fields: usize) -> usize {
    size_of::<&T>() + size_of::<&mut CloneQuote>() + fields + size_of::<Result<(), RuntimeError>>()
}

fn container_counter<T: 'static>() -> usize {
    size_of::<&Vec<T>>()
        + size_of::<std::slice::Iter<'static, T>>()
        + size_of::<Option<&T>>()
        + size_of::<&T>()
        + size_of::<&mut CloneQuote>()
        + size_of::<Result<(), RuntimeError>>()
}

impl CnpSemanticInstallation {
    /// Names fixed quote-walk controls before borrowing actual declaration data.
    ///
    /// These real field loans, result/iterator windows and the declared JSON
    /// stack are separate from the future Clone's dynamic typed windows.
    pub(in crate::node_adapters::cnp::semantic) fn complete_template_clone_counter_scratch_data()
    -> usize {
        let mut bytes = NodeRuntime::capture_installation_clone_counter_scratch_data()
            + size_of::<CloneQuote>()
            + size_of::<&mut CloneQuote>() // observer method input
            + size_of::<&mut CloneQuote>() // nested output/add borrow
            + size_of::<&Self>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>() // CloneQuote::add return
            + size_of::<Result<(), RuntimeError>>() // output/sequence/map return
            + size_of::<Result<(), RuntimeError>>() // closed leaf visitor return
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<[usize; 3]>() // add's two inputs and checked total
            + size_of::<[usize; 2]>() // counter accumulator and record_counter fields argument
            + size_of::<bool>()
            + size_of::<[Option<JsonFrame<'static>>; 64]>() // actual initializer
            + size_of::<[Option<JsonFrame<'static>>; 64]>() // actual stack local
            + size_of::<&mut [Option<JsonFrame<'static>>; 64]>()
            + size_of::<&mut usize>()
            + size_of::<usize>() // actual stack length
            + size_of::<JsonFrame<'static>>() // moved frame/pattern
            + size_of::<JsonFrame<'static>>() // push's owned frame input
            + size_of::<Option<JsonFrame<'static>>>()
            + size_of::<Result<JsonFrame<'static>, RuntimeError>>()
            + size_of::<Option<&mut Option<JsonFrame<'static>>>>()
            + size_of::<Result<&mut Option<JsonFrame<'static>>, RuntimeError>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<Option<&Value>>()
            + size_of::<Option<(&String, &Value)>>()
            + size_of::<(&String, &Value)>()
            + size_of::<&Value>()
            + size_of::<&bool>() // quote's JSON Bool pattern binding
            + size_of::<&String>() // quote's JSON String pattern binding
            + size_of::<&Vec<Value>>() // quote's JSON Array pattern binding
            + size_of::<&Id>() // quote's Option<Id> Some binding
            + size_of::<&U64>() // quote's Option<U64> Some binding
            + size_of::<&Map<String, Value>>()
            + size_of::<&BTreeMap<String, Value>>()
            + size_of::<&String>()
            + size_of::<&Id>()
            + size_of::<&Option<Id>>()
            + size_of::<&Option<U64>>()
            + size_of::<&str>() // Id::as_str's actual returned view
            + size_of::<&bool>()
            + size_of::<&u16>()
            + size_of::<&U64>()
            + size_of::<&Direction>()
            + size_of::<&OperatingMode>()
            + size_of::<&SchedulingRole>()
            + size_of::<&Repeatability>()
            + size_of::<&CaptureScope>()
            + size_of::<&Continuation>();
        bytes += record_counter::<ProviderManifest>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&ImplementationIdentity>()
                + size_of::<&IdSet>()
                + size_of::<&Vec<NodeManifest>>()
                + size_of::<&IdSet>()
                + size_of::<&Vec<ContentRef>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<NodeManifest>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&IdSet>()
                + size_of::<&SchemaRef>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&Vec<SchemaRef>>()
                + size_of::<&Vec<FacetSelection>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<NodeDescriptor>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&IdSet>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&Vec<PortDescriptor>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<NodeBinding>(
            size_of::<&BindingCompatibility>()
                + size_of::<&LiveAuthority>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<CapabilityProfile>(
            size_of::<&Version>()
                + size_of::<&Vec<FacetSelection>>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<FacetSelection>(
            size_of::<&Id>()
                + size_of::<&Version>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<GuaranteeProfile>(
            size_of::<&Version>()
                + size_of::<&Repeatability>()
                + size_of::<&CaptureScope>()
                + size_of::<&Continuation>()
                + size_of::<&bool>()
                + size_of::<&bool>()
                + size_of::<&bool>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<OwnerBinding>(
            size_of::<&Version>()
                + size_of::<&OwnerRef>()
                + size_of::<&IdSet>()
                + size_of::<&Vec<NodeBindingRef>>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<RealizeRequest>(
            size_of::<&Id>()
                + size_of::<&ContentRef>()
                + size_of::<&IdSet>()
                + size_of::<&ResourceLimits>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<ImplementationIdentity>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&Vec<ArtifactIdentity>>()
                + size_of::<&Vec<ContentRef>>()
                + size_of::<&Vec<SchemaRef>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<ArtifactIdentity>(
            size_of::<&Id>()
                + size_of::<&Id>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<BindingCompatibility>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&HashRef>()
                + size_of::<&ImplementationIdentity>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&OperatingContract>()
                + size_of::<&OwnerRef>()
                + size_of::<&OwnerRef>()
                + size_of::<&ContentRef>()
                + size_of::<&ContentRef>()
                + size_of::<&Vec<ContentRef>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<OperatingContract>(
            size_of::<&Version>()
                + size_of::<&OperatingMode>()
                + size_of::<&SchedulingRole>()
                + size_of::<&String>()
                + size_of::<&ContentRef>()
                + size_of::<&Option<U64>>()
                + size_of::<&Option<U64>>()
                + size_of::<&Vec<FacetSelection>>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<OwnerRef>(
            size_of::<&Id>() + size_of::<&IdSet>() + size_of::<&IdSet>(),
        );
        bytes += record_counter::<LiveAuthority>(
            size_of::<&Version>()
                + size_of::<&Id>()
                + size_of::<&Id>()
                + size_of::<&Id>()
                + size_of::<&Option<Id>>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&Id>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<NodeBindingRef>(
            size_of::<&Id>() + size_of::<&HashRef>() + size_of::<&Extensions>(),
        );
        bytes += record_counter::<ResourceLimits>(
            size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<SchemaRef>(
            size_of::<&Id>()
                + size_of::<&Version>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<PortDescriptor>(
            size_of::<&Id>()
                + size_of::<&Vec<LaneDescriptor>>()
                + size_of::<&Id>()
                + size_of::<&IdSet>()
                + size_of::<&ContentRef>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<LaneDescriptor>(
            size_of::<&Id>()
                + size_of::<&Direction>()
                + size_of::<&SchemaRef>()
                + size_of::<&U64>()
                + size_of::<&U64>()
                + size_of::<&Extensions>(),
        );
        bytes += record_counter::<ContentRef>(
            size_of::<&HashRef>() + size_of::<&U64>() + size_of::<&String>(),
        );
        bytes += record_counter::<HashRef>(
            size_of::<&String>() + size_of::<&String>() + size_of::<&String>(),
        );
        bytes += size_of::<&ProviderManifest>()
            + size_of::<&NodeManifest>()
            + size_of::<&NodeDescriptor>()
            + size_of::<&NodeBinding>()
            + size_of::<&CapabilityProfile>()
            + size_of::<&FacetSelection>()
            + size_of::<&GuaranteeProfile>()
            + size_of::<&OwnerBinding>()
            + size_of::<&RealizeRequest>()
            + size_of::<&Id>()
            + size_of::<&Id>()
            + size_of::<&Id>()
            + size_of::<&ContentRef>()
            + size_of::<&HashRef>()
            + size_of::<&Vec<FacetKind>>()
            + size_of::<&SchemaRef>();
        bytes += container_counter::<Id>();
        bytes += container_counter::<NodeManifest>();
        bytes += container_counter::<SchemaRef>();
        bytes += container_counter::<FacetSelection>();
        bytes += container_counter::<ContentRef>();
        bytes += container_counter::<ArtifactIdentity>();
        bytes += container_counter::<PortDescriptor>();
        bytes += container_counter::<LaneDescriptor>();
        bytes += container_counter::<NodeBindingRef>();
        bytes += size_of::<&Vec<FacetKind>>()
            + size_of::<&mut CloneQuote>()
            + size_of::<Result<(), RuntimeError>>();
        bytes
    }
}

#[path = "clone_storage/private_birth.rs"]
mod private_birth;

pub(in crate::node_adapters::cnp::semantic) use private_birth::{
    private_birth_clone_construction_data, private_birth_clone_counter_scratch_data,
};
