//! Prices only actual typed coordinator Vec elements before deserialization.
//!
//! Every opaque Value, extension tree, key and owned string is independently
//! covered by the parent's complete raw Value row. These static field tables
//! add only the real Vec<T> requests: nested records are inline in their actual
//! root or vector element. This walk allocates no DTO, DOM or authority owner.

use super::*;
use crate::bodies::RealizeRequest;
use serde_json::Value;

const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy)]
enum Record {
    Coordinator,
    Host,
    Selection,
    Provider,
    Implementation,
    Artifact,
    Profile,
    Facet,
    Realization,
    Descriptor,
    Port,
    Lane,
    Binding,
    Compatibility,
    Authority,
    Owner,
    OwnerBinding,
    BindingRef,
    Operating,
    Realize,
    Limits,
    Content,
    Hash,
    Schema,
    Id,
}

#[derive(Clone, Copy)]
enum Kind {
    Atom,
    Opaque,
    Extensions,
    Inline(Record),
    Vector(Record),
}

struct Field {
    name: &'static str,
    kind: Kind,
}

macro_rules! field {
    ($name:literal, $kind:expr) => {
        Field {
            name: $name,
            kind: $kind,
        }
    };
}

fn fields(record: Record) -> &'static [Field] {
    match record {
        Record::Coordinator => &[
            field!("schema", Kind::Atom),
            field!("participants", Kind::Vector(Record::Selection)),
            field!("host", Kind::Inline(Record::Host)),
            field!("template", Kind::Opaque),
        ],
        Record::Host => &[
            field!("descriptor", Kind::Inline(Record::Descriptor)),
            field!("binding", Kind::Inline(Record::Binding)),
            field!("owner", Kind::Inline(Record::OwnerBinding)),
            field!("prepared_token", Kind::Atom),
            field!("initial_node", Kind::Opaque),
        ],
        Record::Selection => &[
            field!("provider", Kind::Inline(Record::Provider)),
            field!("realization", Kind::Inline(Record::Realization)),
            field!("realize", Kind::Inline(Record::Realize)),
            field!("prepared_token", Kind::Atom),
            field!("admission", Kind::Atom),
            field!("transaction", Kind::Atom),
            field!("gate", Kind::Atom),
            field!("world", Kind::Inline(Record::Hash)),
            field!("admission_receipt", Kind::Inline(Record::Content)),
        ],
        Record::Provider => &[
            field!("schema_version", Kind::Atom),
            field!("provider_id", Kind::Atom),
            field!("implementation", Kind::Inline(Record::Implementation)),
            field!("protocol_versions", Kind::Vector(Record::Id)),
            field!("supported_profiles", Kind::Vector(Record::Profile)),
            field!("extensions_supported", Kind::Vector(Record::Id)),
            field!("qualification_refs", Kind::Vector(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Implementation => &[
            field!("schema_version", Kind::Atom),
            field!("implementation_id", Kind::Atom),
            field!("artifacts", Kind::Vector(Record::Artifact)),
            field!("model_definitions", Kind::Vector(Record::Content)),
            field!("formats", Kind::Vector(Record::Schema)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Artifact => &[
            field!("id", Kind::Atom),
            field!("role", Kind::Atom),
            field!("content", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Profile => &[
            field!("schema_version", Kind::Atom),
            field!("profile_id", Kind::Atom),
            field!("roles", Kind::Vector(Record::Id)),
            field!("configuration_schema", Kind::Inline(Record::Schema)),
            field!("allowed_combinations_ref", Kind::Inline(Record::Content)),
            field!("port_templates_ref", Kind::Inline(Record::Content)),
            field!("state_formats", Kind::Vector(Record::Schema)),
            field!("operation_facets", Kind::Vector(Record::Facet)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Facet => &[
            field!("id", Kind::Atom),
            field!("version", Kind::Atom),
            field!("configuration_ref", Kind::Inline(Record::Content)),
            field!("guarantees_ref", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Realization => &[
            field!("schema_version", Kind::Atom),
            field!("realization_id", Kind::Atom),
            field!("provider_manifest", Kind::Inline(Record::Content)),
            field!("descriptors", Kind::Vector(Record::Descriptor)),
            field!("bindings", Kind::Vector(Record::Binding)),
            field!("owners", Kind::Vector(Record::Owner)),
            field!("owner_bindings", Kind::Vector(Record::OwnerBinding)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Descriptor => &[
            field!("schema_version", Kind::Atom),
            field!("id", Kind::Atom),
            field!("roles", Kind::Vector(Record::Id)),
            field!("model_ref", Kind::Inline(Record::Content)),
            field!("configuration_ref", Kind::Inline(Record::Content)),
            field!("initialization_ref", Kind::Inline(Record::Content)),
            field!("ports", Kind::Vector(Record::Port)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Port => &[
            field!("id", Kind::Atom),
            field!("lanes", Kind::Vector(Record::Lane)),
            field!("interface_id", Kind::Atom),
            field!("features", Kind::Vector(Record::Id)),
            field!("configuration_ref", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Lane => &[
            field!("id", Kind::Atom),
            field!("direction", Kind::Atom),
            field!("payload_schema", Kind::Inline(Record::Schema)),
            field!("maximum_payload_bytes", Kind::Atom),
            field!("maximum_pending_events", Kind::Atom),
            field!("extensions", Kind::Extensions),
        ],
        Record::Binding => &[
            field!("compatibility", Kind::Inline(Record::Compatibility)),
            field!("authority", Kind::Inline(Record::Authority)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Compatibility => &[
            field!("schema_version", Kind::Atom),
            field!("node_id", Kind::Atom),
            field!("descriptor_hash", Kind::Inline(Record::Hash)),
            field!("implementation", Kind::Inline(Record::Implementation)),
            field!("profile_ref", Kind::Inline(Record::Content)),
            field!("configuration_ref", Kind::Inline(Record::Content)),
            field!("operating_contract", Kind::Inline(Record::Operating)),
            field!("execution_owner", Kind::Inline(Record::Owner)),
            field!("capture_owner", Kind::Inline(Record::Owner)),
            field!("capabilities_ref", Kind::Inline(Record::Content)),
            field!("guarantees_ref", Kind::Inline(Record::Content)),
            field!("qualification_refs", Kind::Vector(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Authority => &[
            field!("schema_version", Kind::Atom),
            field!("session_id", Kind::Atom),
            field!("incarnation_id", Kind::Atom),
            field!("realization_id", Kind::Atom),
            field!("activation_id", Kind::Atom),
            field!("world_generation", Kind::Atom),
            field!("owner_generation", Kind::Atom),
            field!("input_epoch", Kind::Atom),
            field!("host_receipt", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Owner => &[
            field!("id", Kind::Atom),
            field!("participant_ids", Kind::Vector(Record::Id)),
            field!("state_domain_ids", Kind::Vector(Record::Id)),
        ],
        Record::OwnerBinding => &[
            field!("schema_version", Kind::Atom),
            field!("owner", Kind::Inline(Record::Owner)),
            field!("owner_roles", Kind::Vector(Record::Id)),
            field!("node_bindings", Kind::Vector(Record::BindingRef)),
            field!("ownership_ref", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::BindingRef => &[
            field!("node_id", Kind::Atom),
            field!("binding_hash", Kind::Inline(Record::Hash)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Operating => &[
            field!("schema_version", Kind::Atom),
            field!("mode", Kind::Atom),
            field!("scheduling_role", Kind::Atom),
            field!("ordering_profile", Kind::Atom),
            field!("policy_ref", Kind::Inline(Record::Content)),
            field!("resolution_ps", Kind::Atom),
            field!("phase_ps", Kind::Atom),
            field!("facets", Kind::Vector(Record::Facet)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Realize => &[
            field!("realization_id", Kind::Atom),
            field!("configuration", Kind::Inline(Record::Content)),
            field!("requested_node_ids", Kind::Vector(Record::Id)),
            field!("resource_limits", Kind::Inline(Record::Limits)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Limits => &[
            field!("cpu_budget_ns", Kind::Atom),
            field!("memory_bytes", Kind::Atom),
            field!("writable_bytes", Kind::Atom),
            field!("processes", Kind::Atom),
            field!("descriptors", Kind::Atom),
            field!("pending_events", Kind::Atom),
            field!("content_bytes", Kind::Atom),
            field!("maximum_operations", Kind::Atom),
            field!("extensions", Kind::Extensions),
        ],
        Record::Content => &[
            field!("hash", Kind::Inline(Record::Hash)),
            field!("length", Kind::Atom),
            field!("media_type", Kind::Atom),
        ],
        Record::Hash => &[
            field!("algorithm", Kind::Atom),
            field!("domain", Kind::Atom),
            field!("digest", Kind::Atom),
        ],
        Record::Schema => &[
            field!("id", Kind::Atom),
            field!("version", Kind::Atom),
            field!("definition", Kind::Inline(Record::Content)),
            field!("extensions", Kind::Extensions),
        ],
        Record::Id => &[],
    }
}

fn element_size(record: Record) -> usize {
    match record {
        Record::Coordinator => size_of::<PacketNative5CoordinatorInstallation>(),
        Record::Host => size_of::<PacketConnectedHostSelection>(),
        Record::Selection => size_of::<PacketControlSelection>(),
        Record::Provider => size_of::<ProviderManifest>(),
        Record::Implementation => size_of::<ImplementationIdentity>(),
        Record::Artifact => size_of::<ArtifactIdentity>(),
        Record::Profile => size_of::<NodeManifest>(),
        Record::Facet => size_of::<FacetSelection>(),
        Record::Realization => size_of::<RealizationManifest>(),
        Record::Descriptor => size_of::<NodeDescriptor>(),
        Record::Port => size_of::<PortDescriptor>(),
        Record::Lane => size_of::<LaneDescriptor>(),
        Record::Binding => size_of::<NodeBinding>(),
        Record::Compatibility => size_of::<BindingCompatibility>(),
        Record::Authority => size_of::<LiveAuthority>(),
        Record::Owner => size_of::<OwnerRef>(),
        Record::OwnerBinding => size_of::<OwnerBinding>(),
        Record::BindingRef => size_of::<NodeBindingRef>(),
        Record::Operating => size_of::<OperatingContract>(),
        Record::Realize => size_of::<crate::bodies::RealizeRequest>(),
        Record::Limits => size_of::<ResourceLimits>(),
        Record::Content => size_of::<ContentRef>(),
        Record::Hash => size_of::<HashRef>(),
        Record::Schema => size_of::<SchemaRef>(),
        Record::Id => size_of::<Id>(),
    }
}

fn vector_requested(count: usize, element: usize, maximum: usize) -> Result<usize, ProviderError> {
    // The existing selected bound covers exact-size owned-Value iteration,
    // cautious serde reservations and geometric Vec growth, including an empty
    // array's independent minimum bank. This changes the element, not the cap.
    count
        .checked_add(1)
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_mul(element))
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(refused)
}

fn vector(
    bytes: &[u8],
    record: Record,
    depth: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut items = Fields::array(bytes)?;
    let mut count = 0usize;
    let mut nested = 0usize;
    while let Some(item) = items.next()? {
        count = count.checked_add(1).ok_or_else(refused)?;
        nested = sum(&[nested, walk(item, record, depth + 1, maximum)?], maximum)?;
    }
    items.finish()?;
    sum(
        &[
            nested,
            vector_requested(count, element_size(record), maximum)?,
        ],
        maximum,
    )
}

fn walk(
    bytes: &[u8],
    record: Record,
    depth: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    if depth >= MAX_DEPTH {
        return Err(refused());
    }
    if matches!(record, Record::Id) {
        if bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
            return Err(refused());
        }
        return Ok(0);
    }
    let roster = fields(record);
    if roster.len() >= u64::BITS as usize {
        return Err(refused());
    }
    let mut object = Fields::object(bytes)?;
    let mut seen = 0u64;
    let mut total = 0usize;
    while let Some((key, value)) = object.pair()? {
        let name = plain_string(key)?;
        let index = roster
            .iter()
            .position(|field| field.name == name)
            .ok_or_else(refused)?;
        let bit = 1u64.checked_shl(index as u32).ok_or_else(refused)?;
        if seen & bit != 0 {
            return Err(refused());
        }
        seen |= bit;
        let nested = match roster[index].kind {
            Kind::Atom => {
                if value
                    .first()
                    .is_none_or(|byte| matches!(*byte, b'{' | b'['))
                {
                    return Err(refused());
                }
                0
            }
            Kind::Opaque => 0,
            Kind::Extensions => {
                if value.first() != Some(&b'{') || value.last() != Some(&b'}') {
                    return Err(refused());
                }
                0
            }
            Kind::Inline(child) => walk(value, child, depth + 1, maximum)?,
            Kind::Vector(child) => vector(value, child, depth, maximum)?,
        };
        total = sum(&[total, nested], maximum)?;
    }
    object.finish()?;
    if seen != (1u64 << roster.len()) - 1 {
        return Err(refused());
    }
    Ok(total)
}

pub(super) fn arrays(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    walk(bytes, Record::Coordinator, 0, maximum)
}

pub(super) fn counter_scratch_data() -> usize {
    // Static tables have promoted static storage. Each bounded recursive record
    // and vector view remains explicit; compiler/serde call frames stay separate.
    type RecordLocals<'a> = (
        Fields<'a>,
        &'static [Field],
        u64,
        u64,
        [usize; 5],
        Record,
        Kind,
        Option<(&'a [u8], &'a [u8])>,
        [&'a [u8]; 3],
        &'a str,
    );
    type VectorLocals<'a> = (
        Fields<'a>,
        [usize; 5],
        Record,
        Option<&'a [u8]>,
        [&'a [u8]; 2],
    );
    MAX_DEPTH * (size_of::<RecordLocals<'static>>() + size_of::<VectorLocals<'static>>()
        + size_of::<Result<usize, ProviderError>>())
        + size_of::<[u8; 128]>() // Fields::span's returning borrowed-token scan
        + size_of::<[usize; 4]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
}

// Exhaustive field and type patterns keep the static shape roster tied to
// every actual serde DTO. These unnamed constants construct no runtime owner.
const _: fn(&PacketNative5CoordinatorInstallation) = |value| {
    let PacketNative5CoordinatorInstallation {
        schema,
        participants,
        host,
        template,
    } = value;
    let _: &String = schema;
    let _: &Vec<PacketControlSelection> = participants;
    let _: &PacketConnectedHostSelection = host;
    let _: &Value = template;
};

const _: fn(&PacketConnectedHostSelection) = |value| {
    let PacketConnectedHostSelection {
        descriptor,
        binding,
        owner,
        prepared_token,
        initial_node,
    } = value;
    let _: &NodeDescriptor = descriptor;
    let _: &NodeBinding = binding;
    let _: &OwnerBinding = owner;
    let _: &Id = prepared_token;
    let _: &Value = initial_node;
};

const _: fn(&PacketControlSelection) = |value| {
    let PacketControlSelection {
        provider,
        realization,
        realize,
        prepared_token,
        admission,
        transaction,
        gate,
        world,
        admission_receipt,
    } = value;
    let _: &ProviderManifest = provider;
    let _: &RealizationManifest = realization;
    let _: &RealizeRequest = realize;
    let _: &Id = prepared_token;
    let _: &Id = admission;
    let _: &Id = transaction;
    let _: &Id = gate;
    let _: &HashRef = world;
    let _: &ContentRef = admission_receipt;
};

const _: fn(&ProviderManifest) = |value| {
    let ProviderManifest {
        schema_version,
        provider_id,
        implementation,
        protocol_versions,
        supported_profiles,
        extensions_supported,
        qualification_refs,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = provider_id;
    let _: &ImplementationIdentity = implementation;
    let _: &IdSet = protocol_versions;
    let _: &Vec<NodeManifest> = supported_profiles;
    let _: &IdSet = extensions_supported;
    let _: &Vec<ContentRef> = qualification_refs;
    let _: &Extensions = extensions;
};

const _: fn(&ImplementationIdentity) = |value| {
    let ImplementationIdentity {
        schema_version,
        implementation_id,
        artifacts,
        model_definitions,
        formats,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = implementation_id;
    let _: &Vec<ArtifactIdentity> = artifacts;
    let _: &Vec<ContentRef> = model_definitions;
    let _: &Vec<SchemaRef> = formats;
    let _: &Extensions = extensions;
};

const _: fn(&ArtifactIdentity) = |value| {
    let ArtifactIdentity {
        id,
        role,
        content,
        extensions,
    } = value;
    let _: &Id = id;
    let _: &Id = role;
    let _: &ContentRef = content;
    let _: &Extensions = extensions;
};

const _: fn(&NodeManifest) = |value| {
    let NodeManifest {
        schema_version,
        profile_id,
        roles,
        configuration_schema,
        allowed_combinations_ref,
        port_templates_ref,
        state_formats,
        operation_facets,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = profile_id;
    let _: &IdSet = roles;
    let _: &SchemaRef = configuration_schema;
    let _: &ContentRef = allowed_combinations_ref;
    let _: &ContentRef = port_templates_ref;
    let _: &Vec<SchemaRef> = state_formats;
    let _: &Vec<FacetSelection> = operation_facets;
    let _: &Extensions = extensions;
};

const _: fn(&FacetSelection) = |value| {
    let FacetSelection {
        id,
        version,
        configuration_ref,
        guarantees_ref,
        extensions,
    } = value;
    let _: &Id = id;
    let _: &Version = version;
    let _: &ContentRef = configuration_ref;
    let _: &ContentRef = guarantees_ref;
    let _: &Extensions = extensions;
};

const _: fn(&RealizationManifest) = |value| {
    let RealizationManifest {
        schema_version,
        realization_id,
        provider_manifest,
        descriptors,
        bindings,
        owners,
        owner_bindings,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = realization_id;
    let _: &ContentRef = provider_manifest;
    let _: &Vec<NodeDescriptor> = descriptors;
    let _: &Vec<NodeBinding> = bindings;
    let _: &Vec<OwnerRef> = owners;
    let _: &Vec<OwnerBinding> = owner_bindings;
    let _: &Extensions = extensions;
};

const _: fn(&NodeDescriptor) = |value| {
    let NodeDescriptor {
        schema_version,
        id,
        roles,
        model_ref,
        configuration_ref,
        initialization_ref,
        ports,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = id;
    let _: &IdSet = roles;
    let _: &ContentRef = model_ref;
    let _: &ContentRef = configuration_ref;
    let _: &ContentRef = initialization_ref;
    let _: &Vec<PortDescriptor> = ports;
    let _: &Extensions = extensions;
};

const _: fn(&PortDescriptor) = |value| {
    let PortDescriptor {
        id,
        lanes,
        interface_id,
        features,
        configuration_ref,
        extensions,
    } = value;
    let _: &Id = id;
    let _: &Vec<LaneDescriptor> = lanes;
    let _: &Id = interface_id;
    let _: &IdSet = features;
    let _: &ContentRef = configuration_ref;
    let _: &Extensions = extensions;
};

const _: fn(&LaneDescriptor) = |value| {
    let LaneDescriptor {
        id,
        direction,
        payload_schema,
        maximum_payload_bytes,
        maximum_pending_events,
        extensions,
    } = value;
    let _: &Id = id;
    let _: &Direction = direction;
    let _: &SchemaRef = payload_schema;
    let _: &U64 = maximum_payload_bytes;
    let _: &U64 = maximum_pending_events;
    let _: &Extensions = extensions;
};

const _: fn(&NodeBinding) = |value| {
    let NodeBinding {
        compatibility,
        authority,
        extensions,
    } = value;
    let _: &BindingCompatibility = compatibility;
    let _: &LiveAuthority = authority;
    let _: &Extensions = extensions;
};

const _: fn(&BindingCompatibility) = |value| {
    let BindingCompatibility {
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
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = node_id;
    let _: &HashRef = descriptor_hash;
    let _: &ImplementationIdentity = implementation;
    let _: &ContentRef = profile_ref;
    let _: &ContentRef = configuration_ref;
    let _: &OperatingContract = operating_contract;
    let _: &OwnerRef = execution_owner;
    let _: &OwnerRef = capture_owner;
    let _: &ContentRef = capabilities_ref;
    let _: &ContentRef = guarantees_ref;
    let _: &Vec<ContentRef> = qualification_refs;
    let _: &Extensions = extensions;
};

const _: fn(&LiveAuthority) = |value| {
    let LiveAuthority {
        schema_version,
        session_id,
        incarnation_id,
        realization_id,
        activation_id,
        world_generation,
        owner_generation,
        input_epoch,
        host_receipt,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &Id = session_id;
    let _: &Id = incarnation_id;
    let _: &Id = realization_id;
    let _: &Option<Id> = activation_id;
    let _: &U64 = world_generation;
    let _: &U64 = owner_generation;
    let _: &Id = input_epoch;
    let _: &ContentRef = host_receipt;
    let _: &Extensions = extensions;
};

const _: fn(&OwnerRef) = |value| {
    let OwnerRef {
        id,
        participant_ids,
        state_domain_ids,
    } = value;
    let _: &Id = id;
    let _: &IdSet = participant_ids;
    let _: &IdSet = state_domain_ids;
};

const _: fn(&OwnerBinding) = |value| {
    let OwnerBinding {
        schema_version,
        owner,
        owner_roles,
        node_bindings,
        ownership_ref,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &OwnerRef = owner;
    let _: &IdSet = owner_roles;
    let _: &Vec<NodeBindingRef> = node_bindings;
    let _: &ContentRef = ownership_ref;
    let _: &Extensions = extensions;
};

const _: fn(&NodeBindingRef) = |value| {
    let NodeBindingRef {
        node_id,
        binding_hash,
        extensions,
    } = value;
    let _: &Id = node_id;
    let _: &HashRef = binding_hash;
    let _: &Extensions = extensions;
};

const _: fn(&OperatingContract) = |value| {
    let OperatingContract {
        schema_version,
        mode,
        scheduling_role,
        ordering_profile,
        policy_ref,
        resolution_ps,
        phase_ps,
        facets,
        extensions,
    } = value;
    let _: &Version = schema_version;
    let _: &OperatingMode = mode;
    let _: &SchedulingRole = scheduling_role;
    let _: &String = ordering_profile;
    let _: &ContentRef = policy_ref;
    let _: &Option<U64> = resolution_ps;
    let _: &Option<U64> = phase_ps;
    let _: &Vec<FacetSelection> = facets;
    let _: &Extensions = extensions;
};

const _: fn(&crate::bodies::RealizeRequest) = |value| {
    let crate::bodies::RealizeRequest {
        realization_id,
        configuration,
        requested_node_ids,
        resource_limits,
        extensions,
    } = value;
    let _: &Id = realization_id;
    let _: &ContentRef = configuration;
    let _: &IdSet = requested_node_ids;
    let _: &ResourceLimits = resource_limits;
    let _: &Extensions = extensions;
};

const _: fn(&ResourceLimits) = |value| {
    let ResourceLimits {
        cpu_budget_ns,
        memory_bytes,
        writable_bytes,
        processes,
        descriptors,
        pending_events,
        content_bytes,
        maximum_operations,
        extensions,
    } = value;
    let _: &U64 = cpu_budget_ns;
    let _: &U64 = memory_bytes;
    let _: &U64 = writable_bytes;
    let _: &U64 = processes;
    let _: &U64 = descriptors;
    let _: &U64 = pending_events;
    let _: &U64 = content_bytes;
    let _: &U64 = maximum_operations;
    let _: &Extensions = extensions;
};

const _: fn(&ContentRef) = |value| {
    let ContentRef {
        hash,
        length,
        media_type,
    } = value;
    let _: &HashRef = hash;
    let _: &U64 = length;
    let _: &String = media_type;
};

const _: fn(&HashRef) = |value| {
    let HashRef {
        algorithm,
        domain,
        digest,
    } = value;
    let _: &String = algorithm;
    let _: &String = domain;
    let _: &String = digest;
};

const _: fn(&SchemaRef) = |value| {
    let SchemaRef {
        id,
        version,
        definition,
        extensions,
    } = value;
    let _: &Id = id;
    let _: &Version = version;
    let _: &ContentRef = definition;
    let _: &Extensions = extensions;
};

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_typed_coordinator_and_independent_copy_fit_precise_backing() -> TestResult {
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let bytes = original.bytes.as_slice();
        let actual = PacketNative5CoordinatorInstallation::decode(bytes, &local)?;
        let independent = actual.clone();
        for dto in [&actual, &independent] {
            let facts = crate::retained_metadata::observe_retained_native_coordinator(dto)?;
            let owned = requested_metadata_backing_storage_data(&facts)?;
            assert!(
                super::super::backing(bytes, usize::MAX)?
                    >= owned + size_of::<PacketNative5CoordinatorInstallation>()
            );
        }
        assert!(arrays(bytes, usize::MAX).is_ok());
        assert!(
            super::super::backing(bytes, usize::MAX)?
                < super::super::conservative_backing(bytes, usize::MAX)?
        );
        assert!(super::super::backing(bytes, 0).is_err());
        Ok(())
    }

    #[test]
    fn nested_typed_arrays_and_opaque_extension_values_keep_all_actual_backing() -> TestResult {
        let (_, _, _, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let mut value: serde_json::Value = serde_json::from_slice(original.bytes.as_slice())?;
        let first = &mut value["participants"][0];
        first["provider"]["protocol_versions"] =
            serde_json::json!(["cnp/1", "a", "b", "c", "d", "e", "f", "g", "h"]);
        first["provider"]["extensions"]["opaque"] =
            serde_json::json!({"nested":[[],["long-owned-value",{"leaf":[1,2,3]}]]});
        let bytes = canonical::canonical_json(&value)?;
        let actual: PacketNative5CoordinatorInstallation = serde_json::from_slice(&bytes)?;
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&actual)?;
        assert!(
            super::super::backing(&bytes, usize::MAX)?
                >= requested_metadata_backing_storage_data(&facts)?
                    + size_of::<PacketNative5CoordinatorInstallation>()
        );
        assert!(arrays(&bytes, usize::MAX).is_ok());
        Ok(())
    }

    #[test]
    fn empty_concrete_vectors_preserve_element_layout_and_overflow_refuses() -> TestResult {
        let ids: Vec<Id> = serde_json::from_slice(b"[]")?;
        let ports: Vec<PortDescriptor> = serde_json::from_slice(b"[]")?;
        let id_bank = vector(b"[]", Record::Id, 0, usize::MAX)?;
        let port_bank = vector(b"[]", Record::Port, 0, usize::MAX)?;
        assert!(id_bank >= ids.capacity() * size_of::<Id>());
        assert!(port_bank >= ports.capacity() * size_of::<PortDescriptor>());
        assert!(port_bank > id_bank);
        assert_eq!(vector(b"[]", Record::Port, 0, port_bank)?, port_bank);
        assert!(vector(b"[]", Record::Port, 0, port_bank - 1).is_err());
        assert!(vector_requested(usize::MAX, size_of::<PortDescriptor>(), usize::MAX).is_err());
        assert!(vector_requested(1, usize::MAX, usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn unrecognized_shape_uses_unchanged_conservative_fallback() -> TestResult {
        let (_, _, _, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let mut value: serde_json::Value = serde_json::from_slice(original.bytes.as_slice())?;
        value["participants"][0]["future_field"] = serde_json::json!({"nested":[["x"]]});
        let bytes = canonical::canonical_json(&value)?;
        assert!(arrays(&bytes, usize::MAX).is_err());
        assert_eq!(
            super::super::backing(&bytes, usize::MAX)?,
            super::super::conservative_backing(&bytes, usize::MAX)?
        );
        // The actual deny_unknown_fields deserializer remains the authority on
        // accepted DTO grammar; the counter never installs a permissive decoder.
        assert!(serde_json::from_slice::<PacketNative5CoordinatorInstallation>(&bytes).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(original.bytes.as_slice())?;
        value["host"]["binding"]["authority"]
            .as_object_mut()
            .ok_or("authority is not an object")?
            .remove("activation_id");
        let missing = canonical::canonical_json(&value)?;
        assert!(arrays(&missing, usize::MAX).is_err());
        assert_eq!(
            super::super::backing(&missing, usize::MAX)?,
            super::super::conservative_backing(&missing, usize::MAX)?
        );
        let bytes = original.bytes.as_slice();
        assert!(walk(bytes, Record::Coordinator, MAX_DEPTH, usize::MAX).is_err());
        Ok(())
    }
}
