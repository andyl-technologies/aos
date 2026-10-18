//! Projects the closed index-three metadata shapes before capture effects.
//!
//! Role counts come from the admitted actual source geometry and current object
//! inventory. The projection is allocation data, never source authority. It
//! includes the three signed-index serialization passes and their simultaneously
//! retained encoded buffers, separate from native payload banks streamed to disk.

use crate::node_contract::NativeStateKey;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_contract::{ContentRef, Id, Position, SchemaRef, U64};
use serde::{Serialize, Serializer, ser::SerializeSeq};

struct Repeated<'a, T> {
    value: &'a T,
    count: usize,
}

impl<T: Serialize> Serialize for Repeated<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.count))?;
        for _ in 0..self.count {
            sequence.serialize_element(self.value)?;
        }
        sequence.end()
    }
}

// Mirrors storage::pages' exact outer and inner sequence size hints. It
// allocates neither the repeated evidence rows nor their page containers.
struct PagedRepeated<'a, T> {
    value: &'a T,
    count: usize,
}

impl<T: Serialize> Serialize for PagedRepeated<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut pages = serializer.serialize_seq(Some(self.count.div_ceil(256)))?;
        let mut remaining = self.count;
        while remaining != 0 {
            let count = remaining.min(256);
            pages.serialize_element(&Repeated {
                value: self.value,
                count,
            })?;
            remaining -= count;
        }
        pages.end()
    }
}

#[derive(Serialize)]
struct ProjectedObject<'a> {
    reference: &'a ContentRef,
    dependencies: &'a [ContentRef],
}

#[derive(Serialize)]
struct ProjectedInventory<'a> {
    schema_version: u16,
    objects: Repeated<'a, ProjectedObject<'a>>,
}

#[derive(Serialize)]
struct ProjectedIndex<'a, O> {
    schema_version: u16,
    artifact: &'a ContentRef,
    typed_inventory: ProjectedInventory<'a>,
    owners: &'a O,
    original_capture_journal: &'a ContentRef,
}

#[derive(Serialize)]
struct ProjectedEnvelope<'a, I> {
    body: &'a I,
    authentication: [u8; 32],
}

fn add(a: usize, b: usize) -> Result<usize, RuntimeError> {
    a.checked_add(b).ok_or(RuntimeError::ResourceLimit)
}

fn multiply(a: usize, b: usize) -> Result<usize, RuntimeError> {
    a.checked_mul(b).ok_or(RuntimeError::ResourceLimit)
}

// Closed core metadata has no floating/custom-byte codecs. Canonical ordering
// changes key order, not extent; this uses the same JSON string/number encoder.
#[derive(Default)]
struct EncodedBodyCredit {
    bytes: usize,
    largest: usize,
}

struct CountWriter {
    bytes: usize,
    maximum: usize,
}

impl std::io::Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or_else(|| std::io::Error::other("closed core encoded credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encoded_extent(value: &impl Serialize, maximum: usize) -> Result<usize, RuntimeError> {
    let mut writer = CountWriter { bytes: 0, maximum };
    serde_json::to_writer(&mut writer, value).map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(writer.bytes)
}

impl NodeRuntime {
    pub(crate) fn capture_encoded_output_storage(
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let written = encoded_extent(value, maximum)?;
        let requested = add(multiply(written, 4)?, 8)?;
        if requested > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(requested)
    }
}

impl EncodedBodyCredit {
    fn authenticate_record_ceiling(&self, maximum: usize) -> Result<(), RuntimeError> {
        if self.largest > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    fn charge(
        &mut self,
        value: &impl Serialize,
        count: usize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let length = encoded_extent(value, maximum)?;
        self.bytes = add(self.bytes, multiply(length, count)?)?;
        self.largest = self.largest.max(length);
        Ok(())
    }
}

/// Produces the longest encoded valid core ContentRef without a payload buffer.
/// Printable quote bytes each require two JSON bytes; plain ASCII is shorter.
fn maximum_reference() -> ContentRef {
    ContentRef {
        hash: crucible_node_contract::HashRef {
            algorithm: "blake3-256".to_owned(),
            domain: "cnp.blob.v1".to_owned(),
            digest: "0".repeat(64),
        },
        length: U64::new(u64::MAX),
        media_type: "\"".repeat(128),
    }
}

// Generic hash domains permit ASCII controls. NUL requires six JSON bytes,
// whereas IDs and content hash domains have narrower unescaped grammars.
fn maximum_hash() -> crucible_node_contract::HashRef {
    crucible_node_contract::HashRef {
        algorithm: "blake3-256".to_owned(),
        domain: "\0".repeat(128),
        digest: "0".repeat(64),
    }
}

// This named projection is a minimum for the actual closed core phases.
// Source-owned payload banks and original runtime/prepared-attempt storage
// remain separate mandatory reservations; this data cannot issue a seal.
fn projected_index_serialization<O: Serialize>(
    owners: &O,
    objects: usize,
    edges: usize,
    record_bytes: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let reference = maximum_reference();
    let object = ProjectedObject {
        reference: &reference,
        dependencies: &[],
    };
    let body = ProjectedIndex {
        schema_version: 3,
        artifact: &reference,
        typed_inventory: ProjectedInventory {
            schema_version: 2,
            objects: Repeated {
                value: &object,
                count: objects,
            },
        },
        owners,
        original_capture_journal: &reference,
    };
    // persist first counts the index without a DOM, then builds the MAC body
    // and envelope Values. A third body pass is retained as explicit spare
    // credit; the count-only pass is not described as an allocation.
    let body_pass = NodeRuntime::capture_serialization_storage(&body, maximum)?;
    let mut requested = multiply(body_pass, 2)?;
    requested = add(
        requested,
        NodeRuntime::capture_serialization_storage(
            &ProjectedEnvelope {
                body: &body,
                authentication: [255; 32],
            },
            maximum,
        )?,
    )?;
    // Dependency strings and object graphs are counted separately from the
    // already projected fixed object fields. All three signing passes visit them.
    let dependency = Repeated {
        value: &reference,
        count: edges,
    };
    let dependency_storage = NodeRuntime::capture_serialization_storage(&dependency, maximum)?;
    requested = add(requested, multiply(dependency_storage, 3)?)?;
    // Actual dependencies are paged at256. The flat projection accounts all
    // edge Value slots; reserve the additional outer-page Value slots too.
    let pages = add(objects, edges.div_ceil(256))?;
    requested = add(
        requested,
        multiply(pages, 3 * std::mem::size_of::<serde_json::Value>())?,
    )?;
    // Reference extents plus separators cover every edge; page brackets are
    // bounded by one page per object plus each complete256-edge page.
    let reference_extent = add(encoded_extent(&reference, maximum)?, 1)?;
    let body_extent = add(
        encoded_extent(&body, maximum)?,
        add(multiply(edges, reference_extent)?, multiply(pages, 2)?)?,
    )?;
    let envelope_overhead = encoded_extent(
        &ProjectedEnvelope {
            body: &(),
            authentication: [255; 32],
        },
        maximum,
    )?;
    let encoded_bound = add(body_extent, envelope_overhead)?;
    if encoded_bound > record_bytes {
        return Err(RuntimeError::ResourceLimit);
    }
    // MAC body and envelope banks coexist. Charge cumulative Vec requests
    // from their projected extents, not the unrelated record refusal ceiling.
    requested = add(
        requested,
        multiply(add(multiply(encoded_bound, 4)?, 8)?, 2)?,
    )?;
    // An existing same-name index may grow during its bounded comparison read.
    // That sequential reader coexists with the new MAC/envelope banks above;
    // charge its cumulative requests up to encoded_bound + 1 before refusal.
    let index_read = add(multiply(add(encoded_bound, 1)?, 4)?, 8)?;
    requested = add(requested, index_read)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[derive(Serialize)]
struct ProjectedNativeOwner<'a> {
    owner: &'a Id,
    participants: Repeated<'a, Id>,
    key: &'a NativeStateKey,
    cut: Position,
    state: &'a ContentRef,
    evidence: PagedRepeated<'a, ContentRef>,
    artifacts: &'a [()],
}

/// Projects the longest legal cloned identifier/reference banks. Incoming spare
/// allocation is charged separately by actual returned storage; core clones
/// use logical contents and cannot retain another source's spare bank.
fn projected_owner_serialization(
    cut: Position,
    maximum_objects: &[usize; 4],
    objects: usize,
    edges: usize,
    record_bytes: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference = maximum_reference();
    let key = NativeStateKey {
        implementation: id.clone(),
        profile: id.clone(),
        schema: SchemaRef {
            id: id.clone(),
            version: u16::MAX,
            definition: reference.clone(),
            extensions: Default::default(),
        },
    };
    let owners = maximum_objects.map(|count| ProjectedNativeOwner {
        owner: &id,
        participants: Repeated {
            value: &id,
            count: 1,
        },
        key: &key,
        cut,
        state: &reference,
        evidence: PagedRepeated {
            value: &reference,
            count,
        },
        artifacts: &[],
    });
    let index = projected_index_serialization(&owners, objects, edges, record_bytes, maximum)?;
    let evidence_pages = maximum_objects
        .iter()
        .try_fold(0usize, |count, objects| add(count, objects.div_ceil(256)))?;
    let extra_page_slots = multiply(evidence_pages, 3 * std::mem::size_of::<serde_json::Value>())?;
    let requested = add(index, extra_page_slots)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[derive(Serialize)]
struct ProjectedOwnerReceipt<'a> {
    schema_version: u16,
    owner: &'a Id,
    inventory: &'a crucible_node_contract::HashRef,
    coordinator: &'a ContentRef,
    cut: Position,
    ordinal: U64,
    domains: Repeated<'a, Id>,
}

/// Counts the inventory hash pass and both receipt record passes for each
/// actual owner. Domain rows come from the original graph, and evidence rows
/// from the selected source geometry, independently of payload hash sharing.
#[cfg(test)]
fn projected_owner_receipt_serialization(
    cut: Position,
    owner_objects: &[usize; 4],
    domains: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    projected_owner_receipt_serialization_with_bodies(cut, owner_objects, domains, maximum, None)
}

fn projected_owner_receipt_serialization_with_bodies(
    cut: Position,
    owner_objects: &[usize; 4],
    domains: usize,
    maximum: usize,
    bodies: Option<&mut EncodedBodyCredit>,
) -> Result<usize, RuntimeError> {
    let id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference = maximum_reference();
    let hash = maximum_hash();
    let key = NativeStateKey {
        implementation: id.clone(),
        profile: id.clone(),
        schema: SchemaRef {
            id: id.clone(),
            version: u16::MAX,
            definition: reference.clone(),
            extensions: Default::default(),
        },
    };
    let receipt = ProjectedOwnerReceipt {
        schema_version: 1,
        owner: &id,
        inventory: &hash,
        coordinator: &reference,
        cut,
        ordinal: U64::new(u64::MAX),
        domains: Repeated {
            value: &id,
            count: domains,
        },
    };
    let receipt_pass = NodeRuntime::capture_serialization_storage(&receipt, maximum)?;
    if let Some(bodies) = bodies {
        bodies.charge(&receipt, 4, maximum)?;
    }
    let mut requested = 0;
    for count in owner_objects {
        let inventory = ProjectedNativeOwner {
            owner: &id,
            participants: Repeated {
                value: &id,
                count: 1,
            },
            key: &key,
            cut,
            state: &reference,
            evidence: PagedRepeated {
                value: &reference,
                count: add(*count, 1)?,
            },
            artifacts: &[],
        };
        requested = add(
            requested,
            NodeRuntime::capture_serialization_storage(&inventory, maximum)?,
        )?;
        requested = add(requested, multiply(receipt_pass, 2)?)?;
        requested = add(
            requested,
            NodeRuntime::capture_future_decode_storage(&receipt, maximum)?,
        )?;
    }
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

/// Bounds the distinct metadata owners created after native capture. Every term
/// names an actual owner; cumulative requests safely bound coexistence across
/// phases without presuming payload deduplication frees the original buffers.
fn projected_typed_archive_storage(
    owner_objects: &[usize; 4],
    objects: usize,
    edges: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use super::storage::{Index, NativeOwnerState, Object};
    use std::collections::{BTreeMap, BTreeSet};
    use std::mem::size_of;

    let reference = maximum_reference();
    let reference_strings = NodeRuntime::capture_reference_storage(&reference)?;
    let id_strings = 128usize;
    // Each core clone requests its logical string length; supplied spare banks
    // belong to returned/source storage and are charged by the separate walker.
    let key_strings = add(multiply(id_strings, 3)?, reference_strings)?;
    let key_extensions = NodeRuntime::capture_map_node_storage::<String, serde_json::Value>();
    let owner_fixed = add(
        size_of::<NativeOwnerState>(),
        add(
            add(std::mem::size_of::<Id>(), multiply(id_strings, 2)?)?,
            add(key_strings, key_extensions)?,
        )?,
    )?;
    let owner_references = owner_objects.iter().try_fold(0usize, |total, count| {
        // The local settlement journal is an additional evidence occurrence.
        add(total, multiply(add(*count, 1)?, 2)?.max(4))
    })?;
    let reference_slot = add(size_of::<ContentRef>(), reference_strings)?;
    let owner_storage = add(
        multiply(owner_fixed, 4)?,
        add(
            multiply(owner_references, reference_slot)?,
            multiply(reference_strings, 4)?,
        )?,
    )?;
    let object_storage = add(
        multiply(objects, add(size_of::<Object>(), reference_strings)?)?,
        multiply(multiply(edges, 2)?.max(4), reference_slot)?,
    )?;
    let index = add(
        size_of::<Index>(),
        add(
            multiply(reference_strings, 2)?,
            add(owner_storage, object_storage)?,
        )?,
    )?;
    // Original Index, self.record(index.clone()) and Envelope.body index.clone()
    // may coexist. Include the Arc allocation that owns the verified record.
    let index_copies = add(
        multiply(index, 3)?,
        NodeRuntime::capture_shared_allocation_storage::<Index>(),
    )?;

    // Objects streams bytes to disk, but retains two independent BTree indexes.
    let writer_nodes = add(
        NodeRuntime::capture_map_node_storage::<ContentRef, Object>(),
        NodeRuntime::capture_map_node_storage::<crucible_node_contract::HashRef, ContentRef>(),
    )?;
    let writer = add(
        size_of::<BTreeMap<ContentRef, Object>>()
            + size_of::<BTreeMap<crucible_node_contract::HashRef, ContentRef>>(),
        add(
            multiply(objects.max(1), writer_nodes)?,
            add(
                object_storage,
                multiply(objects, multiply(reference_strings, 3)?)?,
            )?,
        )?,
    )?;

    // Before signing, complete_original_lineage_content verifies a NEW closure
    // alongside all original capture slots. Its bytes are admitted separately;
    // these terms count the two maps and cloned typed reference strings.
    let verifier_nodes = add(
        NodeRuntime::capture_map_node_storage::<
            crucible_node_contract::HashRef,
            (ContentRef, Vec<u8>),
        >(),
        NodeRuntime::capture_map_node_storage::<ContentRef, ()>(),
    )?;
    let verifier = add(
        size_of::<BTreeMap<crucible_node_contract::HashRef, (ContentRef, Vec<u8>)>>()
            + size_of::<BTreeSet<ContentRef>>(),
        add(
            multiply(objects.max(1), verifier_nodes)?,
            multiply(objects, multiply(reference_strings, 3)?)?,
        )?,
    )?;
    // verify_closure keeps its typed queued set and hash-to-reference map
    // beside the returned content/reference maps. The pending VecDeque can
    // retain doubled growth capacity, including each independent cloned ref.
    let queue_nodes = add(
        NodeRuntime::capture_map_node_storage::<ContentRef, ()>(),
        NodeRuntime::capture_map_node_storage::<crucible_node_contract::HashRef, ContentRef>(),
    )?;
    let queued = multiply(objects.max(1), queue_nodes)?;
    let queue_strings = multiply(objects, multiply(reference_strings, 3)?)?;
    let pending_slot = add(
        std::mem::size_of::<(ContentRef, usize)>(),
        reference_strings,
    )?;
    let pending = multiply(multiply(objects, 2)?.max(4), pending_slot)?;
    let closure_work = add(queued, add(queue_strings, pending)?)?;
    let requested = add(index_copies, add(writer, add(verifier, closure_work)?)?)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[derive(Serialize)]
struct ProjectedAdministrativeJournal<'a> {
    schema_version: u16,
    maximum_attempts: U64,
    attempts: Repeated<'a, crate::node_contract::OriginalCaptureAttemptRecord>,
}

#[cfg(test)]
fn projected_administrative_serialization(maximum: usize) -> Result<usize, RuntimeError> {
    projected_administrative_serialization_with_bodies(maximum, None)
}

fn projected_administrative_serialization_with_bodies(
    maximum: usize,
    mut bodies: Option<&mut EncodedBodyCredit>,
) -> Result<usize, RuntimeError> {
    use crate::node_contract::{
        OriginalCaptureAttemptRecord, OriginalCaptureOwnerRecord, OriginalCaptureOwnerState,
        OwnerIdentity, RuntimeOriginalCaptureJournal, SavedRuntimeActivation,
    };
    let id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference = maximum_reference();
    let owner = OwnerIdentity {
        owner: id.clone(),
        incarnation: id.clone(),
        generation: U64::new(u64::MAX),
    };
    let position = Position::new(
        U64::new(u64::MAX),
        U64::new(u64::MAX),
        crucible_node_contract::Phase::BoundaryControl,
    );
    let row = OriginalCaptureOwnerRecord {
        owner: owner.clone(),
        participants: vec![id.clone()],
        operation: id.clone(),
        state: OriginalCaptureOwnerState::Settled {
            snapshot: reference.clone(),
            journal: Box::new(reference.clone()),
        },
    };
    let attempt = OriginalCaptureAttemptRecord {
        sequence: U64::new(u64::MAX),
        capture_id: id.clone(),
        source_runtime: reference,
        source_activation: SavedRuntimeActivation {
            generation: U64::new(u64::MAX),
            activation_id: id,
            world_binding_hash: maximum_hash(),
            owners: vec![owner; 4],
            boundary: position,
        },
        cut: position,
        ordinal: U64::new(u64::MAX),
        owners: vec![row; 4],
    };
    let journal = ProjectedAdministrativeJournal {
        schema_version: 1,
        maximum_attempts: U64::new(64),
        attempts: Repeated {
            value: &attempt,
            count: 64,
        },
    };
    // Only one bounded sample row is owned here. Repeated serializer events
    // project the lifetime64 journal without allocating64 cloned attempts.
    let one = RuntimeOriginalCaptureJournal {
        schema_version: 1,
        maximum_attempts: U64::new(64),
        attempts: vec![],
    };
    let attempt_storage = NodeRuntime::capture_admin_attempt_storage(&attempt)?;
    let future_records = projected_guarantees_and_provenance_serialization_with_bodies(
        &attempt.source_activation,
        position,
        maximum,
        bodies.as_deref_mut(),
    )?;
    if let Some(bodies) = bodies {
        bodies.charge(&journal, 1, maximum)?;
    }
    let typed = add(
        NodeRuntime::capture_admin_storage(&one)?,
        multiply(attempt_storage, 64)?,
    )?;
    // The direct new journal, pre-sign index authentication, complete archive
    // validation and persist's index authentication each construct a typed
    // journal. Their cumulative requested banks conservatively bound overlap.
    let typed_phases = add(multiply(typed, 4)?, future_records)?;
    // core_references retains its growing reference Vec and clones one Value
    // subtree at a time before consuming it into a typed ContentRef. Its DFS
    // stack cannot visit more Value occurrences than serialized bytes: every
    // node has at least one JSON token byte. This is a pointer-bank bound for
    // this closed journal, not a text-to-heap bound for arbitrary decoders.
    let reference_count = 64 * (1 + 4 * 2);
    let reference = maximum_reference();
    let reference_slot = add(
        std::mem::size_of::<ContentRef>(),
        NodeRuntime::capture_reference_storage(&reference)?,
    )?;
    let reference_vector = multiply(multiply(reference_count, 4)?, reference_slot)?;
    let single_reference_clone = NodeRuntime::capture_serialization_storage(&reference, maximum)?;
    let stack = add(
        multiply(
            multiply(encoded_extent(&journal, maximum)?, 4)?,
            std::mem::size_of::<&serde_json::Value>(),
        )?,
        8 * std::mem::size_of::<&serde_json::Value>(),
    )?;
    // validate_journal retains lifetime capture IDs plus one owner's participant
    // set. Operation spelling is compared without allocating a format String.
    let identity_sets = multiply(64 + 4, NodeRuntime::capture_map_node_storage::<&Id, ()>())?;
    let traversal = add(
        reference_vector,
        add(single_reference_clone, add(stack, identity_sets)?)?,
    )?;
    let requested = add(
        typed_phases,
        add(
            traversal,
            add(
                NodeRuntime::capture_serialization_storage(&journal, maximum)?,
                NodeRuntime::capture_future_decode_storage(&journal, maximum)?,
            )?,
        )?,
    )?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[derive(Serialize)]
struct ProjectedCapturedOwner<'a> {
    capture_owner_id: &'a Id,
    participant_ids: Repeated<'a, Id>,
    state_domain_ids: Repeated<'a, Id>,
    binding_hashes: Repeated<'a, crucible_node_contract::HashRef>,
    state_schema: &'a SchemaRef,
    representation: crucible_node_contract::CaptureRepresentation,
    state_ref: Option<&'a ContentRef>,
    retained_source_ref: Option<&'a ContentRef>,
    dependencies: Repeated<'a, Id>,
    capture_receipt: &'a ContentRef,
    extensions: &'a crucible_node_contract::Extensions,
}

#[derive(Serialize)]
struct ProjectedManifest<'a> {
    schema_version: u16,
    capture_id: &'a Id,
    world_binding_hash: &'a crucible_node_contract::HashRef,
    scenario_ref: &'a ContentRef,
    preservation_contract: &'a Id,
    cut: Position,
    event_ordinal: U64,
    ordering_profile: &'a str,
    guarantees_ref: &'a ContentRef,
    coordinator_state_ref: &'a ContentRef,
    owners: [ProjectedCapturedOwner<'a>; 4],
    immutable_refs: Repeated<'a, ContentRef>,
    provenance_ref: &'a ContentRef,
    extensions: &'a crucible_node_contract::Extensions,
}

/// Bounds the complete manifest's borrowed serialization shape. Each owner has
/// one actual participant in this closed four-node route; domain/dependency
/// totals are counted from the actual graph, rather than inferred from labels.
#[cfg(test)]
fn projected_manifest_serialization(
    domains: usize,
    dependencies: usize,
    cut: Position,
    objects: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    projected_manifest_serialization_with_bodies(domains, dependencies, cut, objects, maximum, None)
}

fn projected_manifest_serialization_with_bodies(
    domains: usize,
    dependencies: usize,
    cut: Position,
    objects: usize,
    maximum: usize,
    bodies: Option<&mut EncodedBodyCredit>,
) -> Result<usize, RuntimeError> {
    let id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference = maximum_reference();
    let hash = maximum_hash();
    let extensions = Default::default();
    let schema = SchemaRef {
        id: id.clone(),
        version: u16::MAX,
        definition: reference.clone(),
        extensions: Default::default(),
    };
    let owners = std::array::from_fn(|_| ProjectedCapturedOwner {
        capture_owner_id: &id,
        participant_ids: Repeated {
            value: &id,
            count: 1,
        },
        // Counting all graph domains/dependencies for each owner is a named
        // conservative projection; it never allocates the repeated rows.
        state_domain_ids: Repeated {
            value: &id,
            count: domains,
        },
        binding_hashes: Repeated {
            value: &hash,
            count: 1,
        },
        state_schema: &schema,
        representation: crucible_node_contract::CaptureRepresentation::Durable,
        state_ref: Some(&reference),
        retained_source_ref: None,
        dependencies: Repeated {
            value: &id,
            count: dependencies,
        },
        capture_receipt: &reference,
        extensions: &extensions,
    });
    let manifest = ProjectedManifest {
        schema_version: 1,
        capture_id: &id,
        world_binding_hash: &hash,
        scenario_ref: &reference,
        preservation_contract: &id,
        cut,
        event_ordinal: U64::new(u64::MAX),
        ordering_profile: "full-position-superdense",
        guarantees_ref: &reference,
        coordinator_state_ref: &reference,
        owners,
        immutable_refs: Repeated {
            value: &reference,
            count: objects,
        },
        provenance_ref: &reference,
        extensions: &extensions,
    };
    if let Some(bodies) = bodies {
        bodies.charge(&manifest, 1, maximum)?;
    }
    // core_references first bounded-record encodes the manifest and then builds
    // a second Value; Objects::record performs its own final serialization.
    // Each actual pass also incurs canonical ordered-key/string temporaries.
    add(
        multiply(
            NodeRuntime::capture_serialization_storage(&manifest, maximum)?,
            3,
        )?,
        multiply(
            NodeRuntime::capture_future_decode_storage(&manifest, maximum)?,
            2,
        )?,
    )
}

/// Bounds actual cloned manifest containers separately from serializer scratch.
/// Source-returned spare allocation remains in its independently charged banks;
/// these core-created clones request logical contents and checked Vec growth.
fn projected_typed_manifest_storage(
    domains: usize,
    dependencies: usize,
    objects: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use crucible_node_contract::{CaptureManifest, CapturedOwner, HashRef};
    use std::mem::size_of;
    let reference = maximum_reference();
    let reference_strings = NodeRuntime::capture_reference_storage(&reference)?;
    let id_strings = 128usize;
    let id_slot = add(size_of::<Id>(), id_strings)?;
    let hash_slot = add(
        size_of::<HashRef>(),
        NodeRuntime::capture_hash_storage(&maximum_hash())?,
    )?;
    let cloned_vector = |count: usize, slot: usize| {
        // Filter/map collect starts with a minimum four slots; doubling can
        // retain at most twice the final logical count. This is a requested
        // bank bound for the pinned RawVec implementation, not resident bytes.
        multiply(multiply(count, 2)?.max(4), slot)
    };
    let schema_strings = add(id_strings, reference_strings)?;
    let mut owner = add(size_of::<CapturedOwner>(), id_strings)?;
    owner = add(owner, cloned_vector(1, id_slot)?)?;
    owner = add(owner, cloned_vector(domains, id_slot)?)?;
    owner = add(owner, cloned_vector(1, hash_slot)?)?;
    owner = add(owner, schema_strings)?;
    owner = add(owner, multiply(reference_strings, 2)?)?;
    owner = add(owner, cloned_vector(dependencies, id_slot)?)?;

    let mut manifest = add(size_of::<CaptureManifest>(), multiply(id_strings, 3)?)?;
    manifest = add(
        manifest,
        NodeRuntime::capture_hash_storage(&maximum_hash())?,
    )?;
    // The admitted world requires exactly this fixed ordering-profile spelling.
    manifest = add(manifest, "superdense-v1".len())?;
    manifest = add(manifest, multiply(reference_strings, 4)?)?;
    manifest = add(manifest, multiply(owner, 4)?)?;
    manifest = add(
        manifest,
        cloned_vector(objects, add(size_of::<ContentRef>(), reference_strings)?)?,
    )?;
    // The original manifest, pre-sign verification record and persisted record
    // can coexist. Each record call independently decodes its owned manifest.
    let requested = multiply(manifest, 3)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[derive(Serialize)]
struct ProjectedGuarantees<'a> {
    schema_version: u16,
    world_repeatability: crucible_node_contract::Repeatability,
    exact_model_continuation: bool,
    preservation_contract: &'a Id,
}

#[derive(Serialize)]
struct ProjectedCollectingScope<'a> {
    schema: &'a str,
    plan: &'a ContentRef,
    refused: &'a ContentRef,
    sources: Repeated<'a, ContentRef>,
    world: &'a crucible_node_contract::HashRef,
    ordinary_acceptance: bool,
}

#[derive(Serialize)]
struct ProjectedArchiveDialect<'a> {
    schema_version: u16,
    content_inventory: u16,
    original_capture_journal: &'a ContentRef,
}

#[derive(Serialize)]
struct ProjectedProvenance<'a> {
    schema_version: u16,
    source_activation: &'a crate::node_contract::SavedRuntimeActivation,
    cut: Position,
    ordinal: U64,
    native_archive: ProjectedArchiveDialect<'a>,
    collecting_capture: Option<ProjectedCollectingScope<'a>>,
}

fn projected_guarantees_and_provenance_serialization_with_bodies(
    source_activation: &crate::node_contract::SavedRuntimeActivation,
    cut: Position,
    maximum: usize,
    bodies: Option<&mut EncodedBodyCredit>,
) -> Result<usize, RuntimeError> {
    let id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference = maximum_reference();
    let hash = maximum_hash();
    let guarantees = ProjectedGuarantees {
        schema_version: 1,
        world_repeatability: crucible_node_contract::Repeatability::Nondeterministic,
        exact_model_continuation: true,
        preservation_contract: &id,
    };
    let provenance = ProjectedProvenance {
        schema_version: 1,
        source_activation,
        cut,
        ordinal: U64::new(u64::MAX),
        native_archive: ProjectedArchiveDialect {
            schema_version: 3,
            content_inventory: 2,
            original_capture_journal: &reference,
        },
        collecting_capture: Some(ProjectedCollectingScope {
            schema: "source-owned.collecting-complete-capture/1",
            plan: &reference,
            refused: &reference,
            sources: Repeated {
                value: &reference,
                count: 32,
            },
            world: &hash,
            ordinary_acceptance: false,
        }),
    };
    if let Some(bodies) = bodies {
        bodies.charge(&guarantees, 1, maximum)?;
        bodies.charge(&provenance, 1, maximum)?;
    }
    // json! first creates an independently owned Value for each record;
    // Objects::record then visits it and canonicalizes it. Reserve both phases
    // using the original typed shape, which also covers decimal formatting.
    let requested = multiply(
        add(
            NodeRuntime::capture_serialization_storage(&guarantees, maximum)?,
            NodeRuntime::capture_serialization_storage(&provenance, maximum)?,
        )?,
        2,
    )?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

/// Preflights the exact already-encoded core snapshots before future decoder
/// allocations. The native codec's opaque payload parser is separately charged
/// by its owning source row; this covers only the actual closed core records.
fn projected_known_core_decoding(
    runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
    scheduling: &crate::node_scheduling::SchedulingSnapshot,
    runtime_bytes: &[u8],
    scheduling_bytes: &[u8],
    lineage: crate::node_contract::OriginalInputLineageLimits,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let runtime_credit = super::core_decode_credit::preflight(runtime_bytes, maximum)?;
    let scheduling_credit = super::core_decode_credit::preflight(scheduling_bytes, maximum)?;
    let runtime_pass = add(
        runtime_credit.total()?,
        NodeRuntime::capture_runtime_record_storage(runtime)?,
    )?;
    let scheduling_pass = add(
        scheduling_credit.total()?,
        NodeRuntime::capture_scheduling_record_storage(scheduling)?,
    )?;
    // The later complete verifier validates Runtime7 after decoding it. Its
    // transitive indices, queues and sorted owner/reference sets are independent
    // allocations beside the original and decoded records, not parser banks.
    let validation = super::core_decode_credit::validation_storage(
        &runtime_credit,
        crate::node_contract::HostSchedulingContinuationLimits {
            maximum_record_bytes: runtime_bytes.len(),
            lineage,
        },
    )?;
    let requested = add(add(runtime_pass, scheduling_pass)?, validation)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

pub(super) struct CoreCaptureMetadataGeometry<'a> {
    pub graph: &'a crate::node_admission::AdmittedGraph,
    pub runtime: &'a crate::node_contract::OriginalLineageRuntimeRecord,
    pub scheduling: &'a crate::node_scheduling::SchedulingSnapshot,
    pub runtime_bytes: &'a [u8],
    pub scheduling_bytes: &'a [u8],
    pub lineage: crate::node_contract::OriginalInputLineageLimits,
    pub owners: &'a super::CompleteOriginalCaptureGeometry,
    pub objects: usize,
    pub edges: usize,
    pub record_bytes: usize,
    pub maximum: usize,
}

// Archive IO verifies one artifact at a time. The content banks are charged
// elsewhere; these are the temporary artifact owner, filename/temporary-name
// String requests, fixed streaming hash stack, and digest output. The archive's
// original directory Arc is counted once by the writer's current-core term.
pub(super) fn projected_archive_io_storage() -> Result<usize, RuntimeError> {
    use crate::node_contract::NativeCaptureArtifact;
    let object_name = add(64, ".native-object-v1".len())?;
    let pending_name = add(object_name, ".pending".len())?;
    let names = add(
        add(multiply(object_name, 4)?, 8)?,
        add(multiply(pending_name, 4)?, 8)?,
    )?;
    let artifact = add(
        std::mem::size_of::<NativeCaptureArtifact>(),
        add(
            NodeRuntime::capture_shared_allocation_storage::<std::fs::File>(),
            add(
                "archive-object".len(),
                NodeRuntime::capture_reference_storage(&maximum_reference())?,
            )?,
        )?,
    )?;
    let streaming = add(64 * 1024 + 1 + std::mem::size_of::<blake3::Hasher>(), 64)?;
    add(artifact, add(names, streaming)?)
}

// The caller moves these owners into the writer. A valid short identifier may
// retain an arbitrarily larger incoming String bank, unlike a new core clone.
pub(super) fn original_request_storage(
    capture_id: &Id,
    requirements: &crate::node_state::StateRequirements,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let requested = add(
        std::mem::size_of::<Id>() + std::mem::size_of::<crate::node_state::StateRequirements>(),
        add(
            capture_id.allocated_capacity(),
            requirements.preservation_contract.allocated_capacity(),
        )?,
    )?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

pub(super) struct CoreCaptureMetadataPeak {
    index_serialization: usize,
    typed_archive: usize,
    administrative: usize,
    owner_receipts: usize,
    manifest_serialization: usize,
    typed_manifests: usize,
    known_core_decoding: usize,
    archive_io: usize,
    future_core_bodies: usize,
    future_largest_record: usize,
}

impl CoreCaptureMetadataPeak {
    pub(super) fn prepare(input: CoreCaptureMetadataGeometry<'_>) -> Result<Self, RuntimeError> {
        let rows: &[super::CompleteOriginalOwnerCaptureGeometry; 4] = input
            .owners
            .owners
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let counts = rows.each_ref().map(|row| row.maximum_objects);
        let domains = input.graph.ownership_policy().domains.len();
        let dependencies = input
            .graph
            .ownership_policy()
            .capture_owners
            .iter()
            .try_fold(0usize, |total, owner| add(total, owner.dependencies.len()))?;
        let cut = input.runtime.capture_cut;
        let mut bodies = EncodedBodyCredit::default();
        let mut peak = Self {
            index_serialization: projected_owner_serialization(
                cut,
                &counts,
                input.objects,
                input.edges,
                input.record_bytes,
                input.maximum,
            )?,
            typed_archive: projected_typed_archive_storage(
                &counts,
                input.objects,
                input.edges,
                input.maximum,
            )?,
            administrative: projected_administrative_serialization_with_bodies(
                input.maximum,
                Some(&mut bodies),
            )?,
            owner_receipts: projected_owner_receipt_serialization_with_bodies(
                cut,
                &counts,
                domains,
                input.maximum,
                Some(&mut bodies),
            )?,
            manifest_serialization: projected_manifest_serialization_with_bodies(
                domains,
                dependencies,
                cut,
                input.objects,
                input.maximum,
                Some(&mut bodies),
            )?,
            typed_manifests: projected_typed_manifest_storage(
                domains,
                dependencies,
                input.objects,
                input.maximum,
            )?,
            known_core_decoding: projected_known_core_decoding(
                input.runtime,
                input.scheduling,
                input.runtime_bytes,
                input.scheduling_bytes,
                input.lineage,
                input.maximum,
            )?,
            archive_io: projected_archive_io_storage()?,
            future_core_bodies: 0,
            future_largest_record: 0,
        };
        peak.future_core_bodies = bodies.bytes;
        peak.future_largest_record = bodies.largest;
        bodies.authenticate_record_ceiling(input.record_bytes)?;
        peak.admit(input.maximum)?;
        Ok(peak)
    }

    pub(super) fn future_body_bounds(&self) -> (usize, usize) {
        (self.future_core_bodies, self.future_largest_record)
    }

    pub(super) fn total(&self) -> Result<usize, RuntimeError> {
        [
            self.index_serialization,
            self.typed_archive,
            self.administrative,
            self.owner_receipts,
            self.manifest_serialization,
            self.typed_manifests,
            self.known_core_decoding,
            self.archive_io,
        ]
        .into_iter()
        .try_fold(0usize, add)
    }

    pub(super) fn admit(&self, maximum: usize) -> Result<(), RuntimeError> {
        if self.total()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
}

/// Conjoins conservative capture accounting extents without a text multiplier.
///
/// Each term comes from its owning core/source walker before effects. Terms
/// can overlap: the cached host snapshot also appears in its selected-source
/// row. Keeping both charges is conservative; this is not a unique-backing
/// allocation census. Complete coverage and source codec qualification remain
/// separate obligations, and this sum cannot issue capture authority.
pub(super) struct CompleteCaptureAllocationPeak {
    pub current_core: usize,
    pub original_payloads: usize,
    pub cached_preflight: usize,
    pub registered_history: usize,
    pub planned_geometry: usize,
    pub attempt_construction: usize,
    pub inventory_preparation: usize,
    pub future_metadata: usize,
    pub future_content: usize,
    pub selected_sources: usize,
}

/// Retains a writer-derived finite total without exporting parsed authority.
///
/// Only the closed archive writer can issue this value after its named sum.
/// The original runtime/plan/cut association remains in the geometry seal.
/// The budget includes the actual live runtime's independently owned backing,
/// beyond the portable snapshots and future metadata. Its original owner loan
/// must still be current immediately before the capture geometry is sealed.
pub(crate) struct CompleteCaptureAllocationBudget {
    runtime_identity: crate::node_contract::OriginalRuntimeStorageIdentity,
    writer_total: usize,
    runtime_owned: usize,
    runtime_observer_scratch: usize,
    total: usize,
    maximum: usize,
}

impl CompleteCaptureAllocationBudget {
    pub(crate) fn authenticate(&self, maximum: usize) -> Result<(), RuntimeError> {
        let total = add(
            self.writer_total,
            add(self.runtime_owned, self.runtime_observer_scratch)?,
        )?;
        if maximum != self.maximum || self.total != total || total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    /// Rechecks the same live runtime without expanding its admitted owner row.
    pub(super) fn authenticate_runtime(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        self.runtime_identity.authenticate(runtime)?;
        self.authenticate(self.maximum)?;
        let actual = runtime.original_retained_requested_storage_data(self.runtime_owned)?;
        if actual > self.runtime_owned {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
}

impl CompleteCaptureAllocationPeak {
    /// Issues a writer budget only after walking the actual live runtime.
    ///
    /// Portable Runtime7/Scheduling snapshots are separate owned copies. Their
    /// named terms cannot replace live nodes, process/SDK capsules, activations
    /// or original supervision. Observer scratch is admitted before the walk;
    /// only the remaining simultaneous credit is available to its real owners.
    pub(super) fn issue_budget(
        &self,
        runtime: &NodeRuntime,
        maximum: usize,
        content_maximum: usize,
    ) -> Result<CompleteCaptureAllocationBudget, RuntimeError> {
        let runtime_identity = runtime.original_retained_storage_identity()?;
        let writer_total = self.total()?;
        let runtime_observer_scratch =
            NodeRuntime::original_retained_requested_storage_scratch_bytes();
        let available = maximum
            .min(content_maximum)
            .checked_sub(add(writer_total, runtime_observer_scratch)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        let runtime_owned = runtime.original_retained_requested_storage_data(available)?;
        let total = add(writer_total, add(runtime_observer_scratch, runtime_owned)?)?;
        if total > maximum || total > content_maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        runtime_identity.authenticate(runtime)?;
        Ok(CompleteCaptureAllocationBudget {
            runtime_identity,
            writer_total,
            runtime_owned,
            runtime_observer_scratch,
            total,
            maximum,
        })
    }

    pub(super) fn total(&self) -> Result<usize, RuntimeError> {
        [
            self.current_core,
            self.original_payloads,
            self.cached_preflight,
            self.registered_history,
            self.planned_geometry,
            self.attempt_construction,
            self.inventory_preparation,
            self.future_metadata,
            self.future_content,
            self.selected_sources,
        ]
        .into_iter()
        .try_fold(0usize, add)
    }

    pub(super) fn admit(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let total = self.total()?;
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }
}

/// Bounds the new verifier's payload banks beside the original callback banks.
///
/// Objects currently live on disk; a later closure read creates independent
/// owned Vecs. Core emits four receipts plus admin/guarantees/provenance/manifest.
/// Snapshot/settlement bodies are bounded by each actual source row's admitted
/// retained extent, even if this conservatively counts non-payload allocations.
pub(super) fn projected_future_content_banks(
    known_disk_bytes: usize,
    known_largest_object: usize,
    core_bodies: (usize, usize),
    owners: &super::CompleteOriginalCaptureGeometry,
    limits: super::super::StateLimits,
) -> Result<usize, RuntimeError> {
    let native = owners
        .owners
        .iter()
        .try_fold(0usize, |bytes, row| add(bytes, row.maximum_retained_bytes))?;
    let core = core_bodies.0;
    let retained = add(known_disk_bytes, add(native, core)?)?;
    // storage::read_file reserves the stat length, then read_to_end can grow
    // through its maximum+1 bounded reader if the file changes. That failure
    // still allocates before validation. One sequential largest read retains
    // cumulative old/new Vec requests beside the already verified closure.
    let largest_native = owners
        .owners
        .iter()
        .map(|row| row.maximum_record_bytes)
        .max()
        .unwrap_or(0);
    let largest = known_largest_object.max(largest_native).max(core_bodies.1);
    let read_ceiling = add(largest, 1)?;
    let sequential_read = add(multiply(read_ceiling, 4)?, 8)?;
    let requested = add(retained, sequential_read)?;
    if requested > limits.maximum_total_content_bytes {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

#[cfg(test)]
mod tests {
    // These tests compare inert serialized metadata shapes. They do not issue
    // native actors, capture geometry, archive signatures or restore authority.
    use super::super::storage::{Index, NativeOwnerState, Object};
    use super::*;
    use crucible_node_contract::Phase;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn original_request_spare_id_banks_refuse_before_preparation() {
        let mut capture = String::with_capacity(256 * 1024);
        capture.push_str("capture");
        let capture = Id::new(capture).unwrap();
        let mut contract = String::with_capacity(512 * 1024);
        contract.push_str("source-owned.packet-complete-original-lineage/5");
        let requirements = crate::node_state::StateRequirements {
            preservation_contract: Id::new(contract).unwrap(),
            exact_model_continuation: true,
            deterministic: false,
            restore_mode: crate::node_state::StateRestoreMode::DurableRestart,
        };
        let actual = capture.allocated_capacity()
            + requirements.preservation_contract.allocated_capacity()
            + std::mem::size_of::<Id>()
            + std::mem::size_of::<crate::node_state::StateRequirements>();
        assert_eq!(
            original_request_storage(&capture, &requirements, actual),
            Ok(actual)
        );
        assert_eq!(
            original_request_storage(&capture, &requirements, actual - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(actual >= 768 * 1024);
    }

    #[test]
    fn named_data_total_refuses_one_short_without_issuing_a_runtime_budget() {
        // Arithmetic data alone cannot construct the writer's owning budget.
        let peak = allocation_peak();
        assert_eq!(peak.admit(55), Ok(55));
        assert_eq!(peak.admit(54), Err(RuntimeError::ResourceLimit));
    }

    fn allocation_peak() -> CompleteCaptureAllocationPeak {
        CompleteCaptureAllocationPeak {
            current_core: 1,
            original_payloads: 2,
            cached_preflight: 3,
            registered_history: 4,
            planned_geometry: 5,
            attempt_construction: 6,
            inventory_preparation: 7,
            future_metadata: 8,
            future_content: 9,
            selected_sources: 10,
        }
    }

    #[test]
    fn actual_unknown_runtime_cannot_issue_budget_or_lose_original_owners()
    -> Result<(), RuntimeError> {
        // This real Core fixture owns modeled nodes with unsupported erased
        // backing. Its portable snapshots cannot authorize a whole budget.
        let (runtime, _) = crate::node_contract::test_capture_ticket_fixture();
        let before = runtime.original_capture_journal()?;
        let peak = allocation_peak();
        let result = peak.issue_budget(&runtime, 64 * 1024 * 1024, 64 * 1024 * 1024);
        assert!(matches!(result, Err(RuntimeError::UnsupportedFacet)));
        assert_eq!(runtime.original_capture_journal()?, before);
        Ok(())
    }

    #[test]
    fn named_budget_retains_exact_bound_and_refuses_reinterpretation() -> Result<(), RuntimeError> {
        // These are genuine admitted Core owners with a closed, initial-only
        // model data observer. No native codec or Capture outcome is qualified.
        let (runtime, control) = crate::node_contract::test_known_initial_storage_fixture();
        let peak = allocation_peak();
        let runtime_bytes = runtime.original_retained_requested_storage_data(64 * 1024 * 1024)?;
        let scratch = NodeRuntime::original_retained_requested_storage_scratch_bytes();
        let exact = add(peak.total()?, add(runtime_bytes, scratch)?)?;
        let before = runtime.original_capture_journal()?;
        let effects = control.effect_counts();

        let budget = peak.issue_budget(&runtime, exact, exact)?;

        assert_eq!(budget.runtime_owned, runtime_bytes);
        assert_eq!(budget.runtime_observer_scratch, scratch);
        assert_eq!(budget.total, exact);
        budget.authenticate(exact)?;
        budget.authenticate_runtime(&runtime)?;
        let (foreign, _) = crate::node_contract::test_known_initial_storage_fixture();
        assert_eq!(
            budget.authenticate_runtime(&foreign),
            Err(RuntimeError::ForeignAuthority)
        );
        assert_eq!(
            budget.authenticate(exact - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(
            budget.authenticate(exact + 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(matches!(
            peak.issue_budget(&runtime, exact - 1, exact),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(matches!(
            peak.issue_budget(&runtime, exact, exact - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(runtime.original_capture_journal()?, before);
        assert_eq!(control.effect_counts(), effects);

        // Even an empty model output Vec with real spare backing is outside
        // this initial-only owner class. Neither issuance nor requery may turn
        // that new unsupported allocation into zero, discard it or mutate work.
        control.reserve_output_bank();
        assert_eq!(
            budget.authenticate_runtime(&runtime),
            Err(RuntimeError::UnsupportedFacet)
        );
        assert!(matches!(
            peak.issue_budget(&runtime, 64 * 1024 * 1024, 64 * 1024 * 1024),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert_eq!(runtime.original_capture_journal()?, before);
        assert_eq!(control.effect_counts(), effects);
        Ok(())
    }

    #[test]
    fn runtime_observer_scratch_is_admitted_before_unknown_owners_are_walked() {
        let (runtime, _) = crate::node_contract::test_capture_ticket_fixture();
        let peak = allocation_peak();
        let exact = 55 + NodeRuntime::original_retained_requested_storage_scratch_bytes();
        // One byte short fails before the real runtime walker can reach its
        // unsupported modeled node, and neither whole ceiling is substituted.
        assert!(matches!(
            peak.issue_budget(&runtime, exact - 1, usize::MAX),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(matches!(
            peak.issue_budget(&runtime, usize::MAX, exact - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(runtime.original_capture_journal().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_reference_shapes_bound_valid_json_escaping() {
        use crucible_node_contract::Validate;

        let reference = maximum_reference();
        reference.validate().unwrap();
        let mut plain = reference.clone();
        plain.media_type = "x".repeat(128);
        assert_eq!(
            encoded_extent(&reference, usize::MAX).unwrap(),
            encoded_extent(&plain, usize::MAX).unwrap() + 128,
        );

        let hash = maximum_hash();
        hash.validate().unwrap();
        let mut plain = hash.clone();
        plain.domain = "x".repeat(128);
        assert_eq!(
            encoded_extent(&hash, usize::MAX).unwrap(),
            encoded_extent(&plain, usize::MAX).unwrap() + 5 * 128,
        );
    }

    #[test]
    fn future_record_ceiling_checks_largest_body_not_aggregate_bytes() {
        let credit = EncodedBodyCredit {
            bytes: 8192,
            largest: 2048,
        };
        assert_eq!(credit.authenticate_record_ceiling(2048), Ok(()));
        assert_eq!(
            credit.authenticate_record_ceiling(2047),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(projected_archive_io_storage().is_ok_and(|bytes| bytes > 64 * 1024));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encoded_closed_shape_count_matches_canonical_extent_before_allocation() {
        let position = Position::new(U64::new(u64::MAX), U64::new(7), Phase::Publication);
        let value = ("quoted\"\n\t\\é", U64::new(u64::MAX), position);
        let bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(value).unwrap(),
        )
        .unwrap();
        let counted = encoded_extent(&value, bytes.len()).unwrap();
        assert_eq!(counted, bytes.len());
        assert_eq!(
            encoded_extent(&value, counted - 1),
            Err(RuntimeError::ResourceLimit)
        );
        let mut credit = EncodedBodyCredit::default();
        credit.charge(&value, 3, counted).unwrap();
        assert_eq!(credit.bytes, counted * 3);
        assert_eq!(credit.largest, counted);
    }

    #[test]
    fn future_content_banks_keep_original_and_sequential_read_extents_distinct() {
        let mut limits = crate::node_state::StateLimits {
            maximum_record_bytes: 1024,
            maximum_content_bytes: 64 * 1024 * 1024,
            ..Default::default()
        };
        let plan = super::super::CompleteOriginalCaptureGeometry { owners: Vec::new() };
        let expected = 17 + 8 * 1024 + 4 * (4096 + 1) + 8;
        limits.maximum_total_content_bytes = expected;
        assert_eq!(
            projected_future_content_banks(17, 4096, (8 * 1024, 1024), &plan, limits),
            Ok(expected)
        );
        limits.maximum_total_content_bytes -= 1;
        assert_eq!(
            projected_future_content_banks(17, 4096, (8 * 1024, 1024), &plan, limits),
            Err(RuntimeError::ResourceLimit)
        );
        limits.maximum_total_content_bytes = usize::MAX;
        assert_eq!(
            projected_future_content_banks(usize::MAX, 4096, (8 * 1024, 1024), &plan, limits),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn known_core_decode_banks_conjoin_original_nonempty_record_layout() {
        // Historical source1 readonly data is only an inert closed-layout input.
        // It supplies no Host2/native5 capture or restoration authority.
        let bytes =
            include_bytes!("core_decode_credit/fixtures/nonempty-readonly-continuation2.json");
        let limits = crate::node_contract::HostSchedulingContinuationLimits {
            maximum_record_bytes: 8 * 1024 * 1024,
            lineage: crate::node_contract::OriginalInputLineageLimits::default(),
        };
        let record =
            crate::node_contract::HostSchedulingContinuationRecord::decode(bytes, limits).unwrap();
        let crate::node_contract::HostSchedulingRuntimeRecord::OriginalLineage(runtime) =
            &record.runtime
        else {
            panic!("fixture must retain its original Runtime7 kind");
        };
        let runtime_bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(runtime).unwrap(),
        )
        .unwrap();
        let scheduling_bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&record.scheduling).unwrap(),
        )
        .unwrap();
        let requested = projected_known_core_decoding(
            runtime,
            &record.scheduling,
            &runtime_bytes,
            &scheduling_bytes,
            limits.lineage,
            512 * 1024 * 1024,
        )
        .unwrap();
        let owned = add(
            NodeRuntime::capture_runtime_record_storage(runtime).unwrap(),
            NodeRuntime::capture_scheduling_record_storage(&record.scheduling).unwrap(),
        )
        .unwrap();
        assert!(requested >= owned);
        assert_eq!(
            projected_known_core_decoding(
                runtime,
                &record.scheduling,
                &runtime_bytes,
                &scheduling_bytes,
                limits.lineage,
                requested - 1
            ),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_owner_receipts_charge_inventory_and_both_record_passes() {
        let cut = Position::new(U64::new(6), U64::new(1), Phase::Publication);
        let reference = maximum_reference();
        let id = Id::new("x".repeat(128)).unwrap();
        let key = NativeStateKey {
            implementation: id.clone(),
            profile: id.clone(),
            schema: SchemaRef {
                id: id.clone(),
                version: u16::MAX,
                definition: reference.clone(),
                extensions: Default::default(),
            },
        };
        let domains = vec![id.clone(); 6];
        let mut actual = 0;
        for count in [2usize, 256, 257, 1024] {
            let native = NativeOwnerState {
                owner: id.clone(),
                participants: vec![id.clone()],
                key: key.clone(),
                cut,
                state: reference.clone(),
                evidence: vec![reference.clone(); count + 1],
                artifacts: vec![],
            };
            let receipt = super::super::lineage_capture::OwnerReceipt {
                schema_version: 1,
                owner: &id,
                inventory: maximum_hash(),
                coordinator: &reference,
                cut,
                ordinal: U64::new(u64::MAX),
                domains: &domains,
            };
            actual = add(
                actual,
                NodeRuntime::capture_serialization_storage(&native, 512 * 1024 * 1024).unwrap(),
            )
            .unwrap();
            actual = add(
                actual,
                multiply(
                    NodeRuntime::capture_serialization_storage(&receipt, 512 * 1024 * 1024)
                        .unwrap(),
                    2,
                )
                .unwrap(),
            )
            .unwrap();
        }
        let needed =
            projected_owner_receipt_serialization(cut, &[2, 256, 257, 1024], 6, 512 * 1024 * 1024)
                .unwrap();
        assert!(needed >= actual);
        assert_eq!(
            projected_owner_receipt_serialization(cut, &[2, 256, 257, 1024], 6, needed - 1),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn future_decoder_shape_bounds_actual_closed_owner_receipt() {
        let id = Id::new("x".repeat(128)).unwrap();
        let reference = maximum_reference();
        let domains = vec![id.clone(); 6];
        let receipt = super::super::lineage_capture::OwnerReceipt {
            schema_version: 1,
            owner: &id,
            inventory: maximum_hash(),
            coordinator: &reference,
            cut: Position::new(
                U64::new(u64::MAX),
                U64::new(u64::MAX),
                Phase::BoundaryControl,
            ),
            ordinal: U64::new(u64::MAX),
            domains: &domains,
        };
        let bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&receipt).unwrap(),
        )
        .unwrap();
        let actual = super::super::core_decode_credit::preflight(&bytes, 512 * 1024 * 1024)
            .unwrap()
            .total()
            .unwrap();
        let projected =
            NodeRuntime::capture_future_decode_storage(&receipt, 512 * 1024 * 1024).unwrap();
        assert!(
            projected >= actual,
            "future {projected} below actual lexical decoder {actual}"
        );
        assert_eq!(
            NodeRuntime::capture_future_decode_storage(&receipt, projected - 1),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_manifest_has_named_finite_serialization_passes() {
        let cut = Position::new(
            U64::new(u64::MAX),
            U64::new(u64::MAX),
            Phase::BoundaryControl,
        );
        let requested =
            projected_manifest_serialization(6, 2, cut, 128, 512 * 1024 * 1024).unwrap();
        assert!(requested > 0);
        let typed = projected_typed_manifest_storage(6, 2, 128, 512 * 1024 * 1024).unwrap();
        assert!(typed > 0);
        assert_eq!(
            projected_typed_manifest_storage(6, 2, 128, typed - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(
            projected_manifest_serialization(usize::MAX, 2, cut, 128, 512 * 1024 * 1024),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_typed_metadata_checks_the_complete_final_sum() {
        let needed = projected_typed_archive_storage(&[8; 4], 128, 256, 512 * 1024 * 1024).unwrap();
        assert!(needed > 0);
        assert_eq!(
            projected_typed_archive_storage(&[8; 4], 128, 256, needed - 1),
            Err(RuntimeError::ResourceLimit),
        );
        assert_eq!(
            projected_typed_archive_storage(&[usize::MAX; 4], 128, 256, usize::MAX),
            Err(RuntimeError::ResourceLimit),
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_index_covers_actual_paged_owner_and_dependency_shapes() {
        for count in [1usize, 256, 257, 1024] {
            let id = Id::new("x".repeat(128)).unwrap();
            let reference = maximum_reference();
            let key = NativeStateKey {
                implementation: id.clone(),
                profile: id.clone(),
                schema: SchemaRef {
                    id: id.clone(),
                    version: u16::MAX,
                    definition: reference.clone(),
                    extensions: Default::default(),
                },
            };
            let cut = Position::new(
                U64::new(u64::MAX),
                U64::new(u64::MAX),
                Phase::BoundaryControl,
            );
            let owners = vec![
                NativeOwnerState {
                    owner: id.clone(),
                    participants: vec![id],
                    key,
                    cut,
                    state: reference.clone(),
                    evidence: vec![reference.clone(); count],
                    artifacts: vec![]
                };
                4
            ];
            let index = Index {
                schema_version: 3,
                artifact: reference.clone(),
                objects: vec![
                    Object {
                        reference: reference.clone(),
                        dependencies: vec![reference.clone(); count]
                    };
                    3
                ],
                owners,
                selected_extensions: None,
                original_capture_journal: Some(reference),
            };
            let actual =
                NodeRuntime::capture_serialization_storage(&index, 512 * 1024 * 1024).unwrap();
            let projected = projected_owner_serialization(
                cut,
                &[count; 4],
                3,
                3 * count,
                8 * 1024 * 1024,
                512 * 1024 * 1024,
            )
            .unwrap();
            assert!(projected >= actual);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn projected_administration_has_finite_lifetime_shape() {
        let needed = projected_administrative_serialization(512 * 1024 * 1024).unwrap();
        assert!(needed > 0);
        assert_eq!(
            projected_administrative_serialization(needed - 1),
            Err(RuntimeError::ResourceLimit)
        );
    }
}
