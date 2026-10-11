//! Preserves original public Script/Block preparation beside native custody.
//!
//! Selected envelope nine references the exact original public barrier, model
//! session and Ready bodies. The older native envelope remains an unchanged
//! dependency. This reader accepts only authenticated original archive content;
//! its inventory remains data until a fresh installed factory owns restoration.
//!
//! ```text
//! format: crucible.host.public-owned-model-continuation
//! schema_version: 9
//! node, native_state, world_preparation, session, ready,
//! native_ready, original_model: exact original identities or full ContentRefs
//! previous: required null or exact prior authenticated envelope ContentRef
//! ```

use super::*;
use crate::node_adapters::preparation_state::OriginalWorldPreparation;
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{SchemaRef, U64};
use serde::{Deserialize, Serialize};

#[path = "ancestry.rs"]
mod ancestry;

#[derive(Serialize)]
struct BorrowedActivation<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: &'a [OwnerIdentity],
    boundary: Position,
}

pub(in crate::node_adapters::host) struct PreservedOwnedModelPreparation {
    pub(super) original: InputPayload,
    pub(super) evidence: Vec<InputPayload>,
    pub(super) target: ActivationRecord,
    pub(super) target_credit: usize,
}

impl HostModelNode {
    /// Restores exact finite-model native custody from its authenticated public source.
    ///
    /// The actual target model remains owned by this node before validation or
    /// native restoration. Original preparation bodies stay retained separately
    /// from fresh ownership; no historical Ready token becomes a new permit.
    ///
    /// # Errors
    /// Refuses foreign graph, source, model or target scope, used preparation,
    /// missing installed model qualification, incomplete original signed bodies,
    /// or bounded native restoration and retention failures.
    pub fn prepare_public_owned_model_continuation(
        &mut self,
        graph: &AdmittedGraph,
        source: &crate::node_state::AuthenticatedNativeSource<'_>,
        target: &ActivationRecord,
        installed: &dyn HostModelQualification,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        if graph.world_binding_hash() != &self.world_hash
            || graph.binding(&self.route.node) != Some(&self.binding)
            || graph.descriptor(&self.route.node) != Some(&self.descriptor)
            || self.public_model_preparation.is_some()
            || self.public_model_history.is_some()
            || self.readiness.is_some()
            || target.owners.is_empty()
            || target.owners.len() > 64
            || target
                .owners
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
            || !self
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
            || !self
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&host_public_owned_model_continuation_schema()?)
            || !matches!(self.model.as_ref(), Some(HostModel::ScriptedSource(script)) if script.kind() == super::super::super::ScriptedRequestKind::Block)
                && !matches!(self.model.as_ref(), Some(HostModel::Io(model)) if model.block_device().is_some())
        {
            return Err(failure(
                "public finite-model restoration has another target or selected codec",
            ));
        }
        let target_credit = borrowed_length(
            &BorrowedActivation {
                generation: target.generation,
                activation_id: &target.activation_id,
                world_binding_hash: &target.world_binding_hash,
                owners: &target.owners,
                boundary: target.boundary,
            },
            self.limits.maximum_capture_bytes,
        )?;
        let inventory = validate_with_target_credit(
            source,
            graph,
            &self.route.node,
            self.limits,
            target_credit,
        )?;
        let outer = source
            .native()
            .map_err(|error| failure(&error.to_string()))?;
        let wire: Wire = decode(outer, self.limits.maximum_capture_bytes)?;
        let native = source
            .content()
            .get(&wire.native_state)
            .ok_or_else(|| failure("authenticated finite-model native dependency disappeared"))?;
        let retained = inventory.evidence.iter().try_fold(
            outer
                .len()
                .checked_add(target_credit)
                .ok_or_else(|| failure("finite-model target retention overflows"))?,
            |total, body| {
                total
                    .checked_add(body.bytes.len())
                    .ok_or_else(|| failure("finite-model source retention overflows"))
            },
        )?;
        if retained > self.limits.maximum_capture_bytes {
            return Err(failure(
                "finite-model source history exceeds original retention credit",
            ));
        }
        let qualifier = OriginalModelQualification {
            installed,
            source,
            native,
            target,
        };
        // Retain the complete historical capsule before an effect-capable native
        // restore; errors leave these bytes with the same owning model.
        self.public_model_history = Some(PreservedOwnedModelPreparation {
            original: InputPayload {
                reference: source.owner().state.clone(),
                bytes: outer.to_vec(),
            },
            evidence: inventory.evidence,
            target: target.clone(),
            target_credit,
        });
        let proof = self.prepare_continuation(native, source.runtime(), target, &qualifier)?;
        if let Err(mut error) = self.retain_restored_owned_model_preparation(target) {
            // The original native restore has already succeeded. Retain its
            // capsule and quarantine rather than describing this as no effect.
            self.quarantined = true;
            error.effects = EffectKnowledge::Unknown;
            return Err(error);
        }
        Ok(proof)
    }
}

struct OriginalModelQualification<'a, 'b> {
    installed: &'a dyn HostModelQualification,
    source: &'a crate::node_state::AuthenticatedNativeSource<'b>,
    native: &'a [u8],
    target: &'a ActivationRecord,
}

impl HostModelQualification for OriginalModelQualification<'_, '_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.installed
            .authenticate_model(model, descriptor, binding)
    }

    fn authenticate_continuation(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
        native: &[u8],
        runtime: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        // Source equality cannot replace the independently installed factory's
        // default-refusing continuation decision.
        InstalledContinuationRequest {
            model,
            descriptor,
            binding,
            native,
            runtime,
            target,
        }
        .authenticate(self.installed)?;
        self.authenticate_model(model, descriptor, binding)?;
        if self.source.owner().participants.as_slice() != std::slice::from_ref(&descriptor.id)
            || native != self.native
            || runtime != self.source.runtime()
            || target != self.target
            || target.boundary != runtime.capture_cut
            || target.world_binding_hash != runtime.source_activation.world_binding_hash
            || target.generation <= runtime.source_activation.generation
            || target.activation_id == runtime.source_activation.activation_id
        {
            return Err(failure(
                "finite-model native restoration differs from original source and fresh target",
            ));
        }
        Ok(())
    }
}

pub(super) struct InstalledContinuationRequest<'a> {
    pub(super) model: &'a HostModel,
    pub(super) descriptor: &'a NodeDescriptor,
    pub(super) binding: &'a NodeBinding,
    pub(super) native: &'a [u8],
    pub(super) runtime: &'a RuntimeSnapshot,
    pub(super) target: &'a ActivationRecord,
}

impl InstalledContinuationRequest<'_> {
    pub(super) fn authenticate(
        &self,
        installed: &dyn HostModelQualification,
    ) -> Result<(), OperationFailure> {
        installed.authenticate_continuation(
            self.model,
            self.descriptor,
            self.binding,
            self.native,
            self.runtime,
            self.target,
        )
    }
}

impl HostModelNode {
    pub(in crate::node_adapters::host) fn capture_public_owned_model(
        &mut self,
        activation: &WorldActivation,
        runtime: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        let schema = host_public_owned_model_continuation_schema()?;
        let preparation = self
            .public_model_preparation
            .as_ref()
            .ok_or_else(|| failure("public finite-model capture omits actual preparation"))?;
        let (original, ready, ready_bytes) = preparation
            .ready
            .as_ref()
            .ok_or_else(|| failure("public finite-model capture omits original Ready"))?;
        if !self
            .binding
            .compatibility
            .implementation
            .formats
            .contains(&schema)
            || !self.same_world(activation)
            || original != activation.record()
            || match (
                &preparation.previous,
                &self.public_model_history,
                self.preparation_origin,
            ) {
                (None, None, HostPreparationOrigin::Original) => false,
                (Some(previous), Some(history), HostPreparationOrigin::Restored) => {
                    previous != &history.original.reference || &history.target != original
                }
                _ => true,
            }
            || !Rc::ptr_eq(&preparation.anchor, &self.original_model_session)
            || self
                .readiness
                .as_ref()
                .is_none_or(|(world, receipt)| world != original || receipt != ready)
            || !matches!(self.model.as_ref(), Some(HostModel::ScriptedSource(source)) if source.kind() == super::super::super::ScriptedRequestKind::Block)
                && !matches!(self.model.as_ref(), Some(HostModel::Io(model)) if model.block_device().is_some())
        {
            return Err(failure(
                "public finite-model capture has another actual source or codec",
            ));
        }
        preparation
            .initial_native
            .verify(self.initial.as_slice())
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .session
            .verify(&preparation.session_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .native_ready
            .verify(&preparation.native_ready_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        ready
            .ready_receipt
            .verify(ready_bytes)
            .map_err(|error| failure(&error.to_string()))?;

        let prepared_owners = activation
            .prepared_owners()
            .ok_or_else(|| failure("public finite-model capture omits the all-owner barrier"))?;
        let coordinator = activation
            .coordinator_snapshot()
            .ok_or_else(|| failure("public finite-model capture omits original coordinator"))?;
        if activation.node_preparations().len() > 64 || prepared_owners.len() > 64 {
            return Err(failure(
                "public finite-model barrier exceeds participant credit",
            ));
        }
        // The record and publication contain subsets of this borrowed complete
        // barrier, twice, plus fixed format/reference headers. Reserve that
        // conservative geometry before the shared helper clones its records.
        let geometry = borrowed_length(
            &(
                BorrowedActivation {
                    generation: activation.record().generation,
                    activation_id: &activation.record().activation_id,
                    world_binding_hash: &activation.record().world_binding_hash,
                    owners: &activation.record().owners,
                    boundary: activation.record().boundary,
                },
                activation.node_preparations(),
                prepared_owners,
            ),
            limits.maximum_total_record_bytes,
        )?;
        let barrier_credit = geometry
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| failure("public finite-model barrier geometry overflows"))?;
        let leaves = [
            preparation.session_bytes.as_slice(),
            preparation.native_ready_bytes.as_slice(),
            ready_bytes.as_slice(),
            self.initial.as_slice(),
            coordinator.bytes.as_slice(),
        ];
        let historical = self
            .public_model_history
            .as_ref()
            .map_or(Ok(0), |history| {
                if history.original.bytes.len() > limits.maximum_record_bytes {
                    return Err(failure(
                        "public finite-model original envelope exceeds record credit",
                    ));
                }
                history
                    .evidence
                    .iter()
                    .try_fold(history.original.bytes.len(), |total, body| {
                        if body.bytes.len() > limits.maximum_record_bytes {
                            return Err(failure(
                                "public finite-model ancestor exceeds record credit",
                            ));
                        }
                        total
                            .checked_add(body.bytes.len())
                            .ok_or_else(|| failure("public finite-model ancestry credit overflows"))
                    })
            })?;
        let history_objects = self
            .public_model_history
            .as_ref()
            .map_or(0, |history| history.evidence.len() + 1);
        let extra = leaves
            .iter()
            .try_fold(barrier_credit, |total, bytes| {
                if bytes.len() > limits.maximum_record_bytes {
                    return Err(failure(
                        "public finite-model preparation leaf exceeds record credit",
                    ));
                }
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| failure("public finite-model preparation credit overflows"))
            })?
            .checked_add(historical)
            .ok_or_else(|| failure("public finite-model historical aggregate credit overflows"))?
            .checked_add(limits.maximum_record_bytes)
            .ok_or_else(|| failure("public finite-model outer record credit overflows"))?;
        let mut inner_limits = limits;
        inner_limits.maximum_total_record_bytes = limits
            .maximum_total_record_bytes
            .checked_sub(extra)
            .ok_or_else(|| failure("public finite-model preparation exhausts aggregate credit"))?;
        inner_limits.maximum_record_bytes = inner_limits
            .maximum_record_bytes
            .min(inner_limits.maximum_total_record_bytes);
        inner_limits.maximum_objects =
            limits
                .maximum_objects
                .checked_sub(9usize.checked_add(history_objects).ok_or_else(|| {
                    failure("public finite-model ancestry object credit overflows")
                })?)
                .ok_or_else(|| failure("public finite-model preparation exhausts object credit"))?;

        let (world, record, coordinator, publication) =
            OriginalWorldPreparation::capture(activation, limits.maximum_record_bytes)?;
        if record
            .bytes
            .len()
            .checked_add(publication.bytes.len())
            .is_none_or(|total| total > barrier_credit)
            || world.node(&self.route.node)?.ready_receipt != ready.ready_receipt
        {
            return Err(failure(
                "public finite-model barrier differs from reserved original geometry",
            ));
        }
        let inner =
            state::capture_live(self, activation, runtime, inner_limits.maximum_record_bytes)?;
        let mut capture = InstalledNativeCapture::from_host(
            inner,
            &self.descriptor,
            &self.binding,
            runtime.capture_cut,
            inner_limits,
        )?;
        let wire = Wire {
            format: "crucible.host.public-owned-model-continuation".to_owned(),
            schema_version: 9,
            node: self.route.node.clone(),
            native_state: capture.state.reference.clone(),
            world_preparation: record.reference.clone(),
            session: preparation.session.clone(),
            ready: ready.ready_receipt.clone(),
            native_ready: preparation.native_ready.clone(),
            original_model: preparation.initial_native.clone(),
            previous: preparation.previous.clone(),
        };
        let bytes = crate::node_adapters::preparation_state::bounded_preparation_json(
            &wire,
            limits.maximum_record_bytes,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        let additions = [
            InputPayload {
                reference: preparation.session.clone(),
                bytes: preparation.session_bytes.clone(),
            },
            InputPayload {
                reference: preparation.native_ready.clone(),
                bytes: preparation.native_ready_bytes.clone(),
            },
            InputPayload {
                reference: ready.ready_receipt.clone(),
                bytes: ready_bytes.clone(),
            },
            InputPayload {
                reference: preparation.initial_native.clone(),
                bytes: self.initial.as_ref().clone(),
            },
            record,
            coordinator,
            publication,
        ];
        capture
            .evidence
            .try_reserve_exact(additions.len() + history_objects + 1)
            .map_err(|_| failure("public finite-model evidence reservation failed"))?;
        capture.evidence.push(capture.state);
        let history = self
            .public_model_history
            .iter()
            .flat_map(|history| std::iter::once(&history.original).chain(&history.evidence));
        for object in additions.into_iter().chain(history.cloned()) {
            match capture
                .evidence
                .iter()
                .find(|old| old.reference.hash == object.reference.hash)
            {
                Some(old) if old != &object => {
                    return Err(failure(
                        "public finite-model evidence has another typed original body",
                    ));
                }
                Some(_) => {}
                None => capture.evidence.push(object),
            }
        }
        capture.state = InputPayload { reference, bytes };
        capture.key.profile = Id::new(HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE)
            .map_err(|error| failure(&error.to_string()))?;
        capture.key.schema = schema;
        Ok(capture)
    }
}

fn borrowed_length(value: &impl Serialize, maximum: usize) -> Result<usize, OperationFailure> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("public model barrier budget exhausted"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(maximum);
    serde_json::to_writer(&mut counter, value).map_err(|error| failure(&error.to_string()))?;
    Ok(maximum - counter.0)
}

/// Names the distinct preparation-bearing finite-model preservation profile.
pub const HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE: &str =
    "host/public-owned-model-preservation-v1";

/// Defines the source-owned original public finite-model envelope grammar.
pub const HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION: &str = "Host native envelope9: exact original independently owned finite Block-request Script or Block/COW model; unchanged complete host-native1 state, operations, input ACKs, FIFO and original scheduling payloads; original public owned-model session, initialized state, raw native Ready, common Ready, complete public world preparation/coordinator/publication and exact original owner binding; restored private owning preparation remains distinct from initial realization; required nullable predecessor retains at most64 strictly decreasing preparation generations, exact historical native initial model and immutable complete bodies under aggregate byte/object credit; locally authenticated full native archive and independently qualified fresh factory required; no physical ingress, Compute, 9p, aliases, fork or replay authority";

/// Returns the separately selected original finite-model preservation schema.
///
/// # Errors
/// Refuses invalid identifiers or specification content construction.
pub fn host_public_owned_model_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("host/public-owned-model-continuation-v1")
            .map_err(|error| failure(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| failure(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    node: Id,
    native_state: ContentRef,
    world_preparation: ContentRef,
    session: ContentRef,
    ready: ContentRef,
    native_ready: ContentRef,
    original_model: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    previous: Option<ContentRef>,
}

fn validate_wire_scope(wire: &Wire, node: &Id) -> Result<(), OperationFailure> {
    if wire.format != "crucible.host.public-owned-model-continuation"
        || wire.schema_version != 9
        || &wire.node != node
    {
        return Err(failure(
            "public model continuation has a foreign envelope edition",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    world_hash: HashRef,
    node: Id,
    owners: Vec<OwnerIdentity>,
    binding: HashRef,
    initialization: ContentRef,
    initial_native_state: ContentRef,
    original_native_ready: ContentRef,
    complete_original_owners: Vec<OwnerIdentity>,
    #[serde(default)]
    source_preparation: Option<ContentRef>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<ContentRef>, D::Error> {
    Option::<ContentRef>::deserialize(decoder)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    world: SavedRuntimeActivation,
    session: ContentRef,
    initial_native_state: ContentRef,
    original_native_ready: ContentRef,
    inventory: ContentRef,
    boundary: Position,
    owners: Vec<OwnerIdentity>,
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, OperationFailure> {
    if bytes.len() > maximum {
        return Err(failure(
            "public model preparation exceeds original record credit",
        ));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let record = T::deserialize(&mut decoder)
        .map_err(|_| failure("public model preparation has unsupported closed fields"))?;
    decoder
        .end()
        .map_err(|_| failure("public model preparation has trailing bytes"))?;
    Ok(record)
}

fn body<'a>(
    source: &'a crate::node_state::AuthenticatedNativeSource<'_>,
    reference: &ContentRef,
    remaining: &mut usize,
) -> Result<&'a [u8], OperationFailure> {
    if !source.owner().evidence.contains(reference) {
        return Err(failure(
            "public model preparation is outside its signed owner closure",
        ));
    }
    let bytes = source
        .content()
        .get(reference)
        .ok_or_else(|| failure("signed public model preparation body is missing"))?;
    reference
        .verify(bytes)
        .map_err(|error| failure(&error.to_string()))?;
    *remaining = remaining
        .checked_sub(bytes.len())
        .ok_or_else(|| failure("public model preparation exhausts original aggregate credit"))?;
    Ok(bytes)
}

/// Validates original public finite-model preparation under a signed native source.
///
/// This function checks historical data only. It neither constructs a model nor
/// supplies fresh ownership, readiness, admission or an execution permission.
///
/// # Errors
/// Refuses a foreign selected codec, changed original preparation or binding,
/// missing signed bodies, excessive byte credit, incomplete native operations,
/// or a mismatched source world, owner, initial model or Ready receipt.
pub fn validate_public_owned_model_continuation(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    graph: &AdmittedGraph,
    node: &Id,
    limits: HostModelResources,
) -> Result<HostContinuationInventory, OperationFailure> {
    validate_with_target_credit(source, graph, node, limits, 0)
}

fn validate_with_target_credit(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    graph: &AdmittedGraph,
    node: &Id,
    limits: HostModelResources,
    target_credit: usize,
) -> Result<HostContinuationInventory, OperationFailure> {
    let descriptor = graph
        .descriptor(node)
        .ok_or_else(|| failure("public model continuation descriptor is absent"))?;
    let binding = graph
        .binding(node)
        .ok_or_else(|| failure("public model continuation binding is absent"))?;
    let schema = host_public_owned_model_continuation_schema()?;
    let owner = source.owner();
    if owner.key.profile.as_str() != HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE
        || owner.key.schema != schema
        || !binding
            .compatibility
            .implementation
            .formats
            .contains(&schema)
        || owner.key.implementation != binding.compatibility.implementation.implementation_id
        || owner.owner != binding.compatibility.capture_owner.id
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || !owner.artifacts.is_empty()
        || source.runtime().source_activation.world_binding_hash != *graph.world_binding_hash()
        || source.archive().manifest().world_binding_hash != *graph.world_binding_hash()
        || !matches!(
            binding
                .compatibility
                .implementation
                .implementation_id
                .as_str(),
            "crucible-host-scripted-source" | "crucible-host-block"
        )
    {
        return Err(failure(
            "public model continuation selects another installed source scope",
        ));
    }
    let outer = source
        .native()
        .map_err(|error| failure(&error.to_string()))?;
    let wire: Wire = decode(outer, limits.maximum_capture_bytes)?;
    validate_wire_scope(&wire, node)?;

    // Charge the entire signed owner closure before either native inspection
    // or ancestry retention copies a body. This conservative association count
    // includes bodies later shared by both inventories; deduplication cannot
    // create additional credit. The largest verified body reserves the native
    // model's separately retained inventory association. Fresh target geometry
    // consumes the same budget; parser temporaries are not this credit metric.
    precredit_retention(
        outer.len(),
        target_credit,
        owner.evidence.iter().map(|reference| {
            let bytes = source
                .content()
                .get(reference)
                .ok_or_else(|| failure("signed public model dependency is missing"))?;
            reference
                .verify(bytes)
                .map_err(|error| failure(&error.to_string()))?;
            Ok(bytes.len())
        }),
        limits.maximum_capture_bytes,
    )?;
    let original = ancestry::authenticate(source, descriptor, limits.maximum_capture_bytes)?;
    let native = source
        .content()
        .get(&original.native)
        .ok_or_else(|| failure("authenticated public finite-model native body disappeared"))?;
    let mut inventory =
        validate_host_continuation(native, source.runtime(), descriptor, binding, limits)?;
    for object in std::iter::once(&inventory.native_model).chain(&inventory.evidence) {
        if !owner.evidence.contains(&object.reference)
            || source.content().get(&object.reference) != Some(object.bytes.as_slice())
        {
            return Err(failure(
                "public model signed source omits actual native state or receipts",
            ));
        }
    }
    if inventory.boundary != owner.cut {
        return Err(failure(
            "public model native boundary differs from signed original cut",
        ));
    }
    let references = original.references;
    inventory
        .evidence
        .try_reserve_exact(references.len())
        .map_err(|_| failure("public model preparation evidence reservation failed"))?;
    for reference in references {
        if inventory
            .evidence
            .iter()
            .any(|object| object.reference == reference)
        {
            continue;
        }
        let bytes = source
            .content()
            .get(&reference)
            .ok_or_else(|| failure("precredited public model source body disappeared"))?;
        inventory.evidence.push(InputPayload {
            reference,
            bytes: bytes.to_vec(),
        });
    }
    Ok(inventory)
}

fn precredit_retention(
    outer: usize,
    target: usize,
    bodies: impl IntoIterator<Item = Result<usize, OperationFailure>>,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    let initial = outer
        .checked_add(target)
        .ok_or_else(|| failure("finite-model combined retention credit overflows"))?;
    let (total, largest) =
        bodies
            .into_iter()
            .try_fold((initial, 0), |(total, largest), length| {
                let length = length?;
                let largest = largest.max(length);
                let total = total
                    .checked_add(length)
                    .ok_or_else(|| failure("finite-model combined retention credit overflows"))?;
                if total
                    .checked_add(largest)
                    .is_none_or(|total| total > maximum)
                {
                    return Err(failure(
                        "finite-model combined source and target exceed retention credit",
                    ));
                }
                Ok((total, largest))
            })?;
    let total = total
        .checked_add(largest)
        .ok_or_else(|| failure("finite-model native model association credit overflows"))?;
    if total > maximum {
        return Err(failure(
            "finite-model combined source and target exceed retention credit",
        ));
    }
    Ok(total)
}

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;
