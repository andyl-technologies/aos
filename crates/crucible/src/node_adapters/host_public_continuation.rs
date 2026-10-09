//! Preserves actual public Clock preparation beside its original native envelope.
//!
//! Historical session and coordinator bodies remain source data. A reconstructed
//! clock is authenticated against the selected installed model, restored from its
//! exact native envelope, and given an independently owned fresh preparation.

use super::*;
use crate::node_adapters::preparation_state::OriginalWorldPreparation;
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{Extensions, SchemaRef};
use serde::{Deserialize, Serialize};

/// Names the selected complete public Clock preservation profile.
pub const HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE: &str = "host/public-clock-preservation-v1";

/// Defines original public Clock preparation and coordinator preservation.
pub const HOST_PUBLIC_CLOCK_CONTINUATION_SPECIFICATION: &str = "host public clock continuation v1: unchanged exact native host-v1 envelope and original native model/operation/input bodies; actual committed public preparation/coordinator bytes; original memory-session/native-ready/common-ready and complete owner-binding roster; fresh restored Clock ownership and explicit installed source authentication; restored construction never passes initial realization, including at zero; exact source preparation ancestry remains immutable through independent fresh public publication";

/// Returns the source-owned preparation-bearing Clock schema.
///
/// # Errors
/// Refuses invalid format identities or content construction failure.
pub fn host_public_clock_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/host-public-clock-continuation-v1")
            .map_err(|error| failure(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            HOST_PUBLIC_CLOCK_CONTINUATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| failure(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

/// Names the distinct preparation and original-scheduling-epoch preservation edition.
pub const HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE: &str = "host/public-clock-preservation-v2";

/// Returns the selected scheduler-epoch-bearing wrapper schema.
///
/// # Errors
/// Refuses invalid schema identities or specification content construction.
pub fn host_public_clock_epoch_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    let specification = format!(
        "{}; edition2 additionally binds separately signed original scheduling epoch objects under {}",
        HOST_PUBLIC_CLOCK_CONTINUATION_SPECIFICATION,
        crate::node_scheduling::SCHEDULING_EPOCH_POLICY_SPECIFICATION
    );
    Ok(SchemaRef {
        id: Id::new("crucible/host-public-clock-continuation-v2")
            .map_err(|error| failure(&error.to_string()))?,
        version: 2,
        definition: canonical::content_ref(specification.as_bytes(), "text/plain")
            .map_err(|error| failure(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    node: Id,
    native_state: ContentRef,
    world_preparation: ContentRef,
    ready: ContentRef,
    native_ready: ContentRef,
    native_session: ContentRef,
    original_model: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    previous: Option<ContentRef>,
}

struct AuthenticatedClockPreparation {
    native: InputPayload,
    envelope: InputPayload,
    runtime: RuntimeSnapshot,
    history: Vec<InputPayload>,
}

/// Validates selected signed Clock preparation and its complete native ledger.
///
/// The returned inventory contains historical data only. Actual target model
/// ownership, installed qualification and fresh readiness remain mandatory.
///
/// # Errors
/// Refuses another installed backend/schema, missing original preparation bodies,
/// inconsistent source scope, incomplete native receipts or a foreign graph.
pub fn validate_public_clock_continuation(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    graph: &AdmittedGraph,
    node: &Id,
    resources: HostModelResources,
) -> Result<HostContinuationInventory, OperationFailure> {
    let original = authenticate_clock_preparation(source, node, resources.maximum_capture_bytes)?;
    let descriptor = graph
        .descriptor(node)
        .ok_or_else(|| failure("public Clock descriptor absent"))?;
    let binding = graph
        .binding(node)
        .ok_or_else(|| failure("public Clock binding absent"))?;
    if source.runtime().source_activation.world_binding_hash != *graph.world_binding_hash()
        || binding
            .compatibility
            .implementation
            .implementation_id
            .as_str()
            != "crucible-host-clock"
        || !binding
            .compatibility
            .implementation
            .formats
            .iter()
            .any(|schema| {
                schema.id.as_str() == "crucible/host-public-clock-continuation-v1"
                    || schema.id.as_str() == "crucible/host-public-clock-continuation-v2"
            })
    {
        return Err(failure(
            "public Clock source differs from installed selected graph",
        ));
    }
    let inventory = validate_host_continuation(
        &original.native.bytes,
        source.runtime(),
        descriptor,
        binding,
        resources,
    )?;
    if inventory.boundary != source.owner().cut
        || source.content().get(&inventory.native_model.reference)
            != Some(inventory.native_model.bytes.as_slice())
        || !source
            .owner()
            .evidence
            .contains(&inventory.native_model.reference)
        || inventory.evidence.iter().any(|body| {
            source.content().get(&body.reference) != Some(body.bytes.as_slice())
                || !source.owner().evidence.contains(&body.reference)
        })
    {
        return Err(failure(
            "public Clock source omits its original native model or receipts",
        ));
    }
    Ok(inventory)
}

impl HostModelNode {
    /// Restores a selected public Clock without staging or reevaluating original work.
    ///
    /// Authentication consumes the locally verified source capability. Historical
    /// packet or token hashes cannot construct a fresh clock or readiness receipt.
    ///
    /// # Errors
    /// Refuses foreign codec/model/body/lineage, incomplete signed closure, a
    /// changed fresh target, or unavailable installed continuation policy.
    pub fn prepare_public_clock_continuation(
        &mut self,
        graph: &AdmittedGraph,
        source: &crate::node_state::AuthenticatedNativeSource<'_>,
        target: &ActivationRecord,
        installed: &dyn HostModelQualification,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        if !matches!(self.model.as_ref(), Some(HostModel::Clock(_)))
            || !self
                .binding
                .compatibility
                .implementation
                .formats
                .iter()
                .any(|schema| {
                    schema.id.as_str() == "crucible/host-public-clock-continuation-v1"
                        || schema.id.as_str() == "crucible/host-public-clock-continuation-v2"
                })
            || graph.world_binding_hash() != &self.world_hash
            || graph.binding(&self.route.node) != Some(&self.binding)
            || self.public_preparation.is_some()
        {
            return Err(failure(
                "public restored Clock does not select its installed preparation codec",
            ));
        }
        let authenticated = authenticate_clock_preparation(
            source,
            &self.route.node,
            self.limits.maximum_capture_bytes,
        )?;
        let qualifier = OriginalPublicClockQualification {
            installed,
            original: &authenticated,
            target,
        };
        let proof = self.prepare_continuation(
            &authenticated.native.bytes,
            source.runtime(),
            target,
            &qualifier,
        )?;
        let initial_model = canonical::content_ref(&self.initial, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        self.retain_public_clock_session(Some(authenticated.envelope.reference), initial_model)?;
        let preparation = self
            .public_preparation
            .as_mut()
            .ok_or_else(|| failure("restored Clock lost its fresh owning session"))?;
        preparation.history = authenticated.history;
        self.public_continuation = true;
        Ok(proof)
    }

    pub(super) fn capture_public_clock(
        &mut self,
        activation: &WorldActivation,
        runtime: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        if !self.public_continuation
            || !self.same_world(activation)
            || !matches!(self.model.as_ref(), Some(HostModel::Clock(_)))
        {
            return Err(failure(
                "public Clock capture lacks its actual selected activation",
            ));
        }
        let preparation = self
            .public_preparation
            .as_ref()
            .ok_or_else(|| failure("public Clock capture omits its owning preparation"))?;
        let (record_world, record, coordinator, publication) =
            OriginalWorldPreparation::capture(activation, limits.maximum_record_bytes)?;
        let node = record_world.node(&self.route.node)?;
        let (world, ready, ready_bytes) = preparation
            .ready
            .as_ref()
            .ok_or_else(|| failure("public Clock capture omits its exact readiness body"))?;
        if world != activation.record() || ready.ready_receipt != node.ready_receipt {
            return Err(failure(
                "public Clock capture changed its committed preparation",
            ));
        }
        let original_model = canonical::content_ref(&self.initial, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        let extra = [
            preparation.session_bytes.as_slice(),
            preparation.native_ready_bytes.as_slice(),
            ready_bytes.as_slice(),
            self.initial.as_slice(),
            record.bytes.as_slice(),
            coordinator.bytes.as_slice(),
            publication.bytes.as_slice(),
        ]
        .into_iter()
        .chain(
            preparation
                .history
                .iter()
                .map(|object| object.bytes.as_slice()),
        )
        .try_fold(limits.maximum_record_bytes, |total, bytes| {
            if bytes.len() > limits.maximum_record_bytes {
                return Err(failure(
                    "public Clock preparation leaf exceeds native record credit",
                ));
            }
            total
                .checked_add(bytes.len())
                .ok_or_else(|| failure("public Clock preparation credit overflows"))
        })?;
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
                reference: original_model.clone(),
                bytes: self.initial.as_ref().clone(),
            },
            record.clone(),
            coordinator,
            publication,
        ];
        let mut inner_limits = limits;
        inner_limits.maximum_total_record_bytes = limits
            .maximum_total_record_bytes
            .checked_sub(extra)
            .ok_or_else(|| failure("public Clock preparation has no reserved byte credit"))?;
        inner_limits.maximum_record_bytes = inner_limits
            .maximum_record_bytes
            .min(inner_limits.maximum_total_record_bytes);
        inner_limits.maximum_objects = limits
            .maximum_objects
            .checked_sub(additions.len() + preparation.history.len() + 2)
            .ok_or_else(|| failure("public Clock preparation has no reserved object credit"))?;
        let host =
            state::capture_live(self, activation, runtime, inner_limits.maximum_record_bytes)?;
        let mut capture = InstalledNativeCapture::from_host(
            host,
            &self.descriptor,
            &self.binding,
            runtime.capture_cut,
            inner_limits,
        )?;
        let epochs = self
            .binding
            .compatibility
            .implementation
            .formats
            .contains(&host_public_clock_epoch_continuation_schema()?);
        let wire = Wire {
            format: "crucible.host.public-clock-continuation".to_owned(),
            schema_version: if epochs { 2 } else { 1 },
            node: self.route.node.clone(),
            native_state: capture.state.reference.clone(),
            world_preparation: record.reference,
            ready: ready.ready_receipt.clone(),
            native_ready: preparation.native_ready.clone(),
            native_session: preparation.session.clone(),
            original_model,
            previous: preparation.previous.clone(),
        };
        let bytes = bounded_public_json(&wire, limits.maximum_record_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        capture
            .evidence
            .try_reserve(additions.len() + preparation.history.len() + 1)
            .map_err(|_| failure("public Clock evidence allocation exceeds object credit"))?;
        capture.evidence.push(capture.state);
        for object in additions
            .into_iter()
            .chain(preparation.history.iter().cloned())
        {
            if let Some(existing) = capture
                .evidence
                .iter()
                .find(|old| old.reference.hash == object.reference.hash)
            {
                if existing != &object {
                    return Err(failure(
                        "public Clock preparation collides with original typed evidence",
                    ));
                }
            } else {
                capture.evidence.push(object);
            }
        }
        capture.state = InputPayload { reference, bytes };
        capture.key.profile = Id::new(if epochs {
            HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE
        } else {
            HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE
        })
        .map_err(|error| failure(&error.to_string()))?;
        capture.key.schema = if epochs {
            host_public_clock_epoch_continuation_schema()?
        } else {
            host_public_clock_continuation_schema()?
        };
        Ok(capture)
    }
}

fn authenticate_clock_preparation(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    node: &Id,
    maximum: usize,
) -> Result<AuthenticatedClockPreparation, OperationFailure> {
    let owner = source.owner();
    let epochs = owner.key.profile.as_str() == HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE;
    let schema = if epochs {
        host_public_clock_epoch_continuation_schema()?
    } else {
        host_public_clock_continuation_schema()?
    };
    if owner.key.implementation.as_str() != "crucible-host-clock"
        || (!epochs && owner.key.profile.as_str() != HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE)
        || owner.key.schema != schema
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || !owner.artifacts.is_empty()
    {
        return Err(failure(
            "public Clock source selects another complete native codec",
        ));
    }
    let bytes = source
        .native()
        .map_err(|error| failure(&error.to_string()))?;
    let reference = canonical::content_ref(bytes, "application/json")
        .map_err(|error| failure(&error.to_string()))?;
    let envelope = InputPayload {
        reference,
        bytes: bytes.to_vec(),
    };
    let object = |reference: &ContentRef| {
        if !owner.evidence.contains(reference) {
            return Err(failure(
                "public Clock preparation body is absent from its signed owner inventory",
            ));
        }
        let bytes = source.content().get(reference).ok_or_else(|| {
            failure("public Clock preparation body is absent from authenticated content")
        })?;
        reference
            .verify(bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if bytes.len() > maximum {
            return Err(failure(
                "public Clock source leaf exceeds installed byte credit",
            ));
        }
        Ok(InputPayload {
            reference: reference.clone(),
            bytes: bytes.to_vec(),
        })
    };
    let mut history = BTreeMap::new();
    history.insert(envelope.reference.clone(), envelope.clone());
    let mut current = envelope.clone();
    let mut previous_generation = None;
    let mut native = None;
    for depth in 0..64 {
        let wire: Wire = decode_public_json(&current.bytes, maximum)?;
        if wire.format != "crucible.host.public-clock-continuation"
            || wire.schema_version != if epochs { 2 } else { 1 }
            || &wire.node != node
        {
            return Err(failure(
                "public Clock preparation backend, node or edition differs",
            ));
        }
        let world_body = object(&wire.world_preparation)?;
        let world = OriginalWorldPreparation::decode(&world_body.bytes, maximum)?;
        let prepared = world.node(node)?;
        world.validate_publication(&object(&world.publication)?.bytes, maximum)?;
        if prepared.ready_receipt != wire.ready
            || prepared.owners.len() != 1
            || prepared.prepared_owners.len() != 1
            || previous_generation
                .is_some_and(|generation| world.activation.generation >= generation)
            || (depth == 0 && world.activation != source.runtime().source_activation)
        {
            return Err(failure(
                "public Clock preparation differs from original committed scope",
            ));
        }
        previous_generation = Some(world.activation.generation);
        let session = object(&wire.native_session)?;
        let session: ClockSession = decode_public_json(&session.bytes, maximum)?;
        let common: ClockReady = decode_public_json(&object(&wire.ready)?.bytes, maximum)?;
        let owner = &prepared.owners[0];
        let mut native_ready = b"host-model-owned-inactive-v1".to_vec();
        native_ready.extend_from_slice(&world.activation.boundary.time_ps.get().to_le_bytes());
        native_ready.extend_from_slice(owner.owner.as_str().as_bytes());
        native_ready.push(0);
        native_ready.extend_from_slice(owner.incarnation.as_str().as_bytes());
        native_ready.extend_from_slice(&owner.generation.get().to_le_bytes());
        let token = Id::new(format!("host/prepared/{}", wire.native_session.hash.digest))
            .map_err(|error| failure(&error.to_string()))?;
        let origin_matches = match (
            &wire.previous,
            session.format.as_str(),
            &session.source_preparation,
        ) {
            (None, "crucible.host.original-clock-session", None) => true,
            (Some(previous), "crucible.host.restored-clock-session", Some(source)) => {
                previous == source
            }
            _ => false,
        };
        if !origin_matches
            || session.version != 1
            || session.original_native_ready != wire.native_ready
            || session.node != *node
            || session.world_hash != world.activation.world_binding_hash
            || session.owners != prepared.owners
            || session.initial_model != wire.original_model
            || prepared.prepared_owners[0].prepared_token != token
            || prepared.prepared_owners[0].binding_hashes.as_slice()
                != std::slice::from_ref(&session.binding)
            || common.format != "crucible.host.public-clock-ready"
            || common.version != 1
            || common.world != world.activation
            || common.session != wire.native_session
            || common.inventory != prepared.state_inventory
            || common.boundary != prepared.boundary
            || common.owners != prepared.owners
            || common.original_native_ready != wire.native_ready
            || object(&wire.native_ready)?.bytes != native_ready
            || object(&wire.original_model)?.bytes
                != host_clock_initial_bytes(world.activation.boundary.time_ps.get())
        {
            return Err(failure(
                "public Clock session does not bind its original Ready, native model and owner",
            ));
        }
        for reference in [
            &wire.native_state,
            &wire.world_preparation,
            &wire.ready,
            &wire.native_ready,
            &wire.native_session,
            &wire.original_model,
            &world.coordinator,
            &world.publication,
        ] {
            let original = object(reference)?;
            history.insert(reference.clone(), original);
        }
        if depth == 0 {
            native = Some(object(&wire.native_state)?);
        }
        let Some(previous) = wire.previous else {
            return Ok(AuthenticatedClockPreparation {
                native: native
                    .ok_or_else(|| failure("public Clock source native state is absent"))?,
                envelope,
                runtime: source.runtime().clone(),
                history: history.into_values().collect(),
            });
        };
        if depth == 63 {
            return Err(failure(
                "public Clock preparation ancestry exceeds installed generation credit",
            ));
        }
        current = object(&previous)?;
        history.insert(previous, current.clone());
    }
    Err(failure(
        "public Clock preparation ancestry credit exhausted",
    ))
}

struct OriginalPublicClockQualification<'a> {
    installed: &'a dyn HostModelQualification,
    original: &'a AuthenticatedClockPreparation,
    target: &'a ActivationRecord,
}

impl HostModelQualification for OriginalPublicClockQualification<'_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if !matches!(model, HostModel::Clock(_)) {
            return Err(failure(
                "public Clock source cannot authenticate another host model",
            ));
        }
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
        self.authenticate_model(model, descriptor, binding)?;
        if native != self.original.native.bytes
            || runtime != &self.original.runtime
            || target != self.target
            || target.boundary != runtime.capture_cut
            || target.world_binding_hash != runtime.source_activation.world_binding_hash
            || target.generation <= runtime.source_activation.generation
        {
            return Err(failure(
                "public Clock continuation differs from authenticated original source or fresh target",
            ));
        }
        Ok(())
    }
}

fn bounded_public_json(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, OperationFailure> {
    crate::node_adapters::preparation_state::bounded_preparation_json(value, maximum)
}

fn decode_public_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, OperationFailure> {
    let value =
        canonical::parse_json(bytes, maximum).map_err(|error| failure(&error.to_string()))?;
    if canonical::canonical_json(&value).map_err(|error| failure(&error.to_string()))? != bytes {
        return Err(failure(
            "public Clock codec changed original canonical bytes",
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| failure("public Clock codec has unsupported closed fields"))
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockSession {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    world_hash: HashRef,
    node: Id,
    owners: Vec<OwnerIdentity>,
    binding: HashRef,
    initial_model: ContentRef,
    original_native_ready: ContentRef,
    #[serde(default)]
    source_preparation: Option<ContentRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockReady {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    world: SavedRuntimeActivation,
    session: ContentRef,
    inventory: ContentRef,
    boundary: Position,
    owners: Vec<OwnerIdentity>,
    original_native_ready: ContentRef,
}
