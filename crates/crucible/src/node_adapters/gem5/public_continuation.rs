//! Preserves actual public preparation beneath a distinct native owner codec.
//!
//! The envelope points to the unchanged native-v2 record and original committed
//! public barrier bodies. Those are signed source history; independently restored
//! process custody and fresh opaque authority remain necessary for readiness.

use crucible_node_contract::{ContentRef, Extensions, HashRef, Id, SchemaRef, U64, canonical};
use crucible_node_provider::gem5::Gem5Boundary;
use serde::{Deserialize, Serialize};

use crate::{
    node_adapters::preparation_state::OriginalWorldPreparation, node_contract::*,
    node_scheduling::InputPayload,
};

use super::{QualifiedGem5Node, node::native_refusal, refusal};

/// Names the installed preparation-bearing process preservation profile.
pub const GEM5_PUBLIC_CONTINUATION_PROFILE: &str = "gem5/public-process-preservation-v1";

/// Defines complete original preparation retention beside unchanged native state.
pub const GEM5_PUBLIC_CONTINUATION_SPECIFICATION: &str = "crucible/gem5-public-native-continuation-v1: unchanged complete native-v2 state and image/resource roster; original actually committed whole-world preparation and exact coordinator body; original native Ready packet/session and common readiness body; complete binding/owner roster; signed historical bodies grant no initial or fresh authority; every reconstructed peer retains Restored constructor provenance and requires its own unchanged-cut image audit/current exact authority; complete restored public publication binds actual fresh preparations to authenticated original runtime/coordinator custody";

/// Returns the preparation-bearing native schema without granting authority.
///
/// # Errors
/// Refuses invalid schema identifiers or content construction failure.
pub fn gem5_public_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/gem5-public-native-continuation-v1")
            .map_err(|error| refusal(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            GEM5_PUBLIC_CONTINUATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| refusal(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

/// Names the distinct preparation and original-scheduling-epoch preservation edition.
pub const GEM5_PUBLIC_EPOCH_CONTINUATION_PROFILE: &str = "gem5/public-process-preservation-v2";

/// Returns the selected scheduler-epoch-bearing wrapper schema.
///
/// # Errors
/// Refuses invalid schema identities or specification content construction.
pub fn gem5_public_epoch_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    let specification = format!(
        "{}; edition2 additionally binds separately signed original scheduling epoch objects under {}",
        GEM5_PUBLIC_CONTINUATION_SPECIFICATION,
        crate::node_scheduling::SCHEDULING_EPOCH_POLICY_SPECIFICATION
    );
    Ok(SchemaRef {
        id: Id::new("crucible/gem5-public-native-continuation-v2")
            .map_err(|error| refusal(&error.to_string()))?,
        version: 2,
        definition: canonical::content_ref(specification.as_bytes(), "text/plain")
            .map_err(|error| refusal(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicWire {
    pub format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    pub node: Id,
    pub native_state: ContentRef,
    pub world_preparation: ContentRef,
    pub ready: ContentRef,
    pub native_ready: ContentRef,
    pub native_session: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    pub previous: Option<ContentRef>,
}

pub(super) struct AuthenticatedPublicPreparation {
    pub wire: PublicWire,
    pub world: OriginalWorldPreparation,
    pub envelope: InputPayload,
    pub history: Vec<InputPayload>,
}

impl QualifiedGem5Node {
    /// Selects the independently installed preparation-bearing preservation edition.
    ///
    /// Original native birth is still required. The installed graph must explicitly
    /// select both the legacy native mechanism and this new complete owner codec.
    /// The returned failure keeps actual process and supervisory custody.
    ///
    /// # Errors
    /// Refuses reconstructed or already armed peers, missing archive installation,
    /// foreign schema/bindings, or unavailable independent preparation policy.
    pub fn into_public_preserving_initial_preparation(
        mut self,
        graph: &crate::node_admission::AdmittedGraph,
        qualification: &dyn super::Gem5PreparationQualification,
    ) -> Result<Self, Box<super::Gem5PublicPreparationFailure>> {
        let validate = || {
            if self.archive.is_none()
                || self.restored.is_some()
                || self.world.is_some()
                || self.active.is_some()
                || self.quarantined
                || !graph.selected_extensions().is_empty()
                || graph.world_binding_hash() != &self.preparation.world_binding_hash
                || graph.binding(&self.preparation.route.node) != Some(&self.preparation.binding)
                || !(self
                    .preparation
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&gem5_public_continuation_schema()?)
                    || self
                        .preparation
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&gem5_public_epoch_continuation_schema()?))
            {
                return Err(refusal(
                    "public gem5 preservation is not its selected installed initial profile",
                ));
            }
            qualification.authenticate_preparation(
                &self.preparation.native,
                graph,
                &self.preparation.route.node,
            )?;
            self.preparation
                .native
                .initial_prepared_session(&self.authority)
                .map_err(native_refusal)?;
            Ok(())
        };
        if let Err(error) = validate() {
            return Err(Box::new(super::Gem5PublicPreparationFailure {
                error,
                node: self,
            }));
        }
        self.public_preparation = true;
        self.public_continuation = true;
        Ok(self)
    }

    pub(super) fn capture_public_installed(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        if !self.public_continuation || !self.same_world(activation) {
            return Err(refusal(
                "public native capture lacks selected original activation custody",
            ));
        }
        let mapping = self
            .prepared_mapping
            .as_ref()
            .ok_or_else(|| refusal("public native capture omits its actual preparation mapping"))?;
        let (world, record, coordinator, publication) =
            OriginalWorldPreparation::capture(activation, limits.maximum_record_bytes)?;
        let prepared = world.node(&self.preparation.route.node)?;
        if prepared.ready_receipt != mapping.ready.ready_receipt
            || prepared.prepared_owners != mapping.owners
            || mapping.world != *activation.record()
        {
            return Err(refusal(
                "public capture changed its actually committed original mapping",
            ));
        }
        // History access reads only the originally retained packet/transcript. It
        // neither reruns initial admission nor grants current execution authority.
        let session = self
            .preparation
            .native
            .preparation_history()
            .map_err(native_refusal)?;
        let (packet, packet_bytes) = session.packet();
        let (transcript, transcript_bytes) = session.transcript();
        if packet != &mapping.original_packet || transcript != &mapping.original_session {
            return Err(refusal(
                "public capture lost its original owning native session",
            ));
        }
        let epochs = self
            .preparation
            .binding
            .compatibility
            .implementation
            .formats
            .contains(&gem5_public_epoch_continuation_schema()?);
        let wire = PublicWire {
            format: "crucible.gem5.public-native-continuation".to_owned(),
            schema_version: if epochs { 2 } else { 1 },
            node: self.preparation.route.node.clone(),
            // Filled after genuine capture; reserve its complete maximum before
            // invoking the mechanical native hook rather than allocating late.
            native_state: record.reference.clone(),
            world_preparation: record.reference.clone(),
            ready: prepared.ready_receipt.clone(),
            native_ready: packet.clone(),
            native_session: transcript.clone(),
            previous: self
                .restored
                .as_ref()
                .and_then(|source| source.public_preparation.as_ref())
                .map(|original| original.envelope.reference.clone()),
        };
        let envelope_credit = limits.maximum_record_bytes;
        let inner_total = limits
            .maximum_total_record_bytes
            .checked_sub(envelope_credit)
            .ok_or_else(|| refusal("public envelope has no preallocated record credit"))?;
        self.ledger.retain_standalone(&[
            (&record.reference, &record.bytes),
            (&coordinator.reference, &coordinator.bytes),
            (&publication.reference, &publication.bytes),
            (packet, packet_bytes),
            (transcript, transcript_bytes),
        ])?;
        let mut inner_limits = limits;
        inner_limits.maximum_total_record_bytes = inner_total;
        inner_limits.maximum_objects = limits
            .maximum_objects
            .checked_sub(1)
            .ok_or_else(|| refusal("public envelope has no preallocated object credit"))?;
        let profile = Id::new(if epochs {
            GEM5_PUBLIC_EPOCH_CONTINUATION_PROFILE
        } else {
            GEM5_PUBLIC_CONTINUATION_PROFILE
        })
        .map_err(|error| refusal(&error.to_string()))?;
        let schema = if epochs {
            gem5_public_epoch_continuation_schema()?
        } else {
            gem5_public_continuation_schema()?
        };
        // The inner hook retains its original image and seal before returning a
        // fallible copy. Once entered, no local error proves native no-effects.
        let mut captured = self
            .capture_installed(activation, source, inner_limits)
            .map_err(capture_uncertainty)?;
        let mut wire = wire;
        wire.native_state = captured.state.reference.clone();
        let envelope = prepare_public_envelope(&wire, envelope_credit, || {
            captured
                .evidence
                .try_reserve(1)
                .map_err(|_| refusal("public evidence allocation exceeds reserved object credit"))
        })?;

        // Finish all fallible wrapping before moving the original state. On an
        // error, the adapter's retained capture supplies an identical-cut retry.
        let original = std::mem::replace(&mut captured.state, envelope);
        captured.evidence.push(original);
        captured.key.profile = profile;
        captured.key.schema = schema;
        Ok(captured)
    }
}

// This helper owns no native custody. Its caller keeps the already captured
// image and original seal while serialization and evidence allocation can fail.
fn prepare_public_envelope(
    wire: &PublicWire,
    maximum_bytes: usize,
    reserve_evidence: impl FnOnce() -> Result<(), OperationFailure>,
) -> Result<InputPayload, OperationFailure> {
    let prepare = || {
        let bytes = super::capture::bounded_canonical(wire, maximum_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        reserve_evidence()?;
        Ok(InputPayload { reference, bytes })
    };
    prepare().map_err(capture_uncertainty)
}

fn capture_uncertainty(mut failure: OperationFailure) -> OperationFailure {
    failure.effects = EffectKnowledge::Unknown;
    failure
}

#[cfg(test)]
#[path = "public_continuation_tests.rs"]
mod tests;

pub(super) fn decode_public_preparation(
    bytes: &[u8],
    source: &RuntimeSnapshot,
    node: &Id,
    evidence: &[InputPayload],
) -> Result<AuthenticatedPublicPreparation, OperationFailure> {
    let value = canonical::parse_json(bytes, 16 * 1024 * 1024)
        .map_err(|error| refusal(&error.to_string()))?;
    if canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))? != bytes {
        return Err(refusal(
            "public native envelope is not exact canonical source bytes",
        ));
    }
    let wire: PublicWire = serde_json::from_value(value)
        .map_err(|_| refusal("public native envelope has unsupported closed fields"))?;
    if wire.format != "crucible.gem5.public-native-continuation"
        || !matches!(wire.schema_version, 1 | 2)
        || &wire.node != node
    {
        return Err(refusal(
            "public native envelope backend, node or edition differs",
        ));
    }
    let object = |reference: &ContentRef| {
        evidence
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| refusal("public native original preparation body is absent"))
    };
    for reference in [
        &wire.native_state,
        &wire.world_preparation,
        &wire.ready,
        &wire.native_ready,
        &wire.native_session,
    ] {
        let object = object(reference)?;
        reference
            .verify(&object.bytes)
            .map_err(|error| refusal(&error.to_string()))?;
    }
    let world = OriginalWorldPreparation::decode(
        &object(&wire.world_preparation)?.bytes,
        16 * 1024 * 1024,
    )?;
    let prepared = world.node(node)?;
    if world.activation != source.source_activation || prepared.ready_receipt != wire.ready {
        return Err(refusal(
            "public native source preparation differs from original world activation",
        ));
    }
    let original_publication = object(&world.publication)?;
    world.validate_publication(&original_publication.bytes, 16 * 1024 * 1024)?;
    let coordinator = object(&world.coordinator)?;
    world
        .coordinator
        .verify(&coordinator.bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    let session: NativeSession = serde_json::from_value(
        canonical::parse_json(&object(&wire.native_session)?.bytes, 4 * 1024 * 1024)
            .map_err(|error| refusal(&error.to_string()))?,
    )
    .map_err(|_| refusal("public native session has unsupported closed fields"))?;
    let packet: NativeReady = serde_json::from_value(
        canonical::parse_json(&object(&wire.native_ready)?.bytes, 4 * 1024 * 1024)
            .map_err(|error| refusal(&error.to_string()))?,
    )
    .map_err(|_| refusal("public native Ready has unsupported closed fields"))?;
    let common: CommonReady = serde_json::from_value(
        canonical::parse_json(&object(&wire.ready)?.bytes, 4 * 1024 * 1024)
            .map_err(|error| refusal(&error.to_string()))?,
    )
    .map_err(|_| refusal("public common Ready has unsupported closed fields"))?;
    let actual_token = Id::new(format!("gem5/prepared/{}", wire.native_session.hash.digest))
        .map_err(|error| refusal(&error.to_string()))?;
    let owner = prepared
        .owners
        .first()
        .filter(|_| prepared.owners.len() == 1)
        .ok_or_else(|| refusal("public native preparation has an incomplete owner roster"))?;
    if session.format != "crucible.gem5.native-preparation-session"
        || session.version != 1
        || session.pid == 0
        || session.start_ticks.is_empty()
        || session.start_ticks.len() > 32
        || !session
            .start_ticks
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || session.ready_packet != wire.native_ready
        || session.owner != owner.owner
        || session.incarnation != owner.incarnation
        || session.generation != owner.generation
        || packet.kind != "ready"
        || packet.schema != "crucible.gem5.native/2"
        || packet.owner != owner.owner
        || packet.incarnation != owner.incarnation
        || packet.generation != owner.generation
        || packet.continuation != session.origin
        || !matches!(
            (session.origin.as_str(), &session.source_capture),
            ("original", None) | ("restored", Some(_))
        )
        || common.schema != "crucible.gem5.common-readiness.v1"
        || common.activation != world.activation.activation_id
        || common.world_generation != world.activation.generation
        || common.world_hash != world.activation.world_binding_hash
        || common.owners != prepared.owners
        || common.boundary != packet.boundary
        || (session.origin == "original" && common.boundary.logical_position != prepared.boundary)
        || common.independent_closure != prepared.state_inventory
        || prepared.prepared_owners.len() != 1
        || prepared.prepared_owners[0].prepared_token != actual_token
    {
        return Err(refusal(
            "public native source session does not bind its original packet, cut and owner",
        ));
    }
    let original_closure = object(&common.independent_closure)?;
    common
        .independent_closure
        .verify(&original_closure.bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    // The source scope is data authenticated by the installed native importer;
    // validating its portable representation cannot mint execution authority.
    for reference in [&session.controller, &session.model] {
        crucible_node_contract::Validate::validate(reference)
            .map_err(|error| refusal(&error.to_string()))?;
    }
    crucible_node_contract::Validate::validate(&session.launch_scope)
        .map_err(|error| refusal(&error.to_string()))?;
    let reference = canonical::content_ref(bytes, "application/json")
        .map_err(|error| refusal(&error.to_string()))?;
    let envelope = InputPayload {
        reference,
        bytes: bytes.to_vec(),
    };
    let history = preparation_history(&wire, &envelope, evidence)?;
    Ok(AuthenticatedPublicPreparation {
        wire,
        world,
        envelope,
        history,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSession {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    origin: String,
    #[serde(deserialize_with = "required_nullable")]
    source_capture: Option<Id>,
    pid: u32,
    start_ticks: String,
    launch_scope: HashRef,
    controller: ContentRef,
    model: ContentRef,
    owner: Id,
    incarnation: Id,
    generation: U64,
    ready_packet: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeReady {
    kind: String,
    schema: String,
    owner: Id,
    incarnation: Id,
    generation: U64,
    continuation: String,
    boundary: Gem5Boundary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonReady {
    schema: String,
    activation: Id,
    world_generation: U64,
    world_hash: HashRef,
    owners: Vec<OwnerIdentity>,
    boundary: Gem5Boundary,
    independent_closure: ContentRef,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn preparation_history(
    current: &PublicWire,
    envelope: &InputPayload,
    evidence: &[InputPayload],
) -> Result<Vec<InputPayload>, OperationFailure> {
    let mut selected = std::collections::BTreeMap::new();
    selected.insert(envelope.reference.clone(), envelope.clone());
    let mut wire = current.clone();
    let mut previous_generation = None;
    for depth in 0..64 {
        let object = |reference: &ContentRef| {
            evidence
                .iter()
                .find(|object| &object.reference == reference)
                .ok_or_else(|| refusal("public original preparation lineage body is absent"))
        };
        let world = OriginalWorldPreparation::decode(
            &object(&wire.world_preparation)?.bytes,
            16 * 1024 * 1024,
        )?;
        if previous_generation.is_some_and(|generation| world.activation.generation >= generation) {
            return Err(refusal(
                "public original preparation lineage is not strictly historical",
            ));
        }
        previous_generation = Some(world.activation.generation);
        world.validate_publication(&object(&world.publication)?.bytes, 16 * 1024 * 1024)?;
        let prepared = world.node(&wire.node)?;
        for reference in [
            &wire.native_state,
            &wire.world_preparation,
            &wire.ready,
            &wire.native_ready,
            &wire.native_session,
            &world.coordinator,
            &world.publication,
            &prepared.state_inventory,
        ] {
            let original = object(reference)?;
            reference
                .verify(&original.bytes)
                .map_err(|error| refusal(&error.to_string()))?;
            selected.insert(reference.clone(), original.clone());
        }
        let Some(previous) = &wire.previous else {
            return Ok(selected.into_values().collect());
        };
        if depth == 63 {
            return Err(refusal(
                "public original preparation lineage exceeds installed generation credit",
            ));
        }
        let original = object(previous)?;
        previous
            .verify(&original.bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        selected.insert(previous.clone(), original.clone());
        let value = canonical::parse_json(&original.bytes, 16 * 1024 * 1024)
            .map_err(|error| refusal(&error.to_string()))?;
        if canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))?
            != original.bytes
        {
            return Err(refusal(
                "historical public preparation envelope changed canonical bytes",
            ));
        }
        let predecessor: PublicWire = serde_json::from_value(value).map_err(|_| {
            refusal("historical public preparation envelope has unsupported fields")
        })?;
        if predecessor.node != wire.node
            || predecessor.format != "crucible.gem5.public-native-continuation"
            || predecessor.schema_version != wire.schema_version
        {
            return Err(refusal(
                "historical public preparation backend or participant changed",
            ));
        }
        wire = predecessor;
    }
    Err(refusal(
        "public original preparation lineage credit exhausted",
    ))
}
