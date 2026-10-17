//! Authenticates the distinct Root source envelope beneath an installed archive seal.
//!
//! Original preparations, packets and image names establish signed history only.
//! Materialization still requires the mandatory installed source verifier, and
//! every reconstructed process requires its own current opaque certificate.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use crucible_node_contract::{ContentRef, HashRef, Id, U64, Validate, canonical};
use crucible_node_provider::gem5::{
    ArmRootControlHistory, ArmRootControlPacket, ArmRootPreparationRecord, Gem5ArmNativeReady,
};
use serde::Deserialize;

use crate::{
    node_adapters::preparation_state::OriginalWorldPreparation, node_contract::*,
    node_scheduling::InputPayload, node_state::AuthenticatedNativeSource,
};

use super::{
    ARM_ROOT_DIALECT, ARM_ROOT_IMPLEMENTATION, ARM_ROOT_MODEL,
    capture::{ARM_ROOT_PRESERVATION_PROFILE, RootWire, arm_root_continuation_schema},
    refusal,
};

/// Retains a complete Root record authenticated by a local original archive seal.
///
/// The context carries source history, never current process authority or an
/// initial preparation capability. Its native artifact routes are inert original
/// data; a materializer constructs new paths under already reserved custody.
pub struct AuthenticatedArmRootContinuation {
    pub(super) wire: RootWire,
    pub(super) runtime: RuntimeSnapshot,
    pub(super) envelope: InputPayload,
    pub(super) evidence: BTreeMap<ContentRef, InputPayload>,
    pub(super) world: OriginalWorldPreparation,
    pub(super) control: ArmRootControlHistory,
    pub(super) ancestry: Vec<RootWire>,
}

impl AuthenticatedArmRootContinuation {
    /// Borrows the exact signed Root envelope body for historical ancestry.
    pub fn source_record(&self) -> (&ContentRef, &[u8]) {
        (&self.envelope.reference, &self.envelope.bytes)
    }
    /// Borrows the original complete public owner roster as source data.
    pub fn original_prepared_owners(&self) -> &[crucible_node_contract::PreparedOwner] {
        &self.world.prepared_owners
    }

    /// Borrows the complete original common runtime with unchanged operation IDs.
    pub fn runtime(&self) -> &RuntimeSnapshot {
        &self.runtime
    }
    /// Borrows the source-owned model binding without authorizing old-path reads.
    pub fn native_source(&self) -> &crucible_node_provider::gem5::ArmRootHistoricalSource {
        &self.wire.source
    }
    /// Returns the signed original common cut, independent of the native frontier.
    pub fn common_cut(&self) -> crucible_node_contract::Position {
        self.wire.common_cut
    }
    /// Borrows the actual original native frontier retained by the complete image.
    pub fn native_boundary(&self) -> &crucible_node_provider::gem5::Gem5Boundary {
        &self.wire.native_boundary
    }
    /// Borrows the original capture identity for authentic reconstructed sessions.
    pub fn capture(&self) -> &Id {
        &self.wire.capture
    }
    /// Borrows the exact ordered original request, response, Ready and ACK bodies.
    pub fn control_history(&self) -> &ArmRootControlHistory {
        &self.control
    }
    /// Returns the original supplementary root as inert relocation data.
    pub fn supplementary_files_root(&self) -> &str {
        &self.wire.supplementary_files_root
    }
    /// Borrows the exact original pending native Poll without consuming output.
    pub fn pending(&self) -> Option<&Id> {
        self.wire.pending.as_ref()
    }
    /// Borrows the most recent original native ACK administration identity.
    pub fn last_acknowledged(&self) -> Option<&Id> {
        self.wire.last_acknowledged.as_ref()
    }
    /// Returns the immutable selected callback budget for source/target comparison.
    pub fn maximum_events_per_poll(&self) -> U64 {
        self.wire.maximum_events_per_poll
    }
    /// Iterates the complete signed role/name/full-content artifact roster.
    pub fn artifacts(&self) -> impl ExactSizeIterator<Item = (&Id, &str, &ContentRef)> {
        self.wire
            .artifacts
            .iter()
            .map(|file| (&file.role, file.name.as_str(), &file.content))
    }
    /// Borrows exact source evidence as data, without generating replacement receipts.
    pub fn evidence(&self) -> impl ExactSizeIterator<Item = &InputPayload> {
        self.evidence.values()
    }
    /// Reads original successful/refused packets already retained by signed custody.
    ///
    /// # Errors
    /// Refuses a missing original body or unavailable finite response allocation.
    pub fn original_outcomes(&self) -> Result<Vec<Vec<u8>>, OperationFailure> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(self.wire.native_outcomes.len())
            .map_err(|_| refusal("ARM original outcome slots are unavailable"))?;
        for reference in &self.wire.native_outcomes {
            let body = self.object(reference)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(body.bytes.len())
                .map_err(|_| refusal("ARM original outcome body allocation is unavailable"))?;
            bytes.extend_from_slice(&body.bytes);
            result.push(bytes);
        }
        Ok(result)
    }

    /// Matches the whole inert provider import to original signed Root custody.
    ///
    /// An installed factory additionally authenticates its fixed profile and
    /// retained private materialization lease. This comparison never reads any
    /// source route or qualifies the reconstructed process.
    ///
    /// # Errors
    /// Refuses altered source, cut, raw control/ACK history, pending output or
    /// role/name/full-content roster; materialized paths remain provider-checked.
    pub fn verify_imported_record(
        &self,
        record: &crucible_node_provider::gem5::ArmRootArchiveImport,
    ) -> Result<(), OperationFailure> {
        if record.capture != self.wire.capture
            || record.source != self.wire.source
            || record.boundary != self.wire.native_boundary
            || record.source_supplementary_files_root
                != Path::new(&self.wire.supplementary_files_root)
            || record.control_history != self.control
            || record.pending != self.wire.pending
            || record.last_acknowledged != self.wire.last_acknowledged
            || record.original_outcomes.len() != self.wire.native_outcomes.len()
            || record.artifacts.len() != self.wire.artifacts.len()
        {
            return Err(refusal(
                "ARM imported record differs from whole original signed custody",
            ));
        }
        for (reference, bytes) in self
            .wire
            .native_outcomes
            .iter()
            .zip(&record.original_outcomes)
        {
            if self.object(reference)?.bytes != *bytes {
                return Err(refusal("ARM imported outcome changed original raw bytes"));
            }
        }
        for (original, materialized) in self.wire.artifacts.iter().zip(&record.artifacts) {
            let role = match materialized.role {
                crucible_node_provider::gem5::Gem5CapturedArtifactRole::Image => "image",
                crucible_node_provider::gem5::Gem5CapturedArtifactRole::Resource => "resource",
            };
            let relative = materialized
                .relative
                .to_str()
                .ok_or_else(|| refusal("ARM imported reconstruction name is not portable text"))?;
            if original.role.as_str() != role
                || original.name != format!("{role}/{relative}")
                || original.content != materialized.artifact.content
            {
                return Err(refusal(
                    "ARM imported artifact changed original exact role/name/content",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn object(&self, reference: &ContentRef) -> Result<&InputPayload, OperationFailure> {
        self.evidence
            .get(reference)
            .ok_or_else(|| refusal("ARM signed original body is absent"))
    }
}

/// Authenticates signed original Root history without creating current native authority.
///
/// Installed factories must separately verify their exact model/policy identity,
/// construct paths under owned reserved capsule storage and authenticate a fresh
/// live restored peer. This function reads no original native source path.
///
/// # Errors
/// Refuses foreign selected schemas/owners, incomplete original public ancestry,
/// omitted raw packets, altered operation/FIFO/ACK scope, unsupported runtime
/// editions or finite metadata/body credit exhaustion.
pub fn authenticate_arm_root_continuation(
    source: &AuthenticatedNativeSource<'_>,
    node: &Id,
) -> Result<AuthenticatedArmRootContinuation, OperationFailure> {
    let owner = source.owner();
    if owner.key.implementation.as_str() != ARM_ROOT_IMPLEMENTATION
        || owner.key.profile.as_str() != ARM_ROOT_PRESERVATION_PROFILE
        || owner.key.schema != arm_root_continuation_schema()?
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || source.runtime().schema_version != 1
        || owner.evidence.len() > 65_536
        || owner.artifacts.len() > 8192
    {
        return Err(refusal(
            "ARM signed source selects a foreign or unsupported complete owner codec",
        ));
    }
    // Charge every complete full-reference role before reading or cloning bodies.
    let mut extent = 0u64;
    let mut unique = BTreeSet::new();
    for reference in &owner.evidence {
        if !unique.insert(reference) || reference.length.get() > 16 * 1024 * 1024 {
            return Err(refusal(
                "ARM signed evidence role is repeated or exceeds per-record credit",
            ));
        }
        extent = extent
            .checked_add(reference.length.get())
            .filter(|total| *total <= 256 * 1024 * 1024)
            .ok_or_else(|| refusal("ARM signed original body aggregate exceeds finite credit"))?;
    }
    let native = source
        .native()
        .map_err(|error| refusal(&error.to_string()))?;
    let value = canonical::parse_json(native, 16 * 1024 * 1024)
        .map_err(|error| refusal(&error.to_string()))?;
    if canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))? != native {
        return Err(refusal(
            "ARM selected envelope is not original canonical bytes",
        ));
    }
    let wire: RootWire = serde_json::from_value(value)
        .map_err(|_| refusal("ARM selected envelope has unsupported closed fields"))?;
    validate_header(&wire, source, node)?;
    let mut evidence = BTreeMap::new();
    for reference in &owner.evidence {
        let bytes = source
            .content()
            .get(reference)
            .ok_or_else(|| refusal("ARM signed source omitted an original selected body"))?;
        reference
            .verify(bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| refusal("ARM signed original body allocation is unavailable"))?;
        retained.extend_from_slice(bytes);
        evidence.insert(
            reference.clone(),
            InputPayload {
                reference: reference.clone(),
                bytes: retained,
            },
        );
    }
    let ancestry = super::ancestry::decode_ancestry(&wire, &evidence)?;
    let (world, control) = validate_preparation_bodies(&wire, &evidence, node)?;
    super::ancestry::validate_ancestry(&wire, &ancestry, &evidence, node)?;
    super::ancestry::validate_prefix_ancestry(&wire, &ancestry)?;
    super::ancestry::validate_observation_roster(&wire, &ancestry, &evidence)?;
    let object = |reference: &ContentRef| {
        evidence
            .get(reference)
            .ok_or_else(|| refusal("ARM selected envelope omitted an original body"))
    };
    for operation in &wire.operations {
        let original = source
            .runtime()
            .operations
            .iter()
            .find(|saved| saved.operation == operation.original.operation)
            .ok_or_else(|| {
                refusal("ARM selected native record invented a common original grant")
            })?;
        if original != &operation.original
            || original.route.node != *node
            || original.input_batch.is_some()
        {
            return Err(refusal(
                "ARM original common operation differs from complete signed runtime",
            ));
        }
        for prefix in &operation.prefixes {
            if !wire.native_outcomes.contains(&prefix.body) {
                return Err(refusal(
                    "ARM original native prefix lacks exact signed common permission ancestry",
                ));
            }
            object(&prefix.body)?;
        }
    }
    let own_count = source
        .runtime()
        .operations
        .iter()
        .filter(|operation| &operation.route.node == node)
        .count();
    if own_count != wire.operations.len() {
        return Err(refusal(
            "ARM native source omitted common operation custody",
        ));
    }
    let reference = canonical::content_ref(native, "application/json")
        .map_err(|error| refusal(&error.to_string()))?;
    Ok(AuthenticatedArmRootContinuation {
        wire,
        runtime: source.runtime().clone(),
        envelope: InputPayload {
            reference,
            bytes: native.to_vec(),
        },
        evidence,
        world,
        control,
        ancestry,
    })
}

pub(super) fn validate_preparation_bodies(
    wire: &RootWire,
    evidence: &BTreeMap<ContentRef, InputPayload>,
    node: &Id,
) -> Result<(OriginalWorldPreparation, ArmRootControlHistory), OperationFailure> {
    let object = |reference: &ContentRef| {
        evidence
            .get(reference)
            .ok_or_else(|| refusal("ARM selected envelope omitted an original body"))
    };
    let world = OriginalWorldPreparation::decode(
        &object(&wire.world_preparation)?.bytes,
        16 * 1024 * 1024,
    )?;
    if world.activation != wire.source_activation {
        return Err(refusal(
            "ARM original public activation differs from signed runtime",
        ));
    }
    world.validate_publication(&object(&world.publication)?.bytes, 16 * 1024 * 1024)?;
    object(&world.coordinator)?;
    let prepared = world.node(node)?;
    let ready: CommonReady = parse(&object(&wire.ready)?.bytes)?;
    let session: NativeSession = parse(&object(&wire.native_session)?.bytes)?;
    let packet: Gem5ArmNativeReady = parse(&object(&wire.native_ready)?.bytes)?;
    let prepared_owner = prepared
        .prepared_owners
        .first()
        .filter(|_| prepared.prepared_owners.len() == 1)
        .ok_or_else(|| refusal("ARM original public owner preparation is incomplete"))?;
    let original_owner = prepared
        .owners
        .first()
        .filter(|_| prepared.owners.len() == 1)
        .ok_or_else(|| refusal("ARM original native owner preparation is incomplete"))?;
    let token = Id::new(format!(
        "gem5/arm-root/prepared/{}",
        wire.native_session.hash.digest
    ))
    .map_err(|error| refusal(&error.to_string()))?;
    if prepared.ready_receipt != wire.ready
        || ready.schema != "crucible.gem5.arm-root-common-readiness.v1"
        || ready.world != world.activation
        || ready.node != *node
        || ready.owners != prepared.owners
        || ready.native_packet != wire.native_ready
        || ready.native_session != wire.native_session
        || ready.independent_closure != prepared.state_inventory
        || prepared_owner.prepared_token != token
        || prepared_owner.binding_hashes.as_slice() != std::slice::from_ref(&ready.binding)
        || prepared_owner.ready_receipt != wire.ready
        || session.format != "crucible.gem5.arm-root-prepared-session"
        || session.version != 1
        || session.pid == 0
        || session.start_ticks.is_empty()
        || session.start_ticks.len() > 32
        || !session
            .start_ticks
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || session.profile != wire.source.profile
        || session.ready_packet != wire.native_ready
        || session.owner != original_owner.owner
        || session.incarnation != original_owner.incarnation
        || session.generation != original_owner.generation
        || !matches!(
            (session.origin.as_str(), &session.source_capture),
            ("original", None) | ("restored", Some(_))
        )
        || packet.kind != "ready"
        || packet.owner != session.owner
        || packet.incarnation != session.incarnation
        || packet.generation != session.generation
        || packet.continuation != session.origin
        || ready.native_boundary != packet.boundary
        || (session.origin == "original"
            && ready.native_boundary.logical_position != prepared.boundary)
    {
        return Err(refusal(
            "ARM original raw/native/common preparation or binding lineage differs",
        ));
    }
    session
        .source_scope
        .validate()
        .map_err(|error| refusal(&error.to_string()))?;
    object(&ready.independent_closure)?;
    object(&wire.closure)?;
    let _history_credit = wire
        .packets
        .iter()
        .map(|packet| &packet.body)
        .chain(wire.sessions.iter().map(|session| &session.transcript))
        .try_fold(0u64, |total, reference| {
            total.checked_add(reference.length.get())
        })
        .filter(|total| *total <= 64 * 1024 * 1024)
        .ok_or_else(|| {
            refusal("ARM original control-history aggregate exceeds credit before copying")
        })?;
    let control = ArmRootControlHistory {
        schema: wire.control_schema.clone(),
        packets: wire
            .packets
            .iter()
            .map(|packet| {
                Ok(ArmRootControlPacket {
                    kind: packet.kind,
                    bytes: object(&packet.body)?.bytes.clone(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?,
        sessions: wire
            .sessions
            .iter()
            .map(|session| {
                Ok(ArmRootPreparationRecord {
                    token: session.token.clone(),
                    packet: session.packet.clone(),
                    transcript: session.transcript.clone(),
                    transcript_bytes: object(&session.transcript)?.bytes.clone(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?,
    };
    control
        .validate()
        .map_err(|error| refusal(&error.to_string()))?;
    if !control.sessions.iter().any(|original| {
        original.token == token
            && original.packet == wire.native_ready
            && original.transcript == wire.native_session
    }) {
        return Err(refusal(
            "ARM signed control history omits the actual original public native session",
        ));
    }
    for outcome in &wire.native_outcomes {
        let body = object(outcome)?;
        if !control.packets.iter().any(|packet| {
            packet.kind == crucible_node_provider::gem5::ArmRootControlKind::Response
                && packet.bytes == body.bytes
        }) {
            return Err(refusal(
                "ARM original outcome is absent from ordered actual native transport custody",
            ));
        }
    }
    Ok((world, control))
}

fn validate_header(
    wire: &RootWire,
    source: &AuthenticatedNativeSource<'_>,
    node: &Id,
) -> Result<(), OperationFailure> {
    let owner = source.owner();
    if wire.format != "crucible.gem5.arm-root-public-native-continuation"
        || wire.schema_version != 2
        || &wire.node != node
        || wire.source_activation != source.runtime().source_activation
        || wire.common_cut != source.runtime().capture_cut
        || wire.common_cut != owner.cut
        || wire.owners.len() != 1
        || wire.owners[0].owner != owner.owner
        || wire.source.owner != wire.owners[0].owner
        || wire.source.incarnation != wire.owners[0].incarnation
        || wire.source.generation != wire.owners[0].generation
        || wire.source.model_id != ARM_ROOT_MODEL
        || wire.source.native_dialect != ARM_ROOT_DIALECT
        || wire.source.bindings.len() != 17
        || wire.maximum_microsteps.get() != 1_000_000
        || wire.maximum_events_per_poll.get() != 262_144
        || wire.native_boundary.logical_position.microstep >= wire.maximum_microsteps
        || wire.operations.len() > 4096
        || wire.native_outcomes.len() > 512
        || wire.packets.len() > 4096
        || wire.sessions.len() > 256
        || wire.artifacts.len() != owner.artifacts.len()
        || wire.artifacts.len() > 8192
        || wire
            .artifacts
            .iter()
            .zip(&owner.artifacts)
            .any(|(native, archived)| {
                native.role != archived.role
                    || native.name != archived.name
                    || native.content != archived.content
            })
        || wire.observations.len() > 8192
    {
        return Err(refusal(
            "ARM signed source header, native owner, policy or complete artifact roster differs",
        ));
    }
    let root = Path::new(&wire.supplementary_files_root);
    if wire.supplementary_files_root.len() > 4096
        || !root.is_absolute()
        || wire.supplementary_files_root.contains('\0')
        || wire
            .supplementary_files_root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(refusal(
            "ARM original supplementary root is not bounded canonical lineage",
        ));
    }
    for artifact in &wire.artifacts {
        if artifact
            .name
            .strip_prefix(&format!("{}/", artifact.role))
            .is_none()
        {
            return Err(refusal(
                "ARM signed artifact lacks its exact original role prefix",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_native_origin(
    wire: &RootWire,
    evidence: &BTreeMap<ContentRef, InputPayload>,
    previous_capture: Option<&Id>,
) -> Result<(), OperationFailure> {
    let session: NativeSession = parse(
        &evidence
            .get(&wire.native_session)
            .ok_or_else(|| refusal("ARM original native preparation session is absent"))?
            .bytes,
    )?;
    match previous_capture {
        Some(capture)
            if session.origin == "restored" && session.source_capture.as_ref() == Some(capture) =>
        {
            Ok(())
        }
        None if session.origin == "original" && session.source_capture.is_none() => Ok(()),
        _ => Err(refusal(
            "ARM native session differs from its immediately preceding original capture",
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonReady {
    schema: String,
    world: SavedRuntimeActivation,
    node: Id,
    owners: Vec<OwnerIdentity>,
    binding: HashRef,
    native_boundary: crucible_node_provider::gem5::Gem5Boundary,
    native_packet: ContentRef,
    native_session: ContentRef,
    independent_closure: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSession {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: u16,
    origin: String,
    #[serde(default)]
    source_capture: Option<Id>,
    pid: u32,
    start_ticks: String,
    source_scope: HashRef,
    profile: ContentRef,
    ready_packet: ContentRef,
    owner: Id,
    incarnation: Id,
    generation: U64,
}

pub(super) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, OperationFailure> {
    let value = canonical::parse_json(bytes, 16 * 1024 * 1024)
        .map_err(|error| refusal(&error.to_string()))?;
    serde_json::from_value(value)
        .map_err(|_| refusal("ARM original source record has unsupported closed fields"))
}
