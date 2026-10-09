//! Closed native ledger decoding beneath independently authenticated archives.
//!
//! These checks establish record consistency only. They cannot qualify imported
//! images or issue live execution authority. A cold factory must additionally
//! authenticate the signed source, installed native profile and actual fresh peer.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, ContractError, Id, Position, U64, Validate, canonical};
use crucible_node_provider::gem5::{Gem5Boundary, Gem5Completion};
use serde::{Deserialize, Serialize};

use crate::{node_contract::*, node_scheduling::InputPayload};

use super::{
    GEM5_OPAQUE_PRESERVATION_PROFILE, capture::gem5_native_continuation_schema,
    ledger::PrefixScope, refusal,
};

/// Retains backend state admitted through an authentic installed native archive.
///
/// This value establishes historical preservation lineage only. A fresh native
/// process still requires its own independently qualified live authority.
pub struct Gem5AuthenticatedContinuation {
    pub(super) record: Gem5ContinuationRecord,
    pub(super) source: RuntimeSnapshot,
}

impl Gem5AuthenticatedContinuation {
    /// Borrows the original immutable native ledger without granting execution.
    pub fn record(&self) -> &Gem5ContinuationRecord {
        &self.record
    }

    /// Borrows the complete original common runtime custody.
    pub fn runtime(&self) -> &RuntimeSnapshot {
        &self.source
    }
}

/// Authenticates the native codec beneath the locally verified archive capability.
///
/// Installed factories must additionally qualify the selected model and actual
/// fresh native process. This function never opens an original source path.
///
/// # Errors
/// Refuses another backend/profile, incomplete participants or artifact/evidence
/// inventories, changed original runtime scope, and unsupported native records.
pub fn authenticate_gem5_continuation(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    node: &Id,
    maximum_microsteps: U64,
) -> Result<Gem5AuthenticatedContinuation, OperationFailure> {
    let owner = source.owner();
    if owner.key.implementation.as_str() != "gem5/native-process-v1"
        || owner.key.profile.as_str() != GEM5_OPAQUE_PRESERVATION_PROFILE
        || owner.key.schema != gem5_native_continuation_schema()?
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || owner.evidence.len() > 65_536
    {
        return Err(refusal(
            "authenticated native archive selects an unsupported gem5 owner codec",
        ));
    }
    let mut evidence = Vec::with_capacity(owner.evidence.len());
    let mut extent = 0usize;
    for reference in &owner.evidence {
        let bytes = source
            .content()
            .get(reference)
            .ok_or_else(|| refusal("authenticated gem5 native dependency body is absent"))?;
        extent = extent
            .checked_add(bytes.len())
            .filter(|total| *total <= 256 * 1024 * 1024)
            .ok_or_else(|| {
                refusal("authenticated gem5 native dependencies exceed finite credit")
            })?;
        evidence.push(InputPayload {
            reference: reference.clone(),
            bytes: bytes.to_vec(),
        });
    }
    let record = decode_gem5_continuation(
        source
            .native()
            .map_err(|error| refusal(&error.to_string()))?,
        source.runtime(),
        node,
        maximum_microsteps,
        &evidence,
        16 * 1024 * 1024,
    )?;
    if record.wire.common_cut != owner.cut
        || record
            .wire
            .owners
            .first()
            .is_none_or(|identity| identity.owner != owner.owner)
        || record.wire.artifacts.len() != owner.artifacts.len()
        || record
            .wire
            .artifacts
            .iter()
            .zip(&owner.artifacts)
            .any(|(native, archived)| {
                native.role != archived.role
                    || native.name != archived.name
                    || native.content != archived.content
            })
    {
        return Err(refusal(
            "authenticated gem5 owner or complete artifact roster differs from native source",
        ));
    }
    Ok(Gem5AuthenticatedContinuation {
        record,
        source: source.runtime().clone(),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedNativeOperation {
    pub original: SavedRuntimeOperation,
    pub prefixes: Vec<ContentRef>,
    pub prefix_scopes: Vec<PrefixScope>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedArtifact {
    pub role: Id,
    pub name: String,
    pub content: ContentRef,
}

/// Borrows decoded preservation data without granting image or native authority.
pub struct Gem5ContinuationRecord {
    pub(super) wire: Wire,
    pub(super) prefixes: BTreeMap<Id, Gem5Completion>,
    pub(super) evidence: BTreeMap<ContentRef, InputPayload>,
}

impl Gem5ContinuationRecord {
    /// Returns the original unchanged full native frontier, including latent prefixes.
    pub fn native_boundary(&self) -> &Gem5Boundary {
        &self.wire.native_boundary
    }
    /// Returns the original common coordinator capture cut.
    pub fn common_cut(&self) -> Position {
        self.wire.common_cut
    }
    /// Returns the source controller's exact immutable capture identity.
    pub fn capture_id(&self) -> &Id {
        &self.wire.capture
    }
    /// Returns the fixed guest ISA selected by the source installation.
    pub fn guest_isa(&self) -> &str {
        &self.wire.guest_isa
    }
    /// Returns an opaque historical rebinding hint, never a path access grant.
    pub fn source_layout_root(&self) -> &str {
        &self.wire.source_layout_root
    }
    /// Returns every original immutable native receipt in operation ID order.
    pub fn native_prefixes(&self) -> impl ExactSizeIterator<Item = &Gem5Completion> {
        self.prefixes.values()
    }
    /// Returns the original native prefix retaining publication custody.
    pub fn pending_prefix(&self) -> Option<&Id> {
        self.wire.native_pending.as_ref()
    }
    /// Returns original native ACK knowledge without settling a new incarnation.
    pub fn last_acknowledged(&self) -> Option<&Id> {
        self.wire.native_acknowledged.as_ref()
    }
    /// Returns the original qualified finite same-time budget as preservation data.
    pub fn maximum_microsteps(&self) -> U64 {
        self.wire.maximum_microsteps
    }
    /// Returns the actual original native stdout FIFO cursor.
    pub fn output_sequence(&self) -> U64 {
        self.wire.output_sequence
    }
    /// Borrows complete original immutable evidence after integrity checks.
    pub fn evidence(&self) -> impl ExactSizeIterator<Item = &InputPayload> {
        self.evidence.values()
    }
    /// Borrows source operation records without reminting their permissions.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = &SavedRuntimeOperation> {
        self.wire
            .operations
            .iter()
            .map(|operation| &operation.original)
    }
    /// Iterates exact streamed artifact roles, reconstruction names and byte identities.
    pub fn artifacts(&self) -> impl ExactSizeIterator<Item = (&Id, &str, &ContentRef)> {
        self.wire
            .artifacts
            .iter()
            .map(|artifact| (&artifact.role, artifact.name.as_str(), &artifact.content))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Wire {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    pub source_activation: SavedRuntimeActivation,
    pub common_cut: Position,
    pub native_boundary: Gem5Boundary,
    pub guest_isa: String,
    pub source_layout_root: String,
    pub maximum_microsteps: U64,
    pub node: Id,
    pub owners: Vec<OwnerIdentity>,
    pub capture: Id,
    pub closure: ContentRef,
    pub operations: Vec<SavedNativeOperation>,
    pub native_prefixes: Vec<ContentRef>,
    #[serde(deserialize_with = "required_nullable")]
    pub native_pending: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub native_acknowledged: Option<Id>,
    pub output_sequence: U64,
    pub artifacts: Vec<SavedArtifact>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl Validate for Wire {
    fn validate(&self) -> Result<(), ContractError> {
        let invalid = || ContractError::Invalid {
            field: "gem5-native-continuation",
            reason: "invalid closed codec, finite bounds or original native identities".to_owned(),
        };
        if self.schema_version != 1
            || self.owners.len() != 1
            || self.maximum_microsteps.get() < 2
            || !matches!(self.guest_isa.as_str(), "x86_64" | "aarch64")
            || self.source_layout_root.len() > 4096
            || !std::path::Path::new(&self.source_layout_root).is_absolute()
            || self.operations.len() > 65_536
            || self.native_prefixes.len() > 65_536
            || self.artifacts.len() > 8192
            || self.native_boundary.logical_position.microstep >= self.maximum_microsteps
        {
            return Err(invalid());
        }
        for operation in &self.operations {
            if operation.prefixes.len() != operation.prefix_scopes.len()
                || operation.prefixes.len() > 65_536
                || operation.original.input_batch.is_some()
                || operation.original.close_submission.is_some()
                || operation.original.submission_effects.is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Decodes exact native ledger consistency beneath a separately authenticated source.
///
/// The supplied records remain data. Callers must authenticate their original
/// archive and installed profile before using them in a trusted import callback;
/// passing this check does not construct a native image, runtime seal or grant.
///
/// # Errors
/// Refuses malformed or oversized records, unknown fields, missing dependencies,
/// changed original scopes, incomplete prefixes, ACKs or output byte inventories.
pub fn decode_gem5_continuation(
    bytes: &[u8],
    source: &RuntimeSnapshot,
    node: &Id,
    maximum_microsteps: U64,
    evidence: &[InputPayload],
    maximum_record_bytes: usize,
) -> Result<Gem5ContinuationRecord, OperationFailure> {
    if maximum_record_bytes == 0
        || maximum_record_bytes > 16 * 1024 * 1024
        || evidence.len() > 65_536
    {
        return Err(refusal(
            "gem5 native decoding lacks finite installed limits",
        ));
    }
    let wire: Wire = canonical::decode(bytes, maximum_record_bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    if wire.node != *node
        || wire.source_activation != source.source_activation
        || wire.common_cut != source.capture_cut
        || wire.maximum_microsteps != maximum_microsteps
        || source.inputs.iter().any(|input| &input.node == node)
    {
        return Err(refusal(
            "gem5 native record differs from the complete source world and closed input policy",
        ));
    }
    let mut objects = BTreeMap::new();
    let mut total = 0usize;
    for object in evidence {
        if object.bytes.len() > maximum_record_bytes {
            return Err(refusal(
                "gem5 native evidence object exceeds bounded decoder credit",
            ));
        }
        total = total
            .checked_add(object.bytes.len())
            .filter(|total| *total <= 256 * 1024 * 1024)
            .ok_or_else(|| refusal("gem5 native evidence credit exhausted"))?;
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        if objects
            .insert(object.reference.clone(), object.clone())
            .is_some()
        {
            return Err(refusal("gem5 native evidence roster repeats a dependency"));
        }
    }
    if !objects.contains_key(&wire.closure) {
        return Err(refusal("gem5 native independent closure body is missing"));
    }
    let mut prefixes = BTreeMap::new();
    let mut prefix_ids = BTreeMap::new();
    for reference in &wire.native_prefixes {
        let object = objects
            .get(reference)
            .ok_or_else(|| refusal("gem5 original native receipt body is missing"))?;
        let value = canonical::parse_json(&object.bytes, maximum_record_bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        let prefix: Gem5Completion =
            serde_json::from_value(value).map_err(|error| refusal(&error.to_string()))?;
        prefix_ids.insert(reference.clone(), prefix.operation.clone());
        if prefixes.insert(prefix.operation.clone(), prefix).is_some() {
            return Err(refusal("gem5 native receipt identity was repeated"));
        }
    }
    let own: Vec<_> = source
        .operations
        .iter()
        .filter(|operation| &operation.route.node == node)
        .collect();
    if own.len() != wire.operations.len() {
        return Err(refusal(
            "gem5 source original operation closure is incomplete",
        ));
    }
    for (saved, actual) in wire.operations.iter().zip(own) {
        if saved.original != *actual || saved.original.route.owners != wire.owners {
            return Err(refusal("gem5 source original runtime operation changed"));
        }
        let mut previous = None;
        for (index, (reference, scope)) in
            saved.prefixes.iter().zip(&saved.prefix_scopes).enumerate()
        {
            let prefix = prefix_ids
                .get(reference)
                .and_then(|identity| prefixes.get(identity))
                .ok_or_else(|| refusal("gem5 original Poll evidence is missing"))?;
            let identity = canonical::json_hash("crucible.gem5.original-prefix.v1", &serde_json::json!({"operation":saved.original.operation,"owners":scope.route.owners,"activation":scope.activation.activation_id,"prefix":index}))
                .map_err(|error| refusal(&error.to_string()))?;
            if prefix.operation.as_str() != format!("gem5-prefix/{}", identity.digest)
                || scope.route.node != *node
                || scope.activation.world_binding_hash != wire.source_activation.world_binding_hash
                || previous.is_some_and(|before| before != prefix.before.logical_position)
            {
                return Err(refusal(
                    "gem5 original native Poll chain or historical submission scope differs",
                ));
            }
            let (start, limit) = match &saved.original.request {
                OperationRequest::ExactRun { start, limit, .. }
                | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
                _ => {
                    return Err(refusal(
                        "gem5 native saved grant is outside installed exact operation policy",
                    ));
                }
            };
            let range = prefix
                .original
                .exact_range
                .as_ref()
                .ok_or_else(|| refusal("gem5 original Poll lacks full-position mediation"))?;
            if range.limit != limit
                || range.start != prefix.before.logical_position
                || range.start < start
                || (index == 0 && range.start != start)
                || range.maximum_microsteps != maximum_microsteps
                || prefix.after.logical_position < range.start
                || prefix.after.logical_position > limit
                || prefix.original.exclusive_tick != limit.time_ps
            {
                return Err(refusal("gem5 original native Poll widened its exact scope"));
            }
            previous = Some(prefix.after.logical_position);
        }
    }
    for identity in [&wire.native_pending, &wire.native_acknowledged]
        .into_iter()
        .flatten()
    {
        if !prefixes.contains_key(identity) {
            return Err(refusal(
                "gem5 native ACK or publication names an absent original prefix",
            ));
        }
    }
    super::reconciliation::reconcile_native_cache(&wire, &prefixes, &prefix_ids, &objects)?;
    let mut names = BTreeSet::new();
    for artifact in &wire.artifacts {
        crate::node_contract::validate_native_artifact_name(&artifact.name)?;
        if !matches!(artifact.role.as_str(), "image" | "resource")
            || !artifact.name.starts_with(&format!("{}/", artifact.role))
            || !names.insert(&artifact.name)
        {
            return Err(refusal(
                "gem5 native artifact role/name closure is invalid or repeated",
            ));
        }
    }
    Ok(Gem5ContinuationRecord {
        wire,
        prefixes,
        evidence: objects,
    })
}

#[cfg(test)]
mod tests;
