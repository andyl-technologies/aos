//! Authenticates the two retained roles of an original stopped Root observation.
//!
//! The installed Root observer names its original process-audit receipt directly.
//! That receipt is self-contained audit metadata; opaque image bytes remain
//! independently owned native artifacts. This codec never scans arbitrary JSON
//! for references or substitutes the current certificate for an older receipt.

use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::gem5::Gem5Boundary;
use serde::Deserialize;

use super::{node::QualifiedArmRootNode, refusal};
use crate::{
    node_contract::{
        InputProvenanceLimits, OperationFailure, OwnerIdentity, SavedRuntimeActivation,
        WorldActivation,
    },
    node_scheduling::InputPayload,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalStopped {
    schema: String,
    boundary: Gem5Boundary,
    closure: ContentRef,
    owners: Vec<OwnerIdentity>,
    activation: SavedRuntimeActivation,
}

impl QualifiedArmRootNode {
    /// Selects the actual stored audit role of this unchanged stopped observation.
    ///
    /// # Errors
    /// Refuses foreign live custody, unregistered or changed original roles,
    /// another audit codec, and exhausted complete object or byte credit.
    pub(super) fn stopped_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        if !self.same_world(activation)
            || self.quarantined
            || self.active.is_some()
            || !self
                .observation
                .as_ref()
                .is_some_and(|(authority, original)| {
                    std::rc::Rc::ptr_eq(authority, &activation.authority)
                        && &original.proof_ref == root
                })
        {
            return Err(refusal(
                "ARM original observation proof has foreign live custody",
            ));
        }
        authenticate_roles(
            &self.ledger.standalone,
            &self.observations,
            root,
            &SavedRuntimeActivation::from(activation.record()),
            &self.preparation.route.owners,
            self.preparation.native.boundary(),
            limits,
        )
    }
}

// Data checks follow the opaque owning-node check above. Keeping this helper
// separate lets malformed role inventories be tested without native authority.
fn authenticate_roles(
    objects: &[InputPayload],
    observations: &[ContentRef],
    root: &ContentRef,
    activation: &SavedRuntimeActivation,
    owners: &[OwnerIdentity],
    boundary: &Gem5Boundary,
    limits: InputProvenanceLimits,
) -> Result<Vec<ContentRef>, OperationFailure> {
    if limits.maximum_objects < 2
        || !observations.contains(root)
        || root.length.get() > limits.maximum_bytes as u64
    {
        return Err(refusal(
            "ARM original observation roster or complete credit differs",
        ));
    }
    let original = unique_object(objects, root)?;
    let wire: OriginalStopped = serde_json::from_value(
        canonical::parse_json(&original.bytes, limits.maximum_bytes)
            .map_err(|error| refusal(&error.to_string()))?,
    )
    .map_err(|error| refusal(&error.to_string()))?;
    if wire.schema != "crucible.gem5.arm-root-observation.v1"
        || &wire.activation != activation
        || wire.owners != owners
        || &wire.boundary != boundary
        || &wire.closure == root
        || root
            .length
            .get()
            .checked_add(wire.closure.length.get())
            .is_none_or(|total| total > limits.maximum_bytes as u64)
    {
        return Err(refusal(
            "ARM stopped codec scope or complete byte credit differs",
        ));
    }
    let closure = unique_object(objects, &wire.closure)?;
    let audit = canonical::parse_json(&closure.bytes, limits.maximum_bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    if audit.get("schema").and_then(serde_json::Value::as_str)
        != Some("crucible.gem5.process-closure-mechanism.v1")
        || audit.get("profile").and_then(serde_json::Value::as_str) != Some(super::ARM_ROOT_MODEL)
        || audit.get("guest_isa").and_then(serde_json::Value::as_str) != Some("aarch64")
        || audit.get("byte_closure_complete") != Some(&serde_json::Value::Bool(true))
        || [
            "execution_admission_qualified",
            "modeled_diagnostics_complete",
            "full_system_admission_qualified",
        ]
        .iter()
        .any(|field| audit.get(field) != Some(&serde_json::Value::Bool(false)))
        || !audit
            .get("omissions")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(refusal(
            "ARM original closure is outside the installed audit codec",
        ));
    }

    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(1)
        .map_err(|_| refusal("ARM stopped dependency slot credit unavailable"))?;
    dependencies.push(wire.closure);
    Ok(dependencies)
}

fn unique_object<'a>(
    objects: &'a [InputPayload],
    reference: &ContentRef,
) -> Result<&'a InputPayload, OperationFailure> {
    let mut matches = objects
        .iter()
        .filter(|object| &object.reference == reference);
    let object = matches
        .next()
        .ok_or_else(|| refusal("ARM original stopped role is absent"))?;
    if matches.next().is_some() {
        return Err(refusal("ARM original stopped role is duplicated"));
    }
    reference
        .verify(&object.bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    Ok(object)
}

#[cfg(test)]
mod tests;
