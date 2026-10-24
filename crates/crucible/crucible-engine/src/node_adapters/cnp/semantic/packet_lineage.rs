//! Builds bounded inert packet codec rows from separately authenticated originals.
//!
//! These host projections are not native-emitted records, independent execution
//! oracles, qualification or operation authority. Each source must authenticate
//! its same original child, complete grant and every semantic dependency before
//! using this copying helper, and reauthenticate current custody on return.

use std::collections::BTreeMap;

use super::{CnpSemanticInstallation, budget, refused, unknown};
use crate::{
    node_contract::*,
    node_scheduling::{InputPayload, NativePublication},
};
use crucible_node_format::*;

pub(super) struct Rows {
    limits: OriginalInputLineageLimits,
    bytes: usize,
    edges: usize,
    objects: BTreeMap<ContentRef, (Vec<u8>, Vec<ContentRef>)>,
}

impl Rows {
    pub(super) fn new(limits: OriginalInputLineageLimits) -> Result<Self, OperationFailure> {
        let defaults = OriginalInputLineageLimits::default();
        if limits.maximum_objects == 0
            || limits.maximum_objects > defaults.maximum_objects
            || limits.maximum_bytes == 0
            || limits.maximum_bytes > defaults.maximum_bytes
            || limits.maximum_edges > defaults.maximum_edges
        {
            return Err(refused("packet whole lineage limits"));
        }
        Ok(Self {
            limits,
            bytes: 0,
            edges: 0,
            objects: BTreeMap::new(),
        })
    }

    pub(super) fn add(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
        mut dependencies: Vec<ContentRef>,
    ) -> Result<(), OperationFailure> {
        reference.verify(bytes).map_err(unknown)?;
        dependencies.sort();
        dependencies.dedup();
        if dependencies.contains(reference) {
            return Err(refused("packet self-dependent codec row"));
        }
        if let Some((old, rows)) = self.objects.get(reference) {
            if old != bytes || rows != &dependencies {
                return Err(refused("packet original codec row replaced"));
            }
            return Ok(());
        }
        let size = self
            .bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= self.limits.maximum_bytes)
            .ok_or_else(|| refused("packet complete lineage byte credit"))?;
        let edges = self
            .edges
            .checked_add(dependencies.len())
            .filter(|size| *size <= self.limits.maximum_edges)
            .ok_or_else(|| refused("packet complete lineage edge credit"))?;
        if self.objects.len() >= self.limits.maximum_objects {
            return Err(refused("packet complete lineage object credit"));
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| refused("packet original lineage allocation"))?;
        retained.extend_from_slice(bytes);
        self.objects
            .insert(reference.clone(), (retained, dependencies));
        self.bytes = size;
        self.edges = edges;
        Ok(())
    }

    pub(super) fn claim(
        &mut self,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        if claim.objects.len() != claim.rows.len() {
            return Err(refused("packet opaque producer closure incomplete"));
        }
        for (object, row) in claim.objects.iter().zip(&claim.rows) {
            if object.reference != row.object {
                return Err(refused("packet opaque producer row changed"));
            }
            self.add(&object.reference, &object.bytes, row.dependencies.clone())?;
        }
        Ok(())
    }

    pub(super) fn remaining_bytes(&self) -> usize {
        self.limits.maximum_bytes - self.bytes
    }

    pub(super) fn finish(self) -> (Vec<InputPayload>, Vec<OriginalLineageRow>) {
        self.objects
            .into_iter()
            .map(|(reference, (bytes, dependencies))| {
                (
                    InputPayload {
                        reference: reference.clone(),
                        bytes,
                    },
                    OriginalLineageRow {
                        object: reference,
                        dependencies,
                    },
                )
            })
            .unzip()
    }
}

pub(super) fn claim(
    selection: &CnpSemanticInstallation,
    original: &OperationAdmission,
    outcome: &OperationOutcome,
    publication: &NativePublication,
    native: &ContentRef,
    edition: u16,
    mut rows: Rows,
) -> Result<OriginalPublicationClaim, OperationFailure> {
    if !matches!(
        original.request(),
        OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. }
    ) || outcome.operation != *original.token().operation()
        || outcome.node != selection.descriptor.id
        || outcome.scheduling.as_ref().is_none_or(|observation| {
            observation.proof_ref != *native
                || observation
                    .publications
                    .iter()
                    .filter(|row| *row == publication)
                    .count()
                    != 1
        })
        || publication.publication.phase != Phase::Publication
        || publication.evaluation.is_none_or(|evaluation| {
            evaluation.phase != Phase::Reaction || evaluation >= publication.publication
        })
        || publication.payload_bytes.len() > 32
    {
        return Err(refused(
            "packet original exact publication/outcome association",
        ));
    }
    let activation = original.activation().record();
    let authority = &selection.binding.authority;
    let origin = OriginalPublicationOrigin {
        owner_binding_hash: selection.owner.identity().map_err(unknown)?,
        execution_owner_id: selection.owner.owner.id.clone(),
        session_id: authority.session_id.clone(),
        world_binding_hash: activation.world_binding_hash.clone(),
        activation_id: activation.activation_id.clone(),
        world_generation: activation.generation,
        incarnation_id: authority.incarnation_id.clone(),
        owner_generation: authority.owner_generation,
        operation_id: original.token().operation().clone(),
        grant_id: original.token().operation().clone(),
        observation_batch: native.clone(),
        stop_receipt: native.clone(),
        measurement: native.clone(),
    };
    let event = Event {
        schema_version: 1,
        id: publication.publication_id.clone(),
        source: publication.endpoint.clone(),
        destination: publication.endpoint.clone(),
        source_sequence: publication.native_sequence,
        provenance_ref: native.clone(),
        causal_parent_ids: crucible_node_transport::reference_packet::connected::causal_parent_ids(
            &publication.causal_parents,
        )
        .map_err(unknown)?,
        stage: EventStage::Publication,
        position: publication.publication,
        publication_position: publication.publication,
        delivery_position: None,
        payload: publication.payload.clone(),
        extensions: Extensions::new(),
    };
    event.validate().map_err(unknown)?;
    let projection = serde_json::json!({"schema":format!("source-owned.packet-host-publication/{edition}"),"native":native,"event":event,"origin":origin});
    budget::serialized_size(&projection, rows.remaining_bytes().min(8192))?;
    let bytes = canonical::canonical_json(&projection).map_err(unknown)?;
    let published = canonical::content_ref(&bytes, "application/json").map_err(unknown)?;
    rows.add(&publication.payload, &publication.payload_bytes, Vec::new())?;
    rows.add(
        &published,
        &bytes,
        vec![native.clone(), publication.payload.clone()],
    )?;
    let (objects, rows) = rows.finish();
    Ok(OriginalPublicationClaim {
        event,
        origin,
        published,
        objects,
        rows,
    })
}
