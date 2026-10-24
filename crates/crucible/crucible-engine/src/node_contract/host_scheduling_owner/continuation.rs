//! Retains an unchanged original common-state closure in continuation edition two.
//!
//! The opaque producer reads the owning runtime directly. Portable records are
//! facts only; restoration additionally requires the actual fresh runtime and
//! its independently authenticated native continuation context.
//!
//! ```text
//! {"schema_version":2,"source":{},"runtime":{"kind":"original-lineage","record":{}},"scheduling":{},"objects":[]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_format::{Position, U64};
use serde::{Deserialize, Serialize};

use super::*;
use crate::node_contract::{
    OriginalInputLineageLimits, OriginalLineageRestoration, OriginalLineageRuntimeRecord,
    RuntimeSnapshot,
};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};

/// Bounds the complete common-state record and original body inventory.
#[derive(Clone, Copy, Debug)]
pub struct HostSchedulingContinuationLimits {
    /// Bounds the complete encoded record before its JSON buffer is allocated.
    pub maximum_record_bytes: usize,
    /// Bounds all original body roles, bytes and lineage dependency edges.
    pub lineage: OriginalInputLineageLimits,
}

/// Selects the complete represented runtime ledger without changing old editions.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum HostSchedulingRuntimeRecord {
    /// Retains the legacy complete operation/input ledger.
    Legacy(Box<RuntimeSnapshot>),
    /// Retains original source associations and native input history explicitly.
    OriginalLineage(Box<OriginalLineageRuntimeRecord>),
}

/// Carries inert portable common-state continuation data.
///
/// Decoding this record does not create a host source, private runtime identity,
/// native stop, capture permission or usable restoration context.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSchedulingContinuationRecord {
    /// Selects this complete common-state envelope, exactly edition two.
    pub schema_version: u16,
    /// Binds the exact original source selection and explicit host domain roles.
    pub source: HostSchedulingSelection,
    /// Retains the actual runtime's complete common ledger at the unchanged cut.
    pub runtime: HostSchedulingRuntimeRecord,
    /// Retains the same actual scheduler queues, credits, frontiers and histories.
    pub scheduling: SchedulingSnapshot,
    /// Retains complete typed original bodies in strict full-reference order.
    pub objects: Vec<InputPayload>,
}

impl HostSchedulingContinuationRecord {
    /// Decodes bounded portable facts without constructing an original source handle.
    ///
    /// Native continuation, original signatures and fresh private custody remain
    /// independent requirements. A matching decoded record never authorizes Apply.
    ///
    /// # Errors
    /// Refuses oversized or noncanonical JSON, unknown fields/editions, mismatched
    /// runtime/scheduler cuts, malformed source data or incomplete body credit.
    pub fn decode(
        bytes: &[u8],
        limits: HostSchedulingContinuationLimits,
    ) -> Result<Self, RuntimeError> {
        if limits.maximum_record_bytes == 0 || limits.maximum_record_bytes > 64 * 1024 * 1024 {
            return Err(RuntimeError::ResourceLimit);
        }
        let ceiling = OriginalInputLineageLimits::default();
        if limits.lineage.maximum_objects > ceiling.maximum_objects
            || limits.lineage.maximum_bytes > ceiling.maximum_bytes
            || limits.lineage.maximum_edges > ceiling.maximum_edges
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let value = canonical::parse_json(bytes, limits.maximum_record_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)? != bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        let record: Self =
            serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if record.schema_version != 2
            || record.scheduling.schema_version != 1
            || record.scheduling.original_epochs.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let (activation, cut, ordinal) = match &record.runtime {
            HostSchedulingRuntimeRecord::Legacy(runtime) => {
                if !matches!(runtime.schema_version, 1 | 2)
                    || runtime.terminal.is_some()
                    || runtime.condition_stop.is_some()
                    || !record.objects.is_empty()
                {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                (
                    &runtime.source_activation,
                    runtime.capture_cut,
                    runtime.capture_ordinal,
                )
            }
            HostSchedulingRuntimeRecord::OriginalLineage(runtime) => {
                runtime.validate_metadata(limits.lineage, limits.maximum_record_bytes)?;
                (
                    &runtime.source_activation,
                    runtime.capture_cut,
                    runtime.capture_ordinal,
                )
            }
        };
        record
            .source
            .descriptor
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        record
            .source
            .binding
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        record
            .source
            .owner
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        validate_domains(&record.source.domains).map_err(|_| RuntimeError::InvalidReceipt)?;
        if cut != record.scheduling.capture_cut
            || ordinal != record.scheduling.capture_ordinal
            || activation.world_binding_hash != record.scheduling.world_binding_hash
            || activation.activation_id != record.scheduling.source_activation_id
            || activation.generation != record.scheduling.source_generation
            || activation.boundary != record.scheduling.source_boundary
            || record
                .objects
                .windows(2)
                .any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut remaining = limits.lineage;
        for object in &record.objects {
            remaining.maximum_objects = remaining
                .maximum_objects
                .checked_sub(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            remaining.maximum_bytes = remaining
                .maximum_bytes
                .checked_sub(object.bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            object
                .reference
                .verify(&object.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        if let HostSchedulingRuntimeRecord::OriginalLineage(runtime) = &record.runtime {
            let mut required = BTreeSet::new();
            for input in &runtime.inputs {
                required.extend(input.payloads.iter());
                if let Some(provenance) = &input.provenance {
                    required.extend(provenance.objects.iter());
                }
                if let Some(lineage) = &input.lineage {
                    for publication in &lineage.publications {
                        required.extend(publication.objects.iter());
                    }
                }
            }
            if required.len() != record.objects.len()
                || !required
                    .into_iter()
                    .eq(record.objects.iter().map(|object| &object.reference))
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        Ok(record)
    }
}

/// Retains a core-issued original common-state read without global capture authority.
///
/// Only an original runtime observation constructs this handle. The source-one
/// factory capture profile remains unsupported, and native participant state
/// still requires separate complete native capture and restoration.
pub struct HostSchedulingContinuationV2 {
    record: HostSchedulingContinuationRecord,
    encoded: InputPayload,
}

impl HostSchedulingContinuationV2 {
    /// Borrows the exact original common-state record.
    pub fn record(&self) -> &HostSchedulingContinuationRecord {
        &self.record
    }

    /// Borrows the complete canonical record and its typed content commitment.
    pub fn encoded(&self) -> &InputPayload {
        &self.encoded
    }

    pub(super) fn into_encoded(self) -> InputPayload {
        self.encoded
    }

    /// Conjuncts the captured rows with the same fresh runtime's opaque native context.
    ///
    /// This check does not install a scheduler, remint an operation, acknowledge
    /// input, publish Ready or call Apply. Existing whole-runtime restoration
    /// performs the single installation beneath its original custody capsule.
    ///
    /// # Errors
    /// Refuses legacy selection, foreign fresh runtime/source/context, changed
    /// scheduler identity, omitted original bodies or altered captured rows.
    pub fn authenticate_original_lineage_target(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        source: &HostSchedulingSource,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        runtime.authenticate_host_scheduling_source(source)?;
        context.validate_current(runtime)?;
        context.validate_original_scheduler(&self.record.scheduling)?;
        let HostSchedulingRuntimeRecord::OriginalLineage(record) = &self.record.runtime else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if record.as_ref() != context.record()
            || &context.target().world_binding_hash != source.world()
            || self.record.source.descriptor.id != source.selection().descriptor.id
            || self.record.source.owner.owner != source.selection().owner.owner
            || self.record.source.domains != *source.domains()
            || self.record.source.binding.compatibility != source.selection().binding.compatibility
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for object in &self.record.objects {
            if context.original_body(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        context.validate_current(runtime)?;
        runtime.authenticate_host_scheduling_source(source)
    }

    /// Prepares the captured scheduler beneath the same authenticated fresh runtime.
    ///
    /// The opaque native restoration context must belong to this actual target
    /// runtime and authenticate the complete original Runtime7 record. The
    /// prepared scheduler retains queues, reservations, credits and input history
    /// while paused; it cannot issue grants or replace an initialized slot.
    ///
    /// # Errors
    /// Refuses unsupported legacy selection, foreign original source/context,
    /// changed captured bodies, initialized target or incomplete native closure.
    pub fn prepare_original_lineage_scheduler(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        source: &HostSchedulingSource,
        context: &OriginalLineageRestoration<'_>,
        graph: &crate::node_admission::AdmittedGraph,
    ) -> Result<crate::node_scheduling::PreparedSchedulingRestore, RuntimeError> {
        self.authenticate_original_lineage_target(runtime, source, context)?;
        let prepared = runtime.prepare_original_lineage_scheduler(
            graph,
            context,
            self.record.scheduling.clone(),
        )?;
        self.authenticate_original_lineage_target(runtime, source, context)?;
        Ok(prepared)
    }

    /// Installs the complete closure into the same original fresh scheduling slot.
    ///
    /// The actual published activation and opaque native context remain mandatory.
    /// Core retains original scheduler queues before installing native caches and
    /// retains all operation/input ledgers before any native install callback.
    /// Failure preserves the whole owning runtime in containment without replaying
    /// Begin, Stage, Poll or ACK. Source-one capture capability stays unsupported.
    ///
    /// # Errors
    /// Refuses foreign source/context/activation, changed captured scheduler,
    /// initialized target, incomplete native installation or exhausted copy credit.
    pub fn install_original_lineage_target(
        &self,
        runtime: &mut crate::node_contract::NodeRuntime,
        source: &HostSchedulingSource,
        context: &OriginalLineageRestoration<'_>,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &crate::node_contract::WorldActivation,
        scheduling: crate::node_scheduling::PreparedSchedulingRestore,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_lineage_target(runtime, source, context)?;
        runtime.install_complete_original_lineage_restoration(
            graph, context, activation, scheduling,
        )?;
        self.authenticate_original_lineage_target(runtime, source, context)
    }
}

impl HostSchedulingObservation<'_> {
    /// Reads this same original runtime and scheduler into a bounded distinct record.
    ///
    /// No portable snapshot is accepted as producer input. Original lineage
    /// remains explicit rather than being flattened into a legacy input codec.
    /// Unsupported terminal/fault/condition and inherited-epoch combinations
    /// retain their old refusal until their complete selected codecs are joined.
    ///
    /// # Errors
    /// Refuses stale or foreign custody, busy or uninitialized original storage,
    /// unsupported scope, changed cut or insufficient aggregate record/body credit.
    pub fn continuation_v2(
        &self,
        cut: Position,
        ordinal: U64,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<HostSchedulingContinuationV2, RuntimeError> {
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        let quarter = limits
            .maximum_record_bytes
            .checked_div(4)
            .filter(|bytes| *bytes > 0 && limits.maximum_record_bytes <= 64 * 1024 * 1024)
            .ok_or(RuntimeError::ResourceLimit)?;
        let ceiling = OriginalInputLineageLimits::default();
        if limits.lineage.maximum_objects > ceiling.maximum_objects
            || limits.lineage.maximum_bytes > ceiling.maximum_bytes
            || limits.lineage.maximum_edges > ceiling.maximum_edges
        {
            return Err(RuntimeError::ResourceLimit);
        }
        credit(self.source.selection(), quarter).map_err(|_| RuntimeError::ResourceLimit)?;
        self.runtime.host_scheduler_preflight(quarter)?;

        let lineage = self.runtime.host_original_lineage_present();
        let runtime = if lineage {
            HostSchedulingRuntimeRecord::OriginalLineage(Box::new(
                self.runtime.original_lineage_runtime_snapshot(
                    cut,
                    ordinal,
                    limits.lineage,
                    quarter,
                )?,
            ))
        } else {
            HostSchedulingRuntimeRecord::Legacy(Box::new(
                self.runtime.runtime_snapshot(cut, ordinal, quarter)?,
            ))
        };
        let scheduling = self.runtime.host_scheduler_snapshot(cut, ordinal)?;
        let objects = if lineage {
            original_objects(
                self.runtime,
                limits.lineage,
                self.source.selection(),
                &runtime,
                &scheduling,
                limits.maximum_record_bytes,
            )?
        } else {
            Vec::new()
        };
        let record = HostSchedulingContinuationRecord {
            schema_version: 2,
            source: self.source.selection().clone(),
            runtime,
            scheduling,
            objects,
        };
        credit(&record, limits.maximum_record_bytes).map_err(|_| RuntimeError::ResourceLimit)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&record).map_err(|_| RuntimeError::InvalidReceipt)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        Ok(HostSchedulingContinuationV2 {
            record,
            encoded: InputPayload { reference, bytes },
        })
    }
}

fn original_objects(
    runtime: &crate::node_contract::NodeRuntime,
    mut available: OriginalInputLineageLimits,
    source: &HostSchedulingSelection,
    captured_runtime: &HostSchedulingRuntimeRecord,
    scheduling: &SchedulingSnapshot,
    maximum_record_bytes: usize,
) -> Result<Vec<InputPayload>, RuntimeError> {
    let mut borrowed = BTreeMap::new();
    // Charge full role occurrences first; deduplication cannot refund admission.
    for object in runtime.original_lineage_capture_objects() {
        available.maximum_objects = available
            .maximum_objects
            .checked_sub(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        available.maximum_bytes = available
            .maximum_bytes
            .checked_sub(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if let Some(prior) = borrowed.insert(&object.reference, object)
            && prior.bytes != object.bytes
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    #[derive(Serialize)]
    struct BorrowedRecord<'a> {
        schema_version: u16,
        source: &'a HostSchedulingSelection,
        runtime: &'a HostSchedulingRuntimeRecord,
        scheduling: &'a SchedulingSnapshot,
        objects: Vec<&'a InputPayload>,
    }
    let preflight = BorrowedRecord {
        schema_version: 2,
        source,
        runtime: captured_runtime,
        scheduling,
        objects: borrowed.values().copied().collect(),
    };
    // Count the exact final JSON shape, including byte-array expansion, before
    // copying original body bytes. Duplicate references do not renew role credit.
    credit(&preflight, maximum_record_bytes).map_err(|_| RuntimeError::ResourceLimit)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(borrowed.len())
        .map_err(|_| RuntimeError::ResourceLimit)?;
    for object in borrowed.into_values() {
        objects.push(object.clone());
    }
    Ok(objects)
}

#[cfg(test)]
mod tests;
