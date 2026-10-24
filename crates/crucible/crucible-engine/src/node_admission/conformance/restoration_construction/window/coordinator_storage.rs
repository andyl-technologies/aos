//! Quotes the truthful selected coordinator and full activation-manifest phases.
//!
//! All immutable fields are actual original archive/runtime/target loans. Only
//! future readiness/proof references use a closed range projection; it creates
//! neither a DTO nor proof authority. The later constructor must remain within
//! this exact same-source row before retaining its first encoded owner.

use super::coordinator_projection::*;
use super::*;
use crate::node_contract::{
    OriginalLineageNativeScope, OriginalLineageRuntimeRecord, PreparedWorldPublication,
    ValidatedNodePreparation,
};
use crate::node_scheduling::PreparedSchedulingRestore;
use crucible_node_format::{ActivationManifest, HashRef, PreparedOwner, Repeatability, U64};
use serde::Serialize;

/// Describes one concrete selected coordinator/manifest construction as DATA.
///
/// Private construction binds this fixed row to the actual original archive,
/// runtime target and installed roster. Numeric getters carry no allocation,
/// native, publication, context, readiness or activation authority.
#[derive(Clone, Copy)]
pub struct OriginalRestorationCoordinatorConstructionData {
    archive: *const (),
    target: *const ActivationRecord,
    retained: usize,
    transient: usize,
    scratch: usize,
    encoded: usize,
    manifest_retained: usize,
    manifest_transient: usize,
    manifest_scratch: usize,
    manifest_encoded: usize,
    stored_requested: usize,
    stored_encoded: usize,
}

impl OriginalRestorationCoordinatorConstructionData {
    /// Returns the cumulative requested bound for retained coordinator owners.
    pub fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independent simultaneous constructor and comparison work.
    pub fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns separately precredited defining counter and conversion views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked encoded upper extent from the same serializer events.
    pub fn maximum_encoded_bytes_data(&self) -> usize {
        self.encoded
    }

    /// Returns the independent parsed full manifest owner bound during comparison.
    pub fn activation_manifest_retained_requested_bytes_data(&self) -> usize {
        self.manifest_retained
    }

    /// Returns the independent strict parse/DOM/canonical manifest work bound.
    pub fn activation_manifest_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.manifest_transient
    }

    /// Returns the exact defining manifest parse/result/layout scratch roster.
    pub fn activation_manifest_counter_scratch_bytes_data(&self) -> usize {
        self.manifest_scratch
    }

    /// Returns a checked upper bound for the actual full manifest encoding.
    pub fn maximum_activation_manifest_encoded_bytes_data(&self) -> usize {
        self.manifest_encoded
    }

    /// Returns the exact selected durable activation record construction bound.
    pub fn stored_publication_requested_bytes_data(&self) -> usize {
        self.stored_requested
    }

    /// Returns the checked encoded extent of that same durable record projection.
    pub fn maximum_stored_publication_encoded_bytes_data(&self) -> usize {
        self.stored_encoded
    }

    /// Returns separately precredited defining durable-record projection views.
    pub fn stored_publication_counter_scratch_data(&self) -> usize {
        size_of::<FutureStoredPublication<'static>>()
            + size_of::<FutureStoredActivation<'static>>()
            + Self::manifest_counter_scratch_data()
    }

    /// Returns all independently simultaneous coordinator and manifest rows.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow. This performs no owning traversal.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        checked_sum(
            &[
                self.retained,
                self.transient,
                self.scratch,
                self.manifest_retained,
                self.manifest_transient,
                self.manifest_scratch,
            ],
            usize::MAX,
        )
    }

    pub(super) fn authenticate_original_data(
        &self,
        archive: &CompleteOriginalRestorationSource,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        if self.archive != Rc::as_ptr(&archive.inner).cast() || !std::ptr::eq(self.target, target) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn quote(
        plan: &InstalledConformancePlan,
        inputs: &OriginalRestorationConstructionInputs<'_>,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        inputs.authenticate_original_group_data()?;
        if target != inputs.activation {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (world, host) = inputs
            .runtime
            .original_restoration_coordinator_sources_data(plan)?;
        let record = inputs.archive.original_runtime_record_data()?;
        let scheduling = &inputs.archive.original_host_record_data()?.scheduling;
        let nodes = FuturePreparedNodes([
            FuturePreparedNode::native(&inputs.launches[0].selection, target)?,
            FuturePreparedNode::native(&inputs.launches[1].selection, target)?,
            FuturePreparedNode::native(&inputs.launches[2].selection, target)?,
            FuturePreparedNode::host(host, target)?,
        ]);
        let scope = FutureScope {
            archive: inputs.archive,
            record,
            target,
        };
        let proof = super::scope_storage::OriginalRestorationScopeProofProjection {
            schema: super::scope_storage::SCOPE_PROOF_FORMAT,
            source_artifact: inputs.archive.archive().artifact(),
            source_runtime: inputs.archive.runtime_object(),
            target,
            native_held_reference_identities: [[u8::MAX; 32]; 3],
        };
        let scheduling_projection =
            PreparedSchedulingRestore::original_lineage_publication_projection_data(
                record, scheduling, target,
            )?;
        let context = (
            CONTEXT_FORMAT,
            inputs.archive.runtime_object(),
            FutureHash::scheduling(),
            &scope,
            &proof,
        );
        let value = (
            COORDINATOR_FORMAT,
            (
                &target.generation,
                &target.activation_id,
                &target.world_binding_hash,
                &target.owners,
                &target.boundary,
            ),
            world,
            inputs.archive.archive().artifact(),
            inputs.archive.archive().manifest(),
            record,
            scheduling,
            Repeatability::Unqualified,
            &context,
            &scheduling_projection,
            &nodes,
        );
        let (construction, encoded) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                &value,
                Self::maximum_typed_slot_data(),
                maximum,
            )?;
        if encoded > crate::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }

        let mut manifest = 0usize;
        let mut manifest_encoded = 0usize;
        for launch in inputs.launches {
            let selection = &launch.selection;
            let value = FutureManifest {
                schema_version: 1,
                transaction_id: &selection.transaction,
                activation_id: &target.activation_id,
                world_generation: target.generation,
                gate_id: &selection.gate,
                world_binding_hash: &target.world_binding_hash,
                owners: FuturePreparedOwners(&nodes),
                coordinator_state_ref: FutureReference::json(),
                extensions: Default::default(),
            };
            let (requested, encoded) =
                NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                    &value,
                    Self::maximum_typed_slot_data(),
                    maximum,
                )?;
            manifest = manifest.max(requested);
            manifest_encoded = manifest_encoded.max(encoded);
        }
        let stored = FutureStoredPublication {
            format: "crucible.node-world-activation",
            version: 2,
            activation: FutureStoredActivation {
                generation: target.generation,
                activation_id: &target.activation_id,
                world_binding_hash: &target.world_binding_hash,
                owners: &target.owners,
                boundary: target.boundary,
            },
            node_preparations: &nodes,
            prepared_owners: FuturePreparedOwners(&nodes),
            coordinator_state_ref: FutureReference::json(),
        };
        let (stored_requested, stored_encoded) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                &stored,
                Self::maximum_typed_slot_data(),
                maximum,
            )?;
        if stored_encoded > crate::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        let scratch = Self::defining_counter_scratch_data();
        let manifest_scratch = Self::manifest_counter_scratch_data();
        // Each cumulative defining row bounds its constructor/parsed owner as
        // well as the independent simultaneous canonical/DOM work. Keeping both
        // independent rows avoids inferring release from a shared phase label.
        let data = Self {
            archive: Rc::as_ptr(&inputs.archive.inner).cast(),
            target: target as *const _,
            retained: construction,
            transient: construction,
            scratch,
            encoded,
            manifest_retained: manifest,
            manifest_transient: manifest,
            manifest_scratch,
            manifest_encoded,
            stored_requested,
            stored_encoded,
        };
        if data.requested_bytes_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(data)
    }

    pub(super) fn maximum_typed_slot_data() -> usize {
        [
            size_of::<ActivationManifest>(),
            size_of::<PreparedOwner>(),
            size_of::<HashRef>(),
            size_of::<ContentRef>(),
            size_of::<OriginalLineageNativeScope>(),
            size_of::<OriginalLineageRuntimeRecord>(),
            size_of::<ValidatedNodePreparation>(),
            size_of::<crate::node_scheduling::SchedulingSnapshot>(),
            size_of::<serde_json::Value>(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }

    pub(super) fn defining_counter_scratch_data() -> usize {
        NodeRuntime::capture_serialization_counter_scratch_data()
            + projection_counter_scratch_data()
            + coordinator_tuple_counter_scratch_data()
            + super::coordinator_owner::OriginalRestorationCoordinatorOwner::publication_comparison_counter_scratch_data()
            + PreparedSchedulingRestore::original_publication_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<FutureScope<'static>>()
            + size_of::<FuturePreparedNodes<'static>>()
            + size_of::<[FuturePreparedNode<'static>; 4]>()
            + size_of::<FutureReference>()
            + size_of::<FutureHash>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<[usize; 9]>()
            + size_of::<std::array::IntoIter<usize, 9>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<crucible_node_format::U64>()
            + 20
            + super::scope_storage::OriginalRestorationFinalConstructionData::counter_scratch_data()
            + Self::manifest_counter_scratch_data()
    }

    fn manifest_counter_scratch_data() -> usize {
        size_of::<ActivationManifest>()
            + size_of::<Result<ActivationManifest, crucible_node_format::ContractError>>()
            + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
            + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<FutureManifest<'static>>()
            + size_of::<FuturePreparedOwners<'static>>()
            + size_of::<PreparedWorldPublication>()
            + size_of::<Result<&ContentRef, RuntimeError>>()
            + size_of::<Result<&serde_json::Value, RuntimeError>>()
            + size_of::<Result<PreparedWorldPublication, RuntimeError>>()
            + projection_counter_scratch_data()
    }
}

#[derive(Serialize)]
struct FutureManifest<'a> {
    schema_version: u16,
    transaction_id: &'a Id,
    activation_id: &'a Id,
    world_generation: U64,
    gate_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: FuturePreparedOwners<'a>,
    coordinator_state_ref: FutureReference,
    extensions: crucible_node_format::Extensions,
}

#[derive(Serialize)]
struct FutureStoredActivation<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: &'a [crate::node_contract::OwnerIdentity],
    boundary: crucible_node_format::Position,
}

#[derive(Serialize)]
struct FutureStoredPublication<'a> {
    format: &'static str,
    version: u16,
    activation: FutureStoredActivation<'a>,
    node_preparations: &'a FuturePreparedNodes<'a>,
    prepared_owners: FuturePreparedOwners<'a>,
    coordinator_state_ref: FutureReference,
}

// These aliases match the actual future and completed tuple literals. Every
// direct constructor/return view is independently named; the opaque scheduler
// producer also supplies its defining getter so no parent header substitutes
// for its actual nested epoch/outer tuple.
fn coordinator_tuple_counter_scratch_data() -> usize {
    type Target<'a> = (
        &'a U64,
        &'a Id,
        &'a HashRef,
        &'a Vec<crate::node_contract::OwnerIdentity>,
        &'a crucible_node_format::Position,
    );
    type FutureContext<'a> = (
        &'static str,
        &'a ContentRef,
        FutureHash,
        &'a FutureScope<'a>,
        &'a super::scope_storage::OriginalRestorationScopeProofProjection<'a>,
    );
    type FutureCoordinator<'a> = (
        &'static str,
        Target<'a>,
        &'a crucible_node_format::WorldBinding,
        &'a ContentRef,
        &'a crucible_node_format::CaptureManifest,
        &'a OriginalLineageRuntimeRecord,
        &'a crate::node_scheduling::SchedulingSnapshot,
        Repeatability,
        &'a FutureContext<'a>,
        &'a crate::node_scheduling::OriginalSchedulingRestorationPublicationProjection<'a>,
        &'a FuturePreparedNodes<'a>,
    );
    type ActualContext<'a> = (
        &'static str,
        &'a ContentRef,
        &'a HashRef,
        ActualScopeProjection<'a>,
        &'a serde_json::Value,
    );
    type Epoch<'a> = (
        &'a crate::node_scheduling::InputPayload,
        &'a Vec<crate::node_scheduling::SavedSchedulingEpoch>,
        &'a Vec<crate::node_scheduling::InputPayload>,
    );
    type ActualScheduling<'a> = (
        Target<'a>,
        &'a crate::node_scheduling::SchedulingSnapshot,
        &'a Vec<crate::node_scheduling::NativeInputAcknowledgement>,
        Option<Epoch<'a>>,
    );
    type ActualCoordinator<'a> = (
        &'static str,
        Target<'a>,
        &'a crucible_node_format::WorldBinding,
        &'a ContentRef,
        &'a crucible_node_format::CaptureManifest,
        &'a OriginalLineageRuntimeRecord,
        &'a crate::node_scheduling::SchedulingSnapshot,
        Repeatability,
        ActualContext<'a>,
        ActualScheduling<'a>,
        &'a [ValidatedNodePreparation],
    );
    size_of::<Target<'static>>()
        + size_of::<FutureContext<'static>>()
        + size_of::<FutureCoordinator<'static>>()
        + size_of::<Result<FutureCoordinator<'static>, RuntimeError>>()
        + size_of::<ActualContext<'static>>()
        + size_of::<Result<ActualContext<'static>, RuntimeError>>()
        + size_of::<ActualScheduling<'static>>()
        + size_of::<ActualCoordinator<'static>>()
        + size_of::<Result<ActualCoordinator<'static>, RuntimeError>>()
        + size_of::<Result<ActualScopeProjection<'static>, RuntimeError>>()
        + size_of::<
            Result<
                (
                    &'static crucible_node_format::WorldBinding,
                    &'static crate::node_contract::HostSchedulingSource,
                ),
                RuntimeError,
            >,
        >()
        + size_of::<
            Result<
                crate::node_scheduling::OriginalSchedulingRestorationPublicationProjection<'static>,
                RuntimeError,
            >,
        >()
}
