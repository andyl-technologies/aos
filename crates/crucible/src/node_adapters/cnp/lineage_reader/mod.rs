//! Owns selected lineage controls under complete pre-reserved host custody.
//!
//! Installation remains independent of wire syntax. The selected adapter keeps
//! both original groups, opaque admissions, inputs, source proof rows and all
//! unknown outcomes together. The legacy public control and its one-group
//! source qualification are unchanged.

use super::lineage::OriginalRuntimeLineage;
use crate::{node_admission::AdmittedGraph, node_contract::OperationFailure};
use control::ReaderState;
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, client::OriginalLineageRealization, reference_device::DeviceStatus,
    reference_lineage::LineageSourceGuard,
};
use std::collections::BTreeMap;

mod activation;
mod boundary;
mod collection;
mod control;
mod delegate;
mod implementation;
mod input;
mod input_evidence;
mod inventory;
mod lifecycle;
mod negotiation;
mod pending;
mod publication;
mod readiness;
mod transport;
mod window_evidence;
mod windows;

/// Authenticates the separately installed selected source against original custody.
///
/// A trusted installation independently measures the distinct provider/native
/// closure, kernel ancestry, original profile and exact negotiated selection.
/// Parsed rows, handler hashes and matching labels cannot implement that policy.
pub trait LineageReferenceQualification {
    /// Borrows the complete fixture plan identity, or None for ordinary policy.
    ///
    /// This marks a collection-only preparation. It grants no graph or native
    /// authority; ordinary selected constructors refuse such a policy.
    fn collection_plan(&self) -> Option<&ContentRef> {
        None
    }

    /// Authenticates actual selected custody under the opaque installed plan.
    ///
    /// # Errors
    /// Defaults to refusal. Independent fixture policy must compare the complete
    /// original plan, current source/kernel realization and retained authority.
    fn authenticate_collection_scope(
        &self,
        _guard: &LineageSourceGuard,
        _original: &OriginalLineageRealization<'_>,
        _plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "installed collection source policy unavailable",
        ))
    }

    /// Performs the final installed source read before a collecting native send.
    ///
    /// The selected adapter invokes this after its internal policy callbacks,
    /// immediately before the original guarded call or upload. The installed
    /// implementation must finish with direct original owner/registrar reads;
    /// serialized source labels cannot satisfy this callback.
    ///
    /// # Errors
    /// Refuses unavailable terminal authority, changed plan or revoked original
    /// source ownership. Ordinary source controls do not invoke this hook.
    fn authenticate_collection_dispatch(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "installed collection terminal source read unavailable",
        ))
    }

    /// Authenticates original initialized realization before common world readiness.
    ///
    /// # Errors
    /// Refuses unsupported source installation, kernel scope, original raw Ready
    /// or full profile/source contract disagreement.
    fn authenticate_realization(
        &self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
    ) -> Result<(), ProviderError>;

    /// Authenticates the installed typed source and its exact admitted interpretation.
    ///
    /// The source policy independently authenticates the complete original peer
    /// selection, measured definition/profile and dynamic input handler. When
    /// `admitted` is present it also checks the frozen graph's exact durable
    /// facet, compatibility and schema applications for this original node.
    /// A namespace label or successful Hello cannot satisfy this callback.
    ///
    /// # Errors
    /// Refuses by default. An installed policy refuses altered source contracts,
    /// unsupported graph scope or a missing independently installed handler.
    fn authenticate_peer_extensions(
        &self,
        _guard: &LineageSourceGuard,
        _original: &OriginalLineageRealization<'_>,
        _selected: &[ExtensionSelection],
        _admitted: Option<(&AdmittedGraph, &Id)>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "installed typed lineage source policy unavailable",
        ))
    }

    /// Authenticates original producers before a distinct typed native Stage.
    ///
    /// The opaque runtime lineage remains conjunctive with independent installed
    /// source enrollment and original publication witnesses. Metadata alone
    /// cannot authorize this callback or replace a producer's original custody.
    ///
    /// # Errors
    /// Refuses by default, before selected native input effects or retention.
    fn authenticate_original_inputs(
        &self,
        _guard: &LineageSourceGuard,
        _original: &crate::node_scheduling::RuntimeInputBatch,
        _provenance: &crate::node_contract::InputProvenanceClosure,
        _lineage: &crate::node_contract::OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "installed typed original input policy unavailable",
        ))
    }

    /// Authenticates actual ordered native consumption against opaque common input.
    ///
    /// # Errors
    /// Refuses changed installation, original public/native input or preceding
    /// checksum/output ACK closure. This does not invent same-time parent IDs.
    fn authenticate_window(
        &self,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError>;
}

/// Reserves complete selected host/native state before either group is spawned.
///
/// Its owner services original reclamation on the runtime thread. Retention must
/// survive caller drop and callback unwind; an unowned vector is insufficient.
pub trait LineageRuntimeCustodySlot {
    /// Returns the original finite host reservation identity.
    fn identity(&self) -> U64;

    /// Takes the complete original host/native capsule exactly once.
    fn retain(self: Box<Self>, custody: LineageRuntimeCustody);
}

/// Owns both groups and all original input, operation and proof custody.
///
/// This historical capsule supplies no Ready or source-class authority.
pub struct LineageRuntimeCustody {
    state: Box<ReaderState>,
}

impl LineageRuntimeCustody {
    /// Services original group reclamation without discarding historical journals.
    ///
    /// # Errors
    /// Retains the complete capsule on unknown census, signal or wait failure.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        self.state.poll_reclamation()
    }
}

/// Owns the selected native controls and their complete common-runtime obligations.
///
/// Construction requires an actual original initialized guard plus independently
/// installed source qualification. Neither a body DTO nor a Ready hash can
/// construct this control. Drop transfers its already allocated complete state.
pub struct LineageControlledReference {
    state: Option<Box<ReaderState>>,
    slot: Option<Box<dyn LineageRuntimeCustodySlot>>,
    owner: Id,
    incarnation: Id,
    generation: U64,
    native_pid: u32,
    supervision: U64,
}

/// Retains original native and installation custody when selected preparation refuses.
pub struct LineagePreparationFailure {
    /// Reports the original refusal without discarding native uncertainty.
    pub error: ProviderError,
    /// Owns original provider, companion and raw control journals.
    pub guard: LineageSourceGuard,
    /// Owns the original installed source policy through cleanup.
    pub qualification: Box<dyn LineageReferenceQualification>,
    /// Retains the prior complete-host reservation.
    pub slot: Box<dyn LineageRuntimeCustodySlot>,
}

impl LineageControlledReference {
    /// Takes an actual original selected realization under its prior host reservation.
    ///
    /// This performs only source/kernel/read-only original checks; the actual
    /// source actor has already retained Initialize/Ready and the closed gate.
    /// World readiness and operation authority are subsequently issued by the
    /// complete common-runtime barrier under independently admitted graph scope.
    ///
    /// # Errors
    /// Returns complete original custody on source refusal, unknown realization,
    /// unsupported selection, invalid finite credits or changed native scope.
    pub fn from_original(
        guard: LineageSourceGuard,
        realization: Id,
        qualification: Box<dyn LineageReferenceQualification>,
        slot: Box<dyn LineageRuntimeCustodySlot>,
        maximum_operations: usize,
    ) -> Result<Self, Box<LineagePreparationFailure>> {
        Self::prepare_original(
            guard,
            realization,
            qualification,
            slot,
            maximum_operations,
            negotiation::ReaderTransport::Legacy,
        )
    }

    fn prepare_original(
        guard: LineageSourceGuard,
        realization: Id,
        qualification: Box<dyn LineageReferenceQualification>,
        slot: Box<dyn LineageRuntimeCustodySlot>,
        maximum_operations: usize,
        transport: negotiation::ReaderTransport,
    ) -> Result<Self, Box<LineagePreparationFailure>> {
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guard.with_original_realization(&realization, |original| {
                transport.authenticate(&guard, &original, qualification.as_ref(), None)?;
                qualification.authenticate_realization(&guard, &original)?;
                transport.verify_registrar(&guard)?;
                if maximum_operations == 0
                    || maximum_operations > 65_536
                    || slot.identity().get() == 0
                    || original.profile().input_lineage_definition().is_none()
                {
                    return Err(ProviderError::Correlation(
                        "selected runtime preparation credit or profile differs",
                    ));
                }
                let [binding] = original
                    .realization()
                    .realization_manifest
                    .bindings
                    .as_slice()
                else {
                    return Err(ProviderError::Correlation(
                        "original selected binding roster differs",
                    ));
                };
                let [owner_binding] = original
                    .realization()
                    .realization_manifest
                    .owner_bindings
                    .as_slice()
                else {
                    return Err(ProviderError::Correlation(
                        "original selected owner roster differs",
                    ));
                };
                let pid = u32::try_from(original.native_pid().get()).map_err(|_| {
                    ProviderError::Correlation("original selected native PID exceeds kernel domain")
                })?;
                Ok((
                    original.profile().clone(),
                    original.bootstrap().clone(),
                    binding.clone(),
                    owner_binding.clone(),
                    original.gate().clone(),
                    pid,
                ))
            })
        }));
        let original = match checked {
            Ok(original) => original,
            Err(_) => Err(ProviderError::Correlation(
                "installed lineage preparation callback panicked",
            )),
        };
        let (profile, bootstrap, binding, owner_binding, gate, native_pid) = match original {
            Ok(original) => original,
            Err(error) => {
                return Err(Box::new(LineagePreparationFailure {
                    error,
                    guard,
                    qualification,
                    slot,
                }));
            }
        };
        let supervision = slot.identity();
        let owner = owner_binding.owner.id.clone();
        let incarnation = binding.authority.incarnation_id.clone();
        let generation = binding.authority.owner_generation;
        let runtime = super::control::CnpRuntimeCustody {
            binding,
            owner_binding,
            gate,
            companion_pid: native_pid,
            status: DeviceStatus::Parked,
            preparation_attempt: None,
            prepared: None,
            active: None,
            input: None,
            windows: BTreeMap::new(),
            pending: None,
            maximum_operations,
            next_input_sequence: U64::new(1),
            checksum: 0,
            boundary_evidence: BTreeMap::new(),
            boundary_dependencies: BTreeMap::new(),
        };
        Ok(Self {
            state: Some(Box::new(ReaderState {
                guard,
                runtime,
                profile,
                bootstrap,
                realization,
                qualification,
                supervision,
                input_lineages: BTreeMap::new(),
                transport,
                collection: None,
            })),
            slot: Some(slot),
            owner,
            incarnation,
            generation,
            native_pid,
            supervision,
        })
    }

    /// Installs original selected control into an independently admitted graph.
    ///
    /// # Errors
    /// Rejects a changed original descriptor/binding, selected facet or graph
    /// guarantee. Constructor failure transfers the original complete capsule.
    pub fn into_node(
        self,
        graph: &AdmittedGraph,
        node: &Id,
        maximum_operations: usize,
    ) -> Result<
        crate::node_adapters::reference_device::ControlledReferenceNode<Self>,
        OperationFailure,
    > {
        self.install_node(
            graph,
            node,
            maximum_operations,
            negotiation::ReaderTransport::Legacy,
        )
    }

    fn state(&self) -> Result<&ReaderState, ProviderError> {
        self.state.as_deref().ok_or(ProviderError::Correlation(
            "original selected state transferred",
        ))
    }

    fn state_mut(&mut self) -> Result<&mut ReaderState, ProviderError> {
        self.state.as_deref_mut().ok_or(ProviderError::Correlation(
            "original selected state transferred",
        ))
    }
}

impl Drop for LineageControlledReference {
    fn drop(&mut self) {
        if let (Some(state), Some(slot)) = (self.state.take(), self.slot.take()) {
            state.guard.revoke_read_handles();
            slot.retain(LineageRuntimeCustody { state });
        }
    }
}
