//! Joins the actual original packet guard to its opaque collecting runtime.
//!
//! This preparation uses the public source registry, native realization,
//! complete graph admission and provider transfer. It does not spawn a second
//! peer or replace any native receipt. Every failure retains the exact original
//! guard, preparation, node or runtime and its separately reserved supervisor.

use std::rc::Rc;

use crucible::node_adapters::cnp::{
    CnpSemanticAdmissionFailure, CnpSemanticConformanceProvider, CnpSemanticLaunchGuard,
    CnpSemanticPreparation, CnpSemanticPreparationFailure, CnpSemanticProviderFailure,
    CnpSemanticRegistry, CnpSemanticSource,
};
use crucible::node_admission::{
    AdmissionError, AdmissionLimits, AdmissionRequest, InstalledConformancePlan,
    ScenarioRequirements, admit_conformance_graph,
};
use crucible::node_contract::{
    ActivationRecord, ConformanceRuntime, ConformanceRuntimeFailure, RuntimeCustodySlot,
    RuntimeLimits,
};

use super::{InstalledPacketCollectionAuthority, QualificationError};

/// Borrows the independently authored complete world before native realization.
///
/// Both supervisor reservations must already exist before Child allocation. The
/// supplied guard owns that actual Child and original authenticated controller;
/// this request cannot construct either from portable identifiers.
pub struct PacketOriginalRuntimeRequest<'a> {
    /// Borrows the same opaque installed Refused plan used by the source registry.
    pub plan: &'a InstalledConformancePlan,
    /// Borrows the exact immutable scenario requirements bound into the world.
    pub requirements: &'a ScenarioRequirements,
    /// Retains the original initial activation proposal, never predicted Ready.
    pub activation: ActivationRecord,
    /// Bounds ordinary structural/schema/owner admission independently.
    pub admission_limits: AdmissionLimits,
    /// Bounds all original runtime ledgers before native Arm or Begin.
    pub runtime_limits: RuntimeLimits,
    /// Retains the independently pre-reserved whole-runtime cleanup owner.
    pub runtime_custody: Box<dyn RuntimeCustodySlot>,
}

/// Retains each authentic preparation owner without asserting native reclamation.
pub enum PacketOriginalRuntimeFailure {
    /// Retains the actual untouched guard and runtime reservation on host refusal.
    Installation {
        /// Describes the original current/source/credit refusal.
        error: QualificationError,
        /// Retains the original Child, controller and native journals.
        guard: Box<CnpSemanticLaunchGuard>,
        /// Retains the original independent whole-runtime reservation.
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    },
    /// Retains the authentic failed Discover/Realize guard and runtime reservation.
    Realization {
        /// Retains the original native preparation failure, including its guard.
        failure: CnpSemanticPreparationFailure,
        /// Retains the original independent whole-runtime reservation.
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    },
    /// Retains the exact realized native preparation when graph admission refuses.
    Graph {
        /// Describes the ordinary structural or current collecting-scope failure.
        error: AdmissionError,
        /// Retains the actual realization and original public transport bodies.
        preparation: Box<CnpSemanticPreparation>,
        /// Retains the original independent whole-runtime reservation.
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    },
    /// Retains the original failed remote Admit and whole-runtime reservation.
    Admission {
        /// Retains actual native preparation and original Admit disposition.
        failure: CnpSemanticAdmissionFailure,
        /// Retains the original independent whole-runtime reservation.
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    },
    /// Retains the exact inactive node when provider transfer refuses.
    Provider {
        /// Retains the actual original node and native journals.
        failure: CnpSemanticProviderFailure,
        /// Retains the original independent whole-runtime reservation.
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    },
    /// Retains every actual node in its original reserved runtime cleanup owner.
    Runtime(ConformanceRuntimeFailure),
}

impl InstalledPacketCollectionAuthority {
    /// Prepares the one actual source-installed peer through public common APIs.
    ///
    /// The caller reserves native and runtime custody before launch, negotiates
    /// the original Hello, installs the SDK immutable packet verifier, and
    /// attaches that same controller to the guard. This method reauthenticates
    /// the independently installed Refused plan before Discover/Realize. It then
    /// validates the full original graph, submits original remote Admit, and
    /// transfers only that inactive native node into the collecting runtime.
    /// All-owner Arm and authentic initial publication remain later operations.
    ///
    /// # Errors
    /// Retains original custody on foreign plan/world/activation, insufficient
    /// credit, revoked installation, missing immutable transport selection,
    /// source registration, realization, admission or provider/runtime failure.
    /// It never substitutes ordinary behavioral qualification or returns an
    /// ordinary graph, node, activation permit or runtime.
    pub fn prepare_original_runtime(
        self: &Rc<Self>,
        guard: CnpSemanticLaunchGuard,
        registry: &mut CnpSemanticRegistry,
        request: PacketOriginalRuntimeRequest<'_>,
    ) -> Result<ConformanceRuntime, PacketOriginalRuntimeFailure> {
        let installed = (|| {
            if request.plan.authenticate_authority(self.as_ref()).is_err()
                || request.activation.world_binding_hash
                    != self.source.installation().world_binding_hash
                || request.activation.owners.len() != 1
                || request.activation.owners[0].owner != self.source.installation().owner.owner.id
                || request.activation.owners[0].incarnation
                    != self.source.installation().binding.authority.incarnation_id
                || request.activation.owners[0].generation
                    != self
                        .source
                        .installation()
                        .binding
                        .authority
                        .owner_generation
            {
                return Err(QualificationError::Refused(
                    "packet preparation original plan or activation differs",
                ));
            }
            // Count complete borrowed scenario/activation before any further
            // retained copies or source/native realization request.
            super::scope::encoded_size(
                &(
                    &self.world,
                    request.requirements,
                    super::scope::activation_view(&request.activation),
                ),
                8 * 1024 * 1024,
            )?;
            self.current()?;
            request.plan.reauthenticate().map_err(|_| {
                QualificationError::Refused("packet original preparation plan revoked")
            })?;
            let native = guard.custody().map_err(|_| {
                QualificationError::Refused("packet original attached guard unavailable")
            })?;
            self.source.authenticate_provider(native).map_err(|_| {
                QualificationError::Refused("packet original kernel or transport differs")
            })?;
            registry
                .install_for_conformance(self.source.clone(), self.clone(), request.plan)
                .map_err(|_| QualificationError::Refused("packet source registry refused"))
        })();
        let installed = match installed {
            Ok(installed) => installed,
            Err(error) => {
                return Err(PacketOriginalRuntimeFailure::Installation {
                    error,
                    guard: Box::new(guard),
                    runtime_custody: request.runtime_custody,
                });
            }
        };

        let preparation = match CnpSemanticPreparation::prepare_for_conformance(guard, installed) {
            Ok(preparation) => preparation,
            Err(failure) => {
                return Err(PacketOriginalRuntimeFailure::Realization {
                    failure,
                    runtime_custody: request.runtime_custody,
                });
            }
        };
        let selection = self.source.installation();
        let graph = match admit_conformance_graph(
            AdmissionRequest {
                world: &self.world,
                descriptors: std::slice::from_ref(&selection.descriptor),
                bindings: std::slice::from_ref(&selection.binding),
                owners: std::slice::from_ref(&selection.owner),
                requirements: request.requirements,
            },
            request.plan,
            request.admission_limits,
        ) {
            Ok(graph) => graph,
            Err(error) => {
                return Err(PacketOriginalRuntimeFailure::Graph {
                    error,
                    preparation: Box::new(preparation),
                    runtime_custody: request.runtime_custody,
                });
            }
        };

        let node = match preparation.into_conformance_node(&graph) {
            Ok(node) => node,
            Err(failure) => {
                return Err(PacketOriginalRuntimeFailure::Admission {
                    failure,
                    runtime_custody: request.runtime_custody,
                });
            }
        };
        let provider = match CnpSemanticConformanceProvider::new(node, request.activation) {
            Ok(provider) => provider,
            Err(failure) => {
                return Err(PacketOriginalRuntimeFailure::Provider {
                    failure,
                    runtime_custody: request.runtime_custody,
                });
            }
        };
        provider
            .prepare_conformance(graph, request.runtime_limits, request.runtime_custody)
            .map_err(PacketOriginalRuntimeFailure::Runtime)
    }
}
