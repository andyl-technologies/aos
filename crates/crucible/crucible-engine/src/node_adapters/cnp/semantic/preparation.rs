//! Generic original realization before common graph and remote admission.

use crucible_node_format::{
    CaptureScope, Continuation, Extensions, Id, NodeBinding, NodeDescriptor, OperatingMode,
    OwnerBinding, Validate,
};
use crucible_node_transport::{bodies::*, envelope::Method};

use crate::node_contract::{FacetKind, OperationFailure};

use super::{
    CnpSemanticInstallation, CnpSemanticLaunchGuard, CnpSemanticRealizationScope,
    InstalledCnpSemanticRole, refused, unknown,
};

/// Retains the original generic process when native or behavioral preparation fails.
pub struct CnpSemanticPreparationFailure {
    /// Classifies the original failure without claiming reclamation or rollback.
    pub error: OperationFailure,
    /// Retains actual native resources, source policy and complete original journals.
    pub guard: CnpSemanticLaunchGuard,
}

impl CnpSemanticPreparationFailure {
    /// Transfers actual native custody without consuming its original refusal.
    ///
    /// # Panics
    /// The original trusted native supervisor must retain without unwinding.
    pub fn retire_original(&mut self) {
        self.guard.retire_original();
    }
}

/// Owns an original generic realized process beneath an authenticated closed gate.
///
/// This capsule grants no common graph, Ready or execution authority. Actual
/// admission still requires the exact source-installed world, repeated current
/// behavioral/native checks and original remote Admit acceptance.
#[must_use = "retain or supervise the complete original generic realization"]
pub struct CnpSemanticPreparation {
    pub(super) guard: CnpSemanticLaunchGuard,
    pub(super) discovery: DiscoverResult,
    pub(super) realization: RealizeResult,
}

#[path = "preparation/fresh_restore_host.rs"]
mod fresh_restore_host;

impl CnpSemanticPreparation {
    /// Transfers native custody while retaining original discovery and realization data.
    ///
    /// # Panics
    /// The original trusted native supervisor must retain without unwinding.
    pub fn retire_original(&mut self) {
        self.guard.retire_original();
    }

    /// Discovers and realizes the exact installed source selection without running it.
    ///
    /// The supervisor reservation and actual Child already exist. Both mandatory
    /// trusted policies are retained before any public realization. Native gate
    /// validation and complete current behavioral acceptance precede remote Admit;
    /// the constructor cannot skip either policy or use a provider-selected subset.
    ///
    /// # Errors
    /// Returns complete guarded originals on unsupported source scope, missing
    /// policy/evidence, changed discovery/realization, invalid native gate,
    /// exhausted finite credit or uncertain original transport effects.
    pub fn prepare(
        guard: CnpSemanticLaunchGuard,
        installed: InstalledCnpSemanticRole,
    ) -> Result<Self, CnpSemanticPreparationFailure> {
        if installed.conformance.is_some() {
            return Err(CnpSemanticPreparationFailure {
                error: refused("ordinary preparation refuses conformance-only custody"),
                guard,
            });
        }
        Self::prepare_installed(guard, installed)
    }

    /// Realizes an independently installed fixture without accepted-class authority.
    ///
    /// # Errors
    /// Retains original custody on failed current fixture/source authentication,
    /// changed realization, insufficient credit, or uncertain transport effects.
    pub fn prepare_for_conformance(
        guard: CnpSemanticLaunchGuard,
        installed: super::InstalledCnpConformanceRole,
    ) -> Result<Self, CnpSemanticPreparationFailure> {
        Self::prepare_installed(guard, installed.0)
    }

    fn prepare_installed(
        guard: CnpSemanticLaunchGuard,
        installed: InstalledCnpSemanticRole,
    ) -> Result<Self, CnpSemanticPreparationFailure> {
        Self::prepare_installed_selected(guard, installed, None)
    }

    pub(in crate::node_adapters::cnp::semantic) fn prepare_original_initial_selected(
        guard: CnpSemanticLaunchGuard,
        installed: super::InstalledCnpConformanceRole,
        discovery: &mut Option<crucible_node_transport::client::OriginalPacketHostInitialResponse>,
        realization: &mut Option<
            crucible_node_transport::client::OriginalPacketHostInitialResponse,
        >,
    ) -> Result<Self, CnpSemanticPreparationFailure> {
        Self::prepare_installed_selected(guard, installed.0, Some((discovery, realization)))
    }

    fn prepare_installed_selected(
        mut guard: CnpSemanticLaunchGuard,
        installed: InstalledCnpSemanticRole,
        mut initial: Option<(
            &mut Option<crucible_node_transport::client::OriginalPacketHostInitialResponse>,
            &mut Option<crucible_node_transport::client::OriginalPacketHostInitialResponse>,
        )>,
    ) -> Result<Self, CnpSemanticPreparationFailure> {
        let InstalledCnpSemanticRole {
            kind,
            policy,
            identity,
            source,
            acceptance,
            conformance,
            collection_plan,
        } = installed;
        let result = (|| {
            if initial.is_none() {
                kind.authenticate(source.installation())?;
                policy.authenticate(source.installation())?;
                if super::registry::installation_identity(source.installation())? != identity {
                    return Err(refused(
                        "generic source changed after original registration",
                    ));
                }
                match (&acceptance, &conformance, &collection_plan) {
                    (Some(_), None, None) => {}
                    (None, Some(authority), Some(plan)) => {
                        authenticate_collection_selection(
                            plan,
                            authority.as_ref(),
                            source.installation(),
                        )?;
                    }
                    _ => return Err(refused("generic qualification mode is absent or ambiguous")),
                }
            }
            let custody = guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("generic original process custody is unavailable"))?;
            if custody.source.is_some()
                || custody.acceptance.is_some()
                || custody.conformance.is_some()
            {
                return Err(refused("generic original realization is already reserved"));
            }
            custody.installation_kind = Some(kind);
            custody.registration = Some(policy);
            custody.installed_identity = Some(identity);
            custody.source = Some(source);
            custody.acceptance = acceptance;
            custody.conformance = conformance;
            custody.collection_plan = collection_plan;
            if initial.is_some() {
                // The actual original role is already held by custody before
                // any selected installed-policy or Source callback can fail.
                let source = custody
                    .source
                    .as_ref()
                    .ok_or_else(|| refused("original initial installed Source absent"))?;
                custody
                    .installation_kind
                    .ok_or_else(|| refused("original initial registration kind absent"))?
                    .authenticate(source.installation())?;
                custody
                    .registration
                    .as_ref()
                    .ok_or_else(|| refused("original initial policy absent"))?
                    .authenticate(source.installation())?;
                if Some(&super::registry::installation_identity(
                    source.installation(),
                )?) != custody.installed_identity.as_ref()
                {
                    return Err(refused("original initial installed identity changed"));
                }
                match (
                    &custody.acceptance,
                    &custody.conformance,
                    &custody.collection_plan,
                ) {
                    (None, Some(authority), Some(plan)) => authenticate_collection_selection(
                        plan,
                        authority.as_ref(),
                        source.installation(),
                    )?,
                    _ => return Err(refused("original initial collecting role changed")),
                }
            }
            let source = custody
                .source
                .as_ref()
                .cloned()
                .ok_or_else(|| refused("generic installed source disappeared"))?;
            custody.authenticate_process().map_err(unknown)?;
            source.authenticate_provider(custody)?;
            source.preflight_transition(custody, super::CnpSemanticTransition::Preparation)?;

            let install = source.installation();
            let controller = custody
                .controller
                .as_mut()
                .ok_or_else(|| refused("generic original controller is unavailable"))?;
            if controller.authority().session_id() != &install.binding.authority.session_id
                || controller.authority().incarnation_id()
                    != &install.binding.authority.incarnation_id
                || controller.route().node != install.descriptor.id
                || controller.route().execution_owner != install.owner.owner.id
            {
                return Err(refused(
                    "generic controller differs from original installed scope",
                ));
            }
            authenticate_current_collection(
                custody.collection_plan.as_ref(),
                custody.conformance.as_deref(),
                install,
            )?;
            let response = if let Some((original, _)) = initial.as_mut() {
                controller
                    .call_original_host_initial_lifecycle_into(
                        request_id("discover", &install.realize.realization_id)?,
                        Method::Discover,
                        original,
                    )
                    .map_err(unknown)?;
                let owner = original
                    .as_ref()
                    .ok_or_else(|| refused("original initial Discover owner absent"))?;
                owner
                    .authenticate_original_controller_data(controller)
                    .map_err(unknown)?;
                owner.response_data().map_err(unknown)?.clone()
            } else {
                controller
                    .call(
                        request_id("discover", &install.realize.realization_id)?,
                        None,
                        Method::Discover,
                        false,
                        DiscoverRequest {
                            profile_ids: vec![install.profile.profile_id.clone()],
                            cursor: None,
                            extensions: Extensions::new(),
                        },
                    )
                    .map_err(unknown)?
            };
            let Some(MethodResult::Discover(discovery)) = response.result else {
                return Err(unknown("generic original discovery did not complete"));
            };
            if !discovery.complete
                || discovery.next_cursor.0.is_some()
                || discovery.provider_manifest != install.provider
                || discovery.profiles != [install.profile.clone()]
                || !discovery.facet_schemas.contains(&install.receipt_schema)
            {
                return Err(unknown(
                    "generic discovery changed the complete installed selection",
                ));
            }
            authenticate_current_collection(
                custody.collection_plan.as_ref(),
                custody.conformance.as_deref(),
                install,
            )?;
            let response = if let Some((_, original)) = initial.as_mut() {
                controller
                    .call_original_host_initial_lifecycle_into(
                        request_id("realize", &install.realize.realization_id)?,
                        Method::Realize,
                        original,
                    )
                    .map_err(unknown)?;
                let owner = original
                    .as_ref()
                    .ok_or_else(|| refused("original initial Realize owner absent"))?;
                owner
                    .authenticate_original_controller_data(controller)
                    .map_err(unknown)?;
                owner.response_data().map_err(unknown)?.clone()
            } else {
                controller
                    .call(
                        request_id("realize", &install.realize.realization_id)?,
                        None,
                        Method::Realize,
                        false,
                        &install.realize,
                    )
                    .map_err(unknown)?
            };
            let Some(MethodResult::Realize(realization)) = response.result else {
                return Err(unknown("generic original realization did not complete"));
            };
            let manifest = &realization.realization_manifest;
            if manifest.realization_id != install.realize.realization_id
                || manifest.provider_manifest
                    != crucible_node_format::canonical::content_ref(
                        &crucible_node_format::canonical::canonical_json(
                            &serde_json::to_value(&install.provider).map_err(unknown)?,
                        )
                        .map_err(unknown)?,
                        "application/json",
                    )
                    .map_err(unknown)?
                || manifest.descriptors != [install.descriptor.clone()]
                || manifest.bindings != [install.binding.clone()]
                || manifest.owners != [install.owner.owner.clone()]
                || manifest.owner_bindings != [install.owner.clone()]
                || !manifest.extensions.is_empty()
            {
                return Err(unknown(
                    "generic realization changed original complete source/native bindings",
                ));
            }
            Ok((discovery, realization))
        })();
        match result {
            Ok((discovery, realization)) => {
                let preparation = Self {
                    guard,
                    discovery,
                    realization,
                };
                if initial.is_some() {
                    // The selected caller installs this same preparation in its
                    // original output slot before invoking terminal callbacks.
                    // Both original response owners already remain in the SDK.
                    return Ok(preparation);
                }
                match preparation.reauthenticate() {
                    Ok(()) => Ok(preparation),
                    Err(error) => Err(CnpSemanticPreparationFailure {
                        // Realize has already crossed the original native
                        // boundary. A later source/gate rejection cannot claim
                        // that no effects or allocations occurred there.
                        error: super::after_effect(error),
                        guard: preparation.guard,
                    }),
                }
            }
            Err(error) => Err(CnpSemanticPreparationFailure { error, guard }),
        }
    }

    /// Borrows the exact independently verified actual realized descriptor.
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.realization.realization_manifest.descriptors[0]
    }

    /// Borrows original source compatibility and actual live authority.
    pub fn binding(&self) -> &NodeBinding {
        &self.realization.realization_manifest.bindings[0]
    }

    /// Borrows the original complete indivisible native owner binding.
    pub fn owner_binding(&self) -> &OwnerBinding {
        &self.realization.realization_manifest.owner_bindings[0]
    }

    pub(super) fn authenticate_native_dispatch(&self) -> Result<(), OperationFailure> {
        let native = self.guard.custody().map_err(unknown)?;
        match (&native.collection_plan, &native.conformance) {
            (None, None) => Ok(()),
            (Some(plan), Some(authority)) if plan.has_authority(authority.as_ref()) => {
                authority.authenticate_native_dispatch(self.scope()?, plan)?;
                // No source/vendor callback follows the terminal installed read.
                // This view comes from the same actual capsule, not a saved DTO.
                native
                    .original_source_read()
                    .map_err(unknown)?
                    .ensure_current()
                    .map_err(unknown)
            }
            _ => Err(refused(
                "generic original collection dispatch authority changed",
            )),
        }
    }

    pub(super) fn scope(&self) -> Result<CnpSemanticRealizationScope<'_>, OperationFailure> {
        let native = self.guard.custody().map_err(unknown)?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| refused("generic installed source is unavailable"))?;
        Ok(CnpSemanticRealizationScope {
            installation: source.installation(),
            native,
            controller: native
                .controller()
                .ok_or_else(|| refused("generic original controller is unavailable"))?,
            discovery: &self.discovery,
            realization: &self.realization,
        })
    }

    pub(super) fn reauthenticate(&self) -> Result<(), OperationFailure> {
        let native = self.guard.custody().map_err(unknown)?;
        native.authenticate_process().map_err(unknown)?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| refused("generic source is absent"))?;
        native
            .installation_kind
            .ok_or_else(|| refused("generic original registration kind absent"))?
            .authenticate(source.installation())?;
        if native.installed_identity.as_ref()
            != Some(&super::registry::installation_identity(
                source.installation(),
            )?)
        {
            return Err(refused(
                "generic current source changed original installed selection",
            ));
        }
        native
            .registration
            .as_ref()
            .ok_or_else(|| refused("generic independent source registration policy is absent"))?
            .authenticate(source.installation())?;
        source.authenticate_provider(native)?;
        source.authenticate_realization(self.scope()?)?;
        match (&native.acceptance, &native.conformance) {
            (Some(acceptance), None) => acceptance.authenticate(self.scope()?),
            (None, Some(authority)) => {
                let plan = native
                    .collection_plan
                    .as_ref()
                    .ok_or_else(|| refused("original collection plan is absent"))?;
                authenticate_collection_selection(plan, authority.as_ref(), source.installation())?;
                authority.authenticate_realization(self.scope()?)
            }
            _ => Err(refused("generic qualification mode is absent or ambiguous")),
        }
    }
}

// Rechecks the independently retained plan immediately before each native
// realization request. Installation authorization alone cannot keep a revoked
// collection plan live, and portable matching bytes cannot substitute its owner.
fn authenticate_current_collection(
    plan: Option<&crate::node_admission::InstalledConformancePlan>,
    authority: Option<&dyn super::CnpSemanticConformanceAuthority>,
    install: &CnpSemanticInstallation,
) -> Result<(), OperationFailure> {
    match (plan, authority) {
        (None, None) => Ok(()),
        (Some(plan), Some(authority)) => {
            authenticate_collection_selection(plan, authority, install)
        }
        _ => Err(refused(
            "original collection plan authority is absent or ambiguous",
        )),
    }
}

pub(super) fn authenticate_collection_selection(
    plan: &crate::node_admission::InstalledConformancePlan,
    authority: &dyn super::CnpSemanticConformanceAuthority,
    install: &CnpSemanticInstallation,
) -> Result<(), OperationFailure> {
    plan.reauthenticate()
        .map_err(crate::node_adapters::cnp::semantic::refused_display)?;
    if !plan.has_authority(authority) || plan.evidence().world != &install.world_binding_hash {
        return Err(refused(
            "collection source differs from original installed plan authority",
        ));
    }
    authority.authenticate_installation(install)
}

pub(super) fn validate_installation(
    install: &CnpSemanticInstallation,
) -> Result<(), OperationFailure> {
    validate_installation_selected(install, false)
}

// Only the concrete Source5 conformance registration chooses this validator.
// Ordinary registry/prepare entry points retain the exact-only selector above.
pub(super) fn validate_complete_installation(
    install: &CnpSemanticInstallation,
) -> Result<(), OperationFailure> {
    validate_installation_selected(install, true)
}

fn validate_installation_selected(
    install: &CnpSemanticInstallation,
    complete_packet: bool,
) -> Result<(), OperationFailure> {
    if install.maximum_semantic_bytes == 0 || install.maximum_semantic_bytes > 256 * 1024 * 1024 {
        return Err(refused(
            "generic installed semantic byte geometry is unsupported",
        ));
    }
    if install.maximum_result_bytes < 4096
        || install.maximum_result_bytes > install.maximum_semantic_bytes
        || install.maximum_authorization_bytes == 0
        || install.maximum_authorization_bytes > install.maximum_semantic_bytes
    {
        return Err(refused(
            "generic source callback/result credit is unsupported",
        ));
    }
    let mut initial_credit = super::budget::SemanticCredit::default();
    initial_credit.reserve(&install.provider, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.profile, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.descriptor, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.binding, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.owner, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.realize, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.guarantees, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.capabilities, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.exact_facet, install.maximum_semantic_bytes)?;
    initial_credit.reserve(&install.receipt_schema, install.maximum_semantic_bytes)?;
    install.provider.validate().map_err(unknown)?;
    install.profile.validate().map_err(unknown)?;
    install.descriptor.validate().map_err(unknown)?;
    install.binding.validate().map_err(unknown)?;
    install.guarantees.validate().map_err(unknown)?;
    install.capabilities.validate().map_err(unknown)?;
    install.exact_facet.validate().map_err(unknown)?;
    let canonical_body = |value: serde_json::Value| {
        crucible_node_format::canonical::canonical_json(&value).map_err(unknown)
    };
    let guarantee_bytes =
        canonical_body(serde_json::to_value(&install.guarantees).map_err(unknown)?)?;
    install
        .binding
        .compatibility
        .guarantees_ref
        .verify(&guarantee_bytes)
        .map_err(unknown)?;
    let capability_bytes =
        canonical_body(serde_json::to_value(&install.capabilities).map_err(unknown)?)?;
    install
        .binding
        .compatibility
        .capabilities_ref
        .verify(&capability_bytes)
        .map_err(unknown)?;
    install.owner.validate().map_err(unknown)?;
    install.realize.validate().map_err(unknown)?;
    install.receipt_schema.validate().map_err(unknown)?;
    install.world_binding_hash.validate().map_err(unknown)?;
    let owner = &install.owner.owner;
    if install.maximum_operations == 0
        || install.maximum_operations > 4096
        || install.maximum_operations as u64
            > install.realize.resource_limits.maximum_operations.get()
        || install.maximum_semantic_bytes == 0
        || install.maximum_semantic_bytes > 256 * 1024 * 1024
        || install.maximum_semantic_bytes as u64
            > install.realize.resource_limits.memory_bytes.get()
        || install.realize.requested_node_ids.as_slice() != [install.descriptor.id.clone()]
        || install.binding.compatibility.node_id != install.descriptor.id
        || install.binding.compatibility.descriptor_hash
            != install.descriptor.identity().map_err(unknown)?
        || owner.participant_ids.as_slice() != [install.descriptor.id.clone()]
        || install.binding.compatibility.execution_owner != *owner
        || install.binding.compatibility.capture_owner != *owner
        || install.owner.node_bindings[0].binding_hash
            != install.binding.identity().map_err(unknown)?
        || install.exact_facet.guarantees_ref != install.binding.compatibility.guarantees_ref
        || !install
            .provider
            .protocol_versions
            .contains(&Id::new("CNP/1").map_err(unknown)?)
        || install.binding.authority.world_generation.get() != 0
        || install.binding.authority.activation_id.is_some()
        || install.binding.authority.realization_id != install.realize.realization_id
        || install.binding.compatibility.operating_contract.mode != OperatingMode::Exact
        || selected_facets_changed(install, complete_packet)
        || install.binding.compatibility.implementation != install.provider.implementation
        || !install
            .provider
            .supported_profiles
            .contains(&install.profile)
        || !install
            .provider
            .implementation
            .formats
            .contains(&install.receipt_schema)
        || install.profile.roles != install.descriptor.roles
        || install.world_binding_hash.domain != "cnp.world-binding.v1"
    {
        return Err(refused(
            "generic source installation or exact single-owner selection is unsupported",
        ));
    }
    // Ordinary generic installations cannot select preservation. The concrete
    // complete packet path validates its declaration but still requires actual
    // source callbacks and installed capture authority before any effect.
    let guarantees = &install.guarantees;
    if if complete_packet {
        guarantees.capture_scope != CaptureScope::CompleteModel
            || guarantees.continuation != Continuation::Exact
            || !guarantees.durable_restart
            || guarantees.repeatability != crucible_node_format::Repeatability::Unqualified
            || guarantees.isolated_fork || guarantees.conditional_replay
            || install.provider.implementation.implementation_id.as_str()!="source-owned.packet-native/5"
            || install.profile.profile_id.as_str()!="source-owned.packet-complete-original-lineage/5"
            || install.exact_facet.id.as_str()!="source-owned.packet-exact/5"
            || install.exact_facet.version!=5
            || install.receipt_schema != crucible_node_transport::reference_packet::continuation_contracts::complete_packet_receipt_schema().map_err(unknown)?
    } else {
        guarantees.capture_scope != CaptureScope::None
            || guarantees.continuation != Continuation::Unsupported
            || guarantees.durable_restart
            || guarantees.isolated_fork
            || guarantees.conditional_replay
    } {
        return Err(refused(
            "generic initial source scope has no qualified preservation or replay",
        ));
    }
    Ok(())
}

fn selected_facets_changed(install: &CnpSemanticInstallation, complete_packet: bool) -> bool {
    if !complete_packet {
        return install.facets.as_slice() != [FacetKind::ExactExecution]
            || install
                .binding
                .compatibility
                .operating_contract
                .facets
                .as_slice()
                != std::slice::from_ref(&install.exact_facet)
            || install.profile.operation_facets.as_slice()
                != std::slice::from_ref(&install.exact_facet)
            || install.capabilities.facets.as_slice()
                != std::slice::from_ref(&install.exact_facet);
    }

    let facets = &install.binding.compatibility.operating_contract.facets;
    let source_table_changed = install.facets.as_slice()
        != [FacetKind::ExactExecution, FacetKind::Preservation]
        || facets.len() != 2
        || !facets.contains(&install.exact_facet)
        || install.profile.operation_facets != *facets
        || install.capabilities.facets != *facets;
    if source_table_changed {
        return true;
    }

    facets.iter().any(|facet| {
        facet.version != 5
            || facet.configuration_ref != install.binding.compatibility.configuration_ref
            || facet.guarantees_ref != install.binding.compatibility.guarantees_ref
            || !facet.extensions.is_empty()
            || !matches!(
                facet.id.as_str(),
                "source-owned.packet-exact/5" | "source-owned.packet-complete-original-lineage/5"
            )
    })
}

pub(super) fn request_id(prefix: &str, original: &Id) -> Result<Id, OperationFailure> {
    Id::new(format!("cnp-{prefix}-{original}"))
        .map_err(crate::node_adapters::cnp::semantic::refused_display)
}

#[path = "preparation/oracle_body_storage.rs"]
mod oracle_body_storage;
