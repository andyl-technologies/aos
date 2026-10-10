//! Source-installed public discovery and actual closed-gate realization before graph sealing.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, conformance::measure_executable, envelope::Method,
    reference_service::ReferenceProfile,
};
use rustix::process::{Pid, getpgid};

use crate::node_contract::{EffectKnowledge, OperationFailure};

use super::process::CnpLaunchGuard;

/// Authenticates installed source semantics independently of provider-advertised receipts.
///
/// Implementations belong to the trusted host installation registry. They must
/// inspect the actual retained Child and complete measured source/model profile.
/// Wire schemas, byte custody and vendor assertions cannot implement this gate.
pub trait CnpReferenceQualification {
    /// Authenticates the actual original installed endpoint before native realization.
    ///
    /// # Errors
    /// Rejects foreign native custody, unqualified source or changed model identity.
    fn authenticate_provider(
        &self,
        guard: &CnpLaunchGuard,
        profile: &ReferenceProfile,
    ) -> Result<(), OperationFailure>;

    /// Authenticates an exact adverse population beneath original preparation.
    ///
    /// Source policy checks unchanged complete binding and independently measured
    /// native provider/companion custody. Data responses mint no runtime authority.
    ///
    /// # Errors
    /// Refuses by default or when source scope, original IDs/body population or
    /// actual native preparation differs from the installed immutable fixture.
    fn authenticate_prepared_adverse_probes(
        &self,
        _: &CnpReferencePreparation,
        _: &[super::CnpPreparedAdverseRequest],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "source-qualified prepared adverse controls are not installed".into(),
        })
    }

    /// Authenticates the exact planned controls and actual provider-only scope.
    ///
    /// A cached absence of companion metadata is insufficient. Installed policy
    /// must independently establish the actual native premise and authorize the
    /// complete immutable probe population before any control is dispatched.
    /// Ordinary preparation does not invoke this optional qualification seam.
    ///
    /// # Errors
    /// Refuses by default. Installed policy rejects unplanned bodies/identities,
    /// absent native premises, changed source or unsupported qualification scope.
    fn authenticate_pre_realization_probes(
        &self,
        _: &CnpLaunchGuard,
        _: &[super::CnpPreRealizationProbeRequest],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "source-qualified preparation probes are not installed".into(),
        })
    }

    /// Authenticates a fixed retained-original resend population and actual native custody.
    ///
    /// Called before every possible send. Cached companion absence is not a
    /// native premise, and the source policy must authenticate original bodies
    /// under the unchanged attached controller and predeclared fixture.
    ///
    /// # Errors
    /// Refuses by default, unplanned originals, changed scope or native census.
    fn authenticate_pre_realization_resends(
        &self,
        _: &CnpLaunchGuard,
        _: &[Id],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "source-qualified retained-original resends are not installed".into(),
        })
    }

    /// Authenticates the genuinely realized companion beneath its original closed gate.
    ///
    /// # Errors
    /// Rejects changed descriptors, missing native closure or unsupported guarantees.
    fn authenticate_realization(
        &self,
        guard: &CnpLaunchGuard,
        realization: &RealizeResult,
        gate: &ClosedGateRecord,
        companion_pid: u32,
    ) -> Result<(), OperationFailure>;
}

/// Retains the original native process when discovery or realization remains unresolved.
pub struct CnpPreparationFailure {
    /// States the original failure and known effect certainty.
    pub error: OperationFailure,
    /// Preserves actual Child, original request journals and reserved supervision.
    pub guard: CnpLaunchGuard,
}

/// Owns an actual publicly realized checksum companion without issuing world authority.
pub struct CnpReferencePreparation {
    pub(super) guard: CnpLaunchGuard,
    pub(super) realization: RealizeResult,
    pub(super) binding: NodeBinding,
    pub(super) owner_binding: OwnerBinding,
    pub(super) gate: ControlReceipt,
    pub(super) companion_pid: u32,
}

impl CnpReferencePreparation {
    /// Discovers exact installed schemas and realizes the original privately admitted node.
    ///
    /// The provider Child already occupies its reserved native slot. Original
    /// realization IDs and journal records survive every failure. Complete
    /// hash-verified gate records are checked against kernel ancestry and actual
    /// companion executable bytes before preparation can enter graph admission.
    ///
    /// # Errors
    /// Returns complete guarded custody on unqualified source, changed manifests,
    /// uncertain effects, invalid evidence, native peer loss or exhausted limits.
    pub fn prepare(
        guard: CnpLaunchGuard,
        qualification: &dyn CnpReferenceQualification,
    ) -> Result<Self, CnpPreparationFailure> {
        Self::prepare_checked(guard, qualification, None)
    }

    pub(super) fn prepare_checked(
        mut guard: CnpLaunchGuard,
        qualification: &dyn CnpReferenceQualification,
        acceptance: Option<&dyn super::CnpRealizationAcceptance>,
    ) -> Result<Self, CnpPreparationFailure> {
        if let Some(custody) = guard.custody.as_mut() {
            custody.preparation_started = true;
        }
        match prepare(&mut guard, qualification, acceptance) {
            Ok((realization, binding, owner_binding, gate, companion_pid)) => Ok(Self {
                guard,
                realization,
                binding,
                owner_binding,
                gate,
                companion_pid,
            }),
            Err(error) => Err(CnpPreparationFailure { error, guard }),
        }
    }

    /// Returns the exact descriptor observed from the actual installed public provider.
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.realization.realization_manifest.descriptors[0]
    }

    /// Returns the exact privately bound native realization for graph admission.
    pub fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    /// Returns original native owner compatibility and live generation.
    pub fn owner_binding(&self) -> &OwnerBinding {
        &self.owner_binding
    }

    /// Installs original public/native custody into the admitted quantized runtime.
    ///
    /// This consumes preparation; failed construction transfers actual resources
    /// to the already reserved supervisor slot. It does not spawn a replacement
    /// process or turn provider receipt syntax into native qualification.
    ///
    /// # Errors
    /// Rejects changed graph identity, unsupported guarantees, stale native
    /// custody, incompatible schemas, invalid operation bounds or source refusal.
    pub fn into_node(
        self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        qualification: &dyn CnpReferenceQualification,
        maximum_operations: usize,
    ) -> Result<super::CnpReferenceNode, OperationFailure> {
        if maximum_operations == 0 || maximum_operations > 65_536 {
            return Err(failure(
                "public original operation ceiling is invalid",
                false,
            ));
        }
        let original_facets = &self.binding.compatibility.operating_contract.facets;
        if original_facets.len() != 1 || original_facets[0].version != 1 {
            return Err(failure(
                "original public source facet population differs",
                false,
            ));
        }
        let original_facet = original_facets[0].id.clone();
        let child = super::control::CnpControlledReference::new(self, maximum_operations);
        crate::node_adapters::reference_device::ControlledReferenceNode::from_controlled_prepared(
            graph,
            node,
            child,
            original_facet,
            &|child, descriptor, binding| {
                let controller = child.controller().map_err(native)?;
                if descriptor != &controller.profile.descriptor || binding != &child.binding {
                    return Err(failure(
                        "sealed graph changed actual public realization",
                        false,
                    ));
                }
                qualification.authenticate_provider(&child.guard, &controller.profile)?;
                child.verify_native_custody().map_err(native)
            },
            maximum_operations,
        )
    }
}

type Prepared = (
    RealizeResult,
    NodeBinding,
    OwnerBinding,
    ControlReceipt,
    u32,
);

fn prepare(
    guard: &mut CnpLaunchGuard,
    qualification: &dyn CnpReferenceQualification,
    acceptance: Option<&dyn super::CnpRealizationAcceptance>,
) -> Result<Prepared, OperationFailure> {
    let custody = guard
        .custody
        .as_ref()
        .ok_or_else(|| failure("original CNP process unavailable", false))?;
    let controller = custody
        .controller
        .as_ref()
        .ok_or_else(|| failure("original authenticated controller unavailable", false))?;
    qualification.authenticate_provider(guard, &controller.profile)?;
    let profile = controller.profile.clone();
    let bootstrap = controller.bootstrap.clone();
    let (binding, owner_binding) = controller.binding().map_err(native)?;
    let request_id = Id::new(format!(
        "prepare-realize-{}",
        bootstrap.authority.realization_id
    ))
    .map_err(|error| failure(&error.to_string(), false))?;
    let discover_id = Id::new(format!(
        "prepare-discover-{}",
        bootstrap.authority.realization_id
    ))
    .map_err(|error| failure(&error.to_string(), false))?;
    let controller = guard
        .custody
        .as_mut()
        .and_then(|custody| custody.controller.as_mut())
        .ok_or_else(|| failure("original CNP controller custody unavailable", false))?;
    let discovered = controller
        .call(
            discover_id,
            None,
            Method::Discover,
            false,
            DiscoverRequest {
                profile_ids: vec![profile.node_manifest.profile_id.clone()],
                cursor: None,
                extensions: Extensions::new(),
            },
        )
        .map_err(native)?;
    let Some(MethodResult::Discover(discovered)) = discovered.result else {
        return Err(failure("original discovery refused", false));
    };
    if !discovered.complete
        || discovered.next_cursor.0.is_some()
        || discovered.provider_manifest != profile.provider_manifest
        || discovered.profiles != [profile.node_manifest.clone()]
    {
        return Err(failure(
            "public discovery differs from installed immutable profile",
            false,
        ));
    }
    let response = controller
        .call(
            request_id.clone(),
            None,
            Method::Realize,
            false,
            RealizeRequest {
                realization_id: bootstrap.authority.realization_id.clone(),
                configuration: profile.configuration_ref.clone(),
                requested_node_ids: vec![bootstrap.node_id.clone()],
                resource_limits: bootstrap.resource_limits.clone(),
                extensions: Extensions::new(),
            },
        )
        .map_err(native)?;
    let Some(MethodResult::Realize(realization)) = response.result else {
        return Err(failure("original realization did not complete", true));
    };
    let manifest = &realization.realization_manifest;
    let provider_bytes = canonical::canonical_json(
        &serde_json::to_value(&profile.provider_manifest)
            .map_err(|error| failure(&error.to_string(), false))?,
    )
    .map_err(|error| failure(&error.to_string(), false))?;
    let provider_ref = canonical::content_ref(&provider_bytes, "application/json")
        .map_err(|error| failure(&error.to_string(), false))?;
    if manifest.realization_id != bootstrap.authority.realization_id
        || manifest.provider_manifest != provider_ref
        || manifest.descriptors != [profile.descriptor.clone()]
        || manifest.bindings != [binding.clone()]
        || manifest.owners != [profile.owner.clone()]
        || manifest.owner_bindings != [owner_binding.clone()]
        || realization.prepared_token != bootstrap.prepared_token
        || !manifest.extensions.is_empty()
    {
        return Err(failure(
            "realization changed complete privately installed identity",
            true,
        ));
    }
    let gate: ControlReceipt = controller
        .record(&realization.closed_gate_receipt)
        .map_err(native)?;
    let record: ClosedGateRecord = controller.record(&gate.record_ref).map_err(native)?;
    if gate.issuer != ReceiptIssuer::Provider
        || gate.kind != ControlReceiptKind::ClosedGate
        || gate.session_id != bootstrap.authority.session_id
        || gate.incarnation_id != bootstrap.authority.incarnation_id
        || gate.request_id != request_id
        || gate.operation_id.is_some()
        || gate.owner_ids != [bootstrap.owner_id.clone()]
        || gate.world_generation != U64::new(0)
        || !gate.extensions.is_empty()
        || record.gate_id != bootstrap.gate_id
        || record.prepared_token != bootstrap.prepared_token
        || record.owner_ids != [bootstrap.owner_id.clone()]
        || !record.gate_closed
        || !record.extensions.is_empty()
    {
        return Err(failure(
            "native gate receipt differs from original preparation",
            true,
        ));
    }
    let evidence = canonical::parse_json(
        controller
            .content(&record.physical_status_ref)
            .map_err(native)?,
        1_048_576,
    )
    .map_err(|error| failure(&error.to_string(), true))?;
    let pid: U64 = serde_json::from_value(evidence["child_pid"].clone())
        .map_err(|error| failure(&error.to_string(), true))?;
    let companion_pid =
        u32::try_from(pid.get()).map_err(|_| failure("native companion PID out of range", true))?;
    if evidence["application_status"] != "parked" || evidence["physical_pause"] != "unknown" {
        return Err(failure(
            "native application readiness does not match truthful installed profile",
            true,
        ));
    }
    let provider_pid = guard
        .provider_pid()
        .ok_or_else(|| failure("native provider custody lost", true))?;
    verify_companion(companion_pid, provider_pid, &profile)?;
    qualification.authenticate_realization(guard, &realization, &record, companion_pid)?;
    if let Some(acceptance) = acceptance {
        acceptance.authenticate(super::CnpAcceptanceScope {
            guard,
            profile: &profile,
            realization: &realization,
            binding: &binding,
            owner: &owner_binding,
            resources: &bootstrap.resource_limits,
            gate: &record,
        })?;
    }
    // The receipt is host-installed private admission evidence, not a provider
    // assertion. It was checked by the installed qualification gate above.
    let admitted = guard
        .custody
        .as_mut()
        .and_then(|custody| custody.controller.as_mut())
        .ok_or_else(|| failure("original CNP controller unavailable for admission", true))?
        .call(
            super::control::original_id("prepare-admit", &bootstrap.admission_id)
                .map_err(native)?,
            None,
            Method::Admit,
            false,
            AdmitRequest {
                bindings: vec![binding.clone()],
                world_binding_hash: bootstrap.world_binding_hash.clone(),
                admission_receipt: bootstrap.admission_receipt.clone(),
                extensions: Extensions::new(),
            },
        )
        .map_err(native)?;
    let Some(MethodResult::Admit(admitted)) = admitted.result else {
        return Err(failure(
            "original host admission refused by public provider",
            true,
        ));
    };
    if admitted.admission_id != bootstrap.admission_id
        || admitted.accepted_binding_hashes
            != [binding.identity().map_err(|error| native(error.into()))?]
    {
        return Err(failure(
            "original public admission changed complete bindings",
            true,
        ));
    }
    let custody = guard
        .custody
        .as_mut()
        .ok_or_else(|| failure("original CNP custody transferred", true))?;
    custody.companion = Some(companion_pid);
    Ok((realization, binding, owner_binding, gate, companion_pid))
}

pub(super) fn verify_companion(
    pid: u32,
    provider: u32,
    profile: &ReferenceProfile,
) -> Result<(), OperationFailure> {
    let native_pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| failure("native companion PID invalid", true))?;
    let group = getpgid(Some(native_pid)).map_err(|error| failure(&error.to_string(), true))?;
    if u32::try_from(group.as_raw_nonzero().get()).ok() != Some(provider) {
        return Err(failure(
            "native companion escaped original private group",
            true,
        ));
    }
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/status"))
        .map_err(|error| failure(&error.to_string(), true))?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| failure(&error.to_string(), true))?;
    let status = std::str::from_utf8(&bytes).map_err(|error| failure(&error.to_string(), true))?;
    if bytes.len() > 65536
        || !status
            .lines()
            .any(|line| line == format!("PPid:\t{provider}"))
    {
        return Err(failure(
            "native companion is not owned by original provider",
            true,
        ));
    }
    let expected = profile
        .implementation
        .artifacts
        .iter()
        .find(|artifact| artifact.id.as_str() == "device")
        .ok_or_else(|| failure("installed companion measurement absent", true))?;
    let measured = measure_executable(Path::new(&format!("/proc/{pid}/exe"))).map_err(native)?;
    if measured != expected.content
        || !fs::metadata(format!("/proc/{pid}/task"))
            .map_err(|error| failure(&error.to_string(), true))?
            .is_dir()
    {
        return Err(failure(
            "actual companion executable differs from installed source",
            true,
        ));
    }
    Ok(())
}

fn native(error: ProviderError) -> OperationFailure {
    failure(&error.to_string(), true)
}

fn failure(reason: &str, uncertain: bool) -> OperationFailure {
    OperationFailure {
        effects: if uncertain {
            EffectKnowledge::Unknown
        } else {
            EffectKnowledge::None
        },
        reason: reason.into(),
    }
}
