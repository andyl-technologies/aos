//! Native systemd resource admission and lifecycle effect execution.
//!
//! The catalog binds checked logical resources to configured unit names and a
//! fresh D-Bus manager owner. The adapter persists that owner with its request
//! and observes it again immediately before every call, so a bus or manager
//! replacement cannot reuse stale admission evidence.
//!
//! Durable requests use the following versioned wire shape:
//!
//! ```json
//! {"schema":"aos.ability.systemd-request/v2","action":"start","unit":"example.service","unit_identity":"/org/freedesktop/systemd1/unit/example_2eservice","revision":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","manager_bus_id":"0123456789abcdef0123456789abcdef","manager_owner":":1.42"}
//! ```
//!
//! Version 1 requests predate the authenticated loaded-unit revision. Recovery
//! rejects them explicitly because no trusted revision can be inferred from
//! their durable fields; the operation must be replanned and admitted afresh.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aos_ability_model::{
    AbilityActivationMode, AbilityValue, ExecutionStage, IncarnationId, InterfaceKey,
    InterfaceName, LocalKey, MethodReference, Operation, OperationFamily, ProviderAssignment,
    ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId, ServiceAction,
    ValueSchema,
    builtin::{
        systemd_manager_handler, systemd_manager_handler_key, systemd_manager_interface_key,
        systemd_manager_provider,
    },
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, RuntimeControl, TrustedAdapter,
    TrustedResourceCatalog,
};
use aos_contract::Sha256Digest;
use aos_systemd::{JobOutcome, PinnedSystemdManager, SystemdManagerConnection, UnitActiveState};
use serde::{Deserialize, Serialize};

use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::ability_store::inventory::require_machine_global_host_collision_domain;
use crate::config_eval::ability_store::{
    NativeQualifiedResource, NativeResourceInventory, NativeResourceReservation,
};
#[cfg(test)]
use crate::config_eval::native_ability_fs::authenticate_native_executor_path;
use crate::config_eval::native_ability_fs::{
    RootedDirectory, RootedFile, authenticate_native_executor,
};

const REQUEST_SCHEMA: &str = "aos.ability.systemd-request/v2";
const LEGACY_REQUEST_SCHEMA: &str = "aos.ability.systemd-request/v1";
const RECORD_SCHEMA: &str = "aos.ability.systemd-observation/v1";
const REVISION_RECEIPT_SCHEMA: &str = "aos.ability.systemd-unit-revision/v1";
const REVISION_RECEIPT_ROOT: &str = "/etc/aos/ability-revisions";
const MAX_REVISION_RECEIPT_BYTES: u64 = 16 * 1024;
const CATALOG_QUALIFICATION_MILLIS: u64 = 30_000;
const NATIVE_EXECUTOR_SUFFIX: &str = "bin/.aos-package-runtime-unwrapped";
const REFERENCE_SYSTEMD_INTERFACE: &str = "aos.systemd-service-effects";
const REFERENCE_SYSTEMD_DESCRIPTOR: &str =
    "sha256:08e463bed96f053e557f557c95342666e81358396a44f89bf4c07a2aa780d6c5";
const REFERENCE_SYSTEMD_HANDLER: &str = "systemd-terminal";

/// Binds one checked logical resource to the only unit it may control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdResourceSpec {
    /// Names the logical resource declared by the checked provider.
    pub resource: ResourceId,
    /// Names the exact systemd unit authorized for that resource.
    pub unit: String,
    /// Identifies the unit revision that systemd must have parsed and loaded.
    pub revision: RevisionId,
    /// Identifies the exact desired-state generation that authored the unit.
    pub generation: Sha256Digest,
    /// Identifies the authenticated package manifest that owns the unit.
    pub owner_package: Sha256Digest,
}

/// Canonical ownership receipt for one generated systemd unit revision.
///
/// Native orchestration renders this document into the candidate generation at
/// [`Self::etc_relative_path`] and adds [`Self::documentation_uri`] to the
/// unit's `Documentation=` property. After the existing generation activation
/// reloads systemd, the catalog verifies both the protected receipt bytes and
/// systemd's parsed URI before admitting the resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitRevisionReceipt {
    schema: String,
    generation: Sha256Digest,
    owner_package: Sha256Digest,
    resource: ResourceId,
    unit: String,
    revision: RevisionId,
}

impl SystemdUnitRevisionReceipt {
    /// Constructs the exact receipt committed by one trusted resource specification.
    #[must_use]
    pub fn from_resource(spec: &SystemdResourceSpec) -> Self {
        Self {
            schema: REVISION_RECEIPT_SCHEMA.to_string(),
            generation: spec.generation,
            owner_package: spec.owner_package,
            resource: spec.resource.clone(),
            unit: spec.unit.clone(),
            revision: spec.revision,
        }
    }

    /// Returns the path beneath the candidate `/etc` tree where the receipt belongs.
    #[must_use]
    pub fn etc_relative_path(&self) -> PathBuf {
        Path::new("aos/ability-revisions").join(self.receipt_relative_path())
    }

    /// Returns the canonical `file:` URI the generated unit must expose.
    #[must_use]
    pub fn documentation_uri(&self) -> String {
        format!(
            "file:/etc/aos/ability-revisions/{}",
            self.receipt_relative_path().to_string_lossy()
        )
    }

    /// Encodes the exact canonical JSON bytes written into the candidate generation.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, io::Error> {
        aos_contract::canonical::to_vec(self)
            .map_err(|error| invalid_data(format!("encoding systemd unit receipt: {error}")))
    }

    fn receipt_relative_path(&self) -> PathBuf {
        PathBuf::from(encode_uri_path_segment(&self.unit))
            .join("sha256")
            .join(self.revision.0.hex())
    }
}

/// A fresh native handle acquired for one checked systemd resource.
pub struct SystemdResourceHandle {
    unit: String,
    unit_identity: String,
    revision: RevisionId,
    authorized_action: SystemdAbilityAction,
    manager: Arc<PinnedSystemdManager>,
    reservation: NativeResourceReservation,
}

impl std::fmt::Debug for SystemdResourceHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemdResourceHandle")
            .field("unit", &self.unit)
            .field("unit_identity", &self.unit_identity)
            .field("authorized_action", &self.authorized_action)
            .field("manager", &self.manager.incarnation())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct QualifiedSystemdResource {
    unit: String,
    unit_identity: String,
    revision: RevisionId,
    receipt: RootedFile,
    expected_receipt: SystemdUnitRevisionReceipt,
    qualified: NativeQualifiedResource,
}

/// Resolves checked systemd resources against one exact live assignment.
pub struct SystemdResourceCatalog {
    connection: Arc<SystemdManagerConnection>,
    runtime: tokio::runtime::Handle,
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    resources: BTreeMap<ResourceId, QualifiedSystemdResource>,
}

impl SystemdResourceCatalog {
    /// Constructs a catalog from a scoped manager connection, checked
    /// assignment, and authorized units.
    ///
    /// Every acquisition pins `connection`; the catalog never opens or falls
    /// back to another bus scope. Authorized units must already be loaded by a
    /// preceding provider preparation step so qualification remains read-only.
    ///
    /// # Errors
    ///
    /// Returns an error when no Tokio runtime is active, a unit name is unsafe,
    /// a resource belongs to another provider, a resource is duplicated, or
    /// two logical resources name the same concrete unit, an authorized unit is
    /// not already loaded, or its canonical identity cannot be resolved.
    pub fn new(
        connection: Arc<SystemdManagerConnection>,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        resources: impl IntoIterator<Item = SystemdResourceSpec>,
    ) -> Result<Self, io::Error> {
        Self::new_with_receipt_root(
            connection,
            assignment,
            inventory,
            resources,
            Path::new(REVISION_RECEIPT_ROOT),
            0,
        )
    }

    fn new_with_receipt_root(
        connection: Arc<SystemdManagerConnection>,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        resources: impl IntoIterator<Item = SystemdResourceSpec>,
        receipt_root: &Path,
        trusted_owner: u32,
    ) -> Result<Self, io::Error> {
        require_host_assignment(&assignment)?;
        require_machine_global_host_collision_domain()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            invalid_data(format!("systemd catalog requires a Tokio runtime: {error}"))
        })?;
        require_multi_thread_runtime(&runtime)?;
        let configured = index_resources(&assignment, resources)?;
        let receipt_root = RootedDirectory::open(
            receipt_root,
            trusted_owner,
            "systemd unit revision receipt root",
        )?;
        let manager = Arc::new(run_async(
            &runtime,
            CATALOG_QUALIFICATION_MILLIS,
            connection.pin(),
        )?);
        require_assignment_incarnation(&assignment, &manager)?;

        let mut unit_identities = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for (resource, spec) in configured {
            let expected_receipt = SystemdUnitRevisionReceipt::from_resource(&spec);
            let receipt = receipt_root.resolve(&expected_receipt.receipt_relative_path())?;
            verify_revision_receipt(&receipt, &expected_receipt)?;
            let unit_identity = run_async(
                &runtime,
                CATALOG_QUALIFICATION_MILLIS,
                manager.unit_identity_at_revision(&spec.unit, &revision_text(spec.revision)),
            )?;
            if !unit_identities.insert(unit_identity.clone()) {
                return Err(invalid_data(
                    "distinct systemd resources resolve to the same manager unit",
                ));
            }
            let qualified = NativeQualifiedResource::systemd(resource.clone(), &unit_identity)
                .map_err(|error| invalid_data(error.to_string()))?;
            indexed.insert(
                resource,
                QualifiedSystemdResource {
                    unit: spec.unit,
                    unit_identity,
                    revision: spec.revision,
                    receipt,
                    expected_receipt,
                    qualified,
                },
            );
        }
        Ok(Self {
            connection,
            runtime,
            assignment,
            inventory,
            resources: indexed,
        })
    }

    /// Returns the exact logical-to-native qualification for a catalog member.
    #[must_use]
    pub fn qualified_resource(&self, resource: &ResourceId) -> Option<NativeQualifiedResource> {
        self.resources
            .get(resource)
            .map(|resource| resource.qualified.clone())
    }

    pub(crate) fn observe_no_op(
        &self,
        resource: &ResourceId,
    ) -> Result<NativeQualifiedResource, io::Error> {
        let resource = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid_data("systemd no-op resource is not cataloged"))?;
        let manager = self.requalify(resource, CATALOG_QUALIFICATION_MILLIS)?;
        let active_state = run_async(
            &self.runtime,
            CATALOG_QUALIFICATION_MILLIS,
            manager.active_state_exact_revision(
                &resource.unit,
                &resource.unit_identity,
                &revision_text(resource.revision),
            ),
        )?;
        if active_state != UnitActiveState::Active {
            return Err(invalid_data(
                "systemd no-op resource is not active at its exact revision",
            ));
        }
        Ok(resource.qualified.clone())
    }

    fn requalify(
        &self,
        resource: &QualifiedSystemdResource,
        remaining_millis: u64,
    ) -> Result<Arc<PinnedSystemdManager>, io::Error> {
        verify_revision_receipt(&resource.receipt, &resource.expected_receipt)?;
        let manager = Arc::new(run_async(
            &self.runtime,
            remaining_millis,
            self.connection.pin(),
        )?);
        require_assignment_incarnation(&self.assignment, &manager)?;
        let unit_identity = run_async(
            &self.runtime,
            remaining_millis,
            manager.unit_identity_at_revision(&resource.unit, &revision_text(resource.revision)),
        )?;
        if unit_identity != resource.unit_identity {
            return Err(invalid_data(
                "systemd unit identity changed before admission",
            ));
        }
        Ok(manager)
    }
}

fn require_host_assignment(assignment: &ProviderAssignment) -> Result<(), io::Error> {
    if assignment.provider.environment.stage != ExecutionStage::Host {
        return Err(invalid_data(
            "host systemd abilities reject assignments from initrd, user, and container manager scopes",
        ));
    }
    Ok(())
}

fn index_resources(
    assignment: &ProviderAssignment,
    resources: impl IntoIterator<Item = SystemdResourceSpec>,
) -> Result<BTreeMap<ResourceId, SystemdResourceSpec>, io::Error> {
    let mut indexed = BTreeMap::new();
    let mut units = BTreeSet::new();
    for spec in resources {
        if spec.resource.provider != assignment.provider {
            return Err(invalid_data("systemd resource belongs to another provider"));
        }
        validate_unit_name(&spec.unit)?;
        if !units.insert(spec.unit.clone()) {
            return Err(invalid_data(
                "distinct systemd resources target the same concrete unit",
            ));
        }
        if indexed.insert(spec.resource.clone(), spec).is_some() {
            return Err(invalid_data(
                "systemd resource catalog contains a duplicate",
            ));
        }
    }
    Ok(indexed)
}

fn verify_revision_receipt(
    receipt: &RootedFile,
    expected: &SystemdUnitRevisionReceipt,
) -> Result<(), io::Error> {
    let bytes = receipt.read(MAX_REVISION_RECEIPT_BYTES).map_err(|error| {
        invalid_data(format!(
            "reading systemd unit revision receipt {}: {error}",
            receipt.display().display()
        ))
    })?;
    let actual: SystemdUnitRevisionReceipt =
        aos_contract::canonical::from_slice(&bytes, "systemd unit revision receipt").map_err(
            |error| invalid_data(format!("invalid systemd unit revision receipt: {error}")),
        )?;
    if actual.canonical_bytes()? != bytes {
        return Err(invalid_data(
            "systemd unit revision receipt is not canonical JSON",
        ));
    }
    if &actual != expected {
        return Err(invalid_data(
            "systemd unit revision receipt does not match the authorized resource",
        ));
    }
    Ok(())
}

fn require_assignment_incarnation(
    assignment: &ProviderAssignment,
    manager: &PinnedSystemdManager,
) -> Result<(), io::Error> {
    let incarnation = IncarnationId::new(manager.incarnation().token())
        .map_err(|error| invalid_data(format!("invalid systemd manager owner: {error}")))?;
    if incarnation == assignment.incarnation {
        Ok(())
    } else {
        Err(invalid_data(
            "systemd manager incarnation changed before admission",
        ))
    }
}

impl TrustedResourceCatalog for SystemdResourceCatalog {
    type Handle = SystemdResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "systemd access does not target the operation resource",
            ));
        }
        if context.expected_provider != Some(&self.assignment) {
            return Err(invalid_data(
                "systemd provider assignment is absent or stale",
            ));
        }
        let authorized_action = SystemdAbilityAction::from_operation(operation)?;
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid_data("systemd resource is outside the authorized catalog"))?
            .clone();
        let manager = self.requalify(&resource, context.recovery_remaining_millis)?;
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(|error| invalid_data(error.to_string()))?;
        let observation = record_value(SystemdEvidenceFields {
            state: "admitted",
            unit: &resource.unit,
            unit_identity: Some(&resource.unit_identity),
            manager_bus_id: Some(manager.incarnation().bus_id()),
            manager_owner: Some(manager.incarnation().owner()),
            active_state: None,
            job_result: None,
            job_path: None,
        })?;
        let evidence = ResourceAdmissionEvidence::new(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            Some(resource.revision),
            observation,
        );
        Ok(CatalogReservation::new(
            SystemdResourceHandle {
                unit: resource.unit,
                unit_identity: resource.unit_identity,
                revision: resource.revision,
                authorized_action,
                manager,
                reservation,
            },
            evidence,
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if handle.reservation.logical() != resource {
            return Err(invalid_data(
                "systemd release resource does not match its native reservation",
            ));
        }
        handle
            .reservation
            .release()
            .map_err(|error| invalid_data(error.to_string()))
    }
}

/// Durable request reconstructed after fresh systemd resource acquisition.
#[derive(Clone)]
pub struct SystemdAbilityRequest {
    durable: SystemdDurableRequest,
    manager: Arc<PinnedSystemdManager>,
}

impl std::fmt::Debug for SystemdAbilityRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemdAbilityRequest")
            .field("durable", &self.durable)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemdDurableRequest {
    schema: String,
    action: SystemdAbilityAction,
    unit: String,
    unit_identity: String,
    revision: RevisionId,
    manager_bus_id: String,
    manager_owner: String,
}

#[derive(Deserialize)]
struct DurableRequestEnvelope {
    schema: String,
}

fn decode_durable_request(
    durable: &AbilityValue,
    request_name: &str,
) -> Result<SystemdDurableRequest, io::Error> {
    let envelope: DurableRequestEnvelope = serde_json::from_value(durable.as_json().clone())
        .map_err(|error| invalid_data(format!("invalid durable {request_name}: {error}")))?;
    if envelope.schema == LEGACY_REQUEST_SCHEMA {
        return Err(invalid_data(format!(
            "durable {request_name} v1 has no authenticated loaded-unit revision; a fresh plan and admission are required"
        )));
    }
    if envelope.schema != REQUEST_SCHEMA {
        return Err(invalid_data(format!(
            "unsupported durable {request_name} schema"
        )));
    }

    serde_json::from_value(durable.as_json().clone())
        .map_err(|error| invalid_data(format!("invalid durable {request_name}: {error}")))
}

struct SystemdObservation {
    active_state: UnitActiveState,
    record: SystemdAbilityRecord,
}

/// Typed systemd completion or reconciliation evidence.
#[derive(Clone, Debug)]
pub struct SystemdAbilityRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for SystemdAbilityRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for SystemdAbilityRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes a checked systemd lifecycle method through the typed D-Bus client.
pub struct NativeSystemdAdapter {
    runtime: tokio::runtime::Handle,
    assignment: ProviderAssignment,
    fallback: SystemdAbilityRecord,
}

impl NativeSystemdAdapter {
    /// Constructs an adapter from one authenticated package and exact live assignment.
    ///
    /// # Errors
    ///
    /// Returns an error when the package and assignment do not contain the
    /// exact built-in systemd interface, provider, handler, and artifact
    /// linkage, no Tokio runtime is active, or fallback evidence is invalid.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        authenticate_builtin_systemd(package, &assignment)?;
        authenticate_native_executor(
            &assignment.implementation.artifact,
            NATIVE_EXECUTOR_SUFFIX,
            "systemd",
        )?;
        Self::initialize(assignment)
    }

    fn initialize(assignment: ProviderAssignment) -> Result<Self, io::Error> {
        require_host_assignment(&assignment)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            invalid_data(format!("systemd adapter requires a Tokio runtime: {error}"))
        })?;
        require_multi_thread_runtime(&runtime)?;
        let fallback = SystemdAbilityRecord {
            durable: record_value(SystemdEvidenceFields {
                state: "internal-error",
                unit: "unknown.service",
                unit_identity: None,
                manager_bus_id: None,
                manager_owner: None,
                active_state: None,
                job_result: None,
                job_path: None,
            })?,
            outputs: BTreeMap::new(),
        };
        Ok(Self {
            runtime,
            assignment,
            fallback,
        })
    }

    fn observe(
        &self,
        request: &SystemdAbilityRequest,
        remaining_millis: u64,
    ) -> Result<SystemdObservation, io::Error> {
        let active_state = run_async(
            &self.runtime,
            remaining_millis,
            request.manager.active_state_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        )?;
        let record = self.record("observed", request, Some(&active_state), None, None);
        Ok(SystemdObservation {
            active_state,
            record,
        })
    }

    fn record(
        &self,
        state: &str,
        request: &SystemdAbilityRequest,
        active_state: Option<&UnitActiveState>,
        job_result: Option<&str>,
        job_path: Option<&str>,
    ) -> SystemdAbilityRecord {
        let durable = record_value(SystemdEvidenceFields {
            state,
            unit: &request.durable.unit,
            unit_identity: Some(&request.durable.unit_identity),
            manager_bus_id: Some(&request.durable.manager_bus_id),
            manager_owner: Some(&request.durable.manager_owner),
            active_state,
            job_result,
            job_path,
        })
        .unwrap_or_else(|_| self.fallback.durable.clone());
        let mut outputs = BTreeMap::new();
        if let Some(active_state) = active_state
            && let (Ok(port), Ok(value)) = (
                LocalKey::new("active"),
                AbilityValue::new(serde_json::Value::Bool(active_state.is_active())),
            )
        {
            outputs.insert(port, value);
        }
        SystemdAbilityRecord { durable, outputs }
    }

    fn stale_record(&self, request: &SystemdAbilityRequest) -> SystemdAbilityRecord {
        self.record("manager-changed", request, None, None, None)
    }
}

fn authenticate_builtin_systemd(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects {
        return Err(invalid_data(
            "systemd adapter requires a structured-effects package",
        ));
    }

    let interface = systemd_manager_interface_key()
        .map_err(|error| invalid_data(format!("invalid built-in systemd interface: {error:#}")))?;
    let handler_key = systemd_manager_handler_key().map_err(|error| {
        invalid_data(format!("invalid built-in systemd handler key: {error:#}"))
    })?;
    if assignment.interface != interface
        || assignment.implementation.handler.as_ref() != Some(&handler_key)
    {
        return Err(invalid_data(
            "assignment does not select the exact built-in systemd contract",
        ));
    }

    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data("authenticated package does not resolve the assigned systemd handler")
        })?;
    let expected_provider = systemd_manager_provider(verified.handler().artifact.clone())
        .map_err(|error| invalid_data(format!("invalid built-in systemd provider: {error:#}")))?;
    let expected_handler = systemd_manager_handler(verified.handler().artifact.clone())
        .map_err(|error| invalid_data(format!("invalid built-in systemd handler: {error:#}")))?;
    if verified.provider() != &expected_provider || verified.handler() != &expected_handler {
        return Err(invalid_data(
            "authenticated provider or handler differs from the built-in systemd contract",
        ));
    }
    if assignment.implementation.artifact != expected_provider.artifact {
        return Err(invalid_data(
            "live systemd assignment uses another authenticated artifact",
        ));
    }
    Ok(())
}

fn authenticate_reference_systemd(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects {
        return Err(invalid_data(
            "reference systemd adapter requires a structured-effects package",
        ));
    }

    let expected_interface = InterfaceKey {
        name: InterfaceName::new(REFERENCE_SYSTEMD_INTERFACE).map_err(|error| {
            invalid_data(format!("invalid reference systemd interface: {error}"))
        })?,
        abi: NonZeroU32::new(1).ok_or_else(|| invalid_data("invalid reference systemd ABI"))?,
        descriptor: Sha256Digest::parse(REFERENCE_SYSTEMD_DESCRIPTOR).map_err(|error| {
            invalid_data(format!("invalid reference systemd descriptor: {error}"))
        })?,
    };
    let handler_key = LocalKey::new(REFERENCE_SYSTEMD_HANDLER)
        .map_err(|error| invalid_data(format!("invalid reference systemd handler: {error}")))?;
    if assignment.interface != expected_interface
        || assignment.implementation.handler.as_ref() != Some(&handler_key)
    {
        return Err(invalid_data(
            "assignment does not select the exact reference systemd contract",
        ));
    }

    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data(
                "authenticated package does not resolve the assigned reference systemd handler",
            )
        })?;
    if verified.provider().interface != expected_interface
        || verified.provider().artifact != assignment.implementation.artifact
        || verified.provider().requirements != Vec::new()
        || verified.provider().owns_resource_kinds != vec![expected_interface.name.clone()]
        || verified.handler().artifact != assignment.implementation.artifact
        || verified.handler().entry_point != NATIVE_EXECUTOR_SUFFIX
        || verified.handler().arguments != ValueSchema::Boolean
        || verified.handler().result != ValueSchema::Boolean
    {
        return Err(invalid_data(
            "authenticated provider or handler differs from the exact reference systemd contract",
        ));
    }
    Ok(())
}

pub(crate) fn preflight_native_systemd(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    match assignment.interface.name.as_str() {
        aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME => {
            authenticate_builtin_systemd(package, assignment)
        }
        REFERENCE_SYSTEMD_INTERFACE => authenticate_reference_systemd(package, assignment),
        _ => Err(invalid_data(
            "systemd resource map selects an unsupported native terminal interface",
        )),
    }
}

impl TrustedAdapter for NativeSystemdAdapter {
    type Request = SystemdAbilityRequest;
    type Completion = SystemdAbilityRecord;
    type Observation = SystemdAbilityRecord;
    type Handle = SystemdResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        if implementation != &self.assignment.implementation
            || method.interface != self.assignment.interface
        {
            return false;
        }
        match purpose {
            InvocationPurpose::Effect => matches!(
                method.method.as_str(),
                "start" | "reload" | "restart" | "stop" | "observe"
            ),
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel => {
                method.method.as_str() == "observe"
            }
            InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => false,
        }
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        let action = SystemdAbilityAction::from_operation(operation)?;
        if operation.interface != self.assignment.interface {
            return Err(invalid_data("systemd operation uses another interface"));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "systemd operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid_data(
                "systemd handle does not match the operation target",
            ));
        }
        require_authorized_action(action, resource.native().authorized_action, true)?;
        let input: UnitInput = serde_json::from_value(inputs.as_json().clone())
            .map_err(|error| invalid_data(format!("invalid systemd input: {error}")))?;
        validate_unit_name(&input.unit)?;
        if input.unit != resource.native().unit {
            return Err(invalid_data(
                "systemd input unit is outside the resource binding",
            ));
        }
        let request = SystemdDurableRequest {
            schema: REQUEST_SCHEMA.to_string(),
            action,
            unit: input.unit,
            unit_identity: resource.native().unit_identity.clone(),
            revision: resource.native().revision,
            manager_bus_id: resource.native().manager.incarnation().bus_id().to_string(),
            manager_owner: resource.native().manager.incarnation().owner().to_string(),
        };
        AbilityValue::new(
            serde_json::to_value(request)
                .map_err(|error| invalid_data(format!("encoding systemd request: {error}")))?,
        )
        .map_err(|error| invalid_data(format!("systemd request exceeds limits: {error}")))
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request = decode_durable_request(durable, "systemd request")?;
        let [resource] = resources else {
            return Err(invalid_data(
                "systemd recovery requires exactly one resource",
            ));
        };
        if request.unit != resource.native().unit
            || request.unit_identity != resource.native().unit_identity
            || request.revision != resource.native().revision
            || request.manager_bus_id != resource.native().manager.incarnation().bus_id()
            || request.manager_owner != resource.native().manager.incarnation().owner()
        {
            return Err(invalid_data(
                "durable systemd request disagrees with fresh acquisition",
            ));
        }
        require_authorized_action(request.action, resource.native().authorized_action, true)?;
        Ok(SystemdAbilityRequest {
            durable: request,
            manager: Arc::clone(&resource.native().manager),
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(self.record(
                "cancelled-before-dispatch",
                request,
                None,
                None,
                None,
            ));
        }
        if request.durable.action == SystemdAbilityAction::Observe {
            return match self.observe(request, call_remaining_millis(control)) {
                Ok(observation) => EffectDisposition::Completed(observation.record),
                Err(_) => EffectDisposition::Indeterminate(self.record(
                    "observation-failed",
                    request,
                    None,
                    None,
                    None,
                )),
            };
        }
        if request.durable.action == SystemdAbilityAction::Start {
            match self.observe(request, call_remaining_millis(control)) {
                Ok(observation) if observation.active_state.is_active() => {
                    return EffectDisposition::RejectedBeforeEffect(self.record(
                        "active-consumer-revision-unknown",
                        request,
                        Some(&observation.active_state),
                        None,
                        None,
                    ));
                }
                Ok(SystemdObservation {
                    active_state: UnitActiveState::Inactive | UnitActiveState::Failed,
                    ..
                }) => {}
                Ok(observation) => return EffectDisposition::Indeterminate(observation.record),
                Err(_) => {
                    return EffectDisposition::Indeterminate(self.record(
                        "start-precondition-unavailable",
                        request,
                        None,
                        None,
                        None,
                    ));
                }
            }
        }
        let outcome = run_job(&self.runtime, control, request);
        let Ok(outcome) = outcome else {
            return EffectDisposition::Indeterminate(self.record(
                "job-indeterminate",
                request,
                None,
                None,
                None,
            ));
        };
        if !outcome.result.is_done() {
            return EffectDisposition::Indeterminate(self.record(
                "job-failed",
                request,
                None,
                Some(outcome.result.label()),
                Some(outcome.job_path.as_str()),
            ));
        }
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .postcondition(&observation.active_state) =>
            {
                EffectDisposition::Completed(self.record(
                    "completed",
                    request,
                    Some(&observation.active_state),
                    Some(outcome.result.label()),
                    Some(outcome.job_path.as_str()),
                ))
            }
            Ok(observation) => EffectDisposition::Indeterminate(observation.record),
            Err(_) => EffectDisposition::Indeterminate(self.record(
                "postcondition-unavailable",
                request,
                None,
                Some(outcome.result.label()),
                Some(outcome.job_path.as_str()),
            )),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .recovery_postcondition(&observation.active_state) =>
            {
                ReconcileDisposition::Completed(observation.record)
            }
            Ok(observation) => ReconcileDisposition::StillIndeterminate(observation.record),
            Err(_) => ReconcileDisposition::InterventionRequired(self.stale_record(request)),
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .recovery_postcondition(&observation.active_state) =>
            {
                CancellationDisposition::Completed(observation.record)
            }
            Ok(observation) => CancellationDisposition::Indeterminate(observation.record),
            Err(_) => CancellationDisposition::Indeterminate(self.stale_record(request)),
        }
    }
}

/// Boolean completion evidence for the reference systemd terminal contract.
#[derive(Clone, Debug)]
pub struct ReferenceSystemdRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for ReferenceSystemdRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for ReferenceSystemdRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes the explicit `aos.systemd-service-effects` terminal contract.
///
/// This adapter is authenticated independently from the built-in
/// `aos.systemd-manager` path. Its Boolean input is only a checked trigger;
/// the unit name and loaded revision come exclusively from the acquired
/// [`SystemdResourceCatalog`] handle.
pub struct NativeSystemdServiceAdapter {
    runtime: tokio::runtime::Handle,
    assignment: ProviderAssignment,
    completed: ReferenceSystemdRecord,
    unsettled: ReferenceSystemdRecord,
}

impl NativeSystemdServiceAdapter {
    /// Constructs the adapter from one exact authenticated package assignment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the package resolves the fixed reference
    /// interface descriptor and `systemd-terminal` handler to the running AOS
    /// package runtime at `bin/.aos-package-runtime-unwrapped`, or no supported
    /// Tokio runtime is active.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        authenticate_reference_systemd(package, &assignment)?;
        authenticate_native_executor(
            &assignment.implementation.artifact,
            NATIVE_EXECUTOR_SUFFIX,
            "reference systemd",
        )?;
        Self::initialize(assignment)
    }

    fn initialize(assignment: ProviderAssignment) -> Result<Self, io::Error> {
        require_host_assignment(&assignment)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            invalid_data(format!(
                "reference systemd adapter requires a Tokio runtime: {error}"
            ))
        })?;
        require_multi_thread_runtime(&runtime)?;
        Ok(Self {
            runtime,
            assignment,
            completed: reference_record(true)?,
            unsettled: reference_record(false)?,
        })
    }

    fn observe(
        &self,
        request: &SystemdAbilityRequest,
        remaining_millis: u64,
    ) -> Result<UnitActiveState, io::Error> {
        run_async(
            &self.runtime,
            remaining_millis,
            request.manager.active_state_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        )
    }

    fn prepare_reference_request(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<SystemdResourceHandle>],
    ) -> Result<AbilityValue, io::Error> {
        let action = SystemdAbilityAction::from_operation(operation)?;
        if operation.interface != self.assignment.interface {
            return Err(invalid_data(
                "reference systemd operation uses another interface",
            ));
        }
        if inputs.as_json() != &serde_json::Value::Bool(true) {
            return Err(invalid_data(
                "reference systemd operation requires the authenticated true trigger",
            ));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "reference systemd operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid_data(
                "reference systemd handle does not match the operation target",
            ));
        }
        let native = resource.native();
        require_authorized_action(action, native.authorized_action, false)?;
        let request = SystemdDurableRequest {
            schema: REQUEST_SCHEMA.to_string(),
            action,
            unit: native.unit.clone(),
            unit_identity: native.unit_identity.clone(),
            revision: native.revision,
            manager_bus_id: native.manager.incarnation().bus_id().to_string(),
            manager_owner: native.manager.incarnation().owner().to_string(),
        };
        AbilityValue::new(serde_json::to_value(request).map_err(|error| {
            invalid_data(format!("encoding reference systemd request: {error}"))
        })?)
        .map_err(|error| invalid_data(format!("reference systemd request exceeds limits: {error}")))
    }

    fn recover_reference_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<SystemdResourceHandle>],
    ) -> Result<SystemdAbilityRequest, io::Error> {
        let request = decode_durable_request(durable, "reference systemd request")?;
        let [resource] = resources else {
            return Err(invalid_data(
                "reference systemd recovery requires exactly one resource",
            ));
        };
        let native = resource.native();
        if request.unit != native.unit
            || request.unit_identity != native.unit_identity
            || request.revision != native.revision
            || request.manager_bus_id != native.manager.incarnation().bus_id()
            || request.manager_owner != native.manager.incarnation().owner()
        {
            return Err(invalid_data(
                "durable reference systemd request disagrees with fresh acquisition",
            ));
        }
        require_authorized_action(request.action, native.authorized_action, false)?;
        Ok(SystemdAbilityRequest {
            durable: request,
            manager: Arc::clone(&native.manager),
        })
    }
}

impl TrustedAdapter for NativeSystemdServiceAdapter {
    type Request = SystemdAbilityRequest;
    type Completion = ReferenceSystemdRecord;
    type Observation = ReferenceSystemdRecord;
    type Handle = SystemdResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        if implementation != &self.assignment.implementation
            || method.interface != self.assignment.interface
        {
            return false;
        }
        match purpose {
            InvocationPurpose::Effect => {
                matches!(
                    method.method.as_str(),
                    "observe" | "reload" | "start" | "stop"
                )
            }
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel => {
                method.method.as_str() == "observe"
            }
            InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => false,
        }
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        self.prepare_reference_request(operation, inputs, resources)
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        self.recover_reference_request(durable, resources)
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(self.unsettled.clone());
        }
        if request.durable.action == SystemdAbilityAction::Observe {
            return match self.observe(request, call_remaining_millis(control)) {
                Ok(_) => EffectDisposition::Completed(self.completed.clone()),
                Err(_) => EffectDisposition::Indeterminate(self.unsettled.clone()),
            };
        }
        if request.durable.action == SystemdAbilityAction::Start {
            match self.observe(request, call_remaining_millis(control)) {
                Ok(UnitActiveState::Active) => {
                    return EffectDisposition::RejectedBeforeEffect(self.unsettled.clone());
                }
                Ok(UnitActiveState::Inactive | UnitActiveState::Failed) => {}
                Ok(_) | Err(_) => {
                    return EffectDisposition::Indeterminate(self.unsettled.clone());
                }
            }
        }
        let Ok(outcome) = run_job(&self.runtime, control, request) else {
            return EffectDisposition::Indeterminate(self.unsettled.clone());
        };
        if !outcome.result.is_done() {
            return EffectDisposition::Indeterminate(self.unsettled.clone());
        }
        match self.observe(request, call_remaining_millis(control)) {
            Ok(active_state) if request.durable.action.postcondition(&active_state) => {
                EffectDisposition::Completed(self.completed.clone())
            }
            Ok(_) | Err(_) => EffectDisposition::Indeterminate(self.unsettled.clone()),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(active_state) if request.durable.action.recovery_postcondition(&active_state) => {
                ReconcileDisposition::Completed(self.completed.clone())
            }
            Ok(_) => ReconcileDisposition::StillIndeterminate(self.unsettled.clone()),
            Err(_) => ReconcileDisposition::InterventionRequired(self.unsettled.clone()),
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(active_state) if request.durable.action.recovery_postcondition(&active_state) => {
                CancellationDisposition::Completed(self.completed.clone())
            }
            Ok(_) | Err(_) => CancellationDisposition::Indeterminate(self.unsettled.clone()),
        }
    }
}

fn reference_record(success: bool) -> Result<ReferenceSystemdRecord, io::Error> {
    Ok(ReferenceSystemdRecord {
        durable: AbilityValue::new(serde_json::Value::Bool(success)).map_err(|error| {
            invalid_data(format!(
                "reference systemd evidence exceeds limits: {error}"
            ))
        })?,
        outputs: BTreeMap::new(),
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SystemdAbilityAction {
    Start,
    Reload,
    Restart,
    Stop,
    Observe,
}

impl SystemdAbilityAction {
    fn from_operation(operation: &Operation) -> Result<Self, io::Error> {
        let action = match operation.family {
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            } => Self::Start,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Reload,
            } => Self::Reload,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            } => Self::Restart,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            } => Self::Stop,
            OperationFamily::ObserveReadiness => Self::Observe,
            _ => return Err(invalid_data("unsupported systemd operation family")),
        };
        if operation.method.as_str() != action.label() {
            return Err(invalid_data(
                "systemd method disagrees with operation family",
            ));
        }
        Ok(action)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Reload => "reload",
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Observe => "observe",
        }
    }

    const fn postcondition(self, active_state: &UnitActiveState) -> bool {
        match self {
            Self::Start | Self::Reload | Self::Restart => active_state.is_active(),
            Self::Stop => matches!(active_state, UnitActiveState::Inactive),
            Self::Observe => true,
        }
    }

    const fn recovery_postcondition(self, active_state: &UnitActiveState) -> bool {
        match self {
            Self::Stop => matches!(active_state, UnitActiveState::Inactive),
            Self::Observe => true,
            Self::Start | Self::Reload | Self::Restart => false,
        }
    }
}

fn require_authorized_action(
    requested: SystemdAbilityAction,
    authorized: SystemdAbilityAction,
    supports_restart: bool,
) -> Result<(), io::Error> {
    if requested != authorized {
        return Err(invalid_data(
            "durable systemd action disagrees with the freshly authorized operation",
        ));
    }
    if requested == SystemdAbilityAction::Restart && !supports_restart {
        return Err(invalid_data(
            "reference systemd contract does not expose restart",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitInput {
    unit: String,
}

fn run_job(
    runtime: &tokio::runtime::Handle,
    control: &dyn RuntimeControl,
    request: &SystemdAbilityRequest,
) -> Result<JobOutcome, io::Error> {
    let remaining_millis = call_remaining_millis(control);
    match request.durable.action {
        SystemdAbilityAction::Start => run_async(
            runtime,
            remaining_millis,
            request.manager.start_unit_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        ),
        SystemdAbilityAction::Reload => run_async(
            runtime,
            remaining_millis,
            request.manager.reload_unit_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        ),
        SystemdAbilityAction::Restart => run_async(
            runtime,
            remaining_millis,
            request.manager.restart_unit_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        ),
        SystemdAbilityAction::Stop => run_async(
            runtime,
            remaining_millis,
            request.manager.stop_unit_exact_revision(
                &request.durable.unit,
                &request.durable.unit_identity,
                &revision_text(request.durable.revision),
            ),
        ),
        SystemdAbilityAction::Observe => Err(invalid_data("observe does not submit a job")),
    }
}

fn call_remaining_millis(control: &dyn RuntimeControl) -> u64 {
    control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis())
}

fn revision_text(revision: RevisionId) -> String {
    revision.0.to_string()
}

fn encode_uri_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
fn revision_receipt_uri(unit: &str, revision: RevisionId) -> String {
    format!(
        "file:/etc/aos/ability-revisions/{}/sha256/{}",
        encode_uri_path_segment(unit),
        revision.0.hex()
    )
}

fn run_async<T, F>(
    runtime: &tokio::runtime::Handle,
    remaining_millis: u64,
    future: F,
) -> Result<T, io::Error>
where
    T: Send,
    F: Future<Output = aos_systemd::Result<T>> + Send,
{
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|current| current.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread)
    {
        return Err(invalid_data(
            "systemd synchronous bridge cannot run on a current-thread Tokio runtime",
        ));
    }
    if remaining_millis == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "systemd deadline elapsed",
        ));
    }
    let timeout = Duration::from_millis(remaining_millis);
    tokio::task::block_in_place(|| {
        runtime
            .block_on(async move { tokio::time::timeout(timeout, future).await })
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "systemd call timed out"))?
            .map_err(|error| io::Error::other(error.to_string()))
    })
}

fn require_multi_thread_runtime(runtime: &tokio::runtime::Handle) -> Result<(), io::Error> {
    if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
        Ok(())
    } else {
        Err(invalid_data(
            "systemd native execution requires a multi-thread Tokio runtime",
        ))
    }
}

struct SystemdEvidenceFields<'a> {
    state: &'a str,
    unit: &'a str,
    unit_identity: Option<&'a str>,
    manager_bus_id: Option<&'a str>,
    manager_owner: Option<&'a str>,
    active_state: Option<&'a UnitActiveState>,
    job_result: Option<&'a str>,
    job_path: Option<&'a str>,
}

fn record_value(fields: SystemdEvidenceFields<'_>) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::json!({
        "schema": RECORD_SCHEMA,
        "state": fields.state,
        "unit": fields.unit,
        "unit_identity": fields.unit_identity,
        "manager_bus_id": fields.manager_bus_id,
        "manager_owner": fields.manager_owner,
        "active_state": fields.active_state.map(UnitActiveState::label),
        "active": fields.active_state.map(UnitActiveState::is_active),
        "job_result": fields.job_result,
        "job_path": fields.job_path,
    }))
    .map_err(|error| invalid_data(format!("systemd evidence exceeds limits: {error}")))
}

fn validate_unit_name(unit: &str) -> Result<(), io::Error> {
    if unit.is_empty()
        || unit.len() > 255
        || !unit.ends_with(".service")
        || !unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-' | b'\\')
        })
    {
        return Err(invalid_data("invalid systemd service unit name"));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_ability_validate::test_support::{
        checked_effect_plan, checked_systemd_manager_effect_plan,
    };
    use aos_systemd::JobResult;
    use zbus::object_server::SignalEmitter;
    use zbus::zvariant::OwnedObjectPath;

    use super::*;
    use crate::ability_package::seal_test_package;

    const SYSTEMD_NAME: &str = "org.freedesktop.systemd1";
    const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/example_2eservice";
    const REBIND_FIRST_PATH: &str = "/org/freedesktop/systemd1/unit/rebind_2dfirst_2eservice";
    const REBIND_SECOND_PATH: &str = "/org/freedesktop/systemd1/unit/rebind_2dsecond_2eservice";

    struct FakeManager {
        units: BTreeMap<String, OwnedObjectPath>,
        sequences: std::sync::Mutex<BTreeMap<String, Vec<OwnedObjectPath>>>,
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl FakeManager {
        async fn subscribe(&self) {}

        async fn get_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
            if let Some(sequence) = self.sequences.lock().unwrap().get_mut(name)
                && !sequence.is_empty()
            {
                return Ok(sequence.remove(0));
            }
            self.units
                .get(name)
                .cloned()
                .ok_or_else(|| zbus::fdo::Error::Failed("unknown test unit".to_string()))
        }

        #[zbus(signal)]
        async fn job_removed(
            emitter: &SignalEmitter<'_>,
            id: u32,
            job: OwnedObjectPath,
            unit: String,
            result: String,
        ) -> zbus::Result<()>;
    }

    struct FakeUnit {
        id: String,
        active_state: Arc<std::sync::Mutex<String>>,
        documentation: Arc<std::sync::Mutex<Vec<String>>>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl FakeUnit {
        async fn start(
            &self,
            #[zbus(connection)] connection: &zbus::Connection,
            _mode: &str,
        ) -> OwnedObjectPath {
            self.starts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.active_state.lock().unwrap() = "active".to_string();
            let job = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/1")
                .expect("fixed test job path is valid");
            let manager = connection
                .object_server()
                .interface::<_, FakeManager>(MANAGER_PATH)
                .await
                .expect("fake manager remains registered");
            manager
                .job_removed(1, job.clone(), self.id.clone(), "done".to_string())
                .await
                .expect("fake job completion signal is emitted");
            job
        }

        async fn stop(
            &self,
            #[zbus(connection)] connection: &zbus::Connection,
            _mode: &str,
        ) -> OwnedObjectPath {
            let job = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/2")
                .expect("fixed test job path is valid");
            let manager = connection
                .object_server()
                .interface::<_, FakeManager>(MANAGER_PATH)
                .await
                .expect("fake manager remains registered");
            manager
                .job_removed(2, job.clone(), self.id.clone(), "done".to_string())
                .await
                .expect("fake job completion signal is emitted");
            job
        }

        #[zbus(property)]
        fn id(&self) -> &str {
            &self.id
        }

        #[zbus(property)]
        fn active_state(&self) -> String {
            self.active_state.lock().unwrap().clone()
        }

        #[zbus(property)]
        fn documentation(&self) -> Vec<String> {
            self.documentation.lock().unwrap().clone()
        }
    }

    struct TestControl;

    impl RuntimeControl for TestControl {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn elapsed_millis(&self) -> u64 {
            0
        }

        fn attempt_remaining_millis(&self) -> u64 {
            1_000
        }

        fn recovery_remaining_millis(&self) -> u64 {
            1_000
        }
    }

    #[test]
    fn current_thread_runtime_is_rejected_before_native_execution() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");

        runtime.block_on(async {
            assert!(require_multi_thread_runtime(&tokio::runtime::Handle::current()).is_err());
        });
    }

    #[test]
    fn host_systemd_rejects_every_other_execution_stage() {
        let mut assignment = test_assignment("test-manager".to_string());
        assert!(require_host_assignment(&assignment).is_ok());

        for stage in [
            ExecutionStage::Build,
            ExecutionStage::Initrd,
            ExecutionStage::SystemContainer,
            ExecutionStage::User,
            ExecutionStage::ApplicationContainer,
        ] {
            assignment.provider.environment.stage = stage;
            assert!(require_host_assignment(&assignment).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_runtime_flavor_is_accepted() {
        assert!(require_multi_thread_runtime(&tokio::runtime::Handle::current()).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_adapter_requires_the_exact_sealed_builtin_handler()
    -> Result<(), Box<dyn std::error::Error>> {
        let checked = checked_systemd_manager_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new("test-manager")?,
        };
        let artifact = assignment.implementation.artifact.clone();
        let mut package = aos_ability_model::PackageDocument {
            schema:
                <aos_ability_model::PackageDocument as aos_ability_model::VersionedDocument>::SCHEMA
                    .to_string(),
            required_features: Vec::new(),
            activation_mode: AbilityActivationMode::StructuredEffects,
            package: aos_ability_model::document::PackageSubject {
                name: LocalKey::new("native-systemd")?,
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            exports: Vec::new(),
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: aos_ability_model::PackageImplementation {
                providers: vec![systemd_manager_provider(artifact.clone())?],
                handlers: BTreeMap::from([(
                    systemd_manager_handler_key()?,
                    systemd_manager_handler(artifact)?,
                )]),
            },
            ownership: Vec::new(),
        };
        let verified = seal_test_package(package.clone())?;
        let executable =
            Path::new(&assignment.implementation.artifact.store_path).join(NATIVE_EXECUTOR_SUFFIX);

        authenticate_builtin_systemd(&verified, &assignment)?;
        authenticate_native_executor_path(
            &assignment.implementation.artifact,
            NATIVE_EXECUTOR_SUFFIX,
            "systemd",
            &executable,
        )?;
        assert!(NativeSystemdAdapter::initialize(assignment.clone()).is_ok());
        assert!(NativeSystemdAdapter::new(&verified, assignment.clone()).is_err());

        package
            .implementation
            .handlers
            .get_mut(&systemd_manager_handler_key()?)
            .expect("test package contains the built-in handler")
            .entry_point = "libexec/forged-systemd-handler".to_string();
        let forged = seal_test_package(package)?;
        assert!(NativeSystemdAdapter::new(&forged, assignment).is_err());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_adapter_is_distinct_and_rejects_forged_contracts()
    -> Result<(), Box<dyn std::error::Error>> {
        let checked = checked_systemd_manager_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        let artifact = binding.implementation.artifact.clone();
        let interface = InterfaceKey {
            name: InterfaceName::new(REFERENCE_SYSTEMD_INTERFACE)?,
            abi: NonZeroU32::new(1).unwrap(),
            descriptor: Sha256Digest::parse(REFERENCE_SYSTEMD_DESCRIPTOR)?,
        };
        let handler_key = LocalKey::new(REFERENCE_SYSTEMD_HANDLER)?;
        let provider = aos_ability_model::ProviderImplementation {
            interface: interface.clone(),
            artifact: artifact.clone(),
            requirements: Vec::new(),
            implementation: aos_ability_model::ImplementationKind::TerminalHandler {
                handler: handler_key.clone(),
            },
            owns_resource_kinds: vec![interface.name.clone()],
        };
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface,
            implementation: ProviderImplementationReference {
                descriptor: provider.descriptor_digest()?,
                artifact: artifact.clone(),
                handler: Some(handler_key.clone()),
            },
            incarnation: IncarnationId::new("test-manager")?,
        };
        let handler = aos_ability_model::HandlerDescriptor {
            artifact: artifact.clone(),
            entry_point: NATIVE_EXECUTOR_SUFFIX.to_string(),
            arguments: ValueSchema::Boolean,
            result: ValueSchema::Boolean,
        };
        let package_document = |provider, handler| aos_ability_model::PackageDocument {
            schema:
                <aos_ability_model::PackageDocument as aos_ability_model::VersionedDocument>::SCHEMA
                    .to_string(),
            required_features: Vec::new(),
            activation_mode: AbilityActivationMode::StructuredEffects,
            package: aos_ability_model::document::PackageSubject {
                name: LocalKey::new("reference-systemd").expect("fixed package name is valid"),
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            exports: Vec::new(),
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: aos_ability_model::PackageImplementation {
                providers: vec![provider],
                handlers: BTreeMap::from([(handler_key.clone(), handler)]),
            },
            ownership: Vec::new(),
        };

        let verified = seal_test_package(package_document(provider.clone(), handler.clone()))?;
        authenticate_reference_systemd(&verified, &assignment)?;
        assert!(NativeSystemdServiceAdapter::initialize(assignment.clone()).is_ok());
        assert!(authenticate_builtin_systemd(&verified, &assignment).is_err());

        let mut forged_entry = handler.clone();
        forged_entry.entry_point = "libexec/forged-systemd-handler".to_string();
        assert!(
            authenticate_reference_systemd(
                &seal_test_package(package_document(provider.clone(), forged_entry))?,
                &assignment,
            )
            .is_err()
        );

        let mut forged_interface = assignment.clone();
        forged_interface.interface = systemd_manager_interface_key()?;
        assert!(authenticate_reference_systemd(&verified, &forged_interface).is_err());

        let mut forged_artifact = assignment;
        forged_artifact.implementation.artifact.store_path =
            "/nix/store/00000000000000000000000000000000-forged".to_string();
        assert!(authenticate_reference_systemd(&verified, &forged_artifact).is_err());
        Ok(())
    }

    #[test]
    fn legacy_durable_systemd_request_requires_a_fresh_plan() {
        let legacy = AbilityValue::new(serde_json::json!({
            "schema": LEGACY_REQUEST_SCHEMA,
            "action": "start",
            "unit": "example.service",
            "unit_identity": UNIT_PATH,
            "manager_bus_id": "test-bus",
            "manager_owner": ":1.42",
        }))
        .unwrap();

        let error = decode_durable_request(&legacy, "systemd request")
            .expect_err("v1 cannot supply an authenticated loaded-unit revision");

        assert!(error.to_string().contains("fresh plan and admission"));
    }

    #[test]
    fn durable_systemd_action_must_match_fresh_operation_authority() {
        assert!(
            require_authorized_action(
                SystemdAbilityAction::Start,
                SystemdAbilityAction::Start,
                true,
            )
            .is_ok()
        );
        assert!(
            require_authorized_action(
                SystemdAbilityAction::Stop,
                SystemdAbilityAction::Start,
                true,
            )
            .is_err()
        );
        assert!(
            require_authorized_action(
                SystemdAbilityAction::Restart,
                SystemdAbilityAction::Restart,
                false,
            )
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_bridge_constructs_timeout_inside_the_target_runtime() {
        let runtime = tokio::runtime::Handle::current();

        let completed = run_async(&runtime, 100, async { Ok::<_, aos_systemd::Error>(7_u8) })
            .expect("ready future completes through the runtime bridge");
        let timeout = run_async(&runtime, 1, async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, aos_systemd::Error>(())
        })
        .expect_err("slow future reaches the bridge timeout");

        assert_eq!(completed, 7);
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn runtime_bridge_yields_a_single_runtime_worker() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("single-worker test runtime builds");
            let result = runtime.block_on(async {
                tokio::spawn(async {
                    let runtime = tokio::runtime::Handle::current();
                    run_async(&runtime, 500, async {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok::<_, aos_systemd::Error>(11_u8)
                    })
                })
                .await
            });
            sender
                .send(result)
                .expect("watchdog receiver remains available");
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("single-worker bridge must not deadlock")
            .expect("runtime worker task completes")
            .expect("timer-dependent systemd future completes");

        assert_eq!(result, 11);
    }

    #[test]
    fn runtime_bridge_rejects_a_current_thread_call_context() {
        let production = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("production test runtime builds");
        let production_handle = production.handle().clone();
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread test runtime builds");

        let error = caller
            .block_on(async {
                run_async(&production_handle, 100, async {
                    Ok::<_, aos_systemd::Error>(())
                })
            })
            .expect_err("current-thread callers are rejected before block_in_place");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn distinct_resources_cannot_target_the_same_unit() {
        let checked = checked_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new("test-manager").unwrap(),
        };
        let first = ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new("primary-unit").unwrap(),
        };
        let second = ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new("alias-unit").unwrap(),
        };

        let result = index_resources(
            &assignment,
            [
                test_resource_spec(first, "example.service"),
                test_resource_spec(second, "example.service"),
            ],
        );

        assert!(result.is_err());
    }

    #[test]
    fn revision_receipt_requires_canonical_exact_generation_ownership() {
        let root = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(root.path()).unwrap().uid();
        let assignment = test_assignment("test-manager".to_string());
        let spec = test_resource_spec(
            test_resource(&assignment, "primary-unit"),
            "example.service",
        );
        let expected = SystemdUnitRevisionReceipt::from_resource(&spec);
        let path = write_test_revision_receipt(root.path(), &spec);
        let rooted = RootedDirectory::open(root.path(), owner, "test receipt root").unwrap();
        let receipt = rooted.resolve(&expected.receipt_relative_path()).unwrap();

        verify_revision_receipt(&receipt, &expected).unwrap();
        assert_eq!(
            expected.documentation_uri(),
            revision_receipt_uri("example.service", test_revision())
        );

        std::fs::write(&path, serde_json::to_vec_pretty(&expected).unwrap()).unwrap();
        assert!(verify_revision_receipt(&receipt, &expected).is_err());

        let mut forged = expected.clone();
        forged.generation = Sha256Digest::of_bytes("another generation");
        std::fs::write(&path, forged.canonical_bytes().unwrap()).unwrap();
        let error = verify_revision_receipt(&receipt, &expected).unwrap_err();
        assert!(error.to_string().contains("authorized resource"));
    }

    #[test]
    fn revision_receipt_rejects_writable_files_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(root.path()).unwrap().uid();
        let assignment = test_assignment("test-manager".to_string());
        let spec = test_resource_spec(
            test_resource(&assignment, "primary-unit"),
            "example.service",
        );
        let expected = SystemdUnitRevisionReceipt::from_resource(&spec);
        let path = write_test_revision_receipt(root.path(), &spec);
        let rooted = RootedDirectory::open(root.path(), owner, "test receipt root").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(rooted.resolve(&expected.receipt_relative_path()).is_err());

        std::fs::remove_file(&path).unwrap();
        let target = root.path().join("outside-receipt");
        std::fs::write(&target, expected.canonical_bytes().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(rooted.resolve(&expected.receipt_relative_path()).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires the hermetic AOS D-Bus broker"]
    async fn supplied_catalog_dispatches_exact_unit_and_recovers_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory_directory = tempfile::tempdir()?;
        let generation = inventory_directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let inventory_plan = checked_effect_plan();
        let inventory_transaction =
            aos_ability_model::TransactionId(LocalKey::new("systemd-inventory")?);
        let (inventory, _inventory_owner) = NativeResourceInventory::test_for_generation(
            &generation,
            &inventory_transaction,
            &inventory_plan,
        )?;
        let receipt_directory = tempfile::tempdir()?;
        let receipt_owner = std::fs::metadata(receipt_directory.path())?.uid();
        let address = std::env::var("AOS_TEST_DBUS_ADDRESS")?;
        let unit_path = OwnedObjectPath::try_from(UNIT_PATH)?;
        let manager = FakeManager {
            units: BTreeMap::from([
                ("example.service".to_string(), unit_path.clone()),
                ("example-alias.service".to_string(), unit_path.clone()),
            ]),
            sequences: std::sync::Mutex::new(BTreeMap::from([(
                "rebind.service".to_string(),
                vec![
                    OwnedObjectPath::try_from(REBIND_FIRST_PATH)?,
                    OwnedObjectPath::try_from(REBIND_SECOND_PATH)?,
                ],
            )])),
        };
        let example_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let second_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let example_active_state = Arc::new(std::sync::Mutex::new("active".to_string()));
        let example_documentation = Arc::new(std::sync::Mutex::new(vec![revision_receipt_uri(
            "example.service",
            test_revision(),
        )]));
        let rebind_documentation = Arc::new(std::sync::Mutex::new(vec![revision_receipt_uri(
            "rebind.service",
            test_revision(),
        )]));
        let server = zbus::connection::Builder::address(address.as_str())?
            .serve_at(MANAGER_PATH, manager)?
            .serve_at(
                UNIT_PATH,
                FakeUnit {
                    id: "example.service".to_string(),
                    active_state: Arc::clone(&example_active_state),
                    documentation: Arc::clone(&example_documentation),
                    starts: Arc::clone(&example_starts),
                },
            )?
            .serve_at(
                REBIND_FIRST_PATH,
                FakeUnit {
                    id: "rebind.service".to_string(),
                    active_state: Arc::new(std::sync::Mutex::new("active".to_string())),
                    documentation: Arc::clone(&rebind_documentation),
                    starts: Arc::clone(&first_starts),
                },
            )?
            .serve_at(
                REBIND_SECOND_PATH,
                FakeUnit {
                    id: "rebind.service".to_string(),
                    active_state: Arc::new(std::sync::Mutex::new("inactive".to_string())),
                    documentation: rebind_documentation,
                    starts: Arc::clone(&second_starts),
                },
            )?
            .build()
            .await?;
        server.request_name(SYSTEMD_NAME).await?;
        let client = zbus::connection::Builder::address(address.as_str())?
            .build()
            .await?;
        let connection = Arc::new(SystemdManagerConnection::from_connection(client));
        let manager = Arc::new(connection.pin().await?);
        let outcome = manager
            .start_unit_exact("rebind.service", REBIND_FIRST_PATH)
            .await?;
        assert_eq!(outcome.result, JobResult::Done);
        assert_eq!(first_starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(second_starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            manager.unit_identity("rebind.service").await?,
            REBIND_SECOND_PATH
        );
        let assignment = test_assignment(manager.incarnation().token());
        let first = test_resource(&assignment, "primary-unit");
        let second = test_resource(&assignment, "alias-unit");

        let first_spec = test_resource_spec(first.clone(), "example.service");
        let _receipt = write_test_revision_receipt(receipt_directory.path(), &first_spec);
        let catalog = SystemdResourceCatalog::new_with_receipt_root(
            Arc::clone(&connection),
            assignment.clone(),
            inventory.clone(),
            [first_spec],
            receipt_directory.path(),
            receipt_owner,
        )?;
        assert_eq!(catalog.resources[&first].unit_identity, UNIT_PATH);
        let observed = catalog.observe_no_op(&first)?;
        assert_eq!(observed.logical(), &first);
        assert_eq!(
            example_starts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an exact active no-op observation must not send a lifecycle job"
        );

        *example_documentation.lock().unwrap() = vec![revision_receipt_uri(
            "example.service",
            RevisionId(aos_contract::Sha256Digest::of_bytes(
                "replacement loaded revision",
            )),
        )];
        assert!(
            catalog
                .requalify(&catalog.resources[&first], 1_000)
                .is_err(),
            "a daemon reload between qualification and acquisition must invalidate the catalog"
        );
        *example_documentation.lock().unwrap() =
            vec![revision_receipt_uri("example.service", test_revision())];

        let first_spec = test_resource_spec(first, "example.service");
        let second_spec = test_resource_spec(second, "example-alias.service");
        let _first_receipt = write_test_revision_receipt(receipt_directory.path(), &first_spec);
        let _second_receipt = write_test_revision_receipt(receipt_directory.path(), &second_spec);
        let aliases = SystemdResourceCatalog::new_with_receipt_root(
            Arc::clone(&connection),
            assignment.clone(),
            inventory,
            [first_spec, second_spec],
            receipt_directory.path(),
            receipt_owner,
        );
        assert!(aliases.is_err());

        let start_request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Start,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                revision: test_revision(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager: Arc::clone(&manager),
        };
        let mut adapter = NativeSystemdAdapter::initialize(assignment)?;
        *example_documentation.lock().unwrap() = Vec::new();
        let starts_before_stale_dispatch = example_starts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            adapter.execute(&start_request, &TestControl),
            EffectDisposition::Indeterminate(_)
        ));
        assert_eq!(
            example_starts.load(std::sync::atomic::Ordering::SeqCst),
            starts_before_stale_dispatch,
            "a daemon reload after acquisition must fail before the lifecycle call"
        );
        *example_documentation.lock().unwrap() =
            vec![revision_receipt_uri("example.service", test_revision())];
        *example_active_state.lock().unwrap() = "inactive".to_string();
        let completed = adapter.execute(&start_request, &TestControl);
        let EffectDisposition::Completed(completed) = completed else {
            panic!("completed start and active postcondition must settle the lifecycle effect");
        };
        let checked = checked_systemd_manager_effect_plan();
        let operation = &checked.operations()[0];
        let active_port = LocalKey::new("active")?;
        checked.validate_operation_output(
            operation,
            &active_port,
            &completed.outputs()[&active_port],
        )?;
        checked.validate_completion_evidence(operation, completed.durable())?;
        assert_eq!(
            completed.outputs()[&active_port].as_json(),
            &serde_json::Value::Bool(true)
        );
        assert_eq!(example_starts.load(std::sync::atomic::Ordering::SeqCst), 1);

        let rejected = adapter.execute(&start_request, &TestControl);
        let EffectDisposition::RejectedBeforeEffect(record) = rejected else {
            panic!("an already-active process has no proven consumer revision");
        };
        assert_eq!(
            record.durable().as_json()["state"],
            "active-consumer-revision-unknown"
        );
        assert_eq!(
            example_starts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the adapter must reject before sending another start job"
        );

        let stop_request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Stop,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                revision: test_revision(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager: Arc::clone(&manager),
        };
        for transient_state in ["activating", "deactivating", "reloading"] {
            *example_active_state.lock().unwrap() = transient_state.to_string();

            let EffectDisposition::Indeterminate(execution_record) =
                adapter.execute(&stop_request, &TestControl)
            else {
                panic!("transient state cannot settle a completed stop job");
            };
            let ReconcileDisposition::StillIndeterminate(reconcile_record) =
                adapter.reconcile(&stop_request, &TestControl)
            else {
                panic!("transient state cannot reconcile a stop");
            };
            let CancellationDisposition::Indeterminate(cancel_record) =
                adapter.cancel(&stop_request, &TestControl)
            else {
                panic!("transient state cannot cancel a stop as completed");
            };
            for record in [execution_record, reconcile_record, cancel_record] {
                checked.validate_observation_evidence(operation, record.durable())?;
                assert_eq!(record.durable().as_json()["active_state"], transient_state);
            }
        }

        *example_active_state.lock().unwrap() = "active".to_string();

        let request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Observe,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                revision: test_revision(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager,
        };
        let reconciled = adapter.reconcile(&request, &TestControl);
        let ReconcileDisposition::Completed(record) = reconciled else {
            panic!("fresh owner-bound observation did not recover the interrupted read");
        };
        checked.validate_completion_evidence(operation, record.durable())?;
        assert_eq!(
            record.outputs()[&LocalKey::new("active")?].as_json(),
            &serde_json::Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn start_reload_and_restart_cannot_be_recovered_from_active_state_alone() {
        assert!(!SystemdAbilityAction::Start.recovery_postcondition(&UnitActiveState::Active));
        assert!(!SystemdAbilityAction::Reload.recovery_postcondition(&UnitActiveState::Active));
        assert!(!SystemdAbilityAction::Restart.recovery_postcondition(&UnitActiveState::Active));
        assert!(SystemdAbilityAction::Stop.recovery_postcondition(&UnitActiveState::Inactive));
        assert!(SystemdAbilityAction::Observe.recovery_postcondition(&UnitActiveState::Active));
        assert!(SystemdAbilityAction::Observe.recovery_postcondition(&UnitActiveState::Inactive));
        for unsettled in [
            UnitActiveState::Activating,
            UnitActiveState::Deactivating,
            UnitActiveState::Reloading,
            UnitActiveState::Failed,
            UnitActiveState::Unknown("future".to_string()),
        ] {
            assert!(!SystemdAbilityAction::Stop.postcondition(&unsettled));
            assert!(!SystemdAbilityAction::Stop.recovery_postcondition(&unsettled));
        }
    }

    fn test_assignment(incarnation: String) -> ProviderAssignment {
        let checked = checked_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new(incarnation).unwrap(),
        }
    }

    fn test_resource(assignment: &ProviderAssignment, key: &str) -> ResourceId {
        ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new(key).unwrap(),
        }
    }

    fn test_revision() -> RevisionId {
        RevisionId(aos_contract::Sha256Digest::of_bytes(
            "loaded systemd test revision",
        ))
    }

    fn test_resource_spec(resource: ResourceId, unit: &str) -> SystemdResourceSpec {
        SystemdResourceSpec {
            resource,
            unit: unit.to_string(),
            revision: test_revision(),
            generation: Sha256Digest::of_bytes("systemd test generation"),
            owner_package: Sha256Digest::of_bytes("systemd test owner package"),
        }
    }

    fn write_test_revision_receipt(root: &Path, spec: &SystemdResourceSpec) -> PathBuf {
        let receipt = SystemdUnitRevisionReceipt::from_resource(spec);
        let path = root.join(receipt.receipt_relative_path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, receipt.canonical_bytes().unwrap()).unwrap();
        path
    }
}
