//! Durable native-resource ownership and live reservation accounting.
//!
//! The profile ledger records stable physical objects, exact logical consumers,
//! checked operation evidence, and retained artifacts. Its canonical JSON form is:
//!
//! ```text
//! {"consumers":[{"artifacts":[...],"attempt":1,"binding":...,"consumer":...,
//! "desired_revision":...,"generation":"gen-1","logical":...,"operation":...,
//! "physical":{"authority":"system-manager","class":"systemd-unit",
//! "object":"/org/freedesktop/systemd1/unit/example_2eservice"},"plan":...,
//! "provider":...,"transaction":...}],"schema":"aos.ability.native-resource-ledger/v1"}
//! ```
//! Transient reservations share reads for one logical owner and serialize every
//! write. Active handles retain the switch lock, while a separate session token
//! prevents those handles from extending admission after session closure.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use aos_ability_model::{
    AccessMode, ArtifactReference, BindingId, InstanceId, Operation, OperationId, ResourceAccess,
    ResourceId, RevisionId, ScopedOperationKey, ServiceAction, TransactionId,
};
use aos_ability_validate::CheckedEffectPlan;
use serde::{Deserialize, Serialize};

use super::{
    GenerationAbilityStoreError, canonical_artifacts, io_error, read_regular_file, sync_directory,
    validate_generation_directory,
};
use crate::config_eval::activation::SwitchLockGuard;
#[cfg(test)]
use crate::config_eval::activation::acquire_switch_lock_pub;

pub(super) const NATIVE_RESOURCE_LEDGER_FILE: &str = ".ability-native-resources.json";
const NATIVE_RESOURCE_LEDGER_SCHEMA: &str = "aos.ability.native-resource-ledger/v1";
const NATIVE_RESOURCE_LEDGER_MAX_BYTES: usize = 8 * 1024 * 1024;
const NATIVE_RESOURCE_CONSUMER_MAX_COUNT: usize = 65_536;
const NATIVE_RESOURCE_STRING_MAX_BYTES: usize = 4 * 1024;

static NATIVE_RESERVATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static NATIVE_LEDGER_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Requires host-native effects to share the machine-global collision domain.
///
/// The durable ledger prevents conflicting physical claims only when every
/// host catalog uses the same profile and switch lock. Root redirection and
/// test-specific transaction paths therefore cannot authorize live host
/// effects.
///
/// # Errors
///
/// Returns an error when the process selects a redirected root, switch lock,
/// or profile directory.
pub(crate) fn require_machine_global_host_collision_domain() -> Result<(), io::Error> {
    validate_machine_global_host_collision_domain(
        std::env::var_os("AOS_ROOT").as_deref(),
        std::env::var_os("AOS_SWITCH_LOCK_PATH").as_deref(),
        std::env::var_os("AOS_PROFILE_ROOT").as_deref(),
    )
}

fn validate_machine_global_host_collision_domain(
    root: Option<&OsStr>,
    switch_lock: Option<&OsStr>,
    profile_root: Option<&OsStr>,
) -> Result<(), io::Error> {
    let rooted = root.is_some_and(|value| !value.is_empty());
    let custom_lock = switch_lock.is_some_and(|value| !value.is_empty());
    let custom_profile =
        profile_root.is_some_and(|value| !value.is_empty() && value != "/var/lib/profiles");

    if rooted || custom_lock || custom_profile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host-native abilities require the machine-global profile, ledger, and switch-lock domain",
        ));
    }
    Ok(())
}

/// Identifies one qualified native object independently from logical providers.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativePhysicalResource {
    pub(super) class: String,
    pub(super) authority: String,
    pub(super) object: String,
}

/// Proves that a trusted native catalog qualified one logical-to-physical mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQualifiedResource {
    pub(super) logical: ResourceId,
    pub(super) physical: NativePhysicalResource,
}

impl NativeQualifiedResource {
    pub(crate) fn systemd(
        logical: ResourceId,
        unit_path: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let physical = NativePhysicalResource {
            class: "systemd-unit".to_string(),
            authority: "system-manager".to_string(),
            object: unit_path.to_string(),
        };
        physical.validate()?;
        Ok(Self { logical, physical })
    }

    /// Qualifies one managed-configuration destination selected by its trusted catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when `canonical_object` is not a canonical absolute
    /// destination or does not fit the native resource ledger contract.
    pub(crate) fn managed_configuration(
        logical: ResourceId,
        canonical_object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        Self::new(
            logical,
            "managed-configuration",
            "configuration-generation",
            canonical_object,
        )
    }

    /// Qualifies one nginx generation-association record selected by its trusted catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when `canonical_object` is not a canonical absolute
    /// association path or does not fit the native resource ledger contract.
    pub(crate) fn nginx_generation(
        logical: ResourceId,
        canonical_object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        Self::new(
            logical,
            "nginx-generation-association",
            "nginx-runtime",
            canonical_object,
        )
    }

    fn new(
        logical: ResourceId,
        class: &str,
        authority: &str,
        object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let physical = NativePhysicalResource {
            class: class.to_string(),
            authority: authority.to_string(),
            object: object.to_string(),
        };
        physical.validate()?;
        Ok(Self { logical, physical })
    }

    /// Returns the checked logical resource qualified by the native catalog.
    #[must_use]
    pub const fn logical(&self) -> &ResourceId {
        &self.logical
    }
}

impl NativePhysicalResource {
    fn validate(&self) -> Result<(), GenerationAbilityStoreError> {
        for (label, value) in [
            ("class", self.class.as_str()),
            ("authority", self.authority.as_str()),
            ("object", self.object.as_str()),
        ] {
            if value.is_empty()
                || value.len() > NATIVE_RESOURCE_STRING_MAX_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(GenerationAbilityStoreError::Conflict(format!(
                    "native resource {label} is empty, oversized, or contains control characters"
                )));
            }
        }
        match (self.class.as_str(), self.authority.as_str()) {
            ("systemd-unit", "system-manager") => self.validate_systemd_unit()?,
            ("managed-configuration", "configuration-generation") => {
                validate_catalog_object(&self.object, "managed-configuration destination")?;
            }
            ("nginx-generation-association", "nginx-runtime") => {
                validate_catalog_object(&self.object, "nginx generation association")?;
            }
            _ => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native resource ledger contains an unsupported physical resource domain"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_systemd_unit(&self) -> Result<(), GenerationAbilityStoreError> {
        let unit = self
            .object
            .strip_prefix("/org/freedesktop/systemd1/unit/")
            .filter(|unit| !unit.is_empty())
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "native systemd resource does not use the canonical Unit object namespace"
                        .to_string(),
                )
            })?;
        if unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            Ok(())
        } else {
            Err(GenerationAbilityStoreError::Conflict(
                "native systemd resource has an invalid canonical Unit object identity".to_string(),
            ))
        }
    }
}

fn validate_catalog_object(object: &str, label: &str) -> Result<(), GenerationAbilityStoreError> {
    let Some(relative) = object.strip_prefix('/') else {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native {label} is not a canonical absolute path"
        )));
    };
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        Err(GenerationAbilityStoreError::Conflict(format!(
            "native {label} is not a canonical absolute path"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod physical_resource_tests {
    use super::*;

    #[test]
    fn catalog_objects_reject_lexical_path_aliases() {
        for alias in [
            "//trusted/object",
            "/trusted//object",
            "/trusted/./object",
            "/trusted/../object",
        ] {
            assert!(
                validate_catalog_object(alias, "test object").is_err(),
                "{alias}"
            );
        }
        assert!(validate_catalog_object("/trusted/object", "test object").is_ok());
    }

    #[test]
    fn host_native_effects_require_the_machine_global_collision_domain() {
        let empty = OsStr::new("");
        let default_profile = OsStr::new("/var/lib/profiles");

        assert!(validate_machine_global_host_collision_domain(None, None, None).is_ok());
        assert!(
            validate_machine_global_host_collision_domain(Some(empty), Some(empty), Some(empty))
                .is_ok()
        );
        assert!(
            validate_machine_global_host_collision_domain(None, None, Some(default_profile))
                .is_ok()
        );

        for (root, switch_lock, profile_root) in [
            (Some(OsStr::new("/target")), None, None),
            (None, Some(OsStr::new("/tmp/switch.lock")), None),
            (None, None, Some(OsStr::new("/tmp/profiles"))),
        ] {
            let error =
                validate_machine_global_host_collision_domain(root, switch_lock, profile_root)
                    .expect_err("redirected authority must be execution-ineligible");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("machine-global"));
        }
    }
}

/// Shares lock-bound native collision accounting with trusted resource catalogs.
#[derive(Clone, Debug)]
pub struct NativeResourceInventory {
    state: Weak<NativeInventoryState>,
    admission: Weak<()>,
}

impl NativeResourceInventory {
    pub(super) fn new(state: &Arc<NativeInventoryState>, admission: &Arc<()>) -> Self {
        Self {
            state: Arc::downgrade(state),
            admission: Arc::downgrade(admission),
        }
    }

    pub(crate) fn reserve(
        &self,
        resource: &NativeQualifiedResource,
        context: aos_ability_runtime::adapter::ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<NativeResourceReservation, GenerationAbilityStoreError> {
        let (state, _admission) = self.begin_admission()?;
        state.reserve(resource, context, operation, access)
    }

    fn begin_admission(
        &self,
    ) -> Result<(Arc<NativeInventoryState>, Arc<()>), GenerationAbilityStoreError> {
        let admission = self.admission.upgrade().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource inventory is closed for new admission".to_string(),
            )
        })?;
        let state = self.state.upgrade().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource inventory outlived its switch-locked session".to_string(),
            )
        })?;
        Ok((state, admission))
    }

    #[cfg(test)]
    pub(crate) fn test_for_generation(
        generation: &Path,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
    ) -> Result<(Self, NativeResourceInventoryTestOwner), GenerationAbilityStoreError> {
        let profile = generation.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "test generation has no profile parent".to_string(),
            )
        })?;
        let switch_lock = Arc::new(
            acquire_switch_lock_pub(&profile.join(".ability-test-switch.lock"))
                .map_err(GenerationAbilityStoreError::SwitchLock)?,
        );
        let state =
            NativeInventoryState::for_generation(generation, transaction, plan, switch_lock)?;
        let admission = Arc::new(());
        let inventory = Self::new(&state, &admission);
        Ok((
            inventory,
            NativeResourceInventoryTestOwner {
                _state: state,
                _admission: admission,
            },
        ))
    }
}

#[cfg(test)]
pub(crate) struct NativeResourceInventoryTestOwner {
    _state: Arc<NativeInventoryState>,
    _admission: Arc<()>,
}

pub(crate) struct NativeResourceReservation {
    state: Arc<NativeInventoryState>,
    pub(super) physical: NativePhysicalResource,
    logical: ResourceId,
    claim: u64,
    access: AccessMode,
    released: bool,
}

impl NativeResourceReservation {
    pub(crate) const fn logical(&self) -> &ResourceId {
        &self.logical
    }

    pub(crate) fn release(&mut self) -> Result<(), GenerationAbilityStoreError> {
        if self.released {
            return Ok(());
        }
        self.state
            .release(&self.physical, &self.logical, self.claim)?;
        self.released = true;
        Ok(())
    }
}

impl Drop for NativeResourceReservation {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let _ = self
            .state
            .release(&self.physical, &self.logical, self.claim);
    }
}

impl fmt::Debug for NativeResourceReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeResourceReservation")
            .field("physical", &self.physical)
            .field("logical", &self.logical)
            .field("claim", &self.claim)
            .field("access", &self.access)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeResourceLedger {
    pub(super) schema: String,
    pub(super) consumers: Vec<ActiveNativeConsumer>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActiveNativeConsumer {
    pub(super) physical: NativePhysicalResource,
    pub(super) logical: ResourceId,
    pub(super) generation: String,
    pub(super) transaction: TransactionId,
    pub(super) plan: aos_ability_model::PlanId,
    pub(super) binding: BindingId,
    pub(super) consumer: InstanceId,
    pub(super) provider: InstanceId,
    pub(super) desired_revision: Option<RevisionId>,
    pub(super) artifacts: Vec<ArtifactReference>,
    pub(super) operation: OperationId,
    pub(super) attempt: u32,
}

#[derive(Clone, Debug)]
struct NativeOperationClaim {
    operation: Operation,
    binding: BindingId,
    consumer: InstanceId,
    provider: InstanceId,
    resources: BTreeSet<ResourceId>,
    desired_revisions: BTreeMap<ResourceId, RevisionId>,
    retains_consumer: bool,
}

#[derive(Debug)]
struct NativeLiveReservations {
    logical: ResourceId,
    claims: BTreeMap<u64, AccessMode>,
}

pub(super) struct NativeInventoryState {
    generation: String,
    ledger_path: PathBuf,
    transaction: TransactionId,
    plan: aos_ability_model::PlanId,
    artifacts: Vec<ArtifactReference>,
    operations: BTreeMap<ScopedOperationKey, NativeOperationClaim>,
    reservations: Mutex<BTreeMap<NativePhysicalResource, NativeLiveReservations>>,
    _switch_lock: Arc<SwitchLockGuard>,
}

impl NativeInventoryState {
    pub(super) fn for_generation(
        generation: &Path,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
        switch_lock: Arc<SwitchLockGuard>,
    ) -> Result<Arc<Self>, GenerationAbilityStoreError> {
        validate_generation_directory(generation)?;
        let generation_name = generation
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(format!(
                    "configuration generation {} has no UTF-8 name",
                    generation.display()
                ))
            })?;
        validate_generation_name(generation_name)?;
        let profile = generation.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(format!(
                "configuration generation {} has no profile parent",
                generation.display()
            ))
        })?;

        let desired_revisions = plan
            .document()
            .desired_revisions
            .iter()
            .map(|revision| (revision.resource.clone(), revision.revision))
            .collect::<BTreeMap<_, _>>();
        let mut operations = BTreeMap::new();
        for operation in plan.operations() {
            let binding = plan
                .binding_plan()
                .binding(&operation.binding)
                .ok_or_else(|| {
                    GenerationAbilityStoreError::Conflict(format!(
                        "checked operation {:?} has no binding",
                        operation.key
                    ))
                })?;
            let resources = binding
                .caller_grant
                .resources
                .iter()
                .map(|permission| permission.resource.clone())
                .collect();
            operations.insert(
                operation.key.clone(),
                NativeOperationClaim {
                    operation: operation.clone(),
                    binding: binding.id.clone(),
                    consumer: binding.request.consumer.clone(),
                    provider: binding.provider.clone(),
                    resources,
                    desired_revisions: desired_revisions.clone(),
                    retains_consumer: operation
                        .accesses
                        .iter()
                        .any(|access| access.mode.is_write())
                        && matches!(
                            operation.family,
                            aos_ability_model::OperationFamily::ServiceLifecycle {
                                action: ServiceAction::Start
                                    | ServiceAction::Reload
                                    | ServiceAction::Restart
                            }
                        ),
                },
            );
        }

        Ok(Arc::new(Self {
            generation: generation_name.to_string(),
            ledger_path: profile.join(NATIVE_RESOURCE_LEDGER_FILE),
            transaction: transaction.clone(),
            plan: plan.id(),
            artifacts: canonical_artifacts(plan.required_runtime_artifacts())?,
            operations,
            reservations: Mutex::new(BTreeMap::new()),
            _switch_lock: switch_lock,
        }))
    }

    fn reserve(
        self: &Arc<Self>,
        resource: &NativeQualifiedResource,
        context: aos_ability_runtime::adapter::ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<NativeResourceReservation, GenerationAbilityStoreError> {
        resource.physical.validate()?;
        let claim = self.qualify_claim(resource, context, operation, access)?;
        let mut reservations = self.lock_reservations()?;
        let mut ledger = load_native_resource_ledger(&self.ledger_path)?;
        if let Some(active) = ledger
            .consumers
            .iter()
            .find(|active| active.physical == resource.physical)
            && active.logical != resource.logical
        {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "native physical resource is retained by logical resource {:?}",
                active.logical
            )));
        }
        if let Some(live) = reservations.get(&resource.physical) {
            if live.logical != resource.logical {
                return Err(GenerationAbilityStoreError::Conflict(format!(
                    "native physical resource already has a live reservation for {:?}",
                    live.logical
                )));
            }
            if access.mode != AccessMode::Read
                || live.claims.values().any(|mode| *mode != AccessMode::Read)
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native physical resource has an incompatible live reservation".to_string(),
                ));
            }
        }

        if let Some(claim) = claim {
            if let Some(active) = ledger
                .consumers
                .iter()
                .find(|active| same_native_consumer_identity(active, &claim))
            {
                if active != &claim {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native consumer identity is already published with different checked evidence"
                            .to_string(),
                    ));
                }
            } else {
                ledger.consumers.push(claim);
                canonicalize_native_consumers(&mut ledger.consumers)?;
                save_native_resource_ledger(&self.ledger_path, &ledger)?;
            }
        }
        let claim = NATIVE_RESERVATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        if claim == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "native reservation identity space is exhausted".to_string(),
            ));
        }
        reservations
            .entry(resource.physical.clone())
            .or_insert_with(|| NativeLiveReservations {
                logical: resource.logical.clone(),
                claims: BTreeMap::new(),
            })
            .claims
            .insert(claim, access.mode);

        Ok(NativeResourceReservation {
            state: Arc::clone(self),
            physical: resource.physical.clone(),
            logical: resource.logical.clone(),
            claim,
            access: access.mode,
            released: false,
        })
    }

    fn qualify_claim(
        &self,
        resource: &NativeQualifiedResource,
        context: aos_ability_runtime::adapter::ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<Option<ActiveNativeConsumer>, GenerationAbilityStoreError> {
        if context.transaction != &self.transaction
            || context.operation.plan != self.plan
            || context.operation.operation != operation.key
            || operation.target.resource != access.resource
            || access.resource != resource.logical
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native reservation context differs from the checked session operation".to_string(),
            ));
        }
        let checked = self.operations.get(&operation.key).ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native reservation operation is absent from the checked plan".to_string(),
            )
        })?;
        if &checked.operation != operation
            || !checked.operation.accesses.contains(access)
            || checked.provider != resource.logical.provider
            || !checked.resources.contains(&resource.logical)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native reservation exceeds its exact checked binding grant".to_string(),
            ));
        }

        if !checked.retains_consumer {
            return Ok(None);
        }

        Ok(Some(ActiveNativeConsumer {
            physical: resource.physical.clone(),
            logical: resource.logical.clone(),
            generation: self.generation.clone(),
            transaction: self.transaction.clone(),
            plan: self.plan,
            binding: checked.binding.clone(),
            consumer: checked.consumer.clone(),
            provider: checked.provider.clone(),
            desired_revision: checked.desired_revisions.get(&resource.logical).copied(),
            artifacts: self.artifacts.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt.get(),
        }))
    }

    fn release(
        &self,
        physical: &NativePhysicalResource,
        logical: &ResourceId,
        claim: u64,
    ) -> Result<(), GenerationAbilityStoreError> {
        let mut reservations = self.lock_reservations()?;
        let remove_physical = match reservations.get_mut(physical) {
            Some(live) if &live.logical == logical => {
                if live.claims.remove(&claim).is_none() {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native reservation claim is no longer held".to_string(),
                    ));
                }
                live.claims.is_empty()
            }
            Some(live) => {
                return Err(GenerationAbilityStoreError::Conflict(format!(
                    "native reservation owner changed from {logical:?} to {:?}",
                    live.logical
                )));
            }
            None => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native reservation is no longer held".to_string(),
                ));
            }
        };
        if remove_physical {
            reservations.remove(physical);
        }
        Ok(())
    }

    fn lock_reservations(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, BTreeMap<NativePhysicalResource, NativeLiveReservations>>,
        GenerationAbilityStoreError,
    > {
        self.reservations.lock().map_err(|_| {
            GenerationAbilityStoreError::Conflict(
                "native resource inventory lock is poisoned".to_string(),
            )
        })
    }
}

fn same_native_consumer_identity(
    left: &ActiveNativeConsumer,
    right: &ActiveNativeConsumer,
) -> bool {
    left.generation == right.generation
        && left.transaction == right.transaction
        && left.plan == right.plan
        && left.binding == right.binding
        && left.physical == right.physical
        && left.logical == right.logical
        && left.operation == right.operation
        && left.attempt == right.attempt
}

pub(super) fn validate_generation_name(name: &str) -> Result<(), GenerationAbilityStoreError> {
    let number = name.strip_prefix("gen-").ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(format!(
            "configuration generation name {name:?} is not canonical"
        ))
    })?;
    let parsed = number.parse::<u64>().map_err(|_| {
        GenerationAbilityStoreError::Conflict(format!(
            "configuration generation name {name:?} is not canonical"
        ))
    })?;
    if parsed == 0 || parsed.to_string() != number {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "configuration generation name {name:?} is not canonical"
        )));
    }
    Ok(())
}

pub(super) fn load_native_resource_ledger(
    path: &Path,
) -> Result<NativeResourceLedger, GenerationAbilityStoreError> {
    let bytes = match read_regular_file(
        path,
        NATIVE_RESOURCE_LEDGER_MAX_BYTES,
        "native resource ledger",
    ) {
        Ok(bytes) => bytes,
        Err(GenerationAbilityStoreError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(NativeResourceLedger {
                schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
                consumers: Vec::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let ledger: NativeResourceLedger =
        aos_contract::canonical::from_slice(&bytes, "native resource ledger").map_err(
            |source| {
                GenerationAbilityStoreError::Conflict(format!(
                    "native resource ledger {} is malformed: {source}",
                    path.display()
                ))
            },
        )?;
    if ledger.schema != NATIVE_RESOURCE_LEDGER_SCHEMA {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger {} has unsupported schema {:?}",
            path.display(),
            ledger.schema
        )));
    }
    if ledger.consumers.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger {} exceeds the {}-consumer limit",
            path.display(),
            NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        )));
    }

    let mut canonical = ledger.clone();
    canonicalize_native_consumers(&mut canonical.consumers)?;
    let canonical_bytes = aos_contract::canonical::to_vec(&canonical).map_err(|source| {
        GenerationAbilityStoreError::Conflict(format!(
            "encoding native resource ledger {}: {source}",
            path.display()
        ))
    })?;
    if canonical != ledger || canonical_bytes != bytes {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger {} is not canonical",
            path.display()
        )));
    }
    Ok(ledger)
}

pub(super) fn save_native_resource_ledger(
    path: &Path,
    ledger: &NativeResourceLedger,
) -> Result<(), GenerationAbilityStoreError> {
    if ledger.schema != NATIVE_RESOURCE_LEDGER_SCHEMA {
        return Err(GenerationAbilityStoreError::Conflict(
            "refusing to publish a native resource ledger with another schema".to_string(),
        ));
    }
    if ledger.consumers.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger exceeds the {}-consumer limit",
            NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        )));
    }

    let mut canonical = ledger.clone();
    canonicalize_native_consumers(&mut canonical.consumers)?;
    let bytes = aos_contract::canonical::to_vec(&canonical).map_err(|source| {
        GenerationAbilityStoreError::Conflict(format!("encoding native resource ledger: {source}"))
    })?;
    if bytes.len() > NATIVE_RESOURCE_LEDGER_MAX_BYTES {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger exceeds the {}-byte limit",
            NATIVE_RESOURCE_LEDGER_MAX_BYTES
        )));
    }

    let parent = path.parent().ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger path {} has no parent",
            path.display()
        ))
    })?;
    let sequence = NATIVE_LEDGER_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{NATIVE_RESOURCE_LEDGER_FILE}.tmp.{}.{}",
        std::process::id(),
        sequence
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| {
            io_error(
                "creating temporary native resource ledger",
                &temporary,
                source,
            )
        })?;
    if let Err(source) = file.write_all(&bytes) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(
            "writing temporary native resource ledger",
            &temporary,
            source,
        ));
    }
    if let Err(source) = file.sync_all() {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(
            "syncing temporary native resource ledger",
            &temporary,
            source,
        ));
    }
    if let Err(source) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error("publishing native resource ledger", path, source));
    }
    sync_directory(parent)
}

fn canonicalize_native_consumers(
    consumers: &mut [ActiveNativeConsumer],
) -> Result<(), GenerationAbilityStoreError> {
    let mut physical_owners = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for consumer in consumers.iter_mut() {
        consumer.physical.validate()?;
        validate_generation_name(&consumer.generation)?;
        if consumer.logical.provider != consumer.provider {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource consumer provider does not own its logical resource".to_string(),
            ));
        }
        if consumer.operation.plan != consumer.plan || consumer.attempt == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource consumer has invalid operation evidence".to_string(),
            ));
        }
        consumer.artifacts = canonical_artifacts(&consumer.artifacts)?;

        if let Some(owner) =
            physical_owners.insert(consumer.physical.clone(), consumer.logical.clone())
            && owner != consumer.logical
        {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "native physical resource maps to conflicting logical resources {owner:?} and {:?}",
                consumer.logical
            )));
        }
        if !identities.insert((
            consumer.generation.clone(),
            consumer.transaction.clone(),
            consumer.binding.clone(),
            consumer.physical.clone(),
            consumer.operation.clone(),
            consumer.attempt,
        )) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource ledger contains a duplicate consumer identity".to_string(),
            ));
        }
    }

    consumers.sort_by(|left, right| {
        left.physical
            .cmp(&right.physical)
            .then_with(|| left.logical.cmp(&right.logical))
            .then_with(|| left.generation.cmp(&right.generation))
            .then_with(|| left.binding.cmp(&right.binding))
            .then_with(|| left.transaction.cmp(&right.transaction))
            .then_with(|| left.plan.cmp(&right.plan))
            .then_with(|| left.operation.cmp(&right.operation))
            .then_with(|| left.attempt.cmp(&right.attempt))
    });
    Ok(())
}
