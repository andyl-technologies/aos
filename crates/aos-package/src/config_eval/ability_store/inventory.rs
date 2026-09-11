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

/// Records one directly requalified resource used by native no-op verification.
#[derive(Clone, Debug)]
pub(crate) struct NativeNoOpResourceObservation {
    pub(crate) qualified: NativeQualifiedResource,
    pub(crate) revision: RevisionId,
    pub(crate) requires_consumer: bool,
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

    /// Qualifies one nginx validation prefix selected by its trusted catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when `canonical_object` is not a canonical absolute
    /// working prefix or does not fit the native resource ledger contract.
    pub(crate) fn nginx_validation_prefix(
        logical: ResourceId,
        canonical_object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        Self::new(
            logical,
            "nginx-validation-prefix",
            "nginx-runtime",
            canonical_object,
        )
    }

    /// Qualifies one Kubernetes API object selected by its trusted catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when `canonical_object` is empty, oversized, contains
    /// control characters, or does not fit the native resource ledger contract.
    pub(crate) fn kubernetes_object(
        logical: ResourceId,
        canonical_object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        Self::new(
            logical,
            "kubernetes-object",
            "kubernetes-api",
            canonical_object,
        )
    }

    /// Qualifies one production host-resource object selected by a sealed adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when the class, authority, or object is outside the
    /// closed production host-resource domains.
    pub(crate) fn host_resource(
        logical: ResourceId,
        class: &str,
        authority: &str,
        object: &str,
    ) -> Result<Self, GenerationAbilityStoreError> {
        Self::new(logical, class, authority, object)
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
                return Err(GenerationAbilityStoreError::Conflict(
                    "legacy nginx association ledger identity does not prove validation-prefix ownership; migration is required"
                        .to_string(),
                ));
            }
            ("nginx-validation-prefix", "nginx-runtime") => {
                validate_catalog_object(&self.object, "nginx validation prefix")?;
            }
            ("kubernetes-object", "kubernetes-api") => {
                if !self.object.starts_with("cluster=")
                    || !self.object.contains(";apiVersion=")
                    || !self.object.contains(";kind=")
                    || !self.object.contains(";namespace=")
                    || !self.object.contains(";name=")
                {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native Kubernetes object identity is not canonical".to_string(),
                    ));
                }
            }
            ("credential-view", "aos-host-runtime")
            | ("host-storage", "aos-host-runtime")
            | ("postgresql-cluster", "aos-host-runtime") => {
                validate_catalog_object(&self.object, "native host-resource path")?;
            }
            ("network-endpoint", "aos-host-runtime") => {
                let endpoint: std::net::SocketAddr = self.object.parse().map_err(|_| {
                    GenerationAbilityStoreError::Conflict(
                        "native endpoint ledger identity is not a socket address".to_string(),
                    )
                })?;
                if endpoint.ip() != std::net::Ipv4Addr::LOCALHOST || endpoint.port() < 1024 {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native endpoint ledger identity is not a nonprivileged IPv4 loopback socket"
                            .to_string(),
                    ));
                }
            }
            ("network-endpoint-allocation", "aos-host-runtime")
            | ("host-network-policy", "aos-host-runtime") => {
                if self.object.starts_with('/') {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native host-resource ledger key must not be a path".to_string(),
                    ));
                }
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

    fn conflicts_with(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        if !self.is_host_path() || !other.is_host_path() {
            return false;
        }
        path_overlaps(&self.object, &other.object)
    }

    fn is_host_path(&self) -> bool {
        matches!(
            (self.class.as_str(), self.authority.as_str()),
            ("managed-configuration", "configuration-generation")
                | ("nginx-validation-prefix", "nginx-runtime")
                | ("credential-view", "aos-host-runtime")
                | ("host-storage", "aos-host-runtime")
                | ("postgresql-cluster", "aos-host-runtime")
        )
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

fn path_overlaps(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
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

    #[test]
    fn host_paths_conflict_across_catalogs_and_ancestor_boundaries() {
        let managed = NativePhysicalResource {
            class: "managed-configuration".to_string(),
            authority: "configuration-generation".to_string(),
            object: "/etc/nginx".to_string(),
        };
        let nginx_child = NativePhysicalResource {
            class: "nginx-validation-prefix".to_string(),
            authority: "nginx-runtime".to_string(),
            object: "/etc/nginx/conf.d".to_string(),
        };
        let sibling = NativePhysicalResource {
            class: "managed-configuration".to_string(),
            authority: "configuration-generation".to_string(),
            object: "/etc/nginx-extra".to_string(),
        };

        assert!(managed.conflicts_with(&nginx_child));
        assert!(nginx_child.conflicts_with(&managed));
        assert!(!managed.conflicts_with(&sibling));
    }

    #[test]
    fn legacy_nginx_association_identity_requires_explicit_migration() {
        let legacy = NativePhysicalResource {
            class: "nginx-generation-association".to_string(),
            authority: "nginx-runtime".to_string(),
            object: "/var/lib/aos/nginx/associations/resource.json".to_string(),
        };

        let error = legacy
            .validate()
            .expect_err("association paths cannot stand in for validation prefixes");
        assert!(error.to_string().contains("migration is required"));
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
            .find(|active| active.physical.conflicts_with(&resource.physical))
            && (active.logical != resource.logical || active.physical != resource.physical)
        {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "native physical resource is retained by logical resource {:?}",
                active.logical
            )));
        }
        if let Some((physical, live)) = reservations
            .iter()
            .find(|(physical, _)| physical.conflicts_with(&resource.physical))
        {
            if live.logical != resource.logical || physical != &resource.physical {
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

pub(crate) fn verify_retained_native_consumers(
    generation: &Path,
    transaction: &TransactionId,
    plan: aos_ability_model::PlanId,
    observations: &[NativeNoOpResourceObservation],
) -> Result<(), GenerationAbilityStoreError> {
    validate_generation_directory(generation)?;
    let generation_name = generation
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "retained no-op generation has no UTF-8 name".to_string(),
            )
        })?;
    validate_generation_name(generation_name)?;
    let profile = generation.parent().ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(
            "retained no-op generation has no profile parent".to_string(),
        )
    })?;
    let ledger = load_native_resource_ledger(&profile.join(NATIVE_RESOURCE_LEDGER_FILE))?;

    let expected = observations
        .iter()
        .filter(|observation| observation.requires_consumer)
        .collect::<Vec<_>>();
    let retained = ledger
        .consumers
        .iter()
        .filter(|consumer| consumer.generation == generation_name)
        .collect::<Vec<_>>();
    for observation in &expected {
        let consumer = retained
            .iter()
            .copied()
            .find(|consumer| consumer.logical == observation.qualified.logical)
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "retained native resource has no active consumer".to_string(),
                )
            })?;
        if consumer.physical != observation.qualified.physical
            || consumer.provider != observation.qualified.logical.provider
            || consumer.desired_revision != Some(observation.revision)
            || &consumer.transaction != transaction
            || consumer.plan != plan
            || consumer.operation.plan != plan
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained native consumer differs from its directly observed resource".to_string(),
            ));
        }
    }
    for consumer in retained {
        let Some(observation) = expected
            .iter()
            .copied()
            .find(|observation| observation.qualified.logical == consumer.logical)
        else {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained generation has an unobserved active native consumer".to_string(),
            ));
        };
        if consumer.physical != observation.qualified.physical
            || consumer.provider != observation.qualified.logical.provider
            || consumer.desired_revision != Some(observation.revision)
            || &consumer.transaction != transaction
            || consumer.plan != plan
            || consumer.operation.plan != plan
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained native consumer differs from its directly observed resource".to_string(),
            ));
        }
    }
    Ok(())
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
    let mut unique_path_owners = Vec::new();
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

        match physical_owners.get(&consumer.physical) {
            Some(owner) if owner != &consumer.logical => {
                return Err(GenerationAbilityStoreError::Conflict(format!(
                    "native physical resource maps to conflicting logical resources {owner:?} and {:?}",
                    consumer.logical
                )));
            }
            Some(_) => {}
            None => {
                physical_owners.insert(consumer.physical.clone(), consumer.logical.clone());
                if consumer.physical.is_host_path() {
                    unique_path_owners.push((consumer.physical.clone(), consumer.logical.clone()));
                }
            }
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

    unique_path_owners.sort_by(|(left, _), (right, _)| {
        left.object
            .split('/')
            .cmp(right.object.split('/'))
            .then_with(|| left.cmp(right))
    });
    for pair in unique_path_owners.windows(2) {
        let [(left, left_owner), (right, right_owner)] = pair else {
            continue;
        };
        if left.conflicts_with(right) {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "overlapping native paths map to incompatible physical owners {left_owner:?} and {right_owner:?}"
            )));
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

#[cfg(test)]
mod no_op_tests {
    use aos_ability_model::{LocalKey, OperationId, TransactionId};
    use aos_ability_validate::test_support::checked_systemd_manager_effect_plan;

    use super::*;

    #[test]
    fn retained_consumer_must_match_the_directly_loaded_revision() {
        let root = tempfile::tempdir().expect("temporary profile");
        let generation = root.path().join("gen-1");
        std::fs::create_dir(&generation).expect("generation directory");
        let plan = checked_systemd_manager_effect_plan();
        let operation = &plan.operations()[0];
        let binding = plan
            .binding_plan()
            .binding(&operation.binding)
            .expect("fixture binding");
        let revision = plan.document().desired_revisions[0].revision;
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/fixture_2eservice",
        )
        .expect("qualified fixture resource");
        let consumer = ActiveNativeConsumer {
            physical: qualified.physical.clone(),
            logical: qualified.logical.clone(),
            generation: "gen-1".to_string(),
            transaction: TransactionId(LocalKey::new("activate").expect("transaction")),
            plan: plan.id(),
            binding: binding.id.clone(),
            consumer: binding.request.consumer.clone(),
            provider: binding.provider.clone(),
            desired_revision: Some(revision),
            artifacts: plan.required_runtime_artifacts().to_vec(),
            operation: OperationId {
                plan: plan.id(),
                operation: operation.key.clone(),
            },
            attempt: 1,
        };
        save_native_resource_ledger(
            &root.path().join(NATIVE_RESOURCE_LEDGER_FILE),
            &NativeResourceLedger {
                schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
                consumers: vec![consumer],
            },
        )
        .expect("fixture ledger");
        let exact = NativeNoOpResourceObservation {
            qualified: qualified.clone(),
            revision,
            requires_consumer: true,
        };
        verify_retained_native_consumers(
            &generation,
            &TransactionId(LocalKey::new("activate").expect("transaction")),
            plan.id(),
            std::slice::from_ref(&exact),
        )
        .expect("exact retained consumer");

        let loaded_new_revision = NativeNoOpResourceObservation {
            qualified,
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("new loaded revision")),
            requires_consumer: true,
        };
        let error = verify_retained_native_consumers(
            &generation,
            &TransactionId(LocalKey::new("activate").expect("transaction")),
            plan.id(),
            &[loaded_new_revision],
        )
        .expect_err("an old consumer cannot stand in for a newly loaded revision");
        assert!(error.to_string().contains("directly observed resource"));
    }

    #[test]
    fn retained_resource_without_consumer_proof_does_not_claim_a_consumer_revision() {
        let root = tempfile::tempdir().expect("temporary profile");
        let generation = root.path().join("gen-1");
        std::fs::create_dir(&generation).expect("generation directory");
        let plan = checked_systemd_manager_effect_plan();
        let operation = &plan.operations()[0];
        let observation = NativeNoOpResourceObservation {
            qualified: NativeQualifiedResource::systemd(
                operation.target.resource.clone(),
                "/org/freedesktop/systemd1/unit/k3s_2eservice",
            )
            .expect("qualified K3s resource"),
            revision: plan.document().desired_revisions[0].revision,
            requires_consumer: false,
        };

        verify_retained_native_consumers(
            &generation,
            &TransactionId(LocalKey::new("activate").expect("transaction")),
            plan.id(),
            &[observation],
        )
        .expect("resource-only no-op evidence does not invent a consumer");
    }
}
