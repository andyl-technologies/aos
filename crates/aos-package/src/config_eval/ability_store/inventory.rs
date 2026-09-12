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
//! "provider":...,"transaction":...}],"owners":[],
//! "schema":"aos.ability.native-resource-ledger/v1"}
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
    AccessMode, ArtifactReference, BindingId, DependencyKind, InstanceId, Operation, OperationId,
    PlanNodeKey, ProviderAdoptionAuthorization, RequiredFeature, ResourceAccess, ResourceId,
    RevisionId, ScopedOperationKey, ServiceAction, TransactionId,
};
use aos_ability_plan::{RuntimeResourceState, TransitionReconciliation};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_validate::{BindingAuthorityKind, CheckedEffectPlan};
use serde::{Deserialize, Serialize};

use super::{
    GenerationAbilityStoreError, TERMINAL_MARKER_FILE, TERMINAL_MARKER_MAX_BYTES, TRANSACTION_ROOT,
    TerminalMarker, canonical_artifacts, io_error, read_regular_file, sync_directory,
    terminal_is_prune_eligible, validate_generation_directory,
};
use crate::config_eval::activation::SwitchLockGuard;
#[cfg(test)]
use crate::config_eval::activation::acquire_switch_lock_pub;

mod ownership;

use ownership::{
    NativeLinkedAdoptionVerification, NativeProviderHandlerIdentity, NativeProviderIdentity,
    NativeProviderOwner, NativeProviderSelection, canonicalize_native_owners,
    operation_provider_identity, retained_provider_owner_for_teardown, selected_provider_owners,
    selected_retained_provider_owners,
};
#[cfg(test)]
use ownership::{
    NativeProviderAdoptionReceipt, assignment_from_endpoint, endpoint_matches_selected_owner,
    handler_from_endpoint, operation_provider_owner, unique_provider_owner_selections,
};

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
    pub(crate) state: RuntimeResourceState,
    pub(crate) consumer_requirement: NativeConsumerRequirement,
}

/// States whether a directly observed native resource may retain a consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NativeConsumerRequirement {
    /// Requires exactly one durable consumer with successful provenance.
    Required,
    /// Requires the resource to have no durable consumers.
    Forbidden,
}

/// Reports whether linked adoption evidence must be recorded, reused, or skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkedAdoptionVerificationState {
    /// Requires exact pre-effect verification of the sealed reconciliation union.
    Pending,
    /// Reuses durable receipt requirements while freshly rechecking the union.
    Recorded,
    /// Reports that marker replay already cleared every named receipt.
    Settled,
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
        let state = NativeInventoryState::for_generation(
            generation,
            transaction,
            plan,
            None,
            BTreeSet::new(),
            switch_lock,
        )?;
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) owners: Vec<NativeProviderOwner>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner: Option<NativeProviderIdentity>,
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
    implementation: aos_ability_model::ProviderImplementationReference,
    owner: Option<NativeProviderIdentity>,
    owner_handler: Option<NativeProviderHandlerIdentity>,
    resources: BTreeSet<ResourceId>,
    desired_revisions: BTreeMap<ResourceId, RevisionId>,
    retains_consumer: bool,
    admits_receipt_source: bool,
}

struct QualifiedNativeClaim {
    consumer: Option<ActiveNativeConsumer>,
    owner: Option<NativeProviderIdentity>,
    owner_handler: Option<NativeProviderHandlerIdentity>,
    admits_receipt_source: bool,
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
    plan_bundle: Option<aos_contract::Sha256Digest>,
    supported_features: BTreeSet<RequiredFeature>,
    artifacts: Vec<ArtifactReference>,
    transition_authority: Option<aos_contract::Sha256Digest>,
    reconciliation_authority_publication: Option<aos_contract::Sha256Digest>,
    adoptions: Vec<ProviderAdoptionAuthorization>,
    desired_revisions: BTreeMap<ResourceId, RevisionId>,
    desired_resources: BTreeSet<ResourceId>,
    desired_owner_selections: Vec<NativeProviderSelection>,
    current_owner_selections: Vec<NativeProviderSelection>,
    linked_recovery_observations: BTreeMap<ResourceId, RuntimeResourceState>,
    operations: BTreeMap<ScopedOperationKey, NativeOperationClaim>,
    dispatch_positions: BTreeMap<ScopedOperationKey, usize>,
    required_success_edges: Vec<(PlanNodeKey, PlanNodeKey)>,
    replayed_current_effect_intents: Mutex<BTreeSet<(OperationId, u32)>>,
    replayed_clean_current_claims: Mutex<BTreeSet<(OperationId, u32)>>,
    replayed_current_successes: Mutex<BTreeSet<(OperationId, u32)>>,
    replayed_current_terminal: Mutex<Option<aos_ability_model::document::TerminalResult>>,
    authenticated_current_claims: Mutex<BTreeSet<aos_contract::Sha256Digest>>,
    reservations: Mutex<BTreeMap<NativePhysicalResource, NativeLiveReservations>>,
    _switch_lock: Arc<SwitchLockGuard>,
}

impl NativeInventoryState {
    /// Reports whether linked adoption evidence must be written, reused, or skipped.
    ///
    /// # Errors
    ///
    /// Returns an error when a named receipt is missing, receipt states are
    /// mixed, or recorded evidence names another recovery graph or authority.
    pub(crate) fn linked_adoption_verification_state(
        &self,
        reconciliation: &TransitionReconciliation,
    ) -> Result<LinkedAdoptionVerificationState, GenerationAbilityStoreError> {
        let ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        let expected_verification = self.linked_adoption_verification(reconciliation)?;
        let mut state = None;
        for resource in &reconciliation.unsettled_provider_adoptions {
            let matching = ledger
                .owners
                .iter()
                .filter(|owner| owner.resource == *resource)
                .collect::<Vec<_>>();
            let [owner] = matching.as_slice() else {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption verification lacks one exact durable owner".to_string(),
                ));
            };
            let resource_state = match &owner.adoption {
                Some(receipt)
                    if receipt.linked_verification.as_ref() == Some(&expected_verification) =>
                {
                    LinkedAdoptionVerificationState::Recorded
                }
                Some(receipt)
                    if receipt.consumer_requirement.is_none()
                        && receipt.linked_verification.is_none() =>
                {
                    LinkedAdoptionVerificationState::Pending
                }
                Some(_) => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "linked adoption verification witness differs from the current recovery graph"
                            .to_string(),
                    ));
                }
                None => LinkedAdoptionVerificationState::Settled,
            };
            if state
                .replace(resource_state)
                .is_some_and(|prior| prior != resource_state)
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "linked adoption verification receipts have mixed durable states".to_string(),
                ));
            }
        }
        state.ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "linked adoption verification names no receipt resources".to_string(),
            )
        })
    }

    fn linked_adoption_verification(
        &self,
        reconciliation: &TransitionReconciliation,
    ) -> Result<NativeLinkedAdoptionVerification, GenerationAbilityStoreError> {
        let plan_bundle = self.plan_bundle.ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "linked adoption verification lacks a retained plan bundle".to_string(),
            )
        })?;
        Ok(NativeLinkedAdoptionVerification {
            generation: self.generation.clone(),
            transaction: self.transaction.clone(),
            plan: self.plan,
            plan_bundle,
            authority_publication: reconciliation.authority_publication,
        })
    }

    fn has_exact_linked_adoption_verification(
        &self,
        receipt: &ownership::NativeProviderAdoptionReceipt,
    ) -> bool {
        receipt
            .linked_verification
            .as_ref()
            .is_some_and(|verification| {
                verification.generation == self.generation
                    && verification.transaction == self.transaction
                    && verification.plan == self.plan
                    && Some(verification.plan_bundle) == self.plan_bundle
                    && Some(verification.authority_publication)
                        == self.reconciliation_authority_publication
            })
    }

    fn authenticated_retained_terminal_result(
        &self,
        generation: &str,
        transaction: &TransactionId,
        plan: aos_ability_model::PlanId,
    ) -> Result<Option<aos_ability_model::document::TerminalResult>, GenerationAbilityStoreError>
    {
        let current =
            self.classify_current_journal(generation, transaction, plan, "terminal evidence")?;
        let marker = exact_terminal_result(&self.ledger_path, generation, transaction, plan)?;
        if current {
            let replayed = *self.replayed_current_terminal.lock().map_err(|_| {
                GenerationAbilityStoreError::Conflict(
                    "current native terminal replay state is unavailable".to_string(),
                )
            })?;
            if marker != replayed {
                return Err(GenerationAbilityStoreError::Conflict(
                    "current ability terminal marker differs from its recovered execution result"
                        .to_string(),
                ));
            }
            return Ok(marker);
        }
        let Some(marker) = marker else {
            return Ok(None);
        };
        let profile = self.ledger_path.parent().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native resource ledger has no profile parent".to_string(),
            )
        })?;
        let source = super::RetainedAbilityDiagnosticSource::load_from_profile(
            profile.join(generation),
            transaction,
            self.supported_features.clone(),
            profile,
        )?;
        if source.plan().id() != plan
            || source.terminal_result(aos_ability_runtime::journal::JournalLimits::default())?
                != Some(marker)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "ability terminal marker differs from its retained checked journal".to_string(),
            ));
        }
        Ok(Some(marker))
    }

    fn classify_current_journal(
        &self,
        generation: &str,
        transaction: &TransactionId,
        plan: aos_ability_model::PlanId,
        evidence: &str,
    ) -> Result<bool, GenerationAbilityStoreError> {
        if generation != self.generation || transaction != &self.transaction {
            return Ok(false);
        }
        if plan != self.plan {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "current native {evidence} names a different checked plan"
            )));
        }
        Ok(true)
    }

    fn has_current_journal_identity(&self, generation: &str, transaction: &TransactionId) -> bool {
        generation == self.generation && transaction == &self.transaction
    }

    pub(super) fn for_generation(
        generation: &Path,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
        bundle: Option<&ReloadablePlanBundle>,
        supported_features: BTreeSet<RequiredFeature>,
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
        let current_binding = bundle
            .map(|bundle| bundle.revalidate_current_binding(&supported_features))
            .transpose()
            .map_err(GenerationAbilityStoreError::Bundle)?
            .flatten();
        let current_owner_selections = current_binding
            .as_ref()
            .map(selected_retained_provider_owners)
            .transpose()?
            .unwrap_or_default();
        let mut operations = BTreeMap::new();
        let adoptions = bundle
            .map(ReloadablePlanBundle::provider_adoptions)
            .unwrap_or_default()
            .to_vec();
        let desired_resources = desired_revisions.keys().cloned().collect::<BTreeSet<_>>();
        let linked_recovery_observations = bundle
            .and_then(ReloadablePlanBundle::reconciliation)
            .into_iter()
            .flat_map(|reconciliation| &reconciliation.observations)
            .map(|observation| (observation.resource.clone(), observation.state))
            .collect();
        for operation in plan.operations() {
            if operation
                .accesses
                .iter()
                .any(|access| access.resource != operation.target.resource)
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native operations must route every access through their exact target resource"
                        .to_string(),
                ));
            }
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
            let mut owner_claim = operation_provider_identity(plan, operation, &adoptions)?;
            if owner_claim.is_none()
                && let Some(BindingAuthorityKind::Teardown { source_binding, .. }) =
                    plan.binding_plan().binding_authority(&operation.binding)
                && let Some(current_binding) = current_binding.as_ref()
                && let Some(selection) = retained_provider_owner_for_teardown(
                    current_binding,
                    source_binding,
                    &operation.target.resource,
                )?
            {
                owner_claim = Some((selection.identity, selection.handler));
            }
            let (owner, owner_handler) = owner_claim
                .map(|(owner, handler)| (Some(owner), Some(handler)))
                .unwrap_or((None, None));
            let admits_receipt_source = matches!(
                plan.binding_plan().binding_authority(&operation.binding),
                Some(BindingAuthorityKind::Teardown { .. })
            ) && owner
                .as_ref()
                .zip(owner_handler.as_ref())
                .is_some_and(|(owner, handler)| {
                    adoptions.iter().any(|adoption| {
                        adoption.resource == operation.target.resource
                            && NativeProviderIdentity::from_endpoint(&adoption.source) == *owner
                            && ownership::handler_from_endpoint(&adoption.source) == *handler
                    })
                });
            operations.insert(
                operation.key.clone(),
                NativeOperationClaim {
                    operation: operation.clone(),
                    binding: binding.id.clone(),
                    consumer: binding.request.consumer.clone(),
                    provider: binding.provider.clone(),
                    implementation: binding.implementation.clone(),
                    owner,
                    owner_handler,
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
                    admits_receipt_source,
                },
            );
        }

        let mut lifecycle_cardinality = BTreeMap::new();
        for operation in operations.values() {
            let resource = operation.operation.target.resource.clone();
            let counts = lifecycle_cardinality
                .entry(resource)
                .or_insert((0_usize, 0_usize));
            if operation.retains_consumer {
                counts.0 += 1;
            }
            if matches!(
                operation.operation.family,
                aos_ability_model::OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            ) {
                counts.1 += 1;
            }
        }
        if lifecycle_cardinality
            .values()
            .any(|(consumer_writes, stops)| *consumer_writes > 1 || *stops > 1)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native plan has ambiguous lifecycle operation cardinality for one resource"
                    .to_string(),
            ));
        }

        let has_persistent_delete = plan.operations().iter().any(|operation| {
            operation.target.lifetime == aos_ability_model::ResourceLifetime::Persistent
                && operation.accesses.iter().any(|access| {
                    access.resource == operation.target.resource && access.mode.is_write()
                })
                && plan
                    .interfaces()
                    .get(&operation.target.interface)
                    .and_then(|interface| {
                        interface
                            .interface
                            .lifecycle
                            .persistent_delete_method
                            .as_ref()
                    })
                    == Some(&operation.method)
        });
        if has_persistent_delete {
            return Err(GenerationAbilityStoreError::Conflict(
                "persistent deletion requires durable retirement evidence before native effects"
                    .to_string(),
            ));
        }
        for operation in operations.values().filter(|operation| {
            operation.operation.target.lifetime == aos_ability_model::ResourceLifetime::Persistent
                && matches!(
                    operation.operation.family,
                    aos_ability_model::OperationFamily::ServiceLifecycle {
                        action: ServiceAction::Stop
                    }
                )
                && operation.operation.accesses.iter().any(|access| {
                    access.resource == operation.operation.target.resource && access.mode.is_write()
                })
                && !desired_resources.contains(&operation.operation.target.resource)
        }) {
            let replacement_start = operations.values().any(|candidate| {
                candidate.retains_consumer
                    && candidate.operation.target.resource == operation.operation.target.resource
            });
            if !replacement_start {
                return Err(GenerationAbilityStoreError::Conflict(
                    "persistent Stop without a checked replacement requires durable dormant-owner evidence before native effects"
                        .to_string(),
                ));
            }
        }

        let state = Arc::new(Self {
            generation: generation_name.to_string(),
            ledger_path: profile.join(NATIVE_RESOURCE_LEDGER_FILE),
            transaction: transaction.clone(),
            plan: plan.id(),
            plan_bundle: bundle
                .map(ReloadablePlanBundle::digest)
                .transpose()
                .map_err(GenerationAbilityStoreError::Bundle)?,
            supported_features,
            artifacts: canonical_artifacts(plan.required_runtime_artifacts())?,
            transition_authority: bundle
                .and_then(ReloadablePlanBundle::transition_authority_digest),
            reconciliation_authority_publication: bundle
                .and_then(ReloadablePlanBundle::reconciliation)
                .map(|reconciliation| reconciliation.authority_publication),
            adoptions,
            desired_revisions,
            desired_resources,
            desired_owner_selections: selected_provider_owners(plan)?,
            current_owner_selections,
            linked_recovery_observations,
            operations,
            dispatch_positions: plan
                .dispatch_order()
                .iter()
                .enumerate()
                .filter_map(|(position, node)| match node {
                    aos_ability_model::PlanNodeKey::Operation { key } => {
                        Some((key.clone(), position))
                    }
                    _ => None,
                })
                .collect(),
            required_success_edges: plan
                .edges()
                .iter()
                .filter(|edge| edge.kind == DependencyKind::RequiredSuccess)
                .map(|edge| (edge.from.clone(), edge.to.clone()))
                .collect(),
            replayed_current_effect_intents: Mutex::new(BTreeSet::new()),
            replayed_clean_current_claims: Mutex::new(BTreeSet::new()),
            replayed_current_successes: Mutex::new(BTreeSet::new()),
            replayed_current_terminal: Mutex::new(None),
            authenticated_current_claims: Mutex::new(BTreeSet::new()),
            reservations: Mutex::new(BTreeMap::new()),
            _switch_lock: switch_lock,
        });
        Ok(state)
    }

    fn reserve(
        self: &Arc<Self>,
        resource: &NativeQualifiedResource,
        context: aos_ability_runtime::adapter::ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<NativeResourceReservation, GenerationAbilityStoreError> {
        resource.physical.validate()?;
        let qualified = self.qualify_claim(resource, context, operation, access)?;
        let persistent_write = access.mode.is_write()
            && operation.target.lifetime == aos_ability_model::ResourceLifetime::Persistent;
        let checked_stateful_resource = self
            .desired_owner_selections
            .iter()
            .any(|selection| selection.resource == resource.logical)
            || self
                .current_owner_selections
                .iter()
                .any(|selection| selection.resource == resource.logical)
            || self
                .adoptions
                .iter()
                .any(|adoption| adoption.resource == resource.logical);
        if persistent_write
            && checked_stateful_resource
            && (qualified.owner.is_none() || qualified.owner_handler.is_none())
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "stateful native write lacks mandatory durable owner and handler classification"
                    .to_string(),
            ));
        }
        let mut reservations = self.lock_reservations()?;
        let mut ledger = load_native_resource_ledger(&self.ledger_path)?;
        self.validate_current_journal_plans(&ledger)?;
        let mut ledger_changed = false;
        for owner in &ledger.owners {
            if owner.resource == resource.logical {
                if owner.physical != resource.physical {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native logical resource owner retains another physical identity"
                            .to_string(),
                    ));
                }
                let exact_current_owner = qualified.owner.as_ref() == Some(&owner.identity)
                    && qualified.owner_handler.as_ref() == Some(&owner.handler);
                let exact_receipt_source = qualified.admits_receipt_source
                    && owner.adoption.as_ref().is_some_and(|receipt| {
                        qualified.owner.as_ref() == Some(&receipt.source)
                            && qualified.owner_handler.as_ref() == Some(&receipt.source_handler)
                    });
                if persistent_write && !exact_current_owner && !exact_receipt_source {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "stateful native write differs from its retained durable owner and handler"
                            .to_string(),
                    ));
                }
            } else if owner.physical.conflicts_with(&resource.physical) {
                return Err(GenerationAbilityStoreError::Conflict(format!(
                    "native physical resource is retained by durable owner {:?}",
                    owner.resource
                )));
            }
        }
        if access.mode.is_write()
            && let Some(owner) = &qualified.owner
            && resource.logical.provider == owner.provider
            && operation.target.lifetime == aos_ability_model::ResourceLifetime::Persistent
        {
            ledger_changed |= self.authorize_provider_owner(
                &mut ledger,
                owner,
                resource,
                qualified.owner_handler.as_ref(),
                context.expected_provider,
                qualified.admits_receipt_source,
                context.operation,
                context.attempt.get(),
            )?;
        }
        if ledger.consumers.iter().any(|consumer| {
            consumer.logical == resource.logical && consumer.physical != resource.physical
        }) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native logical resource is retained under another physical identity".to_string(),
            ));
        }
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

        if let Some(claim) = qualified.consumer {
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
                ledger_changed = true;
            }
        }
        if ledger_changed {
            canonicalize_native_ledger(&mut ledger)?;
            save_native_resource_ledger(&self.ledger_path, &ledger)?;
            self.mark_persisted_current_claims_authenticated(&ledger)?;
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
    ) -> Result<QualifiedNativeClaim, GenerationAbilityStoreError> {
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
        let actor_matches = checked.provider == resource.logical.provider
            || checked.consumer == resource.logical.provider;
        let handler_matches = context.expected_provider.is_some_and(|assignment| {
            assignment.provider == checked.provider
                && assignment.interface == checked.operation.interface
                && assignment.implementation == checked.implementation
        });
        if &checked.operation != operation
            || !checked.operation.accesses.contains(access)
            || !actor_matches
            || !handler_matches
            || !checked.resources.contains(&resource.logical)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native reservation exceeds its exact checked binding grant".to_string(),
            ));
        }

        let consumer = checked.retains_consumer.then(|| ActiveNativeConsumer {
            physical: resource.physical.clone(),
            logical: resource.logical.clone(),
            generation: self.generation.clone(),
            transaction: self.transaction.clone(),
            plan: self.plan,
            binding: checked.binding.clone(),
            consumer: checked.consumer.clone(),
            provider: checked.provider.clone(),
            owner: checked.owner.clone(),
            desired_revision: checked.desired_revisions.get(&resource.logical).copied(),
            artifacts: self.artifacts.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt.get(),
        });

        Ok(QualifiedNativeClaim {
            consumer,
            owner: checked.owner.clone(),
            owner_handler: checked.owner_handler.clone(),
            admits_receipt_source: checked.admits_receipt_source,
        })
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
    supported_features: BTreeSet<RequiredFeature>,
    journal_limits: aos_ability_runtime::journal::JournalLimits,
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

    verify_retained_native_consumers_with_status(
        &ledger,
        observations,
        |consumer, owner_handler| {
            let terminal = exact_terminal_result(
                &profile.join(NATIVE_RESOURCE_LEDGER_FILE),
                &consumer.generation,
                &consumer.transaction,
                consumer.plan,
            )?
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "retained native consumer has no exact terminal transaction evidence"
                        .to_string(),
                )
            })?;
            if !matches!(
                terminal,
                aos_ability_model::document::TerminalResult::Succeeded
                    | aos_ability_model::document::TerminalResult::SettledFailure
            ) {
                return Ok(false);
            }
            let source = super::RetainedAbilityDiagnosticSource::load_from_profile(
                profile.join(&consumer.generation),
                &consumer.transaction,
                supported_features.clone(),
                profile,
            )?;
            validate_retained_native_consumer_claim(
                consumer,
                source.plan(),
                source.provider_adoptions(),
                owner_handler,
            )?;
            source.operation_succeeded(
                journal_limits,
                &consumer.operation,
                consumer.attempt,
                terminal,
            )
        },
    )
}

fn validate_retained_native_consumer_claim(
    consumer: &ActiveNativeConsumer,
    plan: &CheckedEffectPlan,
    adoptions: &[ProviderAdoptionAuthorization],
    owner_handler: Option<&NativeProviderHandlerIdentity>,
) -> Result<(), GenerationAbilityStoreError> {
    let operation = plan
        .operation(&consumer.operation.operation)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "retained native consumer operation is absent from its checked plan".to_string(),
            )
        })?;
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "retained native consumer operation lost its checked binding".to_string(),
            )
        })?;
    let expected_claim = operation_provider_identity(plan, operation, adoptions)?;
    let (expected_owner, expected_owner_handler) = expected_claim
        .map(|(owner, handler)| (Some(owner), Some(handler)))
        .unwrap_or((None, None));
    let expected_revision = plan
        .document()
        .desired_revisions
        .iter()
        .find(|revision| revision.resource == consumer.logical)
        .map(|revision| revision.revision);
    if consumer.plan != plan.id()
        || consumer.operation.plan != plan.id()
        || consumer.binding != binding.id
        || consumer.consumer != binding.request.consumer
        || consumer.provider != binding.provider
        || operation.target.resource != consumer.logical
        || !operation
            .accesses
            .iter()
            .any(|access| access.resource == consumer.logical && access.mode.is_write())
        || !matches!(
            operation.family,
            aos_ability_model::OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start | ServiceAction::Reload | ServiceAction::Restart
            }
        )
        || consumer.owner != expected_owner
        || expected_owner_handler.as_ref() != owner_handler
        || consumer.desired_revision != expected_revision
        || consumer.artifacts != canonical_artifacts(plan.required_runtime_artifacts())?
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "retained native consumer differs from its exact checked operation claim".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn retained_consumer_owner_handler<'a>(
    ledger: &'a NativeResourceLedger,
    consumer: &ActiveNativeConsumer,
) -> Result<Option<&'a NativeProviderHandlerIdentity>, GenerationAbilityStoreError> {
    let matching_owners = ledger
        .owners
        .iter()
        .filter(|owner| owner.resource == consumer.logical)
        .collect::<Vec<_>>();
    match (&consumer.owner, matching_owners.as_slice()) {
        (None, []) if consumer.provider == consumer.logical.provider => Ok(None),
        (Some(identity), [owner])
            if consumer.consumer == consumer.logical.provider
                && identity.provider == consumer.logical.provider
                && consumer.physical == owner.physical =>
        {
            if identity == &owner.identity {
                return Ok(Some(&owner.handler));
            }
            if let Some(receipt) = &owner.adoption
                && identity == &receipt.source
            {
                return Ok(Some(&receipt.source_handler));
            }
            Err(GenerationAbilityStoreError::Conflict(
                "retained native consumer differs from its exact durable owner".to_string(),
            ))
        }
        _ => Err(GenerationAbilityStoreError::Conflict(
            "retained native consumer has ambiguous logical and terminal provider actors"
                .to_string(),
        )),
    }
}

pub(super) fn verify_retained_native_consumers_with_status(
    ledger: &NativeResourceLedger,
    observations: &[NativeNoOpResourceObservation],
    mut consumer_operation_succeeded: impl FnMut(
        &ActiveNativeConsumer,
        Option<&NativeProviderHandlerIdentity>,
    ) -> Result<bool, GenerationAbilityStoreError>,
) -> Result<(), GenerationAbilityStoreError> {
    let mut observed_resources = BTreeSet::new();
    for observation in observations {
        if !observed_resources.insert(observation.qualified.logical.clone()) {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained no-op observations contain a duplicate logical resource".to_string(),
            ));
        }
    }

    for observation in observations {
        let matching_consumers = ledger
            .consumers
            .iter()
            .filter(|consumer| consumer.logical == observation.qualified.logical)
            .collect::<Vec<_>>();
        let matching_owners = ledger
            .owners
            .iter()
            .filter(|owner| owner.resource == observation.qualified.logical)
            .collect::<Vec<_>>();
        match matching_owners.as_slice() {
            [] => {}
            [owner] if owner.physical == observation.qualified.physical => {}
            _ => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "retained native owner differs from its directly observed physical resource"
                        .to_string(),
                ));
            }
        }
        if observation.consumer_requirement == NativeConsumerRequirement::Forbidden {
            if !matching_consumers.is_empty() {
                return Err(GenerationAbilityStoreError::Conflict(
                    "resource-only retained native observation has active consumers".to_string(),
                ));
            }
            continue;
        }
        let [consumer] = matching_consumers.as_slice() else {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained native resource lacks one exact active consumer".to_string(),
            ));
        };
        let owner_handler = retained_consumer_owner_handler(ledger, consumer)?;
        let expected_revision = match observation.state {
            RuntimeResourceState::Present {
                revision,
                health:
                    aos_ability_plan::RuntimeResourceHealth::Healthy
                    | aos_ability_plan::RuntimeResourceHealth::Divergent,
            } => Some(revision),
            _ => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "retained active consumer is not backed by a healthy resource observation"
                        .to_string(),
                ));
            }
        };
        if consumer.physical != observation.qualified.physical
            || consumer.desired_revision != expected_revision
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained native consumer differs from its directly observed resource".to_string(),
            ));
        }

        if !consumer_operation_succeeded(consumer, owner_handler)? {
            return Err(GenerationAbilityStoreError::Conflict(
                "retained native consumer lacks exact successful operation evidence".to_string(),
            ));
        }
    }
    if ledger
        .consumers
        .iter()
        .any(|consumer| !observed_resources.contains(&consumer.logical))
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "retained ledger has an unobserved active native consumer".to_string(),
        ));
    }
    if ledger.owners.iter().any(|owner| {
        !observed_resources.contains(&owner.resource)
            || ledger
                .owners
                .iter()
                .filter(|candidate| candidate.resource == owner.resource)
                .count()
                != 1
    }) {
        return Err(GenerationAbilityStoreError::Conflict(
            "retained ledger has an unobserved or ambiguous native owner".to_string(),
        ));
    }
    for observation in observations {
        if observation.consumer_requirement == NativeConsumerRequirement::Forbidden
            && ledger
                .consumers
                .iter()
                .any(|consumer| consumer.logical == observation.qualified.logical)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "resource-only retained native observation has active consumers".to_string(),
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

fn exact_terminal_result(
    ledger_path: &Path,
    generation: &str,
    transaction: &TransactionId,
    plan: aos_ability_model::PlanId,
) -> Result<Option<aos_ability_model::document::TerminalResult>, GenerationAbilityStoreError> {
    let profile = ledger_path.parent().ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(
            "native resource ledger has no profile parent".to_string(),
        )
    })?;
    let path = profile
        .join(generation)
        .join(TRANSACTION_ROOT)
        .join(transaction.0.as_str())
        .join(TERMINAL_MARKER_FILE);
    let bytes = match read_regular_file(&path, TERMINAL_MARKER_MAX_BYTES, "ability terminal marker")
    {
        Ok(bytes) => bytes,
        Err(GenerationAbilityStoreError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let marker: TerminalMarker =
        aos_contract::canonical::from_slice(&bytes, "ability terminal marker").map_err(
            |source| {
                GenerationAbilityStoreError::Conflict(format!(
                    "decoding completed provider-adoption marker: {source}"
                ))
            },
        )?;
    let canonical = aos_contract::canonical::to_vec(&marker).map_err(|source| {
        GenerationAbilityStoreError::Conflict(format!(
            "encoding completed provider-adoption marker: {source}"
        ))
    })?;
    if canonical != bytes
        || marker.schema != super::TERMINAL_MARKER_SCHEMA
        || &marker.transaction != transaction
        || marker.plan != plan
        || !terminal_is_prune_eligible(marker.terminal)
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "ability terminal marker differs from its native ownership transaction".to_string(),
        ));
    }
    Ok(Some(marker.terminal))
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
                owners: Vec::new(),
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
    if ledger.consumers.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        || ledger.owners.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT
    {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger {} exceeds the {}-consumer limit",
            path.display(),
            NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        )));
    }

    let mut canonical = ledger.clone();
    canonicalize_native_ledger(&mut canonical)?;
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
    if ledger.consumers.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        || ledger.owners.len() > NATIVE_RESOURCE_CONSUMER_MAX_COUNT
    {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native resource ledger exceeds the {}-consumer limit",
            NATIVE_RESOURCE_CONSUMER_MAX_COUNT
        )));
    }

    let mut canonical = ledger.clone();
    canonicalize_native_ledger(&mut canonical)?;
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

/// Returns resources whose adoption receipt belongs to a settled failed transaction.
///
/// An unmarked receipt may still belong to an interrupted transaction and must
/// resume that exact graph. This query reports only immutable settled failures,
/// which require a newly linked recovery transaction.
///
/// # Errors
///
/// Returns an error when the native ledger or referenced terminal evidence is
/// malformed, noncanonical, or mismatched.
pub(crate) fn settled_failed_provider_adoption_resources(
    profile: &Path,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<BTreeSet<ResourceId>, GenerationAbilityStoreError> {
    let ledger_path = profile.join(NATIVE_RESOURCE_LEDGER_FILE);
    let ledger = load_native_resource_ledger(&ledger_path)?;
    let mut resources = BTreeSet::new();

    for owner in ledger
        .owners
        .iter()
        .filter(|owner| owner.adoption.is_some())
    {
        let marker = exact_terminal_result(
            &ledger_path,
            &owner.generation,
            &owner.transaction,
            owner.plan,
        )?;
        if marker != Some(aos_ability_model::document::TerminalResult::SettledFailure) {
            continue;
        }
        let source = super::RetainedAbilityDiagnosticSource::load_from_profile(
            profile.join(&owner.generation),
            &owner.transaction,
            supported_features.clone(),
            profile,
        )?;
        if source.plan().id() != owner.plan
            || source.terminal_result(aos_ability_runtime::journal::JournalLimits::default())?
                != marker
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "settled provider-adoption marker differs from its retained checked journal"
                    .to_string(),
            ));
        }
        resources.insert(owner.resource.clone());
    }

    Ok(resources)
}

/// Returns every resource protected by an unsettled provider-adoption receipt.
///
/// # Errors
///
/// Returns an error when the native ledger is malformed or noncanonical.
pub(crate) fn provider_adoption_receipt_resources(
    profile: &Path,
) -> Result<BTreeSet<ResourceId>, GenerationAbilityStoreError> {
    Ok(
        load_native_resource_ledger(&profile.join(NATIVE_RESOURCE_LEDGER_FILE))?
            .owners
            .into_iter()
            .filter(|owner| owner.adoption.is_some())
            .map(|owner| owner.resource)
            .collect(),
    )
}

fn canonicalize_native_ledger(
    ledger: &mut NativeResourceLedger,
) -> Result<(), GenerationAbilityStoreError> {
    canonicalize_native_owners(&mut ledger.owners)?;
    canonicalize_native_consumers(&mut ledger.consumers)?;
    validate_native_physical_fences(ledger)
}

fn validate_native_physical_fences(
    ledger: &NativeResourceLedger,
) -> Result<(), GenerationAbilityStoreError> {
    for (index, owner) in ledger.owners.iter().enumerate() {
        for other in ledger.owners.iter().skip(index + 1) {
            if owner.physical.conflicts_with(&other.physical) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native provider owners claim conflicting physical resources".to_string(),
                ));
            }
        }

        for consumer in &ledger.consumers {
            if owner.resource == consumer.logical {
                if owner.physical != consumer.physical {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "owned native consumer differs from its provider owner's physical resource"
                            .to_string(),
                    ));
                }
            } else if owner.physical.conflicts_with(&consumer.physical) {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native provider owner and consumer claim conflicting physical resources"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn canonicalize_native_consumers(
    consumers: &mut [ActiveNativeConsumer],
) -> Result<(), GenerationAbilityStoreError> {
    let mut physical_owners = BTreeMap::new();
    let mut logical_subjects = BTreeMap::new();
    let mut unique_path_owners = Vec::new();
    let mut identities = BTreeSet::new();
    for consumer in consumers.iter_mut() {
        consumer.physical.validate()?;
        validate_generation_name(&consumer.generation)?;
        let actor_matches = match &consumer.owner {
            Some(owner) => {
                consumer.consumer == consumer.logical.provider
                    && owner.provider == consumer.logical.provider
            }
            None => consumer.provider == consumer.logical.provider,
        };
        if !actor_matches {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource consumer has inconsistent logical and terminal provider actors"
                    .to_string(),
            ));
        }
        if consumer.owner.as_ref().is_some_and(|owner| {
            owner.provider != consumer.logical.provider
                || owner.state_format.artifact != owner.implementation.artifact
        }) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource consumer has inconsistent provider-owner evidence".to_string(),
            ));
        }
        if consumer.operation.plan != consumer.plan || consumer.attempt == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource consumer has invalid operation evidence".to_string(),
            ));
        }
        consumer.artifacts = canonical_artifacts(&consumer.artifacts)?;

        match logical_subjects.get(&consumer.logical) {
            Some(physical) if physical != &consumer.physical => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native logical resource maps to conflicting physical subjects".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                logical_subjects.insert(consumer.logical.clone(), consumer.physical.clone());
            }
        }

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
mod no_op_tests;
