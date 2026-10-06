//! Live, authenticated operational ownership and bounded durable request history.
//!
//! Guest identity and modeled clocks never enter this registry. Exact daemon,
//! process, mapping, and cap incarnations select existing operational owners.
//! Disk intent precedes mutation; ambiguous application retains authority and
//! cancels execution instead of manufacturing convergence or releasing capacity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, TryLockError, Weak};
use std::time::{Duration, Instant};

use crucible_api::host_operational::*;
use crucible_linux_resource::host_supervision::{
    HostOperationState, HostOperationSupervisor, HostSupervisionError,
};
use crucible_linux_resource::ram_policy::HostResourceTransition;
use crucible_protocol::ram_control::{RamControlError, RamControlReply};
use crucible_qemu::ram_control::{
    RamControlClient, RamControlRegistrar, RamControlRetirementAuthority, RamInventoryAdmission,
};

mod history;
mod mutation;
mod native_resources;
mod node_retirement;
mod resources;

/// Owns terminal cleanup of the original charged executor actor.
///
/// Implementations retain the original counters rather than constructing a
/// replacement actor. This authority is installed when normal actor ownership
/// ends and runs only after all physical registry fields and permits close.
pub(crate) trait RegistryRetirementAuthority: Send + Sync {
    /// Discharges the exact registry service after physical registry cleanup.
    ///
    /// # Errors
    /// Refuses uncertain original actor ownership or incomplete service cleanup.
    fn retire_after_cleanup(&mut self, owner: [u8; 32]) -> Result<(), HostOperationalError>;
}

const MAX_OWNERS: usize = 4096;
const MAX_PRINCIPALS: usize = 64;
const MAX_UNIQUE_UPDATES: u64 = 128;
const REQUESTS_PER_SECOND: u32 = 16;

struct PrincipalRate {
    started: Instant,
    count: u32,
}

struct Owner {
    mutation: Mutex<()>,
    supervisor: HostOperationSupervisor,
    cap: HostOuterCapTarget,
    capabilities: HostRamCapabilities,
    qualification: HostRamQualification,
    state: Mutex<HostRamStatus>,
    client: Mutex<Option<RamControlClient>>,
    pending: Mutex<Option<HostResourceTransition>>,
    retirement: Mutex<Option<Weak<node_retirement::NodeRetirement>>>,
}

struct NativeRamRegistration {
    target: HostRamTarget,
    policy: HostRamPolicy,
    resources: HostResourceVector,
    capabilities: HostRamCapabilities,
    qualification: HostRamQualification,
    supervisor: HostOperationSupervisor,
    client: Option<RamControlClient>,
}

struct CapOwner {
    mutation: Mutex<()>,
    supervisor: HostOperationSupervisor,
    class: HostOuterCapClass,
}

type NativeWorldIdentity = ([u8; 32], [u8; 32]);

struct RegistryState {
    principals: BTreeMap<String, PrincipalRate>,
    nodes: BTreeMap<HostRamTarget, Arc<Owner>>,
    caps: BTreeMap<HostOuterCapTarget, Arc<CapOwner>>,
    retired: BTreeSet<HostRamTarget>,
}

struct Shared {
    retained_catalogs: Mutex<BTreeMap<[u8; 32], Arc<dyn Send + Sync>>>,
    bootstrap: Mutex<Option<crucible_api::vm_lifecycle::HostRamBootstrapLimits>>,
    native_resources: Mutex<BTreeMap<NativeWorldIdentity, native_resources::NativeWorldResources>>,
    state: Mutex<RegistryState>,
    history: Option<Mutex<history::History>>,
    mutation: Mutex<()>,
    qualification_match: Mutex<()>,
    admission: Mutex<Option<Arc<dyn HostResourceAdmission>>>,
    // Physical registry custody is last: history and indexed owners close
    // before their allocator permits and original actor can be discharged.
    resources: Option<resources::RegistryResources>,
}

/// Existing executor actor's reserve-before-apply resource ownership interface.
pub trait HostResourceAdmission: Send + Sync {
    /// Retains the actual current capacity actor during uncertain service cleanup.
    ///
    /// # Errors
    /// Refuses unavailable custody or an incomplete preparation handoff.
    fn capacity_custody(&self) -> Result<Arc<dyn Send + Sync>, HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Reads an exact owner's genuinely reserved immutable resource ceiling.
    ///
    /// # Errors
    /// Refuses an unknown epoch, owner or unsupported admission authority.
    fn owner_ceiling(
        &self,
        _daemon_epoch: [u8; 32],
        _owner: [u8; 32],
    ) -> Result<HostResourceVector, HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Reserves a service while preserving an explicit complete assignment peak.
    ///
    /// # Errors
    /// Refuses unsupported actor custody or a combined peak that cannot fit.
    fn reserve_service_with_assignment_headroom(
        &self,
        _owner: [u8; 32],
        _service: HostResourceVector,
        _assignment: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Reserves a service alongside an existing genuinely charged assignment.
    ///
    /// # Errors
    /// Refuses unsupported custody, an inactive assignment owner, or capacity
    /// that cannot cover the existing allocation and new complete service peak.
    fn reserve_service_with_admitted_assignment(
        &self,
        _owner: [u8; 32],
        _service: HostResourceVector,
        _existing_execution_owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Reports whether a known service has discharged every native node reservation.
    ///
    /// # Errors
    /// Refuses unsupported actor custody or an unknown service identity.
    fn service_nodes_cleaned(&self, _owner: [u8; 32]) -> Result<bool, HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Discharges a service after its watchdog and every native owner were cleaned.
    ///
    /// # Errors
    /// Refuses unsupported proof custody, live node reservations or stale owners.
    fn release_service_after_cleanup(&self, _owner: [u8; 32]) -> Result<(), HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Reclassifies admitted subset entitlements before guest execution.
    ///
    /// # Errors
    /// Refuses changed complete totals, stale initial ownership, or exhaustion.
    fn repartition_node_before_cpu(
        &self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError>;

    /// Discharges a never-published node from final private launch custody.
    ///
    /// # Errors
    /// Refuses stale exact held resources or unsupported terminal proof ownership.
    fn release_unpublished_after_cleanup(
        &self,
        _target: HostRamTarget,
        _resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Names an uncertain unpublished reservation while retaining all charges.
    ///
    /// # Errors
    /// Refuses stale exact ownership or exhausted quarantine records.
    fn quarantine_unpublished(
        &self,
        _target: HostRamTarget,
        _resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        Err(HostOperationalError::Unavailable)
    }

    /// Discharges a node after all native and host borrowers finish cleanup.
    ///
    /// # Errors
    /// Refuses stale physical ownership or uncertain retained accounting.
    fn release_after_cleanup(&self, target: HostRamTarget) -> Result<(), HostOperationalError>;

    /// Binds one explicit complete partition to a current immutable assignment.
    ///
    /// # Errors
    /// Refuses stale ownership, an inconsistent repeat, or a partition exceeding
    /// the assignment's already reserved complete host allocation.
    fn configure_owner(
        &self,
        daemon_epoch: [u8; 32],
        owner: [u8; 32],
        ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError>;

    /// Reserves one exact node inside its already configured assignment partition.
    ///
    /// # Errors
    /// Refuses a stale owner, duplicate inconsistent target, or exhausted capacity.
    fn admit_node(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError>;

    /// Reserves the full old/new physical transition peak before application.
    ///
    /// # Errors
    /// Refuses stale reservations, pending transitions, or insufficient capacity.
    fn begin_transition(
        &self,
        target: HostRamTarget,
        amendment: HostReservationAmendment,
    ) -> Result<HostResourceTransition, HostOperationalError>;

    /// Releases surplus after exact authenticated physical convergence.
    ///
    /// # Errors
    /// Refuses stale tokens or uncertain ownership, retaining the full peak.
    fn finish_transition(
        &self,
        transition: HostResourceTransition,
    ) -> Result<(), HostOperationalError>;
}

/// Cloneable executor authority over registered live watchdogs and RAM managers.
///
/// The initial principal roster is empty. Callers must grant independently
/// authenticated operator certificate identities before installing the handle.
#[derive(Clone)]
pub struct HostOperationalRegistry {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for HostOperationalRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostOperationalRegistry")
            .finish_non_exhaustive()
    }
}

/// Encodes an existing 128-bit operational identity without changing its identity.
#[must_use]
pub fn operational_identity(bytes: [u8; 16]) -> [u8; 32] {
    let mut encoded = [0; 32];
    encoded[16..].copy_from_slice(&bytes);
    encoded
}

impl Default for HostOperationalRegistry {
    fn default() -> Self {
        Self::from_history(None)
    }
}

impl HostOperationalRegistry {
    /// Publishes behavior only after the scoped immutable receipt proves this incarnation.
    pub(crate) fn register_with_qualification(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        mut client: Option<RamControlClient>,
        qualification: HostRamQualification,
    ) -> Result<(), RamControlError> {
        let observation = client
            .as_mut()
            .ok_or(RamControlError::AuthorityMismatch)?
            .status()?;
        let logical = observation.logical_ram_bytes;
        if logical == 0 {
            return Err(RamControlError::AuthorityMismatch);
        }
        let services = self
            .bootstrap_limits()
            .ok_or(RamControlError::AuthorityMismatch)?
            .host_service_resident_bytes();
        let floor = resources
            .metadata_bytes
            .checked_add(resources.staging_bytes)
            .and_then(|bytes| bytes.checked_add(services))
            .ok_or(RamControlError::InvalidFrame)?;
        let qualified_placement = qualification.backend == HostRamBackend::PausedPager
            && qualification.authenticated_pages
            && qualification.evidence.is_some();
        let capabilities = HostRamCapabilities {
            logical_ram_bytes: logical,
            compulsory_resident_bytes: floor,
            minimum_execution_peak_bytes: logical,
            maximum_paging_io_slots: 1,
            dynamic_residency: qualified_placement,
            disk_oriented: false,
            resident_required: false,
        };
        self.register_node(NativeRamRegistration {
            target,
            policy,
            resources,
            capabilities,
            qualification,
            supervisor,
            client,
        })
        .map_err(|_| RamControlError::AuthorityMismatch)
    }
}

impl HostOperationalRegistry {
    /// Opens durable history for isolated controller component tests.
    ///
    /// # Errors
    /// This fixture exercises journal behavior without claiming production
    /// resource admission. Managed launches use the admitted constructor.
    #[cfg(test)]
    fn open_component(
        path: &Path,
        maximum_history_bytes: u64,
    ) -> Result<Self, HostOperationalError> {
        if maximum_history_bytes < history::FIXED_HISTORY_CHARGE {
            return Err(HostOperationalError::Unavailable);
        }
        Ok(Self::from_history(Some(history::History::open(
            path,
            maximum_history_bytes,
        )?)))
    }

    fn from_history(history: Option<history::History>) -> Self {
        Self::from_history_and_resources(history, None)
    }

    fn from_history_and_resources(
        history: Option<history::History>,
        resources: Option<resources::RegistryResources>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                retained_catalogs: Mutex::new(BTreeMap::new()),
                bootstrap: Mutex::new(None),
                native_resources: Mutex::new(BTreeMap::new()),
                state: Mutex::new(RegistryState {
                    principals: BTreeMap::new(),
                    nodes: BTreeMap::new(),
                    caps: BTreeMap::new(),
                    retired: BTreeSet::new(),
                }),
                history: history.map(Mutex::new),
                mutation: Mutex::new(()),
                qualification_match: Mutex::new(()),
                admission: Mutex::new(None),
                resources,
            }),
        }
    }

    /// Serializes receipt matching within the admitted registry service peak.
    ///
    /// The baseline reserves the hash buffers and descriptor peak before this
    /// method can run. Waiting and matching retain the caller's original
    /// operation boundary; contention never starts a new deadline.
    ///
    /// # Errors
    /// Refuses an unadmitted registry, poisoned synchronization, or an expired
    /// original boundary, and preserves errors returned by the matching work.
    pub(crate) fn with_paging_qualification_match<T>(
        &self,
        boundary: &mut dyn FnMut() -> std::io::Result<()>,
        operation: impl FnOnce(&mut dyn FnMut() -> std::io::Result<()>) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        if self.shared.resources.is_none() {
            return Err(std::io::Error::other(
                "paging qualification requires registry admission",
            ));
        }
        let _matching = loop {
            boundary()?;
            match self.shared.qualification_match.try_lock() {
                Ok(matching) => break matching,
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(std::io::Error::other(
                        "paging qualification ownership is unavailable",
                    ));
                }
            }
        };
        boundary()?;
        operation(boundary)
    }

    /// Returns the explicitly configured complete node bootstrap entitlement.
    pub(crate) fn bootstrap_limits(
        &self,
    ) -> Option<crucible_api::vm_lifecycle::HostRamBootstrapLimits> {
        *self.shared.bootstrap.lock().ok()?
    }

    /// Installs the complete native and host-service bootstrap ceilings.
    ///
    /// # Errors
    /// Refuses replacement or installation after any owner becomes visible.
    pub(crate) fn configure_bootstrap_limits(
        &self,
        limits: crucible_api::vm_lifecycle::HostRamBootstrapLimits,
    ) -> Result<(), HostOperationalError> {
        let _mutation = self.shared.mutation.lock().map_err(unavailable)?;
        let state = self.shared.state.lock().map_err(unavailable)?;
        if !state.nodes.is_empty() || !state.caps.is_empty() {
            return Err(HostOperationalError::Unavailable);
        }
        let mut bootstrap = self.shared.bootstrap.lock().map_err(unavailable)?;
        if bootstrap.is_some() {
            return Err(HostOperationalError::Unavailable);
        }
        *bootstrap = Some(limits);
        Ok(())
    }

    /// Installs the same actor admission authority used by campaign assignments.
    ///
    /// # Errors
    /// Refuses replacing an existing authority or uncertain lock ownership.
    pub fn attach_admission(
        &self,
        admission: Arc<dyn HostResourceAdmission>,
    ) -> Result<(), HostOperationalError> {
        let mut slot = self.shared.admission.lock().map_err(unavailable)?;
        if slot.is_some() {
            return Err(HostOperationalError::Unavailable);
        }
        *slot = Some(admission);
        Ok(())
    }

    fn admission(&self) -> Result<Arc<dyn HostResourceAdmission>, HostOperationalError> {
        self.shared
            .admission
            .lock()
            .map_err(unavailable)?
            .clone()
            .ok_or(HostOperationalError::Unavailable)
    }

    /// Retains actual preparation or worker-pool ownership for service quarantine.
    ///
    /// # Errors
    /// Refuses unavailable custody or an incomplete preparation handoff.
    pub(crate) fn capacity_custody(&self) -> Result<Arc<dyn Send + Sync>, HostOperationalError> {
        self.admission()?.capacity_custody()
    }

    /// Keeps durable catalog ownership charged independently of live readers.
    ///
    /// The enclosing quota namespace remains persisted across assignment and
    /// provider drops. Only authenticated complete namespace deletion can
    /// discharge that service; shutdown does not imply deletion.
    ///
    /// # Errors
    /// Refuses reused service identities, exhausted bounded custody, or poisoned
    /// ownership. It never evicts an existing durable service to admit another.
    pub(crate) fn retain_catalog_service(
        &self,
        owner: [u8; 32],
        custody: Arc<dyn Send + Sync>,
    ) -> Result<(), HostOperationalError> {
        let mut retained = self.shared.retained_catalogs.lock().map_err(unavailable)?;
        if retained.contains_key(&owner) || retained.len() >= MAX_OWNERS {
            return Err(HostOperationalError::Unavailable);
        }
        retained.insert(owner, custody);
        Ok(())
    }

    /// Reads the actual immutable entitlement of one admitted execution or service.
    ///
    /// # Errors
    /// Refuses unknown ownership, epoch mismatch or unavailable actor custody.
    pub(crate) fn owner_ceiling(
        &self,
        daemon_epoch: [u8; 32],
        owner: [u8; 32],
    ) -> Result<HostResourceVector, HostOperationalError> {
        self.admission()?.owner_ceiling(daemon_epoch, owner)
    }

    /// Reserves a template service while preserving actual assignment headroom.
    ///
    /// # Errors
    /// Refuses unavailable actor custody or any combined physical capacity limit.
    pub(crate) fn reserve_service_with_assignment_headroom(
        &self,
        owner: [u8; 32],
        service: HostResourceVector,
        assignment: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.admission()?
            .reserve_service_with_assignment_headroom(owner, service, assignment)
    }

    /// Reserves a fresh source service beside an already admitted assignment.
    ///
    /// # Errors
    /// Refuses unavailable custody, an unknown or inactive execution owner,
    /// stale authored resources, or any combined physical capacity limit.
    pub(crate) fn reserve_service_with_admitted_assignment(
        &self,
        owner: [u8; 32],
        service: HostResourceVector,
        existing_execution_owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        self.admission()?.reserve_service_with_admitted_assignment(
            owner,
            service,
            existing_execution_owner,
        )
    }

    /// Reads actual native cleanup before stopping a retained service watchdog.
    ///
    /// # Errors
    /// Refuses unavailable actor custody or an unknown service identity.
    pub(crate) fn service_nodes_cleaned(
        &self,
        owner: [u8; 32],
    ) -> Result<bool, HostOperationalError> {
        self.admission()?.service_nodes_cleaned(owner)
    }

    /// Discharges a physically cleaned service while retaining durable history.
    ///
    /// # Errors
    /// Refuses live or ambiguous ownership; shutdown never fabricates cleanup.
    pub(crate) fn release_service_after_cleanup(
        &self,
        owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        self.admission()?.release_service_after_cleanup(owner)
    }

    /// Configures an explicit complete host allocation inside a live assignment.
    ///
    /// # Errors
    /// Returns actual executor admission or stale-owner refusal.
    pub fn configure_owner(
        &self,
        daemon_epoch: [u8; 32],
        owner_id: [u8; 32],
        ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.admission()?
            .configure_owner(daemon_epoch, owner_id, ceiling)
    }

    /// Reserves one exact launch owner through the existing executor actor.
    ///
    /// # Errors
    /// Returns actual aggregate-capacity, stale-owner, or duplicate-owner refusal.
    pub fn admit_node(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.admission()?.admit_node(target, resources)
    }

    /// Reclassifies initial resource subsets using authenticated native inventory.
    ///
    /// The startup registrar invokes this before publishing a node or releasing
    /// guest execution. Complete entitlements and operational clocks stay fixed.
    ///
    /// # Errors
    /// Refuses a published or retired arena, changed complete totals, stale
    /// initial ownership, or insufficient admitted subset capacity.
    pub fn repartition_node_before_cpu(
        &self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        let state = self.shared.state.lock().map_err(unavailable)?;
        if state.nodes.contains_key(&target) || state.retired.contains(&target) {
            return Err(HostOperationalError::Unavailable);
        }
        drop(state);
        self.admission()?
            .repartition_node_before_cpu(target, expected_initial, resources)
    }

    /// Lists a bounded page of current RAM arenas for one exact execution owner.
    ///
    /// The caller authenticates the transport principal before invoking this
    /// method. Enumeration excludes retired arenas and never takes a guest or
    /// lifecycle lock. Continuation is an exclusive cursor, not a frozen view;
    /// a returned target must still be validated at command execution.
    ///
    /// # Errors
    /// Refuses a limit outside 1 through 32, a cursor for another owner, or
    /// uncertain operational registry ownership.
    pub fn registered_targets(
        &self,
        daemon_epoch: [u8; 32],
        owner_id: [u8; 32],
        after: Option<HostRamTarget>,
        limit: u8,
    ) -> Result<(Vec<HostRamTarget>, Option<HostRamTarget>), HostOperationalError> {
        if !(1..=32).contains(&limit)
            || after.is_some_and(|target| {
                target.daemon_epoch != daemon_epoch || target.owner_id != owner_id
            })
        {
            return Err(HostOperationalError::Unavailable);
        }
        let state = self.shared.state.lock().map_err(unavailable)?;
        let mut matching = state.nodes.keys().copied().filter(|target| {
            target.daemon_epoch == daemon_epoch
                && target.owner_id == owner_id
                && !state.retired.contains(target)
                && after.is_none_or(|cursor| *target > cursor)
        });
        let targets: Vec<_> = matching.by_ref().take(usize::from(limit)).collect();
        let continuation = matching.next().and_then(|_| targets.last().copied());
        Ok((targets, continuation))
    }

    /// Grants one transport-derived certificate principal operational authority.
    ///
    /// # Errors
    /// Rejects malformed certificate fingerprints, a full bounded roster, or
    /// uncertain registry ownership. Existing grants are idempotent.
    pub fn grant_principal(&self, principal: &str) -> Result<(), HostOperationalError> {
        if principal.len() != 64
            || !principal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HostOperationalError::PrincipalDenied);
        }
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        if state.principals.contains_key(principal) {
            return Ok(());
        }
        if state.principals.len() >= MAX_PRINCIPALS {
            return Err(HostOperationalError::Unavailable);
        }
        state.principals.insert(
            principal.to_owned(),
            PrincipalRate {
                started: operational_now(),
                count: 0,
            },
        );
        Ok(())
    }

    /// Registers an existing independently named original-start supervisor cap.
    ///
    /// # Errors
    /// Refuses stale or zero generations, mismatched cap identity, duplicate
    /// ownership, and bounded registry exhaustion.
    pub fn register_cap(
        &self,
        target: HostOuterCapTarget,
        class: HostOuterCapClass,
        supervisor: HostOperationSupervisor,
    ) -> Result<(), HostOperationalError> {
        if target.owner_generation == 0 || target.cap_id != supervisor.cap_id() {
            return Err(HostOperationalError::Unavailable);
        }
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        if let Some(existing) = state.caps.get(&target) {
            return if existing.supervisor.shares_outer_cap(&supervisor) && existing.class == class {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        if state.caps.len() >= MAX_OWNERS {
            return Err(HostOperationalError::Unavailable);
        }
        state.caps.insert(
            target,
            Arc::new(CapOwner {
                supervisor,
                class,
                mutation: Mutex::new(()),
            }),
        );
        Ok(())
    }

    /// Registers an admitted node with independently established qualification.
    ///
    /// Qualification must come from deployment evidence, never socket presence
    /// or an operator boolean. Full RAM is the minimum execution peak whenever
    /// fault-safe reclamation has not been independently qualified.
    ///
    /// # Errors
    /// Refuses reused targets, invalid policy/admission, mismatched live handles,
    /// unqualified capability claims, and unavailable controller authority.
    fn register_node(
        &self,
        registration: NativeRamRegistration,
    ) -> Result<(), HostOperationalError> {
        let NativeRamRegistration {
            target,
            policy,
            resources,
            capabilities,
            qualification,
            supervisor,
            mut client,
        } = registration;
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        if target.owner_generation == 0
            || target.arena_generation == 0
            || client
                .as_ref()
                .is_some_and(|value| value.target() != target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.admit_node(target, resources)?;
        // The public canonical codec validates the closed qualification matrix.
        codec::encode_response(&HostOperationalResponse::Capabilities {
            target,
            capabilities,
            qualification,
        })?;
        let finite_outer = supervisor
            .outer_cap_status()
            .map_err(unavailable)?
            .allowance
            .is_some();
        policy
            .validate_update(policy, capabilities, resources, finite_outer)
            .map_err(unavailable)?;
        let (_, budgets) = supervisor.budgets().map_err(unavailable)?;
        if budgets != policy.latency {
            return Err(HostOperationalError::Unavailable);
        }
        // RAM process generations select an already admitted assignment or
        // service cap. A node cannot manufacture a second outer authority.
        let cap = {
            let state = self.shared.state.lock().map_err(unavailable)?;
            let mut matching = state.caps.iter().filter(|(cap, owner)| {
                let owner_id = match cap.owner {
                    HostOuterCapOwner::Execution(id) | HostOuterCapOwner::Service(id) => id,
                };
                cap.daemon_epoch == target.daemon_epoch
                    && owner_id == target.owner_id
                    && cap.cap_id == supervisor.cap_id()
                    && owner.supervisor.shares_outer_cap(&supervisor)
            });
            let cap = *matching.next().ok_or(HostOperationalError::Unavailable)?.0;
            if matching.next().is_some() {
                return Err(HostOperationalError::Unavailable);
            }
            cap
        };
        let cap_owner = self
            .shared
            .state
            .lock()
            .map_err(unavailable)?
            .caps
            .get(&cap)
            .cloned()
            .ok_or(HostOperationalError::Unavailable)?;
        // Registration and amendment serialize on the same original authority.
        // The native startup binding may have been sampled before an amendment;
        // synchronize it before publication so no new owner misses the fanout.
        let _cap_transaction = cap_owner.mutation.try_lock().map_err(unavailable)?;
        if let Some(client) = client.as_mut() {
            let binding = supervisor.outer_cap_binding().map_err(unavailable)?;
            let reply = client.sync_outer_cap(binding).map_err(unavailable)?;
            if reply.disposition != crucible_protocol::ram_control::RamControlDisposition::Accepted
            {
                return Err(HostOperationalError::Unavailable);
            }
        }
        let mut status = HostRamStatus {
            target,
            observation_sequence: 1,
            policy_revision: 0,
            reservation_revision: 0,
            requested_policy: policy,
            applied_policy: policy,
            effective_resident_target_bytes: policy.resident_target_bytes,
            effective_floor_bytes: capabilities.compulsory_resident_bytes,
            limitation_reasons: Vec::new(),
            measurements_available: false,
            activity: None,
            private_resident_bytes: 0,
            shared_resident_bytes_observed: 0,
            preserved_backing_bytes: 0,
            private_dirty_bytes: 0,
            writeback_pending_bytes: 0,
            convergence: HostRamConvergence::Stable,
            accepted_unique_update_count: 0,
            remaining_unique_update_capacity: MAX_UNIQUE_UPDATES,
            history_disk_bytes: 0,
            transition: None,
            admitted_resources: resources,
            outer_caps: Vec::new(),
            outstanding_operations: Vec::new(),
        };
        if let Some(client) = client.as_mut() {
            let setup = supervisor
                .begin(crucible_linux_resource::host_supervision::HostOperationClass::Setup)
                .map_err(unavailable)?;
            let mut reply = client
                .apply(0, 1, 0, policy, resources)
                .map_err(unavailable)?;
            if reply.disposition != crucible_protocol::ram_control::RamControlDisposition::Accepted
                || reply.requested_policy_revision != 1
            {
                supervisor.cancel().map_err(unavailable)?;
                return Err(HostOperationalError::Unavailable);
            }
            while reply.applied_policy_revision != 1 {
                setup.wait_for_change().map_err(unavailable)?;
                reply = client.status().map_err(unavailable)?;
                if reply.requested_policy_revision != 1 || reply.applied_policy_revision > 1 {
                    return Err(HostOperationalError::Unavailable);
                }
            }
            status.policy_revision = 1;
            mutation::observe_reply(&mut status, reply, policy, 1)?;
            setup.complete().map_err(unavailable)?;
        }
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        if state.nodes.len() + state.retired.len() >= MAX_OWNERS
            || state.nodes.contains_key(&target)
            || state.retired.contains(&target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        state.nodes.insert(
            target,
            Arc::new(Owner {
                mutation: Mutex::new(()),
                supervisor,
                cap,
                capabilities,
                qualification,
                state: Mutex::new(status),
                client: Mutex::new(client),
                pending: Mutex::new(None),
                retirement: Mutex::new(None),
            }),
        );
        Ok(())
    }

    /// Retires node lookup while retaining history and containment authority.
    ///
    /// This method does not release resources or assert that native processes,
    /// descriptor borrowers, or retained templates have completed cleanup.
    ///
    /// # Errors
    /// Returns an error if exact ownership is unavailable.
    pub fn retire_node(&self, target: HostRamTarget) -> Result<(), HostOperationalError> {
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        let owner = state
            .nodes
            .get(&target)
            .cloned()
            .ok_or(HostOperationalError::Unavailable)?;
        owner.supervisor.cancel().map_err(unavailable)?;
        state.retired.insert(target);
        Ok(())
    }

    /// Discharges an exact node after successful process and borrower cleanup.
    ///
    /// History remains retained. The same target cannot be readmitted, and this
    /// method does not cancel the execution cap or another node's budget owner.
    ///
    /// # Errors
    /// Refuses an in-flight mutation, active controller borrower, stale target,
    /// or uncertain release. Refusal retains the complete reservation.
    pub fn retire_node_after_cleanup(
        &self,
        target: HostRamTarget,
    ) -> Result<(), HostOperationalError> {
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        let owner = self
            .shared
            .state
            .lock()
            .map_err(unavailable)?
            .nodes
            .get(&target)
            .cloned()
            .ok_or(HostOperationalError::Unavailable)?;
        let _owner_transaction = owner.mutation.try_lock().map_err(unavailable)?;
        let mut client = owner.client.try_lock().map_err(unavailable)?;
        *client = None;
        self.finish_native_node_cleanup(target, || {
            self.admission()?.release_after_cleanup(target)
        })?;
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        // Last retained-owner cleanup can retire the complete execution
        // registry under the actor. Exact ownership was resolved before
        // release, so an already removed entry confirms that retirement.
        state.nodes.remove(&target);
        if state.caps.contains_key(&owner.cap) {
            state.retired.insert(target);
        }
        Ok(())
    }

    pub(crate) fn retire_execution(
        &self,
        daemon: [u8; 32],
        owner_id: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        let targets: Vec<_> = state
            .nodes
            .keys()
            .copied()
            .filter(|target| target.daemon_epoch == daemon && target.owner_id == owner_id)
            .collect();
        for target in targets {
            if let Some(owner) = state.nodes.remove(&target) {
                owner.supervisor.cancel().map_err(unavailable)?;
            }
        }
        state
            .retired
            .retain(|target| target.daemon_epoch != daemon || target.owner_id != owner_id);
        state.caps.retain(|target, _| {
            target.daemon_epoch != daemon || target.owner != HostOuterCapOwner::Execution(owner_id)
        });
        // Durable key history remains on disk. The executor has ended this
        // never-reused execution, so no future live actor can select its targets.
        Ok(())
    }

    fn node(&self, target: HostRamTarget) -> Result<Arc<Owner>, HostOperationalError> {
        let state = self.shared.state.lock().map_err(unavailable)?;
        if state.retired.contains(&target) {
            return Err(HostOperationalError::Unavailable);
        }
        state
            .nodes
            .get(&target)
            .cloned()
            .ok_or(HostOperationalError::Unavailable)
    }

    /// Retires a service namespace after the actor proves complete cleanup.
    ///
    /// # Errors
    /// Refuses live node lookup or poisoned ownership rather than canceling a
    /// retained template whose physical reservation has not been discharged.
    pub(crate) fn retire_service(
        &self,
        daemon: [u8; 32],
        owner_id: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        let caps: Vec<_> = self
            .shared
            .state
            .lock()
            .map_err(unavailable)?
            .caps
            .iter()
            .filter(|(target, _)| {
                target.daemon_epoch == daemon
                    && target.owner == HostOuterCapOwner::Service(owner_id)
            })
            .map(|(target, cap)| (*target, Arc::clone(cap)))
            .collect();
        // An accepted amendment must finish before this alias can disappear.
        // Try-lock keeps retirement from waiting behind a live transport while
        // holding the actor; refusal retains the complete Service charge.
        let mut mutations = Vec::with_capacity(caps.len());
        for (_, cap) in &caps {
            mutations.push(cap.mutation.try_lock().map_err(unavailable)?);
        }
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        if state
            .nodes
            .keys()
            .any(|target| target.daemon_epoch == daemon && target.owner_id == owner_id)
        {
            return Err(HostOperationalError::Unavailable);
        }
        let mut registered = state.caps.iter().filter(|(target, _)| {
            target.daemon_epoch == daemon && target.owner == HostOuterCapOwner::Service(owner_id)
        });
        if registered.clone().count() != caps.len()
            || !registered.all(|(target, cap)| {
                caps.iter()
                    .any(|(original, authority)| original == target && Arc::ptr_eq(authority, cap))
            })
        {
            return Err(HostOperationalError::Unavailable);
        }
        state
            .retired
            .retain(|target| target.daemon_epoch != daemon || target.owner_id != owner_id);
        state.caps.retain(|target, _| {
            target.daemon_epoch != daemon || target.owner != HostOuterCapOwner::Service(owner_id)
        });
        Ok(())
    }

    fn status(&self, owner: &Owner) -> Result<HostRamStatus, HostOperationalError> {
        // Status remains responsive during socket application: it reports the
        // last authenticated physical observation, never a guessed RSS value.
        if let Ok(mut client) = owner.client.try_lock()
            && let Some(client) = client.as_mut()
        {
            match client.status() {
                Ok(reply) => self.observe_owner(owner, reply)?,
                // Admission refusal occurs before the first transport byte.
                // A concurrent control operation may consume the reserved
                // slots; retain the last authenticated observation without
                // turning this harmless query into guest cancellation.
                Err(RamControlError::Io(error))
                    if error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<HostSupervisionError>())
                        == Some(&HostSupervisionError::CapacityExhausted) => {}
                Err(_) => {
                    owner.supervisor.cancel().map_err(unavailable)?;
                    owner.state.lock().map_err(unavailable)?.convergence =
                        HostRamConvergence::Quarantined;
                }
            }
        }
        let mut status = owner.state.lock().map_err(unavailable)?.clone();
        let (cap_status, operations) = owner.supervisor.status_snapshot().map_err(unavailable)?;
        status.outstanding_operations = operations;
        let state = self.shared.state.lock().map_err(unavailable)?;
        let cap = state
            .caps
            .get(&owner.cap)
            .ok_or(HostOperationalError::Unavailable)?;
        status.outer_caps = vec![HostOuterCapObservation {
            target: owner.cap,
            class: cap.class,
            status: cap_status,
        }];
        Ok(status)
    }

    fn observe_owner(
        &self,
        owner: &Owner,
        reply: RamControlReply,
    ) -> Result<(), HostOperationalError> {
        let mut status = owner.state.lock().map_err(unavailable)?;
        if reply.requested_policy_revision != status.policy_revision
            || reply.reservation_revision != status.reservation_revision
        {
            return Err(HostOperationalError::Unavailable);
        }
        let policy = status.requested_policy;
        let revision = status.policy_revision;
        mutation::observe_reply(&mut status, reply, policy, revision)?;
        let mut pending = owner.pending.lock().map_err(unavailable)?;
        if let Some(transition) = *pending {
            let measured_peak = reply
                .private_resident_bytes
                .checked_add(reply.effective_floor_bytes)
                .ok_or(HostOperationalError::Unavailable)?;
            if reply.applied_policy_revision == revision
                && status.convergence == HostRamConvergence::Stable
                && reply.measurements_available
                && measured_peak <= transition.requested.resident_peak_bytes
                && reply.preserved_backing_bytes <= transition.requested.backing_peak_bytes
            {
                self.admission()?.finish_transition(transition)?;
                status.admitted_resources = transition.requested;
                status.transition = None;
                *pending = None;
            }
        }
        status.observation_sequence = status
            .observation_sequence
            .checked_add(1)
            .ok_or(HostOperationalError::Unavailable)?;
        Ok(())
    }
}

impl HostOperationalControl for HostOperationalRegistry {
    fn execute(
        &self,
        principal: &str,
        request: HostOperationalRequest,
    ) -> Result<HostOperationalResponse, HostOperationalError> {
        let digest = host_operational_request_digest(principal, &request)?;
        {
            let mut state = self.shared.state.lock().map_err(unavailable)?;
            let rate = state
                .principals
                .get_mut(principal)
                .ok_or(HostOperationalError::PrincipalDenied)?;
            if request.is_mutating() {
                let now = operational_now();
                if now.duration_since(rate.started) >= Duration::from_secs(1) {
                    rate.started = now;
                    rate.count = 0;
                }
                if rate.count >= REQUESTS_PER_SECOND {
                    return Ok(mutation::refused(
                        &request,
                        digest,
                        HostOperationalDisposition::RateLimited,
                    ));
                }
                rate.count += 1;
            }
        }
        match &request {
            HostOperationalRequest::ListTargets {
                target,
                after,
                limit,
            } => {
                let (targets, next) =
                    self.registered_targets(target.daemon_epoch, target.owner_id, *after, *limit)?;
                Ok(HostOperationalResponse::Targets {
                    target: *target,
                    targets,
                    next,
                })
            }
            HostOperationalRequest::Capabilities { target } => {
                let owner = self.node(*target)?;
                Ok(HostOperationalResponse::Capabilities {
                    target: *target,
                    capabilities: owner.capabilities,
                    qualification: owner.qualification,
                })
            }
            HostOperationalRequest::Status { target } => {
                let owner = self.node(*target)?;
                Ok(HostOperationalResponse::Status(Box::new(
                    self.status(&owner)?,
                )))
            }
            _ => self.mutate(request, digest),
        }
    }
}

impl RamControlRegistrar for HostOperationalRegistry {
    fn admit_inventory(
        &self,
        admission: RamInventoryAdmission<'_>,
    ) -> Result<HostResourceVector, RamControlError> {
        let RamInventoryAdmission {
            target,
            expected_initial,
            declared_ram_bytes,
            topology,
            native_metadata_bytes,
            native_scratch_bytes,
            owner_resources,
        } = admission;
        if declared_ram_bytes == 0
            || declared_ram_bytes % (1024 * 1024) != 0
            || topology.total_logical_bytes() < declared_ram_bytes
        {
            return Err(RamControlError::InvalidFrame);
        }
        if owner_resources.existing_tasks == 0
            || owner_resources.existing_file_descriptors == 0
            || owner_resources.registered_service_tasks > owner_resources.existing_tasks
        {
            return Err(RamControlError::InvalidFrame);
        }
        let tasks = owner_resources
            .existing_tasks
            .checked_add(owner_resources.prospective_tasks)
            .ok_or(RamControlError::InvalidFrame)?;
        let descriptors = owner_resources
            .existing_file_descriptors
            .checked_add(owner_resources.prospective_file_descriptors)
            .ok_or(RamControlError::InvalidFrame)?;
        let bootstrap = self
            .bootstrap_limits()
            .ok_or(RamControlError::AuthorityMismatch)?;
        if expected_initial.task_slots != bootstrap.task_slots()
            || expected_initial.file_descriptors != bootstrap.file_descriptors()
            || tasks > bootstrap.native_task_slots()
            || descriptors > bootstrap.native_file_descriptors()
        {
            return Err(RamControlError::AuthorityMismatch);
        }
        let operations = u32::try_from(expected_initial.paging_io_slots)
            .map_err(|_| RamControlError::InvalidFrame)?;
        let required = crucible_qemu::ram_admission::actual_inventory_ram_requirements(
            topology,
            native_metadata_bytes,
            native_scratch_bytes,
            operations,
        )
        .map_err(|_| RamControlError::InvalidFrame)?;
        let resources = HostResourceVector {
            metadata_bytes: expected_initial.metadata_bytes.max(required.metadata_bytes),
            staging_bytes: expected_initial.staging_bytes.max(required.staging_bytes),
            ..expected_initial
        };

        // Inventory consumes named process/device and overlay entitlement;
        // complete retained peaks and original-start supervision never grow.
        let alignment_reserve = u64::try_from(topology.regions().len())
            .ok()
            .and_then(|regions| regions.checked_mul(2 * 4096))
            .ok_or(RamControlError::InvalidFrame)?;
        let resident = topology
            .total_logical_bytes()
            .checked_add(resources.metadata_bytes)
            .and_then(|bytes| bytes.checked_add(resources.staging_bytes))
            .and_then(|bytes| bytes.checked_add(bootstrap.host_service_resident_bytes()))
            .and_then(|bytes| bytes.checked_add(alignment_reserve))
            .ok_or(RamControlError::InvalidFrame)?;
        let memory_mib = u32::try_from(declared_ram_bytes / (1024 * 1024))
            .map_err(|_| RamControlError::InvalidFrame)?;
        let vmstate =
            crucible_qemu::QemuLaunchResourceRequirements::from_vm_shape(memory_mib, 1, true);
        let backing = crucible_api::host_operational::HostRamBackingPartition::required(
            topology,
            crucible_qemu::ram_admission::private_spill_quota_bytes(topology)
                .map_err(|_| RamControlError::InvalidFrame)?,
            resources.staging_bytes,
            vmstate.minimum_writable_bytes(),
        )
        .and_then(|backing| backing.within_peak(resources.backing_peak_bytes))
        .map_err(|_| RamControlError::AuthorityMismatch)?;
        if resident > resources.resident_peak_bytes {
            return Err(RamControlError::AuthorityMismatch);
        }
        let outside_resident = resources
            .paging_io_slots
            .checked_mul(crucible_qemu::ram_admission::RAM_CAS_OPERATION_SCRATCH_BYTES)
            .and_then(|bytes| bytes.checked_add(bootstrap.host_service_resident_bytes()))
            .ok_or(RamControlError::InvalidFrame)?;
        let outside_backing = backing.staging_bytes;
        self.tighten_native_resources(target, outside_resident, outside_backing)
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        self.repartition_node_before_cpu(target, expected_initial, resources)
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        Ok(resources)
    }

    fn retire_unpublished_after_cleanup(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        let _transaction = self
            .shared
            .mutation
            .try_lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        {
            let state = self
                .shared
                .state
                .lock()
                .map_err(|_| RamControlError::AuthorityMismatch)?;
            if state.nodes.contains_key(&target) || state.retired.contains(&target) {
                return Err(RamControlError::AuthorityMismatch);
            }
        }
        self.finish_native_node_cleanup(target, || {
            self.admission()?
                .release_unpublished_after_cleanup(target, resources)
        })
        .map_err(|_| RamControlError::AuthorityMismatch)
    }

    fn quarantine_unpublished(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        let _transaction = self
            .shared
            .mutation
            .try_lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        {
            let state = self
                .shared
                .state
                .lock()
                .map_err(|_| RamControlError::AuthorityMismatch)?;
            if state.nodes.contains_key(&target) || state.retired.contains(&target) {
                return Err(RamControlError::AuthorityMismatch);
            }
        }
        self.admission()
            .and_then(|admission| admission.quarantine_unpublished(target, resources))
            .map_err(|_| RamControlError::AuthorityMismatch)
    }

    fn retire_after_cleanup(&self, target: HostRamTarget) -> Result<(), RamControlError> {
        self.retire_node_after_cleanup(target)
            .map_err(|_| RamControlError::AuthorityMismatch)
    }

    fn retirement_authority(
        &self,
        target: HostRamTarget,
    ) -> Result<Arc<dyn RamControlRetirementAuthority>, RamControlError> {
        self.node_retirement_authority(target)
            .map(|authority| authority as Arc<dyn RamControlRetirementAuthority>)
            .map_err(|_| RamControlError::AuthorityMismatch)
    }

    fn prepare_retirement_after_cleanup(
        &self,
        target: HostRamTarget,
    ) -> Result<(), RamControlError> {
        let _transaction = self
            .shared
            .mutation
            .try_lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let owner = self
            .shared
            .state
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?
            .nodes
            .get(&target)
            .cloned()
            .ok_or(RamControlError::AuthorityMismatch)?;
        let _owner_transaction = owner
            .mutation
            .try_lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let mut client = owner
            .client
            .try_lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let retirement = owner
            .retirement
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?
            .as_ref()
            .and_then(Weak::upgrade);
        // Resolve and retain the original actor before changing registry
        // ownership. A failed arm leaves the existing Owner/client intact.
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if let Some(retirement) = &retirement {
            retirement.arm(
                self.admission()
                    .map_err(|_| RamControlError::AuthorityMismatch)?,
            )?;
        }
        state.retired.insert(target);
        // Closing this registry borrower allows the private final-close record
        // to run after the node's remaining descriptors and service leases.
        // The actor reservation remains intact until that record supplies proof.
        if retirement.is_some() {
            state.nodes.remove(&target);
        }
        drop(state);
        *client = None;
        Ok(())
    }

    fn register(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        client: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        self.register_with_qualification(
            target,
            policy,
            resources,
            supervisor,
            client,
            HostRamQualification::default(),
        )
    }
}

fn unavailable<T>(_source: T) -> HostOperationalError {
    HostOperationalError::Unavailable
}

// crucible-lint: allow clippy-disallowed-method -- rate admission uses private monotonic time and never changes modeled identity.
#[allow(
    clippy::disallowed_methods,
    reason = "operational rate admission uses host monotonic time only"
)]
fn operational_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod qualification;
#[cfg(test)]
mod tests;
