//! Connects the actual protected Network startup under its same fixed F.

use super::*;
use std::path::Path;

const CONFIGURATION: &str = "/run/credentials/aos-netd.service";
// This is the installed daemon's existing protected policy floor.
const MINIMUM_POLICY_GENERATION: u64 = 1;

impl NetworkServiceOriginalV4 {
    pub(super) fn capture_startup_v4(&mut self, maximum_entries: usize) -> Result<()> {
        self.geometry = Some((|| {
            let policy = ProtectedNetworkPolicyOriginalV4::native_receiving_demand_v4()
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            ProtectedBrokerAuthorityConfiguration::receiving_demand_v1()?.checked_add(policy)
        })());
        let fixed = match self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(fixed) => fixed,
            None => { self.first = Some(First::Geometry); return Err(NetworkServiceClosedV4); }
        };
        self.funding[0] = Some(self.common.require_startup_representation_v4(fixed));
        if !matches!(self.funding[0], Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(NetworkServiceClosedV4);
        }
        self.body = Some(self.capture_paid_startup_v4(maximum_entries));
        let body = if matches!(self.body, Some(Ok(()))) { Ok(()) } else { Err(Closed) };
        // This remains independent after a failed native before or any body
        // error. No healthy/debit gate can suppress this prearmed destination.
        self.after = Some(self.common.finish_startup_native_once_v4(body));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        if self.first.is_some() { return Err(NetworkServiceClosedV4); }
        self.take_completed_startup_v4()
    }

    fn capture_paid_startup_v4(&mut self, maximum_entries: usize) -> Result<()> {
        self.native_before = Some(self.common.begin_startup_native_once_v4());
        if !matches!(self.native_before, Some(Ok(()))) {
            self.first = Some(First::Before);
            return Err(NetworkServiceClosedV4);
        }
        self.configuration_result = Some(self.configuration.capture_network_once_v4(Path::new(CONFIGURATION)));
        if !matches!(self.configuration_result, Some(Ok(()))) {
            self.first = Some(First::Configuration);
            return Err(NetworkServiceClosedV4);
        }
        let configuration = match self.configuration.take_configuration_once() {
            Some(configuration) => configuration,
            None => { self.first = Some(First::Configuration); return Err(NetworkServiceClosedV4); }
        };
        let (authority, credentials) = NetworkAuthorityV1::from_captured_network_configuration_v4(configuration);
        self.authority = Some(authority);
        self.credentials = Some(credentials);

        self.policy_native = Some(self.policy.capture_native_once_v4(Path::new(CONFIGURATION)));
        if !matches!(self.policy_native, Some(Ok(()))) {
            self.first = Some(First::Policy);
            return Err(NetworkServiceClosedV4);
        }
        self.geometry = Some(self.policy.typed_receiving_demand_v4()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes }));
        let demand = match self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => { self.first = Some(First::Geometry); return Err(NetworkServiceClosedV4); }
        };
        self.admit_startup_v4(demand, 1)?;
        self.policy_typed = Some(self.policy.materialize_once_v4(MINIMUM_POLICY_GENERATION));
        if !matches!(self.policy_typed, Some(Ok(()))) {
            self.first = Some(First::Policy);
            return Err(NetworkServiceClosedV4);
        }
        let authority = self.authority.as_ref().ok_or(NetworkServiceClosedV4)?;
        self.stage_results[0] = Some(self.creation_opening.capture_once_v4(&mut self.common,
            authority, &self.policy, MINIMUM_POLICY_GENERATION).map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(0, First::Creation)?;
        let authority = self.authority.as_ref().ok_or(NetworkServiceClosedV4)?;
        self.stage_results[1] = Some(self.lifecycle_opening.capture_once_v4(&mut self.common, authority)
            .map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(1, First::Lifecycle)?;
        let policy = match self.policy.take_completed_v4() {
            Some(policy) => policy,
            None => { self.first = Some(First::Policy); return Err(NetworkServiceClosedV4); }
        };
        // The actual policy moves directly into this owning stage before its
        // next fallible operation. Neither errors nor native prefixes escape
        // into a local constructor whose unwind would drop their custody.
        self.stage_results[2] = Some(self.preparation_opening.capture_once_v4(&mut self.common,
            policy, MINIMUM_POLICY_GENERATION).map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(2, First::Preparations)?;
        self.stage_results[3] = Some(self.namespace_opening.capture_once_v4(&mut self.common)
            .map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(3, First::Namespaces)?;
        self.stage_results[4] = Some(self.store_opening.prepare_once_v4(maximum_entries, &mut self.common)
            .map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(4, First::Store)?;

        self.geometry = Some(worker_inputs_receiving_demand_v4());
        let demand = match self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => { self.first = Some(First::Geometry); return Err(NetworkServiceClosedV4); }
        };
        self.admit_startup_v4(demand, 2)?;
        self.stage_results[5] = Some(self.capture_worker_inputs_v4(0));
        self.require_stage_v4(5, First::Inputs(0))?;
        if self.cgroups[0].is_none() || self.hosts[0].is_none() {
            self.first = Some(First::Transfer);
            return Err(NetworkServiceClosedV4);
        }
        let (Some(root), Some(host)) = (self.cgroups[0].take(), self.hosts[0].take()) else { std::process::abort() };
        self.stage_results[6] = Some(self.prepare_opening.prepare_once_v4(root, host, &mut self.common)
            .map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(6, First::PrepareExecutor)?;
        self.stage_results[7] = Some(self.capture_worker_inputs_v4(1));
        self.require_stage_v4(7, First::Inputs(1))?;
        if self.cgroups[1].is_none() || self.hosts[1].is_none() {
            self.first = Some(First::Transfer);
            return Err(NetworkServiceClosedV4);
        }
        let (Some(root), Some(host)) = (self.cgroups[1].take(), self.hosts[1].take()) else { std::process::abort() };
        self.stage_results[8] = Some(self.observe_opening.prepare_once_v4(root, host, &mut self.common)
            .map_err(|_| NetworkServiceClosedV4));
        self.require_stage_v4(8, First::ObserveExecutor)?;
        self.listener_result = Some(self.common.capture_service_listener_once_v4(&mut self.listener_opening));
        if !matches!(self.listener_result, Some(Ok(()))) {
            self.listener_original_selected = self.listener_opening.failure().is_none();
            self.first = Some(First::Listener);
            return Err(NetworkServiceClosedV4);
        }
        Ok(())
    }

    fn capture_worker_inputs_v4(&mut self, index: usize) -> Result<()> {
        self.cgroup_opened[index] = Some(crate::worker_runtime::open_cgroup_root_candidate_retaining_v4());
        if !matches!(self.cgroup_opened[index], Some(Ok(_))) { return Err(NetworkServiceClosedV4); }
        let Some(Ok(descriptor)) = self.cgroup_opened[index].take() else { std::process::abort() };
        if self.cgroup_originals[index].admit_once(descriptor).is_err() { return Err(NetworkServiceClosedV4); }
        self.cgroups[index] = self.cgroup_originals[index].take_completed_once();
        if self.host_originals[index].capture_once_v4().is_err() { return Err(NetworkServiceClosedV4); }
        self.hosts[index] = self.host_originals[index].take_completed_once_v4();
        if self.cgroups[index].is_none() || self.hosts[index].is_none() { return Err(NetworkServiceClosedV4); }
        Ok(())
    }

    fn admit_startup_v4(&mut self, demand: ResourceVector, slot: usize) -> Result<()> {
        self.funding[slot] = Some(self.common.require_additional_startup_representation_v4(demand));
        if !matches!(self.funding[slot], Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(NetworkServiceClosedV4);
        }
        Ok(())
    }

    fn require_stage_v4(&mut self, slot: usize, first: First) -> Result<()> {
        if !matches!(self.stage_results[slot], Some(Ok(()))) {
            self.first.get_or_insert(first);
            return Err(NetworkServiceClosedV4);
        }
        Ok(())
    }

    fn take_completed_startup_v4(&mut self) -> Result<()> {
        // Each native move first parks in this same whole owner. Check the
        // conjunction before the infallible field split into the coordinator.
        self.creation = self.creation_opening.take_completed_once_v4();
        self.lifecycle = self.lifecycle_opening.take_completed_once_v4();
        self.preparations = self.preparation_opening.take_completed_once_v4();
        self.namespaces = self.namespace_opening.take_completed_once_v4();
        self.namespace_store = self.store_opening.take_completed_once_v4();
        self.prepare_executor = self.prepare_opening.take_completed_once_v4();
        self.observation_executor = self.observe_opening.take_completed_once_v4();
        if self.creation.is_none() || self.lifecycle.is_none() || self.authority.is_none()
            || self.preparations.is_none() || self.namespaces.is_none() || self.namespace_store.is_none()
            || self.prepare_executor.is_none() || self.observation_executor.is_none() {
            self.first = Some(First::Transfer);
            return Err(NetworkServiceClosedV4);
        }
        let (Some(authority), Some(creation), Some(lifecycle)) =
            (self.authority.take(), self.creation.take(), self.lifecycle.take()) else { std::process::abort() };
        self.coordinator = Some(NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle));
        self.ready = true;
        Ok(())
    }
}

fn worker_inputs_receiving_demand_v4() -> std::result::Result<ResourceVector, AccountingError> {
    let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let (root_bytes, root_files, root_names) = CgroupRootOriginalV2::receiving_obligations_v2().ok_or(overflow)?;
    let (host_bytes, host_files, host_names) = CurrentNetworkNamespaceOriginalV4::receiving_obligations_v4().ok_or(overflow)?;
    let bytes = root_bytes.checked_add(host_bytes).and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(overflow)?;
    let files = root_files.checked_add(host_files).and_then(|files| files.checked_mul(2))
        .and_then(|files| u64::try_from(files).ok()).ok_or(overflow)?;
    let names = root_names.checked_add(host_names).and_then(|names| names.checked_mul(2))
        .and_then(|names| u64::try_from(names).ok()).ok_or(overflow)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files).with(D::MetadataEntries, names))
}
