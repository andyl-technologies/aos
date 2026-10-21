//! Accepts explicit operator deployment policy before runtime or actor creation.
//!
//! This local policy is not accepted from node-control requests or worker DATA.
//! It reserves the whole parent process and selects actual delegated host
//! controls; a listening endpoint or retained capsule grants no node readiness.
//!
//! ```text
//! {"format":"crucible.node-operational-deployment", "version":1,
//!  "parent":{"cpu_seconds":...,"address_space_bytes":...,"descriptors":...},
//!  "worker":{"cgroup_root":...,"run_root":...,"project_id":...,
//!            "user_id":...,"group_id":...,"limits":...},
//!  "export_workspace_slots":...}
//! ```

#[path = "deployment/namespace.rs"]
mod namespace;

use super::{NodeControlError, canonical};
use crucible_engine::node_adapters::cnp::source_birth_derivation::installation::VerifiedSourceBirthMechanism;
use crucible_engine::node_contract::RuntimeError;
use crucible_host_resources::DeploymentResourceReadContext;
use crucible_host_resources::{
    LinuxProcessLimits, LinuxPureWorkerConfiguration, LinuxPureWorkerLimits,
    OriginalDeploymentResourceReservation,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentPolicy {
    cpu_seconds: u64,
    address_space_bytes: u64,
    descriptors: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerPolicy {
    cgroup_root: PathBuf,
    run_root: PathBuf,
    project_id: u32,
    user_id: u32,
    group_id: u32,
    limits: WorkerLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerLimits {
    memory_bytes: u64,
    address_space_bytes: u64,
    cpu_seconds: u64,
    descriptors: u64,
    disk_bytes: u64,
    inodes: u64,
    input_bytes: u64,
    maximum_input_elements: u64,
    maximum_result_bytes: u64,
    diagnostic_bytes: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    wall_seconds: u64,
}

/// Decodes the operator's explicit whole-parent and delegated-worker policy.
///
/// The policy has no defaults, implementation hashes or authority flags. Its
/// actual trusted service entry must retain/install the original reservation;
/// decoding these DATA alone reserves nothing and enables no operation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOperationalDeploymentPolicy {
    format: String,
    version: u32,
    parent: ParentPolicy,
    worker: WorkerPolicy,
    export_workspace_slots: usize,
}

impl NodeOperationalDeploymentPolicy {
    /// Reads one bounded closed local operational policy.
    ///
    /// # Errors
    /// Refuses invalid/duplicate/unknown fields, another edition, zero bounds,
    /// or nonabsolute delegated paths. Actual workspace representability is
    /// checked by the defining installed-mechanism opener before Source work.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeControlError> {
        let value = canonical::parse_json(bytes, 64 * 1024)?;
        let policy: Self =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), NodeControlError> {
        let policy = self;
        if policy.format != "crucible.node-operational-deployment"
            || policy.version != 1
            || policy.parent.cpu_seconds == 0
            || policy.parent.address_space_bytes == 0
            || policy.parent.descriptors == 0
            || !policy.worker.cgroup_root.is_absolute()
            || !policy.worker.run_root.is_absolute()
            || policy.export_workspace_slots == 0
        {
            return Err(super::refused(
                "invalid operator operational deployment policy",
            ));
        }
        let limits = &policy.worker.limits;
        LinuxPureWorkerLimits {
            memory_bytes: limits.memory_bytes,
            address_space_bytes: limits.address_space_bytes,
            cpu_seconds: limits.cpu_seconds,
            descriptors: limits.descriptors,
            disk_bytes: limits.disk_bytes,
            inodes: limits.inodes,
            input_bytes: limits.input_bytes,
            elements: limits.maximum_input_elements,
            bank_bytes: limits.maximum_result_bytes,
            diagnostic_bytes: limits.diagnostic_bytes,
            stdout_bytes: limits.stdout_bytes,
            stderr_bytes: limits.stderr_bytes,
            wall_seconds: limits.wall_seconds,
        }
        .validate()
        .map_err(|_| super::refused("invalid operator worker limits"))?;
        Ok(())
    }
}

/// Retains the actual accepted deployment transaction and worker configuration.
///
/// The nonClone owner crosses the service-factory Send boundary. Its original
/// reservation precedes runtime/actor/manifest creation and survives failure.
#[must_use = "retain original operational deployment through actor teardown"]
pub struct NodeOperationalDeployment {
    pub(crate) original: Option<OriginalDeploymentResourceReservation>,
    configuration: LinuxPureWorkerConfiguration,
    limits: LinuxPureWorkerLimits,
    slots: usize,
}

impl NodeOperationalDeployment {
    /// Installs the explicit operator policy at the actual before-actors entry.
    ///
    /// # Errors
    /// Refuses an occupied output, repeated process reservation, an invalid
    /// birth phase or actual kernel/proc enforcement. The output retains every
    /// attempted original; callers must not replace it after error.
    pub fn install_before_actors_into(
        output: &mut Option<Self>,
        policy: NodeOperationalDeploymentPolicy,
    ) -> Result<(), NodeControlError> {
        if output.is_some() {
            return Err(super::refused("operational deployment already attempted"));
        }
        policy.validate()?;
        let WorkerLimits {
            memory_bytes,
            address_space_bytes,
            cpu_seconds,
            descriptors,
            disk_bytes,
            inodes,
            input_bytes,
            maximum_input_elements,
            maximum_result_bytes,
            diagnostic_bytes,
            stdout_bytes,
            stderr_bytes,
            wall_seconds,
        } = policy.worker.limits;
        *output = Some(Self {
            original: None,
            configuration: LinuxPureWorkerConfiguration {
                cgroup_root: policy.worker.cgroup_root,
                run_root: policy.worker.run_root,
                project_id: policy.worker.project_id,
                child_user_id: policy.worker.user_id,
                child_group_id: policy.worker.group_id,
            },
            limits: LinuxPureWorkerLimits {
                memory_bytes,
                address_space_bytes,
                cpu_seconds,
                descriptors,
                disk_bytes,
                inodes,
                input_bytes,
                elements: maximum_input_elements,
                bank_bytes: maximum_result_bytes,
                diagnostic_bytes,
                stdout_bytes,
                stderr_bytes,
                wall_seconds,
            },
            slots: policy.export_workspace_slots,
        });
        let owner = output
            .as_mut()
            .ok_or_else(|| super::refused("operational deployment output absent"))?;
        OriginalDeploymentResourceReservation::install_before_actors_into(
            &mut owner.original,
            LinuxProcessLimits {
                cpu_seconds: policy.parent.cpu_seconds,
                address_space_bytes: policy.parent.address_space_bytes,
                descriptors: policy.parent.descriptors,
            },
        )
        .map_err(|_| super::refused("original process reservation refused"))
    }

    pub(crate) fn original(
        &self,
    ) -> Result<&OriginalDeploymentResourceReservation, NodeControlError> {
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| super::refused("original deployment reservation absent"))?;
        original
            .authenticate_current()
            .map_err(|_| super::refused("original deployment enforcement changed"))?;
        Ok(original)
    }

    pub(crate) fn worker_configuration(&self) -> LinuxPureWorkerConfiguration {
        self.configuration.clone()
    }

    pub(crate) fn worker_limits(&self) -> LinuxPureWorkerLimits {
        self.limits
    }

    pub(crate) fn workspace_slots(&self) -> usize {
        self.slots
    }

    pub(crate) fn known_configuration_backing_data(&self) -> Option<usize> {
        self.configuration
            .cgroup_root
            .capacity()
            .checked_add(self.configuration.run_root.capacity())
    }
}

/// Keeps the nonClone reservation and actor-local installed owner together.
pub(crate) struct InstalledDeployment {
    owner: NodeOperationalDeployment,
    mechanism: std::cell::OnceCell<Rc<VerifiedSourceBirthMechanism>>,
    attempted: std::cell::Cell<bool>,
    namespace: std::cell::RefCell<Option<namespace::FundedNamespace>>,
}

impl InstalledDeployment {
    pub(crate) fn new(owner: NodeOperationalDeployment) -> Rc<Self> {
        Rc::new(Self {
            owner,
            mechanism: std::cell::OnceCell::new(),
            attempted: std::cell::Cell::new(false),
            namespace: std::cell::RefCell::new(None),
        })
    }

    pub(crate) fn initialize(&self) -> Result<(), crate::node_qualification::QualificationError> {
        if self.attempted.replace(true) {
            return Err(crate::node_qualification::QualificationError::Refused(
                "operational installation already attempted",
            ));
        }
        let mechanism = VerifiedSourceBirthMechanism::open_with_deployment(
            self.owner.original().map_err(|_| {
                crate::node_qualification::QualificationError::Refused(
                    "original operational deployment unavailable",
                )
            })?,
            self.owner.worker_configuration(),
            self.owner.worker_limits(),
            self.owner.workspace_slots(),
        )
        .map_err(|failure| {
            crate::node_qualification::QualificationError::Refused(failure.stage_data())
        })?;
        self.mechanism.set(Rc::new(mechanism)).map_err(|_| {
            crate::node_qualification::QualificationError::Refused(
                "operational installation already retained",
            )
        })
    }

    pub(crate) fn mechanism(&self) -> Result<&Rc<VerifiedSourceBirthMechanism>, RuntimeError> {
        self.mechanism.get().ok_or(RuntimeError::UnsupportedFacet)
    }

    pub(crate) fn context(&self) -> Result<DeploymentResourceReadContext<'_>, RuntimeError> {
        self.owner
            .original()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .read_context()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    pub(crate) fn revoke(&self) {
        if let Some(original) = &self.owner.original {
            original.revoke();
        }
    }

    pub(crate) fn authenticate(&self) -> Result<(), RuntimeError> {
        self.owner
            .original()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.mechanism()?.authenticate_current()
    }

    pub(crate) fn create_namespace(
        &self,
        path: PathBuf,
    ) -> Result<(PathBuf, (u64, u64)), crate::node_qualification::QualificationError> {
        self.authenticate().map_err(|_| {
            crate::node_qualification::QualificationError::Refused(
                "funded namespace original unavailable",
            )
        })?;
        let mut output = self.namespace.try_borrow_mut().map_err(|_| {
            crate::node_qualification::QualificationError::Refused("funded namespace is busy")
        })?;
        namespace::FundedNamespace::create_into(&mut output, path).map_err(|_| {
            crate::node_qualification::QualificationError::Refused(
                "funded namespace creation refused",
            )
        })
    }

    // Acceptance is already revoked. This follows the retained original
    // namespace, never a new public path or an active Source borrow.
    pub(crate) fn cleanup_namespace(&self) -> Result<(), ()> {
        let mut output = self.namespace.try_borrow_mut().map_err(|_| ())?;
        match output.as_mut() {
            Some(original) => original.cleanup(),
            None => Ok(()),
        }
    }

    pub(crate) fn known_direct_backing_data(&self) -> Result<usize, RuntimeError> {
        let configuration = self
            .owner
            .known_configuration_backing_data()
            .ok_or(RuntimeError::ResourceLimit)?;
        let mechanism = self
            .mechanism()?
            .direct_buffer_census()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let namespace = self
            .namespace
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        configuration
            .checked_add(mechanism.checked_sum().ok_or(RuntimeError::ResourceLimit)?)
            .and_then(|n| {
                n.checked_add(
                    namespace
                        .as_ref()
                        .map_or(Some(0), namespace::FundedNamespace::known_backing_data)?,
                )
            })
            .ok_or(RuntimeError::ResourceLimit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> serde_json::Value {
        serde_json::json!({
            "format":"crucible.node-operational-deployment", "version":1,
            "parent":{"cpu_seconds":10,"address_space_bytes":536870912,"descriptors":128},
            "worker":{"cgroup_root":"/delegated/cgroup", "run_root":"/delegated/runs",
                "project_id":27,"user_id":29,"group_id":31,
                "limits":{"memory_bytes":67108864,"address_space_bytes":134217728,
                    "cpu_seconds":5,"descriptors":64,"disk_bytes":1048576,
                    "inodes":128,"input_bytes":65536,"maximum_input_elements":4096,
                    "maximum_result_bytes":65536,"diagnostic_bytes":4096,
                    "stdout_bytes":131072,"stderr_bytes":4096,"wall_seconds":10}},
            "export_workspace_slots":64
        })
    }

    #[test]
    fn policy_parsing_is_data_only_and_has_no_default_or_stage_selector() {
        let value = policy();
        let parsed =
            NodeOperationalDeploymentPolicy::from_json(&serde_json::to_vec(&value).unwrap())
                .unwrap();
        assert_eq!(parsed.export_workspace_slots, 64);
        assert_eq!(parsed.parent.descriptors, 128);

        let mut unknown = value.clone();
        unknown["bank_stage"] = serde_json::json!("ready");
        assert!(
            NodeOperationalDeploymentPolicy::from_json(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("parent");
        assert!(
            NodeOperationalDeploymentPolicy::from_json(&serde_json::to_vec(&missing).unwrap())
                .is_err()
        );
        let mut zero = value;
        zero["worker"]["limits"]["input_bytes"] = serde_json::json!(0);
        assert!(
            NodeOperationalDeploymentPolicy::from_json(&serde_json::to_vec(&zero).unwrap())
                .is_err()
        );
    }

    #[test]
    fn duplicate_policy_keys_and_invalid_direct_deserialization_cannot_install() {
        assert!(
            NodeOperationalDeploymentPolicy::from_json(br#"{"format":"a","format":"b"}"#).is_err()
        );
        let mut value = policy();
        value["parent"]["cpu_seconds"] = serde_json::json!(0);
        let invalid: NodeOperationalDeploymentPolicy = serde_json::from_value(value).unwrap();
        let mut output = None;
        // Revalidation occurs before the process-once latch or any limits effect.
        assert!(
            NodeOperationalDeployment::install_before_actors_into(&mut output, invalid).is_err()
        );
        assert!(output.is_none());
    }

    #[test]
    fn actual_service_handoff_owner_is_send() {
        fn check<T: Send>() {}
        check::<NodeOperationalDeployment>();
    }
}
