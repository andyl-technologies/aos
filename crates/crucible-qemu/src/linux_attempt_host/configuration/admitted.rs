//! Constructs the required host contract under its retained decode account.
//!
//! Paths and actual credential arrays are admitted before copying. The fixed
//! refusal body is created before validation and keeps the original lower
//! storage cause without converting it to an owning diagnostic string.

use std::ffi::OsString;

use crucible::owned_decode::json_profiles::workflow::ExecutorHost;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};

use super::*;

/// Retains the actual admitted host configuration refusal.
#[derive(Debug, thiserror::Error)]
#[error("admitted QEMU host configuration refused: {failure}")]
pub struct AdmittedHostConfigurationError {
    #[source]
    failure: Failure,
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("configuration storage admission refused: {0}")]
    Admission(#[source] DecodeAdmissionError),
    #[error(transparent)]
    Retained(FailureOwner),
}

struct FailureOwner {
    data: Box<FailureData>,
    _credit: DecodeScratch,
    _custody: DecodeCustody,
}

#[derive(Debug)]
struct FailureData {
    first: Option<Cause>,
    after: Option<DecodeAdmissionError>,
}

#[derive(Debug, thiserror::Error)]
enum Cause {
    #[error("configuration admission refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    #[error("configuration allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("process configuration refused: {0}")]
    Process(&'static str),
    #[error("storage configuration refused: {0}")]
    Storage(#[source] crate::linux_attempt_storage::LinuxQemuAttemptStorageError),
}

impl std::fmt::Debug for FailureOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::fmt::Display for FailureOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.data.first {
            Some(cause) => write!(formatter, "{cause}; postcheck: {:?}", self.data.after),
            None => formatter.write_str("configuration refusal has no initiating cause"),
        }
    }
}

impl std::error::Error for FailureOwner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.data.first.as_ref()?;
        Some(cause)
    }
}

impl LinuxQemuAttemptHostConfig {
    /// Constructs the explicit workflow host contract under the same budget.
    ///
    /// This validates the current supervisor credentials. It neither opens a
    /// cgroup or run root nor certifies their physical containment. The caller
    /// must retain its decode custody through the returned configuration's use.
    ///
    /// # Errors
    /// Refuses storage admission before allocation, invalid process or storage
    /// requirements, failed credential inspection, or an original postcheck.
    /// The returned error frees its actual body before its credit and custody.
    pub fn try_from_workflow_admitted(
        input: &ExecutorHost<'_>,
        budget: &DecodeBudget,
    ) -> Result<Self, AdmittedHostConfigurationError> {
        let credit = budget
            .reserve_scratch_array::<FailureData>(1)
            .map_err(|source| AdmittedHostConfigurationError {
                failure: Failure::Admission(source),
            })?;
        let mut failure = FailureOwner {
            data: Box::new(FailureData {
                first: None,
                after: None,
            }),
            _credit: credit,
            _custody: budget.custody(),
        };
        let work = (|| {
            budget.verify_live()?;
            let _scope = budget.enter();
            if input.maximum_node_host_service_tasks == 0
                || input.maximum_node_host_service_file_descriptors == 0
                || input.maximum_node_host_service_resident_bytes == 0
                || input.watcher_service_resident_bytes == 0
            {
                return Err(Cause::Process("node host-service ceilings must be nonzero"));
            }
            let process = LinuxQemuAttemptProcessConfig::new_typed(
                path(input.cgroup_root, budget)?,
                string(input.attempt_namespace, budget)?,
                input.child_user_id,
                input.child_group_id,
                input.maximum_tasks,
                input.maximum_file_descriptors,
                Duration::from_millis(input.finish_timeout_millis),
            )
            .map_err(Cause::Process)?;
            let process = process
                .with_maximum_locked_bytes_typed(input.maximum_locked_bytes)
                .map_err(Cause::Process)?;
            let storage = LinuxQemuAttemptStorageConfig::new(
                path(input.run_root, budget)?,
                string(input.attempt_namespace, budget)?,
                input.first_project_id,
                input.project_id_count,
                input.child_user_id,
                input.child_group_id,
                input.maximum_inodes,
            )
            .map_err(Cause::Storage)?;
            Ok(Self {
                process,
                storage,
                maximum_node_host_service_tasks: input.maximum_node_host_service_tasks,
                maximum_node_host_service_file_descriptors: input
                    .maximum_node_host_service_file_descriptors,
                maximum_node_host_service_resident_bytes: input
                    .maximum_node_host_service_resident_bytes,
                watcher_service_resident_bytes: input.watcher_service_resident_bytes,
            })
        })();
        let after = budget.verify_live();
        match (work, after) {
            (Ok(config), Ok(())) => Ok(config),
            (Err(cause), after) => {
                failure.data.first = Some(cause);
                failure.data.after = after.err();
                Err(AdmittedHostConfigurationError {
                    failure: Failure::Retained(failure),
                })
            }
            (Ok(_), Err(cause)) => {
                failure.data.first = Some(Cause::Admission(cause));
                Err(AdmittedHostConfigurationError {
                    failure: Failure::Retained(failure),
                })
            }
        }
    }
}

fn path(value: &str, budget: &DecodeBudget) -> Result<PathBuf, Cause> {
    budget.charge_bytes(value.len() as u64)?;
    let mut path = OsString::new();
    path.try_reserve_exact(value.len())?;
    path.push(value);
    Ok(path.into())
}

fn string(value: &str, budget: &DecodeBudget) -> Result<String, Cause> {
    budget.charge_bytes(value.len() as u64)?;
    let mut owned = String::new();
    owned.try_reserve_exact(value.len())?;
    owned.push_str(value);
    Ok(owned)
}
