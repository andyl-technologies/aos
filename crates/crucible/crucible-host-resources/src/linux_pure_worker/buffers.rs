//! Direct requested-buffer observations, separate from supervisor admission.
//!
//! These values describe actual retained Vec/PathBuf capacities visible to this
//! owner. They exclude headers, Arc control blocks, file/thread/kernel/runtime
//! state, opaque Command/error backing and every constructor transient. They
//! cannot replace the independently enforced shared-process supervisor budget.

use super::*;

/// Describes one actual direct buffer allocation in a retained worker view.
///
/// Path buffers use their byte-vector geometry. Runtime-root rosters use the
/// compiled private `(PathBuf, OwnedFd)` element layout, including spare slots.
/// These are allocator-request DATA; opaque runtime and kernel custody remain
/// separate obligations. No descriptor or process-private reference escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxPureWorkerBufferCapacityData {
    /// Reports the original allocation's element capacity, including spare slots.
    pub capacity: usize,
    /// Reports the compiled size of one element in this allocation.
    pub element_bytes: usize,
    /// Reports the compiled alignment of one element in this allocation.
    pub alignment: usize,
}

impl LinuxPureWorkerBufferCapacityData {
    /// Reports the concrete controls of the allocation-free direct-buffer walk.
    ///
    /// Caller-specific observer captures and error values are additional terms.
    /// Opaque runtime backing remains under the original deployment reservation.
    pub fn counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<Self>()
            + size_of::<&LinuxPureWorkerFactory>()
            + size_of::<&LinuxPureWorkerAttempt>()
            + size_of::<&LinuxPureWorkerCompletion>()
            + size_of::<&LinuxPureWorkerProgram>()
            + size_of::<&Roots>()
            + size_of::<&State>()
            + size_of::<MutexGuard<'static, State>>()
            + size_of::<&Workspace>()
            + size_of::<&Cgroup>()
            + size_of::<&aos_linux_project_quota::LinuxProjectQuotaReservation>()
            + size_of::<&PathBuf>()
            + size_of::<&Vec<u8>>()
            + size_of::<&LinuxPureWorkerOutcome>()
            + size_of::<&Vec<(PathBuf, OwnedFd)>>()
            + size_of::<std::slice::Iter<'static, (PathBuf, OwnedFd)>>()
            + size_of::<(&PathBuf, &OwnedFd)>()
    }

    pub(super) fn bytes(capacity: usize) -> Self {
        Self {
            capacity,
            element_bytes: std::mem::size_of::<u8>(),
            alignment: std::mem::align_of::<u8>(),
        }
    }

    pub(super) fn vector<T>(owner: &Vec<T>) -> Self {
        Self {
            capacity: owner.capacity(),
            element_bytes: std::mem::size_of::<T>(),
            alignment: std::mem::align_of::<T>(),
        }
    }
}

/// Reports selected direct requested buffer backing through one owner view.
///
/// Capacity bytes are logical allocator requests, not usable-size/RSS facts.
/// Shared Program/root buffers appear in each holder view; callers must retain
/// original identity context before discounting repeated observations. This
/// DATA does not certify a complete footprint, construction bound or admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxPureWorkerDirectBuffers {
    /// Retained worker path and each exact read-only runtime-root path.
    pub program_path_bytes: usize,
    /// Actual Vec capacity for the private (PathBuf, OwnedFd) runtime roster.
    pub program_roster_bytes: usize,
    /// Retained configured cgroup-root and run-root PathBuf capacities.
    pub namespace_path_bytes: usize,
    /// Currently retained child-cgroup and quota diagnostic-path capacities.
    pub attempt_path_bytes: usize,
    /// Currently owned stdout/stderr Vec capacities, after disk retirement.
    pub output_capacity_bytes: usize,
}

impl LinuxPureWorkerDirectBuffers {
    /// Adds only the explicitly named requested-buffer populations.
    ///
    /// This is not an aggregate owner footprint or memory reservation.
    pub fn checked_sum(self) -> Option<usize> {
        self.program_path_bytes
            .checked_add(self.program_roster_bytes)?
            .checked_add(self.namespace_path_bytes)?
            .checked_add(self.attempt_path_bytes)?
            .checked_add(self.output_capacity_bytes)
    }
}

fn base(
    program: &LinuxPureWorkerProgram,
    roots: &Roots,
) -> Result<LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
    let (program_path_bytes, program_roster_bytes) = program.direct_buffer_parts()?;
    let namespace_path_bytes = roots
        .configuration
        .cgroup_root
        .capacity()
        .checked_add(roots.configuration.run_root.capacity())
        .ok_or(LinuxPureWorkerError::Configuration)?;
    Ok(LinuxPureWorkerDirectBuffers {
        program_path_bytes,
        program_roster_bytes,
        namespace_path_bytes,
        attempt_path_bytes: 0,
        output_capacity_bytes: 0,
    })
}

fn state_buffers(state: &State) -> Result<LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
    let mut observation = base(&state.program, &state.roots)?;
    observation.attempt_path_bytes = state
        .group
        .as_ref()
        .map_or(0, |group| group.path.capacity())
        .checked_add(
            state
                .workspace
                .as_ref()
                .map_or(0, Workspace::path_buffer_bytes),
        )
        .ok_or(LinuxPureWorkerError::Configuration)?;
    observation.output_capacity_bytes = state
        .stdout
        .capacity()
        .checked_add(state.stderr.capacity())
        .ok_or(LinuxPureWorkerError::Configuration)?;
    Ok(observation)
}

fn observe_base<E>(
    program: &LinuxPureWorkerProgram,
    roots: &Roots,
    observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
) -> Result<(), E> {
    program.observe_direct_buffers(observe)?;
    observe(LinuxPureWorkerBufferCapacityData::bytes(
        roots.configuration.cgroup_root.capacity(),
    ))?;
    observe(LinuxPureWorkerBufferCapacityData::bytes(
        roots.configuration.run_root.capacity(),
    ))
}

fn observe_state<E>(
    state: &State,
    observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
) -> Result<(), E> {
    observe_base(&state.program, &state.roots, observe)?;
    if let Some(group) = &state.group {
        observe(LinuxPureWorkerBufferCapacityData::bytes(
            group.path.capacity(),
        ))?;
    }
    if let Some(workspace) = &state.workspace {
        workspace.observe_path_buffer(observe)?;
    }
    observe(LinuxPureWorkerBufferCapacityData::vector(&state.stdout))?;
    observe(LinuxPureWorkerBufferCapacityData::vector(&state.stderr))
}

impl LinuxPureWorkerFactory {
    /// Observes each original direct buffer without aggregating its geometry.
    ///
    /// Shared views repeat their rows. Empty allocations retain zero capacity;
    /// spare runtime-root slots keep their defining compiled element layout.
    ///
    /// # Errors
    /// Returns the observer's first error without visiting subsequent buffers.
    pub fn observe_direct_buffers<E>(
        &self,
        observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
    ) -> Result<(), E> {
        observe_base(&self.program, &self.roots, observe)
    }

    /// Observes its original immutable paths and runtime-root roster only.
    ///
    /// # Errors
    /// Refuses arithmetic that cannot represent the actual requested capacities.
    pub fn direct_buffer_census(
        &self,
    ) -> Result<LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
        base(&self.program, &self.roots)
    }
}

impl LinuxPureWorkerAttempt {
    /// Observes original direct buffers while retaining the attempt state lock.
    ///
    /// Failed and cancelled prefixes remain observable. The synchronous observer
    /// must not reenter this attempt; no native operation or allocation is made
    /// by the walk. Private Command/error/thread backing is excluded.
    ///
    /// # Errors
    /// Returns the observer's first error, preserving state and its emitted prefix.
    pub fn observe_direct_buffers<E>(
        &self,
        observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
    ) -> Result<(), E> {
        observe_state(&lock(&self.shared), observe)
    }

    /// Observes direct buffers from this same retained attempt under its lock.
    ///
    /// This neither authenticates currentness nor changes failed/cancelled state.
    /// Private command/error/thread backing remains outside this DATA scope.
    ///
    /// # Errors
    /// Refuses arithmetic that cannot represent the actual requested capacities.
    pub fn direct_buffer_census(
        &self,
    ) -> Result<LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
        state_buffers(&lock(&self.shared))
    }
}

impl LinuxPureWorkerCompletion {
    /// Observes original state buffers and the actual moved outcome vectors.
    ///
    /// State observation holds the original attempt lock; the observer must not
    /// reenter it. This supplies no result-acceptance or currentness authority.
    ///
    /// # Errors
    /// Returns the observer's first error, retaining every original buffer.
    pub fn observe_direct_buffers<E>(
        &self,
        observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
    ) -> Result<(), E> {
        observe_state(&lock(&self.shared), observe)?;
        observe(LinuxPureWorkerBufferCapacityData::vector(
            &self.outcome.stdout,
        ))?;
        observe(LinuxPureWorkerBufferCapacityData::vector(
            &self.outcome.stderr,
        ))
    }

    /// Observes retained direct buffers including its actual moved output Vecs.
    ///
    /// It does not perform [`Self::verify_original`] or grant result acceptance.
    ///
    /// # Errors
    /// Refuses arithmetic that cannot represent the actual requested capacities.
    pub fn direct_buffer_census(
        &self,
    ) -> Result<LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
        let mut observation = state_buffers(&lock(&self.shared))?;
        observation.output_capacity_bytes = observation
            .output_capacity_bytes
            .checked_add(self.outcome.stdout.capacity())
            .and_then(|sum| sum.checked_add(self.outcome.stderr.capacity()))
            .ok_or(LinuxPureWorkerError::Configuration)?;
        Ok(observation)
    }
}

#[cfg(test)]
#[path = "buffers/tests.rs"]
mod tests;
