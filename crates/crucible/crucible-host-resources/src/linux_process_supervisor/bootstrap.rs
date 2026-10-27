//! Configures aggregate process limits only at the real single-threaded entry.
//!
//! This optional deployment operation affects the whole daemon and every actor
//! it later creates. It is not suitable inside an already running service. It
//! preserves stricter inherited limits and retains the original transaction
//! before its first irreversible hard-limit change. No actual enforcement
//! operation is performed by source qualification or pure controls.

use super::*;
use rustix::process::setrlimit;
use std::{fs, io::Read, path::PathBuf};

/// Retains an irreversible whole-process bootstrap transaction through failure.
#[must_use = "retain original aggregate process setup even after partial failure"]
pub struct LinuxProcessSupervisor {
    process: u32,
    thread: ThreadId,
    target: LinuxProcessCeilingsData,
    original: LinuxProcessCeilingsData,
    complete: bool,
    installation_attempted: bool,
}

impl LinuxProcessSupervisor {
    /// Reports its compiled inline payload layout without checking kernel state.
    ///
    /// The closed roster contains only fixed process, thread, ceiling and once
    /// fields. This DATA neither proves completion nor authorizes deployment.
    pub fn retained_payload_layout_data(&self) -> std::alloc::Layout {
        let Self {
            process: _,
            thread: _,
            target: _,
            original: _,
            complete: _,
            installation_attempted: _,
        } = self;
        std::alloc::Layout::for_value(self)
    }

    /// Names the fixed inline layout observer's concrete controls.
    pub fn retained_capacity_counter_scratch_data() -> usize {
        use std::{alloc::Layout, mem::size_of};

        size_of::<&Self>()
            + size_of::<Layout>()
            + size_of::<(
                &u32,
                &ThreadId,
                &LinuxProcessCeilingsData,
                &LinuxProcessCeilingsData,
                &bool,
                &bool,
            )>()
    }
}

fn no_greater(current: Rlimit, requested: u64) -> Result<Rlimit, LinuxProcessSupervisorError> {
    if requested == 0 {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    let mut value = requested;
    if let Some(soft) = current.current {
        value = value.min(soft);
    }
    if let Some(hard) = current.maximum {
        value = value.min(hard);
    }
    if value == 0 {
        return Err(LinuxProcessSupervisorError::ResourceLimit);
    }
    Ok(Rlimit {
        current: Some(value),
        maximum: Some(value),
    })
}

fn single_original_task(process: u32) -> Result<(), LinuxProcessSupervisorError> {
    let path = PathBuf::from(format!("/proc/{process}/task"));
    let mut tasks =
        fs::read_dir(path).map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
    let first = tasks
        .next()
        .ok_or(LinuxProcessSupervisorError::ForeignAuthority)?
        .map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
    if first
        .file_name()
        .to_str()
        .and_then(|name| name.parse::<u32>().ok())
        != Some(process)
        || tasks.next().is_some()
    {
        return Err(LinuxProcessSupervisorError::ForeignAuthority);
    }
    // Single-threaded deployment must also precede child birth. A byte is
    // enough to refuse any existing child without allocating its whole roster.
    let mut children = fs::File::open(format!("/proc/{process}/task/{process}/children"))
        .map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?;
    let mut byte = [0u8; 1];
    if children
        .read(&mut byte)
        .map_err(|_| LinuxProcessSupervisorError::UnsupportedFacet)?
        != 0
    {
        return Err(LinuxProcessSupervisorError::ForeignAuthority);
    }
    Ok(())
}

impl LinuxProcessSupervisor {
    /// Prepares exact shared-process ceilings before creating service actors.
    ///
    /// A production entry point calls this while still single-threaded and
    /// before spawning children. This is a whole-daemon deployment decision:
    /// CPU exhaustion can terminate every world in that process. It must never
    /// be invoked as per-node admission inside an existing shared service.
    /// The kernel task census enforces the available current-thread boundary;
    /// the called entry point must also own startup and forbid concurrent birth.
    ///
    /// # Errors
    /// Refuses an occupied slot, multiple threads, an existing child, invalid
    /// ceilings or existing resources above them. This preparation changes no
    /// kernel limit and does not authenticate a completed supervisor.
    pub fn prepare_before_actors_into(
        slot: &mut Option<Self>,
        limits: &LinuxProcessLimits,
    ) -> Result<(), LinuxProcessSupervisorError> {
        if slot.is_some() {
            return Err(LinuxProcessSupervisorError::DuplicateOperation);
        }
        let process = std::process::id();
        single_original_task(process)?;
        let old = LinuxProcessCeilingsData::current();
        let target = LinuxProcessCeilingsData {
            cpu: no_greater(old.cpu, limits.cpu_seconds)?,
            address_space: no_greater(old.address_space, limits.address_space_bytes)?,
            descriptors: no_greater(old.descriptors, limits.descriptors)?,
        };
        // Refuse preexisting resources above the proposed new limits before
        // making any irreversible change. A lowered rlimit cannot evict them.
        current::authenticate(target)?;
        if LinuxProcessCeilingsData::current() != old {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        *slot = Some(Self {
            process,
            thread: std::thread::current().id(),
            target,
            original: old,
            complete: false,
            installation_attempted: false,
        });
        Ok(())
    }

    /// Installs the prepared exact ceilings once under this retained original.
    ///
    /// The caller installs the owner in its final custody before this call.
    ///
    /// # Errors
    /// Refuses repeated setup, changed originals, unavailable kernel updates or
    /// exact readback failure. Every irreversible partial remains in this owner.
    pub fn install_prepared_before_actors(&mut self) -> Result<(), LinuxProcessSupervisorError> {
        if self.installation_attempted {
            return Err(LinuxProcessSupervisorError::DuplicateOperation);
        }
        self.installation_attempted = true;
        let process = self.process;
        let target = self.target;
        if self.thread != std::thread::current().id()
            || process != std::process::id()
            || LinuxProcessCeilingsData::current() != self.original
        {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        for (resource, value) in [
            (Resource::Cpu, target.cpu),
            (Resource::As, target.address_space),
            (Resource::Nofile, target.descriptors),
        ] {
            single_original_task(process)?;
            setrlimit(resource, value).map_err(|_| LinuxProcessSupervisorError::ResourceLimit)?;
            if getrlimit(resource) != value {
                return Err(LinuxProcessSupervisorError::ForeignAuthority);
            }
        }
        single_original_task(process)?;
        let owner = self;
        if owner.process != std::process::id()
            || owner.thread != std::thread::current().id()
            || LinuxProcessCeilingsData::current() != owner.target
        {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        current::authenticate(owner.target)?;
        if LinuxProcessCeilingsData::current() != owner.target {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        owner.complete = true;
        Ok(())
    }

    /// Prepares and installs the original whole-process ceilings before actors.
    ///
    /// The output is populated before the first irreversible kernel update.
    ///
    /// # Errors
    /// Preserves the preparation, original-identity, update and readback refusals;
    /// failed partial setup remains spent in `slot`.
    pub fn install_before_actors_into(
        slot: &mut Option<Self>,
        limits: &LinuxProcessLimits,
    ) -> Result<(), LinuxProcessSupervisorError> {
        Self::prepare_before_actors_into(slot, limits)?;
        slot.as_mut()
            .ok_or(LinuxProcessSupervisorError::OutstandingObligations)?
            .install_prepared_before_actors()
    }

    /// Borrows original pre-update ceilings for retained partial-failure diagnosis.
    ///
    /// The ordered rows are CPU seconds, address-space bytes and open descriptors.
    /// `None` retains the kernel's unbounded value; these data grant no authority.
    pub fn previous_ceiling_data(&self) -> [(Option<u64>, Option<u64>); 3] {
        [
            (self.original.cpu.current, self.original.cpu.maximum),
            (
                self.original.address_space.current,
                self.original.address_space.maximum,
            ),
            (
                self.original.descriptors.current,
                self.original.descriptors.maximum,
            ),
        ]
    }

    /// Borrows completed original setup without changing or extending a limit.
    ///
    /// # Errors
    /// Refuses partial setup, foreign creator or changed original kernel limits.
    pub fn authenticate_current(&self) -> Result<(), LinuxProcessSupervisorError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.complete
            || LinuxProcessCeilingsData::current() != self.target
        {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        self.authenticate_enforcement_after_origin()
    }

    // The actual installed target includes stricter inherited ceilings. This
    // getter cannot turn an uninstalled preparation into a reserved envelope.
    pub(super) fn installed_target_data(
        &self,
    ) -> Result<LinuxProcessLimits, LinuxProcessSupervisorError> {
        if !self.complete {
            return Err(LinuxProcessSupervisorError::OutstandingObligations);
        }
        Ok(LinuxProcessLimits {
            cpu_seconds: self
                .target
                .cpu
                .current
                .ok_or(LinuxProcessSupervisorError::ResourceLimit)?,
            address_space_bytes: self
                .target
                .address_space
                .current
                .ok_or(LinuxProcessSupervisorError::ResourceLimit)?,
            descriptors: self
                .target
                .descriptors
                .current
                .ok_or(LinuxProcessSupervisorError::ResourceLimit)?,
        })
    }

    // Only the completed, before-actors reservation issues a process-scoped
    // handoff. The public legacy entry above retains its creator-thread gate.
    pub(super) fn authenticate_process_current(&self) -> Result<(), LinuxProcessSupervisorError> {
        if self.process != std::process::id()
            || !self.complete
            || LinuxProcessCeilingsData::current() != self.target
        {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        self.authenticate_enforcement_after_origin()
    }

    fn authenticate_enforcement_after_origin(&self) -> Result<(), LinuxProcessSupervisorError> {
        current::authenticate(self.target)?;
        if LinuxProcessCeilingsData::current() != self.target {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_bootstrap_never_raises_stricter_inherited_ceiling()
    -> Result<(), LinuxProcessSupervisorError> {
        let exact = Rlimit {
            current: Some(17),
            maximum: Some(17),
        };
        assert_eq!(
            no_greater(exact, 16)?,
            Rlimit {
                current: Some(16),
                maximum: Some(16)
            }
        );
        assert_eq!(no_greater(exact, 18)?, exact);
        assert_eq!(
            no_greater(
                Rlimit {
                    current: Some(11),
                    maximum: Some(17)
                },
                16
            )?,
            Rlimit {
                current: Some(11),
                maximum: Some(11)
            }
        );
        assert_eq!(
            no_greater(
                Rlimit {
                    current: None,
                    maximum: None
                },
                19
            )?,
            Rlimit {
                current: Some(19),
                maximum: Some(19)
            }
        );
        assert_eq!(
            no_greater(exact, 0),
            Err(LinuxProcessSupervisorError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn a_foreign_prepared_owner_is_spent_before_any_kernel_update() {
        // Deliberately invalid private test state can prove refusal/once order,
        // never completed deployment or permission to run a real process.
        let ceilings = LinuxProcessCeilingsData {
            cpu: Rlimit {
                current: Some(17),
                maximum: Some(17),
            },
            address_space: Rlimit {
                current: Some(19),
                maximum: Some(19),
            },
            descriptors: Rlimit {
                current: Some(23),
                maximum: Some(23),
            },
        };
        let mut original = LinuxProcessSupervisor {
            process: 0,
            thread: std::thread::current().id(),
            target: ceilings,
            original: ceilings,
            complete: false,
            installation_attempted: false,
        };
        let before = original.previous_ceiling_data();
        assert_eq!(
            original.install_prepared_before_actors(),
            Err(LinuxProcessSupervisorError::ForeignAuthority)
        );
        assert!(original.installation_attempted && !original.complete);
        assert_eq!(original.previous_ceiling_data(), before);
        assert_eq!(
            original.install_prepared_before_actors(),
            Err(LinuxProcessSupervisorError::DuplicateOperation)
        );
        assert_eq!(
            original.authenticate_current(),
            Err(LinuxProcessSupervisorError::ForeignAuthority)
        );
    }
}
