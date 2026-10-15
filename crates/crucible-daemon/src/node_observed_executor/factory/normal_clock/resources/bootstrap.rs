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
pub struct OriginalClockProcessBootstrap {
    process: u32,
    thread: ThreadId,
    target: ProcessCeilings,
    original: ProcessCeilings,
    complete: bool,
}

fn no_greater(current: Rlimit, requested: u64) -> Result<Rlimit, RuntimeError> {
    if requested == 0 {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut value = requested;
    if let Some(soft) = current.current {
        value = value.min(soft);
    }
    if let Some(hard) = current.maximum {
        value = value.min(hard);
    }
    if value == 0 {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(Rlimit {
        current: Some(value),
        maximum: Some(value),
    })
}

fn single_original_task(process: u32) -> Result<(), RuntimeError> {
    let path = PathBuf::from(format!("/proc/{process}/task"));
    let mut tasks = fs::read_dir(path).map_err(|_| RuntimeError::UnsupportedFacet)?;
    let first = tasks
        .next()
        .ok_or(RuntimeError::ForeignAuthority)?
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
    if first
        .file_name()
        .to_str()
        .and_then(|name| name.parse::<u32>().ok())
        != Some(process)
        || tasks.next().is_some()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    // Single-threaded deployment must also precede child birth. A byte is
    // enough to refuse any existing child without allocating its whole roster.
    let mut children = fs::File::open(format!("/proc/{process}/task/{process}/children"))
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
    let mut byte = [0u8; 1];
    if children
        .read(&mut byte)
        .map_err(|_| RuntimeError::UnsupportedFacet)?
        != 0
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

impl OriginalClockProcessBootstrap {
    /// Lowers actual shared-process ceilings before creating service actors.
    ///
    /// A production entry point calls this while still single-threaded and
    /// before spawning children. This is a whole-daemon deployment decision:
    /// CPU exhaustion can terminate every world in that process. It must never
    /// be invoked as per-node admission inside an existing shared service.
    /// The kernel task census enforces the available current-thread boundary;
    /// the called entry point must also own startup and forbid concurrent birth.
    ///
    /// # Errors
    /// Refuses an occupied slot, multiple threads, invalid ceilings, any failed
    /// kernel update or failed exact readback. Partial hard-limit changes remain
    /// installed and their original owner remains in `slot`; no rollback/retry
    /// or budget extension is attempted.
    pub fn install_before_actors_into(
        slot: &mut Option<Self>,
        limits: &ResourceLimits,
    ) -> Result<(), RuntimeError> {
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let process = std::process::id();
        single_original_task(process)?;
        let old = ProcessCeilings::current();
        let target = ProcessCeilings {
            cpu: no_greater(old.cpu, limits.cpu_budget_ns.get() / 1_000_000_000)?,
            address_space: no_greater(old.address_space, limits.memory_bytes.get())?,
            descriptors: no_greater(old.descriptors, limits.descriptors.get())?,
        };
        // Refuse preexisting resources above the proposed new limits before
        // making any irreversible change. A lowered rlimit cannot evict them.
        current::authenticate(target)?;
        if ProcessCeilings::current() != old {
            return Err(RuntimeError::ForeignAuthority);
        }
        *slot = Some(Self {
            process,
            thread: std::thread::current().id(),
            target,
            original: old,
            complete: false,
        });
        for (resource, value) in [
            (Resource::Cpu, target.cpu),
            (Resource::As, target.address_space),
            (Resource::Nofile, target.descriptors),
        ] {
            single_original_task(process)?;
            setrlimit(resource, value).map_err(|_| RuntimeError::ResourceLimit)?;
            if getrlimit(resource) != value {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        single_original_task(process)?;
        let owner = slot.as_mut().ok_or(RuntimeError::OutstandingObligations)?;
        if owner.process != std::process::id()
            || owner.thread != std::thread::current().id()
            || ProcessCeilings::current() != owner.target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        current::authenticate(owner.target)?;
        if ProcessCeilings::current() != owner.target {
            return Err(RuntimeError::ForeignAuthority);
        }
        owner.complete = true;
        Ok(())
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
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.complete
            || ProcessCeilings::current() != self.target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        current::authenticate(self.target)?;
        if ProcessCeilings::current() != self.target {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_bootstrap_never_raises_stricter_inherited_ceiling() -> Result<(), RuntimeError> {
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
        assert_eq!(no_greater(exact, 0), Err(RuntimeError::ResourceLimit));
        Ok(())
    }
}
