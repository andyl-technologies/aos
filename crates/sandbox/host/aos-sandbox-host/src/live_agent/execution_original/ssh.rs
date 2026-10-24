//! Prices SSH's actual source and descendant before the existing Agent issue.
//!
//! These values are comparison DATA. Only the accepted execution's original
//! consumed purpose20 can debit the complete requirement before parking them
//! on its own existing AgentExecutionOriginalV2.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct GuestSshSourceQuoteDataV1 {
    pub(crate) memory: u64,
    pub(crate) nofile: u32,
    pub(crate) copied_files: u32,
    pub(crate) highest_fd: u32,
    pub(crate) demand: ResourceVector,
}

impl GuestSshSourceQuoteDataV1 {
    pub(crate) fn derive(available: ResourceVector) -> Option<Self> {
        use aos_sandbox_linux::guest_cgroup::{GuestSshBirthSourceOriginalV1, GuestSshScopeOriginalV1};
        use aos_sandbox_linux::seqpacket::descriptor_subject::GuestSshBootstrapOriginalV1;

        let source = GuestSshBirthSourceOriginalV1::receiving_obligations_v1()?;
        let channel = GuestSshBootstrapOriginalV1::receiving_obligations_v1()?;
        let scope = GuestSshScopeOriginalV1::receiving_obligations_v1(1)?;
        let fixed_files = u64::try_from(source.1.checked_add(channel.1)?.checked_add(scope.1)?).ok()?;
        let variable_files = available.get(D::OpenFiles).checked_sub(fixed_files)?;

        // Independent finite source and descendant shares prevent the child's
        // nofile from being mistaken for a retroactive bound on parent FDs.
        // An inherited high FD is accepted only if the separate table permit
        // and actual collector fit; it can otherwise deny this quoted recipe.
        let source_files = variable_files / 2;
        let copied_files = u32::try_from(source_files / 2).ok()?;
        let nofile = u32::try_from((variable_files - source_files) / 4).ok()?;
        if copied_files == 0 || nofile < 3 || available.get(D::Pids) < 3 { return None; }
        let scope = GuestSshScopeOriginalV1::receiving_obligations_v1(copied_files)?;
        let controls = u64::try_from(source.0.checked_add(channel.0)?.checked_add(scope.0)?).ok()?;
        let variable_memory = available.get(D::MemoryBytes).checked_sub(controls)?;
        let source_memory = variable_memory / 2;
        let memory = variable_memory - source_memory;
        if memory == 0 { return None; }

        // Find the largest explicit inclusive table position paid by this
        // source share. No host RLIMIT or guessed kernel layout participates.
        let mut lower = 2_u64;
        let mut upper = u64::from(u32::MAX);
        if aos_sandbox_linux::kernel_clone::dominant_birth_bytes_data_v1(lower, 5)? > source_memory {
            return None;
        }
        while lower < upper {
            let middle = lower.checked_add((upper - lower + 1) / 2)?;
            match aos_sandbox_linux::kernel_clone::dominant_birth_bytes_data_v1(middle, 5) {
                Some(bytes) if bytes <= source_memory => lower = middle,
                _ => upper = middle - 1,
            }
        }
        let highest_fd = u32::try_from(lower).ok()?;
        let clone_bytes = aos_sandbox_linux::kernel_clone::dominant_birth_bytes_data_v1(lower, 5)?;
        let notes = aos_sandbox_linux::kernel_clone::configured_notes_bytes_data_v1()?.checked_add(1)?;
        let files = fixed_files.checked_add(u64::from(copied_files).checked_mul(2)?)?
            .checked_add(u64::from(nofile).checked_mul(4)?)?;
        let names = u64::try_from(source.2.checked_add(channel.2)?.checked_add(scope.2)?).ok()?;
        let demand = ResourceVector::ZERO
            .with(D::MemoryBytes, controls.checked_add(clone_bytes)?.checked_add(memory)?)
            .with(D::OpenFiles, files)
            // The enclosing real Guest-lifetime invoice already retains one
            // daemon PID. These three complete the enforced whole SSH four;
            // the original Tenant child remains independently counted there.
            .with(D::Pids, 3)
            .with(D::MetadataEntries, names)
            // Original request192, receipt88 and release40; the same private
            // EOF probe consumes no additional record or network permission.
            .with(D::NetworkBytes, 192 + 88 + 40)
            .with(D::OutputBytes, notes);
        available.checked_sub(demand).ok()?;
        Some(Self { memory, nofile, copied_files, highest_fd, demand })
    }
}
