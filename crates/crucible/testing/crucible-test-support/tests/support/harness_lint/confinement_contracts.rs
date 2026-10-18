//! Binds reviewed operational exports to their exact source and declaration.
//!
//! The grouped exports expose closed owner, cause, and publication types. The
//! two service-phase helpers additionally bind their entire implementation:
//! admission preserves the authenticated Main start, and retained verification
//! checks the existing phase without entering or renewing an operation. Changes
//! to these bodies require reviewing this contract and its negative controls.

use std::path::Path;

use super::{Token, scrub_comments_and_strings};

struct ExportContract {
    path: &'static str,
    source: &'static str,
}

const CONTRACTS: &[ExportContract] = &[
    ExportContract {
        path: "crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
        source: r#"pub(crate) use target_dispatcher::TargetDispatcher;"#,
    },
    ExportContract {
        path: "crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
        source: r#"pub(crate) use memory_control::tighten_process_envelope;"#,
    },
    ExportContract {
        path: "crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
        source: r#"pub use memory_events::LinuxQemuMemoryLimitFailure;"#,
    },
    ExportContract {
        path: "crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
        source: r#"pub(crate) use attempt_owner::{
    LinuxQemuAttemptProcessOwner, LinuxQemuAttemptProcessOwnerError,
    LinuxQemuAttemptProcessOwnerStatus,
};"#,
    },
    ExportContract {
        path: "crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
        source: r#"pub(crate) const fn source_error(&self) -> &LinuxQemuCgroupError {
    &self.source
}"#,
    },
    ExportContract {
        path: "crucible/host/crucible-host-resources/src/host_supervision.rs",
        source: r#"pub use action_loan::{
    HostActionLoan, HostActionPublisher, HostActionReturnReceipt, HostParentParkReturnReceipt,
};"#,
    },
    ExportContract {
        path: "crucible/host/crucible-host-resources/src/host_supervision.rs",
        source: r#"pub use source_publication::{SourceSupervisionPublisher, SourceSupervisionSnapshot};"#,
    },
    ExportContract {
        path: "crucible/host/crucible-host-resources/src/host_supervision.rs",
        source: r#"pub(crate) fn from_service_interval(
        budgets: HostOperationBudgets,
        start_us: u64,
        end_us: u64,
    ) -> Result<Self, HostSupervisionError> {
        let sampled = host_now();
        let now_ns = kernel_monotonic_ns()?;
        let start_ns = start_us
            .checked_mul(1000)
            .ok_or(HostSupervisionError::InvalidBudget)?;
        let end_ns = end_us
            .checked_mul(1000)
            .ok_or(HostSupervisionError::InvalidBudget)?;
        if start_ns == 0 || start_ns > now_ns || end_ns <= now_ns {
            return Err(HostSupervisionError::InvalidBudget);
        }
        // Instant is sampled first: conversion may shorten, never renew, the
        // authenticated main interval. The temporary owner is not published.
        let started = sampled
            .checked_sub(Duration::from_nanos(now_ns - start_ns))
            .ok_or(HostSupervisionError::InvalidBudget)?;
        let span = Duration::from_nanos(end_ns - start_ns);
        budgets.validate(true)?;
        let ordinal = NEXT_CAP_ID
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |ordinal| {
                ordinal.checked_add(1)
            })
            .map_err(|_| HostSupervisionError::IdentityExhausted)?;
        let mut cap_id = [0; 32];
        cap_id[24..].copy_from_slice(&ordinal.to_be_bytes());
        let supervisor = Self::publish(
            budgets,
            Some(span),
            started,
            start_ns,
            cap_id,
            Arc::new(Condvar::new()),
            Some(span),
        )?;
        supervisor.verify_original_live()?;
        Ok(supervisor)
    }"#,
    },
    ExportContract {
        path: "crucible/host/crucible-host-resources/src/host_supervision.rs",
        source: r#"pub(crate) fn verify_retained_phase(&self) -> Result<(), HostSupervisionError> {
        #[cfg(feature = "private-measurement-domain")]
        self.check_original_preparation()?;
        self.supervisor.verify_original_live()?;
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        if decision.state == HostOperationState::Completed {
            return Ok(());
        }
        decision.require_running(self.id)
    }"#,
    },
    ExportContract {
        path: "crucible/host/crucible-host-resources/src/measurement_origin.rs",
        source: r#"pub use actor_family::AuthenticatedActorFamily;"#,
    },
];

pub(super) fn reviewed_export(path: &Path, content: &str, tokens: &[Token], index: usize) -> bool {
    let Some(tail) = public_item_tail(content, tokens, index) else {
        return false;
    };
    let actual = compact(&tail);
    CONTRACTS.iter().any(|contract| {
        path.ends_with(contract.path) && actual.starts_with(&compact(contract.source))
    })
}

// Select the actual visibility token, including when several items share a
// line. Comment/string occurrences cannot select a neighboring valid export.
fn public_item_tail(content: &str, tokens: &[Token], index: usize) -> Option<String> {
    let line = tokens.get(index)?.line;
    let ordinal = tokens[..index]
        .iter()
        .rev()
        .take_while(|token| token.line == line)
        .filter(|token| token.kind.as_ident() == Some("pub"))
        .count();
    let scrubbed: Vec<char> = scrub_comments_and_strings(content).chars().collect();
    let original: Vec<char> = content.chars().collect();
    let mut current_line = 1;
    let mut occurrence = 0;
    for offset in 0..scrubbed.len() {
        if current_line == line
            && scrubbed[offset..].starts_with(&['p', 'u', 'b'])
            && (offset == 0 || !identifier_character(scrubbed[offset - 1]))
            && scrubbed
                .get(offset + 3)
                .is_none_or(|ch| !identifier_character(*ch))
        {
            if occurrence == ordinal {
                return Some(original[offset..].iter().collect());
            }
            occurrence += 1;
        }
        if scrubbed[offset] == '\n' {
            current_line += 1;
        }
        if current_line > line {
            break;
        }
    }
    None
}

fn identifier_character(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}

// Retain operators, numeric literals, and feature names. The general lint
// tokenizer intentionally omits some of them and cannot bind a clock formula.
fn compact(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
#[path = "confinement_contracts/tests.rs"]
mod tests;
