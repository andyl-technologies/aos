//! Advisory copies of original idle-plan selection and callback return paths.
//!
//! The exact Linux runtime opt-in and aggregate allowance admit at most 256
//! rows, each at most 512 bytes. A plan reserves its return allowance before the
//! original wait. Identical rows are omitted; contention, exhaustion, PID mismatch
//! and failed captures lose only observations. Missing rows are inconclusive.
//! An optional picosecond floor filters already-computed plans before admission;
//! it does not authorize time or consume allowance for earlier boot plans.
//! No control request, native grant or callback completion is minted here.
//! Existing capture policy preserves descriptor flags and signal disposition.
//!
//! The runtime opt-in alone also keeps the newest plans and returns in a small
//! ring, regardless of floor or allowance. A stall trace flushes that ring as
//! `CRUCIBLE-IDLE-PLAN-RECENT-V1` rows, so the plans nearest an unforeseeable
//! stall survive even after the admitted allowance was spent earlier.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::sync::Mutex;

use crucible_shmem::AdvanceStopCondition;

use crate::{ExactDeadlineReport, IdleWakePlan};

use super::device_wait_witness::capture::destination;

const MAX_ROWS: usize = 256;

/// Newest plan and return records the rolling ring keeps.
const RECENT_ROWS: usize = 32;

pub(super) struct IdlePlanWitness {
    budget: usize,
    minimum_ps: u64,
    owner_pid: u32,
    inventory: Mutex<Inventory>,
    recent: Option<Mutex<RecentPlans>>,
    #[cfg(test)]
    pub(super) destination: Option<Mutex<std::fs::File>>,
}

impl IdlePlanWitness {
    pub(super) fn from_env() -> Self {
        Self::from_settings(
            std::env::var_os("CRUCIBLE_OUT_RESUME_RUNTIME_TRACE").as_deref(),
            std::env::var_os("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS").as_deref(),
            std::env::var_os("CRUCIBLE_IDLE_PLAN_DIAGNOSTIC_MIN_PS").as_deref(),
        )
    }

    pub(super) fn from_settings(
        runtime_trace: Option<&OsStr>,
        aggregate: Option<&OsStr>,
        minimum: Option<&OsStr>,
    ) -> Self {
        let minimum_ps = match minimum {
            None => Some(0),
            Some(value) => value.to_str().and_then(|text| {
                text.parse::<u64>()
                    .ok()
                    .filter(|value| *value <= i64::MAX as u64 && value.to_string() == text)
            }),
        };
        let setting = if runtime_trace == Some(OsStr::new("1")) && minimum_ps.is_some() {
            aggregate
        } else {
            None
        };
        let mut witness = Self::from_setting(setting);
        witness.minimum_ps = minimum_ps.unwrap_or(0);
        if runtime_trace == Some(OsStr::new("1")) {
            witness.recent = Some(Mutex::new(RecentPlans::default()));
        }
        witness
    }

    pub(super) fn from_setting(setting: Option<&OsStr>) -> Self {
        let budget = setting
            .and_then(OsStr::to_str)
            .and_then(|text| {
                text.parse::<usize>()
                    .ok()
                    .filter(|value| (1..=MAX_ROWS).contains(value) && value.to_string() == text)
            })
            .unwrap_or(0);
        Self {
            budget,
            minimum_ps: 0,
            owner_pid: if budget == 0 { 0 } else { std::process::id() },
            inventory: Mutex::new(Inventory::default()),
            recent: None,
            #[cfg(test)]
            destination: None,
        }
    }

    /// Rebinds an enabled witness to a forked child with a fresh allowance.
    ///
    /// A hot-fork child inherits the parent's PID binding and spent inventory;
    /// without this every child row would be dropped as a PID mismatch.
    pub(super) fn rebind(&mut self) {
        if self.budget == 0 {
            return;
        }
        self.owner_pid = std::process::id();
        self.inventory = Mutex::new(Inventory::default());
    }

    /// Writes the rolling ring, oldest first, without consuming it.
    ///
    /// Each record is copied at most once per flush; contention skips the
    /// flush rather than block the caller.
    pub(super) fn flush_recent(&self) {
        let Some(recent) = &self.recent else {
            return;
        };
        let records = {
            let Ok(recent) = recent.try_lock() else {
                return;
            };
            recent.oldest_first()
        };
        for record in records {
            self.emit_with_prefix(record, RECENT_PREFIX);
        }
    }

    /// Pairs an unadmitted return with the newest unanswered plan in the ring.
    ///
    /// Each idle callback ends the plan it began on the same vCPU thread, so
    /// the newest open plan is normally its own; interleaved vCPUs can only
    /// mispair advisory rows.
    fn remember_unadmitted_return(&self, outcome: Outcome) {
        if let Some(recent) = &self.recent
            && let Ok(mut recent) = recent.try_lock()
            && let Some(plan) = recent.newest_open_plan()
        {
            recent.push(Record {
                plan,
                outcome: Some(outcome),
            });
        }
    }

    fn remember(&self, record: Record) {
        if let Some(recent) = &self.recent
            && let Ok(mut recent) = recent.try_lock()
        {
            recent.push(record);
        }
    }

    /// Reserves both rows without altering the plan or the admitted wait.
    pub(super) fn begin(
        &self,
        vcpu: u32,
        raw: u64,
        plan: IdleWakePlan,
        exact_deadline: ExactDeadlineReport,
        stop: AdvanceStopCondition,
    ) -> Option<PlanObservation> {
        let record = Record {
            plan: PlanRecord {
                pid: std::process::id(),
                vcpu,
                raw,
                plan,
                exact_deadline,
                stop,
            },
            outcome: None,
        };
        // Every plan enters the rolling ring; only an admitted plan reserves
        // allowance and emits rows.
        self.remember(record);
        if plan.current_icount() < self.minimum_ps
            || self.budget == 0
            || self.owner_pid != std::process::id()
        {
            return None;
        }
        let emit = {
            let Ok(mut inventory) = self.inventory.try_lock() else {
                return None;
            };
            let duplicate = inventory.contains(record);
            let needed = 1 + usize::from(!duplicate);
            if inventory.count + inventory.reserved + needed > self.budget {
                return None;
            }
            inventory.reserved += 1;
            if !duplicate {
                inventory.insert(record);
            }
            !duplicate
        };
        if emit {
            self.emit(record);
        }
        Some(PlanObservation(record.plan))
    }

    /// Copies the exact original return choice, not native RR execution.
    pub(super) fn end(&self, observation: Option<PlanObservation>, outcome: Outcome) {
        let Some(PlanObservation(plan)) = observation else {
            self.remember_unadmitted_return(outcome);
            return;
        };
        let record = Record {
            plan,
            outcome: Some(outcome),
        };
        self.remember(record);
        if plan.pid != self.owner_pid || self.owner_pid != std::process::id() {
            return;
        }
        {
            let Ok(mut inventory) = self.inventory.try_lock() else {
                return;
            };
            // A dropped return conservatively keeps its reserved allowance.
            inventory.reserved = inventory.reserved.saturating_sub(1);
            if inventory.contains(record) {
                return;
            }
            inventory.insert(record);
        }
        self.emit(record);
    }

    fn emit(&self, record: Record) {
        self.emit_with_prefix(record, ADMITTED_PREFIX);
    }

    fn emit_with_prefix(&self, record: Record, prefix: &str) {
        let mut bytes = [0_u8; 512];
        let mut writer = io::Cursor::new(bytes.as_mut_slice());
        if record.write_to(&mut writer, prefix).is_err() {
            return;
        }
        let length = writer.position() as usize;
        #[cfg(test)]
        if let Some(source) = &self.destination {
            let Ok(source) = source.try_lock() else {
                return;
            };
            if let Ok(destination) = destination(&*source) {
                let _ = (&destination).write(&bytes[..length]);
            }
            return;
        }
        if let Ok(destination) = destination(&io::stderr()) {
            let _ = (&destination).write(&bytes[..length]);
        }
    }
}

struct Inventory {
    rows: [Option<Record>; MAX_ROWS],
    count: usize,
    reserved: usize,
}

impl Inventory {
    fn contains(&self, record: Record) -> bool {
        self.rows[..self.count].contains(&Some(record))
    }

    fn insert(&mut self, record: Record) {
        self.rows[self.count] = Some(record);
        self.count += 1;
    }
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            rows: [None; MAX_ROWS],
            count: 0,
            reserved: 0,
        }
    }
}

/// Fixed-capacity ring of the newest plan and return records.
#[derive(Default)]
struct RecentPlans {
    rows: [Option<Record>; RECENT_ROWS],
    next: usize,
}

impl RecentPlans {
    fn push(&mut self, record: Record) {
        self.rows[self.next] = Some(record);
        self.next = (self.next + 1) % RECENT_ROWS;
    }

    fn newest_open_plan(&self) -> Option<PlanRecord> {
        self.oldest_first()
            .into_iter()
            .rev()
            .find(|record| record.outcome.is_none())
            .map(|record| record.plan)
    }

    fn oldest_first(&self) -> Vec<Record> {
        self.rows[self.next..]
            .iter()
            .chain(&self.rows[..self.next])
            .flatten()
            .copied()
            .collect()
    }
}

const ADMITTED_PREFIX: &str = "CRUCIBLE-IDLE-PLAN-V1";
const RECENT_PREFIX: &str = "CRUCIBLE-IDLE-PLAN-RECENT-V1";

// The token is deliberately not Copy or Clone: one admitted wait has one return.
pub(super) struct PlanObservation(PlanRecord);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    ReturnToQemu,
    RescanInQemu,
    AlreadyDueReturn(u64),
    AdvanceSelected(u64),
    WaitError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanRecord {
    pid: u32,
    vcpu: u32,
    raw: u64,
    plan: IdleWakePlan,
    exact_deadline: ExactDeadlineReport,
    stop: AdvanceStopCondition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    plan: PlanRecord,
    outcome: Option<Outcome>,
}

impl Record {
    fn write_to(self, writer: &mut impl Write, prefix: &str) -> io::Result<()> {
        let plan = self.plan;
        writeln!(
            writer,
            "{prefix} phase={} pid={} vcpu={} raw={} current_ps={} ceiling_ps={} stop={:?} wake_ps={} cause={:?} exact_deadline={:?} timer_ps={:?} inbound_ps={:?} device_ps={:?} device_active={} outcome={:?}",
            if self.outcome.is_some() {
                "return"
            } else {
                "plan"
            },
            plan.pid,
            plan.vcpu,
            plan.raw,
            plan.plan.current_icount(),
            plan.plan.ceiling_icount(),
            plan.stop,
            plan.plan.desired_wake_icount(),
            plan.plan.cause(),
            plan.exact_deadline,
            plan.plan.timer_deadline_icount(),
            plan.plan.inbound_delivery_icount(),
            plan.plan.device_completion_deadline_tick(),
            u8::from(plan.plan.device_io_holding_ticks()),
            self.outcome,
        )
    }
}

#[cfg(test)]
mod tests;
