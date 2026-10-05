//! Advisory copies of original idle-plan selection and callback return paths.
//!
//! The exact Linux runtime opt-in and aggregate allowance admit at most 256
//! rows, each at most 512 bytes. A plan reserves its return allowance before the
//! original wait. Identical rows are omitted; contention, exhaustion, PID mismatch
//! and failed captures lose only observations. Missing rows are inconclusive.
//! No control request, native grant or callback completion is minted here.
//! Existing capture policy preserves descriptor flags and signal disposition.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::sync::Mutex;

use crucible_shmem::AdvanceStopCondition;

use crate::{ExactDeadlineReport, IdleWakePlan};

use super::device_wait_witness::capture::destination;

const MAX_ROWS: usize = 256;

pub(super) struct IdlePlanWitness {
    budget: usize,
    owner_pid: u32,
    inventory: Mutex<Inventory>,
    #[cfg(test)]
    pub(super) destination: Option<Mutex<std::fs::File>>,
}

impl IdlePlanWitness {
    pub(super) fn from_env() -> Self {
        Self::from_settings(
            std::env::var_os("CRUCIBLE_OUT_RESUME_RUNTIME_TRACE").as_deref(),
            std::env::var_os("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS").as_deref(),
        )
    }

    fn from_settings(runtime_trace: Option<&OsStr>, aggregate: Option<&OsStr>) -> Self {
        let setting = if runtime_trace == Some(OsStr::new("1")) {
            aggregate
        } else {
            None
        };
        Self::from_setting(setting)
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
            owner_pid: if budget == 0 { 0 } else { std::process::id() },
            inventory: Mutex::new(Inventory::default()),
            #[cfg(test)]
            destination: None,
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
        if self.budget == 0 || self.owner_pid != std::process::id() {
            return None;
        }
        let plan = PlanRecord {
            pid: self.owner_pid,
            vcpu,
            raw,
            plan,
            exact_deadline,
            stop,
        };
        let record = Record {
            plan,
            outcome: None,
        };
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
        Some(PlanObservation(plan))
    }

    /// Copies the exact original return choice, not native RR execution.
    pub(super) fn end(&self, observation: Option<PlanObservation>, outcome: Outcome) {
        let Some(PlanObservation(plan)) = observation else {
            return;
        };
        if plan.pid != self.owner_pid || self.owner_pid != std::process::id() {
            return;
        }
        let record = Record {
            plan,
            outcome: Some(outcome),
        };
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
        let mut bytes = [0_u8; 512];
        let mut writer = io::Cursor::new(bytes.as_mut_slice());
        if record.write_to(&mut writer).is_err() {
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
    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        let plan = self.plan;
        writeln!(
            writer,
            "CRUCIBLE-IDLE-PLAN-V1 phase={} pid={} vcpu={} raw={} current_ps={} ceiling_ps={} stop={:?} wake_ps={} cause={:?} exact_deadline={:?} timer_ps={:?} inbound_ps={:?} device_ps={:?} device_active={} outcome={:?}",
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
