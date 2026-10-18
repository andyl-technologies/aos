//! Advisory device-wait transitions copied from original callback decisions.
//!
//! The existing aggregate setting admits an independent stream of at most 256
//! rows, each at most 512 bytes. This is not the control witness's budget or a
//! process-wide combined limit. Retry deduplication, contention, missing identity,
//! PID mismatch and failed capture lose only observations. No native getter or
//! canonical mutex is acquired to fill a missing field. Each pending advance
//! retains its original immutable request attribution through nested callbacks.
//!
//! Regular captures share their existing file cursor and filesystem latency.
//! Linux FIFO captures use an independent nonblocking descriptor only when
//! a read-only disposition check proves SIGPIPE is already ignored. Other
//! unsupported destinations are dropped; writes have no retry or stdio lock.
//! No blocking pipe writer, worker, queue, clock or runtime admission is introduced.
//!
//! ```text
//! CRUCIBLE-DEVICE-WAIT-V1 phase=enqueue pid=42 request=7 slot=0 generation=1 device=2 inode=3 length=4096 current=100 deadline=200 raw=2 target=200 arm=1 status=0 result=accepted
//! ```

use std::ffi::OsStr;
use std::io::{self, Write};
use std::sync::Mutex;

use super::control_callback_stage::ControlStageIdentity;
pub(in crate::runtime) mod capture;
use capture::destination;

const MAX_ROWS: usize = 256;

pub(super) struct DeviceWaitWitness {
    budget: usize,
    owner_pid: u32,
    inventory: Mutex<Inventory>,
    #[cfg(test)]
    pub(super) destination: Option<Mutex<std::fs::File>>,
}

impl DeviceWaitWitness {
    pub(super) fn from_env() -> Self {
        Self::from_setting(
            std::env::var_os("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS").as_deref(),
        )
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

    pub(super) fn rebind(&mut self) {
        if self.budget == 0 {
            return;
        }
        self.owner_pid = std::process::id();
        self.inventory = Mutex::new(Inventory::default());
    }

    pub(super) fn request(
        &self,
        request: u32,
        identity: Option<ControlStageIdentity>,
    ) -> Option<RequestObservation> {
        if self.budget == 0 || self.owner_pid != std::process::id() {
            return None;
        }
        Some(RequestObservation {
            pid: self.owner_pid,
            request,
            identity,
            current: None,
            deadline: None,
            exact_deadline: None,
        })
    }

    pub(super) fn emit(
        &self,
        request: Option<RequestObservation>,
        phase: &'static str,
        advance: (Option<u64>, Option<u64>, Option<u64>),
        completion: (Option<i32>, Option<i64>),
        result: &'static str,
    ) {
        let Some(request) = request else {
            return;
        };
        if self.budget == 0 || request.pid != self.owner_pid || self.owner_pid != std::process::id()
        {
            return;
        }
        let (raw, target, arm) = advance;
        let (status, echo_target) = completion;
        let record = Record {
            request,
            phase,
            raw,
            target,
            arm,
            status,
            echo_target,
            result,
        };
        {
            let Ok(mut inventory) = self.inventory.try_lock() else {
                return;
            };
            if inventory.count == self.budget
                || inventory.rows[..inventory.count].contains(&Some(record))
            {
                return;
            }
            let index = inventory.count;
            inventory.rows[index] = Some(record);
            inventory.count += 1;
        }
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
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            rows: [None; MAX_ROWS],
            count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RequestObservation {
    pid: u32,
    request: u32,
    identity: Option<ControlStageIdentity>,
    pub(super) current: Option<u64>,
    pub(super) deadline: Option<u64>,
    pub(super) exact_deadline: Option<crate::ExactDeadlineReport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    request: RequestObservation,
    phase: &'static str,
    raw: Option<u64>,
    target: Option<u64>,
    arm: Option<u64>,
    status: Option<i32>,
    echo_target: Option<i64>,
    result: &'static str,
}

impl Record {
    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "CRUCIBLE-DEVICE-WAIT-V1 phase={} pid={} request={}",
            self.phase, self.request.pid, self.request.request
        )?;
        if let Some(identity) = self.request.identity {
            let (backing, slot, generation) = identity.parts();
            write!(
                writer,
                " slot={slot} generation={generation} device={} inode={} length={}",
                backing.device(),
                backing.inode(),
                backing.length()
            )?;
        } else {
            write!(
                writer,
                " slot=unavailable generation=unavailable device=unavailable inode=unavailable length=unavailable"
            )?;
        }
        for (name, value) in [
            ("current", self.request.current),
            ("deadline", self.request.deadline),
            ("raw", self.raw),
            ("target", self.target),
            ("arm", self.arm),
        ] {
            write!(writer, " {name}=")?;
            match value {
                Some(value) => write!(writer, "{value}")?,
                None => write!(writer, "unavailable")?,
            }
        }
        write!(writer, " exact_deadline=")?;
        match self.request.exact_deadline {
            None => write!(writer, "unavailable")?,
            Some(crate::ExactDeadlineReport::NoArmedTimer) => write!(writer, "none")?,
            Some(crate::ExactDeadlineReport::Armed { deadline_ps }) => {
                write!(writer, "{deadline_ps}")?
            }
        }
        if let Some(target) = self.echo_target {
            write!(writer, " echo_target={target}")?;
        }
        write!(writer, " status=")?;
        match self.status {
            Some(status) => write!(writer, "{status}")?,
            None => write!(writer, "unavailable")?,
        }
        writeln!(writer, " result={}", self.result)
    }
}

#[cfg(test)]
mod tests;
