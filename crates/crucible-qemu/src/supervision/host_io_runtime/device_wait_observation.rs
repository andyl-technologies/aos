//! Literal device-deadline ownership captured by the original publication path.
//!
//! Queued heads are the immutable sorted device response. A worker pin is only
//! a provisional candidate and is never substituted for an older computed head.
//! All values are advisory host-local data; no device state is restored from them.

use std::io::{self, Write};

use crucible_shmem::FrameDeliveryKey;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CompletionCandidate {
    pub(super) deadline: Option<u64>,
    head: Option<(FrameDeliveryKey, u32)>,
    pin: Option<(u64, Option<u32>, u64, u64)>,
    worker_active: bool,
}

impl CompletionCandidate {
    pub(super) fn queued(deadline: Option<u64>, head: Option<(FrameDeliveryKey, u32)>) -> Self {
        Self {
            deadline,
            head,
            ..Self::default()
        }
    }

    pub(super) fn worker(deadline: Option<u64>, pin: Option<(u64, Option<u32>, u64, u64)>) -> Self {
        Self {
            deadline,
            pin,
            worker_active: true,
            ..Self::default()
        }
    }

    fn write_to(self, writer: &mut impl Write, family: &str) -> io::Result<()> {
        write!(
            writer,
            " {family}_due={:?} {family}_phase={}",
            self.deadline,
            if self.worker_active {
                "worker"
            } else {
                "queue"
            }
        )?;
        write!(writer, " {family}_head=")?;
        match self.head {
            Some((key, request)) => write!(
                writer,
                "{}:{}:{}:{}",
                key.delivery_icount, key.src_node, key.seq, request
            )?,
            None => write!(writer, "unavailable")?,
        }
        write!(writer, " {family}_owner_request=")?;
        match self
            .head
            .filter(|(key, _)| Some(key.delivery_icount) == self.deadline)
        {
            Some((_, request)) if !self.worker_active => write!(writer, "{request}")?,
            _ => write!(writer, "unavailable")?,
        }
        if family == "block" {
            write!(writer, " block_pin=")?;
            match self.pin {
                Some((sequence, request, tick, horizon)) => {
                    write!(writer, "{sequence}:{request:?}:{tick}:{horizon}")?
                }
                None => write!(writer, "unavailable")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DeviceDeadlines {
    pub(super) block: CompletionCandidate,
    pub(super) ninep: CompletionCandidate,
    pub(super) accelerator: Option<u64>,
}

impl DeviceDeadlines {
    fn minimum_mask(self) -> u8 {
        let minimum = [self.block.deadline, self.ninep.deadline, self.accelerator]
            .into_iter()
            .flatten()
            .min();
        let Some(minimum) = minimum else {
            return 0;
        };
        u8::from(self.block.deadline == Some(minimum))
            | (u8::from(self.ninep.deadline == Some(minimum)) << 1)
            | (u8::from(self.accelerator == Some(minimum)) << 2)
    }
}

pub(super) fn write_deadlines(
    writer: &mut impl Write,
    observation: Option<DeviceDeadlines>,
) -> io::Result<()> {
    let Some(observation) = observation else {
        return write!(writer, " device_min_families=unavailable");
    };
    // Bits 1/2/4 identify block/9P/accelerator, including coincident minima.
    write!(
        writer,
        " device_min_families={}",
        observation.minimum_mask()
    )?;
    observation.block.write_to(writer, "block")?;
    observation.ninep.write_to(writer, "ninep")?;
    write!(writer, " accelerator_due={:?}", observation.accelerator)
}
