//! SPDX-License-Identifier: GPL-2.0-or-later
//! Opt-in, charged application I/O measurements outside guest execution paths.

use std::io;
use std::sync::Mutex;

use crucible_protocol::ram_control::{
    RAM_PERFORMANCE_BANK_RESERVE_BYTES, RAM_PERFORMANCE_IO_CLASSES, RamControlIoClass,
    RamControlIoMeasurement, RamControlPerformance,
};
use crucible_ram::{MetadataBudget, MetadataReservation};

use super::source::ObservationOperationError;
use super::supervision::{monotonic_ns, monotonic_ns_for};

/// Holds one fixed interval; no operation samples or queues are retained.
#[derive(Debug)]
pub(crate) struct PerformanceBank {
    state: Mutex<RamControlPerformance>,
    _credit: MetadataReservation,
}

const _: () = assert!(
    std::mem::size_of::<PerformanceBank>() + 2 * std::mem::size_of::<usize>() + 4096
        <= RAM_PERFORMANCE_BANK_RESERVE_BYTES as usize
);

impl PerformanceBank {
    pub(super) fn new(budget: &MetadataBudget) -> io::Result<Self> {
        // The reservation precedes the integrating caller's Arc allocation.
        let credit = budget
            .reserve_bytes(RAM_PERFORMANCE_BANK_RESERVE_BYTES)
            .map_err(io::Error::other)?;
        Ok(Self {
            state: Mutex::new(RamControlPerformance {
                generation: 1,
                active: true,
                complete: true,
                pending_operations: 0,
                io: [RamControlIoMeasurement::default(); RAM_PERFORMANCE_IO_CLASSES],
            }),
            _credit: credit,
        })
    }

    pub(super) fn snapshot(&self, stop: bool) -> io::Result<RamControlPerformance> {
        let mut state = self.state.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "performance snapshot unavailable",
            )
        })?;
        if stop {
            state.active = false;
        }
        Ok(*state)
    }

    fn begin(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if !state.active {
            return false;
        }
        let Some(pending) = state.pending_operations.checked_add(1) else {
            state.complete = false;
            state.active = false;
            return false;
        };
        state.pending_operations = pending;
        true
    }

    fn finish(&self, class: RamControlIoClass, work: IoWork, elapsed: Option<u64>, success: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.pending_operations -= 1;
        let previous = state.io[class as usize];
        let next = (|| {
            if !work.representable {
                return None;
            }
            Some(RamControlIoMeasurement {
                operations: previous.operations.checked_add(1)?,
                completed: previous.completed.checked_add(u64::from(success))?,
                failed: previous.failed.checked_add(u64::from(!success))?,
                syscalls: previous.syscalls.checked_add(work.syscalls)?,
                transferred_bytes: previous.transferred_bytes.checked_add(work.bytes)?,
                elapsed_ns: previous.elapsed_ns.checked_add(elapsed?)?,
                maximum_elapsed_ns: previous.maximum_elapsed_ns.max(elapsed?),
            })
        })();
        if let Some(next) = next {
            state.io[class as usize] = next;
        } else {
            // Measurement loss never changes the underlying preservation result.
            // The receiver must refuse completeness claims for this interval.
            state.complete = false;
            state.active = false;
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IoWork {
    pub(super) bytes: u64,
    pub(super) syscalls: u64,
    pub(super) representable: bool,
}

impl Default for IoWork {
    fn default() -> Self {
        Self {
            bytes: 0,
            syscalls: 0,
            representable: true,
        }
    }
}

pub(super) struct MeasuredIo<'a> {
    bank: Option<&'a PerformanceBank>,
    started: Option<u64>,
    class: RamControlIoClass,
}

impl<'a> MeasuredIo<'a> {
    pub(super) fn begin(bank: Option<&'a PerformanceBank>, class: RamControlIoClass) -> Self {
        Self::begin_with_clock(bank, class, monotonic_ns)
    }

    pub(super) fn begin_observation(
        bank: Option<&'a PerformanceBank>,
        class: RamControlIoClass,
    ) -> Self {
        let bank = bank.filter(|bank| bank.begin());
        let started = bank.and_then(|_| monotonic_ns_for::<true>().ok());
        Self {
            bank,
            started,
            class,
        }
    }

    pub(super) fn finish_observation(self, work: IoWork, success: bool) {
        if let Some(bank) = self.bank {
            let elapsed = self.started.and_then(|start| {
                monotonic_ns_for::<true>()
                    .ok()
                    .and_then(|end| end.checked_sub(start))
            });
            bank.finish(self.class, work, elapsed, success);
        }
    }

    fn begin_with_clock(
        bank: Option<&'a PerformanceBank>,
        class: RamControlIoClass,
        clock: impl FnOnce() -> io::Result<u64>,
    ) -> Self {
        let bank = bank.filter(|bank| bank.begin());
        // Disabled measurements perform no clock reads or allocations.
        let started = bank.and_then(|_| clock().ok());
        Self {
            bank,
            started,
            class,
        }
    }

    pub(super) fn finish(self, work: IoWork, result: &io::Result<()>) {
        if let Some(bank) = self.bank {
            let elapsed = self
                .started
                .and_then(|start| monotonic_ns().ok().and_then(|end| end.checked_sub(start)));
            bank.finish(self.class, work, elapsed, result.is_ok());
        }
    }
}

/// Executes the same exact-transfer semantics while retaining partial returns.
pub(super) fn read_exact_at(
    bytes: &mut [u8],
    offset: u64,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> (IoWork, io::Result<()>) {
    transfer(
        bytes.len(),
        offset,
        |position, address| read(&mut bytes[position..], address),
        false,
    )
}

pub(super) fn write_all_at(
    bytes: &[u8],
    offset: u64,
    mut write: impl FnMut(&[u8], u64) -> io::Result<usize>,
) -> (IoWork, io::Result<()>) {
    transfer(
        bytes.len(),
        offset,
        |position, address| write(&bytes[position..], address),
        true,
    )
}

fn transfer(
    length: usize,
    offset: u64,
    syscall: impl FnMut(usize, u64) -> io::Result<usize>,
    writing: bool,
) -> (IoWork, io::Result<()>) {
    let (work, result) = transfer_for::<false>(length, offset, syscall, writing);
    (work, result.map_err(ObservationOperationError::into_io))
}

/// Keeps observation transfer refusals owned without constructing diagnostics.
pub(super) fn read_exact_at_observation(
    bytes: &mut [u8],
    offset: u64,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> (IoWork, Result<(), ObservationOperationError>) {
    transfer_for::<true>(
        bytes.len(),
        offset,
        |position, address| read(&mut bytes[position..], address),
        false,
    )
}

fn transfer_for<const BORROWED: bool>(
    length: usize,
    offset: u64,
    mut syscall: impl FnMut(usize, u64) -> io::Result<usize>,
    writing: bool,
) -> (IoWork, Result<(), ObservationOperationError>) {
    let mut work = IoWork::default();
    while work.bytes < length as u64 {
        let Some(address) = offset.checked_add(work.bytes) else {
            return (
                work,
                Err(ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::Other,
                    "measured I/O offset overflow",
                )),
            );
        };
        if let Some(next) = work.syscalls.checked_add(1) {
            work.syscalls = next;
        } else {
            work.representable = false;
        }
        match syscall(work.bytes as usize, address) {
            Ok(0) => {
                let kind = if writing {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::UnexpectedEof
                };
                return (
                    work,
                    Err(ObservationOperationError::static_error::<BORROWED>(
                        kind,
                        "incomplete spill transfer",
                    )),
                );
            }
            Ok(count) if count <= length - work.bytes as usize => work.bytes += count as u64,
            Ok(_) => {
                return (
                    work,
                    Err(ObservationOperationError::static_error::<BORROWED>(
                        io::ErrorKind::Other,
                        "invalid syscall byte count",
                    )),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return (work, Err(error.into())),
        }
    }
    (work, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_diagnostics_never_sample_the_clock() {
        let measurement = MeasuredIo::begin_with_clock(None, RamControlIoClass::PageRead, || {
            panic!("disabled measurement sampled clock")
        });
        measurement.finish(IoWork::default(), &Ok(()));
    }

    #[test]
    fn actual_partial_returns_survive_read_and_write_failures() {
        let mut calls = 0;
        let mut bytes = [0; 17];
        let (read, result) = read_exact_at(&mut bytes, 4096, |bytes, offset| {
            calls += 1;
            match calls {
                1 => {
                    assert_eq!(offset, 4096);
                    bytes[..7].fill(1);
                    Ok(7)
                }
                2 => Err(io::ErrorKind::Interrupted.into()),
                3 => {
                    assert_eq!(offset, 4103);
                    Err(io::Error::from_raw_os_error(libc::EIO))
                }
                _ => panic!("read continued after failure"),
            }
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert_eq!((read.bytes, read.syscalls), (7, 3));

        calls = 0;
        let (write, result) = write_all_at(&bytes, 8192, |bytes, offset| {
            calls += 1;
            if calls == 1 {
                assert_eq!(bytes.len(), 17);
                assert_eq!(offset, 8192);
                Ok(11)
            } else {
                assert_eq!(offset, 8203);
                Ok(0)
            }
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
        assert_eq!((write.bytes, write.syscalls), (11, 2));
    }

    #[test]
    fn charged_bank_counts_failed_work_and_retains_credit_until_last_drop() {
        let budget = MetadataBudget::new(64 * 1024);
        let bank = std::sync::Arc::new(PerformanceBank::new(&budget).unwrap());
        let credit = budget.used_bytes();
        assert!(credit >= std::mem::size_of::<PerformanceBank>() as u64);
        assert!(bank.begin());
        assert_eq!(bank.snapshot(false).unwrap().pending_operations, 1);
        bank.finish(
            RamControlIoClass::PageRead,
            IoWork {
                bytes: 7,
                syscalls: 3,
                ..IoWork::default()
            },
            Some(99),
            false,
        );
        let observed = bank.snapshot(true).unwrap();
        assert!(!observed.active);
        assert!(observed.complete);
        assert_eq!(observed.pending_operations, 0);
        assert_eq!(
            observed.io[0],
            RamControlIoMeasurement {
                operations: 1,
                completed: 0,
                failed: 1,
                syscalls: 3,
                transferred_bytes: 7,
                elapsed_ns: 99,
                maximum_elapsed_ns: 99
            }
        );
        assert!(!bank.begin());
        let retained = bank.clone();
        drop(bank);
        assert_eq!(budget.used_bytes(), credit);
        drop(retained);
        assert_eq!(budget.used_bytes(), 0);
        assert!(PerformanceBank::new(&MetadataBudget::new(0)).is_err());
    }

    #[test]
    fn clock_or_counter_loss_invalidates_measurements_without_changing_io() {
        let bank = PerformanceBank::new(&MetadataBudget::new(64 * 1024)).unwrap();
        assert!(bank.begin());
        bank.finish(
            RamControlIoClass::PageRead,
            IoWork {
                bytes: 17,
                syscalls: 1,
                ..IoWork::default()
            },
            None,
            true,
        );
        assert!(!bank.snapshot(false).unwrap().complete);
        assert!(!bank.begin());
    }

    #[test]
    fn overflowing_statistics_invalidate_the_interval_without_io_failure() {
        let bank = PerformanceBank::new(&MetadataBudget::new(64 * 1024)).unwrap();
        bank.state.lock().unwrap().io[0] = RamControlIoMeasurement {
            operations: u64::MAX,
            completed: u64::MAX,
            ..RamControlIoMeasurement::default()
        };
        assert!(bank.begin());
        bank.finish(
            RamControlIoClass::PageRead,
            IoWork {
                bytes: 17,
                syscalls: 1,
                ..IoWork::default()
            },
            Some(9),
            true,
        );
        let observed = bank.snapshot(false).unwrap();
        assert!(!observed.complete);
        assert!(!observed.active);
        assert_eq!(observed.pending_operations, 0);
        assert_eq!(observed.io[0].operations, u64::MAX);
    }

    #[test]
    fn observation_transfer_retains_partial_work_and_static_errors_before_conversion() {
        let mut bytes = [0; 9];
        let mut calls = 0;
        let (work, result) = read_exact_at_observation(&mut bytes, 4096, |output, offset| {
            calls += 1;
            match calls {
                1 => Err(io::ErrorKind::Interrupted.into()),
                2 => {
                    assert_eq!(offset, 4096);
                    output[..4].fill(1);
                    Ok(4)
                }
                _ => {
                    assert_eq!(offset, 4100);
                    Err(io::Error::from_raw_os_error(libc::EIO))
                }
            }
        });
        assert_eq!((work.bytes, work.syscalls), (4, 3));
        assert!(
            matches!(result, Err(ObservationOperationError::Io(error)) if error.raw_os_error() == Some(libc::EIO))
        );
        let (work, result) = read_exact_at_observation(&mut bytes, 0, |_, _| Ok(0));
        assert_eq!((work.bytes, work.syscalls), (0, 1));
        assert!(matches!(
            result,
            Err(ObservationOperationError::Static {
                kind: io::ErrorKind::UnexpectedEof,
                message: "incomplete spill transfer",
            })
        ));
    }
}
