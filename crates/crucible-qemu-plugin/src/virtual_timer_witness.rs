//! Actual virtual-timer callback witnessing.
//!
//! Patched QEMU arms one witness at an all-vCPU idle boundary and completes it
//! only after the matching `QEMU_CLOCK_VIRTUAL` callback returns. The plugin
//! validates that native observation before publishing the corresponding
//! logical idle wake.

use std::os::raw::c_int;

use thiserror::Error;

/// QEMU export used to arm one exact virtual-timer witness.
pub const QEMU_PLUGIN_CRUCIBLE_ARM_VIRTUAL_TIMER_WITNESS_SYMBOL: &str =
    "qemu_plugin_crucible_arm_virtual_timer_witness";
/// QEMU export used to query one completed virtual-timer witness.
pub const QEMU_PLUGIN_CRUCIBLE_QUERY_VIRTUAL_TIMER_WITNESS_SYMBOL: &str =
    "qemu_plugin_crucible_query_virtual_timer_witness";

/// Native evidence retained by QEMU around one actual virtual-timer callback.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuVirtualTimerWitnessRecord {
    /// Monotonic QEMU witness generation.
    pub generation: u64,
    /// Armed absolute `QEMU_CLOCK_VIRTUAL` deadline.
    pub deadline_ps: i64,
    /// Plugin-supplied exact logical tick corresponding to `deadline_ps`.
    pub deadline_tick: u64,
    /// QEMU raw icount captured when the witness was armed.
    pub armed_raw_icount: u64,
    /// Saved expiry of the timer whose callback actually ran.
    pub fired_expire_ps: i64,
    /// `QEMU_CLOCK_VIRTUAL` value sampled immediately before that callback.
    pub fired_virtual_ps: i64,
    /// QEMU raw icount sampled immediately before that callback.
    pub fired_raw_icount: u64,
    /// Nonzero only after the matching callback returned.
    pub completed: u32,
    /// Must remain zero for this ABI version.
    pub reserved: u32,
}

/// QEMU function that arms one exact virtual-timer witness.
pub type QemuArmVirtualTimerWitnessFn = extern "C" fn(i64, u64, *mut u64) -> c_int;

/// QEMU function that queries one exact virtual-timer witness generation.
pub type QemuQueryVirtualTimerWitnessFn =
    extern "C" fn(u64, *mut QemuVirtualTimerWitnessRecord) -> c_int;

/// Required pair of QEMU virtual-timer witness functions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuVirtualTimerWitness {
    arm: QemuArmVirtualTimerWitnessFn,
    query: QemuQueryVirtualTimerWitnessFn,
}

impl QemuVirtualTimerWitness {
    #[cfg(test)]
    pub(crate) fn test_stub(
        arm: QemuArmVirtualTimerWitnessFn,
        query: QemuQueryVirtualTimerWitnessFn,
    ) -> Self {
        Self { arm, query }
    }

    /// Requires both halves of the native timer witness boundary.
    pub(crate) fn require(
        arm: Option<QemuArmVirtualTimerWitnessFn>,
        query: Option<QemuQueryVirtualTimerWitnessFn>,
    ) -> Result<Self, VirtualTimerWitnessError> {
        let arm = arm.ok_or(VirtualTimerWitnessError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_CRUCIBLE_ARM_VIRTUAL_TIMER_WITNESS_SYMBOL,
        })?;
        let query = query.ok_or(VirtualTimerWitnessError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_CRUCIBLE_QUERY_VIRTUAL_TIMER_WITNESS_SYMBOL,
        })?;
        Ok(Self { arm, query })
    }

    /// Arms QEMU for the timer callback that owns `deadline_ps`.
    pub(crate) fn arm(
        self,
        deadline_ps: u64,
        deadline_tick: u64,
    ) -> Result<ArmedVirtualTimerWitness, VirtualTimerWitnessError> {
        let deadline_ps = i64::try_from(deadline_ps)
            .map_err(|_error| VirtualTimerWitnessError::DeadlineOutOfRange { deadline_ps })?;
        let mut generation = 0;
        let status = (self.arm)(deadline_ps, deadline_tick, &mut generation);
        if status != 0 || generation == 0 {
            return Err(VirtualTimerWitnessError::ArmRejected { status, generation });
        }
        Ok(ArmedVirtualTimerWitness {
            generation,
            deadline_ps,
            deadline_tick,
        })
    }

    /// Queries and validates one completed callback witness.
    pub(crate) fn query_completed(
        self,
        armed: ArmedVirtualTimerWitness,
        expected_raw_icount: u64,
        expected_target_virtual_ps: u64,
    ) -> Result<VirtualTimerFireEvidence, VirtualTimerWitnessError> {
        let expected_target_virtual_ps =
            i64::try_from(expected_target_virtual_ps).map_err(|_error| {
                VirtualTimerWitnessError::TargetOutOfRange {
                    target_virtual_ps: expected_target_virtual_ps,
                }
            })?;
        let mut observed = QemuVirtualTimerWitnessRecord::default();
        let status = (self.query)(armed.generation, &mut observed);
        if status != 0 {
            return Err(VirtualTimerWitnessError::QueryRejected {
                generation: armed.generation,
                status,
            });
        }
        if observed.reserved != 0
            || observed.completed != 1
            || observed.generation != armed.generation
            || observed.deadline_ps != armed.deadline_ps
            || observed.deadline_tick != armed.deadline_tick
            || observed.armed_raw_icount != expected_raw_icount
            || observed.fired_expire_ps != armed.deadline_ps
            || observed.fired_virtual_ps != expected_target_virtual_ps
            || observed.fired_virtual_ps != observed.fired_expire_ps
            || observed.fired_raw_icount != expected_raw_icount
        {
            return Err(VirtualTimerWitnessError::EvidenceMismatch {
                expected_generation: armed.generation,
                expected_deadline_ps: armed.deadline_ps,
                expected_deadline_tick: armed.deadline_tick,
                expected_raw_icount,
                expected_target_virtual_ps,
                observed,
            });
        }
        Ok(VirtualTimerFireEvidence { observed })
    }
}

/// Identity returned when QEMU accepts one timer witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArmedVirtualTimerWitness {
    generation: u64,
    deadline_ps: i64,
    deadline_tick: u64,
}

/// Validated proof that one matching virtual-timer callback actually returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtualTimerFireEvidence {
    observed: QemuVirtualTimerWitnessRecord,
}

impl VirtualTimerFireEvidence {
    pub(crate) fn into_shared(self) -> crucible_shmem::VirtualTimerFireWitness {
        crucible_shmem::VirtualTimerFireWitness {
            generation: self.observed.generation,
            deadline_ps: self.observed.deadline_ps.unsigned_abs(),
            deadline_tick: self.observed.deadline_tick,
            armed_raw_icount: self.observed.armed_raw_icount,
            fired_expire_ps: self.observed.fired_expire_ps.unsigned_abs(),
            fired_virtual_ps: self.observed.fired_virtual_ps.unsigned_abs(),
            fired_raw_icount: self.observed.fired_raw_icount,
            completed: self.observed.completed,
            reserved: self.observed.reserved,
        }
    }
}

/// Failure to arm or validate QEMU's actual virtual-timer callback witness.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum VirtualTimerWitnessError {
    /// A required patched-QEMU symbol is unavailable.
    #[error("required virtual-timer witness capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing symbol.
        symbol: &'static str,
    },
    /// The unsigned deadline cannot cross QEMU's signed picosecond ABI.
    #[error(
        "virtual-timer witness deadline {deadline_ps} does not fit QEMU's signed picosecond ABI"
    )]
    DeadlineOutOfRange {
        /// Rejected deadline.
        deadline_ps: u64,
    },
    /// The commanded virtual target cannot cross QEMU's signed picosecond ABI.
    #[error(
        "virtual-timer witness target {target_virtual_ps} does not fit QEMU's signed picosecond ABI"
    )]
    TargetOutOfRange {
        /// Rejected target.
        target_virtual_ps: u64,
    },
    /// QEMU rejected the witness arm operation or returned no generation.
    #[error(
        "QEMU rejected virtual-timer witness arm with status {status}, generation {generation}"
    )]
    ArmRejected {
        /// Negative errno-style status.
        status: c_int,
        /// Generation returned by QEMU.
        generation: u64,
    },
    /// QEMU rejected the query for an armed generation.
    #[error(
        "QEMU rejected virtual-timer witness generation {generation} query with status {status}"
    )]
    QueryRejected {
        /// Queried generation.
        generation: u64,
        /// Negative errno-style status.
        status: c_int,
    },
    /// QEMU returned evidence that does not exactly match the armed timer.
    #[error(
        "virtual-timer witness mismatch for generation {expected_generation}, deadline_ps {expected_deadline_ps}, target_ps {expected_target_virtual_ps}, logical deadline {expected_deadline_tick}, raw icount {expected_raw_icount}: {observed:?}"
    )]
    EvidenceMismatch {
        /// Expected generation.
        expected_generation: u64,
        /// Expected virtual deadline.
        expected_deadline_ps: i64,
        /// Expected logical deadline.
        expected_deadline_tick: u64,
        /// Expected unchanged raw icount.
        expected_raw_icount: u64,
        /// Scheduler-commanded exact virtual picosecond target.
        expected_target_virtual_ps: i64,
        /// Full QEMU observation.
        observed: QemuVirtualTimerWitnessRecord,
    },
}

const _: () = assert!(core::mem::size_of::<QemuVirtualTimerWitnessRecord>() == 64);
const _: () = assert!(core::mem::align_of::<QemuVirtualTimerWitnessRecord>() == 8);

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        static ARMED: Cell<(u64, i64, u64)> = const { Cell::new((0, 0, 0)) };
    }

    extern "C" fn arm(deadline_ps: i64, deadline_tick: u64, generation: *mut u64) -> c_int {
        ARMED.set((7, deadline_ps, deadline_tick));
        // SAFETY: this test calls through the wrapper with a live output pointer.
        unsafe { generation.write(7) };
        0
    }

    extern "C" fn query(generation: u64, out: *mut QemuVirtualTimerWitnessRecord) -> c_int {
        let (armed_generation, deadline_ps, deadline_tick) = ARMED.get();
        // SAFETY: this test calls through the wrapper with a live output pointer.
        unsafe {
            out.write(QemuVirtualTimerWitnessRecord {
                generation: armed_generation,
                deadline_ps,
                deadline_tick,
                armed_raw_icount: 41,
                fired_expire_ps: deadline_ps,
                fired_virtual_ps: 100,
                fired_raw_icount: 41,
                completed: u32::from(generation == armed_generation),
                reserved: 0,
            });
        }
        0
    }

    #[test]
    fn completed_witness_binds_actual_callback_to_raw_and_logical_coordinates() {
        let witness = QemuVirtualTimerWitness::test_stub(arm, query);
        let armed = witness
            .arm(100, 50)
            .unwrap_or_else(|error| panic!("witness should arm: {error}"));

        let evidence = witness
            .query_completed(armed, 41, 100)
            .unwrap_or_else(|error| panic!("matching callback should authenticate: {error}"));

        assert_eq!(evidence.observed.fired_raw_icount, 41);
        assert_eq!(evidence.observed.deadline_tick, 50);
    }

    #[test]
    fn completed_witness_rejects_a_raw_icount_mismatch() {
        let witness = QemuVirtualTimerWitness::test_stub(arm, query);
        let armed = witness
            .arm(100, 50)
            .unwrap_or_else(|error| panic!("witness should arm: {error}"));

        assert!(matches!(
            witness.query_completed(armed, 42, 100),
            Err(VirtualTimerWitnessError::EvidenceMismatch { .. })
        ));
    }
}
