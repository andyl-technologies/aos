//! Shared deterministic preemption planning primitives.
//!
//! The scheduler and loaded QEMU plugin use the same node-icount arithmetic for
//! inter-vCPU interrupt delivery. Keeping the boundary calculation in the L1
//! protocol crate prevents the live backend from restating the plugin model.

/// Rounds an inter-vCPU interrupt to its deterministic RR delivery boundary.
///
/// `send_icount + fixed_latency_icount` is rounded up to the next multiple of
/// `rr_switch_quantum`. An already aligned earliest delivery remains unchanged.
///
/// Returns `None` when the latency addition or boundary rounding overflows, or
/// when `rr_switch_quantum` is zero.
#[must_use]
pub const fn deterministic_ipi_delivery_icount(
    send_icount: u64,
    fixed_latency_icount: u64,
    rr_switch_quantum: u64,
) -> Option<u64> {
    if rr_switch_quantum == 0 {
        return None;
    }
    let Some(earliest_icount) = send_icount.checked_add(fixed_latency_icount) else {
        return None;
    };
    let remainder = earliest_icount % rr_switch_quantum;
    if remainder == 0 {
        Some(earliest_icount)
    } else {
        earliest_icount.checked_add(rr_switch_quantum - remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::deterministic_ipi_delivery_icount;

    #[test]
    fn ipi_delivery_adds_fixed_latency_and_rounds_to_rr_boundary() {
        assert_eq!(deterministic_ipi_delivery_icount(18, 5, 8), Some(24));
        assert_eq!(deterministic_ipi_delivery_icount(24, 8, 8), Some(32));
    }

    #[test]
    fn ipi_delivery_rejects_zero_quantum_and_overflow() {
        assert_eq!(deterministic_ipi_delivery_icount(18, 5, 0), None);
        assert_eq!(deterministic_ipi_delivery_icount(u64::MAX, 1, 8), None);
        assert_eq!(deterministic_ipi_delivery_icount(u64::MAX - 1, 0, 8), None);
    }
}
