//! Binds conservative private clone costs to the selected running kernel.
//!
//! Build-only facts come from that kernel's target compiler. They grant no
//! spawn, account or cgroup authority. A native consumer keeps its own notes
//! proof and parent hard-cgroup backstop before entering the existing spawn
//! engine; ordinary Cargo builds have no configured facts and remain closed.

mod notes;
pub use notes::ConfiguredKernelCloneOriginalV1;

#[cfg(feature = "selected-kernel-clone-layout")]
mod configured {
    include!(concat!(env!("OUT_DIR"), "/aos-kernel-clone-layout-v1.rs"));
}

/// Returns the exact configured notes extent as passive input-cost DATA.
///
/// The caller pays the bounded hash input and EOF probe before its own native
/// proof. This supplies neither a running-kernel match nor a file permission.
#[must_use]
pub fn configured_notes_bytes_data_v1() -> Option<u64> {
    expected_notes_v1().map(|(bytes, _)| bytes)
}

/// Returns the dominant private copied-table and libc spawn-stack byte permit.
///
/// `highest_fd` includes CLOEXEC positions and all prospective concurrent
/// growth. `arguments` includes argv[0]. This passive checked geometry cannot
/// establish actual table completeness, pay for it or authorize a native birth.
/// Page permits intentionally do not claim exact slab/cache/RCU occupancy;
/// the real source hard-cgroup remains a separate required backstop.
#[must_use]
pub fn dominant_birth_bytes_data_v1(highest_fd: u64, arguments: usize) -> Option<u64> {
    #[cfg(not(feature = "selected-kernel-clone-layout"))]
    {
        let _ = (highest_fd, arguments);
        None
    }
    #[cfg(feature = "selected-kernel-clone-layout")]
    {
        use configured::*;
        if FORMAT != 1
            || FILE_POINTER_BYTES != 8
            || ULONG_BYTES != 8
            || BITS_PER_LONG != 64
            || !PAGE_BYTES.is_power_of_two()
            || !NR_OPEN_DEFAULT.is_power_of_two()
            || NR_OPEN_DEFAULT < BITS_PER_LONG
            || !L1_CACHE_BYTES.is_power_of_two()
        {
            return None;
        }
        let wanted = highest_fd.checked_add(1)?;
        let mut total = object_permit(FILES_STRUCT_BYTES, PAGE_BYTES)?;
        if wanted > NR_OPEN_DEFAULT {
            let slots = wanted.checked_next_power_of_two()?;
            let array = slots.checked_mul(FILE_POINTER_BYTES)?;
            let words = slots
                .checked_add(BITS_PER_LONG - 1)?
                .checked_div(BITS_PER_LONG)?;
            let bitbit_words = words
                .checked_add(BITS_PER_LONG - 1)?
                .checked_div(BITS_PER_LONG)?;
            let bitmap = slots
                .checked_div(4)?
                .checked_add(bitbit_words.checked_mul(ULONG_BYTES)?)?
                .max(L1_CACHE_BYTES);
            for bytes in [FDTABLE_BYTES, array, bitmap] {
                total = total.checked_add(object_permit(bytes, PAGE_BYTES)?)?;
            }
        }
        // glibc2.39's argc loop postincrements through argv's terminal NULL.
        // Its mapping therefore aligns (arguments+1)*sizeof(void*) +512 +32KiB.
        // This parent work is independent of the child's memory.max.
        let scratch = u64::try_from(arguments)
            .ok()?
            .checked_add(1)?
            .checked_mul(FILE_POINTER_BYTES)?
            .checked_add(512 + 32 * 1024)?;
        total.checked_add(page_permit(scratch, PAGE_BYTES)?)
    }
}

#[cfg(feature = "selected-kernel-clone-layout")]
fn object_permit(bytes: u64, page: u64) -> Option<u64> {
    // A non-power-of-two bitmap can occupy the next kmalloc class. Round the
    // requested object first, then retain whole pages as a conservative permit.
    page_permit(bytes.checked_next_power_of_two()?, page)
}

#[cfg(feature = "selected-kernel-clone-layout")]
fn page_permit(bytes: u64, page: u64) -> Option<u64> {
    bytes
        .checked_add(page.checked_sub(1)?)
        .map(|rounded| rounded & !(page - 1))
}

#[cfg(feature = "selected-kernel-clone-layout")]
pub(super) fn expected_notes_v1() -> Option<(u64, [u8; 32])> {
    (configured::FORMAT == 1 && configured::NOTES_BYTES != 0)
        .then_some((configured::NOTES_BYTES, configured::NOTES_SHA256))
}

#[cfg(not(feature = "selected-kernel-clone-layout"))]
pub(super) fn expected_notes_v1() -> Option<(u64, [u8; 32])> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_unconfigured_layout_or_overflow_can_price_a_birth() {
        assert!(dominant_birth_bytes_data_v1(u64::MAX, 5).is_none());
        #[cfg(not(feature = "selected-kernel-clone-layout"))]
        assert!(dominant_birth_bytes_data_v1(2, 5).is_none());
    }

    #[test]
    #[cfg(feature = "selected-kernel-clone-layout")]
    fn actual_configured_table_crossings_and_stack_growth_are_charged() {
        let embedded = dominant_birth_bytes_data_v1(configured::NR_OPEN_DEFAULT - 1, 5).unwrap();
        let dynamic = dominant_birth_bytes_data_v1(configured::NR_OPEN_DEFAULT, 5).unwrap();
        assert!(dynamic > embedded);
        assert!(dominant_birth_bytes_data_v1(configured::NR_OPEN_DEFAULT, 1024).unwrap() > dynamic);
        assert_eq!(
            dominant_birth_bytes_data_v1(configured::NR_OPEN_DEFAULT + 1, 5),
            Some(dynamic)
        );
    }

    #[test]
    #[cfg(feature = "selected-kernel-clone-layout")]
    fn libc_terminal_null_advances_the_actual_stack_page_boundary() {
        let remainder = (512 + 32 * 1024) % configured::PAGE_BYTES;
        let arguments = usize::try_from(
            (configured::PAGE_BYTES - remainder) / configured::FILE_POINTER_BYTES,
        ).unwrap();
        let before = dominant_birth_bytes_data_v1(2, arguments - 1).unwrap();
        let after = dominant_birth_bytes_data_v1(2, arguments).unwrap();

        assert_eq!(after - before, configured::PAGE_BYTES);
        if configured::PAGE_BYTES == 4096 {
            assert_eq!(arguments, 448);
        }
    }
}
