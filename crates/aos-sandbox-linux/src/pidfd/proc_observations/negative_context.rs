//! Retains a single negative context sample over the already-captured OFD.
//!
//! The ordinary preparation requires a complete healthy original. A separate
//! negative-prefix preparation can duplicate an already-held partial OFD;
//! neither route renews that source, chooses a path or authenticates a role.

use std::error::Error as StdError;

use super::negative_identity::{ProcReadOriginalV1, read_proc_bytes};
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum NegativeContextPhaseV1 {
    Fresh,
    Prepared,
    Observed,
    Closed,
}

struct ContextInfoOriginalV1 {
    info: Option<Result<PidFdInfo>>,
    binding: Option<Result<()>>,
    alive: Option<Result<bool>>,
    liveness: Option<Result<()>>,
}

impl ContextInfoOriginalV1 {
    const fn new() -> Self {
        Self {
            info: None,
            binding: None,
            alive: None,
            liveness: None,
        }
    }

    fn observe(&mut self, original: &PidFd, expected: Option<PidFdInfo>) {
        self.info = Some(original.info());
        self.binding = Some(match self.info.as_ref() {
            Some(Ok(info)) => require_original_info_binding(*info, expected),
            _ => Err(closed()),
        });
        // This is an independently owed liveness observation, including when
        // GET_INFO or its original-coordinate comparison has already failed.
        self.alive = Some(original.is_alive());
        self.liveness = Some(match self.alive.as_ref() {
            Some(Ok(alive)) => require_original_liveness(*alive),
            _ => Err(closed()),
        });
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.info)
            .or_else(|| failure(&self.binding))
            .or_else(|| failure(&self.alive))
            .or_else(|| failure(&self.liveness))
    }
}

/// Retains context bytes and native outcomes from the same prearmed descriptor.
///
/// This DATA requires genuine purpose admission before preparation and use.
/// The purpose still retains its original pidfd and applies its exact context
/// matcher. Successful sampling cannot reopen a healthy observation phase.
#[must_use = "retain the actual duplicate, bounded bytes and original native outcomes"]
pub struct PidFdNegativeContextOriginalV1 {
    duplicate: Option<std::io::Result<File>>,
    expected: Option<PidFdInfo>,
    preparation: Option<Result<()>>,
    before: ContextInfoOriginalV1,
    bytes: Vec<u8>,
    read_original: ProcReadOriginalV1,
    read: Option<Result<()>>,
    after: ContextInfoOriginalV1,
    result: Option<Result<()>>,
    phase: NegativeContextPhaseV1,
}

impl PidFdNegativeContextOriginalV1 {
    /// Creates inert fixed native-result destinations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            duplicate: None,
            expected: None,
            preparation: None,
            before: ContextInfoOriginalV1::new(),
            bytes: Vec::new(),
            read_original: ProcReadOriginalV1::new(),
            read: None,
            after: ContextInfoOriginalV1::new(),
            result: None,
            phase: NegativeContextPhaseV1::Fresh,
        }
    }

    /// Describes the actual owner, bounded context/read work and one duplicate.
    ///
    /// The fifteen result cells are duplicate/preparation, four per GET_INFO
    /// bookend, three raw read outcomes, bounded read and whole completion.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let bound = CONTEXT_BYTES.checked_add(1)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(bound.checked_mul(2)?)?
            .checked_add(256)?
            .checked_add(16 * 256)?;
        Some((bytes, 1, 15))
    }

    /// Supplies this same reader's maximum requested context traffic with EOF.
    ///
    /// This is passive DATA; it grants no read, descriptor or healthy phase.
    #[must_use]
    pub fn maximum_requested_read_bytes_v1() -> Option<usize> {
        CONTEXT_BYTES.checked_add(1)
    }

    /// Observes once from the same prearmed context OFD and original pidfd.
    ///
    /// Both native bookends still run when the read or earlier comparison
    /// refuses. Whole original results stay resident before projection.
    ///
    /// # Errors
    /// Rejects incomplete/repeated preparation, unavailable or changed process
    /// observations, exit, native read refusal or excess context bytes.
    pub fn observe_once(&mut self, original: &PidFd) -> Result<&[u8]> {
        if self.phase != NegativeContextPhaseV1::Prepared {
            return Err(closed());
        }
        self.phase = NegativeContextPhaseV1::Closed;

        self.before.observe(original, self.expected);
        let file = match self.duplicate.as_mut() {
            Some(Ok(file)) => Some(file),
            _ => None,
        };
        self.read = Some(read_proc_bytes(
            file,
            &mut self.bytes,
            CONTEXT_BYTES,
            Some(&mut self.read_original),
        ));
        self.after.observe(original, self.expected);
        self.result = Some(if self.failure().is_some() {
            Err(closed())
        } else {
            Ok(())
        });

        if matches!(self.result, Some(Ok(()))) {
            self.phase = NegativeContextPhaseV1::Observed;
            Ok(&self.bytes)
        } else {
            Err(closed())
        }
    }

    /// Borrows the first actual native or semantic failure in observation order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.duplicate)
            .or_else(|| failure(&self.preparation))
            .or_else(|| self.before.failure())
            .or_else(|| self.read_original.failure())
            .or_else(|| failure(&self.read))
            .or_else(|| self.after.failure())
            .or_else(|| failure(&self.result))
    }

    /// Reports a complete sample without authorizing process/role continuation.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.phase == NegativeContextPhaseV1::Observed && matches!(self.result, Some(Ok(())))
    }
}

impl Default for PidFdNegativeContextOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PidFdProcObservationsV1 {
    /// Prearms one negative sample from this same complete original context OFD.
    ///
    /// The actual duplicate is parked before any later fallible check. No
    /// pathname is reopened and this source's phase is never renewed.
    ///
    /// # Errors
    /// Rejects absent/closed capture, repeated preparation or failed duplication.
    pub fn prepare_negative_context_once_into(
        &self,
        original: &mut PidFdNegativeContextOriginalV1,
    ) -> Result<()> {
        self.prepare_negative_context_recipe_into(original, true)
    }

    /// Prepares a negative DATA sample from an already-reached native prefix.
    ///
    /// This never opens a pathname, changes source readiness or supplies an
    /// original identity when the initial capture did not establish one. The
    /// actual caller prepays this duplicate and retains the primary source.
    ///
    /// # Errors
    /// Retains reentry, absent held OFD or failed duplication. The subsequent
    /// sample retains its native read even when original binding is absent.
    pub fn prepare_available_negative_context_once_into_v1(
        &self, original: &mut PidFdNegativeContextOriginalV1,
    ) -> Result<()> {
        self.prepare_negative_context_recipe_into(original, false)
    }

    fn prepare_negative_context_recipe_into(
        &self, original: &mut PidFdNegativeContextOriginalV1, completed_source: bool,
    ) -> Result<()> {
        if original.phase != NegativeContextPhaseV1::Fresh {
            return Err(closed());
        }
        original.phase = NegativeContextPhaseV1::Closed;
        original.preparation = Some((|| {
            if completed_source && self.phase != ObservationPhaseV1::Ready {
                return Err(closed());
            }
            original.expected = self.original_info;
            if completed_source && original.expected.is_none() {
                return Err(closed());
            }
            let file = self.context.file.as_ref().ok_or_else(closed)?;
            original.duplicate = Some(file.try_clone());
            if !matches!(original.duplicate, Some(Ok(_))) {
                return Err(closed());
            }
            Ok(())
        })());
        if matches!(original.preparation, Some(Ok(()))) {
            original.phase = NegativeContextPhaseV1::Prepared;
            Ok(())
        } else {
            Err(closed())
        }
    }
}

fn failure<T, E: StdError + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn StdError)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn same_context_negative_sample_preserves_closed_healthy_source() {
        let pidfd = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut source = pidfd.prepare_proc_observations_v1();
        source.capture_stat(&pidfd).unwrap();
        let captured = source.capture_context(&pidfd).map(|_| ());
        if let Err(cause) = captured {
            // Some kernels expose attr/current but cannot supply its context.
            // Only the exact native read refusal qualifies this host-negative
            // path; every other unexpected acquisition/refusal still fails.
            let Error::Syscall { operation, source: native } = &cause else {
                panic!("unexpected original context capture refusal: {cause:?}");
            };
            assert_eq!(*operation, "read(original proc observation)");
            assert_eq!(native.raw_os_error(), Some(rustix::io::Errno::INVAL.raw_os_error()));
            let first = native as *const std::io::Error;
            let descriptor = source.context.file.as_ref().unwrap().as_raw_fd();
            assert!(matches!(source.phase, ObservationPhaseV1::Closed));

            let mut negative = PidFdNegativeContextOriginalV1::new();
            assert!(source.prepare_negative_context_once_into(&mut negative).is_err());
            assert!(negative.duplicate.is_none());
            assert!(negative.expected.is_none());
            assert!(negative.read.is_none());
            assert!(negative.before.info.is_none());
            assert!(negative.after.info.is_none());
            assert!(negative.bytes.is_empty());
            assert!(!negative.is_complete());
            let refused = negative.failure().unwrap().downcast_ref::<Error>().unwrap()
                as *const Error;

            assert!(negative.observe_once(&pidfd).is_err());
            assert!(source.prepare_negative_context_once_into(&mut negative).is_err());
            assert!(std::ptr::eq(
                negative.failure().unwrap().downcast_ref::<Error>().unwrap(), refused,
            ));
            assert!(source.observe_context(&pidfd).is_err());
            assert!(matches!(source.phase, ObservationPhaseV1::Closed));
            assert_eq!(source.context.file.as_ref().unwrap().as_raw_fd(), descriptor);
            rustix::io::fcntl_getfd(source.context.file.as_ref().unwrap()).unwrap();
            let Error::Syscall { operation, source: native } = &cause else {
                panic!("the actual original read cause must remain owned");
            };
            assert_eq!(*operation, "read(original proc observation)");
            assert!(std::ptr::eq(native, first));
            assert_eq!(native.raw_os_error(), Some(rustix::io::Errno::INVAL.raw_os_error()));
            assert!(negative.duplicate.is_none());
            assert!(negative.read.is_none());
            assert!(negative.before.info.is_none());
            assert!(negative.after.info.is_none());
            std::io::Write::write_all(
                &mut std::io::stderr().lock(),
                b"RFC21_NATIVE_CONTEXT_READ_UNAVAILABLE operation=read(original_proc_observation) errno=EINVAL positive_same_ofd_context=unqualified\n",
            ).unwrap();
            return;
        }

        let mut negative = PidFdNegativeContextOriginalV1::new();
        source.prepare_negative_context_once_into(&mut negative).unwrap();
        assert_ne!(
            source.context.file.as_ref().unwrap().as_raw_fd(),
            negative.duplicate.as_ref().unwrap().as_ref().unwrap().as_raw_fd(),
        );

        // Repeated healthy capture closes the original; the duplicate was
        // derived before that failure and cannot change its phase afterward.
        assert!(source.capture_context(&pidfd).is_err());
        assert_eq!(negative.observe_once(&pidfd).unwrap(), source.context.current);
        assert!(negative.is_complete());
        assert!(negative.failure().is_none());
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        assert!(source.observe_context(&pidfd).is_err());
        assert!(negative.observe_once(&pidfd).is_err());
        assert!(negative.is_complete());
    }
}
