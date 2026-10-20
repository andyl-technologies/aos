//! Retains exact Capture writer-alias close outcomes during authorized Stop.
//!
//! This mechanical destination owns no permission or financial reservation.
//! Callers must first hold genuine fresh Stop containment of their same native
//! Capture. Every transferred descriptor is consumed once; close is never
//! retried, including EINTR, because Linux has already released that number.

use std::os::fd::{IntoRawFd as _, OwnedFd, RawFd};

/// Exact number of ordered stdout/stderr writer aliases in the closed recipe.
pub const CAPTURE_WRITER_ALIAS_COUNT_V4: usize = 2;

/// Retains both actual writer-close results and their consumed descriptor slots.
#[derive(Default)]
pub struct CaptureWriterAliasCloseOriginalV4 {
    entered: bool,
    slots: [Option<(RawFd, std::io::Result<()>)>; CAPTURE_WRITER_ALIAS_COUNT_V4],
    refused: bool,
}

impl CaptureWriterAliasCloseOriginalV4 {
    /// Creates inert fixed destinations without closing or adopting descriptors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes exactly two already-owned writer aliases once, retaining errors.
    ///
    /// Both native closes run independently. A shape refusal leaves the entire
    /// owning vector in its caller; no descriptor is taken or implicitly closed.
    /// Actual pipe identity/role and Stop permission remain caller obligations.
    ///
    /// # Errors
    /// Refuses reentry, another vector shape, or either actual native close.
    /// Consumed raw numbers are tombstones, never safe to close or reuse again.
    pub fn close_once_v4(
        &mut self,
        writers: &mut Vec<OwnedFd>,
    ) -> Result<(), CaptureWriterAliasCloseRefusalV4> {
        self.close_with_gate_v4::<std::convert::Infallible>(writers, None)
            .0
    }

    /// Gates each exact native close under the caller's retained current cut.
    ///
    /// A gate refusal leaves every not-yet-consumed alias in the same vector.
    /// The caller owns the returned gate error beside this native original;
    /// neither gate nor native errors permit reentry or a close retry.
    ///
    /// # Errors
    /// Refuses the same conditions as `close_once_v4`, or the current-cut gate.
    pub fn close_once_with_current_cut_v4<E>(
        &mut self,
        writers: &mut Vec<OwnedFd>,
        current: &mut dyn FnMut() -> Result<(), E>,
    ) -> (Result<(), CaptureWriterAliasCloseRefusalV4>, Option<E>) {
        self.close_with_gate_v4(writers, Some(current))
    }

    fn close_with_gate_v4<E>(
        &mut self,
        writers: &mut Vec<OwnedFd>,
        mut current: Option<&mut dyn FnMut() -> Result<(), E>>,
    ) -> (Result<(), CaptureWriterAliasCloseRefusalV4>, Option<E>) {
        let reentered = self.entered;
        self.entered = true;
        if reentered || writers.len() != self.slots.len() {
            self.refused = true;
            return (Err(CaptureWriterAliasCloseRefusalV4), None);
        }
        for slot in &mut self.slots {
            if let Some(current) = current.as_deref_mut() {
                if let Err(cause) = current() {
                    return (Err(CaptureWriterAliasCloseRefusalV4), Some(cause));
                }
            }
            // Removing index zero preserves the original ordered stream slots;
            // the two-element move cannot allocate and leaves the Vec backing.
            let descriptor = writers.remove(0).into_raw_fd();
            // SAFETY: this unique OwnedFd was just consumed. Linux invalidates
            // the number on close even if close reports EINTR; no owner or
            // retry survives. The numeric value below is only a tombstone.
            let returned = unsafe { libc::close(descriptor) };
            *slot = Some((
                descriptor,
                if returned == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                },
            ));
        }
        (
            if self.completed_v4() {
                Ok(())
            } else {
                Err(CaptureWriterAliasCloseRefusalV4)
            },
            None,
        )
    }

    /// Reports only both actual successful once-only native closes.
    #[must_use]
    pub fn completed_v4(&self) -> bool {
        self.entered
            && !self.refused
            && self
                .slots
                .iter()
                .all(|slot| matches!(slot, Some((_, Ok(())))))
    }

    /// Borrows the first actual close cause without discarding the other result.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.slots
            .iter()
            .find_map(|slot| slot.as_ref()?.1.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.refused
                    .then_some(&CaptureWriterAliasCloseRefusalV4 as _)
            })
    }

    /// Returns fixed owner, native syscall frame and both possible error bytes.
    #[must_use]
    pub fn receiving_bytes_v4() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<RawFd>())?
            .checked_add(std::mem::size_of::<libc::c_int>())?
            .checked_add(std::mem::size_of::<std::io::Result<()>>())
    }
}

/// Reports refusal while exact owning close results remain in the same original.
#[derive(Debug, thiserror::Error)]
#[error("the exact Capture writer alias close refused")]
pub struct CaptureWriterAliasCloseRefusalV4;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn close_consumes_both_actual_aliases_and_preserves_once_outcomes() {
        let (read0, write0) = rustix::pipe::pipe().unwrap();
        let (read1, write1) = rustix::pipe::pipe().unwrap();
        let mut writers = vec![write0, write1];
        let mut original = CaptureWriterAliasCloseOriginalV4::new();

        original.close_once_v4(&mut writers).unwrap();

        assert!(original.completed_v4());
        assert!(writers.is_empty());
        assert_eq!(rustix::io::read(read0.as_fd(), &mut [0; 1]).unwrap(), 0);
        assert_eq!(rustix::io::read(read1.as_fd(), &mut [0; 1]).unwrap(), 0);
        assert!(original.close_once_v4(&mut writers).is_err());
        assert!(
            original
                .slots
                .iter()
                .all(|slot| matches!(slot, Some((_, Ok(())))))
        );
    }

    #[test]
    fn later_gate_refusal_keeps_the_unclosed_actual_alias_and_first_tombstone() {
        let (read0, write0) = rustix::pipe::pipe().unwrap();
        let (_read1, write1) = rustix::pipe::pipe().unwrap();
        let mut writers = vec![write0, write1];
        let mut original = CaptureWriterAliasCloseOriginalV4::new();
        let mut reached = 0;

        let (result, gate) = original.close_once_with_current_cut_v4(&mut writers, &mut || {
            reached += 1;
            if reached == 2 {
                Err("actual later cutoff refusal")
            } else {
                Ok(())
            }
        });

        assert!(result.is_err());
        assert_eq!(gate, Some("actual later cutoff refusal"));
        assert_eq!(writers.len(), 1);
        assert!(matches!(original.slots[0], Some((_, Ok(())))));
        assert!(original.slots[1].is_none());
        assert!(rustix::io::fcntl_getfd(writers[0].as_fd()).is_ok());
        assert_eq!(rustix::io::read(read0.as_fd(), &mut [0; 1]).unwrap(), 0);
        assert!(!original.completed_v4());
    }

    #[test]
    fn wrong_shape_does_not_consume_the_actual_descriptor() {
        let (_read, writer) = rustix::pipe::pipe().unwrap();
        let mut writers = vec![writer];
        let mut original = CaptureWriterAliasCloseOriginalV4::new();

        assert!(original.close_once_v4(&mut writers).is_err());

        assert_eq!(writers.len(), 1);
        assert!(original.slots.iter().all(Option::is_none));
        let (_other_read, other_writer) = rustix::pipe::pipe().unwrap();
        writers.push(other_writer);
        assert!(original.close_once_v4(&mut writers).is_err());
        assert_eq!(writers.len(), CAPTURE_WRITER_ALIAS_COUNT_V4);
        assert!(original.slots.iter().all(Option::is_none));
    }
}
