//! Retains one real pidfd namespace ioctl through its original native checks.
//!
//! This readonly native destination supplies no namespace role or admission.
//! It keeps the actual returned FD before CLOEXEC, nsfs, kind and identity
//! checks; genuine callers retain their process/launch joins and owed posts.

use super::*;

/// Owns one actual namespace acquisition and its complete failure prefix.
#[derive(Debug, Default)]
pub struct PidFdNamespaceOriginalV2 {
    raw: Option<OwnedFd>,
    validated: Option<NamespaceFd>,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
}

impl PidFdNamespaceOriginalV2 {
    /// Creates empty destinations without issuing an ioctl or adopting a file.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Uses the same original pidfd ioctl, flag and namespace validation engine.
    ///
    /// # Errors
    /// Retains the exact ioctl or validation error and every returned native
    /// descriptor. Reentry cannot resample or replace an earlier original.
    pub fn capture_once(&mut self, process: &PidFd, kind: NamespaceKind) -> Result<()> {
        self.capture_descriptor_once(process.as_fd(), kind)
    }

    fn capture_descriptor_once(&mut self, descriptor: BorrowedFd<'_>, kind: NamespaceKind) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some((|| {
            uapi::pidfd_namespace_retaining_v2(descriptor, namespace_request_v2(kind), &mut self.raw)?;
            let identity = NamespaceFd::validate_original_kind(
                self.raw.as_ref().ok_or_else(closed)?.as_fd(), kind,
            )?;
            let fd = self.raw.take().ok_or_else(closed)?;
            self.validated = Some(NamespaceFd { fd, kind, identity });
            Ok(())
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    /// Moves only the same fully validated namespace descriptor once.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<NamespaceFd> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.validated.take()
    }

    /// Borrows the original native failure before any later reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Bounds the native carriers and one returned FD; no pathname is opened.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?, 1, 0))
    }
}

fn closed() -> Error {
    Error::invalid("retained pidfd namespace", "original operation remains closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_real_ioctl_keeps_original_error_and_never_reenters() {
        // A regular descriptor reaches the real ioctl's ENOTTY before any
        // namespace can be created. Private construction tests only the same
        // mechanical error path, never a process or namespace authority.
        let process = std::fs::File::open("/dev/null").unwrap();
        let mut original = PidFdNamespaceOriginalV2::new();
        assert!(original.capture_descriptor_once(process.as_fd(), NamespaceKind::Mount).is_err());
        let first = original.failure().unwrap() as *const Error;
        assert!(original.raw.is_none());
        assert!(original.validated.is_none());

        assert!(original.capture_descriptor_once(process.as_fd(), NamespaceKind::User).is_err());
        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert!(original.take_completed_once().is_none());
        assert!(uapi::fstat(process.as_fd()).is_ok());
    }
}
