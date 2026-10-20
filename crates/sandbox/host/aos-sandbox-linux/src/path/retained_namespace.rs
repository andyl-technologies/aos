//! Retains the existing bind-pinned namespace open and type-check prefix.
//!
//! The descriptor is parked before nsfs/kind/identity validation. This native
//! mechanism lends no namespace, broker role, financial or effect authority.

use super::*;
use crate::pidfd::NamespaceAdoptionFailureV2;

/// Owns one descriptor-relative namespace acquisition through failed typing.
#[derive(Debug, Default)]
pub struct BeneathNamespaceOpenOriginalV4 {
    opened: Option<Result<OwnedFd>>,
    typed: Option<std::result::Result<NamespaceFd, NamespaceAdoptionFailureV2>>,
    closed: Option<Error>,
    entered: bool,
}

impl BeneathNamespaceOpenOriginalV4 {
    /// Creates empty owning destinations without native work.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Resolves and types the same original namespace descriptor once.
    ///
    /// # Errors
    /// Retains the actual open error or failed descriptor/type-check error.
    /// Reentry cannot replace any preceding original or repeat its syscalls.
    pub fn open_once_v4(&mut self, root: &BeneathRoot, relative: &Path,
        kind: NamespaceKind) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| Error::invalid("retained namespace open", "already entered"));
            return Err(Error::invalid("retained namespace open", "already entered"));
        }
        self.entered = true;
        self.opened = Some(root.open_namespace_candidate_v4(relative));
        if !matches!(self.opened, Some(Ok(_))) {
            return Err(Error::invalid("retained namespace open", "native open refused"));
        }
        let Some(Ok(descriptor)) = self.opened.take() else { std::process::abort() };
        self.typed = Some(NamespaceFd::from_owned_retaining_v2(descriptor, kind));
        if matches!(self.typed, Some(Ok(_))) { Ok(()) }
        else { Err(Error::invalid("retained namespace open", "typing refused")) }
    }

    /// Borrows only the same successfully typed descriptor without new IO.
    #[must_use]
    pub fn completed_namespace_v4(&self) -> Option<&NamespaceFd> {
        if self.closed.is_some() { return None; }
        self.typed.as_ref()?.as_ref().ok()
    }

    /// Closes only the same successfully typed validation descriptor once.
    ///
    /// The returned identity is passive DATA. A caller performing a later
    /// native mutation retains its separate original namespace and authority;
    /// this disposable validation descriptor cannot become that authority.
    ///
    /// # Errors
    /// Refuses an incomplete, failed, already retired or reused original and
    /// leaves every failed descriptor and its original cause resident.
    pub fn retire_positive_namespace_once_v2(&mut self) -> Result<crate::pidfd::NamespaceIdentity> {
        let identity = self.completed_namespace_v4().map(NamespaceFd::identity)
            .ok_or_else(|| Error::invalid("retained namespace retirement", "no completed validation descriptor"))?;
        drop(self.typed.take());
        Ok(identity)
    }

    /// Borrows the first native/path/type error before a later order marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.typed.as_ref().and_then(|result| result.as_ref().err()).map(|error| error.cause()))
            .or(self.closed.as_ref())
    }

    /// Consumes a failed ordinary attempt and moves its original native error.
    ///
    /// This ordinary teardown closes any rejected descriptor. A prepaid
    /// retained role instead keeps this owner and borrows [`Self::failure`]
    /// until all of its independently owed posts have settled.
    #[must_use]
    pub fn into_ordinary_error_v2(self) -> Option<Error> {
        if let Some(Err(cause)) = self.opened { return Some(cause); }
        if let Some(Err(failure)) = self.typed {
            let (descriptor, cause) = failure.into_parts();
            drop(descriptor);
            return Some(cause);
        }
        self.closed
    }

    /// Bounds the compiled carriers, one actual descriptor and path scratch.
    ///
    /// This passive DATA supplies neither a root nor receiving permission.
    #[must_use]
    pub fn receiving_obligations_v4(relative_bytes: usize) -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(relative_bytes.checked_add(1)?.checked_mul(2)?)?;
        Some((bytes, 1, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_namespace_retains_the_opened_descriptor_after_reentry_refusal() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("pin"), b"not nsfs").unwrap();
        let descriptor = rustix::fs::open(directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();
        let mut original = BeneathNamespaceOpenOriginalV4::new();

        assert!(original.open_once_v4(&root, Path::new("pin"), NamespaceKind::Network).is_err());
        let rejected = original.typed.as_ref().unwrap().as_ref().unwrap_err();
        let before = rustix::fs::fstat(rejected.as_fd()).unwrap();
        let cause = original.failure().unwrap() as *const Error;

        assert!(original.retire_positive_namespace_once_v2().is_err());
        assert!(std::ptr::eq(cause, original.failure().unwrap()));
        let rejected = original.typed.as_ref().unwrap().as_ref().unwrap_err();
        let retained = rustix::fs::fstat(rejected.as_fd()).unwrap();
        assert_eq!((before.st_dev, before.st_ino), (retained.st_dev, retained.st_ino));

        assert!(original.open_once_v4(&root, Path::new("absent"), NamespaceKind::Network).is_err());
        let rejected = original.typed.as_ref().unwrap().as_ref().unwrap_err();
        let after = rustix::fs::fstat(rejected.as_fd()).unwrap();
        assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
        assert!(std::ptr::eq(cause, original.failure().unwrap()));
        assert!(original.completed_namespace_v4().is_none());
    }
}
