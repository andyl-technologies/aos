//! Retains the fixed current-Network namespace acquisition and comparison.
//!
//! Both ordinary and retained callers use the same open, adoption and identity
//! predicates. This native owner supplies no namespace-role or effect grant.

use super::*;

fn open_current_network() -> Result<OwnedFd> {
    rustix::fs::open(
        "/proc/self/ns/net",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open /proc/self/ns/net",
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    })
}

pub(super) fn capture_local() -> Result<NamespaceFd> {
    NamespaceFd::from_owned(open_current_network()?, NamespaceKind::Network)
}

trait CurrentNetworkObservation {
    fn identity(&mut self) -> Result<NamespaceIdentity>;
}

struct LocalCurrent;

impl CurrentNetworkObservation for LocalCurrent {
    fn identity(&mut self) -> Result<NamespaceIdentity> {
        Ok(capture_local()?.identity())
    }
}

fn compare_current(
    expected: &NamespaceFd,
    native: &mut impl CurrentNetworkObservation,
) -> Result<()> {
    if expected.kind() != NamespaceKind::Network {
        return Err(Error::WrongDescriptorType {
            expected: "Network namespace",
        });
    }
    if native.identity()? != expected.identity() {
        return Err(Error::InvalidInput {
            field: "current Network namespace",
            message: "retained descriptor does not identify the current namespace".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn compare_local(expected: &NamespaceFd) -> Result<()> {
    compare_current(expected, &mut LocalCurrent)
}

/// Retains one current-Network namespace and all actual refused native inputs.
#[derive(Debug, Default)]
pub struct CurrentNetworkNamespaceOriginalV4 {
    opened: Option<std::result::Result<(), Error>>,
    descriptor: Option<OwnedFd>,
    returned: Option<std::result::Result<NamespaceFd, NamespaceAdoptionFailureV2>>,
    comparison: Option<Result<()>>,
    closed: Option<Error>,
    entered: bool,
    taken: bool,
}

impl CurrentNetworkNamespaceOriginalV4 {
    /// Creates inert destinations without opening or observing native state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures the same fixed current namespace once, parking before adoption.
    ///
    /// # Errors
    /// Keeps the original open/adoption failure and rejects repeated entry.
    pub fn capture_once_v4(&mut self) -> Result<()> {
        if self.entered || self.comparison.is_some() {
            self.closed.get_or_insert_with(|| Error::InvalidInput {
                field: "current Network namespace original",
                message: "already entered".to_owned(),
            });
            return Err(current_network_closed());
        }
        self.entered = true;
        self.opened = Some(match open_current_network() {
            Ok(descriptor) => {
                self.descriptor = Some(descriptor);
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        if !matches!(self.opened, Some(Ok(()))) {
            return Err(current_network_closed());
        }
        let Some(descriptor) = self.descriptor.take() else {
            std::process::abort()
        };
        self.returned = Some(NamespaceFd::from_owned_retaining_v2(
            descriptor,
            NamespaceKind::Network,
        ));
        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            Err(current_network_closed())
        }
    }

    /// Runs the same kind/open/identity comparison and retains its current pin.
    ///
    /// # Errors
    /// Retains wrong kind, the actual native prefix or mismatched identity.
    pub fn validate_once_v4(&mut self, expected: &NamespaceFd) -> Result<()> {
        if self.comparison.is_some() || self.entered {
            self.closed.get_or_insert_with(current_network_closed);
            return Err(current_network_closed());
        }
        self.comparison = Some(compare_current(expected, self));
        if matches!(self.comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(current_network_closed())
        }
    }

    /// Borrows the actual namespace only after complete positive acquisition.
    #[must_use]
    pub fn namespace_v4(&self) -> Option<&NamespaceFd> {
        if self.closed.is_some() || self.comparison.as_ref().is_some_and(Result::is_err) {
            return None;
        }
        self.returned.as_ref()?.as_ref().ok()
    }

    /// Moves the same fully validated namespace once; no new descriptor opens.
    #[must_use]
    pub fn take_completed_once_v4(&mut self) -> Option<NamespaceFd> {
        if self.taken || self.namespace_v4().is_none() {
            return None;
        }
        self.taken = true;
        match self.returned.take() {
            Some(Ok(value)) => Some(value),
            _ => std::process::abort(),
        }
    }

    /// Borrows the first actual open, adoption, comparison or closed cause.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.opened
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(NamespaceAdoptionFailureV2::cause)
            })
            .or_else(|| self.comparison.as_ref()?.as_ref().err())
            .or(self.closed.as_ref())
    }

    /// Bounds native construction, one actual descriptor and its fixed name.
    #[must_use]
    pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<libc::statfs>())?
            .checked_add(2 * std::mem::size_of::<libc::stat>())?
            .checked_add(2 * std::mem::size_of::<Result<OwnedFd>>())?
            .checked_add(2 * b"/proc/self/ns/net\0".len())?;
        Some((bytes, 1, 1))
    }
}

impl CurrentNetworkObservation for CurrentNetworkNamespaceOriginalV4 {
    fn identity(&mut self) -> Result<NamespaceIdentity> {
        self.capture_once_v4()?;
        self.namespace_v4()
            .map(NamespaceFd::identity)
            .ok_or_else(current_network_closed)
    }
}

fn current_network_closed() -> Error {
    Error::InvalidInput {
        field: "current Network namespace original",
        message: "original remains incomplete or refused".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn changed_expected_identity_keeps_actual_current_pin_and_first_cause() {
        let mut expected = NamespaceFd::current_network().unwrap();
        expected.identity.inode ^= 1;
        let mut original = CurrentNetworkNamespaceOriginalV4::new();

        assert!(original.validate_once_v4(&expected).is_err());
        let Some(Ok(actual)) = original.returned.as_ref() else {
            panic!("the completed current namespace must remain owned");
        };
        let native_inode = rustix::fs::fstat(actual.as_fd()).unwrap().st_ino;
        assert_eq!(native_inode, actual.identity().inode);
        assert_ne!(actual.identity(), expected.identity());
        let first = original.failure().unwrap() as *const Error;

        assert!(original.capture_once_v4().is_err());
        assert_eq!(first, original.failure().unwrap() as *const Error);
        assert!(original.take_completed_once_v4().is_none());
        let Some(Ok(actual)) = original.returned.as_ref() else {
            panic!("refused reentry must keep the same native namespace");
        };
        assert_eq!(
            rustix::fs::fstat(actual.as_fd()).unwrap().st_ino,
            native_inode
        );
    }
}
