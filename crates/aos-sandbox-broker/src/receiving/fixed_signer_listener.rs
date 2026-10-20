//! Observes the actual fixed Source or Cache inherited stdin listener.
//!
//! This native DATA owner duplicates descriptor zero only. It never binds,
//! listens, enables subject options, adopts a caller file or admits a purpose.
//! A genuine role pays and retains it before invoking its fixed recipe.

use std::error::Error;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::Path;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamListenerReadbackV1;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::time::Timespec;
use rustix::net::{SocketFlags, accept_with};

const SOURCE_PATH: &str = "/run/aos/sandbox-source-signerd.sock";

#[derive(Clone, Copy)]
enum Recipe { Source, Cache { uid: u32, gid: u32 } }

/// Classifies an incomplete native listener observation without authority.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the fixed inherited signer listener is unavailable")]
pub struct FixedSignerListenerClosedV1;

/// Retains the actual original listener duplicate and native observations.
pub struct FixedSignerListenerOriginalV1 {
    recipe: Recipe,
    entered: bool,
    duplicate: Option<Result<UnixListener, aos_sandbox_linux::Error>>,
    subject: RetainedSubjectStreamListenerReadbackV1,
    subject_result: Option<Result<(), aos_sandbox_linux::Error>>,
    address: Option<std::io::Result<SocketAddr>>,
    socket_custody: Option<std::io::Result<()>>,
    flags: Option<rustix::io::Result<OFlags>>,
    nonblocking: Option<rustix::io::Result<()>>,
    closed: Option<FixedSignerListenerClosedV1>,
}

impl FixedSignerListenerOriginalV1 {
    /// Creates the fixed Source listener's empty native destinations.
    pub fn source() -> Self { Self::new(Recipe::Source) }

    /// Creates the fixed Cache listener's empty native destinations.
    ///
    /// IDs are comparison DATA. The actual service derives them from its
    /// inherited profile and finite original before invoking this recipe.
    pub fn cache(uid: u32, gid: u32) -> Self { Self::new(Recipe::Cache { uid, gid }) }

    fn new(recipe: Recipe) -> Self {
        Self {
            recipe,
            entered: false,
            duplicate: None,
            subject: RetainedSubjectStreamListenerReadbackV1::new(),
            subject_result: None,
            address: None,
            socket_custody: None,
            flags: None,
            nonblocking: None,
            closed: None,
        }
    }

    /// Returns the fixed native byte peak and one real duplicate file.
    ///
    /// Original stdin belongs to the separately retained process table. This
    /// geometry includes no namespace entry, account or purpose permission.
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<SocketAddr>())?
            .checked_add(8 * 256)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 1))
    }

    /// Captures descriptor zero and its existing listener options once.
    ///
    /// # Errors
    /// Retains native duplicate, option, address or fixed Cache socket-custody
    /// errors, and refuses wrong shape, path or repeated entry. The Cache
    /// recipe also retains its actual nonblocking flag transition.
    pub fn observe_once(&mut self) -> Result<(), FixedSignerListenerClosedV1> {
        if self.entered {
            self.closed.get_or_insert(FixedSignerListenerClosedV1);
            return Err(FixedSignerListenerClosedV1);
        }
        self.entered = true;
        self.duplicate = Some(aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor(0)
            .map(UnixListener::from));
        let listener = self.duplicate.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(FixedSignerListenerClosedV1)?;
        self.subject_result = Some(self.subject.observe_once(listener.as_fd()));
        self.address = Some(listener.local_addr());
        let expected = match self.recipe {
            Recipe::Source => SOURCE_PATH,
            Recipe::Cache { .. } => crate::cache_signer_connection::CACHE_SIGNER_SOCKET_PATH_V1,
        };
        if !self.subject.complete() || !self.address.as_ref().is_some_and(|result|
            result.as_ref().is_ok_and(|address| address.as_pathname() == Some(Path::new(expected))))
        {
            self.closed.get_or_insert(FixedSignerListenerClosedV1);
            return Err(FixedSignerListenerClosedV1);
        }
        if let Recipe::Cache { uid, gid } = self.recipe {
            self.socket_custody = Some(crate::cache_signer_connection::
                require_cache_signer_socket_custody_v1(uid, gid));
            if !matches!(self.socket_custody, Some(Ok(()))) {
                self.closed.get_or_insert(FixedSignerListenerClosedV1);
                return Err(FixedSignerListenerClosedV1);
            }
            self.make_cache_nonblocking_once()?;
        }
        Ok(())
    }

    fn make_cache_nonblocking_once(&mut self) -> Result<(), FixedSignerListenerClosedV1> {
        // A poll does not make a later blocking accept deadline-safe. Only
        // Cache's selected recipe changes the actual inherited listener.
        if self.flags.is_some() { return Err(FixedSignerListenerClosedV1); }
        let listener = self.duplicate.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(FixedSignerListenerClosedV1)?;
        self.flags = Some(fcntl_getfl(listener));
        if let Some(Ok(flags)) = self.flags.as_ref() {
            self.nonblocking = Some(fcntl_setfl(listener, *flags | OFlags::NONBLOCK));
        }
        if !matches!(self.nonblocking, Some(Ok(()))) {
            self.closed.get_or_insert(FixedSignerListenerClosedV1);
            return Err(FixedSignerListenerClosedV1);
        }
        Ok(())
    }

    /// Accepts one ordinary Source endpoint from the same completed listener.
    ///
    /// The owning role retains this actual returned result before adoption.
    /// Acceptance alone neither authenticates a sender nor grants a purpose.
    ///
    /// # Errors
    /// Preserves the actual accept error and refuses an incomplete listener.
    pub fn accept_once(&self) -> std::io::Result<(UnixStream, SocketAddr)> {
        if !matches!(self.recipe, Recipe::Source) || !self.complete() {
            return Err(std::io::Error::other("original fixed signer listener is unavailable"));
        }
        self.duplicate.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| std::io::Error::other("original fixed signer listener is unavailable"))?
            .accept()
    }

    /// Accepts one Cache endpoint with atomic nonblocking/close-on-exec flags.
    ///
    /// The actual private Cache purpose prepays and parks the returned native
    /// original before stream adoption. The listener is already nonblocking;
    /// this also prevents an accepted socket from blocking after readiness.
    ///
    /// # Errors
    /// Refuses another recipe/incomplete listener and preserves the actual
    /// accept4 errno, including interrupted or would-block outcomes.
    pub fn accept_cache_once(&self) -> rustix::io::Result<OwnedFd> {
        if !matches!(self.recipe, Recipe::Cache { .. }) || !self.complete() {
            return Err(rustix::io::Errno::INVAL);
        }
        let listener = self.duplicate.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(rustix::io::Errno::INVAL)?;
        accept_nonblocking_cache(listener)
    }

    /// Polls only the same retained listener using the supplied bounded timeout.
    ///
    /// The actual role retains this result and checks its absolute clock again
    /// before native accept. A timeout is comparison DATA, not a deadline grant.
    ///
    /// # Errors
    /// Preserves the actual poll error or refuses an incomplete listener.
    pub fn poll_once(&self, timeout: &Timespec) -> rustix::io::Result<(usize, PollFlags)> {
        if !self.complete() { return Err(rustix::io::Errno::INVAL); }
        let listener = self.duplicate.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(rustix::io::Errno::INVAL)?;
        let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
        let count = poll(&mut descriptors, Some(timeout))?;
        Ok((count, descriptors[0].revents()))
    }

    /// Reports complete native listener comparison DATA only.
    pub fn complete(&self) -> bool {
        self.entered && self.closed.is_none() && self.subject.complete()
            && self.address.as_ref().is_some_and(|result| result.as_ref().is_ok_and(|address|
                address.as_pathname() == Some(Path::new(match self.recipe {
                    Recipe::Source => SOURCE_PATH,
                    Recipe::Cache { .. } => crate::cache_signer_connection::CACHE_SIGNER_SOCKET_PATH_V1,
                }))))
            && match self.recipe {
                Recipe::Source => true,
                Recipe::Cache { .. } => matches!(self.socket_custody, Some(Ok(())))
                    && matches!(self.nonblocking, Some(Ok(()))),
            }
    }

    /// Borrows the earliest actual native error before fixed classification.
    pub fn native_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.duplicate.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
            .or_else(|| self.subject.failure().map(|error| error as _))
            .or_else(|| self.address.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.socket_custody.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.flags.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.nonblocking.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }

    /// Borrows the actual failure without replacing its earlier native cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_failure().or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn accept_nonblocking_cache(listener: &UnixListener) -> rustix::io::Result<OwnedFd> {
    accept_with(listener, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_listener_flag_transition_makes_empty_native_accept_nonblocking() {
        let directory = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(directory.path().join("native-cache-listener")).unwrap();
        assert!(!fcntl_getfl(&listener).unwrap().contains(OFlags::NONBLOCK));
        let mut original = FixedSignerListenerOriginalV1::cache(1001, 1002);
        // This is the actual owned native listener, without a financial or
        // admitted-role fixture. The private flag body performs real IO.
        original.duplicate = Some(Ok(listener));

        original.make_cache_nonblocking_once().unwrap();
        let held = original.duplicate.as_ref().unwrap().as_ref().unwrap();
        let result = held.accept();

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert!(fcntl_getfl(held).unwrap().contains(OFlags::NONBLOCK));
        assert!(matches!(original.flags, Some(Ok(_))));
        assert!(matches!(original.nonblocking, Some(Ok(()))));
        assert!(!original.complete());
        assert!(original.make_cache_nonblocking_once().is_err());
    }

    #[test]
    fn actual_accepted_cache_endpoint_has_atomic_native_flags() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native-cache-accepted-flags");
        let listener = UnixListener::bind(&path).unwrap();
        let flags = fcntl_getfl(&listener).unwrap();
        fcntl_setfl(&listener, flags | OFlags::NONBLOCK).unwrap();
        let _client = UnixStream::connect(&path).unwrap();

        let accepted = accept_nonblocking_cache(&listener).unwrap();

        assert!(fcntl_getfl(&accepted).unwrap().contains(OFlags::NONBLOCK));
        assert!(rustix::io::fcntl_getfd(&accepted).unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        assert!(matches!(accept_nonblocking_cache(&listener), Err(rustix::io::Errno::AGAIN)));
    }

}
