//! Keeps Source's real F/lifetime around the shared fixed listener observer.
//!
//! Only the actual Source startup invokes the inherited descriptor-zero recipe
//! after prepayment. The lower owner grants no role or operation authority.

use std::error::Error;
use std::os::unix::net::{SocketAddr, UnixStream};

use aos_sandbox_broker::receiving::FixedSignerListenerOriginalV1;
use super::{CLOSED, SourceReceivingClosedV1};

pub(super) struct SourceInheritedListenerV1 {
    original: FixedSignerListenerOriginalV1,
}

impl Default for SourceInheritedListenerV1 {
    fn default() -> Self { Self { original: FixedSignerListenerOriginalV1::source() } }
}

impl SourceInheritedListenerV1 {
    pub(super) fn observe_once(&mut self) -> Result<(), SourceReceivingClosedV1> {
        self.original.observe_once().map_err(|_| CLOSED)
    }

    pub(super) fn accept_once(&self) -> std::io::Result<(UnixStream, SocketAddr)> {
        if !self.complete() {
            return Err(std::io::Error::other("original Source listener is unavailable"));
        }
        self.original.accept_once()
    }

    pub(super) fn complete(&self) -> bool { self.original.complete() }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.native_failure().or_else(|| self.original.failure().map(|_| &CLOSED as _))
    }
}
