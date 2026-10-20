//! Owns the actual fixed child and bounded carrier wait, without a TPM factory.

use std::os::fd::BorrowedFd;
use std::process::Child;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::NvCustodyErrorV1;

/// Stops/reaps its exact spawned child on every owner exit.
pub(crate) struct OwnedHelperChildV1(pub(crate) Child);

impl Drop for OwnedHelperChildV1 {
    fn drop(&mut self) {
        // Child owns this process instance. No TPM clear/reset/undefine occurs.
        // Restart still requires the original service-population barrier; an
        // OFD loan alone does not order deferred kernel release on SIGKILL.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn wait_channel(
    fd: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), NvCustodyErrorV1> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(NvCustodyErrorV1::Unavailable)?;
    let timeout = Timespec::try_from(remaining).map_err(|_| NvCustodyErrorV1::Unavailable)?;
    let mut descriptors = [PollFd::new(&fd, interest)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(_) if descriptors[0].revents().contains(interest) => Ok(()),
        Err(rustix::io::Errno::INTR) => Ok(()),
        _ => Err(NvCustodyErrorV1::Unavailable),
    }
}
