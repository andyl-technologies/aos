//! Keeps only the actual completed SSH listener pins after bootstrap retirement.
//!
//! The private constructor consumes the verified same-child receipt. Rechecks
//! use those descriptors, the still-owned child and original execution cutoff;
//! they neither scan global socket tables nor adopt a persisted listener.

use super::*;

/// Retains the original listeners emitted by one owner-created SSH child.
///
/// The type has no public constructor. Its native observations cannot grant
/// process authority, extend an execution or replace recursive-empty and reap.
pub struct GuestSshListenerCustodyV1 {
    anchor: std::sync::Arc<crate::cgroup::RetainedCgroupAnchor>,
    execution: [u8; 16],
    port: u16,
    cookies: [u64; 2],
    cut: FixedProcessCaptureCutV3,
    rights: Vec<OwnedFd>,
    probes: [ListenerOriginal; 2],
    alive: Option<NativeResult<bool>>,
    clock: CaptureProcessCutOriginalV3,
    after_clock: CaptureProcessCutOriginalV3,
    primary: Option<NativeResult<()>>,
    after: Option<NativeResult<std::time::Duration>>,
    closed: Option<Error>,
}

impl GuestSshListenerCustodyV1 {
    pub(super) fn from_completed(
        anchor: std::sync::Arc<crate::cgroup::RetainedCgroupAnchor>,
        execution: [u8; 16],
        port: u16,
        cookies: [u64; 2],
        cut: FixedProcessCaptureCutV3,
        rights: Vec<OwnedFd>,
    ) -> Self {
        Self {
            anchor,
            execution,
            port,
            cookies,
            cut,
            rights,
            probes: std::array::from_fn(|_| ListenerOriginal::default()),
            alive: None,
            clock: Default::default(),
            after_clock: Default::default(),
            primary: None,
            after: None,
            closed: None,
        }
    }

    /// Rechecks the same actual listeners and child under the original horizon.
    ///
    /// Every entered observation owes its independent clock after, including
    /// failures of the primary clock or a native listener probe. A failed
    /// prefix is sticky and retains all pins and its original native cause.
    ///
    /// # Errors
    /// Refuses a foreign scope, changed listener, dead child, expired original
    /// cutoff, failed native observation or an earlier incomplete observation.
    pub fn recheck_once_v1(&mut self, scope: &GuestSshScopeOriginalV1) -> NativeResult<()> {
        if self.failure().is_some() || self.primary.is_some() {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.primary = Some(self.recheck_inner(scope));
        self.after = Some(self.after_clock.observe(self.cut));
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.after, Some(Ok(_))) {
            return Err(closed());
        }
        // These observations own no FDs and have completed both bookends.
        // Listener descriptors and their original identity remain resident.
        self.primary = None;
        self.after = None;
        self.alive = None;
        self.probes = std::array::from_fn(|_| ListenerOriginal::default());
        Ok(())
    }

    fn recheck_inner(&mut self, scope: &GuestSshScopeOriginalV1) -> NativeResult<()> {
        if !std::sync::Arc::ptr_eq(&self.anchor, scope.bootstrap_anchor_v1()?)
            || scope.execution_data_v1() != self.execution
            || !(1..=2).contains(&self.rights.len())
        {
            return Err(closed());
        }
        self.clock.observe(self.cut)?;
        self.alive = Some(scope.child_pidfd_v1()?.is_alive());
        if !matches!(self.alive, Some(Ok(true))) {
            return Err(closed());
        }
        for (index, fd) in self.rights.iter().enumerate() {
            self.probes[index].capture(fd.as_fd(), self.port, self.cookies[index])?;
        }
        Ok(())
    }

    /// Borrows the actual first failed observation without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.primary.as_ref() {
            return self
                .clock
                .failure()
                .map(|cause| cause as _)
                .or_else(|| self.alive.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.probes.iter().find_map(ListenerOriginal::failure))
                .or(Some(cause));
        }
        self.after
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| clock_cause(cause, &self.after_clock))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<OwnedFd>())?
            .checked_add(2 * std::mem::size_of::<rustix::net::SocketAddrAny>())?
            .checked_add(
                2 * ("Guest SSH bootstrap original".len()
                    + "native prefix is incomplete or refused".len()),
            )
    }
}
