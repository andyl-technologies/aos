//! Fresh runtime evidence joined to the original live holder request.
//!
//! Lease renewal may advance publication history without replacing a channel.
//! The complete intervening protected history must preserve holder and manifest,
//! and both observations must retain the same live Host and payload executions.
//! Neither historical audit bytes nor an administrative cgroup can supply origin.

use super::*;
use crate::runtime_authority::RuntimeAuthorityStore;
use crate::runtime_scope::{
    CurrentRuntimeScope, CurrentRuntimeScopeError, CurrentRuntimeScopePolicy, RuntimeScopeClient,
    RuntimeScopeHolder, acquire_current_runtime,
};

/// Retains fresh runtime evidence for an authenticated publisher request join.
///
/// This is not admission or a publication permit. Source release, root authority,
/// capability operation authorization, reservation, challenge consumption, and
/// signing remain separate checks. The scope has a fixed short deadline and
/// cannot be restored from audit records or renewed by rechecking.
///
/// ```compile_fail
/// use aos_sandbox::publisher_control::{JoinedPublisherRequest, RuntimeJoinedPublisherRequest};
/// fn promote<'a>(join: JoinedPublisherRequest<'a>) -> RuntimeJoinedPublisherRequest<'a> {
///     join.into()
/// }
/// ```
pub struct RuntimeJoinedPublisherRequest<'a> {
    joined: JoinedPublisherRequest<'a>,
    runtime: CurrentRuntimeScope,
}

impl<'a> JoinedPublisherRequest<'a> {
    /// Acquires fresh Host evidence and joins it to this channel's retained origin.
    ///
    /// Trusted configuration supplies the connected Host client and authority
    /// policy; holder and sandbox selection come only from the actual session.
    /// The clock must be the same protected adapter used for issuance and joining.
    /// Lease renewal is allowed only across uninterrupted bound decisions for the
    /// identical holder and manifest. The old observation's deadline is not
    /// extended or used as the channel lifetime.
    ///
    /// # Errors
    /// Rejects administrative origins, invalidated joins, stale channels, failed
    /// Host or signature checks, changed boot/clock identity, broken historical
    /// continuity, and replaced executions. Any failure closes holder ingress.
    pub fn bind_current_runtime<T>(
        mut self,
        client: RuntimeScopeClient,
        policy: CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<RuntimeJoinedPublisherRequest<'a>, PublisherJoinError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let result = (|| {
            self.recheck(clock)?;
            let origin = self
                .holder
                .runtime_origin()
                .ok_or(PublisherJoinError::HolderMismatch)?;
            if origin.binding().manifest().manifest().node() != policy.node
                || self.publisher.scope().node != policy.node
                || origin.observation_clock().provenance().as_bytes() != policy.clock_provenance
                || policy.clock_provenance != self.config.control.clock_provenance
            {
                return Err(CurrentRuntimeScopeError::Configuration.into());
            }
            let scope = self.holder.scope();
            Ok(acquire_current_runtime(
                self.journal,
                RuntimeScopeHolder {
                    sandbox: scope.sandbox,
                    holder: scope.holder,
                },
                client,
                policy,
                clock,
            )?)
        })();
        let runtime = match result {
            Ok(runtime) => runtime,
            Err(error) => {
                self.valid = false;
                self.holder.close_channel();
                return Err(error);
            }
        };
        let mut result = RuntimeJoinedPublisherRequest {
            joined: self,
            runtime,
        };
        result.recheck(clock)?;
        Ok(result)
    }
}

impl RuntimeJoinedPublisherRequest<'_> {
    /// Borrows the exact request received on the original holder channel.
    #[must_use]
    pub fn request(&self) -> &PublisherAdmissionRequestV1 {
        self.joined.request()
    }

    /// Borrows the fresh scope without extracting or renewing its authority.
    #[must_use]
    pub const fn runtime(&self) -> &CurrentRuntimeScope {
        &self.runtime
    }

    /// Rechecks the joined channels, current authority, and uninterrupted origin.
    ///
    /// # Errors
    /// Rejects changed or expired joins, runtime revisions, clocks, or execution
    /// pins. A failure permanently invalidates this join and closes holder ingress.
    pub fn recheck<T>(&mut self, clock: &mut T) -> Result<(), PublisherJoinError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let result = self.check_current(clock);
        if result.is_err() {
            self.joined.valid = false;
            self.joined.holder.close_channel();
        }
        result
    }

    fn check_current<T>(&mut self, clock: &mut T) -> Result<(), PublisherJoinError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.joined.recheck(clock)?;
        self.runtime.recheck(self.joined.journal, clock)?;
        let origin = self
            .joined
            .holder
            .runtime_origin()
            .ok_or(PublisherJoinError::HolderMismatch)?;
        if origin.observation_clock().host_boot_id()
            != self.runtime.observation_clock().host_boot_id()
            || origin.observation_clock().provenance()
                != self.runtime.observation_clock().provenance()
            || origin.observation_clock().boottime_nanoseconds()
                > self.runtime.observation_clock().boottime_nanoseconds()
            || origin.observation_clock().wall_seconds()
                > self.runtime.observation_clock().wall_seconds()
        {
            return Err(CurrentRuntimeScopeError::Clock.into());
        }
        RuntimeAuthorityStore::load(
            self.joined.journal,
            self.joined.config.authority_limits.runtime_limits(),
        )
        .and_then(|store| store.validate_continuity(origin.binding(), self.runtime.binding()))
        .map_err(CurrentRuntimeScopeError::from)?;
        origin
            .observed()
            .check_continuity(self.runtime.observed())
            .map_err(CurrentRuntimeScopeError::from)?;
        self.joined.recheck(clock)?;
        self.runtime.recheck(self.joined.journal, clock)?;
        Ok(())
    }
}
