//! Retains the isolated actor's original failure through native role disposition.

use super::*;
use crucible_protocol::ram_control::{RamControlFaultActorFailure, RamControlFaultActorReport};

#[derive(Default)]
pub(in crate::paged_ram::engine) struct ActorLifetime {
    thread_id: u64,
    exit_requested: bool,
    failure: Option<RamError>,
    membership_released: bool,
}

impl ActorLifetime {
    pub(in crate::paged_ram::engine) fn admitted(&mut self, thread_id: u64) {
        self.thread_id = thread_id;
    }

    pub(in crate::paged_ram::engine) fn request_exit(&mut self) -> Result<(), RamError> {
        if self.thread_id == 0 || self.failure.is_some() || self.membership_released {
            return Err(RamError::Invariant("fault actor is not live"));
        }
        self.exit_requested = true;
        Ok(())
    }

    pub(in crate::paged_ram::engine) fn poll(&self) -> Result<(), RamError> {
        if self.exit_requested {
            return Err(RamError::FaultActorTestExit);
        }
        Ok(())
    }

    pub(in crate::paged_ram::engine) fn failed(&mut self, failure: RamError) {
        // The first concrete cause remains retained after the worker returns.
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }

    pub(in crate::paged_ram::engine) fn released(&mut self) {
        self.membership_released = true;
    }

    pub(in crate::paged_ram::engine) fn report(
        &self,
        worker_generation: u64,
    ) -> Option<RamControlFaultActorReport> {
        if self.thread_id == 0 || (self.membership_released && self.failure.is_none()) {
            return None;
        }
        let failure = self.failure.as_ref().map(|failure| match failure {
            RamError::FaultActorTestExit => RamControlFaultActorFailure::RequestedExit,
            RamError::Io(source) => RamControlFaultActorFailure::Io {
                errno: source.raw_os_error().unwrap_or(0),
            },
            _ => RamControlFaultActorFailure::Other,
        });
        Some(RamControlFaultActorReport {
            worker_generation,
            thread_id: self.thread_id,
            exit_requested: self.exit_requested,
            failure,
            membership_released: self.membership_released,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_report_keeps_original_io_cause_until_role_release() {
        let mut state = ActorLifetime::default();
        assert!(state.request_exit().is_err());
        state.admitted(123);
        state.failed(std::io::Error::from_raw_os_error(libc::EIO).into());
        state.failed(RamError::FaultActorTestExit);
        assert!(state.request_exit().is_err());

        let before = state
            .report(7)
            .unwrap_or_else(|| panic!("admitted actor report"));
        assert_eq!(
            before.failure,
            Some(RamControlFaultActorFailure::Io { errno: libc::EIO })
        );
        assert!(!before.membership_released);
        state.released();
        let after = state
            .report(7)
            .unwrap_or_else(|| panic!("retained terminal report"));
        assert!(after.membership_released);
        assert_eq!(after.failure, before.failure);
    }

    #[test]
    fn requested_exit_is_returned_by_the_actor_poll() {
        let mut state = ActorLifetime::default();
        state.admitted(456);
        assert!(state.poll().is_ok());
        state
            .request_exit()
            .unwrap_or_else(|error| panic!("live actor request: {error}"));
        assert!(matches!(state.poll(), Err(RamError::FaultActorTestExit)));
        let before = state.report(8).unwrap_or_else(|| panic!("live report"));
        assert!(before.exit_requested);
        assert!(before.failure.is_none());
        state.failed(RamError::FaultActorTestExit);
        state.released();
        let after = state.report(8).unwrap_or_else(|| panic!("terminal report"));
        assert_eq!(
            after.failure,
            Some(RamControlFaultActorFailure::RequestedExit)
        );
        assert!(after.membership_released);
    }
}
