//! Separately entitled terminal requests against the exact isolated fault actor.

use super::*;

impl LivePagerController {
    pub(super) fn dispatch_fault_actor_test(
        &self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: RamControlFaultActorAction,
    ) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        if self.fault_actor_test_entitlement != Some(entitlement) {
            return self.reply(&mut state, RamControlDisposition::Unsupported);
        }
        if state.fork_preparing || state.policy_applying {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        if state
            .outer
            .is_none_or(|outer| outer_remaining(outer).is_err())
            || self.canceled.load(Ordering::Acquire)
        {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        let Some(owner) = state.owner.as_ref() else {
            return self.reply(&mut state, RamControlDisposition::Unavailable);
        };
        let disposition = match owner.fault_actor_report() {
            Ok(Some(report)) if report.worker_generation == worker_generation => {
                if action == RamControlFaultActorAction::Observe
                    || owner
                        .request_fault_actor_test_exit(worker_generation)
                        .is_ok()
                {
                    RamControlDisposition::Accepted
                } else {
                    RamControlDisposition::AdmissionRefused
                }
            }
            Ok(Some(_)) => RamControlDisposition::NotCurrent,
            _ => RamControlDisposition::Unavailable,
        };
        // Accepted means only the request is queued. The actor publishes its
        // cause and real membership disposition independently at its own poll.
        self.reply(&mut state, disposition)
    }
}
