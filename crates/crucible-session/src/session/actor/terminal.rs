//! Actor-side publication of terminal engine failures.

use super::*;

impl<L> SessionActor<L>
where
    L: QuantumLoop,
{
    pub(super) fn terminalize_actor_error(&mut self, error: &SessionError) {
        self.engine.stop_after_actor_crash(error.to_string());
        self.sync_reproduction_log();
        self.publish_live_snapshot();
    }
}
