//! Restore-only network-transmit continuation state.

use super::PluginNetworkTx;

impl PluginNetworkTx {
    /// Restores the authenticated sequence before VM execution resumes.
    pub(crate) fn restore_next_seq(&self, next_seq: u32) {
        self.next_seq.set(next_seq);
    }
}
