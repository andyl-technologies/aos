//! Pins the journal's filesystem owner to the protected endpoint role.
//!
//! Broker journals remain root-owned. Client journals belong to the service
//! execution whose custody is revalidated around capture and every reopen.
//! This is filesystem custody, not a UID-to-project authentication mapping.

use std::path::Path;

use aos_sandbox::{Journal, JournalError, JournalLimits, RecoveryReport};
use aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1;

/// Retains the initial owner policy across all ambiguous-write reopen attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JournalOwnerV1 {
    RootBroker,
    ServiceClient(u32),
}

impl JournalOwnerV1 {
    /// Captures only after the endpoint has revalidated its pinned execution.
    pub(super) fn capture(role: BrokerSessionDurableEndpointV1) -> Self {
        Self::for_role(role, rustix::process::geteuid().as_raw())
    }

    const fn for_role(role: BrokerSessionDurableEndpointV1, service_uid: u32) -> Self {
        match role {
            BrokerSessionDurableEndpointV1::Client => Self::ServiceClient(service_uid),
            BrokerSessionDurableEndpointV1::Broker => Self::RootBroker,
        }
    }

    pub(super) fn open(
        self,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Journal, RecoveryReport), JournalError> {
        match self {
            Self::RootBroker => Journal::open_protected_at(directory, name, limits),
            Self::ServiceClient(uid) => {
                Journal::open_protected_at_for_uid(directory, name, limits, uid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_journals_never_adopt_an_unprivileged_process_owner() {
        for uid in [0, 811, 65534] {
            assert_eq!(
                JournalOwnerV1::for_role(BrokerSessionDurableEndpointV1::Broker, uid),
                JournalOwnerV1::RootBroker,
            );
        }
    }

    #[test]
    fn client_owner_is_exact_and_retained_for_reopen() {
        for uid in [0, 811, 65534] {
            let owner = JournalOwnerV1::for_role(BrokerSessionDurableEndpointV1::Client, uid);
            let retained = owner;

            assert_eq!(retained, JournalOwnerV1::ServiceClient(uid));
            assert_ne!(retained, JournalOwnerV1::RootBroker);
        }
        assert_eq!(
            JournalOwnerV1::capture(BrokerSessionDurableEndpointV1::Client),
            JournalOwnerV1::ServiceClient(rustix::process::geteuid().as_raw()),
        );
    }
}
