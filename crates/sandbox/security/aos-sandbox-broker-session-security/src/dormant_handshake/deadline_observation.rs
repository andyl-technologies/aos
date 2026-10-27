//! Retains the original BOOTTIME sample at the same cold-cutoff comparator.
//!
//! The actual opaque cutoff is never renewed. This sink stores no authority,
//! clock snapshot grant, payer or permission to enter a native operation.

use std::error::Error;

use super::{DormantBrokerSessionHandshakeErrorV1, Timespec};
use crate::handshake::OriginalBrokerColdDeadlineV1;

pub(crate) struct BrokerColdDeadlineObservationV1 {
    sample: Option<Timespec>,
    returned: Option<Result<u64, DormantBrokerSessionHandshakeErrorV1>>,
    closed: Option<DormantBrokerSessionHandshakeErrorV1>,
    entered: bool,
}

impl BrokerColdDeadlineObservationV1 {
    pub(crate) const fn new() -> Self {
        Self { sample: None, returned: None, closed: None, entered: false }
    }

    fn observe_value_once(&mut self, deadline: u64)
        -> Result<(), DormantBrokerSessionHandshakeErrorV1>
    {
        if self.entered {
            self.closed.get_or_insert(DormantBrokerSessionHandshakeErrorV1::Transport);
            return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
        }
        self.entered = true;
        self.returned = Some(super::remaining_handshake_nanoseconds_observed(
            deadline, Some(&mut self.sample),
        ));
        match self.returned.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(DormantBrokerSessionHandshakeErrorV1::Deadline)) => {
                Err(DormantBrokerSessionHandshakeErrorV1::Deadline)
            }
            _ => Err(DormantBrokerSessionHandshakeErrorV1::Transport),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.returned.as_ref().and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref()).map(|cause| cause as _)
    }
}

impl OriginalBrokerColdDeadlineV1 {
    /// Checks the same original cutoff while retaining its actual native sample.
    ///
    /// # Errors
    /// Preserves the shared comparator's deadline/encoding classes and fences
    /// reentry without observing another clock or renewing the cutoff.
    pub(crate) fn check_retaining_once_v1(
        self,
        original: &mut BrokerColdDeadlineObservationV1,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        original.observe_value_once(self.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_native_sample_and_original_cause_survive_reentry() {
        let mut original = BrokerColdDeadlineObservationV1::new();
        assert!(matches!(original.observe_value_once(0),
            Err(DormantBrokerSessionHandshakeErrorV1::Deadline)));
        let sample = original.sample.expect("actual same-engine BOOTTIME sample");
        let cause = std::ptr::from_ref(original.failure().unwrap()).cast::<()>();

        assert!(matches!(original.observe_value_once(u64::MAX),
            Err(DormantBrokerSessionHandshakeErrorV1::Transport)));

        assert_eq!(original.sample, Some(sample));
        assert_eq!(std::ptr::from_ref(original.failure().unwrap()).cast::<()>(), cause);
        assert!(matches!(original.returned,
            Some(Err(DormantBrokerSessionHandshakeErrorV1::Deadline))));
    }
}
