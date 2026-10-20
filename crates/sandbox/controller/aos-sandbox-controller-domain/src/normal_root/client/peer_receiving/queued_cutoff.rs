//! Keeps the same absolute Root-turn cutoff at the queued PID1 frontier.
//!
//! This passive original owns the actual native sample before comparison. It
//! neither renews a deadline nor supplies role, receiving or task authority.

use super::Refusal;

pub(super) struct PropertyQueuedCutoffOriginalV1 {
    sample: Option<rustix::time::Timespec>,
    returned: Option<Result<(), Refusal>>,
    reentry: Option<Refusal>,
}

impl PropertyQueuedCutoffOriginalV1 {
    pub(super) const fn new() -> Self {
        Self { sample: None, returned: None, reentry: None }
    }

    pub(super) fn observe_once(&mut self, cutoff: u64) -> Result<(), Refusal> {
        if self.returned.is_some() {
            self.reentry.get_or_insert(Refusal::Service);
            return Err(Refusal::Service);
        }
        self.sample = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.returned = Some((|| {
            let sample = self.sample.as_ref().ok_or(Refusal::Service)?;
            let seconds = u64::try_from(sample.tv_sec).map_err(|_| Refusal::Service)?;
            let nanos = u64::try_from(sample.tv_nsec).map_err(|_| Refusal::Service)?;
            if nanos >= 1_000_000_000 { return Err(Refusal::Service); }
            let now = seconds.checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanos)).ok_or(Refusal::Service)?;
            if now < cutoff { Ok(()) } else { Err(Refusal::Service) }
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(Refusal::Service) }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.returned.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref()).map(|cause| cause as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_queued_sample_survives_attempted_deadline_renewal() {
        let mut original = PropertyQueuedCutoffOriginalV1::new();
        assert!(original.observe_once(0).is_err());
        let sample = original.sample.unwrap();
        let cause = std::ptr::from_ref(original.failure().unwrap()).cast::<()>();

        assert!(original.observe_once(u64::MAX).is_err());

        let retained = original.sample.unwrap();
        assert_eq!((sample.tv_sec, sample.tv_nsec), (retained.tv_sec, retained.tv_nsec));
        assert_eq!(std::ptr::from_ref(original.failure().unwrap()).cast::<()>(), cause);
    }
}
