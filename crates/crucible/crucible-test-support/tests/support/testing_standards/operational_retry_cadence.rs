//! Binds scheduling-only retry tokens to their finite cadence implementation.
//!
//! Exact scheduling and component controls grant no operation or guest-time
//! authority. Callers still require their own saved-original effect contracts.

use super::{Companion, Contract};

const CADENCE_PATH: &str =
    "crates/crucible/crucible-host-resources/src/host_supervision/retry_cadence.rs";
const CLOCK_PATH: &str = "crates/crucible/crucible-host-resources/src/host_supervision.rs";
const EXPORT: &str = "mod retry_cadence;\npub use retry_cadence::HostRetryCadence;";
const CLOCK: &str = "fn host_now() -> Instant {\n    Instant::now()\n}";

const OWNER: &str = r#"#[derive(Clone, Copy, Debug, Default)]
pub struct HostRetryCadence {
    next: Option<Instant>,
}"#;

const METHODS: &str = r#"impl HostRetryCadence {
    /// Returns the remaining delay, or schedules one eligible physical attempt.
    ///
    /// A zero delay describes scheduling eligibility only. The next retry is
    /// recorded before the caller attempts an effect, even if that effect fails.
    /// The caller must independently check the same retained operation around
    /// every physical attempt; this method creates no operation or permission.
    ///
    /// # Errors
    /// Returns [`HostSupervisionError::InvalidBudget`] for a zero interval or an
    /// unrepresentable next retry. Refusal preserves the previous schedule.
    pub fn poll(&mut self, interval: Duration) -> Result<Duration, HostSupervisionError> {
        self.poll_at(host_now(), interval)
    }

    /// Reports whether an eligible retry has already established a schedule.
    ///
    /// This observation proves neither a physical attempt nor its completion.
    #[must_use]
    pub fn is_scheduled(&self) -> bool {
        self.next.is_some()
    }

    fn poll_at(
        &mut self,
        now: Instant,
        interval: Duration,
    ) -> Result<Duration, HostSupervisionError> {
        if interval.is_zero() {
            return Err(HostSupervisionError::InvalidBudget);
        }

        if let Some(next) = self.next.filter(|next| *next > now) {
            return Ok(next.duration_since(now));
        }

        let next = now
            .checked_add(interval)
            .ok_or(HostSupervisionError::InvalidBudget)?;
        self.next = Some(next);
        Ok(Duration::ZERO)
    }
}"#;

const CONTROLS: &str = r#"#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_readiness_cannot_accelerate_a_scheduled_job() {
        let now = host_now();
        let interval = Duration::from_millis(10);
        let mut job = HostRetryCadence::default();
        let mut other = HostRetryCadence::default();

        assert_eq!(job.poll_at(now, interval), Ok(Duration::ZERO));
        for elapsed in 1..10 {
            let event = now + Duration::from_millis(elapsed);
            let _ = other.poll_at(event, interval).unwrap();
            assert_eq!(
                job.poll_at(event, interval),
                Ok(Duration::from_millis(10 - elapsed))
            );
        }

        assert_eq!(job.poll_at(now + interval, interval), Ok(Duration::ZERO));
        assert_eq!(job.poll_at(now + interval, interval), Ok(interval));
    }

    #[test]
    fn moving_to_quarantine_keeps_the_existing_retry_delay() {
        let now = host_now();
        let interval = Duration::from_millis(10);
        let mut running = HostRetryCadence::default();
        assert!(!running.is_scheduled());
        assert_eq!(running.poll_at(now, interval), Ok(Duration::ZERO));

        let mut quarantined = running;
        assert!(quarantined.is_scheduled());
        assert_eq!(quarantined.poll_at(now, interval), Ok(interval));
    }

    #[test]
    fn invalid_intervals_preserve_the_previous_schedule() {
        let now = host_now();
        let mut cadence = HostRetryCadence::default();

        assert_eq!(
            cadence.poll_at(now, Duration::ZERO),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert!(!cadence.is_scheduled());
        assert_eq!(
            cadence.poll_at(now, Duration::MAX),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert!(!cadence.is_scheduled());

        let interval = Duration::from_millis(10);
        assert_eq!(cadence.poll_at(now, interval), Ok(Duration::ZERO));
        let scheduled = cadence.next;
        assert_eq!(
            cadence.poll_at(now + interval, Duration::MAX),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert_eq!(cadence.next, scheduled);
    }
}"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-host-resources",
        target: "src/host_supervision/retry_cadence",
        required: &[OWNER, METHODS, CONTROLS],
        expressions: &[(OWNER, 1), (METHODS, 1), (CONTROLS, 1)],
        companions: &[Companion {
            path: CLOCK_PATH,
            required: &[CLOCK, EXPORT],
            counts: &[(CLOCK, 1), (EXPORT, 1)],
        }],
    },
    Contract {
        package: "crucible-host-resources",
        target: "src/host_supervision",
        required: &[EXPORT, CLOCK],
        expressions: &[(EXPORT, 1)],
        companions: &[Companion {
            path: CADENCE_PATH,
            required: &[OWNER, METHODS, CONTROLS],
            counts: &[(OWNER, 1), (METHODS, 1), (CONTROLS, 1)],
        }],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source(contract: &Contract) -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn cadence_classification_requires_the_exact_finite_owner_and_monotonic_clock()
    -> Result<(), Box<dyn std::error::Error>> {
        for contract in CONTRACTS {
            let code = source(contract)?;
            let companions = read_companions(contract)?;

            assert!(has_retry(&code));
            assert!(!has_retry(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            let extra = format!("{code}\nfn unrelated_retry() {{ loop {{ retry(); }} }}");
            assert!(has_retry(&mask_with_companions(
                contract,
                &extra,
                &companions
            )));

            for (index, binding) in contract.companions.iter().enumerate() {
                for required in binding.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] = changed[index].replacen(required, "foreign_retry();", 1);
                    assert!(has_retry(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn cadence_classification_rejects_renewal_reset_or_weakened_component_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let code = source(contract)?;
        let companions = read_companions(contract)?;
        let compact = super::super::compact_code(&code);

        for (before, after) in [
            (
                "self.poll_at(host_now(),interval)",
                "self.poll_at(host_now(),Duration::ZERO)",
            ),
            ("self.next=Some(next);", "self.next=None;"),
            (
                "self.next.filter(|next|*next>now)",
                "self.next.filter(|next|*next>=now)",
            ),
            ("now.checked_add(interval)", "now.checked_sub(interval)"),
            ("Ok(Duration::ZERO)", "Ok(interval)"),
            (
                "letmutquarantined=running;",
                "letmutquarantined=HostRetryCadence::default();",
            ),
            (
                "let_=other.poll_at(event,interval).unwrap();",
                "let_=job.poll_at(event,interval).unwrap();",
            ),
            (
                "assert_eq!(cadence.next,scheduled);",
                "assert_eq!(cadence.next,None);",
            ),
        ] {
            assert!(
                compact.contains(before),
                "missing actual cadence cut: {before}"
            );
            let changed = compact.replacen(before, after, 1);
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &companions)),
                "changed cadence was classified: {before}"
            );
        }
        Ok(())
    }
}
