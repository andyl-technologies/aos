//! Separates an observation's issue time from its conservative expiry check.

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::{DirectRequestContext, WireInteger};

/// Retains the actual observation time and the original exclusive cutoff.
pub(super) struct ObservationWindow {
    /// Observed producer clock time after the actual reservation check.
    pub(super) issued_at: WireInteger,
    /// Earlier original context or admission cutoff, without renewal.
    pub(super) expires_at: WireInteger,
}

impl ObservationWindow {
    /// Checks a fresh observation against the original context and admission.
    ///
    /// # Errors
    /// Rejects a regressed clock, stale context or conservatively expired window.
    pub(super) fn new(
        context: &DirectRequestContext,
        admission_expires_at: WireInteger,
        observed_at: u64,
        latest_now: u64,
    ) -> Result<Self> {
        context.validate(
            &context.deployment_id,
            &context.executor_public_origin,
            latest_now,
        )?;
        ensure!(
            context.issued_at.get() <= observed_at && observed_at <= latest_now,
            "direct baseline observation clock regressed"
        );
        let expires_at = context.expires_at.get().min(admission_expires_at.get());
        ensure!(
            latest_now < expires_at,
            "direct baseline observation expired"
        );

        // Uncertainty bounds expiry; adding it to an issue time can put the
        // witness in the future of another independently qualified clock.
        Ok(Self {
            issued_at: WireInteger::new(observed_at),
            expires_at: WireInteger::new(expires_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use aos_hub_db::direct_upload::{DirectDestinationBaselineWitness, DirectForegroundBudget};

    use super::*;

    fn context() -> DirectRequestContext {
        DirectRequestContext {
            deployment_id: "fixture-deployment".into(),
            executor_public_origin: "https://worker.example.test".into(),
            public_authority: "worker.example.test".into(),
            foreground: DirectForegroundBudget {
                invocation_id: "11".repeat(32),
                issued_at: WireInteger::new(100),
                expires_at: WireInteger::new(130),
            },
            request_nonce: "22".repeat(32),
            request_body_sha256: "33".repeat(32),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        }
    }

    #[test]
    fn observation_remains_current_when_independently_qualified_clocks_differ() {
        let owner = super::super::fixture::reservation("fixture-deployment", "fixture/final");
        let baseline = owner.baseline.unwrap();
        let context = context();
        let window =
            ObservationWindow::new(&context, owner.admission.expires_at, 100, 101).unwrap();
        let witness = DirectDestinationBaselineWitness {
            binding: baseline.binding.clone(),
            baseline_digest: baseline.fingerprint().unwrap(),
            observation_operation_id: "aa".repeat(32),
            issued_at: window.issued_at,
            expires_at: window.expires_at,
        };

        // The consumer reads 99 with one second of qualified uncertainty. The
        // producer's upper bound of 101 is not the observation's issue time.
        witness.validate_for(&baseline, &context, 100).unwrap();

        assert_eq!(witness.issued_at.get(), 100);
        assert_eq!(witness.expires_at.get(), 130);
        assert!(witness.validate_for(&baseline, &context, 130).is_err());
    }

    #[test]
    fn expiry_uses_the_upper_bound_and_keeps_the_earlier_original_cutoff() {
        let context = context();

        assert!(ObservationWindow::new(&context, WireInteger::new(130), 129, 130).is_err());
        assert!(ObservationWindow::new(&context, WireInteger::new(120), 119, 120).is_err());
        let window = ObservationWindow::new(&context, WireInteger::new(120), 118, 119).unwrap();

        assert_eq!(window.expires_at.get(), 120);
    }

    #[test]
    fn observation_cannot_precede_its_challenge_or_exceed_the_current_bound() {
        let context = context();

        assert!(ObservationWindow::new(&context, WireInteger::new(130), 99, 100).is_err());
        assert!(ObservationWindow::new(&context, WireInteger::new(130), 102, 101).is_err());
    }
}
