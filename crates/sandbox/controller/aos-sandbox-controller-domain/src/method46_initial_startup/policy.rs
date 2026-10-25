//! Retains Source-paid enforcing-policy comparisons for manual initial startup.
//!
//! The canonical package pathname and digest are comparison DATA from the held
//! profile. Each probe uses the existing native enforcing-policy engine; neither
//! a profile pin nor a matching policy creates a writer or provisioning grant.

use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, RetainedLiveSelinuxPolicyReadbackV1};

use super::*;

pub(super) struct InitialPolicyOriginalV1 {
    observations: [RefCell<PolicyObservationOriginalV1>; 2],
    paid: bool,
    entered: bool,
}

struct PolicyObservationOriginalV1 {
    original: RetainedLiveSelinuxPolicyReadbackV1,
    result: Option<Result<(), PolicyReadbackError>>,
    digest_matches: Option<bool>,
    entered: bool,
}

impl PolicyObservationOriginalV1 {
    fn new() -> Self {
        Self {
            original: RetainedLiveSelinuxPolicyReadbackV1::new(),
            result: None,
            digest_matches: None,
            entered: false,
        }
    }
}

impl InitialPolicyOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            observations: std::array::from_fn(|_| RefCell::new(PolicyObservationOriginalV1::new())),
            paid: false,
            entered: false,
        }
    }

    fn observe(
        &self,
        index: usize,
        profile: Option<&Method46InitialProfileDataV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut observation = self
            .observations
            .get(index)
            .ok_or(Method46InitialStartupClosedV1)?
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if observation.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        observation.entered = true;
        let pin = &profile
            .ok_or(Method46InitialStartupClosedV1)?
            .canonical_policy;
        observation.result = Some(observation.original.verify_once(&pin.path));
        observation.digest_matches = observation
            .original
            .verified()
            .map(|observed| observed.digest() == pin.sha256);
        if matches!(observation.result, Some(Ok(()))) && observation.digest_matches == Some(true) {
            Ok(())
        } else {
            Err(Method46InitialStartupClosedV1)
        }
    }

    pub(super) fn finish_post(
        &self,
        profile: Option<&Method46InitialProfileDataV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.paid {
            return Ok(());
        }
        // Payment precedes the initial probe. Its failure cannot suppress this
        // independent enforcing-policy read, even after another startup post.
        self.observe(1, profile)
    }
}

fn policy_demand() -> Option<ResourceVector> {
    let native = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
    // Both retained native headers already belong to the prepaid boxed body.
    // Keep the engine's full scratch allowance and fixed pathname overhead.
    let memory = native
        .memory_bytes
        .checked_sub(std::mem::size_of::<RetainedLiveSelinuxPolicyReadbackV1>())?
        .checked_add(2 * PATH_BYTES)?;
    let one = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
        .with(D::OpenFiles, u64::try_from(native.open_files).ok()?)
        .with(D::MetadataEntries, native.metadata_entries)
        .with(D::OutputBytes, native.input_bytes);
    one.checked_add(one).ok()
}

impl Method46InitialStartupOriginalV1 {
    /// Compares the actual enforcing policy with the original profile's pin.
    ///
    /// The same captured Source prepays both native observations before entry.
    /// The independently owed post uses its own retained destination even when
    /// this initial comparison or another startup stage refuses. Matching bytes
    /// supply no journal, approval, TPM, checkpoint or readiness authority.
    ///
    /// # Errors
    /// Refuses missing current capture, profile admission, payment, repetition,
    /// permissive state, changed policy bytes or any native verifier failure.
    pub fn observe_live_policy_once_v1(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        if body.policy.entered || !matches!(body.profile_shape, Some(Ok(()))) {
            return Err(self.fail(First::Policy));
        }
        body.policy.entered = true;
        self.fund_additional(policy_demand())?;

        let body = self.body.as_mut().ok_or(self.closed)?;
        body.policy.paid = true;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        if body.policy.observe(0, profile).is_err() {
            return Err(self.fail(First::Policy));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn missing_source_cannot_pay_or_enter_policy_observations() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));
            startup.body = Some(Box::new(StartupRolesOriginalV1::new()));

            assert!(startup.observe_live_policy_once_v1().is_err());

            let policy = &startup.body.as_ref().unwrap().policy;
            assert!(!policy.paid);
            assert!(!policy.entered);
            assert!(
                policy
                    .observations
                    .iter()
                    .all(|slot| !slot.borrow().entered)
            );
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn busy_policy_post_cannot_suppress_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let mut body = StartupRolesOriginalV1::new();
        // Negative dispatch only: this fabricates no Source or native proof.
        body.policy.paid = true;
        startup.body = Some(Box::new(body));
        let held = startup.body.as_ref().unwrap().policy.observations[1].borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Policy)));
        drop(held);
    }

    #[test]
    fn unpaid_policy_post_does_not_enter_native_observation() {
        let policy = InitialPolicyOriginalV1::new();

        assert!(policy.finish_post(None).is_ok());

        assert!(
            policy
                .observations
                .iter()
                .all(|slot| !slot.borrow().entered)
        );
    }
}
