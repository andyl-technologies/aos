//! Keeps an already-entered C native name post on the same original writer.
//!
//! The trusted Controller coordinator arms this destination before its upper
//! semantic body. It remains independently payable after native poison; fresh
//! entry still requires the original writer's healthy admission. Mechanical
//! completion proves no upper semantic success or Bank/role authority.

use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::coordinator::ControllerCoordinatorWriterV1;
use super::identity::ControllerWriterIdentityV1;
use super::writer::ControllerWriterNameSampleV1;
use super::ControllerBankLaunchErrorV1;

/// Owns one same-writer prearmed native post through all upper owed bookends.
///
/// No public constructor, raw file, account or success marker exists. A failed
/// or abandoned destination cannot release its native partials through Drop.
#[must_use]
pub struct ControllerNativePostOriginalV1 {
    identity: Arc<ControllerWriterIdentityV1>,
    sample: ControllerWriterNameSampleV1,
    entry: Result<(), ControllerBankLaunchErrorV1>,
    returned: Option<Result<(), ControllerBankLaunchErrorV1>>,
    settled: bool,
}

impl ControllerNativePostOriginalV1 {
    /// Describes the actual fixed carrier and retained name/witness geometry.
    ///
    /// # Errors
    /// Refuses checked byte/descriptor arithmetic overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes)
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?)
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?)
    }

    pub(super) fn is_disposed_for_v1(&self, identity: &Arc<ControllerWriterIdentityV1>) -> bool {
        self.settled && Arc::ptr_eq(&self.identity, identity)
            && self.entry.is_ok()
            && matches!(self.returned, Some(Ok(())))
            && self.sample.has_disposed_complete_interval_v1()
    }

    /// Borrows the actual retained name, native Metadata or witness refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sample.failure()
            .or_else(|| entry_or_after_failure_v2(&self.entry, &self.returned)
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Arms one independent post before the trusted upper body can mutate.
    ///
    /// Its geometry is included in the genuine upper operation's complete
    /// predebit; this method produces no semantic completion or role loan.
    ///
    /// # Errors
    /// Refuses an unhealthy writer or a failed actual same-owner admission.
    pub fn begin_independent_native_post_once(
        &self,
    ) -> Result<ControllerNativePostOriginalV1, ControllerBankLaunchErrorV1> {
        self.fixed.require_healthy()?;
        let mut sample = ControllerWriterNameSampleV1::new();
        let entry = self.arm_independent_native_post_sample_v2(&mut sample)?;
        Ok(ControllerNativePostOriginalV1 {
            identity: Arc::clone(self.fixed.identity()), sample,
            entry: Ok(entry), returned: None, settled: false,
        })
    }

    // Both ordinary and retaining entrances use the sole existing sample
    // engine. The retaining caller parks its whole destination before issue.
    fn arm_independent_native_post_sample_v2(
        &self, sample: &mut ControllerWriterNameSampleV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed.begin_name_sample(sample)
    }

    /// Retains the actual prearm prefix even when its interpretation refuses.
    ///
    /// Only the finite maintenance native lender uses this private sibling.
    /// `Ok` returns custody, not prearm success: the consumer must inspect its
    /// failure and always finish the entered post before positive disposal.
    pub(super) fn begin_independent_native_post_retaining_v2(
        &self,
    ) -> Result<ControllerNativePostOriginalV1, ControllerBankLaunchErrorV1> {
        self.fixed.require_healthy()?;
        let mut post = ControllerNativePostOriginalV1 {
            identity: Arc::clone(self.fixed.identity()),
            sample: ControllerWriterNameSampleV1::new(),
            entry: Ok(()), returned: None, settled: false,
        };
        post.entry = self.arm_independent_native_post_sample_v2(&mut post.sample);
        Ok(post)
    }

    /// Attempts an already-armed actual native post even after body poison.
    ///
    /// # Errors
    /// Retains the original lower name/witness error or rejects reentry and a
    /// different writer identity. This cannot rearm a fresh operation.
    pub fn finish_independent_native_post_once(
        &self,
        post: &mut ControllerNativePostOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if post.returned.is_some() || post.settled
            || !Arc::ptr_eq(&post.identity, self.fixed.identity())
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        post.returned = Some(self.fixed.finish_owed_name_sample(&mut post.sample));
        if matches!(post.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    /// Disposes only this completed post after all actual upper posts finish.
    ///
    /// The C coordinator is trusted to sequence its sole semantic engine. This
    /// mechanical disposition neither accepts a body-success DTO nor proves it.
    ///
    /// # Errors
    /// Refuses a failed, incomplete, foreign or already settled actual post.
    pub fn dispose_native_post_after_upper_posts_once(
        &self,
        post: &mut ControllerNativePostOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if post.settled || !Arc::ptr_eq(&post.identity, self.fixed.identity())
            || !matches!(post.returned, Some(Ok(()))) || post.failure().is_some()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        post.sample.dispose_after_complete_interval();
        post.settled = true;
        Ok(())
    }
}

impl Drop for ControllerNativePostOriginalV1 {
    fn drop(&mut self) {
        if !self.settled {
            // Terminate before any reached native owner or its identity drops.
            std::process::abort();
        }
    }
}


// A later owed after cannot replace the earlier prearm refusal. Native sample
// errors remain selected first by the actual original's failure method above.
fn entry_or_after_failure_v2<'cause>(
    entry: &'cause Result<(), ControllerBankLaunchErrorV1>,
    after: &'cause Option<Result<(), ControllerBankLaunchErrorV1>>,
) -> Option<&'cause ControllerBankLaunchErrorV1> {
    entry.as_ref().err().or_else(|| after.as_ref()?.as_ref().err())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_prearm_keeps_its_original_cause_through_a_failed_owed_after() {
        let entry = Err(ControllerBankLaunchErrorV1::Conflict);
        let after = Some(Err(ControllerBankLaunchErrorV1::Conflict));
        let selected = entry_or_after_failure_v2(&entry, &after).unwrap();
        assert!(std::ptr::eq(selected, entry.as_ref().unwrap_err()));

        let positive_entry = Ok(());
        let selected = entry_or_after_failure_v2(&positive_entry, &after).unwrap();
        assert!(std::ptr::eq(selected, after.as_ref().unwrap().as_ref().unwrap_err()));
        assert!(entry_or_after_failure_v2(&positive_entry, &None).is_none());
    }
}
