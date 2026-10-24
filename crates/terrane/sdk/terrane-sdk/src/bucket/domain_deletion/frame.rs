//! Projects only acknowledged administrative payload removals in a retained frame.

use super::{BucketBinding, FencePolicy, Frame, LocalFs, Plan, StoreFailure, corrupt, unsupported};
use std::path::Path;
use terrane_format::bucket::BucketKey;

impl Frame {
    /// Removes one fixed domain payload while retaining every other predicate.
    ///
    /// # Errors
    /// Rejects paths outside pack/index payloads, missing exact bodies, unexpected
    /// named constraints or collector pairs, changed authority and failed durable
    /// effects. An indeterminate failure never projects the target as absent.
    pub(in crate::store::native_effect) async fn remove_domain_target<
        F: LocalFs + BucketBinding,
    >(
        &mut self,
        fs: &F,
        root: &Path,
        path: &Path,
        owner: u32,
    ) -> Result<(), StoreFailure> {
        let key = path
            .strip_prefix(root)
            .map_err(|_| corrupt())?
            .to_str()
            .ok_or_else(unsupported)?;
        let parsed = BucketKey::parse(key).map_err(|_| corrupt())?;
        if !(parsed.as_str().starts_with("objects/pack/")
            || parsed.as_str().starts_with("objects/index/"))
            || !self.pairs.is_empty()
            || self.names.iter().any(|name| name.path == path)
        {
            return Err(corrupt());
        }
        let policy = FencePolicy::Payload { owner };
        if self.actual_read(fs, path, policy).await?.is_none() {
            return Err(corrupt());
        }
        let effect = self.effect(Plan::Remove {
            path: path.to_owned(),
        })?;
        #[cfg(all(test, feature = "tokio"))]
        let effect = super::super::domain_deletion::inject_remove_fault(root, effect)?;
        fs.execute_retained_effect(effect)
            .await
            .map_err(super::native_failure)?;

        // The real Remove executor unlinks and synchronizes this exact parent.
        // Only its successful durable acknowledgment allows this operation's
        // exact removed target to change from its original body to absence.
        self.reads.retain(|read| read.path != path);
        self.observed_read(fs, path, None, None, policy).await?;
        Ok(())
    }
}
