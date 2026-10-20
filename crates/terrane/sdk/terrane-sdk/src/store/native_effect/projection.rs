//! Refreshes every retained physical and current predicate at primitive boundaries.

use super::{
    CreatedDirectory, ExactRead, NamedFence, NativeEffectFailure, NativeExclusion,
    NativeOpenedDirectory, OwnedFinalCheck, artifact_seal,
};
use std::{path::PathBuf, sync::Arc};

/// Borrows the complete immutable projection while its worker owns the holds.
pub(super) struct Projection<'a> {
    /// The actual duplicated descriptors retaining native exclusions.
    pub(super) exclusions: &'a [NativeExclusion],
    /// The complete retained name, policy, ancestry and descriptor predicates.
    pub(super) names: &'a [NamedFence],
    /// Every retained exact whole-value and physical incarnation predicate.
    pub(super) preimages: &'a [ExactRead],
    /// The closed producer's current authorization, controls and deadline check.
    pub(super) final_check: Option<&'a OwnedFinalCheck>,
    /// The actual retained container pairs independently refreshed at each check.
    pub(super) pairs: &'a [Arc<artifact_seal::current_pair::PairHold>],
    #[cfg(test)]
    /// The test-only physical read failures applied to the original projection.
    pub(super) faults: &'a [super::EffectFault],
}

impl Projection<'_> {
    /// Refreshes names, ancestry, pairs, whole preimages and current authority.
    ///
    /// # Errors
    /// Rejects changed physical predicates, unavailable reads or current denial.
    pub(super) fn check(
        &self,
        directories: Option<&[NativeOpenedDirectory]>,
        created: Option<&CreatedDirectory>,
    ) -> Result<(), NativeEffectFailure> {
        self.check_scoped(directories, created, None)
    }

    /// Keeps all physical checks while deferring proven unrelated output bodies.
    ///
    /// # Errors
    /// Preserves physical, input and current-authority refusal.
    pub(super) fn check_scoped(
        &self,
        directories: Option<&[NativeOpenedDirectory]>,
        created: Option<&CreatedDirectory>,
        scope: Option<&super::immutable_cohort::scope::Scope>,
    ) -> Result<(), NativeEffectFailure> {
        #[cfg(test)]
        let _projection_span = super::check_timings::span(super::check_timings::Group::Projection);
        #[cfg(test)]
        let fence_span = super::check_timings::span(super::check_timings::Group::FenceBefore);
        self.fence(directories)?;
        #[cfg(test)]
        drop(fence_span);
        for pair in self.pairs {
            #[cfg(test)]
            let _pair_span = super::check_timings::span(super::check_timings::Group::Pair);
            pair.recheck()?;
        }
        let mut scratch = Vec::new();
        let mut parent_prefix = PathBuf::new();
        for preimage in self.preimages {
            #[cfg(test)]
            let _row_span = super::check_timings::span(super::check_timings::Group::Preimage);
            #[cfg(test)]
            if self
                .faults
                .contains(&super::EffectFault::UnavailableRead(preimage.path.clone()))
            {
                return Err(std::io::Error::other("injected retained exact read failure").into());
            }
            match created.filter(|created| created.path == preimage.path) {
                Some(created) => preimage.check_created_directory(created)?,
                None => {
                    #[cfg(unix)]
                    if scope.is_some_and(|scope| scope.defers(preimage)) {
                        preimage.check_leaf(&mut scratch, &mut parent_prefix, false)?;
                    } else {
                        preimage.check_with_parent_scratch(&mut scratch, &mut parent_prefix)?;
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = scope;
                        preimage.check_with_parent_scratch(&mut scratch, &mut parent_prefix)?;
                    }
                }
            }
        }
        #[cfg(test)]
        let fence_span = super::check_timings::span(super::check_timings::Group::FenceAfter);
        self.fence(directories)?;
        #[cfg(test)]
        drop(fence_span);
        if let Some(created) = created {
            #[cfg(test)]
            let _created_span = super::check_timings::span(super::check_timings::Group::Created);
            created.check()?;
        }
        if let Some(final_check) = self.final_check {
            #[cfg(test)]
            let _current_span = super::check_timings::span(super::check_timings::Group::Current);
            final_check.recheck()?;
        }
        Ok(())
    }

    fn fence(&self, directories: Option<&[NativeOpenedDirectory]>) -> std::io::Result<()> {
        if let Some(directories) = directories {
            for directory in directories {
                #[cfg(test)]
                let _directory_span =
                    super::check_timings::span(super::check_timings::Group::Directory);
                directory.check()?;
            }
        }
        let mut parent_prefix = PathBuf::new();
        for name in self.names {
            #[cfg(test)]
            let _name_span = super::check_timings::span(super::check_timings::Group::Name);
            name.check_with_parent_scratch(self.exclusions, &mut parent_prefix)?;
        }
        Ok(())
    }
}
