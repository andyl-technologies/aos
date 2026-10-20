//! Joins one already-held Network original to the fixed helper aggregate.
//!
//! This owner contains native identity evidence only. The genuine Network
//! receiver initializes it through its private same-operation loan, after
//! paying the child and broker shapes. No descriptor, pathname, decoded grant
//! or successful comparison can create a receiving account or effect scope.

use super::*;

/// Retains the fixed aggregate and its join to an independently held original.
#[derive(Debug)]
pub struct NetworkWorkerAggregateAssociationOriginalV4 {
    fixed: NetworkReceivingAggregateCgroupReadbackV4,
    fixed_result: Option<Result<()>>,
    pair: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    before: CgroupActiveOriginalV2,
    before_result: Option<Result<()>>,
    comparison: Option<Result<()>>,
    after: CgroupActiveOriginalV2,
    after_result: Option<Result<()>>,
    entered: bool,
    first: Option<Failure>,
    closed: Option<Error>,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Before,
    Fixed,
    Comparison,
    After,
    Closed,
}

impl Default for NetworkWorkerAggregateAssociationOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkWorkerAggregateAssociationOriginalV4 {
    /// Creates inert destinations without observing or acquiring anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fixed: NetworkReceivingAggregateCgroupReadbackV4::new(),
            fixed_result: None,
            pair: None,
            before: CgroupActiveOriginalV2::new(),
            before_result: None,
            comparison: None,
            after: CgroupActiveOriginalV2::new(),
            after_result: None,
            entered: false,
            first: None,
            closed: None,
        }
    }

    /// Joins the actual held aggregate to a fresh fixed capture exactly once.
    ///
    /// The caller retains its original anchor throughout this interval. Once
    /// the first native boundary is entered, its independent after observation
    /// runs even when that boundary, fixed acquisition or comparison fails.
    ///
    /// # Errors
    /// Retains the first actual native or identity cause and every reached
    /// acquisition prefix. Reentry makes no native observation or replacement.
    pub fn capture_once_v4(&mut self, enrolled: &RetainedCgroupAnchor) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            self.first.get_or_insert(Failure::Closed);
            return Err(closed());
        }
        self.entered = true;
        self.before_result = Some(self.before.capture_once_v2(enrolled));
        if matches!(self.before_result, Some(Ok(()))) {
            self.fixed_result = Some(self.fixed.capture_once());
            if matches!(self.fixed_result, Some(Ok(()))) {
                self.pair = self.fixed.take_validated_pair();
                self.comparison = Some(match self.pair.as_ref() {
                    Some((_, actual)) if same_identity(actual, enrolled) => Ok(()),
                    _ => Err(Error::InvalidInput {
                        field: "Network worker aggregate",
                        message: "fixed directory differs from the held receiving original".to_owned(),
                    }),
                });
                if !matches!(self.comparison, Some(Ok(()))) {
                    self.first = Some(Failure::Comparison);
                }
            } else {
                self.first = Some(Failure::Fixed);
            }
        } else {
            self.first = Some(Failure::Before);
        }

        self.after_result = Some(self.after.capture_once_v2(enrolled));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::After);
        }
        if self.first.is_some() {
            Err(closed())
        } else {
            Ok(())
        }
    }

    /// Compares this completed native join with the same continuously held anchor.
    ///
    /// This is historical identity DATA. Every later native effect still needs
    /// the genuine receiver's own currentness, time and operation checks.
    #[must_use]
    pub fn is_bound_to_v4(&self, enrolled: &RetainedCgroupAnchor) -> bool {
        self.first.is_none()
            && self.closed.is_none()
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.comparison, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
            && self
                .pair
                .as_ref()
                .is_some_and(|(_, actual)| same_identity(actual, enrolled))
    }

    /// Borrows the first original native or identity failure without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Before => self.before.failure().map(|cause| cause as _),
            Failure::Fixed => self.fixed.failure(),
            Failure::Comparison => self
                .comparison
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            Failure::After => self.after.failure().map(|cause| cause as _),
            Failure::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    /// Bounds both whole native bookends and the fixed acquisition before entry.
    #[must_use]
    pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let fixed = NetworkReceivingAggregateCgroupReadbackV4::receiving_obligations_v4()?;
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(fixed.0)?
            .checked_add(active.0.checked_mul(2)?)?
            .checked_add(2 * ("fixed directory differs from the held receiving original".len()
                + "original association is incomplete or refused".len()))?;
        let files = fixed.1.checked_add(active.1.checked_mul(2)?)?;
        // The fixed reader counts the complete compiled hierarchy. The
        // independently held original adds its actual cgroup.procs lookup.
        let names = fixed.2.checked_add(1)?;
        Some((memory, files, names))
    }
}

fn same_identity(left: &RetainedCgroupAnchor, right: &RetainedCgroupAnchor) -> bool {
    left.kernel_id == right.kernel_id && left.root.identity() == right.root.identity()
}

fn closed() -> Error {
    Error::InvalidInput {
        field: "Network worker aggregate",
        message: "original association is incomplete or refused".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_original_boundary_still_enters_after_and_keeps_first_native_cause() {
        let directory = std::fs::File::open(std::env::temp_dir()).unwrap();
        let root = BeneathRoot::from_owned(directory.into()).unwrap();
        let enrolled = RetainedCgroupAnchor {
            kernel_id: root.identity().inode,
            root,
        };
        let mut original = NetworkWorkerAggregateAssociationOriginalV4::new();

        assert!(original.capture_once_v4(&enrolled).is_err());
        assert!(matches!(original.before_result, Some(Err(_))));
        assert!(matches!(original.after_result, Some(Err(_))));
        assert!(original.fixed_result.is_none());
        assert!(!original.is_bound_to_v4(&enrolled));
        let first = original.before.failure().unwrap() as *const Error;

        assert!(original.capture_once_v4(&enrolled).is_err());
        assert_eq!(first, original.before.failure().unwrap() as *const Error);
        assert!(std::ptr::eq(
            first,
            original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const Error,
        ));
    }
}
