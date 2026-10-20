//! Compares actual Source/worker parents with their donated common aggregate.
//!
//! Only the kernel's fixed parent entry is opened; no caller path or decoded
//! component name is resolved. This proves native identity DATA, never Source,
//! payment, migration fencing or effect permission.

use super::*;

#[derive(Clone, Copy)]
enum First { Order, Before(usize), Open(usize), Parent(usize), Identity(usize), After(usize) }

/// Retains the two actual parent opens and all six independent active probes.
pub struct NetworkChildAggregateAncestryOriginalV2 {
    entered: bool,
    before: [CgroupActiveOriginalV2; 3],
    before_result: [Option<Result<()>>; 3],
    opened: [Option<std::result::Result<OwnedFd, rustix::io::Errno>>; 2],
    open_result: [Option<std::result::Result<(), rustix::io::Errno>>; 2],
    parents: [RuntimeScopeCgroupOriginalV1; 2],
    parent_result: [Option<Result<()>>; 2],
    pairs: [Option<(CgroupV2Root, RetainedCgroupAnchor)>; 2],
    identities: [Option<bool>; 2],
    after: [CgroupActiveOriginalV2; 3],
    after_result: [Option<Result<()>>; 3],
    first: Option<First>,
    closed: Option<Error>,
    retired_parents: Option<[(crate::path::FileIdentity, u64); 2]>,
}

impl NetworkChildAggregateAncestryOriginalV2 {
    /// Creates resident destinations without opening or validating anything.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false,
            before: std::array::from_fn(|_| CgroupActiveOriginalV2::new()),
            before_result: std::array::from_fn(|_| None), opened: std::array::from_fn(|_| None),
            open_result: std::array::from_fn(|_| None),
            parents: std::array::from_fn(|_| RuntimeScopeCgroupOriginalV1::new()),
            parent_result: std::array::from_fn(|_| None), pairs: std::array::from_fn(|_| None),
            identities: [None; 2], after: std::array::from_fn(|_| CgroupActiveOriginalV2::new()),
            after_result: std::array::from_fn(|_| None), first: None, closed: None,
            retired_parents: None }
    }

    /// Joins the actual two immediate parents with the same native aggregate.
    ///
    /// This is the selected closed service topology: both native service
    /// groups are direct children of the common Network slice. A different
    /// topology refuses rather than inventing a descendant path or ancestor.
    /// All three independently owed active afters run after any reached before,
    /// open, canonical parent admission or identity failure.
    ///
    /// # Errors
    /// Retains stale groups, native open/admission failures, different actual
    /// parents and repeated entry without replacing any native prefix.
    pub fn capture_once_v2(&mut self, source: &RetainedCgroupAnchor,
        worker: &RetainedCgroupAnchor, aggregate: &RetainedCgroupAnchor) -> Result<()>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let anchors = [source, worker, aggregate];
        for (index, anchor) in anchors.iter().enumerate() {
            self.before_result[index] = Some(self.before[index].capture_once_v2(anchor));
            if !matches!(self.before_result[index], Some(Ok(()))) { self.first.get_or_insert(First::Before(index)); }
        }
        if self.first.is_none() {
            let _ = self.capture_parents(source, worker, aggregate);
        }
        for (index, anchor) in anchors.iter().enumerate() {
            self.after_result[index] = Some(self.after[index].capture_once_v2(anchor));
            if !matches!(self.after_result[index], Some(Ok(()))) { self.first.get_or_insert(First::After(index)); }
        }
        if self.first.is_some() { Err(closed()) } else { Ok(()) }
    }

    fn capture_parents(&mut self, source: &RetainedCgroupAnchor,
        worker: &RetainedCgroupAnchor, aggregate: &RetainedCgroupAnchor) -> Result<()>
    {
        for (index, anchor) in [source, worker].into_iter().enumerate() {
            self.opened[index] = Some(rustix::fs::openat(anchor.as_fd(), "..",
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty()));
            self.open_result[index] = self.opened[index].as_ref().map(|result| {
                result.as_ref().map(|_| ()).map_err(|cause| *cause)
            });
            if !matches!(self.opened[index], Some(Ok(_))) { return self.refuse(First::Open(index)); }
            let Some(Ok(parent)) = self.opened[index].take() else { return self.refuse(First::Open(index)); };
            // Capture takes ownership before validation and retains failed
            // directory/active/anchor prefixes in the canonical native owner.
            self.parent_result[index] = Some(self.parents[index].capture_once(parent));
            if !matches!(self.parent_result[index], Some(Ok(()))) { return self.refuse(First::Parent(index)); }
            self.pairs[index] = self.parents[index].take_completed_once();
            self.identities[index] = self.pairs[index].as_ref().map(|(_, parent)| {
                parent.kernel_id == aggregate.kernel_id && parent.root.identity() == aggregate.root.identity()
            });
            if self.identities[index] != Some(true) { return self.refuse(First::Identity(index)); }
        }
        Ok(())
    }

    fn refuse(&mut self, cause: First) -> Result<()> {
        self.first.get_or_insert(cause);
        self.closed.get_or_insert_with(closed);
        Err(closed())
    }

    /// Borrows the first native cause or closed identity marker without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before(index) => self.before[index].failure().map(|cause| cause as _),
            First::Open(index) => self.opened[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Parent(index) => self.parents[index].failure().map(|cause| cause as _),
            First::After(index) => self.after[index].failure().map(|cause| cause as _),
            First::Order | First::Identity(_) => None,
        }.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Closes complete parent-walk/probe temporaries after owner comparisons.
    ///
    /// Both exact parent directory identities, kernel IDs and all results
    /// remain resident. The caller still owns the three donated anchors.
    /// Financial charges and the native observation's once fences remain.
    ///
    /// # Errors
    /// Refuses partial, failed, inconsistent or already retired ancestry.
    pub fn retire_positive_proofs_once_v2(&mut self) -> Result<()> {
        if self.first.is_some() || self.retired_parents.is_some()
            || self.identities != [Some(true); 2]
            || self.after_result.iter().any(|result| !matches!(result, Some(Ok(())))) {
            return Err(closed());
        }
        let identity = |index: usize| self.pairs[index].as_ref()
            .map(|(_, anchor)| (anchor.root.identity(), anchor.kernel_id))
            .ok_or_else(closed);
        let identities = [identity(0)?, identity(1)?];
        for parent in &mut self.parents { parent.retire_positive_probes_once_v2()?; }
        for probe in &mut self.before { probe.retire_positive_file_once_v2()?; }
        for probe in &mut self.after { probe.retire_positive_file_once_v2()?; }
        for pair in &mut self.pairs { drop(pair.take()); }
        self.retired_parents = Some(identities);
        Ok(())
    }

    /// Prices both actual parent admissions and the six native active probes.
    #[must_use]
    pub fn receiving_obligations_data_v2() -> Option<(usize, usize, usize)> {
        let parent = RuntimeScopeCgroupOriginalV1::receiving_demand_v1()?;
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(parent.0.checked_mul(2)?)?.checked_add(active.0.checked_mul(6)?)?
            .checked_add(4 * 256)?;
        // The parent supplier includes each newly opened input. No separate
        // input descriptor is added to those same actual parent admissions.
        Some((bytes, parent.1.checked_mul(2)?.checked_add(active.1.checked_mul(6)?)?,
            parent.2.checked_mul(2)?.checked_add(active.2.checked_mul(6)?)?))
    }
}

impl Default for NetworkChildAggregateAncestryOriginalV2 {
    fn default() -> Self { Self::new() }
}

fn closed() -> Error {
    Error::invalid("Network child aggregate ancestry", "the original native parent join is closed")
}
