//! Retains native stopped-owner cgroup observations for initial floor setup.
//!
//! Fixed coordinates share the existing strict stopped-cgroup acquisition
//! recipe. The selected disposition additionally retains the original event
//! bytes and native parse/read result. These observations neither stop a unit
//! nor exclude a writer or a later process migration.

use super::*;

#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;

/// Selects a fixed native owner coordinate as DATA, without supplying a root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46StoppedOwnerCgroupV1 {
    /// Selects the existing Controller service subtree.
    Controller,
    /// Selects one existing Storage containment layout.
    Storage(StorageCgroupLayoutV1),
}

impl Method46StoppedOwnerCgroupV1 {
    fn relative(self) -> &'static Path {
        Path::new(match self {
            Self::Controller => "aos.slice/aos-control.slice/aos-sandboxd.service",
            Self::Storage(layout) => layout.main_relative_v1(),
        })
    }
}

/// Retains one fixed empty/absent observation beneath an authenticated root.
///
/// The caller authenticates that same cgroup-v2 hierarchy and prepays the full
/// representation before entry. Native descriptors, resolution and active-file
/// probes, event bytes and failures remain resident. No path, supplied state or
/// copied identifier constructs a positive observation.
#[derive(Debug, Default)]
#[must_use = "retain all reached native cgroup originals through independently owed posts"]
pub struct Method46StoppedOwnerCgroupOriginalV1 {
    original: NixOfflineStoppedCgroupReadbackV5,
    population: CgroupPopulationObservationV1,
    owner: Option<Method46StoppedOwnerCgroupV1>,
    returned: Option<Result<()>>,
    closed: Option<Error>,
}

impl Method46StoppedOwnerCgroupOriginalV1 {
    /// Creates empty native destinations without allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes one fixed subtree through the shared native acquisition recipe.
    ///
    /// Missing-directory DATA requires valid hierarchy probes on both sides.
    /// An existing directory requires an empty recursive population and all
    /// active-reference checks. A retired or populated subtree refuses.
    ///
    /// # Errors
    /// Retains the original resolution, descriptor, identity, read or parse
    /// failure. Reentry cannot replace the selected owner or retry native IO.
    pub fn observe_once_v1(
        &mut self,
        root: &CgroupV2Root,
        owner: Method46StoppedOwnerCgroupV1,
    ) -> Result<()> {
        if self.owner.is_some() || self.returned.is_some() || self.closed.is_some() {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.owner = Some(owner);
        self.returned = Some(self.original.capture_with_population(
            root,
            owner.relative(),
            Some(&mut self.population),
        ));
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(closed());
        }
        if self.original.population() != Some(CgroupPopulationState::Empty)
            && self.original.absence().is_none()
        {
            self.closed = Some(Error::invalid(
                "initial stopped owner cgroup",
                "the original subtree is populated or retired",
            ));
            return Err(closed());
        }
        Ok(())
    }

    /// Reports complete native empty/absent DATA for this same selected owner.
    ///
    /// This passive observation supplies no process, writer or effect grant.
    #[must_use]
    pub fn is_empty_or_absent_data_v1(&self) -> bool {
        self.owner.is_some()
            && self.closed.is_none()
            && matches!(self.returned, Some(Ok(())))
            && (self.original.population() == Some(CgroupPopulationState::Empty)
                || self.original.absence().is_some())
    }

    /// Borrows the earliest actual native cause without moving any original.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // A population refusal can only follow successful earlier acquisition.
        // Its actual native result precedes the shared engine's stopping marker.
        self.population.failure().or_else(|| {
            self.original
                .failure()
                .or_else(|| {
                    self.returned
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                })
                .or(self.closed.as_ref())
                .map(|error| error as _)
        })
    }

    /// Bounds retained representations, seven descriptors and ten coordinates.
    ///
    /// The fixed longest recipe resolves four path components and six probe or
    /// event names. Sixteen KiB additionally bounds fixed syscall/path frames,
    /// allocator scratch and sixteen bounded error payloads. Observed coordinate
    /// storage is metadata work; this read creates no namespace entry.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(16 * 1024)?;
        Some((bytes, 7, 10))
    }
}

fn closed() -> Error {
    Error::invalid(
        "initial stopped owner cgroup",
        "original observation remains closed",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use super::*;

    #[test]
    fn foreign_filesystem_refuses_before_resolution_and_cannot_change_owner() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();
        // Test-only malformed root exercises the real filesystem rejection;
        // public construction cannot authenticate this ordinary directory.
        let kernel_id = root.identity().inode;
        let hierarchy = CgroupV2Root {
            anchor: RetainedCgroupAnchor { root, kernel_id },
        };
        let mut original = Method46StoppedOwnerCgroupOriginalV1::new();

        assert!(
            original
                .observe_once_v1(&hierarchy, Method46StoppedOwnerCgroupV1::Controller)
                .is_err()
        );
        let first = original.failure_v1().unwrap() as *const dyn std::error::Error as *const ();
        assert!(
            original
                .observe_once_v1(
                    &hierarchy,
                    Method46StoppedOwnerCgroupV1::Storage(StorageCgroupLayoutV1::Ordinary)
                )
                .is_err()
        );

        assert_eq!(
            original.owner,
            Some(Method46StoppedOwnerCgroupV1::Controller)
        );
        assert_eq!(
            original.failure_v1().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(!original.is_empty_or_absent_data_v1());
        assert!(original.original.anchor.is_none());
        assert!(original.original.events.is_none());
        assert!(uapi::fstat(hierarchy.anchor.as_fd()).is_ok());
    }

    #[test]
    fn original_population_failure_precedes_later_stopping_markers() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"populated broken\n").unwrap();
        let mut original = Method46StoppedOwnerCgroupOriginalV1::new();

        assert!(original.population.capture_once(&file).is_err());
        let first = original.failure_v1().unwrap() as *const dyn std::error::Error as *const ();
        original.closed = Some(closed());
        file.set_len(0).unwrap();
        file.rewind().unwrap();
        file.write_all(b"populated 0\n").unwrap();
        assert!(original.population.capture_once(&file).is_err());

        assert_eq!(
            original.failure_v1().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(!original.is_empty_or_absent_data_v1());
        assert!(original.population.state().is_none());
    }
}
