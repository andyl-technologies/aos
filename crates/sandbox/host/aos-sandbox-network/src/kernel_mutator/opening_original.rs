//! Retains all earlier artifact pins if a later fixed mutator input refuses.
//!
//! Construction uses one recipe for ordinary and enrolled child lifetimes.
//! The child source funds this complete owner before entry; the mechanical
//! artifact role checks never mint a worker or authorize kernel mutation.

use super::*;
use crate::kernel_reader::{NetworkArtifactOpeningOriginalV4, NetworkArtifactRoleV4};

const ROLES: [NetworkArtifactRoleV4; 5] = [
    NetworkArtifactRoleV4::Ip,
    NetworkArtifactRoleV4::Nft,
    NetworkArtifactRoleV4::Enforcement,
    NetworkArtifactRoleV4::LeaseLoader,
    NetworkArtifactRoleV4::LeaseObject,
];

trait ArtifactNativeV4 {
    fn open(&mut self, index: usize, path: PathBuf) -> Result<(), NetworkKernelMutationError>;
    fn complete(&mut self) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError>;
}

fn construct_recipe_v4(
    paths: [PathBuf; 5],
    native: &mut impl ArtifactNativeV4,
) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
    for (index, path) in paths.into_iter().enumerate() {
        native.open(index, path)?;
    }
    native.complete()
}

struct LocalArtifactsV4 {
    artifacts: [Option<PinnedArtifact>; 5],
}

impl ArtifactNativeV4 for LocalArtifactsV4 {
    fn open(&mut self, index: usize, path: PathBuf) -> Result<(), NetworkKernelMutationError> {
        self.artifacts[index] = Some(PinnedArtifact::open(path, ROLES[index].executable())?);
        Ok(())
    }

    fn complete(&mut self) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
        take_mutator(&mut self.artifacts)
    }
}

pub(super) fn construct_local_v4(
    ip: PathBuf,
    nft: PathBuf,
    enforcement: PathBuf,
    lease_loader: PathBuf,
    lease_object: PathBuf,
) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
    let mut native = LocalArtifactsV4 {
        artifacts: std::array::from_fn(|_| None),
    };
    construct_recipe_v4(
        [ip, nft, enforcement, lease_loader, lease_object],
        &mut native,
    )
}

fn take_mutator(
    artifacts: &mut [Option<PinnedArtifact>; 5],
) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
    if artifacts.iter().any(Option::is_none) {
        return Err(NetworkKernelMutationError::Artifact);
    }
    Ok(FixedNetworkKernelMutator {
        ip: artifacts[0]
            .take()
            .ok_or(NetworkKernelMutationError::Artifact)?,
        nft: artifacts[1]
            .take()
            .ok_or(NetworkKernelMutationError::Artifact)?,
        enforcement_artifact: artifacts[2]
            .take()
            .ok_or(NetworkKernelMutationError::Artifact)?,
        lease_gate_loader: artifacts[3]
            .take()
            .ok_or(NetworkKernelMutationError::Artifact)?,
        lease_gate_object: artifacts[4]
            .take()
            .ok_or(NetworkKernelMutationError::Artifact)?,
    })
}

#[derive(Clone, Copy)]
enum First {
    Artifact(usize),
    Disposition(usize),
    Body,
    Closed,
}

/// Owns all five reached native openings, not only a completed mutator result.
pub(crate) struct NetworkMutatorOpeningOriginalV4 {
    openings: [NetworkArtifactOpeningOriginalV4; 5],
    artifacts: [Option<PinnedArtifact>; 5],
    disposition: [Option<Result<(), NetworkKernelReaderError>>; 5],
    completed: Option<FixedNetworkKernelMutator>,
    returned: Option<Result<(), NetworkKernelMutationError>>,
    closed: Option<NetworkKernelMutationError>,
    first: Option<First>,
    entered: bool,
    taken: bool,
}

impl NetworkMutatorOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            openings: std::array::from_fn(|_| NetworkArtifactOpeningOriginalV4::new()),
            artifacts: std::array::from_fn(|_| None),
            disposition: std::array::from_fn(|_| None),
            completed: None,
            returned: None,
            closed: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    /// Bounds the same compiled five-role constructor before any child IO.
    ///
    /// Positive per-artifact currentness temporaries close before the next
    /// artifact opens. All completed artifact File/ancestry pins remain held;
    /// the last failed opening adds its own full currentness/path prefix.
    pub(crate) fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<FixedNetworkKernelMutator>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<[PathBuf; 5]>().checked_mul(2)?)?;
        let mut files = 0usize;
        let mut temporary_peak = 0usize;
        let mut names = 0usize;
        let inline = std::mem::size_of::<NetworkArtifactOpeningOriginalV4>().checked_mul(2)?;
        for role in ROLES {
            let (memory, total_files, entries) =
                NetworkArtifactOpeningOriginalV4::receiving_obligations_v4(role)?;
            // Each opening prices identical original and currentness walks.
            // Their real native count is even; this decomposition follows that
            // actual supplier rather than inventing descriptor credits.
            let persistent = total_files.checked_div(2)?;
            if persistent.checked_mul(2)? != total_files {
                return None;
            }
            files = files.checked_add(persistent)?;
            temporary_peak = temporary_peak.max(persistent);
            bytes = bytes.checked_add(memory.checked_sub(inline)?)?;
            names = names.checked_add(entries)?;
        }
        Some((bytes, files.checked_add(temporary_peak)?, names))
    }

    /// Captures the exact named input roles once through the common constructor.
    ///
    /// # Errors
    /// Retains any path/metadata/hash failure and all earlier real artifacts.
    /// Repeated entry cannot replace the first cause or native owner.
    pub(crate) fn prepare_once_v4(
        &mut self,
        ip: PathBuf,
        nft: PathBuf,
        enforcement: PathBuf,
        lease_loader: PathBuf,
        lease_object: PathBuf,
    ) -> Result<(), NetworkKernelMutationError> {
        if self.entered || self.closed.is_some() {
            self.closed
                .get_or_insert(NetworkKernelMutationError::Artifact);
            self.first.get_or_insert(First::Closed);
            return Err(NetworkKernelMutationError::Artifact);
        }
        self.entered = true;
        let returned = construct_recipe_v4(
            [ip, nft, enforcement, lease_loader, lease_object],
            &mut SelectedArtifactsV4 { owner: self },
        );
        self.returned = Some(match returned {
            Ok(mutator) => {
                self.completed = Some(mutator);
                Ok(())
            }
            Err(error) => Err(error),
        });
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Body);
            Err(NetworkKernelMutationError::Artifact)
        }
    }

    /// Moves only the same completed mutator after every native role passed.
    pub(crate) fn take_completed_once_v4(&mut self) -> Option<FixedNetworkKernelMutator> {
        if self.taken || self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.taken = true;
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Artifact(index) => self.openings[index].failure(),
            First::Disposition(index) => self.disposition[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Body => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

impl Drop for NetworkMutatorOpeningOriginalV4 {
    fn drop(&mut self) {
        // The child must finish its actual failure handback while every earlier
        // pin is still resident. Never unwind a partial constructor first.
        if self.entered && (!self.taken || self.first.is_some()) {
            std::process::abort();
        }
    }
}

struct SelectedArtifactsV4<'held> {
    owner: &'held mut NetworkMutatorOpeningOriginalV4,
}

impl ArtifactNativeV4 for SelectedArtifactsV4<'_> {
    fn open(&mut self, index: usize, path: PathBuf) -> Result<(), NetworkKernelMutationError> {
        if self.owner.openings[index]
            .open_once_v4(path, ROLES[index])
            .is_err()
        {
            self.owner.first.get_or_insert(First::Artifact(index));
            return Err(NetworkKernelMutationError::Artifact);
        }
        self.owner.artifacts[index] = self.owner.openings[index].take_completed_once_v4();
        if self.owner.artifacts[index].is_none() {
            return Err(NetworkKernelMutationError::Artifact);
        }
        self.owner.disposition[index] =
            Some(self.owner.openings[index].dispose_positive_temporary_once_v4());
        if !matches!(self.owner.disposition[index], Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Disposition(index));
            return Err(NetworkKernelMutationError::Artifact);
        }
        Ok(())
    }

    fn complete(&mut self) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
        take_mutator(&mut self.owner.artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingConstruction {
        entered: Vec<usize>,
    }

    impl ArtifactNativeV4 for RefusingConstruction {
        fn open(&mut self, index: usize, _path: PathBuf) -> Result<(), NetworkKernelMutationError> {
            self.entered.push(index);
            if index == 2 {
                Err(NetworkKernelMutationError::Artifact)
            } else {
                Ok(())
            }
        }
        fn complete(&mut self) -> Result<FixedNetworkKernelMutator, NetworkKernelMutationError> {
            panic!("an incomplete native prefix cannot manufacture a mutator")
        }
    }

    #[test]
    fn later_refusal_never_enters_later_artifacts_or_completion() {
        let mut native = RefusingConstruction {
            entered: Vec::new(),
        };
        let paths = std::array::from_fn(|index| PathBuf::from(index.to_string()));
        assert!(construct_recipe_v4(paths, &mut native).is_err());
        assert_eq!(native.entered, [0, 1, 2]);
    }
}
