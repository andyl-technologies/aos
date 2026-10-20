//! Shares fixed credential DATA capture, named readback and first-cause custody.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum CredentialRosterKindV1 {
    ControllerPublic,
    GenerationOrigin,
    GitCoverage(git_coverage::GitCoverageCredentialRoleV1),
    PublisherBootstrap,
}

impl CredentialRosterKindV1 {
    fn directory(self) -> &'static Path {
        match self {
            Self::GitCoverage(role) => Path::new(role.directory()),
            _ => Path::new(NIX_CONTROLLER_DIRECTORY),
        }
    }

    fn names(self) -> &'static [&'static str] {
        match self {
            Self::ControllerPublic => &NIX_PUBLIC_NAMES,
            Self::GenerationOrigin => &["nix-storage-generation-origin-v1"],
            Self::GitCoverage(role) => {
                &git_coverage::GIT_COVERAGE_CREDENTIAL_NAMES_V1[..role.count()]
            }
            Self::PublisherBootstrap => &publisher_bootstrap::PUBLISHER_BOOTSTRAP_NAMES,
        }
    }

    fn profile(self, index: usize) -> CredentialReadProfile {
        match self {
            Self::GitCoverage(_) => git_coverage::git_coverage_read_profile(index),
            Self::PublisherBootstrap => publisher_bootstrap::publisher_read_profile(index),
            _ => CredentialReadProfile::Ordinary(MAXIMUM_CREDENTIAL_BYTES),
        }
    }

    fn exact(self, index: usize) -> Option<usize> {
        match (self, index) {
            (Self::GitCoverage(_), 2 | 3) => Some(80),
            (Self::GitCoverage(_), 4 | 5) => Some(920),
            (Self::PublisherBootstrap, 0) => Some(272),
            (Self::PublisherBootstrap, 2) => Some(32),
            _ => None,
        }
    }

    fn directory_rejection(self) -> ControllerNixPublicCredentialErrorV1 {
        match self {
            Self::GitCoverage(_) | Self::PublisherBootstrap => credential_state_rejected(),
            _ => stale_directory_rejection(),
        }
    }
}

// The public wrappers select only compiled rosters. This owner lends local
// DATA; its fixed profile cannot admit Source/F, a signer or a Session.
pub(super) struct CredentialRosterCustodyV1<const N: usize, E> {
    kind: CredentialRosterKindV1,
    pub(super) originals: [OriginalControllerCredential; N],
    pub(super) ancestors: CredentialAncestors,
    pub(super) readback: CredentialReadback<N>,
    pub(super) uid: Option<u32>,
    phase: ControllerCredentialPhase,
    failure: Option<E>,
}

impl<const N: usize, E: From<ControllerNixPublicCredentialErrorV1>>
    CredentialRosterCustodyV1<N, E>
{
    pub(super) fn new(kind: CredentialRosterKindV1) -> Self {
        Self {
            kind,
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readback: CredentialReadback::new(),
            uid: None,
            phase: ControllerCredentialPhase::Fresh,
            failure: None,
        }
    }

    pub(super) fn capture(&mut self) -> Result<(), &E> {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.uid = Some(rustix::process::geteuid().as_raw());
        let result = (|| {
            let uid = self.uid.ok_or_else(credential_state_rejected)?;
            let names = self.kind.names();
            if names.len() > N {
                return Err(credential_state_rejected());
            }
            let profiles: [_; N] = std::array::from_fn(|index| self.kind.profile(index));
            let exact: [_; N] = std::array::from_fn(|index| self.kind.exact(index));
            capture_roster_originals(
                self.kind.directory(),
                uid,
                names,
                &profiles[..names.len()],
                &exact[..names.len()],
                &mut self.originals,
                &mut self.ancestors,
            )?;
            self.observe_originals()
        })();
        self.finish(result)
    }

    pub(super) fn recheck(&mut self) -> Result<(), &E> {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        let result = self.observe_originals();
        self.finish(result)
    }

    fn observe_originals(&mut self) -> CredentialResult<()> {
        let names = self.kind.names();
        let profiles: [_; N] = std::array::from_fn(|index| self.kind.profile(index));
        observe_roster_readback(
            self.kind.directory(),
            self.uid.ok_or_else(credential_state_rejected)?,
            names,
            &profiles[..names.len()],
            Some(self.kind),
            &mut self.originals,
            &self.ancestors,
            &mut self.readback,
        )
    }

    pub(super) fn public(&self, index: usize) -> Option<&PinnedSystemdCredential> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        self.originals.get(index)?.public.as_ref()
    }

    pub(super) fn failure(&self) -> Option<&E> {
        self.failure.as_ref()
    }

    pub(super) fn fence(&mut self) {
        self.phase = ControllerCredentialPhase::Closed;
    }

    pub(super) fn finish(&mut self, result: CredentialResult<()>) -> Result<(), &E> {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(cause) => {
                self.phase = ControllerCredentialPhase::Closed;
                Err(self.failure.get_or_insert_with(|| cause.into()))
            }
        }
    }
}

pub(super) fn capture_roster_originals<const N: usize>(
    path: &Path,
    uid: u32,
    names: &[&'static str],
    profiles: &[CredentialReadProfile],
    exact: &[Option<usize>],
    originals: &mut [OriginalControllerCredential; N],
    ancestors: &mut CredentialAncestors,
) -> CredentialResult<()> {
    open_directory_with_custody(path, uid, &mut DirectoryCustody::Resident(ancestors))?;
    let directory = ancestors.directory()?;
    let directory_identity = ancestors.slots[3]
        .identity
        .ok_or_else(credential_state_rejected)?;
    for (index, name) in names.iter().enumerate() {
        let original = &mut originals[index];
        let file_identity = require_present_credential(open_read_credential_with_profile(
            directory,
            name,
            uid,
            profiles[index],
            &mut original.read,
        )?)?;
        if exact[index].is_some_and(|width| {
            original.read.bytes.as_ref().map(|bytes| bytes.len()) != Some(width)
        }) {
            return Err(credential_state_rejected());
        }
        let path = path.to_path_buf();
        let bytes = original
            .read
            .bytes
            .take()
            .ok_or_else(credential_state_rejected)?;
        original.public = Some(PinnedSystemdCredential {
            name: *name,
            path,
            uid,
            directory_identity,
            file_identity,
            bytes,
            exact_bytes: None,
        });
    }
    Ok(())
}

fn stale_directory_rejection() -> ControllerNixPublicCredentialErrorV1 {
    ControllerNixPublicCredentialErrorV1::rejected(
        CredentialFailureClass::Stale,
        CredentialOperation::DirectoryProvenance,
    )
}

pub(super) fn observe_roster_readback<const N: usize>(
    path: &Path,
    uid: u32,
    names: &[&str],
    profiles: &[CredentialReadProfile],
    kind: Option<CredentialRosterKindV1>,
    originals: &mut [OriginalControllerCredential; N],
    ancestors: &CredentialAncestors,
    readback: &mut CredentialReadback<N>,
) -> CredentialResult<()> {
    let rejected = || {
        kind.map_or_else(
            stale_directory_rejection,
            CredentialRosterKindV1::directory_rejection,
        )
    };
    if rustix::process::geteuid().as_raw() != uid {
        return Err(rejected());
    }
    recheck_credential_ancestors(ancestors, uid)?;
    open_directory_with_custody(
        path,
        uid,
        &mut DirectoryCustody::Resident(&mut readback.ancestors),
    )?;
    for (original, named) in ancestors.slots.iter().zip(&readback.ancestors.slots) {
        if original.identity != named.identity {
            return Err(rejected());
        }
    }
    let directory = readback.ancestors.directory()?;
    for (index, name) in names.iter().enumerate() {
        observe_credential_readback(
            &mut originals[index],
            &mut readback.original_bytes[index],
            &mut readback.named[index],
            directory,
            name,
            uid,
            profiles[index],
        )?;
    }
    for (original, named) in originals[..names.len()].iter().zip(&readback.named) {
        let public = original
            .public
            .as_ref()
            .ok_or_else(credential_state_rejected)?;
        recheck_credential_file(
            original
                .read
                .file
                .as_ref()
                .ok_or_else(credential_state_rejected)?,
            public.file_identity,
        )?;
        recheck_credential_file(
            named.file.as_ref().ok_or_else(credential_state_rejected)?,
            public.file_identity,
        )?;
    }
    recheck_credential_ancestors(ancestors, uid)?;
    recheck_credential_ancestors(&readback.ancestors, uid)?;
    if rustix::process::geteuid().as_raw() != uid {
        return Err(rejected());
    }
    Ok(())
}
