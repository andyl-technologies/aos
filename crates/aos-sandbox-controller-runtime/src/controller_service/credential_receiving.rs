//! Retains the actual optional startup credential pipeline above one reader.
//!
//! Ordinary and selected constructors share their existing semantic engines.
//! The selected parent prepares each typed attempt before its first read; raw
//! file outcomes, decoder causes and the whole typed construction Result stay
//! together until the same completed owner moves to its existing destination.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, FixedRoleCredentialErrorV1, FixedRoleCredentialReadV1,
    read_optional_bounded_role_credential_v1, read_required_public_role_credential_v1,
};

#[derive(Clone, Copy)]
pub(super) enum CredentialMetadataV1 {
    Protected {
        private: bool,
        owner: CredentialOwnerPolicyV1,
    },
    PublicRegular,
}

// This private adapter supplies I/O disposition only. It has no resource
// vector, original C, payer, authority constructor or currentness callback.
pub(super) trait CredentialSourceV1 {
    // Ordinary callers preserve their existing environment observation. A
    // selected owner may supply the same already-captured startup locator;
    // this DATA changes no file/credential semantic or authority check.
    fn process_directory(&self) -> Option<OsString> {
        std::env::var_os("CREDENTIALS_DIRECTORY")
    }

    fn directory(&mut self, _directory: &OsStr) {}

    fn read(
        &mut self,
        directory: &Path,
        name: &'static str,
        minimum: usize,
        maximum: usize,
        metadata: CredentialMetadataV1,
    ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1>;

    fn retain<E: Error + Send + Sync + 'static>(&mut self, _cause: E) {}
}

pub(super) struct OrdinaryCredentialSourceV1;

impl CredentialSourceV1 for OrdinaryCredentialSourceV1 {
    fn read(
        &mut self,
        directory: &Path,
        name: &'static str,
        minimum: usize,
        maximum: usize,
        metadata: CredentialMetadataV1,
    ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
        match metadata {
            CredentialMetadataV1::Protected { private, owner } => {
                read_optional_bounded_role_credential_v1(
                    directory, name, minimum, maximum, private, owner,
                )
            }
            CredentialMetadataV1::PublicRegular => {
                read_required_public_role_credential_v1(directory, name, maximum).map(Some)
            }
        }
    }
}

enum OriginalFailureV1 {
    Read(usize),
    Decoder(Box<dyn Error + Send + Sync>),
}

pub(super) struct RetainedCredentialSourceV1<const READS: usize = 6> {
    reads: [FixedRoleCredentialReadV1; READS],
    names: [Option<&'static str>; READS],
    next: usize,
    directory: Option<OsString>,
    process_directory: Option<OsString>,
    first: Option<OriginalFailureV1>,
    exhausted: Option<FixedRoleCredentialErrorV1>,
}

impl<const READS: usize> RetainedCredentialSourceV1<READS> {
    fn new() -> Self {
        Self {
            reads: std::array::from_fn(|_| FixedRoleCredentialReadV1::prearmed()),
            names: [None; READS],
            next: 0,
            directory: None,
            process_directory: None,
            first: None,
            exhausted: None,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first.as_ref() {
            Some(OriginalFailureV1::Read(index)) => self.reads[*index].failure(),
            Some(OriginalFailureV1::Decoder(cause)) => Some(cause.as_ref()),
            None => self.exhausted.as_ref().map(|cause| cause as _),
        }
    }

    // These simple constructors perform no later descriptor currentness check.
    // After their complete typed success, retain bytes and native outcomes but
    // dispose the read-only files. Failed constructions keep every original.
    fn retire_completed_native_files(&mut self) {
        for read in &mut self.reads[..self.next] {
            let _retired = read.retire_completed_file_once_v1();
        }
    }
}

impl<const READS: usize> CredentialSourceV1 for RetainedCredentialSourceV1<READS> {
    fn process_directory(&self) -> Option<OsString> {
        self.process_directory.clone().or_else(|| std::env::var_os("CREDENTIALS_DIRECTORY"))
    }

    fn directory(&mut self, directory: &OsStr) {
        self.directory = Some(directory.to_owned());
    }

    fn read(
        &mut self,
        directory: &Path,
        name: &'static str,
        minimum: usize,
        maximum: usize,
        metadata: CredentialMetadataV1,
    ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
        let index = self.next;
        let Some(read) = self.reads.get_mut(index) else {
            self.exhausted.get_or_insert(FixedRoleCredentialErrorV1);
            return Err(FixedRoleCredentialErrorV1);
        };
        self.next += 1;
        self.names[index] = Some(name);
        match metadata {
            CredentialMetadataV1::Protected { private, owner } => {
                read.read_once(directory, name, minimum, maximum, private, owner);
            }
            CredentialMetadataV1::PublicRegular => {
                read.read_public_once(directory, name, maximum);
            }
        }
        match read.outcome() {
            Some(Ok(Some(bytes))) => Ok(Some(bytes.as_slice().to_vec())),
            Some(Ok(None)) => Ok(None),
            _ => {
                self.first.get_or_insert(OriginalFailureV1::Read(index));
                Err(FixedRoleCredentialErrorV1)
            }
        }
    }

    fn retain<E: Error + Send + Sync + 'static>(&mut self, cause: E) {
        if self.first.is_none() {
            self.first = Some(OriginalFailureV1::Decoder(Box::new(cause)));
        }
    }
}

/// Owns one actual typed optional construction and its original read/parse causes.
pub(super) struct CredentialAttemptV1<T, E, const READS: usize = 6> {
    reader: RetainedCredentialSourceV1<READS>,
    result: Option<Result<Option<T>, E>>,
    taken: bool,
    typed_present: bool,
}

impl<T, E: Error + 'static, const READS: usize> CredentialAttemptV1<T, E, READS> {
    fn empty() -> Self {
        Self {
            reader: RetainedCredentialSourceV1::<READS>::new(),
            result: None,
            taken: false,
            typed_present: false,
        }
    }

    pub(super) fn bind_process_directory_once(&mut self, directory: &OsStr) -> bool {
        if self.result.is_some() || self.taken || self.reader.process_directory.is_some() {
            return false;
        }
        self.reader.process_directory = Some(directory.to_owned());
        true
    }

    // Reentry creates no second read or typed admission and preserves the
    // original whole Result. It does not revoke an earlier transferred output.
    pub(super) fn capture_once(
        &mut self,
        construct: impl FnOnce(&mut RetainedCredentialSourceV1<READS>) -> Result<Option<T>, E>,
    ) -> bool {
        if self.result.is_some() || self.taken {
            return false;
        }
        self.result = Some(construct(&mut self.reader));
        let completed = matches!(self.result, Some(Ok(_))) && self.reader.failure().is_none();
        if completed {
            self.typed_present = matches!(self.result, Some(Ok(Some(_))));
            self.reader.retire_completed_native_files();
        }
        completed
    }

    pub(super) fn take_completed(&mut self) -> Option<Option<T>> {
        if self.taken || self.reader.failure().is_some() {
            return None;
        }
        let Some(Ok(value)) = self.result.as_mut() else {
            return None;
        };
        self.taken = true;
        Some(value.take())
    }

    /// Borrows the actual directory only after a complete typed present output.
    pub(super) fn completed_directory_v1(&self) -> Option<&OsStr> {
        if !self.typed_present || self.reader.failure().is_some() { return None; }
        self.reader.directory.as_deref()
    }

    /// Moves the same locator after its real typed output was transferred once.
    /// Native/read/parse causes and the one-shot state remain in this attempt.
    pub(super) fn take_completed_directory_v1(&mut self) -> Option<OsString> {
        if !self.taken || self.completed_directory_v1().is_none() { return None; }
        self.reader.directory.take()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.reader.failure().or_else(|| {
            self.result.as_ref()?.as_ref().err().map(|cause| cause as _)
        })
    }
}

// Ordinary pipelines retain their exact existing six-destination shape.
impl<T, E: Error + 'static> CredentialAttemptV1<T, E> {
    pub(super) fn new() -> Self { Self::empty() }
}

// Only the real selected executor signer needs seed, two public policy/key
// pairs and BOTH independently configured revocation scopes: seven reads.
impl CredentialAttemptV1<super::plan_signer::ControllerBrokerPlanSignerV1,
    super::plan_signer::ControllerBrokerPlanSignerError, 7> {
    pub(super) fn new_start_signer_v2() -> Self { Self::empty() }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("credential semantic fixture refused")]
    struct SemanticRefusal;

    fn credential_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        std::fs::write(&path, [17_u8; 4]).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        directory
    }

    fn read_credential(
        source: &mut RetainedCredentialSourceV1,
        directory: &Path,
    ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
        source.read(
            directory,
            "credential",
            4,
            4,
            CredentialMetadataV1::Protected {
                private: true,
                owner: CredentialOwnerPolicyV1::RootOrCurrent,
            },
        )
    }

    #[test]
    fn completed_directory_moves_same_startup_locator_only_after_typed_take() {
        use std::os::unix::ffi::OsStrExt as _;
        let directory = credential_directory();
        let mut attempt = CredentialAttemptV1::new();

        assert!(attempt.bind_process_directory_once(directory.path().as_os_str()));
        assert!(attempt.capture_once(|source| {
            let captured = source.process_directory().unwrap();
            source.directory(&captured);
            read_credential(source, Path::new(&captured))
        }));
        let address = attempt.completed_directory_v1().unwrap().as_bytes().as_ptr();
        assert!(attempt.take_completed_directory_v1().is_none());
        assert_eq!(attempt.take_completed(), Some(Some(vec![17; 4])));

        let moved = attempt.take_completed_directory_v1().unwrap();
        assert_eq!(moved.as_bytes().as_ptr(), address);
        assert_eq!(moved.as_os_str(), directory.path().as_os_str());
        assert!(attempt.take_completed_directory_v1().is_none());
        assert!(attempt.failure().is_none());
    }

    #[test]
    fn absent_or_failed_typed_output_cannot_supply_completed_directory() {
        let directory = credential_directory();
        let mut absent = CredentialAttemptV1::<Vec<u8>, SemanticRefusal>::new();
        assert!(absent.capture_once(|source| {
            source.directory(directory.path().as_os_str());
            Ok(None)
        }));
        assert_eq!(absent.take_completed(), Some(None));
        assert!(absent.completed_directory_v1().is_none());
        assert!(absent.take_completed_directory_v1().is_none());

        let mut failed = CredentialAttemptV1::<Vec<u8>, SemanticRefusal>::new();
        assert!(!failed.capture_once(|source| {
            source.directory(directory.path().as_os_str());
            Err(SemanticRefusal)
        }));
        assert!(failed.completed_directory_v1().is_none());
        assert!(failed.take_completed_directory_v1().is_none());
        assert!(failed.failure().unwrap().is::<SemanticRefusal>());
    }

    #[test]
    fn completed_typed_credential_disposes_file_and_keeps_original_bytes_and_read_outcomes() {
        let directory = credential_directory();
        let mut attempt = CredentialAttemptV1::new();

        assert!(attempt.capture_once(|source| read_credential(source, directory.path())));
        std::fs::remove_file(directory.path().join("credential")).unwrap();

        let read = &attempt.reader.reads[0];
        assert!(read.view().open.is_none());
        assert!(read.view().retired_completed_file);
        assert!(read.view().metadata.unwrap().is_ok());
        assert!(read.view().exact.unwrap().is_ok());
        assert!(read.view().trailing.unwrap().is_ok());
        let bytes = read.outcome().unwrap().unwrap().unwrap();
        assert_eq!(bytes.as_slice(), &[17; 4]);

        assert_eq!(attempt.take_completed(), Some(Some(vec![17; 4])));
        assert!(attempt.take_completed().is_none());
        assert!(!attempt.capture_once(|_| panic!("completed original cannot reread")));
        assert!(attempt.failure().is_none());
    }

    #[test]
    fn late_semantic_refusal_keeps_file_and_exact_cause_through_reentry() {
        let directory = credential_directory();
        let mut attempt = CredentialAttemptV1::<Vec<u8>, SemanticRefusal>::new();

        assert!(!attempt.capture_once(|source| {
            let _bytes = read_credential(source, directory.path()).unwrap().unwrap();
            source.retain(SemanticRefusal);
            Err(SemanticRefusal)
        }));
        std::fs::remove_file(directory.path().join("credential")).unwrap();
        let original_cause = attempt.failure().unwrap()
            .downcast_ref::<SemanticRefusal>().unwrap();
        let cause = std::ptr::from_ref(original_cause);

        assert!(attempt.reader.reads[0].view().open.unwrap().is_ok());
        assert!(!attempt.reader.reads[0].view().retired_completed_file);
        let bytes = attempt.reader.reads[0].outcome().unwrap().unwrap().unwrap();
        assert_eq!(bytes.as_slice(), &[17; 4]);

        assert!(attempt.take_completed().is_none());
        assert!(!attempt.capture_once(|_| panic!("failed original cannot reread")));
        let after_reentry = attempt.failure().unwrap()
            .downcast_ref::<SemanticRefusal>().unwrap();
        assert_eq!(std::ptr::from_ref(after_reentry), cause);
        assert!(attempt.reader.reads[0].view().open.unwrap().is_ok());
    }

    #[test]
    fn sixth_selected_credential_keeps_all_prior_files_on_late_failure() {
        let directory = credential_directory();
        let mut attempt = CredentialAttemptV1::<Vec<u8>, SemanticRefusal>::new();

        assert!(!attempt.capture_once(|source| {
            for _ in 0..6 {
                read_credential(source, directory.path()).unwrap().unwrap();
            }
            source.retain(SemanticRefusal);
            Err(SemanticRefusal)
        }));

        assert_eq!(attempt.reader.next, 6);
        for original in &attempt.reader.reads {
            assert!(original.view().open.unwrap().is_ok());
            assert!(!original.view().retired_completed_file);
        }
        assert!(attempt.failure().unwrap().is::<SemanticRefusal>());
        assert!(attempt.take_completed().is_none());
        assert!(!attempt.capture_once(|_| panic!("failed six-read original cannot reenter")));
    }
}
