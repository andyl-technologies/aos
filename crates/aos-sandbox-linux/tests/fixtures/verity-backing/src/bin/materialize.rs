//! Proves fresh-inode fs-verity materialization inside the VM's ext4 fixture.
//!
//! The expected AOS descriptor is constructed from test-owned bytes. This is a
//! kernel-mechanics qualification, not production publication authority.

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fmt;
    use std::fs::{File, OpenOptions};
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::{
        MediaType, ObjectDescriptorVerificationError, ObjectDescriptorVerifier,
        descriptor_for_bytes,
    };
    use aos_sandbox_linux::Error as LinuxError;
    use aos_sandbox_linux::immutable_file::{
        BeforeRenameFailure, FsVerityBacking, FsVerityDigest, FsVerityPublicationRoot,
        MaterializationCallbacks, MaterializationFailure, NoReplacePublicationError,
        PublicationName, RetainedPrivatePhase,
    };
    use aos_sandbox_linux::path::BeneathRoot;

    const SUCCESS_NAME: &str = ".materialize-success";
    const FINAL_NAME: &str = "materialized-object";
    const RENAME_CONFLICT_NAME: &str = "materialized-conflict";
    const OVER_LIMIT_NAME: &str = ".materialize-over-limit";
    const EXISTING_NAME: &str = ".materialize-existing";
    const REJECTED_NAME: &str = ".materialize-rejected";

    #[derive(Debug)]
    enum CallbackError {
        Descriptor(ObjectDescriptorVerificationError),
        MissingVerifier,
        Rejected,
    }

    impl fmt::Display for CallbackError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Descriptor(error) => error.fmt(formatter),
                Self::MissingVerifier => formatter.write_str("descriptor verifier was reused"),
                Self::Rejected => formatter.write_str("fixture rejected copied bytes"),
            }
        }
    }

    impl Error for CallbackError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Descriptor(error) => Some(error),
                Self::MissingVerifier | Self::Rejected => None,
            }
        }
    }

    impl From<ObjectDescriptorVerificationError> for CallbackError {
        fn from(error: ObjectDescriptorVerificationError) -> Self {
            Self::Descriptor(error)
        }
    }

    struct ExactCallbacks {
        verifier: Option<ObjectDescriptorVerifier>,
    }

    impl MaterializationCallbacks for ExactCallbacks {
        type Error = CallbackError;

        fn checkpoint(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.verifier
                .as_mut()
                .ok_or(CallbackError::MissingVerifier)?
                .update(bytes)?;
            Ok(())
        }

        fn finish_verification(&mut self) -> Result<(), Self::Error> {
            self.verifier
                .take()
                .ok_or(CallbackError::MissingVerifier)?
                .finish()?;
            Ok(())
        }
    }

    struct RejectingCallbacks;

    impl MaterializationCallbacks for RejectingCallbacks {
        type Error = CallbackError;

        fn checkpoint(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn verify_chunk(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
            Err(CallbackError::Rejected)
        }

        fn finish_verification(&mut self) -> Result<(), Self::Error> {
            Err(CallbackError::Rejected)
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let root_path = required_root()?;
        let source_path = root_path
            .parent()
            .ok_or("publication root has no parent")?
            .join("materialize-source");
        let bytes: Vec<u8> = (0..(160 * 1024 + 37))
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect();
        std::fs::write(&source_path, &bytes)?;

        let source_metadata = std::fs::metadata(&source_path)?;
        let mut source_pin = File::open(&source_path)?;
        source_pin.seek(SeekFrom::Start(7))?;
        let source_for_publication: OwnedFd = source_pin.try_clone()?.into();

        let root = FsVerityPublicationRoot::from_owned(File::open(&root_path)?.into())?;
        let expected = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")?,
            &bytes,
        );
        let mut exact = ExactCallbacks {
            verifier: Some(ObjectDescriptorVerifier::new(expected.clone())),
        };
        let sealed = root.materialize_and_seal(
            source_for_publication,
            publication_name(SUCCESS_NAME)?,
            expected.encoded_size(),
            &mut exact,
        )?;

        let source_offset_unchanged = source_pin.stream_position()? == 7;
        let fresh_inode =
            sealed.device() != source_metadata.dev() || sealed.inode() != source_metadata.ino();
        let exact_size = sealed.bytes() == expected.encoded_size();
        let measurement = sealed.verity_digest();
        let measurement_is_sha256 = matches!(measurement, FsVerityDigest::Sha256(_));
        let sealed_device = sealed.device();
        let sealed_inode = sealed.inode();

        let mut pinned_bytes = Vec::new();
        File::from(sealed.as_fd().try_clone_to_owned()?).read_to_end(&mut pinned_bytes)?;
        let exact_bytes = pinned_bytes == bytes;

        let (same_name_preserved, sealed) = match sealed
            .publish_noreplace(publication_name(SUCCESS_NAME)?)
        {
            Err(NoReplacePublicationError::BeforeRename {
                failure: BeforeRenameFailure::SameName,
                private,
            }) => {
                let private_metadata = std::fs::metadata(root_path.join(SUCCESS_NAME))?;
                let preserved = private.device() == sealed_device
                    && private.inode() == sealed_inode
                    && private.bytes() == expected.encoded_size()
                    && private.verity_digest() == measurement
                    && private_metadata.dev() == sealed_device
                    && private_metadata.ino() == sealed_inode;
                (preserved, *private)
            }
            _ => {
                return Err("same-name publication did not return the exact private token".into());
            }
        };

        let rename_conflict_path = root_path.join(RENAME_CONFLICT_NAME);
        std::fs::write(&rename_conflict_path, b"rename conflict")?;
        let rename_conflict_before = std::fs::metadata(&rename_conflict_path)?;
        let (rename_conflict_preserved, sealed) = match sealed
            .publish_noreplace(publication_name(RENAME_CONFLICT_NAME)?)
        {
            Err(NoReplacePublicationError::BeforeRename {
                failure: BeforeRenameFailure::DestinationExists,
                private,
            }) => {
                let rename_conflict_after = std::fs::metadata(&rename_conflict_path)?;
                let private_metadata = std::fs::metadata(root_path.join(SUCCESS_NAME))?;
                let preserved = std::fs::read(&rename_conflict_path)? == b"rename conflict"
                    && rename_conflict_before.dev() == rename_conflict_after.dev()
                    && rename_conflict_before.ino() == rename_conflict_after.ino()
                    && private.device() == sealed_device
                    && private.inode() == sealed_inode
                    && private.verity_digest() == measurement
                    && private_metadata.dev() == sealed_device
                    && private_metadata.ino() == sealed_inode;
                (preserved, *private)
            }
            _ => {
                return Err("EEXIST publication did not preserve the exact private token".into());
            }
        };

        let named = match sealed.publish_noreplace(publication_name(FINAL_NAME)?) {
            Ok(named) => named,
            Err(_) => return Err("retry to a free final name failed".into()),
        };
        let final_metadata = std::fs::metadata(root_path.join(FINAL_NAME))?;
        let durable_rename_preserved = named.device() == sealed_device
            && named.inode() == sealed_inode
            && named.bytes() == expected.encoded_size()
            && named.verity_digest() == measurement
            && final_metadata.dev() == sealed_device
            && final_metadata.ino() == sealed_inode
            && final_metadata.len() == expected.encoded_size();
        let old_private_absent = matches!(
            std::fs::symlink_metadata(root_path.join(SUCCESS_NAME)),
            Err(ref error) if error.raw_os_error() == Some(libc::ENOENT)
        );
        let conflict_retry_succeeded = named.final_name().as_os_str() == OsStr::new(FINAL_NAME);

        let reopen_root = BeneathRoot::from_owned(File::open(&root_path)?.into())?;
        let reopened = FsVerityBacking::open_beneath(
            &reopen_root,
            Path::new(FINAL_NAME),
            measurement,
            expected.encoded_size(),
            expected.encoded_size(),
        )?;
        let reopened_identity = reopened.identity();
        let backing_verified = reopened_identity.device() == named.device()
            && reopened_identity.inode() == named.inode()
            && reopened_identity.bytes() == named.bytes();
        let writable_open = OpenOptions::new()
            .write(true)
            .open(root_path.join(FINAL_NAME));
        let writable_open_denied = matches!(
            writable_open,
            Err(ref error) if error.raw_os_error() == Some(libc::EPERM)
        );

        let before_over_limit = directory_entries(&root_path)?;
        let over_limit_source: OwnedFd = File::open(&source_path)?.into();
        let mut over_limit_callbacks = ExactCallbacks {
            verifier: Some(ObjectDescriptorVerifier::new(expected.clone())),
        };
        let over_limit = root.materialize_and_seal(
            over_limit_source,
            publication_name(OVER_LIMIT_NAME)?,
            expected.encoded_size() - 1,
            &mut over_limit_callbacks,
        );
        let quota_rejected_before_create = matches!(
            over_limit,
            Err(ref error)
                if matches!(error.cause(), MaterializationFailure::ByteLimitExceeded)
                    && error.retained_artifact().is_none()
        ) && !root_path.join(OVER_LIMIT_NAME).exists()
            && directory_entries(&root_path)? == before_over_limit;

        let existing_path = root_path.join(EXISTING_NAME);
        std::fs::write(&existing_path, b"existing bytes")?;
        let existing_before = std::fs::metadata(&existing_path)?;
        let existing_source: OwnedFd = File::open(&source_path)?.into();
        let mut existing_callbacks = ExactCallbacks {
            verifier: Some(ObjectDescriptorVerifier::new(expected.clone())),
        };
        let existing = root.materialize_and_seal(
            existing_source,
            publication_name(EXISTING_NAME)?,
            expected.encoded_size(),
            &mut existing_callbacks,
        );
        let existing_after = std::fs::metadata(&existing_path)?;
        let existing_name_untouched = matches!(
            existing.as_ref(),
            Err(error)
                if error.retained_artifact().is_none()
                    && matches!(
                        error.cause(),
                        MaterializationFailure::Linux(LinuxError::Syscall { source, .. })
                            if source.raw_os_error() == Some(libc::EEXIST)
                    )
        ) && std::fs::read(&existing_path)? == b"existing bytes"
            && existing_before.dev() == existing_after.dev()
            && existing_before.ino() == existing_after.ino();

        let rejected_source: OwnedFd = File::open(&source_path)?.into();
        let mut rejecting = RejectingCallbacks;
        let rejected = root.materialize_and_seal(
            rejected_source,
            publication_name(REJECTED_NAME)?,
            expected.encoded_size(),
            &mut rejecting,
        );
        let rejected_artifact = rejected
            .as_ref()
            .err()
            .and_then(|error| error.retained_artifact())
            .ok_or("callback rejection did not retain private artifact evidence")?;
        let callback_failure_retained = matches!(
            rejected.as_ref().err().map(|error| error.cause()),
            Some(MaterializationFailure::Callback(CallbackError::Rejected))
        ) && rejected_artifact.phase()
            == RetainedPrivatePhase::Materializing
            && rejected_artifact.name().as_os_str() == OsStr::new(REJECTED_NAME)
            && rejected_artifact.confirmed_bytes() == 0
            && std::fs::metadata(root_path.join(REJECTED_NAME))?.len() > 0;
        let retained_unsealed_writable = OpenOptions::new()
            .write(true)
            .open(root_path.join(REJECTED_NAME))
            .is_ok();

        println!(
            "{{\"schema_version\":\"aos.sandbox.verity-materialize-proof/v1\",\
             \"descriptor_verified\":{},\"fresh_inode\":{},\"exact_size\":{},\
             \"exact_bytes\":{},\"source_offset_unchanged\":{},\
             \"measurement_is_sha256\":{},\"backing_verified\":{},\
             \"writable_open_denied\":{},\"same_name_preserved\":{},\
             \"rename_conflict_preserved\":{},\"durable_rename_preserved\":{},\
             \"old_private_absent\":{},\"conflict_retry_succeeded\":{},\
             \"quota_rejected_before_create\":{},\
             \"existing_name_untouched\":{},\"callback_failure_retained\":{},\
             \"retained_unsealed_writable\":{}}}",
            exact.verifier.is_none(),
            fresh_inode,
            exact_size,
            exact_bytes,
            source_offset_unchanged,
            measurement_is_sha256,
            backing_verified,
            writable_open_denied,
            same_name_preserved,
            rename_conflict_preserved,
            durable_rename_preserved,
            old_private_absent,
            conflict_retry_succeeded,
            quota_rejected_before_create,
            existing_name_untouched,
            callback_failure_retained,
            retained_unsealed_writable,
        );
        Ok(())
    }

    fn required_root() -> Result<PathBuf, Box<dyn Error>> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        let root = arguments
            .next()
            .ok_or("missing publication-root argument")?;
        if arguments.next().is_some() {
            return Err("expected exactly one publication-root argument".into());
        }
        Ok(root.into())
    }

    fn publication_name(name: &str) -> Result<PublicationName, Box<dyn Error>> {
        Ok(PublicationName::new(OsStr::new(name))?)
    }

    fn directory_entries(root: &Path) -> Result<Vec<std::ffi::OsString>, Box<dyn Error>> {
        let mut entries = std::fs::read_dir(root)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        Ok(entries)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    linux::run()?;
    Ok(())
}
