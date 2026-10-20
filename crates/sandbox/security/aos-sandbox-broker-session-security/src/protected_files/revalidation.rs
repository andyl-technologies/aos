//! One complete endpoint-file currentness observation and its native custody.
//!
//! Successful selected observations remain live until their enclosing
//! execution-after post succeeds. Failed observations keep every acquired
//! descriptor and partial secret read. An ordinary adapter uses the same
//! recipe and disposes each temporary at the original local return boundary.

use super::*;
use super::observations::*;
use super::opening::{ManifestOpeningV1, SecretOpeningV1};

/// Retains one file currentness observation; it grants no endpoint authority.
pub(crate) struct ProtectedEndpointFilesRevalidationV1 {
    entered: bool,
    owner: Option<Result<(), BrokerSessionSecurityError>>,
    held_directory: MetadataOriginalsV1,
    held_directory_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    held_opposite: OppositeNamesOriginalsV1,
    held_manifest: FileContentsOriginalsV1<[u8; BROKER_SESSION_MANIFEST_BYTES]>,
    held_manifest_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    held_secrets: [FileContentsOriginalsV1<SecretReadBytesV1>; 2],
    held_secret_comparisons: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    // Field order also preserves the ordinary fresh child-before-parent close
    // boundary on a failed comparison.
    reopened_secret_files: [Option<SecretFile>; 2],
    reopened_secrets: [SecretOpeningV1; 2],
    reopened_secret_comparisons: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    reopened_manifest_file: Option<ManifestFile>,
    reopened_manifest: ManifestOpeningV1,
    reopened_manifest_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    reopened_directory: FileOpenOriginalsV1,
    reopened_metadata: MetadataOriginalsV1,
    reopened_directory_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    reopened_opposite: OppositeNamesOriginalsV1,
    result: Option<Result<(), BrokerSessionSecurityError>>,
}

fn error<T>(slot: &Option<Result<T, BrokerSessionSecurityError>>) -> Option<&BrokerSessionSecurityError> {
    slot.as_ref().and_then(|result| result.as_ref().err())
}

fn require(comparison: bool) -> Result<(), BrokerSessionSecurityError> {
    if comparison { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) }
}

impl ProtectedEndpointFilesRevalidationV1 {
    pub(crate) const fn new() -> Self {
        Self {
            entered: false, owner: None, held_directory: MetadataOriginalsV1::new(),
            held_directory_comparison: None, held_opposite: OppositeNamesOriginalsV1::new(),
            held_manifest: FileContentsOriginalsV1::new(), held_manifest_comparison: None,
            held_secrets: [FileContentsOriginalsV1::new(), FileContentsOriginalsV1::new()],
            held_secret_comparisons: [None, None],
            reopened_secret_files: [None, None],
            reopened_secrets: [SecretOpeningV1::new(), SecretOpeningV1::new()],
            reopened_secret_comparisons: [None, None], reopened_manifest_file: None, reopened_manifest: ManifestOpeningV1::new(),
            reopened_manifest_comparison: None, reopened_directory: FileOpenOriginalsV1::new(),
            reopened_metadata: MetadataOriginalsV1::new(), reopened_directory_comparison: None,
            reopened_opposite: OppositeNamesOriginalsV1::new(), result: None,
        }
    }

    /// Counts the additional secret heap retained by one complete observation.
    pub(crate) const fn secret_heap_bytes_v1() -> usize {
        // Held and reopened pairs each retain both reads of both secrets.
        2 * 2 * 2 * std::mem::size_of::<Zeroizing<[u8; SECRET_BYTES]>>()
            + 4 * EndpointNativeFileV1::selected_descriptor_heap_bytes_v1()
    }

    pub(crate) const fn opened_file_bound_v1() -> usize {
        // Fresh directory, manifest and the two local secret descriptors.
        1 + 1 + 2
    }

    pub(crate) const fn metadata_cell_bound_v1() -> usize {
        // One owner plus 18 Stat returns, 12 complete read returns, four
        // opened descriptor slots and eight zeroizing heap allocations.
        1 + 18 + 12 + Self::opened_file_bound_v1() + 8
    }

    #[cfg(test)]
    pub(crate) fn retained_file_count(&self) -> usize {
        usize::from(self.reopened_directory.descriptor().is_some())
            + usize::from(self.reopened_manifest.descriptor.descriptor().is_some())
            + usize::from(self.reopened_manifest_file.is_some())
            + self.reopened_secrets.iter().filter(|secret| secret.descriptor.descriptor().is_some()).count()
            + self.reopened_secret_files.iter().filter(|secret| secret.is_some()).count()
    }

    #[cfg(test)]
    pub(crate) fn retained_manifest_pair_v1(&self) -> Option<(&[u8], &[u8])> {
        if !self.held_manifest.completed() {
            return None;
        }
        Some((self.held_manifest.exact.as_ref()?.as_slice(),
            self.held_manifest.repeated.as_ref()?.as_slice()))
    }

    pub(crate) fn completed(&self) -> bool { matches!(self.result, Some(Ok(()))) }

    /// Disposes a complete positive probe after the enclosing execution post.
    ///
    /// Only the actual joint endpoint constructor calls this after both file
    /// comparisons, entropy and its independent process post pass. The real
    /// endpoint files remain identity anchors. Failed probes are untouched;
    /// the entered/result fence prevents a later observation from reusing it.
    pub(crate) fn retire_completed_probes_v1(&mut self) -> bool {
        if !self.completed() || self.failure().is_some() {
            return false;
        }
        self.dispose_ordinary();
        true
    }

    pub(crate) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).cloned()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! typed { ($slot:expr) => { error($slot).map(|cause| cause as &dyn std::error::Error) }; }
        typed!(&self.owner).or_else(|| self.held_directory.failure())
            .or_else(|| typed!(&self.held_directory_comparison)).or_else(|| self.held_opposite.failure())
            .or_else(|| self.held_manifest.failure()).or_else(|| typed!(&self.held_manifest_comparison))
            .or_else(|| self.held_secrets[0].failure()).or_else(|| typed!(&self.held_secret_comparisons[0]))
            .or_else(|| self.held_secrets[1].failure()).or_else(|| typed!(&self.held_secret_comparisons[1]))
            .or_else(|| self.reopened_directory.failure()).or_else(|| self.reopened_metadata.failure())
            .or_else(|| typed!(&self.reopened_directory_comparison)).or_else(|| self.reopened_opposite.failure())
            .or_else(|| self.reopened_manifest.failure()).or_else(|| typed!(&self.reopened_manifest_comparison))
            .or_else(|| self.reopened_secrets[0].failure()).or_else(|| typed!(&self.reopened_secret_comparisons[0]))
            .or_else(|| self.reopened_secrets[1].failure()).or_else(|| typed!(&self.reopened_secret_comparisons[1]))
            .or_else(|| typed!(&self.result))
    }

    pub(super) fn observe_once(&mut self, files: &ProtectedEndpointFiles, retained: bool) {
        if self.entered { return; }
        self.entered = true;
        self.result = Some(self.observe_inner(files, retained));
    }

    // Ordinary observations dispose at their immediate return boundary. The
    // selected adapter reaches this only after the complete execution-after post.
    pub(super) fn dispose_ordinary(&mut self) {
        if !self.entered || self.result.is_none() { return; }
        let result = self.result.take();
        *self = Self::new();
        self.entered = true;
        self.result = result;
    }

    fn observe_inner(&mut self, files: &ProtectedEndpointFiles, retained: bool) -> Result<(), BrokerSessionSecurityError> {
        self.owner = Some(require(rustix::process::geteuid().as_raw() == files.owner));
        self.owner.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        self.held_directory.directory_once(&files.directory, files.owner);
        if let Some(cause) = self.held_directory.classified_failure() { return Err(cause); }
        self.held_directory_comparison = Some(require(self.held_directory.snapshot() == Some(files.directory_metadata)));
        self.held_directory_comparison.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        self.held_opposite.observe_once(&files.directory, files.role);
        if let Some(cause) = self.held_opposite.classified_failure() { return Err(cause); }

        self.held_manifest.observe_once(&files.manifest_file.descriptor, files.owner,
            BROKER_SESSION_MANIFEST_BYTES, "manifest", new_manifest_bytes, || Ok(()));
        if let Some(cause) = self.held_manifest.classified_failure() { return Err(cause); }
        self.held_manifest_comparison = Some(require(manifest_matches(&self.held_manifest, &files.manifest_file)));
        self.held_manifest_comparison.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        if !retained { self.held_manifest = FileContentsOriginalsV1::new(); }

        for (index, secret) in files.secrets.iter().enumerate() {
            self.held_secrets[index].observe_once(&secret.descriptor, files.owner, SECRET_BYTES,
                secret.label, new_secret_bytes, || Ok(()));
            if let Some(cause) = self.held_secrets[index].classified_failure() { return Err(cause); }
            self.held_secret_comparisons[index] = Some(require(secret_matches(&self.held_secrets[index], secret)));
            self.held_secret_comparisons[index].as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
            if !retained { self.held_secrets[index] = FileContentsOriginalsV1::new(); }
        }

        self.reopened_directory.corresponding_directory_once(&files.directory, &files.path);
        let directory = self.reopened_directory.descriptor().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.reopened_metadata.directory_once(directory, files.owner);
        if let Some(cause) = self.reopened_metadata.classified_failure() { return Err(cause); }
        self.reopened_directory_comparison = Some(require(self.reopened_metadata.snapshot() == Some(files.directory_metadata)));
        self.reopened_directory_comparison.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        self.reopened_opposite.observe_once(directory, files.role);
        if let Some(cause) = self.reopened_opposite.classified_failure() { return Err(cause); }

        self.reopened_manifest.load_once(directory, files.owner);
        if let Some(cause) = self.reopened_manifest.classified_failure() { return Err(cause); }
        self.reopened_manifest_file = if retained {
            self.reopened_manifest.take_completed()
        } else {
            let opening = std::mem::replace(&mut self.reopened_manifest, ManifestOpeningV1::new());
            Some(opening.into_result()?)
        };
        let manifest = self.reopened_manifest_file.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.reopened_manifest_comparison = Some(require(
            manifest.metadata == files.manifest_file.metadata
                && manifest.digest == files.manifest_file.digest
                && manifest.exact == files.manifest_file.exact,
        ));
        self.reopened_manifest_comparison.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        for (index, (secret, (name, label, _))) in files.secrets.iter().zip(files.role.local_files()).enumerate() {
            self.reopened_secrets[index].load_once(directory, files.owner, name, label, || Ok(()));
            if let Some(cause) = self.reopened_secrets[index].classified_failure() { return Err(cause); }
            self.reopened_secret_files[index] = if retained {
                self.reopened_secrets[index].take_completed()
            } else {
                let opening = std::mem::replace(&mut self.reopened_secrets[index], SecretOpeningV1::new());
                Some(opening.into_result()?)
            };
            let reopened = self.reopened_secret_files[index].as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            self.reopened_secret_comparisons[index] = Some(require(
                reopened.metadata == secret.metadata && reopened.exact[..] == secret.exact[..],
            ));
            if !retained { self.reopened_secret_files[index] = None; }
            self.reopened_secret_comparisons[index].as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone()?;
        }
        Ok(())
    }
}

fn manifest_matches(contents: &FileContentsOriginalsV1<[u8; BROKER_SESSION_MANIFEST_BYTES]>, expected: &ManifestFile) -> bool {
    contents.completed() && contents.before.snapshot() == Some(expected.metadata)
        && contents.exact() == Some(&expected.exact[..])
        && contents.exact.as_ref().map(|exact| <[u8; 32]>::from(Sha256::digest(exact))) == Some(expected.digest)
}

fn secret_matches(contents: &FileContentsOriginalsV1<SecretReadBytesV1>, expected: &SecretFile) -> bool {
    contents.completed() && contents.before.snapshot() == Some(expected.metadata)
        && contents.exact() == Some(&expected.exact[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn failed_actual_child_open_keeps_exact_native_cause_on_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open_directory(directory.path()).unwrap();
        let mut observation = SecretOpeningV1::new();
        let owner = rustix::process::geteuid().as_raw();

        observation.load_once(&descriptor, owner, "missing", "missing secret", || Ok(()));
        let native = observation.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap()
            as *const rustix::io::Errno;
        assert_eq!(observation.classified_failure(),
            Some(BrokerSessionSecurityError::filesystem("missing secret", "open")));
        fs::write(directory.path().join("missing"), [7; SECRET_BYTES]).unwrap();
        fs::set_permissions(directory.path().join("missing"), fs::Permissions::from_mode(0o400)).unwrap();
        observation.load_once(&descriptor, owner, "missing", "replacement label", || Ok(()));

        assert!(std::ptr::eq(observation.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap(), native));
        assert!(observation.take_completed().is_none());
        assert!(observation.contents.exact.is_none());
    }
}
