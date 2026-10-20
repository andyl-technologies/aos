//! Retained endpoint acquisition over the shared native file observations.
//!
//! Completed files move only after their ordinary checks succeed. Failed
//! descriptors, native results and partial zeroizing secret buffers remain in
//! the same destination. These private owners grant no receiving authority.

use super::*;
use crate::controller_session_receiving::{ControllerClientReceivingV4, ControllerClientReceivingErrorV4};
use aos_sandbox_broker::endpoint_native_files::EndpointNativeLockOriginalV1;
use super::observations::*;

fn cause<T, E>(slot: &Option<Result<T, E>>) -> Option<&E> {
    slot.as_ref().and_then(|result| result.as_ref().err())
}

pub(super) struct ManifestOpeningV1 {
    pub(super) contents: FileContentsOriginalsV1<[u8; BROKER_SESSION_MANIFEST_BYTES]>,
    pub(super) descriptor: FileOpenOriginalsV1,
}

impl ManifestOpeningV1 {
    pub(super) const fn new() -> Self {
        Self { contents: FileContentsOriginalsV1::new(), descriptor: FileOpenOriginalsV1::new() }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.descriptor.failure().or_else(|| self.contents.failure())
    }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.descriptor.classified_failure().or_else(|| self.contents.classified_failure())
    }

    pub(super) fn load_once(&mut self, directory: &EndpointNativeFileV1, owner: u32) {
        if self.descriptor.entered() { return; }
        self.descriptor.child_once(directory, MANIFEST_NAME, "manifest");
        let Some(descriptor) = self.descriptor.descriptor() else { return };
        self.contents.observe_once(descriptor, owner, BROKER_SESSION_MANIFEST_BYTES,
            "manifest", new_manifest_bytes, || Ok(()));
    }

    pub(super) fn take_completed(&mut self) -> Option<ManifestFile> {
        if !self.contents.completed() { return None; }
        let metadata = self.contents.before.snapshot()?;
        let exact = self.contents.exact.take()?;
        let digest = Sha256::digest(exact).into();
        Some(ManifestFile { descriptor: self.descriptor.take_descriptor()?, metadata, exact, digest })
    }

    pub(super) fn into_result(mut self) -> Result<ManifestFile, BrokerSessionSecurityError> {
        self.take_completed().ok_or_else(|| self.classified_failure()
            .unwrap_or(BrokerSessionSecurityError::Currentness))
    }
}

pub(super) struct SecretOpeningV1 {
    pub(super) contents: FileContentsOriginalsV1<SecretReadBytesV1>,
    pub(super) descriptor: FileOpenOriginalsV1,
    label: &'static str,
}

impl SecretOpeningV1 {
    pub(super) const fn new() -> Self {
        Self { contents: FileContentsOriginalsV1::new(), descriptor: FileOpenOriginalsV1::new(), label: "unentered secret" }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.descriptor.failure().or_else(|| self.contents.failure())
    }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.descriptor.classified_failure().or_else(|| self.contents.classified_failure())
    }

    pub(super) fn load_once(
        &mut self, directory: &EndpointNativeFileV1, owner: u32, name: &'static str, label: &'static str,
        between_reads: impl FnOnce() -> Result<(), BrokerSessionSecurityError>,
    ) {
        if self.descriptor.entered() { return; }
        self.label = label;
        self.descriptor.child_once(directory, name, label);
        let Some(descriptor) = self.descriptor.descriptor() else { return };
        self.contents.observe_once(descriptor, owner, SECRET_BYTES, label, new_secret_bytes, between_reads);
    }

    pub(super) fn take_completed(&mut self) -> Option<SecretFile> {
        if !self.contents.completed() { return None; }
        Some(SecretFile {
            metadata: self.contents.before.snapshot()?,
            descriptor: self.descriptor.take_descriptor()?,
            exact: self.contents.exact.take()?.0,
            label: self.label,
        })
    }

    pub(super) fn into_result(mut self) -> Result<SecretFile, BrokerSessionSecurityError> {
        self.take_completed().ok_or_else(|| self.classified_failure()
            .unwrap_or(BrokerSessionSecurityError::Currentness))
    }
}

/// Keeps the actual partial endpoint acquisition through independent posts.
pub(crate) struct ProtectedEndpointFilesOpeningV1 {
    entered: bool,
    retain_completed_probes: bool,
    path: Option<Result<(), BrokerSessionSecurityError>>,
    directory: FileOpenOriginalsV1,
    controller_entry: Option<Result<(), ControllerClientReceivingErrorV4>>,
    metadata: MetadataOriginalsV1,
    opposite: OppositeNamesOriginalsV1,
    manifest_opening: ManifestOpeningV1,
    manifest_file: Option<ManifestFile>,
    lock_native: EndpointNativeLockOriginalV1,
    locked: Option<Result<(), BrokerSessionSecurityError>>,
    manifest: Option<Result<BrokerSessionManifestV1, aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestErrorV1>>,
    active: Option<Result<(), aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestErrorV1>>,
    secret_openings: [SecretOpeningV1; 2],
    secrets: [Option<SecretFile>; 2],
    keys: Option<Result<(), BrokerSessionSecurityError>>,
    files: Option<ProtectedEndpointFiles>,
    final_post: ProtectedEndpointFilesRevalidationV1,
}

impl ProtectedEndpointFilesOpeningV1 {
    pub(crate) const fn new() -> Self {
        Self {
            entered: false, retain_completed_probes: true, path: None, directory: FileOpenOriginalsV1::new(), controller_entry: None,
            metadata: MetadataOriginalsV1::new(), opposite: OppositeNamesOriginalsV1::new(),
            manifest_opening: ManifestOpeningV1::new(), manifest_file: None,
            lock_native: EndpointNativeLockOriginalV1::new(), locked: None, manifest: None, active: None,
            secret_openings: [SecretOpeningV1::new(), SecretOpeningV1::new()],
            secrets: [None, None], keys: None, files: None,
            final_post: ProtectedEndpointFilesRevalidationV1::new(),
        }
    }

    /// Bounds initial key buffers plus the retained first file post.
    pub(crate) const fn secret_heap_bytes_v1() -> usize {
        4 * std::mem::size_of::<Zeroizing<[u8; SECRET_BYTES]>>()
            + 4 * EndpointNativeFileV1::selected_descriptor_heap_bytes_v1()
            + ProtectedEndpointFilesRevalidationV1::secret_heap_bytes_v1()
    }

    /// Bounds original file custody and the retained initial file post.
    pub(crate) const fn opened_file_bound_v1() -> usize {
        // Original directory, manifest and two local secret descriptors.
        4 + ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1()
    }

    /// Bounds the reached native/read/key carriers, including the initial post.
    pub(crate) const fn metadata_cell_bound_v1() -> usize {
        // One owner, four opens, nine Stat returns, six exact-read returns,
        // one flock, two manifest results, one key check and four secret boxes.
        1 + 4 + 9 + 6 + 1 + 2 + 1 + 4
            + ProtectedEndpointFilesRevalidationV1::metadata_cell_bound_v1()
    }

    pub(crate) const fn ordinary() -> Self {
        let mut value = Self::new();
        value.retain_completed_probes = false;
        value
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        cause(&self.path).map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.controller_entry.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.directory.failure()).or_else(|| self.metadata.failure())
            .or_else(|| self.opposite.failure()).or_else(|| self.manifest_opening.failure())
            .or_else(|| self.lock_native.result().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| cause(&self.locked).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| cause(&self.manifest).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| cause(&self.active).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.secret_openings[0].failure()).or_else(|| self.secret_openings[1].failure())
            .or_else(|| cause(&self.keys).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.final_post.failure())
    }

    pub(crate) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        if matches!(self.controller_entry, Some(Err(_))) {
            return Some(BrokerSessionSecurityError::Currentness);
        }
        cause(&self.path).cloned().or_else(|| self.directory.classified_failure())
            .or_else(|| self.metadata.classified_failure()).or_else(|| self.opposite.classified_failure())
            .or_else(|| self.manifest_opening.classified_failure()).or_else(|| cause(&self.locked).cloned())
            .or_else(|| cause(&self.manifest).cloned().map(Into::into))
            .or_else(|| cause(&self.active).cloned().map(Into::into))
            .or_else(|| self.secret_openings[0].classified_failure())
            .or_else(|| self.secret_openings[1].classified_failure())
            .or_else(|| cause(&self.keys).cloned()).or_else(|| self.final_post.classified_failure())
    }

    pub(crate) fn load_once(&mut self, path: &Path, role: EndpointRole) {
        self.load_with_initial_once(path, role, None);
    }

    pub(crate) fn load_controller_initial_once(&mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>) {
        self.load_controller_context_v4(&mut ControllerClientReceivingV4::Initial(receiving));
    }

    pub(crate) fn load_controller_context_v4(&mut self, receiving: &mut ControllerClientReceivingV4<'_, '_>) {
        let path = receiving.role().endpoint_custody_path_v1();
        self.load_with_initial_once(Path::new(path), EndpointRole::Client, Some(receiving));
    }

    fn load_with_initial_once(
        &mut self,
        path: &Path,
        role: EndpointRole,
        initial: Option<&mut ControllerClientReceivingV4<'_, '_>>,
    ) {
        if self.entered { return; }
        self.entered = true;
        self.path = Some(validate_absolute_fixed_path(path));
        if cause(&self.path).is_some() { return; }
        let owner = rustix::process::geteuid().as_raw();
        match initial {
            Some(receiving) => {
                self.controller_entry = Some(self.directory.controller_directory_once(receiving));
                if !matches!(self.controller_entry, Some(Ok(()))) { return; }
            }
            None => self.directory.directory_once(path, false),
        }
        let Some(directory) = self.directory.descriptor() else { return };
        self.metadata.directory_once(directory, owner);
        if self.metadata.snapshot().is_none() { return; }
        self.opposite.observe_once(directory, role);
        if !self.opposite.completed() { return; }
        self.manifest_opening.load_once(directory, owner);
        self.manifest_file = self.manifest_opening.take_completed();
        if !self.retain_completed_probes && self.manifest_file.is_some() {
            self.manifest_opening = ManifestOpeningV1::new();
        }
        let Some(manifest_file) = self.manifest_file.as_ref() else { return };

        self.lock_native.lock_once(&manifest_file.descriptor);
        self.locked = Some(match self.lock_native.result() {
            Some(Ok(())) => Ok(()),
            Some(Err(rustix::io::Errno::AGAIN)) => Err(BrokerSessionSecurityError::AlreadyInUse),
            _ => Err(BrokerSessionSecurityError::filesystem("manifest", "lock")),
        });
        if cause(&self.locked).is_some() { return; }
        self.manifest = Some(BrokerSessionManifestV1::decode(&manifest_file.exact));
        let Some(Ok(manifest)) = self.manifest.as_ref() else { return };
        self.active = Some(manifest.require_all_active());
        if cause(&self.active).is_some() { return; }

        let [first, second] = role.local_files();
        for (index, (name, label, _)) in [first, second].into_iter().enumerate() {
            self.secret_openings[index].load_once(directory, owner, name, label, || Ok(()));
            self.secrets[index] = self.secret_openings[index].take_completed();
            if self.secrets[index].is_none() { return; }
            if !self.retain_completed_probes { self.secret_openings[index] = SecretOpeningV1::new(); }
        }
        let secret_refs = match (&self.secrets[0], &self.secrets[1]) {
            (Some(first), Some(second)) => [first, second],
            _ => std::process::abort(),
        };
        self.keys = Some(validate_local_key_refs(manifest, secret_refs, [first.2, second.2]));
        if cause(&self.keys).is_some() { return; }

        let Some(metadata) = self.metadata.snapshot() else { std::process::abort() };
        let Some(directory) = self.directory.take_descriptor() else { std::process::abort() };
        let Some(manifest_file) = self.manifest_file.take() else { std::process::abort() };
        let Some(Ok(manifest)) = self.manifest.take() else { std::process::abort() };
        let [Some(first), Some(second)] = [self.secrets[0].take(), self.secrets[1].take()] else { std::process::abort() };
        self.files = Some(ProtectedEndpointFiles {
            path: path.to_path_buf(), owner, role, directory, directory_metadata: metadata,
            manifest_file, secrets: [first, second], manifest,
        });
        let Some(files) = self.files.as_ref() else { std::process::abort() };
        if self.retain_completed_probes {
            files.revalidate_into(&mut self.final_post);
        } else {
            self.final_post.observe_once(files, false);
            self.final_post.dispose_ordinary();
        }
    }

    pub(crate) fn completed_ref(&self) -> Option<&ProtectedEndpointFiles> {
        if self.final_post.completed() { self.files.as_ref() } else { None }
    }

    // The upper endpoint constructor has also completed its independent
    // self-execution post before calling this positive-only disposition.
    pub(crate) fn retire_completed_probes_v1(&mut self) -> bool {
        self.retain_completed_probes
            && self.files.is_some()
            && self.final_post.retire_completed_probes_v1()
    }

    #[cfg(test)]
    pub(crate) fn retained_probe_file_count_v1(&self) -> usize {
        self.final_post.retained_file_count()
    }

    pub(crate) fn take_completed(&mut self) -> Option<ProtectedEndpointFiles> {
        if self.final_post.completed() { self.files.take() } else { None }
    }

    pub(crate) fn into_result(mut self) -> Result<ProtectedEndpointFiles, BrokerSessionSecurityError> {
        let result = self.take_completed().ok_or_else(|| self.classified_failure()
            .unwrap_or(BrokerSessionSecurityError::Currentness));
        // The ordinary loader's partially constructed child drops before its
        // earlier siblings, then manifest, then directory. Selected callers do
        // not enter this immediate disposition.
        self.final_post = ProtectedEndpointFilesRevalidationV1::new();
        self.files = None;
        self.secret_openings[1] = SecretOpeningV1::new();
        self.secret_openings[0] = SecretOpeningV1::new();
        self.secrets = [None, None];
        self.manifest_file = None;
        self.manifest_opening = ManifestOpeningV1::new();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn malformed_manifest_keeps_the_actual_original_exclusive_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(MANIFEST_NAME);
        fs::write(&path, [0; BROKER_SESSION_MANIFEST_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let mut opening = ProtectedEndpointFilesOpeningV1::new();

        opening.load_once(directory.path(), EndpointRole::Broker);
        assert!(opening.failure().is_some());
        assert!(matches!(opening.locked, Some(Ok(()))));
        assert!(opening.files.is_none());
        let parent = open_directory(directory.path()).unwrap();
        let competing = open_child(&parent, MANIFEST_NAME, "manifest").unwrap();
        assert_eq!(competing.lock_exclusive_nonblocking(), Err(rustix::io::Errno::AGAIN));

        drop(opening);
        assert!(competing.lock_exclusive_nonblocking().is_ok());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_negative_between_reads_keeps_the_first_secret_and_original_descriptor() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("secret");
        fs::write(&path, [0x41; SECRET_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let directory = open_directory(temporary.path()).unwrap();
        let mut opening = SecretOpeningV1::new();
        let original_inode = fs::metadata(&path).unwrap();
        use std::os::unix::fs::MetadataExt as _;

        opening.load_once(&directory, rustix::process::geteuid().as_raw(), "secret", "secret", || {
            fs::rename(&path, temporary.path().join("old-secret")).unwrap();
            fs::write(&path, [0x42; SECRET_BYTES]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            Err(BrokerSessionSecurityError::Entropy)
        });

        assert_eq!(opening.classified_failure(), Some(BrokerSessionSecurityError::Entropy));
        let retained = opening.descriptor.descriptor().unwrap();
        assert_eq!(retained.metadata().unwrap().st_ino, original_inode.ino());
        assert_ne!(fs::metadata(&path).unwrap().ino(), original_inode.ino());
        assert_eq!(&opening.contents.exact.as_ref().unwrap().0[..], &[0x41; SECRET_BYTES]);
        assert!(opening.contents.repeated.is_none());
        assert!(opening.take_completed().is_none());
    }

    #[test]
    fn ordinary_and_retained_secret_failure_keep_the_same_classification() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("secret");
        fs::write(&path, [0x41; SECRET_BYTES - 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let directory = open_directory(temporary.path()).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let mut opening = SecretOpeningV1::new();
        opening.load_once(&directory, owner, "secret", "secret", || Ok(()));

        let ordinary = load_secret(&directory, owner, "secret", "secret").err();
        assert_eq!(opening.classified_failure().as_ref(), ordinary.as_ref());
        assert!(opening.descriptor.descriptor().is_some());
        assert!(opening.contents.exact.is_none());
    }
}
