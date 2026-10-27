//! Shared native observations for endpoint loading and currentness.
//!
//! Owners park native results and partial buffers before classification. The
//! ordinary adapter drops this same owner at its historical return boundary;
//! a selected caller retains it through the independently required posts.

use super::*;
use crate::controller_session_receiving::{ControllerClientReceivingV4, ControllerClientReceivingErrorV4};
use aos_sandbox_broker::endpoint_native_files::{
    EndpointNativeFileOpenOriginalV1, EndpointNativeMetadataOriginalV1,
    EndpointNativeReadOriginalV1,
};

fn ready<T>(slot: &Option<Result<T, BrokerSessionSecurityError>>) -> Option<&T> {
    slot.as_ref().and_then(|result| result.as_ref().ok())
}

pub(super) struct FileOpenOriginalsV1 {
    native: EndpointNativeFileOpenOriginalV1,
    result: Option<Result<(), BrokerSessionSecurityError>>,
}

impl FileOpenOriginalsV1 {
    pub(super) const fn new() -> Self {
        Self { native: EndpointNativeFileOpenOriginalV1::new(), result: None }
    }

    pub(super) fn directory_once(&mut self, path: &Path, currentness: bool) {
        if self.native.entered() { return; }
        self.native.directory_once(path);
        self.result = Some(match self.native.result() {
            Some(Ok(_)) => Ok(()),
            _ if currentness => Err(BrokerSessionSecurityError::CurrentnessObservation {
                observation: "directory open",
            }),
            _ => Err(BrokerSessionSecurityError::filesystem("endpoint directory", "open")),
        });
    }

    pub(super) fn controller_directory_once(
        &mut self,
        receiving: &mut ControllerClientReceivingV4<'_, '_>,
    ) -> Result<(), ControllerClientReceivingErrorV4> {
        receiving.capture_directory_once(&mut self.native)?;
        self.result = Some(match self.native.result() {
            Some(Ok(_)) => Ok(()),
            _ => Err(BrokerSessionSecurityError::filesystem("endpoint directory", "open")),
        });
        Ok(())
    }

    pub(super) fn corresponding_directory_once(
        &mut self,
        held: &EndpointNativeFileV1,
        path: &Path,
    ) {
        if self.native.entered() { return; }
        self.native.corresponding_directory_once(held, path);
        self.result = Some(match self.native.result() {
            Some(Ok(_)) => Ok(()),
            _ => Err(BrokerSessionSecurityError::CurrentnessObservation {
                observation: "corresponding directory open",
            }),
        });
    }

    pub(super) fn child_once(&mut self, directory: &EndpointNativeFileV1, name: &'static str, label: &'static str) {
        if self.native.entered() { return; }
        self.native.child_once(directory, name);
        self.result = Some(if matches!(self.native.result(), Some(Ok(_))) { Ok(()) }
            else { Err(BrokerSessionSecurityError::filesystem(label, "open")) });
    }

    pub(super) fn entered(&self) -> bool { self.native.entered() }

    pub(super) fn descriptor(&self) -> Option<&EndpointNativeFileV1> {
        self.native.descriptor()
    }

    pub(super) fn take_descriptor(&mut self) -> Option<EndpointNativeFileV1> {
        self.native.take_descriptor()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure().map(|cause| cause as &dyn std::error::Error)
    }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).cloned()
    }
}

pub(super) struct MetadataOriginalsV1 {
    native: EndpointNativeMetadataOriginalV1,
    result: Option<Result<MetadataSnapshot, BrokerSessionSecurityError>>,
}

impl MetadataOriginalsV1 {
    pub(super) const fn new() -> Self {
        Self { native: EndpointNativeMetadataOriginalV1::new(), result: None }
    }

    pub(super) fn directory_once(&mut self, descriptor: &EndpointNativeFileV1, owner: u32) {
        if self.native.entered() { return; }
        self.native.held_once(descriptor);
        self.result = Some(match self.native.result() {
            Some(Ok(stat)) => require_directory_metadata(stat, owner)
                .map(|()| MetadataSnapshot::capture(stat)),
            _ => Err(BrokerSessionSecurityError::filesystem("endpoint directory", "inspect")),
        });
    }

    fn child_once(&mut self, descriptor: &EndpointNativeFileV1, owner: u32, size: usize, label: &'static str) {
        if self.native.entered() { return; }
        self.native.held_once(descriptor);
        self.result = Some(match self.native.result() {
            Some(Ok(stat)) => i64::try_from(size)
                .map_err(|_| BrokerSessionSecurityError::Metadata { object: label })
                .and_then(|size| require_child_metadata(stat, owner, size, label))
                .map(|()| MetadataSnapshot::capture(stat)),
            _ => Err(BrokerSessionSecurityError::filesystem(label, "inspect")),
        });
    }

    pub(super) fn snapshot(&self) -> Option<MetadataSnapshot> {
        ready(&self.result).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.native.result() { return Some(cause); }
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
    }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).cloned()
    }
}

pub(super) struct OppositeNamesOriginalsV1 {
    native: [EndpointNativeMetadataOriginalV1; 2],
    result: Option<Result<(), BrokerSessionSecurityError>>,
}

impl OppositeNamesOriginalsV1 {
    pub(super) const fn new() -> Self {
        Self { native: [EndpointNativeMetadataOriginalV1::new(), EndpointNativeMetadataOriginalV1::new()], result: None }
    }

    pub(super) fn observe_once(&mut self, directory: &EndpointNativeFileV1, role: EndpointRole) {
        if self.result.is_some() || self.native.iter().any(EndpointNativeMetadataOriginalV1::entered) { return; }
        for (index, name) in role.opposite_files().into_iter().enumerate() {
            self.native[index].child_once(directory, name);
            let result = match self.native[index].result() {
                Some(Err(rustix::io::Errno::NOENT)) => Ok(()),
                Some(Ok(_)) => Err(BrokerSessionSecurityError::OppositeRoleSecret),
                _ => Err(BrokerSessionSecurityError::filesystem("opposite-role secret name", "inspect")),
            };
            if result.is_err() { self.result = Some(result); return; }
        }
        self.result = Some(Ok(()));
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for result in &self.native {
            if let Some(Err(cause)) = result.result() {
                if *cause != rustix::io::Errno::NOENT { return Some(cause); }
            }
        }
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
    }

    pub(super) fn completed(&self) -> bool { matches!(self.result, Some(Ok(()))) }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).cloned()
    }
}

pub(super) struct SecretReadBytesV1(pub(super) Box<Zeroizing<[u8; SECRET_BYTES]>>);

impl AsRef<[u8]> for SecretReadBytesV1 {
    fn as_ref(&self) -> &[u8] { &self.0[..] }
}

impl AsMut<[u8]> for SecretReadBytesV1 {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.0[..] }
}

pub(super) fn new_secret_bytes() -> SecretReadBytesV1 {
    SecretReadBytesV1(Box::new(Zeroizing::new([0; SECRET_BYTES])))
}

pub(super) fn new_manifest_bytes() -> [u8; BROKER_SESSION_MANIFEST_BYTES] {
    [0; BROKER_SESSION_MANIFEST_BYTES]
}

// The fixed manifest uses its original inline arrays. A secret enters its
// final zeroizing heap allocation directly, including on a partial read.
pub(super) struct FileContentsOriginalsV1<Bytes> {
    pub(super) before: MetadataOriginalsV1,
    pub(super) exact: Option<Bytes>,
    first_read: EndpointNativeReadOriginalV1,
    between: Option<Result<(), BrokerSessionSecurityError>>,
    pub(super) repeated: Option<Bytes>,
    second_read: EndpointNativeReadOriginalV1,
    after: MetadataOriginalsV1,
    compared: Option<Result<(), BrokerSessionSecurityError>>,
    label: &'static str,
}

impl<Bytes: AsRef<[u8]> + AsMut<[u8]>> FileContentsOriginalsV1<Bytes> {
    pub(super) const fn new() -> Self {
        Self {
            before: MetadataOriginalsV1::new(), exact: None, first_read: EndpointNativeReadOriginalV1::new(),
            between: None, repeated: None, second_read: EndpointNativeReadOriginalV1::new(),
            after: MetadataOriginalsV1::new(), compared: None, label: "unentered file",
        }
    }

    pub(super) fn observe_once(
        &mut self, descriptor: &EndpointNativeFileV1, owner: u32, size: usize, label: &'static str,
        new_bytes: fn() -> Bytes, between_reads: impl FnOnce() -> Result<(), BrokerSessionSecurityError>,
    ) {
        if self.before.native.entered() { return; }
        self.label = label;
        self.before.child_once(descriptor, owner, size, label);
        if self.before.snapshot().is_none() { return; }

        self.exact = Some(new_bytes());
        let Some(exact) = self.exact.as_mut() else { std::process::abort() };
        self.first_read.read_once(descriptor, exact.as_mut());
        if !matches!(self.first_read.result(), Some(Ok(()))) { return; }
        self.between = Some(between_reads());
        if !matches!(self.between, Some(Ok(()))) { return; }

        self.repeated = Some(new_bytes());
        let Some(repeated) = self.repeated.as_mut() else { std::process::abort() };
        self.second_read.read_once(descriptor, repeated.as_mut());
        if !matches!(self.second_read.result(), Some(Ok(()))) { return; }
        self.after.child_once(descriptor, owner, size, label);
        if self.after.snapshot().is_none() { return; }
        self.compared = Some(if self.before.snapshot() == self.after.snapshot()
            && self.exact.as_ref().map(AsRef::as_ref) == self.repeated.as_ref().map(AsRef::as_ref)
        {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::CurrentnessObservation {
                observation: "file read comparison",
            })
        });
    }

    pub(super) fn completed(&self) -> bool { matches!(self.compared, Some(Ok(()))) }

    pub(super) fn exact(&self) -> Option<&[u8]> {
        self.exact.as_ref().map(AsRef::as_ref)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure()
            .or_else(|| self.first_read.result().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.between.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.second_read.result().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.after.failure())
            .or_else(|| self.compared.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
    }

    pub(super) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        let read_failure = |slot: &EndpointNativeReadOriginalV1| {
            slot.result().and_then(|result| result.as_ref().err())
                .map(|error| exact_read_error(error.legacy_classification(), self.label))
        };
        self.before.classified_failure()
            .or_else(|| read_failure(&self.first_read))
            .or_else(|| self.between.as_ref().and_then(|result| result.as_ref().err()).cloned())
            .or_else(|| read_failure(&self.second_read))
            .or_else(|| self.after.classified_failure())
            .or_else(|| self.compared.as_ref().and_then(|result| result.as_ref().err()).cloned())
    }
}

impl<Bytes> Drop for FileContentsOriginalsV1<Bytes> {
    fn drop(&mut self) {
        // Ordinary file-local reads historically dropped the repeated buffer
        // before the first; both secret allocations remain zeroizing.
        drop(self.repeated.take());
        drop(self.exact.take());
    }
}
