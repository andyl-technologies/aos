//! Owns native protected endpoint descriptors without exposing raw handles.
//!
//! The existing endpoint loader and currentness recipe delegate their native
//! operations here. This owner has no manifest decoder, signing material,
//! role admission, currentness verdict, account, or payment authority. The
//! semantic owner retains every read buffer and comparison; the actual lower
//! owning destinations retain each whole native result and descriptor.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use crate::controller_receiving::{
    ControllerInitialBrokerSessionRoleV1, ControllerReceivingOriginalV1,
};

use aos_sandbox_linux::protected_file::{self, ExactReadFailure};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, Stat};

/// Owns one actual protected endpoint descriptor with no raw-handle escape.
///
/// Its mechanical operations preserve the loader's existing open, metadata,
/// lock and positioned-read sequence. In particular, constructing this owner
/// neither authenticates an endpoint nor permits a signing operation.
#[doc(hidden)]
pub struct EndpointNativeFileV1 {
    descriptor: EndpointDescriptorOwnerV1,
    origin: Option<Arc<EndpointNativeSelectedOriginV1>>,
    child_name: Option<&'static str>,
    depth: usize,
}

enum EndpointDescriptorOwnerV1 {
    Ordinary(OwnedFd),
    Selected(Arc<SelectedEndpointDescriptorV1>),
}

// Only the actual same-C once-role receiver creates this association. Weak
// ownership avoids a cycle if C later retains the same physical file capsule.
pub(crate) struct EndpointNativeSelectedOriginV1 {
    original: Weak<ControllerReceivingOriginalV1>,
    role: ControllerInitialBrokerSessionRoleV1,
    resident_files: AtomicUsize,
}

// Descriptor drops before its census guard, so the decrement proves actual
// native close rather than loss of one alias. Sharing never installs a new FD.
struct SelectedEndpointDescriptorV1 {
    descriptor: OwnedFd,
    _census: SelectedEndpointDescriptorCensusV1,
}

struct SelectedEndpointDescriptorCensusV1 {
    origin: Arc<EndpointNativeSelectedOriginV1>,
}

impl SelectedEndpointDescriptorCensusV1 {
    fn enter(origin: &Arc<EndpointNativeSelectedOriginV1>) -> Self {
        // Register before native open, so an in-flight operation cannot be
        // mistaken for completed quiescence by the owning handoff.
        origin.resident_files.fetch_add(1, Ordering::AcqRel);
        Self { origin: Arc::clone(origin) }
    }
}

impl Drop for SelectedEndpointDescriptorCensusV1 {
    fn drop(&mut self) {
        self.origin.resident_files.fetch_sub(1, Ordering::AcqRel);
    }
}

impl EndpointNativeSelectedOriginV1 {
    pub(crate) fn new(
        original: &Arc<ControllerReceivingOriginalV1>,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> Arc<Self> {
        Arc::new(Self {
            original: Arc::downgrade(original),
            role,
            resident_files: AtomicUsize::new(0),
        })
    }
}


impl EndpointNativeFileV1 {
    /// Opens the existing no-follow, close-on-exec readonly directory recipe.
    ///
    /// # Errors
    /// Returns the original native open error without classification.
    pub fn open_directory(path: &Path) -> rustix::io::Result<Self> {
        Self::open_directory_descriptor(path).map(|descriptor| Self {
            descriptor: EndpointDescriptorOwnerV1::Ordinary(descriptor),
            origin: None,
            child_name: None,
            depth: 0,
        })
    }

    fn open_directory_descriptor(path: &Path) -> rustix::io::Result<OwnedFd> {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    fn native(&self) -> &OwnedFd {
        match &self.descriptor {
            EndpointDescriptorOwnerV1::Ordinary(descriptor) => descriptor,
            EndpointDescriptorOwnerV1::Selected(descriptor) => &descriptor.descriptor,
        }
    }

    fn selected(
        descriptor: OwnedFd,
        census: SelectedEndpointDescriptorCensusV1,
        child_name: Option<&'static str>,
        depth: usize,
    ) -> Self {
        let origin = Arc::clone(&census.origin);
        let descriptor = Arc::new(SelectedEndpointDescriptorV1 { descriptor, _census: census });
        Self {
            descriptor: EndpointDescriptorOwnerV1::Selected(descriptor),
            origin: Some(origin),
            child_name,
            depth,
        }
    }

    fn clone_selected(&self, expected: &Arc<EndpointNativeSelectedOriginV1>) -> Option<Self> {
        let origin = self.origin.as_ref()?;
        if !Arc::ptr_eq(origin, expected) { return None; }
        match &self.descriptor {
            EndpointDescriptorOwnerV1::Selected(descriptor) => Some(Self {
                descriptor: EndpointDescriptorOwnerV1::Selected(Arc::clone(descriptor)),
                origin: Some(Arc::clone(origin)),
                child_name: self.child_name,
                depth: self.depth,
            }),
            EndpointDescriptorOwnerV1::Ordinary(_) => None,
        }
    }

    /// Supplies shared descriptor backing and construction bytes before growth.
    pub const fn selected_descriptor_heap_bytes_v1() -> usize {
        2 * std::mem::size_of::<SelectedEndpointDescriptorV1>()
            + 2 * std::mem::size_of::<usize>()
    }

    /// Supplies actual selected origin allocation and construction bytes.
    ///
    /// This is passive layout DATA; it grants no role, capture or disposal.
    pub const fn selected_origin_heap_bytes_v1() -> usize {
        2 * std::mem::size_of::<EndpointNativeSelectedOriginV1>()
            + 2 * std::mem::size_of::<usize>()
    }

    fn open_selected_directory(origin: &Arc<EndpointNativeSelectedOriginV1>)
        -> rustix::io::Result<Self>
    {
        let census = SelectedEndpointDescriptorCensusV1::enter(origin);
        let descriptor = Self::open_directory_descriptor(Path::new(origin.role.endpoint_custody_path_v1()))?;
        Ok(Self::selected(descriptor, census, None, 0))
    }

    fn reopen_corresponding_directory(&self, ordinary_path: &Path)
        -> rustix::io::Result<Self>
    {
        match &self.origin {
            Some(origin) => Self::open_selected_directory(origin),
            None => Self::open_directory(ordinary_path),
        }
    }

    /// Opens a no-follow readonly child through this actual directory.
    ///
    /// # Errors
    /// Returns the same bounded-name validation or native open error.
    pub fn open_nofollow_child(&self, name: &'static str) -> rustix::io::Result<Self> {
        let census = self.origin.as_ref().map(SelectedEndpointDescriptorCensusV1::enter);
        let descriptor = protected_file::open_nofollow_child(self.native(), name)?;
        Ok(match census {
            Some(census) => Self::selected(descriptor, census, Some(name), self.depth.saturating_add(1)),
            None => Self {
                descriptor: EndpointDescriptorOwnerV1::Ordinary(descriptor),
                origin: None,
                child_name: Some(name),
                depth: self.depth.saturating_add(1),
            },
        })
    }

    /// Observes metadata of this same held descriptor.
    ///
    /// # Errors
    /// Returns the original native descriptor-metadata error.
    pub fn metadata(&self) -> rustix::io::Result<Stat> {
        rustix::fs::fstat(self.native())
    }

    /// Observes a fixed child name without following its final symlink.
    ///
    /// # Errors
    /// Returns the original native name-metadata error, including absence.
    pub fn metadata_nofollow_child(&self, name: &'static str) -> rustix::io::Result<Stat> {
        rustix::fs::statat(self.native(), name, AtFlags::SYMLINK_NOFOLLOW)
    }

    /// Acquires the existing nonblocking exclusive manifest lock.
    ///
    /// # Errors
    /// Returns the original native lock error, including an existing holder.
    pub fn lock_exclusive_nonblocking(&self) -> rustix::io::Result<()> {
        rustix::fs::flock(self.native(), FlockOperation::NonBlockingLockExclusive)
    }

    /// Reads the exact bounded bytes into the caller's retained destination.
    ///
    /// No returned descriptor, stored seed accessor or signing operation is
    /// exposed. The caller retains its zeroizing destination even on refusal.
    ///
    /// # Errors
    /// Returns the same whole native exact-read failure and partial extent.
    pub fn read_exact_positioned_retaining_cause(
        &self,
        output: &mut [u8],
    ) -> Result<(), ExactReadFailure> {
        protected_file::read_exact_positioned_retaining_cause(self.native(), output)
    }
}

/// Retains one native endpoint open result through its caller's disposition.
///
/// This owner never classifies errors or authenticates a role. Successful
/// transfer moves the same descriptor; failed or absent results remain in
/// their original slot. No raw descriptor constructor or getter is provided.
#[doc(hidden)]
#[repr(transparent)]
pub struct EndpointNativeFileOpenOriginalV1 {
    native: Option<rustix::io::Result<EndpointNativeFileV1>>,
}

impl EndpointNativeFileOpenOriginalV1 {
    /// Creates an inert native result destination.
    pub const fn new() -> Self {
        Self { native: None }
    }

    /// Parks the actual directory open before any upper classification.
    pub fn directory_once(&mut self, path: &Path) {
        if self.native.is_none() {
            self.native = Some(EndpointNativeFileV1::open_directory(path));
        }
    }

    pub(crate) fn selected_directory_once(&mut self, origin: &Arc<EndpointNativeSelectedOriginV1>) {
        if self.native.is_none() {
            self.native = Some(EndpointNativeFileV1::open_selected_directory(origin));
        }
    }

    /// Reopens the same selected fixed directory or the existing ordinary path.
    ///
    /// Selected provenance is inherited from the actual held directory; a
    /// caller path cannot redirect that selected reopening.
    pub fn corresponding_directory_once(&mut self, held: &EndpointNativeFileV1, ordinary_path: &Path) {
        if self.native.is_none() {
            self.native = Some(held.reopen_corresponding_directory(ordinary_path));
        }
    }

    /// Parks the actual child open before any upper classification.
    pub fn child_once(&mut self, directory: &EndpointNativeFileV1, name: &'static str) {
        if self.native.is_none() {
            self.native = Some(directory.open_nofollow_child(name));
        }
    }

    /// Reports whether the original native operation has entered.
    pub const fn entered(&self) -> bool {
        self.native.is_some()
    }

    /// Borrows the whole native result without exposing a raw handle.
    pub fn result(&self) -> Option<&rustix::io::Result<EndpointNativeFileV1>> {
        self.native.as_ref()
    }

    /// Borrows this original's actual opaque successful descriptor owner.
    pub fn descriptor(&self) -> Option<&EndpointNativeFileV1> {
        self.native.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Moves the same successful descriptor and preserves a failed result.
    pub fn take_descriptor(&mut self) -> Option<EndpointNativeFileV1> {
        match self.native.take() {
            Some(Ok(descriptor)) => Some(descriptor),
            other => {
                self.native = other;
                None
            }
        }
    }

    /// Borrows the original native error at its stable owning destination.
    pub fn failure(&self) -> Option<&rustix::io::Errno> {
        self.native.as_ref().and_then(|result| result.as_ref().err())
    }
}

/// Owns the whole native metadata result of one held or fixed-name probe.
#[doc(hidden)]
#[repr(transparent)]
pub struct EndpointNativeMetadataOriginalV1 {
    native: Option<rustix::io::Result<Stat>>,
}

impl EndpointNativeMetadataOriginalV1 {
    /// Creates an inert result destination.
    pub const fn new() -> Self {
        Self { native: None }
    }

    /// Parks one actual held-descriptor metadata observation.
    pub fn held_once(&mut self, file: &EndpointNativeFileV1) {
        if self.native.is_none() {
            self.native = Some(file.metadata());
        }
    }

    /// Parks one actual fixed-name observation without following a symlink.
    pub fn child_once(&mut self, directory: &EndpointNativeFileV1, name: &'static str) {
        if self.native.is_none() {
            self.native = Some(directory.metadata_nofollow_child(name));
        }
    }

    /// Reports whether the native operation has entered.
    pub const fn entered(&self) -> bool {
        self.native.is_some()
    }

    /// Borrows the original complete native result.
    pub fn result(&self) -> Option<&rustix::io::Result<Stat>> {
        self.native.as_ref()
    }
}

/// Owns the complete native exact-read result beside its caller's byte owner.
///
/// The destination slice remains in Security's original zeroizing allocation.
/// This lower owner retains the original read or trailing-byte failure.
#[doc(hidden)]
#[repr(transparent)]
pub struct EndpointNativeReadOriginalV1 {
    native: Option<Result<(), ExactReadFailure>>,
}

impl EndpointNativeReadOriginalV1 {
    /// Creates an inert exact-read result destination.
    pub const fn new() -> Self {
        Self { native: None }
    }

    /// Reads once into the actual caller-owned bounded destination.
    pub fn read_once(&mut self, file: &EndpointNativeFileV1, output: &mut [u8]) {
        if self.native.is_none() {
            self.native = Some(file.read_exact_positioned_retaining_cause(output));
        }
    }

    /// Borrows the whole original native read result.
    pub fn result(&self) -> Option<&Result<(), ExactReadFailure>> {
        self.native.as_ref()
    }
}

/// Owns the original native nonblocking manifest-lock result.
#[doc(hidden)]
#[repr(transparent)]
pub struct EndpointNativeLockOriginalV1 {
    native: Option<rustix::io::Result<()>>,
}

impl EndpointNativeLockOriginalV1 {
    /// Creates an inert lock-result destination.
    pub const fn new() -> Self {
        Self { native: None }
    }

    /// Parks the actual same-file nonblocking lock result once.
    pub fn lock_once(&mut self, file: &EndpointNativeFileV1) {
        if self.native.is_none() {
            self.native = Some(file.lock_exclusive_nonblocking());
        }
    }

    /// Borrows the whole original native lock result.
    pub fn result(&self) -> Option<&rustix::io::Result<()>> {
        self.native.as_ref()
    }
}

/// Owns the actual initial-role self guard without exposing its descriptors.
///
/// Only the genuine paid once-role receiver constructs this owner. Required
/// roles share the same C's first captured guard; every comparison still uses
/// a distinct fresh native observation and its unchanged baseline predicates.
#[doc(hidden)]
pub struct ControllerEndpointExecutionOriginalV1 {
    guard: Arc<aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard>,
    original: Weak<ControllerReceivingOriginalV1>,
    role: ControllerInitialBrokerSessionRoleV1,
    freshly_captured: bool,
}

impl ControllerEndpointExecutionOriginalV1 {
    pub(crate) fn from_shared_v1(
        guard: Arc<aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard>,
        original: &Arc<ControllerReceivingOriginalV1>,
        role: ControllerInitialBrokerSessionRoleV1,
        freshly_captured: bool,
    ) -> Self { Self { guard, original: Arc::downgrade(original), role, freshly_captured } }

    pub(crate) fn share_v1(&self) -> Self {
        Self { guard: Arc::clone(&self.guard), original: self.original.clone(),
            role: self.role, freshly_captured: self.freshly_captured }
    }

    fn has_original_v1(&self, original: &Arc<ControllerReceivingOriginalV1>,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> bool {
        self.role == role && Weak::ptr_eq(&self.original, &Arc::downgrade(original))
    }

    /// Completes this role's fresh entry sandwich through the same native engine.
    ///
    /// The first actual capture already performed its baseline sandwich at
    /// this frontier. A reused guard instead validates fresh native facts into
    /// this role's own destination before any endpoint files are acquired.
    ///
    /// # Errors
    /// Retains incomplete/repeated observation or the original native refusal.
    pub fn observe_role_entry_v1(&self,
        destination: &mut aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    ) -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError> {
        if self.freshly_captured { Ok(()) }
        else { self.guard.validate_current_retaining(destination) }
    }

    /// Returns the same actual captured process ID as comparison DATA.
    pub fn captured_process_id_v1(&self) -> u32 { self.guard.captured_process_id_v1() }

    /// Returns the same actual captured boot ID as comparison DATA.
    pub fn boot_id(&self) -> [u8; 16] { self.guard.boot_id() }

    /// Reports only the actual completed guard's surviving native anchors.
    pub fn selected_retained_open_file_count_v1(&self) -> Option<usize> {
        self.guard.selected_retained_open_file_count_v1()
    }

    /// Observes fresh boot, process, credentials, stat and liveness by the same guard.
    ///
    /// # Errors
    /// Returns the existing native execution comparison refusal.
    pub fn validate_current(&self)
        -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError>
    { self.guard.validate_current() }

    /// Retains the same fresh native observation in the caller's own destination.
    ///
    /// # Errors
    /// Refuses incomplete/repeated observations or any original native predicate.
    pub fn validate_current_retaining(&self,
        destination: &mut aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    ) -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError> {
        self.guard.validate_current_retaining(destination)
    }
}

/// Retains the same first capture error or a closed original-entry refusal.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum ControllerEndpointExecutionCaptureErrorV1 {
    /// Refuses unentered, foreign, repeated or already failed original entry.
    Unavailable,
    /// Keeps the actual first native capture owner shared without cloning its cause.
    Native(Arc<aos_sandbox_linux::self_execution::RetainedSelfExecutionCaptureError>),
}

impl std::fmt::Display for ControllerEndpointExecutionCaptureErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("original endpoint execution capture is closed"),
            Self::Native(cause) => std::fmt::Display::fmt(cause.as_ref(), formatter),
        }
    }
}

impl std::error::Error for ControllerEndpointExecutionCaptureErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Native(cause) => Some(cause.as_ref()), Self::Unavailable => None }
    }
}

/// Owns the real selected endpoint anchors after native temporary disposition.
///
/// Only the genuine same-C role receiver constructs this aggregate from its
/// private directory provenance and actual Linux execution guard. Security
/// retains manifest/seed DATA and authentication; this is native custody only.
#[doc(hidden)]
pub struct ControllerEndpointNativeCustodyV1 {
    files: [Option<EndpointNativeFileV1>; 4],
    execution: ControllerEndpointExecutionOriginalV1,
    post: aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    // Native anchors close before the final same-original funding reference.
    _original: Arc<ControllerReceivingOriginalV1>,
}

struct ControllerEndpointNativePartialV1 {
    files: [Option<EndpointNativeFileV1>; 4],
    execution: Option<ControllerEndpointExecutionOriginalV1>,
    post: Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
    _original: Arc<ControllerReceivingOriginalV1>,
}

impl ControllerEndpointNativeCustodyV1 {
    /// Returns the boot identity of the same actual held execution guard.
    pub fn boot_id(&self) -> [u8; 16] {
        self.execution.boot_id()
    }

    /// Observes the same held guard through the existing ordinary adapter.
    ///
    /// # Errors
    /// Returns the existing native execution comparison refusal.
    pub fn validate_current(&self) -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError> {
        self.execution.validate_current()
    }

    /// Observes the same guard into the caller's actual retained destination.
    ///
    /// # Errors
    /// Returns the existing native execution comparison refusal.
    pub fn validate_current_retaining(
        &self,
        destination: &mut aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    ) -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError> {
        self.execution.validate_current_retaining(destination)
    }

    /// Compares actual shared execution custody without native IO or new authority.
    #[must_use]
    pub fn shares_execution_original_v1(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.execution.guard, &other.execution.guard)
    }

    /// Counts the actual surviving descriptors in this native owning aggregate.
    pub fn retained_open_file_count_v1(&self) -> Option<usize> {
        if self.files.iter().any(Option::is_none)
            || !self.post.completed_positive_native_disposition_v1()
        { return None; }
        let origin = self.files.first()?.as_ref()?.origin.as_ref()?;
        // Aliases share these four actual OFDs. A later fresh native probe
        // increments the same census before open and closes before decrement.
        if origin.resident_files.load(Ordering::Acquire) != 4 { return None; }
        4usize.checked_add(self.execution.selected_retained_open_file_count_v1()?)
    }
}

/// Retains the native owning handoff, including every refused partial input.
#[doc(hidden)]
pub struct ControllerEndpointNativeCustodyCaptureV1 {
    original: Option<ControllerEndpointNativePartialV1>,
    completed: Option<Arc<ControllerEndpointNativeCustodyV1>>,
    returned: Option<Result<(), crate::controller_receiving::ControllerReceivingErrorV1>>,
    reentry: Option<crate::controller_receiving::ControllerReceivingErrorV1>,
}

impl ControllerEndpointNativeCustodyCaptureV1 {
    /// Creates an inert owning destination before the enclosing capture enters.
    pub const fn new() -> Self {
        Self { original: None, completed: None, returned: None, reentry: None }
    }

    /// Supplies the actual aggregate allocation/construction overlap as DATA.
    pub const fn receiving_heap_bytes_v1() -> usize {
        2 * std::mem::size_of::<ControllerEndpointNativeCustodyV1>()
            + 2 * std::mem::size_of::<usize>()
            + 2 * std::mem::size_of::<aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard>()
            + 2 * std::mem::size_of::<aos_sandbox_linux::self_execution::RetainedSelfExecutionCaptureError>()
            + 4 * std::mem::size_of::<usize>()
    }

    pub(crate) fn capture_once(
        &mut self,
        execution: &mut Option<ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
        files: [&EndpointNativeFileV1; 4],
        expected: &Arc<EndpointNativeSelectedOriginV1>,
        original: &Arc<ControllerReceivingOriginalV1>,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), crate::controller_receiving::ControllerReceivingErrorV1> {
        use crate::controller_receiving::ControllerReceivingErrorV1 as Error;
        if self.returned.is_some() {
            self.reentry.get_or_insert(Error::Conflict);
            return Err(Error::Conflict);
        }
        self.original = Some(ControllerEndpointNativePartialV1 {
            files: [None, None, None, None],
            execution: execution.take(),
            post: post.take(),
            _original: Arc::clone(original),
        });
        self.returned = Some((|| {
            if expected.role != role || !Weak::ptr_eq(&expected.original, &Arc::downgrade(original)) {
                return Err(Error::Conflict);
            }
            if expected.resident_files.load(Ordering::Acquire) != 4
                || files[0].depth != 0 || files[0].child_name.is_some()
                || files[1].depth != 1 || files[1].child_name != Some("broker-session-manifest")
                || files[2].depth != 1 || files[2].child_name != Some("client-hello-signing-key")
                || files[3].depth != 1 || files[3].child_name != Some("client-record-signing-key")
            { return Err(Error::Conflict); }
            for index in 0..files.len() {
                for previous in &files[..index] {
                    match (&files[index].descriptor, &previous.descriptor) {
                        (EndpointDescriptorOwnerV1::Selected(left), EndpointDescriptorOwnerV1::Selected(right))
                            if !Arc::ptr_eq(left, right) => {}
                        _ => return Err(Error::Conflict),
                    }
                }
            }
            let custody = self.original.as_mut().ok_or(Error::Conflict)?;
            if !custody.post.as_ref().is_some_and(|post| post.completed_positive_native_disposition_v1()) {
                return Err(Error::Conflict);
            }
            let execution = custody.execution.as_ref().ok_or(Error::Conflict)?;
            if !execution.has_original_v1(original, role)
                || execution.captured_process_id_v1() != std::process::id()
                || execution.selected_retained_open_file_count_v1() != Some(2)
            { return Err(Error::Conflict); }
            for (destination, file) in custody.files.iter_mut().zip(files) {
                *destination = file.clone_selected(expected);
                if destination.is_none() { return Err(Error::Conflict); }
            }
            Ok(())
        })());
        if !matches!(self.returned, Some(Ok(()))) { return Err(Error::Conflict); }
        let Some(mut partial) = self.original.take() else { return Err(Error::Conflict); };
        let Some(execution) = partial.execution.take() else {
            self.original = Some(partial);
            self.returned = Some(Err(Error::Conflict));
            return Err(Error::Conflict);
        };
        let Some(post) = partial.post.take() else {
            partial.execution = Some(execution);
            self.original = Some(partial);
            self.returned = Some(Err(Error::Conflict));
            return Err(Error::Conflict);
        };
        self.completed = Some(Arc::new(ControllerEndpointNativeCustodyV1 {
            files: partial.files,
            execution,
            post,
            _original: partial._original,
        }));
        Ok(())
    }

    /// Borrows only a complete native owning handoff.
    pub fn completed(&self) -> Option<&Arc<ControllerEndpointNativeCustodyV1>> {
        if self.reentry.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.completed.as_ref()
    }

    /// Moves the same complete native aggregate without another descriptor.
    pub fn take_completed(&mut self) -> Option<Arc<ControllerEndpointNativeCustodyV1>> {
        self.completed()?;
        self.completed.take()
    }

    /// Borrows the actual retained native-association refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().and_then(|original| original.post.as_ref()?.failure())
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn selected_sharing_keeps_one_real_descriptor_until_last_owner_drops() {
        let directory = tempfile::tempdir().unwrap();
        // This fixture exercises native lifetime mechanics only. Its empty
        // Weak cannot pass the production same-C aggregate association.
        let origin = Arc::new(EndpointNativeSelectedOriginV1 {
            original: Weak::new(),
            role: ControllerInitialBrokerSessionRoleV1::Host,
            resident_files: AtomicUsize::new(0),
        });
        let census = SelectedEndpointDescriptorCensusV1::enter(&origin);
        let descriptor = EndpointNativeFileV1::open_directory_descriptor(directory.path()).unwrap();
        let first = EndpointNativeFileV1::selected(descriptor, census, None, 0);
        let identity = first.metadata().unwrap();
        let second = first.clone_selected(&origin).unwrap();

        assert_eq!(first.native().as_raw_fd(), second.native().as_raw_fd());
        assert_eq!(origin.resident_files.load(Ordering::Acquire), 1);
        drop(first);

        let still_held = second.metadata().unwrap();
        assert_eq!((still_held.st_dev, still_held.st_ino), (identity.st_dev, identity.st_ino));
        assert_eq!(origin.resident_files.load(Ordering::Acquire), 1);
        drop(second);
        assert_eq!(origin.resident_files.load(Ordering::Acquire), 0);
    }
}
