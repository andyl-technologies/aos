//! Retains Root's selected instruction, actual GC root and complete object checks.
//!
//! All paths come from the measured Root profile and the sole decoded manifest.
//! The same recurring R pays each closed stage before construction or IO. The
//! GC acknowledgement is available only after every object and the independent
//! final root/name checks succeed. None of these DATA models authorizes Source
//! publication without the actual accepted Root/Controller interval.

use std::collections::TryReserveError;
use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use aos_sandbox_broker::immutable_image::{
    ImmutableFileAcquisitionOriginalV1, ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1,
};
use aos_sandbox_model::{ObjectDescriptor, ObjectDigest, ResourceDimension as D, ResourceId, ResourceVector, Revision};
use aos_sandbox_journal::protected_storage::resolve_protected_directory_from_root_original;
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, openat, readlinkat};
use sha2::{Digest as _, Sha256};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::RootEnvironmentStageReceivingV1;
use super::super::{EnvironmentGcRootAcknowledgementV1, EnvironmentModelError};
use super::EnvironmentDeploymentTemplateV1;

pub(crate) const ENVIRONMENT_GC_ROOT_DIRECTORY: &str = "/nix/var/nix/gcroots";
pub(crate) const ENVIRONMENT_GC_ROOT_NAME: &str = "aos-selected-environment-v1";

#[derive(Debug, thiserror::Error)]
pub(crate) enum EnvironmentDeploymentErrorV1 {
    #[error("selected Environment deployment is absent, incomplete or no longer exact")]
    Closed,
    #[error("selected Environment receiving requirement cannot be represented")]
    Bounds,
    #[error("selected Environment native observation failed")]
    Native,
    #[error(transparent)]
    Model(#[from] EnvironmentModelError),
}

type Unit = Result<(), EnvironmentDeploymentErrorV1>;

/// Owns one real fixed GC-root probe; it cannot create or change a root.
#[derive(Default)]
struct GcRootReadbackV1 {
    ancestors: Vec<File>,
    directory: Option<Result<File, JournalError>>,
    directory_error: Option<rustix::io::Errno>,
    link: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<Stat, rustix::io::Errno>>,
    target: Option<Result<CString, rustix::io::Errno>>,
    binding: Option<Unit>,
    entered: bool,
}

impl GcRootReadbackV1 {
    fn capture_once(&mut self, package: &Path) -> Unit {
        if self.entered { return Err(EnvironmentDeploymentErrorV1::Closed); }
        self.entered = true;
        self.binding = Some(self.capture_inner(package));
        unit(&self.binding)
    }

    fn capture_inner(&mut self, package: &Path) -> Unit {
        self.directory = Some(resolve_protected_directory_from_root_original::<JournalError>(
            Path::new(ENVIRONMENT_GC_ROOT_DIRECTORY), 0,
            Some(&mut self.ancestors), Some(&mut self.directory_error),
        ));
        let directory = positive(&self.directory)?;
        // O_PATH|NOFOLLOW pins the link itself. Reading its empty relative name
        // never follows a replaced link or converts its target into authority.
        self.link = Some(openat(directory, ENVIRONMENT_GC_ROOT_NAME,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty()));
        let link = positive(&self.link)?;
        self.metadata = Some(fstat(link));
        let metadata = positive(&self.metadata)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Symlink
            || metadata.st_uid != 0 || metadata.st_gid != 0
        {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        self.target = Some(readlinkat(link, c"", Vec::new()));
        use std::os::unix::ffi::OsStrExt as _;
        if positive(&self.target)?.to_bytes() != package.as_os_str().as_bytes() {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        Ok(())
    }

    fn same_link(&self, original: &Self) -> bool {
        let Some(Ok(current)) = self.metadata.as_ref() else { return false; };
        let Some(Ok(before)) = original.metadata.as_ref() else { return false; };
        matches!(self.binding, Some(Ok(())))
            && matches!(original.binding, Some(Ok(())))
            && (current.st_dev, current.st_ino, current.st_size,
                current.st_mtime, current.st_mtime_nsec, current.st_ctime, current.st_ctime_nsec)
                == (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime, before.st_mtime_nsec, before.st_ctime, before.st_ctime_nsec)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.directory).or_else(|| failure(&self.link))
            .or_else(|| failure(&self.metadata)).or_else(|| failure(&self.target))
            .or_else(|| failure(&self.binding))
    }

    fn demand_v1() -> Option<ResourceVector> {
        let directories = Path::new(ENVIRONMENT_GC_ROOT_DIRECTORY).components().count();
        let files = directories.checked_add(1)?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(directories.checked_mul(size_of::<File>())?)?
            .checked_add(8192)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(directories.checked_add(1)?).ok()?))
    }
}

struct ObjectOriginalV1 {
    acquisition: ImmutableFileAcquisitionOriginalV1,
    returned: Option<Result<(), ImmutableImageErrorV1>>,
    after: ImmutableFileRevalidationOriginalV1,
    after_result: Option<Result<(), ImmutableImageErrorV1>>,
    claim_after: ImmutableFileRevalidationOriginalV1,
    claim_after_result: Option<Result<(), ImmutableImageErrorV1>>,
}

impl ObjectOriginalV1 {
    fn new() -> Self {
        Self { acquisition: ImmutableFileAcquisitionOriginalV1::new(), returned: None,
            after: ImmutableFileRevalidationOriginalV1::new(), after_result: None,
            claim_after: ImmutableFileRevalidationOriginalV1::new(), claim_after_result: None }
    }
}

#[derive(Clone, Copy)]
enum First {
    Root,
    Instruction,
    Read,
    Decode,
    Allocation,
    Object(usize),
    Acknowledgement,
}

/// Keeps the selected package and every reached failed native prefix resident.
pub(crate) struct RootEnvironmentDeploymentOriginalV1 {
    package: PathBuf,
    instruction_digest: [u8; 32],
    root_before: GcRootReadbackV1,
    root_after: GcRootReadbackV1,
    root_claim_after: GcRootReadbackV1,
    instruction: ImmutableFileAcquisitionOriginalV1,
    instruction_result: Option<Result<(), ImmutableImageErrorV1>>,
    reader: FixedRoleCredentialReadV1,
    decoded: Option<Result<EnvironmentDeploymentTemplateV1, EnvironmentModelError>>,
    allocation: Option<Result<(), TryReserveError>>,
    descriptors: Vec<ObjectDescriptor>,
    objects: Vec<ObjectOriginalV1>,
    acknowledgements: Vec<EnvironmentGcRootAcknowledgementV1>,
    next: usize,
    entered: bool,
    closure_prepared: bool,
    after_entered: bool,
    root_comparison: Option<Unit>,
    finished: Option<Unit>,
    instruction_after: ImmutableFileRevalidationOriginalV1,
    instruction_after_result: Option<Result<(), ImmutableImageErrorV1>>,
    instruction_claim_after: ImmutableFileRevalidationOriginalV1,
    instruction_claim_after_result: Option<Result<(), ImmutableImageErrorV1>>,
    claim_root_comparison: Option<Unit>,
    claim_after_entered: bool,
    first: Option<First>,
    primary: Option<Unit>,
}

impl RootEnvironmentDeploymentOriginalV1 {
    /// Pays the real fixed destination before cloning paths or constructing it.
    pub(crate) fn begin_once_v1(receiving: &mut RootEnvironmentStageReceivingV1<'_, '_>)
        -> Result<Self, EnvironmentDeploymentErrorV1>
    {
        let pin = receiving.environment_provision_data_v1().ok_or(EnvironmentDeploymentErrorV1::Closed)?;
        let locator = pin.instruction.path.len();
        let own = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pin.root.len().checked_mul(2)?))
            .ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, own as u64).with(D::OpenFiles, 1);
        let demand = add(fixed, ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(locator))?;
        let demand = add(demand, ImmutableFileRevalidationOriginalV1::receiving_demand_v1())?;
        let demand = add(demand, ImmutableFileRevalidationOriginalV1::receiving_demand_v1())?;
        let demand = add(add(add(demand, GcRootReadbackV1::demand_v1())?,
            GcRootReadbackV1::demand_v1())?, GcRootReadbackV1::demand_v1())?;
        receiving.admit_environment_artifact_fixed_once_v1(RootContinuationDemandV1::from_demand_v1(demand))
            .map_err(|_| EnvironmentDeploymentErrorV1::Closed)?;
        let pin = receiving.environment_provision_data_v1().ok_or(EnvironmentDeploymentErrorV1::Closed)?;
        Ok(Self {
            package: PathBuf::from(&pin.root), instruction_digest: pin.instruction.sha256,
            root_before: GcRootReadbackV1::default(), root_after: GcRootReadbackV1::default(),
            root_claim_after: GcRootReadbackV1::default(),
            instruction: ImmutableFileAcquisitionOriginalV1::new(), instruction_result: None,
            reader: FixedRoleCredentialReadV1::prearmed(), decoded: None, allocation: None,
            descriptors: Vec::new(), objects: Vec::new(), acknowledgements: Vec::new(),
            next: 0, entered: false,
            closure_prepared: false, after_entered: false, root_comparison: None, finished: None,
            instruction_after: ImmutableFileRevalidationOriginalV1::new(),
            instruction_after_result: None, instruction_claim_after: ImmutableFileRevalidationOriginalV1::new(),
            instruction_claim_after_result: None, claim_root_comparison: None,
            claim_after_entered: false, first: None, primary: None,
        })
    }

    pub(crate) fn capture_instruction_once_v1(&mut self,
        receiving: &mut RootEnvironmentStageReceivingV1<'_, '_>) -> Unit
    {
        if self.entered || self.first.is_some() { return Err(EnvironmentDeploymentErrorV1::Closed); }
        self.entered = true;
        self.primary = Some(self.capture_instruction_inner(receiving));
        unit(&self.primary)
    }

    fn capture_instruction_inner(&mut self, receiving: &mut RootEnvironmentStageReceivingV1<'_, '_>) -> Unit {
        self.first = Some(First::Root);
        self.root_before.capture_once(&self.package)?;
        self.first = Some(First::Instruction);
        self.instruction_result = Some(self.instruction.open_and_measure_once(
            self.package.join("instruction-v1"), Some(self.instruction_digest),
            (super::super::format::MAXIMUM_RECORD_BYTES + 16) as u64, false,
        ));
        positive(&self.instruction_result)?;
        let measurement = self.instruction.completed_measurement().ok_or(EnvironmentDeploymentErrorV1::Closed)?;
        let length = usize::try_from(measurement.physical_identity().2)
            .map_err(|_| EnvironmentDeploymentErrorV1::Bounds)?;
        let models = instruction_model_bytes_v1(length).ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        receiving.admit_environment_artifact_native_once_v1(RootContinuationDemandV1::from_demand_v1(
            ResourceVector::ZERO.with(D::MemoryBytes, models),
        )).map_err(|_| EnvironmentDeploymentErrorV1::Closed)?;
        self.first = Some(First::Read);
        self.reader.read_exact_at_once(measurement.original_descriptor_v1(), length);
        let bytes = match self.reader.outcome() {
            Some(Ok(Some(bytes))) => bytes,
            _ => return Err(EnvironmentDeploymentErrorV1::Native),
        };
        self.first = Some(First::Decode);
        self.decoded = Some(EnvironmentDeploymentTemplateV1::decode(bytes));
        positive(&self.decoded)?;
        self.first = None;
        Ok(())
    }

    /// Pays the exact typed closure count before its destinations or paths grow.
    pub(crate) fn prepare_closure_once_v1(&mut self, receiving: &mut RootEnvironmentStageReceivingV1<'_, '_>) -> Unit {
        if self.closure_prepared || self.first.is_some() || !matches!(self.primary, Some(Ok(()))) {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        // Set the guard before any checked geometry or financial refusal.
        self.closure_prepared = true;
        self.primary = Some(self.prepare_closure_inner(receiving));
        unit(&self.primary)
    }

    fn prepare_closure_inner(&mut self, receiving: &mut RootEnvironmentStageReceivingV1<'_, '_>) -> Unit {
        let template = positive(&self.decoded)?;
        let manifest = template.template_v1();
        // The immutable package owns runtime closure AND declared build inputs.
        // A flake source descriptor is never substituted by sandbox ancestry.
        let upper = manifest.environment().closure().len().checked_add(manifest.inputs().len())
            .and_then(|count| count.checked_add(2)).ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        let own = upper.checked_mul(size_of::<ObjectOriginalV1>()
            .checked_add(size_of::<ObjectDescriptor>()).ok_or(EnvironmentDeploymentErrorV1::Bounds)?)
            .and_then(|bytes| bytes.checked_add(manifest.environment().closure().len()
                .checked_mul(size_of::<EnvironmentGcRootAcknowledgementV1>())?))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        let strings = manifest.environment().closure().iter()
            .chain(manifest.inputs().iter().map(|input| input.descriptor()))
            .chain([manifest.facade().descriptor(), manifest.effective_policy()])
            .try_fold(0usize, |total, descriptor| total.checked_add(descriptor.media_type().as_str().len()))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        receiving.admit_environment_closure_fixed_once_v1(RootContinuationDemandV1::from_demand_v1(
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(own.checked_add(strings)
                .ok_or(EnvironmentDeploymentErrorV1::Bounds)?).map_err(|_| EnvironmentDeploymentErrorV1::Bounds)?),
        )).map_err(|_| EnvironmentDeploymentErrorV1::Closed)?;
        self.first = Some(First::Allocation);
        self.allocation = Some(self.descriptors.try_reserve_exact(upper));
        positive(&self.allocation)?;
        self.descriptors.extend(manifest.environment().closure().iter().cloned());
        self.descriptors.extend(manifest.inputs().iter().map(|input| input.descriptor().clone()));
        self.descriptors.extend([manifest.facade().descriptor().clone(), manifest.effective_policy().clone()]);
        self.descriptors.sort();
        self.descriptors.dedup();
        let count = self.descriptors.len();
        self.allocation = Some(self.objects.try_reserve_exact(count));
        positive(&self.allocation)?;
        self.allocation = Some(self.acknowledgements.try_reserve_exact(manifest.environment().closure().len()));
        positive(&self.allocation)?;
        let locator_bytes = self.package.as_os_str().len().checked_add("/objects/".len() + 64)
            .ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        let per_object = add(add(ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(locator_bytes)
            .ok_or(EnvironmentDeploymentErrorV1::Bounds)?, ImmutableFileRevalidationOriginalV1::receiving_demand_v1())?,
            ImmutableFileRevalidationOriginalV1::receiving_demand_v1())?;
        let instruction_bytes = self.instruction.completed_measurement()
            .ok_or(EnvironmentDeploymentErrorV1::Closed)?.physical_identity().2;
        let pinned = self.descriptors.iter().try_fold(instruction_bytes, |bytes, descriptor| {
            bytes.checked_add(descriptor.encoded_size())
        }).ok_or(EnvironmentDeploymentErrorV1::Bounds)?;
        // The fixed administrative root protects these exact package files.
        // Its actual correctness-pinned content remains inside SAME R's finite
        // declared peak; a native GC acknowledgement creates no spare capacity.
        let mut native = ResourceVector::ZERO.with(D::PinnedBytes, pinned);
        for descriptor in &self.descriptors {
            native = native.checked_add(per_object).map_err(|_| EnvironmentDeploymentErrorV1::Bounds)?;
            native = native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(descriptor.media_type().as_str().len()).map_err(|_| EnvironmentDeploymentErrorV1::Bounds)?))
                .map_err(|_| EnvironmentDeploymentErrorV1::Bounds)?;
        }
        receiving.admit_environment_closure_native_once_v1(RootContinuationDemandV1::from_demand_v1(native))
            .map_err(|_| EnvironmentDeploymentErrorV1::Closed)?;
        self.objects.extend((0..count).map(|_| ObjectOriginalV1::new()));
        self.first = None;
        Ok(())
    }

    /// Samples only the next actual manifest object; the outer clock gates IO.
    pub(crate) fn capture_next_object_once_v1(&mut self) -> Result<bool, EnvironmentDeploymentErrorV1> {
        if self.first.is_some() || !matches!(self.primary, Some(Ok(()))) {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        match self.capture_next_object_inner() {
            Ok(more) => Ok(more),
            Err(error) => {
                self.primary = Some(Err(error));
                Err(EnvironmentDeploymentErrorV1::Native)
            }
        }
    }

    fn capture_next_object_inner(&mut self) -> Result<bool, EnvironmentDeploymentErrorV1> {
        if !self.closure_prepared || self.after_entered || self.first.is_some()
            || !matches!(self.primary, Some(Ok(())))
        {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        let Some(descriptor) = self.descriptors.get(self.next) else { return Ok(false); };
        let index = self.next;
        self.first = Some(First::Object(index));
        let path = self.package.join("objects").join(digest_name(descriptor.digest()));
        let object = self.objects.get_mut(index).ok_or(EnvironmentDeploymentErrorV1::Closed)?;
        object.returned = Some(object.acquisition.open_and_measure_exact_data_once_v1(
            path, *descriptor.digest().as_bytes(), descriptor.encoded_size(),
        ));
        positive(&object.returned)?;
        self.next += 1;
        self.first = None;
        Ok(true)
    }

    /// Runs every already-paid available after probe, including on a primary error.
    pub(crate) fn finish_available_once_v1(&mut self) -> Unit {
        if self.after_entered { return Err(EnvironmentDeploymentErrorV1::Closed); }
        self.after_entered = true;
        self.finished = Some(self.finish_available_inner());
        unit(&self.finished)
    }

    fn finish_available_inner(&mut self) -> Unit {
        for object in &mut self.objects {
            object.after_result = object.acquisition.observe_available_held_once_v1(&mut object.after);
        }
        self.instruction_after_result = self.instruction.observe_available_held_once_v1(&mut self.instruction_after);
        let root_after = self.root_after.capture_once(&self.package);
        self.root_comparison = Some(root_after.and_then(|()| {
            if self.root_after.same_link(&self.root_before) { Ok(()) }
            else { Err(EnvironmentDeploymentErrorV1::Closed) }
        }));
        if self.failure().is_some() { return Err(EnvironmentDeploymentErrorV1::Native); }
        if !self.closure_prepared || self.next != self.objects.len() {
            return Err(EnvironmentDeploymentErrorV1::Closed);
        }
        // Acknowledgements describe the real GC root only after all its object
        // checks and independent native posts have completed. They are not a
        // substitute for the Root owner that must remain held across Source.
        self.first = Some(First::Acknowledgement);
        let manifest = positive(&self.decoded)?.template_v1();
        for descriptor in manifest.environment().closure() {
            let root_commitment: [u8; 32] = Sha256::new()
                .chain_update(b"aos.environment.installed-gc-root.v1\0")
                .chain_update(ENVIRONMENT_GC_ROOT_DIRECTORY.as_bytes())
                .chain_update(ENVIRONMENT_GC_ROOT_NAME.as_bytes())
                .chain_update(self.package.as_os_str().as_encoded_bytes())
                .chain_update(self.instruction_digest).finalize().into();
            let mut root_id = [0; 16];
            root_id.copy_from_slice(&root_commitment[..16]);
            let receipt = ObjectDigest::from_bytes(Sha256::new()
                .chain_update(b"aos.environment.installed-object-ack.v1\0")
                .chain_update(root_commitment).chain_update(descriptor.digest().as_bytes())
                .chain_update(descriptor.encoded_size().to_be_bytes())
                .chain_update(descriptor.media_type().as_str().as_bytes()).finalize().into());
            self.acknowledgements.push(EnvironmentGcRootAcknowledgementV1::new(
                manifest.generation(), descriptor.clone(), ResourceId::from_bytes(root_id), Revision::new(1), receipt,
            )?);
        }
        self.first = None;
        Ok(())
    }

    /// Finishes the independently prepaid held claim interval on either outcome.
    ///
    /// Root observes only native currentness and authenticated stream completion;
    /// this is never a Source lease-completion proof or a claim that Source NEXT
    /// stayed unchanged across the Controller's legitimate publication.
    pub(crate) fn finish_claim_after_once_v1(&mut self) -> Unit {
        if self.claim_after_entered { return Err(EnvironmentDeploymentErrorV1::Closed); }
        self.claim_after_entered = true;
        for object in &mut self.objects {
            object.claim_after_result = object.acquisition.observe_available_held_once_v1(&mut object.claim_after);
        }
        self.instruction_claim_after_result = self.instruction.observe_available_held_once_v1(&mut self.instruction_claim_after);
        self.claim_root_comparison = Some(self.root_claim_after.capture_once(&self.package).and_then(|()| {
            if self.root_claim_after.same_link(&self.root_before) { Ok(()) }
            else { Err(EnvironmentDeploymentErrorV1::Closed) }
        }));
        if self.failure().is_none() && matches!(self.finished, Some(Ok(()))) { Ok(()) }
        else { Err(EnvironmentDeploymentErrorV1::Native) }
    }

    /// Borrows the measured instruction after the complete object roster is paid.
    /// This precedes object acknowledgement and cannot issue a generation.
    pub(crate) fn prepared_template_v1(&self) -> Result<&EnvironmentDeploymentTemplateV1, EnvironmentModelError> {
        if !self.closure_prepared || self.failure().is_some() {
            return Err(EnvironmentModelError::InvalidModel);
        }
        self.decoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(EnvironmentModelError::InvalidModel)
    }

    pub(crate) fn completed_v1(&self) -> Option<(&EnvironmentDeploymentTemplateV1, &[EnvironmentGcRootAcknowledgementV1])> {
        if !matches!(self.finished, Some(Ok(()))) || self.failure().is_some()
            || self.next != self.descriptors.len()
            || self.decoded.as_ref().and_then(|value| value.as_ref().ok())
                .is_none_or(|template| self.acknowledgements.len() != template.template_v1().environment().closure().len())
        {
            return None;
        }
        Some((self.decoded.as_ref()?.as_ref().ok()?, &self.acknowledgements))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let primary = match self.first {
            Some(First::Root) => self.root_before.failure(),
            Some(First::Instruction) => self.instruction.failure(),
            Some(First::Read) => self.reader.failure(),
            Some(First::Decode) => failure(&self.decoded),
            Some(First::Allocation) => failure(&self.allocation),
            Some(First::Object(index)) => self.objects.get(index).and_then(|object| object.acquisition.failure()),
            Some(First::Acknowledgement) | None => None,
        };
        primary.or_else(|| failure(&self.primary))
            .or_else(|| self.objects.iter().find_map(|object| object.after.failure()
                .or_else(|| failure(&object.after_result))))
            .or_else(|| self.instruction_after.failure())
            .or_else(|| failure(&self.instruction_after_result))
            .or_else(|| self.root_after.failure())
            .or_else(|| failure(&self.root_comparison))
            .or_else(|| failure(&self.finished))
            .or_else(|| self.objects.iter().find_map(|object| object.claim_after.failure()
                .or_else(|| failure(&object.claim_after_result))))
            .or_else(|| self.instruction_claim_after.failure())
            .or_else(|| failure(&self.instruction_claim_after_result))
            .or_else(|| self.root_claim_after.failure())
            .or_else(|| failure(&self.claim_root_comparison))
    }
}

fn digest_name(digest: ObjectDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in digest.as_bytes() {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

fn instruction_model_bytes_v1(length: usize) -> Option<u64> {
    use aos_sandbox_model::{ObjectDescriptor, RelativePath, PathName};
    let atom = [size_of::<ObjectDescriptor>(), size_of::<RelativePath>(), size_of::<PathName>(),
        size_of::<aos_sandbox_model::model::EnvironmentEntry>(), size_of::<aos_sandbox_model::FeatureRef>()]
        .into_iter().max()?;
    // One currently announced collection can reserve before its body fails.
    // Completed collections have encoded heads; two model/encoding planes and
    // the exact positional-read byte destination coexist with the input.
    let announced = aos_sandbox_model::DecodeLimits::default().maximum_collection_items.min(length).checked_mul(atom)?;
    let bytes = length.checked_mul(atom)?.checked_mul(2)?.checked_add(announced)?
        .checked_add(length)?.checked_add(size_of::<EnvironmentDeploymentTemplateV1>().checked_mul(3)?)?;
    u64::try_from(bytes).ok()
}

fn add(value: ResourceVector, other: Option<ResourceVector>) -> Result<ResourceVector, EnvironmentDeploymentErrorV1> {
    value.checked_add(other.ok_or(EnvironmentDeploymentErrorV1::Bounds)?)
        .map_err(|_| EnvironmentDeploymentErrorV1::Bounds)
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, EnvironmentDeploymentErrorV1> {
    result.as_ref().and_then(|value| value.as_ref().ok()).ok_or(EnvironmentDeploymentErrorV1::Native)
}

fn unit(result: &Option<Unit>) -> Unit { positive(result).map(|()| ()) }

fn failure<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|error| error as &(dyn Error + 'static))
}
