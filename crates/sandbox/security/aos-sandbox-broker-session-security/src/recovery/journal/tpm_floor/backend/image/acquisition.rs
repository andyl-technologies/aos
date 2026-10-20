//! Retains the actual fixed Broker helper's two pin and image acquisitions.
//!
//! The same closed purpose recipe serves consuming and retained callers.
//! Actual physical admission parks this owner before the first pin metadata
//! observation. It cannot select another helper or construct a physical owner.

use std::error::Error;
use std::path::{Path, PathBuf};

use aos_sandbox_broker::immutable_image::{
    ImmutableFileAcquisitionOriginalV1, ImmutableImageErrorV1,
    ImmutableImagePinReadOriginalV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    FloorErrorV1, HelperImagePurposeV1, HelperImageRevalidationOriginalV1,
    MeasuredFileV1, MeasuredHelperImageV1,
};

pub(crate) struct HelperImageAcquisitionOriginalV1 {
    pub(super) path: Option<PathBuf>,
    pub(super) loader_path: Option<PathBuf>,
    pub(super) pins: [ImmutableImagePinReadOriginalV1; 2],
    pub(super) executable_digest: Option<Result<[u8; 32], FloorErrorV1>>,
    pub(super) loader_digest: Option<Result<[u8; 32], FloorErrorV1>>,
    pub(super) loader_text: Option<Result<(), std::str::Utf8Error>>,
    pub(super) files: [ImmutableFileAcquisitionOriginalV1; 2],
    pub(super) measurements: [Option<Result<(), ImmutableImageErrorV1>>; 2],
    pub(super) executable: Option<MeasuredFileV1>,
    pub(super) loader: Option<MeasuredFileV1>,
    pub(super) image: Option<MeasuredHelperImageV1>,
    pub(super) revalidation: HelperImageRevalidationOriginalV1,
    pub(super) revalidated: Option<Result<(), FloorErrorV1>>,
    returned: Option<Result<MeasuredHelperImageV1, FloorErrorV1>>,
    transfer: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    taken: bool,
    reentry: Option<FloorErrorV1>,
}

impl HelperImageAcquisitionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            path: None,
            loader_path: None,
            pins: std::array::from_fn(|_| ImmutableImagePinReadOriginalV1::new()),
            executable_digest: None,
            loader_digest: None,
            loader_text: None,
            files: std::array::from_fn(|_| ImmutableFileAcquisitionOriginalV1::new()),
            measurements: [None, None],
            executable: None,
            loader: None,
            image: None,
            revalidation: HelperImageRevalidationOriginalV1::new(),
            revalidated: None,
            returned: None,
            transfer: None,
            entered: false,
            taken: false,
            reentry: None,
        }
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), FloorErrorV1> {
        self.capture_purpose_once(HelperImagePurposeV1::Broker)
    }

    /// Captures only the compiled RuntimeDeployment helper and loader.
    pub(crate) fn capture_runtime_deployment_once(&mut self) -> Result<(), FloorErrorV1> {
        self.capture_purpose_once(HelperImagePurposeV1::RuntimeDeployment)
    }

    fn capture_purpose_once(&mut self, purpose: HelperImagePurposeV1) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Provisioning);
            return Err(FloorErrorV1::Provisioning);
        }
        self.entered = true;
        self.returned = Some(MeasuredHelperImageV1::open_purpose_recipe(
            purpose,
            &mut Some(&mut *self),
        ));
        match self.returned.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(*cause),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(crate) fn take_completed_once(&mut self) -> Option<MeasuredHelperImageV1> {
        if self.taken
            || self.reentry.is_some()
            || self.transfer.is_some()
            || !matches!(self.returned, Some(Ok(_)))
            || !self.revalidation.is_complete()
        {
            return None;
        }
        // The entire typed helper and both final comparisons succeeded. Only
        // these now-unused positive pin Files retire; raw bytes/native results
        // remain owned, and the actual measured files move into the carrier.
        let executable = self.pins[0].retire_completed_file_once_v1();
        let loader = self.pins[1].retire_completed_file_once_v1();
        self.transfer = Some(if executable && loader {
            Ok(())
        } else {
            Err(FloorErrorV1::Unavailable)
        });
        if !matches!(self.transfer, Some(Ok(()))) {
            return None;
        }
        match self.returned.take() {
            Some(Ok(image)) => {
                self.taken = true;
                Some(image)
            }
            original => {
                self.returned = original;
                None
            }
        }
    }

    /// Supplies the real fixed-purpose acquisition peak before construction.
    pub(crate) fn receiving_demand_v1() -> Option<ResourceVector> {
        Self::receiving_purpose_demand_v1(HelperImagePurposeV1::Broker)
    }

    pub(crate) fn runtime_deployment_receiving_demand_v1() -> Option<ResourceVector> {
        // The same acquisition engine measures each file twice and then
        // compares both once more. The two fixed pin reads include EOF bytes.
        let input = ImmutableFileAcquisitionOriginalV1::measurement_input_bytes_v1(
            super::MAXIMUM_IMAGE_BYTES,
        )?.checked_mul(2)?
            .checked_add(super::MAXIMUM_IMAGE_BYTES.checked_add(1)?.checked_mul(2)?)?
            .checked_add(65 + 1 + 578 + 1)?;
        Some(Self::receiving_purpose_demand_v1(HelperImagePurposeV1::RuntimeDeployment)?
            .with(D::OutputBytes, input))
    }

    fn receiving_purpose_demand_v1(purpose: HelperImagePurposeV1) -> Option<ResourceVector> {
        let path = purpose.compiled_path().ok()?;
        let pin = ImmutableImagePinReadOriginalV1::receiving_demand_v1(path.len(), 65)?;
        let loader_pin = ImmutableImagePinReadOriginalV1::receiving_demand_v1(path.len(), 578)?;
        let executable = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(path.len())?;
        let loader = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(512)?;
        // Nested owners conservatively remain in the two compiled copies as
        // well as their lower backing suppliers. No control-field metadata is
        // projected as resident namespace entries.
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(path.len().checked_mul(4)?)?
            .checked_add(512 * 4 + 65 + 578)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?);
        own.checked_add(pin).ok()?
            .checked_add(loader_pin).ok()?
            .checked_add(executable).ok()?
            .checked_add(loader).ok()?
            .checked_add(
                HelperImageRevalidationOriginalV1::receiving_demand_v1()?
                    .with(D::MetadataEntries, 0),
            ).ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.pins[0].failure()
            .or_else(|| error(&self.executable_digest))
            .or_else(|| self.pins[1].failure())
            .or_else(|| error(&self.loader_digest))
            .or_else(|| error(&self.loader_text))
            .or_else(|| self.files[0].failure())
            .or_else(|| error(&self.measurements[0]))
            .or_else(|| self.files[1].failure())
            .or_else(|| error(&self.measurements[1]))
            .or_else(|| self.revalidation.failure())
            .or_else(|| error(&self.revalidated))
            .or_else(|| error(&self.returned))
            .or_else(|| error(&self.transfer))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

pub(super) fn read_pin_once(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
    original: Option<&mut ImmutableImagePinReadOriginalV1>,
) -> Result<Vec<u8>, FloorErrorV1> {
    match original {
        None => super::read_pin(directory, name, minimum, maximum),
        Some(original) => {
            original.read_once(directory, name, minimum, maximum)?;
            // Keep the actual read's bytes before a later hash/loader refusal;
            // the ordinary parser receives only its bounded comparison copy.
            original.completed_bytes().map(<[u8]>::to_vec)
                .ok_or(FloorErrorV1::Provisioning)
        }
    }
}

pub(super) fn loader_text_once<'bytes>(
    bytes: &'bytes [u8],
    original: Option<&mut HelperImageAcquisitionOriginalV1>,
) -> Result<&'bytes str, FloorErrorV1> {
    match std::str::from_utf8(bytes) {
        Ok(value) => {
            if let Some(original) = original {
                original.loader_text = Some(Ok(()));
            }
            Ok(value)
        }
        Err(cause) => {
            if let Some(original) = original {
                original.loader_text = Some(Err(cause));
            }
            Err(FloorErrorV1::Provisioning)
        }
    }
}

fn error<T, E: Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
