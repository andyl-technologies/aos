//! Measures original PID1/self images and owns the separate runtime module.
//!
//! The same startup source pays fixed descriptor/metadata work before native IO,
//! then pays hashing from the retained same-file length before acquisition. The
//! length is a work bound, never image or funding authority. Failed prefixes and
//! independently owed posts remain with their actual startup owner.

use std::fs::Metadata;
use std::path::Path;

use aos_sandbox_broker::immutable_image::ImmutableExecutedFileOriginalV1;
use aos_sandbox_broker::profile_data::schema::ImagePinV1;

use super::*;

const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

mod runtime;
pub(super) use runtime::InitialRuntimeOriginalV1;

pub(super) struct InitialImagesOriginalV1 {
    pid1: ImageOriginalV1,
    executable: ImageOriginalV1,
    manager_execution: [RefCell<ManagerExecutionOriginalV1>; 2],
    manager_execution_paid: bool,
    entered: bool,
}

struct ManagerExecutionOriginalV1 {
    original: ImmutableExecutedFileOriginalV1,
    result: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
}

impl ManagerExecutionOriginalV1 {
    fn new() -> Self {
        Self {
            original: ImmutableExecutedFileOriginalV1::new(),
            result: None,
            entered: false,
        }
    }
}

struct ImageOriginalV1 {
    file: Option<File>,
    open: Option<std::io::Result<()>>,
    metadata: Option<std::io::Result<Metadata>>,
    maximum: Option<u64>,
    acquisition: ImmutableFileAcquisitionOriginalV1,
    measurement: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    preflight_entered: bool,
    post: RefCell<ImagePostOriginalV1>,
}

struct ImagePostOriginalV1 {
    original: ImmutableFileRevalidationOriginalV1,
    incomplete_metadata: Option<std::io::Result<Metadata>>,
    result: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
}

impl ImageOriginalV1 {
    fn new() -> Self {
        Self {
            file: None,
            open: None,
            metadata: None,
            maximum: None,
            acquisition: ImmutableFileAcquisitionOriginalV1::new(),
            measurement: None,
            preflight_entered: false,
            post: RefCell::new(ImagePostOriginalV1 {
                original: ImmutableFileRevalidationOriginalV1::new(),
                incomplete_metadata: None,
                result: None,
                entered: false,
            }),
        }
    }

    fn finish_post(&self) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.preflight_entered {
            return Ok(());
        }
        let mut post = self
            .post
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if post.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        post.entered = true;
        if let Some(file) = self.file.as_ref() {
            // Funding or preflight can refuse before acquisition takes custody.
            // Retain the real held-file post; metadata alone cannot complete an
            // image comparison or permit another measurement attempt.
            post.incomplete_metadata = Some(file.metadata());
            post.result = Some(Err(if matches!(post.incomplete_metadata, Some(Ok(_))) {
                ImmutableImageErrorV1::Provisioning
            } else {
                ImmutableImageErrorV1::Unavailable
            }));
        } else {
            post.result = self
                .acquisition
                .observe_available_held_once_v1(&mut post.original);
        }
        if matches!(post.result, Some(Err(_))) {
            Err(Method46InitialStartupClosedV1)
        } else {
            Ok(())
        }
    }
}

impl InitialImagesOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            pid1: ImageOriginalV1::new(),
            executable: ImageOriginalV1::new(),
            manager_execution: std::array::from_fn(|_| {
                RefCell::new(ManagerExecutionOriginalV1::new())
            }),
            manager_execution_paid: false,
            entered: false,
        }
    }

    pub(super) fn park_pid1(&mut self, file: File) {
        // Only the parent's one-way actual startup-role handoff calls this.
        self.pid1.file = Some(file);
    }

    fn image_mut(&mut self, manager: bool) -> &mut ImageOriginalV1 {
        if manager {
            &mut self.pid1
        } else {
            &mut self.executable
        }
    }

    pub(super) fn finish_posts(&self) -> Result<(), Method46InitialStartupClosedV1> {
        let pid1 = self.pid1.finish_post();
        let executable = self.executable.finish_post();
        let manager = if self.manager_execution_paid {
            self.observe_manager_execution(1)
        } else {
            Ok(())
        };
        // Each reached file owes its own post, including after the other fails.
        pid1.and(executable).and(manager)
    }

    fn observe_manager_execution(
        &self,
        index: usize,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut original = self
            .manager_execution
            .get(index)
            .ok_or(Method46InitialStartupClosedV1)?
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if original.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        original.entered = true;
        // Payment follows positive acquisition. This owner never takes or
        // reenters that acquisition; file posts leave its measurement resident.
        let measured = self
            .pid1
            .acquisition
            .completed_measurement()
            .ok_or(Method46InitialStartupClosedV1)?;
        original.result = Some(measured.require_executed_retaining_v1(1, &mut original.original));
        if matches!(original.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Method46InitialStartupClosedV1)
        }
    }
}

fn manager_execution_demand() -> Option<ResourceVector> {
    // The two native/result headers are already in the prepaid boxed body.
    // Each fixed PID1 probe keeps its own File and bounded "/proc/1/exe" String.
    let one = ResourceVector::ZERO
        .with(D::MemoryBytes, 512)
        .with(D::OpenFiles, 1)
        .with(D::MetadataEntries, 4);
    one.checked_add(one).ok()
}

fn acquisition_demand(pin: &ImagePinV1, maximum: u64) -> Option<ResourceVector> {
    let controls = std::mem::size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
    // The paid boxed body already contains the acquisition header. PID1's FD
    // belongs to Source; the executable FD was separately paid before open.
    let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(pin.path.len())?
        .checked_sub(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(controls).ok()?)
                .with(D::OpenFiles, 1),
        )
        .ok()?;
    acquisition
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(pin.path.len()).ok()?)
                .with(
                    D::MetadataEntries,
                    u64::try_from(Path::new(&pin.path).components().count()).ok()?,
                )
                .with(
                    D::OutputBytes,
                    ImmutableFileAcquisitionOriginalV1::measurement_input_bytes_v1(maximum)?
                        .checked_add(maximum.checked_add(1)?)?,
                ),
        )
        .ok()?
        .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
        .ok()
}

impl Method46InitialStartupOriginalV1 {
    /// Measures the actual inherited manager and executing manual producer once.
    ///
    /// Only the retained original descriptors enter measurement. Fixed native
    /// capture is paid first; retained metadata bounds separately paid digest
    /// work and the owed post. The actual manager's executed inode is compared
    /// with that same inherited file; its independent post is prepaid too.
    /// The decoded image pins are comparison DATA, not
    /// constructors for another descriptor, source or invocation.
    ///
    /// # Errors
    /// Refuses missing positive profile shape, repetition, poison, funding,
    /// changed source, native descriptor/metadata reads or immutable image/hash
    /// comparisons. This step grants no writer, TPM or readiness authority.
    pub fn measure_images_once_v1(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.fail(First::Order));
        }
        let Some(body) = self.body.as_mut() else {
            return Err(self.fail(First::Order));
        };
        if body.images.entered || !matches!(body.profile_shape, Some(Ok(()))) {
            return Err(self.fail(First::Order));
        }
        body.images.entered = true;
        let result = self
            .measure_image(true)
            .and_then(|()| self.measure_image(false))
            .and_then(|()| self.measure_manager_execution());
        if result.is_err() {
            self.fail(First::Image);
        }
        result
    }

    fn measure_manager_execution(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        self.fund_additional(manager_execution_demand())?;
        let images = &mut self.body.as_mut().ok_or(self.closed)?.images;
        images.manager_execution_paid = true;
        images.observe_manager_execution(0)
    }

    fn measure_image(&mut self, manager: bool) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        // Result owners are inline in the already-funded boxed body. Price the
        // bounded native error/path scratch, original open and both metadata
        // observations before any of them can happen.
        self.fund_additional(Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, 2 * 4097 + 128)
                .with(D::OpenFiles, u64::from(!manager))
                .with(D::MetadataEntries, 4),
        ))?;
        let image = self
            .body
            .as_mut()
            .ok_or(self.closed)?
            .images
            .image_mut(manager);
        image.preflight_entered = true;
        if !manager {
            // This is the kernel's actual executing file, never a profile path.
            // Its original File and any raw native error stay co-owned here.
            image.open = Some(match File::open("/proc/self/exe") {
                Ok(file) => {
                    image.file = Some(file);
                    Ok(())
                }
                Err(error) => Err(error),
            });
        }
        let file = image.file.as_ref().ok_or(self.closed)?;
        image.metadata = Some(file.metadata());
        let metadata = image
            .metadata
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let maximum = metadata.len();
        image.maximum = Some(maximum);
        if maximum == 0 || maximum > MAXIMUM_IMAGE_BYTES {
            return Err(self.closed);
        }

        let body = self.body.as_ref().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let pin = if manager {
            &profile.pid1
        } else {
            &profile.executable
        };
        let demand = acquisition_demand(pin, maximum);
        self.fund_additional(demand)?;

        let body = self.body.as_mut().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let pin = if manager {
            &profile.pid1
        } else {
            &profile.executable
        };
        let path = PathBuf::from(&pin.path);
        let expected = pin.sha256;
        let image = body.images.image_mut(manager);
        let file = image.file.take().ok_or(self.closed)?;
        image.measurement = Some(image.acquisition.measure_original_once(
            path,
            file,
            Some(expected),
            maximum,
            true,
        ));
        if !matches!(image.measurement, Some(Ok(()))) {
            return Err(self.closed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn image_work_before_actual_profile_cannot_capture_a_source() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.measure_images_once_v1().is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(matches!(startup.first.get(), Some(First::Order)));
            assert!(!startup.capture_attempted);
            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn image_post_refusal_still_attempts_other_image_and_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        // Inert sinks only, with no descriptor, native capture or authority.
        // A busy first sink must not short-circuit the independently owed ones.
        let mut body = StartupRolesOriginalV1::new();
        body.images.pid1.preflight_entered = true;
        body.images.executable.preflight_entered = true;
        startup.body = Some(Box::new(body));
        let images = &startup.body.as_ref().unwrap().images;
        let held = images.pid1.post.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(images.executable.post.borrow().entered);
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        drop(held);
    }

    #[test]
    fn missing_source_cannot_pay_or_enter_manager_execution_probes() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));
            startup.body = Some(Box::new(StartupRolesOriginalV1::new()));

            assert!(startup.measure_manager_execution().is_err());

            let images = &startup.body.as_ref().unwrap().images;
            assert!(!images.manager_execution_paid);
            assert!(
                images
                    .manager_execution
                    .iter()
                    .all(|probe| !probe.borrow().entered)
            );
            assert!(!startup.capture_attempted);
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn busy_image_post_still_attempts_manager_post_and_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        let mut body = StartupRolesOriginalV1::new();
        // Inert negative sinks check dispatch only; no measured PID1, funding
        // or actual manager-image proof is manufactured by these private flags.
        body.images.pid1.preflight_entered = true;
        body.images.manager_execution_paid = true;
        startup.body = Some(Box::new(body));
        let images = &startup.body.as_ref().unwrap().images;
        let held = images.pid1.post.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(images.manager_execution[1].borrow().entered);
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Image)));
        drop(held);
    }
}
