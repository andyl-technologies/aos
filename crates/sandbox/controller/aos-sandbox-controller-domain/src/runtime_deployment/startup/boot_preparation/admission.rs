//! Parks the actual normal initial roles and admits their measured image closure.

use std::os::fd::AsRawFd as _;
use std::path::Path;

use aos_sandbox_broker::profile_data::runtime_deployment::{
    normalize_publisher_unit_data_v1, publisher_profile_comparison_receiving_bytes_v1,
    require_boot_preparation_profile_shape_data_v1,
};
use aos_sandbox_broker::profile_data::schema::ImagePinV1;
use sha2::{Digest as _, Sha256};

use super::*;

const PROFILE_BYTES: usize = 1024 * 1024;
const UNIT_BYTES: usize = 64 * 1024;
const IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const PATH_BYTES: usize = 1024;

impl RuntimeBootPreparationStartupOriginalV1 {
    /// Captures the original normal Source before argv or any upper native IO.
    ///
    /// The complete optional body is prepaid before allocation and before its
    /// native before. Moving original roles is infallible and parks all three
    /// immediately; it cannot release an entered Source on a refused Result.
    ///
    /// # Errors
    /// Retains capture, funding, native-before or exact-role refusal. The caller
    /// still invokes the same independently owed Source after and exits while
    /// this whole original and every later actual 055 owner remain resident.
    pub fn capture_before_arguments_once_v1(
        &mut self,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if self.capture_attempted {
            return Err(self.fail(First::Order));
        }
        self.capture_attempted = true;
        if self.source.get_mut().capture_once_v1().is_err() {
            return Err(self.fail(First::Source));
        }
        let body_bytes = std::mem::size_of::<Body>().checked_mul(2);
        self.fund_additional(body_bytes.and_then(|bytes| {
            Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
        }))?;
        self.body = Some(Box::new(Body::new()));
        if self
            .source
            .get_mut()
            .observe_native_before_once_v1()
            .is_err()
        {
            return Err(self.fail(First::Source));
        }
        self.origin = self
            .source
            .get_mut()
            .origin_comparison_data_v1()
            .ok()
            .copied();
        if self.origin.is_none() {
            return Err(self.fail(First::Source));
        }
        let roles = self
            .source
            .get_mut()
            .take_completed_startup_roles_once_v1()
            .ok_or_else(|| self.fail(First::Source))?;
        let (listener, pid1, profile) = roles.into_parts_v1();
        let body = self.body.as_mut().ok_or(self.closed)?;
        body.listener = Some(RecordSubjectListenerAdmissionAttemptV1::new(listener));
        body.pid1_original = Some(File::from(pid1));
        body.profile_original = Some(File::from(profile));
        Ok(())
    }

    /// Admits the actual normal profile and complete original image closure once.
    ///
    /// No supplied descriptor, profile bytes, mode or currentness scalar enters
    /// this method. The independently provisioned normal purpose and actual055
    /// full fold/NV/currentness remain mandatory later, under this same Source.
    ///
    /// # Errors
    /// Retains every actual listener/profile/image/open/parse/comparison prefix.
    /// Refuses repetition, missing original roles, unsafe immutable files,
    /// foreign complete profiles, altered unit bytes or exhausted same-M funds.
    pub fn admit_once_v1(&mut self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if !self.capture_attempted || self.admitted || self.first.get().is_some() {
            return Err(self.fail(First::Order));
        }
        let result = self.admit_body();
        if result.is_err() {
            self.fail(First::Admission);
        }
        self.body.as_mut().ok_or(self.closed)?.completed = Some(result);
        result?;
        self.admitted = true;
        self.require_current_v1()
    }

    fn admit_body(&mut self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.fail(First::Source))?;
        // Listener admission changes only its own actual original. Source's
        // original four-entry descriptor debt was paid before this handoff.
        self.body
            .as_mut()
            .ok_or(self.closed)?
            .listener
            .as_mut()
            .ok_or(self.closed)?
            .admit_once(Path::new(super::super::super::SOCKET_PATH))
            .map_err(|_| self.closed)?;
        self.admit_profile()?;
        self.admit_initial_image(true)?;
        self.admit_initial_image(false)?;
        let runtime_count = self
            .body
            .as_ref()
            .ok_or(self.closed)?
            .model()?
            .publisher
            .runtime_files
            .len();
        for index in 0..runtime_count {
            self.admit_list_image(false, index)?;
        }
        for index in 0..3 {
            self.admit_list_image(true, index)?;
        }
        self.admit_fragment()?;
        Ok(())
    }

    fn admit_profile(&mut self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let demand = (|| {
            let controls =
                std::mem::size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
            let memory = 4097_usize.checked_mul(2)?.checked_add(128)?;
            let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(PATH_BYTES)?
                .checked_sub(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, u64::try_from(controls).ok()?)
                        .with(D::OpenFiles, 1),
                )
                .ok()?;
            acquisition
                .checked_add(
                    ResourceVector::ZERO
                        .with(
                            D::MemoryBytes,
                            u64::try_from(
                                memory
                                    .checked_add(PROFILE_BYTES.checked_add(1)?.checked_mul(4)?)?,
                            )
                            .ok()?,
                        )
                        .with(D::MetadataEntries, 10)
                        .with(
                            D::OutputBytes,
                            ImmutableFileAcquisitionOriginalV1::materialized_input_bytes_v1(
                                PROFILE_BYTES as u64,
                            )?
                            .checked_add((PROFILE_BYTES as u64).checked_add(1)?)?,
                        ),
                )
                .ok()
        })();
        self.fund_additional(demand.and_then(|demand| {
            demand
                .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
                .ok()
        }))?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        let file = body.profile_original.as_ref().ok_or(self.closed)?;
        body.profile_flags = Some(rustix::fs::fcntl_getfl(file));
        let flags = body
            .profile_flags
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(self.closed)?;
        crate::immutable_image::require_readonly_launch_flags(flags).map_err(|_| self.closed)?;
        body.profile_path = Some(std::fs::read_link(format!(
            "/proc/self/fd/{}",
            file.as_raw_fd()
        )));
        let path = body
            .profile_path
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let name = path.to_str().ok_or(self.closed)?;
        super::super::require_path_shape(name).map_err(|_| self.closed)?;
        if !name.ends_with(super::super::PROFILE_SUFFIX) {
            return Err(self.closed);
        }
        let path = path.clone();
        let file = body.profile_original.take().ok_or(self.closed)?;
        body.profile_measure =
            Some(
                body.profile
                    .measure_original_once(path, file, None, PROFILE_BYTES as u64, false),
            );
        if !matches!(body.profile_measure, Some(Ok(()))) {
            return Err(self.closed);
        }
        body.profile_read = Some(body.profile.read_completed_bounded());
        if !matches!(body.profile_read, Some(Ok(()))) {
            return Err(self.closed);
        }
        let bytes = body.profile.bytes().len();
        let memory = publisher_profile_comparison_receiving_bytes_v1(bytes, UNIT_BYTES, PATH_BYTES);
        self.fund_additional(memory.and_then(|memory| {
            Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
        }))?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        body.decoded = Some(serde_json::from_slice(body.profile.bytes()));
        let model = body.model()?;
        body.shape = Some(require_boot_preparation_profile_shape_data_v1(model));
        if !matches!(body.shape, Some(Ok(()))) {
            return Err(self.closed);
        }
        let model = body.model()?;
        let profile_path = body
            .profile
            .completed_measurement()
            .ok_or(self.closed)?
            .path();
        if profile_path.parent() != Path::new(&model.publisher.effective_matrix.path).parent() {
            return Err(self.closed);
        }
        Ok(())
    }

    fn image_demand(pin: &ImagePinV1, inherited: bool, inline: bool) -> Option<ResourceVector> {
        let mut demand = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(pin.path.len())?;
        if inline {
            let controls =
                std::mem::size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
            demand = demand
                .checked_sub(
                    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(controls).ok()?),
                )
                .ok()?;
        }
        if inherited {
            demand = demand
                .checked_sub(ResourceVector::ZERO.with(D::OpenFiles, 1))
                .ok()?;
        }
        demand
            .checked_add(
                ResourceVector::ZERO
                    .with(
                        D::MemoryBytes,
                        u64::try_from(
                            pin.path
                                .len()
                                .checked_add(std::mem::size_of::<RetainedImmutableFileV1>())?,
                        )
                        .ok()?,
                    )
                    .with(
                        D::MetadataEntries,
                        u64::try_from(Path::new(&pin.path).components().count()).ok()?,
                    )
                    .with(
                        D::OutputBytes,
                        ImmutableFileAcquisitionOriginalV1::measurement_input_bytes_v1(
                            IMAGE_BYTES,
                        )?
                        .checked_add(IMAGE_BYTES.checked_add(1)?)?,
                    ),
            )
            .ok()?
            .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
            .ok()
    }

    fn admit_initial_image(
        &mut self,
        manager: bool,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let model = self.body.as_ref().ok_or(self.closed)?.model()?;
        let pin = if manager {
            &model.publisher.pid1
        } else {
            &model.publisher.executable
        };
        self.fund_additional(Self::image_demand(pin, manager, true))?;
        // Copy only after the actual path/header contribution is paid.
        let path = PathBuf::from(&pin.path);
        let digest = pin.sha256;
        let body = self.body.as_mut().ok_or(self.closed)?;
        if manager {
            let file = body.pid1_original.take().ok_or(self.closed)?;
            body.pid1_measure =
                Some(
                    body.pid1
                        .measure_original_once(path, file, Some(digest), IMAGE_BYTES, false),
                );
            if !matches!(body.pid1_measure, Some(Ok(()))) {
                return Err(self.closed);
            }
        } else {
            body.executable_open = Some(File::open("/proc/self/exe"));
            let opened = match body.executable_open.take() {
                Some(Ok(file)) => file,
                result => {
                    body.executable_open = result;
                    return Err(self.closed);
                }
            };
            body.executable_measure = Some(body.executable.measure_original_once(
                path,
                opened,
                Some(digest),
                IMAGE_BYTES,
                true,
            ));
            if !matches!(body.executable_measure, Some(Ok(()))) {
                return Err(self.closed);
            }
        }
        Ok(())
    }

    fn admit_list_image(
        &mut self,
        evidence: bool,
        index: usize,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let model = self.body.as_ref().ok_or(self.closed)?.model()?;
        let pin = if evidence {
            [
                &model.publisher.canonical_policy,
                &model.publisher.source_policy,
                &model.publisher.effective_matrix,
            ]
            .get(index)
            .copied()
            .ok_or(self.closed)?
        } else {
            model
                .publisher
                .runtime_files
                .get(index)
                .ok_or(self.closed)?
        };
        self.fund_additional(Self::image_demand(pin, false, false))?;
        let path = PathBuf::from(&pin.path);
        let digest = pin.sha256;
        let executable = !evidence
            && (pin.path == model.publisher.executable.path
                || pin.path == model.publisher.loader.path);
        let body = self.body.as_mut().ok_or(self.closed)?;
        let (attempts, files) = if evidence {
            (&mut body.evidence_acquisitions, &mut body.evidence)
        } else {
            (&mut body.runtime_acquisitions, &mut body.runtime)
        };
        body.allocation = Some(attempts.try_reserve_exact(1));
        if !matches!(body.allocation, Some(Ok(()))) {
            return Err(self.closed);
        }
        body.allocation = Some(files.try_reserve_exact(1));
        if !matches!(body.allocation, Some(Ok(()))) {
            return Err(self.closed);
        }
        let posts = if evidence {
            body.evidence_posts.get_mut()
        } else {
            body.runtime_posts.get_mut()
        };
        body.allocation = Some(posts.try_reserve_exact(1));
        if !matches!(body.allocation, Some(Ok(()))) {
            return Err(self.closed);
        }
        posts.push(ImmutableFileRevalidationOriginalV1::new());
        attempts.push(ImmutableFileAcquisitionOriginalV1::new());
        let acquisition = attempts.last_mut().ok_or(self.closed)?;
        acquisition
            .open_and_measure_once(path, Some(digest), IMAGE_BYTES, executable)
            .map_err(|_| self.closed)?;
        let file = acquisition
            .take_completed_measurement_once()
            .ok_or(self.closed)?;
        files.push(file);
        Ok(())
    }

    fn admit_fragment(&mut self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let demand = (|| {
            let header =
                std::mem::size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
            ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(PATH_BYTES)?
                .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(header).ok()?))
                .ok()?
                .checked_add(
                    ResourceVector::ZERO
                        .with(
                            D::MemoryBytes,
                            u64::try_from(
                                4097_usize
                                    .checked_mul(2)?
                                    .checked_add(UNIT_BYTES.checked_mul(4)?)?,
                            )
                            .ok()?,
                        )
                        .with(D::MetadataEntries, 10)
                        .with(
                            D::OutputBytes,
                            ImmutableFileAcquisitionOriginalV1::materialized_input_bytes_v1(
                                UNIT_BYTES as u64,
                            )?
                            .checked_add((UNIT_BYTES as u64).checked_add(1)?)?,
                        ),
                )
                .ok()
        })();
        self.fund_additional(demand.and_then(|demand| {
            demand
                .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
                .ok()
        }))?;
        let origin = self.origin.ok_or(self.closed)?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        body.fragment_path = Some(std::fs::canonicalize(
            "/etc/systemd/system/aos-sandbox-runtime-publisher.service",
        ));
        let path = body
            .fragment_path
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?
            .clone();
        body.fragment
            .open_and_measure_once(
                path,
                Some(origin.unit_fragment_digest),
                UNIT_BYTES as u64,
                false,
            )
            .map_err(|_| self.closed)?;
        body.fragment
            .read_completed_bounded()
            .map_err(|_| self.closed)?;
        let profile = body
            .profile
            .completed_measurement()
            .ok_or(self.closed)?
            .path()
            .to_str()
            .ok_or(self.closed)?;
        body.fragment_normalized = Some(normalize_publisher_unit_data_v1(
            body.fragment.bytes(),
            profile,
        ));
        let normalized = body
            .fragment_normalized
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        if <[u8; 32]>::from(Sha256::digest(normalized)) != body.model()?.publisher.unit_sha256 {
            return Err(self.closed);
        }
        Ok(())
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    pub(super) fn finish_admission_posts_once(&self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let Some(body) = self.body.as_ref() else {
            return Ok(());
        };
        if body.posts_attempted.replace(true) {
            return Err(self.closed);
        }
        let mut posts = body
            .inline_posts
            .try_borrow_mut()
            .map_err(|_| self.closed)?;
        for (index, original) in [&body.profile, &body.pid1, &body.executable, &body.fragment]
            .into_iter()
            .enumerate()
        {
            if matches!(
                original.observe_available_held_once_v1(&mut posts[index]),
                Some(Err(_))
            ) {
                if body.post_failure.get().is_none() {
                    body.post_failure.set(Some((0, index)));
                }
            }
        }
        drop(posts);
        for (plane, attempts, files, posts) in [
            (
                1,
                &body.runtime_acquisitions,
                &body.runtime,
                &body.runtime_posts,
            ),
            (
                2,
                &body.evidence_acquisitions,
                &body.evidence,
                &body.evidence_posts,
            ),
        ] {
            let mut posts = posts.try_borrow_mut().map_err(|_| self.closed)?;
            for (index, original) in attempts.iter().enumerate() {
                let Some(post) = posts.get_mut(index) else {
                    return Err(self.closed);
                };
                let result = match files.get(index) {
                    Some(file) => Some(file.revalidate_retaining(post)),
                    None => original.observe_available_held_once_v1(post),
                };
                if matches!(result, Some(Err(_))) && body.post_failure.get().is_none() {
                    body.post_failure.set(Some((plane, index)));
                }
            }
        }
        if body.post_failure.get().is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }
}
