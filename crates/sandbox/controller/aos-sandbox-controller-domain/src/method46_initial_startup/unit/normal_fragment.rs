//! Binds the selected stopped normal owner's immutable fragment to the Source.
//!
//! The enclosing unit admission prepays this finite acquisition and both posts.
//! PID1's original reported name is resolved independently before and after;
//! the held immutable file must match the same startup profile's exact pin.
//! This establishes fragment provenance, not complete native configuration,
//! executable/runtime admission, job exclusion or provisioning authority.

use super::*;
use aos_sandbox_broker::profile_data::schema::ImagePinV1;

pub(super) struct NormalFragmentOriginalV1 {
    reported: Option<PathBuf>,
    canonical_before: Option<std::io::Result<PathBuf>>,
    canonical_after: Option<std::io::Result<PathBuf>>,
    file: Option<File>,
    open: Option<std::io::Result<()>>,
    acquisition: ImmutableFileAcquisitionOriginalV1,
    measurement: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    file_post: ImmutableFileRevalidationOriginalV1,
    file_after: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
    posted: bool,
    completed: bool,
}

impl NormalFragmentOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            reported: None,
            canonical_before: None,
            canonical_after: None,
            file: None,
            open: None,
            acquisition: ImmutableFileAcquisitionOriginalV1::new(),
            measurement: None,
            file_post: ImmutableFileRevalidationOriginalV1::new(),
            file_after: None,
            entered: false,
            posted: false,
            completed: false,
        }
    }

    pub(super) fn completed(&self) -> bool {
        self.completed && !self.posted
    }

    pub(super) fn observe_once(
        &mut self,
        sample: &ServicePropertiesReadOriginalV2,
        unit: &str,
        pin: &ImagePinV1,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.entered || self.posted {
            self.completed = false;
            return Err(Method46InitialStartupClosedV1);
        }
        self.entered = true;
        let values = sample
            .unit_values_v2()
            .ok_or(Method46InitialStartupClosedV1)?;
        let reported = fragment_values(values.get(1..).ok_or(Method46InitialStartupClosedV1)?)?;
        require_fragment_name(reported, unit)?;
        self.reported = Some(PathBuf::from(reported));
        self.canonical_before = Some(std::fs::canonicalize(reported));
        let canonical = self
            .canonical_before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        require_selected_path(canonical, pin)?;

        self.open = Some(match File::open(reported) {
            Ok(file) => {
                self.file = Some(file);
                Ok(())
            }
            Err(error) => Err(error),
        });
        let file = self.file.take().ok_or(Method46InitialStartupClosedV1)?;
        self.measurement = Some(self.acquisition.measure_original_once(
            canonical.clone(),
            file,
            Some(pin.sha256),
            UNIT_BYTES as u64,
            false,
        ));
        if !matches!(self.measurement, Some(Ok(()))) {
            return Err(Method46InitialStartupClosedV1);
        }
        self.completed = true;
        Ok(())
    }

    pub(super) fn finish_post(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.entered {
            return Ok(());
        }
        if self.posted {
            return Err(Method46InitialStartupClosedV1);
        }
        self.posted = true;
        // Resolve the original name even when measurement or its other post
        // refused. The held-file post cannot hide a changed /etc unit link.
        if let Some(reported) = &self.reported {
            self.canonical_after = Some(std::fs::canonicalize(reported));
        }
        self.file_after = self
            .acquisition
            .observe_available_held_once_v1(&mut self.file_post);
        let before = self
            .canonical_before
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        let after = self
            .canonical_after
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        if !self.completed
            || before.is_none()
            || before != after
            || !matches!(self.file_after, Some(Ok(())))
        {
            return Err(Method46InitialStartupClosedV1);
        }
        Ok(())
    }
}

fn require_selected_path(
    path: &std::path::Path,
    pin: &ImagePinV1,
) -> Result<(), Method46InitialStartupClosedV1> {
    if path.as_os_str().len() > PATH_BYTES || path != std::path::Path::new(&pin.path) {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(())
}

pub(super) fn receiving_demand() -> Option<ResourceVector> {
    ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(PATH_BYTES)?
        .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
        .ok()?
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, (8 * PATH_BYTES + 2 * 4097 + 128) as u64)
                .with(D::OpenFiles, 1)
                .with(D::MetadataEntries, (4 * PATH_BYTES) as u64)
                .with(
                    D::OutputBytes,
                    ImmutableFileAcquisitionOriginalV1::measurement_input_bytes_v1(
                        UNIT_BYTES as u64,
                    )?
                    .checked_add(UNIT_BYTES as u64 + 1)?,
                ),
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_name_must_equal_the_source_profiles_exact_pin() {
        let pin = ImagePinV1 {
            path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-units/aos-storaged.service"
                .into(),
            sha256: [1; 32],
        };
        assert!(require_selected_path(std::path::Path::new(&pin.path), &pin).is_ok());
        for path in [
            "/etc/systemd/system/aos-storaged.service",
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-system-units/aos-storaged.service",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-units/aos-sandboxd.service",
        ] {
            assert!(require_selected_path(std::path::Path::new(path), &pin).is_err());
        }
    }

    #[test]
    fn incomplete_measurement_keeps_its_independently_owed_post_and_refuses_reentry() {
        let mut original = NormalFragmentOriginalV1::new();
        original.entered = true;
        assert!(original.finish_post().is_err());
        assert!(original.posted);
        assert!(!original.completed());
        assert!(original.finish_post().is_err());
        assert!(original.measurement.is_none());
    }

    #[test]
    fn failed_acquisition_still_resolves_the_original_reported_name_again() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let reported = directory.path().join("aos-storaged.service");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        std::os::unix::fs::symlink(&first, &reported).unwrap();

        // Negative prefix only: no Source or immutable measurement is forged.
        let mut original = NormalFragmentOriginalV1::new();
        original.entered = true;
        original.canonical_before = Some(std::fs::canonicalize(&reported));
        original.reported = Some(reported.clone());
        std::fs::remove_file(&reported).unwrap();
        std::os::unix::fs::symlink(&second, &reported).unwrap();

        assert!(original.finish_post().is_err());

        assert_eq!(
            original
                .canonical_before
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap(),
            &first
        );
        assert_eq!(
            original.canonical_after.as_ref().unwrap().as_ref().unwrap(),
            &second
        );
        assert!(original.file_after.is_none());
        assert!(!original.completed());
    }
}
