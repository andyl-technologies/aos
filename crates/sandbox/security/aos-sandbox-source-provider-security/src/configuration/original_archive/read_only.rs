//! Resident fixed-name readonly public archive readback.
//!
//! Only historical s/e preimages are opened. The selected format is AOSPSI01
//! and deployment format is AOSSPD05, documented by their existing producers.
//! Physical equality and canonical parsing confer no live Source, Session,
//! floor, Root authority, signing custody or successful Drain.

use std::ops::Range;

use aos_sandbox_linux::protected_file::ExactReadFailure;
use aos_sandbox_source_provider_protocol::native_held_completion::SourceSelectedNativeExecutionInputDataV1;

use super::*;
use crate::protected_files::{
    ReadonlyPublicArchiveDirectoryV1, ReadonlyPublicArchiveFileV1, ReadonlyPublicArchiveNameV1,
};

const MAXIMUM_ORIGINAL_BYTES: usize = selected_input::MAXIMUM + DEPLOYMENT_MAXIMUM;

struct SelectedDataV1 {
    deployment: ObjectDigest,
    configuration: ObjectDigest,
    origin: ObjectDigest,
    applying: [u8; 16],
    ordered_digest: [u8; 32],
    frame: SourceSelectedNativeExecutionInputDataV1,
    catalog: Range<usize>,
    backend: Range<usize>,
    dedicated: Range<usize>,
}

struct DeploymentDataV1 {
    configuration: ObjectDigest,
    limits: ObjectDigest,
    projection: ProviderConfigurationDataV5,
    catalog: VerifiedCatalogPublicationV1,
}

/// Owns at most two genuine fixed public files with an irreversible error epoch.
///
/// Every operation prearms failure before its first fallible crossing. A
/// dropped/forgotten operation or unwind cannot reopen this attempt. Original
/// files, partial buffers and available native causes remain in their slots.
pub(crate) struct FixedSourcePublicArchiveReadbackV1 {
    directory: ReadonlyPublicArchiveDirectoryV1,
    selected_file: ReadonlyPublicArchiveFileV1,
    deployment_file: ReadonlyPublicArchiveFileV1,
    selected: Option<(ObjectDigest, SelectedDataV1)>,
    deployment: Option<(ObjectDigest, DeploymentDataV1)>,
    capture: Option<PublicConfigurationCaptureV5>,
    failed: bool,
    first_failure: Option<SourceProviderSecurityError>,
}

impl FixedSourcePublicArchiveReadbackV1 {
    /// Creates empty staging, not a physical owner or positive proof.
    pub(crate) fn new() -> Self {
        Self {
            directory: ReadonlyPublicArchiveDirectoryV1::new(),
            selected_file: ReadonlyPublicArchiveFileV1::new(),
            deployment_file: ReadonlyPublicArchiveFileV1::new(),
            selected: None,
            deployment: None,
            capture: None,
            failed: false,
            first_failure: None,
        }
    }

    /// Opens only the fixed O_PATH archive and parks it before metadata checks.
    ///
    /// # Errors
    ///
    /// Returns the borrowed first refusal; failed epochs cannot perform I/O.
    pub(crate) fn open_fixed(&mut self) -> Result<(), &SourceProviderSecurityError> {
        let result = self.begin().and_then(|()| self.directory.open_fixed());
        self.finish(result)
    }

    /// Reads one selected image without requiring or fabricating Source admission.
    ///
    /// # Errors
    ///
    /// Retains missing/foreign/malformed files, partial reads and late failures.
    pub(crate) fn read_selected(
        &mut self,
        selected: ObjectDigest,
    ) -> Result<(), &SourceProviderSecurityError> {
        let result = self.begin().and_then(|()| self.read_selected_inner(selected));
        self.finish(result)
    }

    fn read_selected_inner(
        &mut self,
        selected: ObjectDigest,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_additional_bound(selected_input::MAXIMUM, self.deployment_file.exact().len())?;
        self.directory.read(
            &mut self.selected_file,
            ReadonlyPublicArchiveNameV1::Selected(selected),
            selected_input::MAXIMUM,
        )?;
        self.require_original_bound()?;

        let exact = self.selected_file.exact();
        require_header(exact, selected_input::MAGIC, selected_input::HEADER)?;
        let deployment = digest_at(exact, 16)?;
        let configuration = digest_at(exact, 48)?;
        let origin = digest_at(exact, 80)?;
        let applying = exact.get(112..128)
            .ok_or(SourceProviderSecurityError::Currentness)?
            .try_into()
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        let ordered_digest = exact.get(128..160)
            .ok_or(SourceProviderSecurityError::Currentness)?
            .try_into()
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        let (frame, catalog, backend, dedicated, _parts) =
            selected_input::selected_body(exact, selected)?;

        self.selected = Some((selected, SelectedDataV1 {
            deployment,
            configuration,
            origin,
            applying,
            ordered_digest,
            frame,
            catalog,
            backend,
            dedicated,
        }));
        self.revalidate_inner()
    }

    /// Reads one E image through the shared public projection/signature engines.
    ///
    /// # Errors
    ///
    /// Retains exact files/capture buffers on structure, signature or late refusal.
    pub(crate) fn read_deployment(
        &mut self,
        deployment: ObjectDigest,
    ) -> Result<(), &SourceProviderSecurityError> {
        let result = self.begin().and_then(|()| self.read_deployment_inner(deployment));
        self.finish(result)
    }

    fn read_deployment_inner(
        &mut self,
        deployment: ObjectDigest,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_additional_bound(DEPLOYMENT_MAXIMUM, self.selected_file.exact().len())?;
        self.directory.read(
            &mut self.deployment_file,
            ReadonlyPublicArchiveNameV1::Deployment(deployment),
            DEPLOYMENT_MAXIMUM,
        )?;
        self.require_original_bound()?;

        let (configuration, limits, parts) =
            deployment_parts(self.deployment_file.exact(), deployment)?;
        self.capture = Some(PublicConfigurationCaptureV5 {
            manifest: parts[0].to_vec(),
            trust: parts[1].to_vec(),
            route: parts[2].to_vec(),
        });
        let capture = self.capture.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let projection = project_public_capture(capture)?;
        let catalog = verify_archived_catalog(&projection, parts[3])?;

        self.deployment = Some((deployment, DeploymentDataV1 {
            configuration,
            limits,
            projection,
            catalog,
        }));
        self.revalidate_inner()
    }

    /// Rechecks the original files and fixed names, never cached currentness.
    ///
    /// # Errors
    ///
    /// Rejects a failed epoch or any physical/byte replacement, preserving custody.
    pub(crate) fn revalidate(&mut self) -> Result<(), &SourceProviderSecurityError> {
        let result = self.begin().and_then(|()| self.revalidate_inner());
        self.finish(result)
    }

    fn revalidate_inner(&mut self) -> Result<(), SourceProviderSecurityError> {
        self.directory.revalidate()?;
        if self.selected.is_some() {
            self.directory.validate_file(&mut self.selected_file)?;
        }
        if self.deployment.is_some() {
            self.directory.validate_file(&mut self.deployment_file)?;
        }
        self.directory.revalidate()
    }

    fn require_original_bound(&self) -> Result<(), SourceProviderSecurityError> {
        let selected = self.selected_file.exact().len();
        let deployment = self.deployment_file.exact().len();
        if selected > selected_input::MAXIMUM
            || deployment > DEPLOYMENT_MAXIMUM
            || selected.checked_add(deployment).is_none_or(|size| size > MAXIMUM_ORIGINAL_BYTES)
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }

    // Charge the other original once before the next named file can grow.
    // Comparison scratch and parsed capture have separate static bounds; this
    // is an original-payload ceiling, not a memory or physical funding proof.
    fn require_additional_bound(
        &self,
        maximum: usize,
        other: usize,
    ) -> Result<(), SourceProviderSecurityError> {
        if maximum.checked_add(other).is_none_or(|size| size > MAXIMUM_ORIGINAL_BYTES) {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<(), SourceProviderSecurityError> {
        if self.failed || self.first_failure.is_some() {
            return Err(SourceProviderSecurityError::Currentness);
        }
        self.failed = true;
        Ok(())
    }

    fn finish(
        &mut self,
        result: Result<(), SourceProviderSecurityError>,
    ) -> Result<(), &SourceProviderSecurityError> {
        match result {
            Ok(()) => {
                self.failed = false;
                Ok(())
            }
            Err(source) => Err(self.first_failure.get_or_insert(source)),
        }
    }

    /// Borrows the first typed refusal without releasing its owner.
    pub(crate) fn first_failure(&self) -> Option<&SourceProviderSecurityError> {
        self.first_failure.as_ref()
    }

    /// Reports negative epoch state only; false is not currentness or Drain.
    pub(crate) const fn failed(&self) -> bool {
        self.failed
    }

    /// Borrows the parsed historical selected frame, including after late failure.
    pub(crate) fn selected_frame(&self) -> Option<&SourceSelectedNativeExecutionInputDataV1> {
        self.selected.as_ref().map(|(_, data)| &data.frame)
    }

    /// Borrows selected E/D/O/Applying/ordered references, never admission proof.
    pub(crate) fn selected_references(&self) -> Option<(
        ObjectDigest, ObjectDigest, ObjectDigest, [u8; 16], [u8; 32],
    )> {
        self.selected.as_ref().map(|(_, data)| {
            (data.deployment, data.configuration, data.origin, data.applying, data.ordered_digest)
        })
    }

    /// Borrows the original selected catalog/backend/dedicated preimages.
    pub(crate) fn selected_preimages(&self) -> Option<(&[u8], &[u8], &[u8])> {
        self.selected.as_ref().map(|(_, data)| {
            let exact = self.selected_file.exact();
            (
                &exact[data.catalog.clone()],
                &exact[data.backend.clone()],
                &exact[data.dedicated.clone()],
            )
        })
    }

    /// Borrows archived projection/signatures without a live owner conversion.
    pub(crate) fn deployment_data(&self) -> Option<(
        ObjectDigest, ObjectDigest, &ProviderConfigurationDataV5, &VerifiedCatalogPublicationV1,
    )> {
        self.deployment.as_ref().map(|(_, data)| {
            (data.configuration, data.limits, &data.projection, &data.catalog)
        })
    }

    /// Borrows actual original read causes; no native error is cloned or replaced.
    pub(crate) fn read_failures(&self) -> (Option<&ExactReadFailure>, Option<&ExactReadFailure>) {
        (self.selected_file.read_failure(), self.deployment_file.read_failure())
    }

    /// Borrows available native child-open/reopen causes separately from policy.
    pub(crate) fn syscall_failures(&self) -> (
        Option<&rustix::io::Errno>, Option<&rustix::io::Errno>,
    ) {
        (self.selected_file.syscall_failure(), self.deployment_file.syscall_failure())
    }

    /// Borrows partial or complete raw DATA; nonempty is not canonical success.
    pub(crate) fn captured_bytes(&self) -> (&[u8], &[u8]) {
        (self.selected_file.exact(), self.deployment_file.exact())
    }

    /// Borrows fallible staging-allocation refusals separately from read causes.
    pub(crate) fn allocation_failures(&self) -> (
        Option<&std::collections::TryReserveError>,
        Option<&std::collections::TryReserveError>,
    ) {
        (self.selected_file.allocation_failure(), self.deployment_file.allocation_failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prearm_and_first_cause_cannot_be_reset_by_later_begin() {
        let mut attempt = FixedSourcePublicArchiveReadbackV1::new();

        attempt.begin().unwrap();
        assert!(attempt.failed());
        assert!(attempt.begin().is_err());
        assert!(attempt.finish(Err(SourceProviderSecurityError::DirectoryPath)).is_err());
        let first = attempt.first_failure().unwrap() as *const SourceProviderSecurityError;
        assert!(attempt.revalidate().is_err());

        assert_eq!(attempt.first_failure().unwrap() as *const SourceProviderSecurityError, first);
        assert!(attempt.selected_frame().is_none());
    }

    #[test]
    fn bounded_pair_is_not_a_current_or_funding_constructor() {
        let attempt = FixedSourcePublicArchiveReadbackV1::new();

        assert_eq!(selected_input::MAXIMUM, 22_958);
        assert_eq!(MAXIMUM_ORIGINAL_BYTES, 22_958 + DEPLOYMENT_MAXIMUM);
        assert!(attempt.require_original_bound().is_ok());
        assert!(attempt.deployment_data().is_none());
        assert!(attempt.read_failures().0.is_none());
    }
}
