//! Immutable public selected-input preimages on the existing protected archive.
//!
//! The original Applying transaction remains in the sole physical Journal
//! replay. This image binds its actual origin; it never decodes another Journal
//! or restores a current Session, floor, signing cut or live original owner.
//!
//! ```text
//! AOSPSI01 | version=1 | reserved[6]=0 | E[32] | D[32] | O[32] |
//! Applying-id[16] | ordered-digest[32] | four lengths:u32be |
//! exact AOSNEM01[648] | exact AOSPCZ01 | AOSSPBV1[928] | AOSZHV01[160]
//! ```

use std::ops::Range;

use aos_sandbox_source_provider_protocol::{
    held_snapshot_catalog::MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1,
    native_held_completion::{
        SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1, SourceSelectedNativeExecutionInputDataV1,
    },
};

use super::*;

pub(super) const MAGIC: &[u8; 8] = b"AOSPSI01";
pub(super) const HEADER: usize = 176;
pub(super) const MAXIMUM: usize = HEADER + SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1
    + MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1 + 928 + 160;

const _: () = assert!(MAXIMUM == 22_958);

/// Retains one immutable original selected-input file and borrowed preimages.
///
/// This public-only evidence has no admission constructor, descriptor extractor,
/// signing authority or cold-to-hot conversion.
#[doc(hidden)]
pub struct ProtectedOriginalSelectedInputV1 {
    file: ProtectedPublicArchiveFileV5,
    frame: SourceSelectedNativeExecutionInputDataV1,
    catalog: Range<usize>,
    backend: Range<usize>,
    dedicated: Range<usize>,
}

impl ProtectedOriginalSelectedInputV1 {
    /// Borrows the original canonical comparison frame, never current authority.
    pub const fn frame(&self) -> &SourceSelectedNativeExecutionInputDataV1 {
        &self.frame
    }

    /// Borrows all exact original catalog bytes without a replacement copy.
    pub fn catalog(&self) -> &[u8] {
        &self.file.exact()[self.catalog.clone()]
    }

    /// Borrows the exact original six-role backend enrollment.
    pub fn backend_enrollment(&self) -> &[u8] {
        &self.file.exact()[self.backend.clone()]
    }

    /// Borrows the distinct original dedicated Storage enrollment.
    pub fn dedicated_enrollment(&self) -> &[u8] {
        &self.file.exact()[self.dedicated.clone()]
    }
}

impl ProtectedOriginalConfigurationArchiveV5 {
    /// Syncs the same retained selected inode without reopening or classifying its cause.
    ///
    /// The genuine Source caller parks the native Result before its bookends.
    /// This mechanical operation alone supplies no durability or effect permit.
    ///
    /// # Errors
    ///
    /// Returns the actual native sync failure, including unsupported filesystem behavior.
    #[doc(hidden)]
    pub fn sync_selected_input_file_v1(
        &self,
        selected: &ProtectedOriginalSelectedInputV1,
    ) -> Result<(), rustix::io::Errno> {
        selected.file.sync_original_inode()
    }

    /// Syncs the same held archive directory without reopening or releasing its lock.
    ///
    /// The genuine Source caller brackets this operation with its original cut.
    ///
    /// # Errors
    ///
    /// Returns the actual native directory-sync failure without coarse remapping.
    #[doc(hidden)]
    pub fn sync_selected_input_directory_v1(&self) -> Result<(), rustix::io::Errno> {
        self.directory.sync_original_directory()
    }

    /// Installs selected preimages under a genuine immutable Applying origin.
    ///
    /// The caller retains the returned whole Result before postchecks. The sole
    /// installer can leave an orphan on failure; an image is not membership.
    ///
    /// # Errors
    ///
    /// Refuses foreign origin/Applying bindings, bounds, conflicting immutable
    /// bytes, or changed file/directory custody. No retry or backfill is implied.
    #[doc(hidden)]
    pub fn install_selected_input_v1(
        &mut self,
        origin: &ProtectedOriginalOriginV5,
        admission: &SourceOriginalAdmissionDataV5,
        ordered_digest: [u8; 32],
        frame: &SourceSelectedNativeExecutionInputDataV1,
        catalog: &[u8],
        backend: &[u8],
        dedicated: &[u8],
    ) -> Result<ProtectedOriginalSelectedInputV1, SourceProviderSecurityError> {
        self.require_selected_origin_v1(origin, admission, ordered_digest)?;
        let parts = [frame.as_canonical_bytes().as_slice(), catalog, backend, dedicated];
        let size = selected_size(parts)?;
        self.bound(size)?;

        let mut exact = header(MAGIC);
        for digest in [origin.deployment, origin.configuration, origin.identity] {
            exact.extend_from_slice(digest.as_bytes());
        }
        exact.extend_from_slice(admission.applying_transaction().id());
        exact.extend_from_slice(&ordered_digest);
        for part in parts {
            append_length(&mut exact, part.len())?;
        }
        for part in parts {
            exact.extend_from_slice(part);
        }

        let file = self.directory.install(&filename(b's', frame.digest()), &exact, MAXIMUM)?;
        self.retain_selected_file_v1(file, size, frame.digest(), origin, admission, ordered_digest)
    }

    /// Reads selected preimages only against the actual recovered Applying origin.
    ///
    /// The entire original transaction comes from Core's same physical replay,
    /// not this image's ID/digest. These references alone prove no admission.
    ///
    /// # Errors
    ///
    /// Refuses absent, substituted, malformed, oversized or foreign-origin files.
    #[doc(hidden)]
    pub fn read_selected_input_v1(
        &mut self,
        selected: ObjectDigest,
        origin: &ProtectedOriginalOriginV5,
        admission: &SourceOriginalAdmissionDataV5,
    ) -> Result<ProtectedOriginalSelectedInputV1, SourceProviderSecurityError> {
        let ordered_digest = origin.file.exact().get(160..192)
            .ok_or(SourceProviderSecurityError::Currentness)?
            .try_into().map_err(|_| SourceProviderSecurityError::Currentness)?;
        self.require_selected_origin_v1(origin, admission, ordered_digest)?;
        let name = filename(b's', selected);
        let size = self.directory.bounded_size(&name, MAXIMUM)?;
        if !self.identities.contains(&(b's', selected)) {
            self.bound(size)?;
        }
        let file = self.directory.read(&name, size)?;
        self.retain_selected_file_v1(file, size, selected, origin, admission, ordered_digest)
    }

    // Both routes retain the actual returned readback File. Parsing does not
    // discard it to open another copy; all filesystem work stays in one engine.
    fn retain_selected_file_v1(
        &mut self,
        file: ProtectedPublicArchiveFileV5,
        size: usize,
        selected: ObjectDigest,
        origin: &ProtectedOriginalOriginV5,
        admission: &SourceOriginalAdmissionDataV5,
        ordered_digest: [u8; 32],
    ) -> Result<ProtectedOriginalSelectedInputV1, SourceProviderSecurityError> {
        let exact = file.exact();
        require_header(exact, MAGIC, HEADER)?;
        if exact.len() != size
            || digest_at(exact, 16)? != origin.deployment
            || digest_at(exact, 48)? != origin.configuration
            || digest_at(exact, 80)? != origin.identity
            || exact.get(112..128) != Some(admission.applying_transaction().id().as_slice())
            || exact.get(128..160) != Some(ordered_digest.as_slice())
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let (frame, catalog, backend, dedicated, _parts) = selected_body(exact, selected)?;
        self.retain(b's', selected, exact.len())?;
        self.directory.validate_file(&file)?;
        Ok(ProtectedOriginalSelectedInputV1 { file, frame, catalog, backend, dedicated })
    }

    /// Revalidates the same retained selected file without reopening a live owner.
    ///
    /// # Errors
    ///
    /// Refuses inode, metadata, named-file or exact-byte replacement.
    #[doc(hidden)]
    pub fn validate_selected_input_v1(
        &self,
        selected: &ProtectedOriginalSelectedInputV1,
    ) -> Result<(), SourceProviderSecurityError> {
        self.directory.validate_file(&selected.file)
    }

    fn require_selected_origin_v1(
        &self,
        origin: &ProtectedOriginalOriginV5,
        admission: &SourceOriginalAdmissionDataV5,
        ordered_digest: [u8; 32],
    ) -> Result<(), SourceProviderSecurityError> {
        self.directory.validate_file(&origin.file)?;
        let exact = origin.file.exact();
        let original = admission.admission_comparison().original();
        if origin.configuration != original.configuration_digest
            || digest_at(exact, 16)? != origin.deployment
            || digest_at(exact, 48)? != origin.configuration
            || digest_at(exact, 80)? != original.acquisition_id
            || digest_at(exact, 112)? != original.session_binding
            || exact.get(144..160) != Some(admission.applying_transaction().id().as_slice())
            || exact.get(160..192) != Some(ordered_digest.as_slice())
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }
}

// Context comparisons stay in the Source caller before this allocating body.
// Its returned parts Vec preserves the caller's original allocation/drop
// interval. A readonly caller shares structure, not live admission.
pub(super) fn selected_body<'a>(
    exact: &'a [u8],
    selected: ObjectDigest,
) -> Result<
    (SourceSelectedNativeExecutionInputDataV1, Range<usize>, Range<usize>, Range<usize>, Vec<&'a [u8]>),
    SourceProviderSecurityError,
> {
    let parts = sections(exact, HEADER, 160, 4)?;
    selected_size([parts[0], parts[1], parts[2], parts[3]])?;
    let frame = SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(parts[0])
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    if frame.digest() != selected {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let catalog = (HEADER + parts[0].len())..(HEADER + parts[0].len() + parts[1].len());
    let backend = catalog.end..(catalog.end + parts[2].len());
    let dedicated = backend.end..exact.len();
    Ok((frame, catalog, backend, dedicated, parts))
}

fn selected_size(parts: [&[u8]; 4]) -> Result<usize, SourceProviderSecurityError> {
    if parts[0].len() != SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1
        || parts[1].is_empty() || parts[1].len() > MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1
        || parts[2].len() != 928 || parts[3].len() != 160
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    parts.into_iter().try_fold(HEADER, |size, bytes| {
        size.checked_add(bytes.len()).ok_or(SourceProviderSecurityError::Currentness)
    })
}

#[cfg(test)]
mod tests {
    //! UNRUN framing/bound vectors, never genuine protected-owner fixtures.

    use super::*;

    #[test]
    fn maximum_and_fixed_parts_are_checked_before_image_growth() {
        let frame = [0; 648];
        let catalog = vec![0; MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1];
        let backend = [0; 928];
        let dedicated = [0; 160];

        assert_eq!(selected_size([&frame, &catalog, &backend, &dedicated]).unwrap(), MAXIMUM);
        assert!(selected_size([&frame, &[], &backend, &dedicated]).is_err());
        assert!(selected_size([&frame[..647], &catalog, &backend, &dedicated]).is_err());
        assert!(selected_size([&frame, &catalog, &backend[..927], &dedicated]).is_err());
        let oversized = vec![0; catalog.len() + 1];
        assert!(selected_size([&frame, &oversized, &backend, &dedicated]).is_err());
    }

    #[test]
    fn selected_header_and_sections_reject_reserved_trailing_and_truncated_bytes() {
        let mut bytes = header(MAGIC);
        bytes.resize(HEADER, 0);
        bytes[160..164].copy_from_slice(&1_u32.to_be_bytes());
        bytes.push(7);

        require_header(&bytes, MAGIC, HEADER).unwrap();
        assert!(sections(&bytes[..HEADER], HEADER, 160, 4).is_err());
        assert_eq!(sections(&bytes, HEADER, 160, 4).unwrap()[0], &[7]);
        bytes.push(8);
        assert!(sections(&bytes, HEADER, 160, 4).is_err());
        bytes[10] = 1;
        assert!(require_header(&bytes, MAGIC, HEADER).is_err());
    }

    #[test]
    fn shared_selected_body_refuses_noncanonical_frame_and_extent() {
        let mut exact = header(MAGIC);
        exact.resize(160, 0);
        for length in [648, 1, 928, 160] {
            append_length(&mut exact, length).unwrap();
        }
        exact.resize(HEADER + 648 + 1 + 928 + 160, 0);

        assert!(selected_body(&exact, ObjectDigest::from_bytes([1; 32])).is_err());
        exact.push(0);
        assert!(selected_body(&exact, ObjectDigest::from_bytes([1; 32])).is_err());
    }
}
