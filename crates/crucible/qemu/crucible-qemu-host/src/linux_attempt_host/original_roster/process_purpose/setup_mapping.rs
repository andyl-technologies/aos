//! Prices one authenticated setup-region view inside the existing process share.
//!
//! The immutable launch configuration produces geometry before Source birth.
//! This request is retained by the containing incarnation; it creates no bank,
//! descriptor, mapping, deadline or native allocation authority. Native still
//! authenticates its actual setup role and debits the same whole rounded view.
// SPDX-License-Identifier: Apache-2.0

use super::InstalledProcessPurposeError;

/// Keeps expected role extent and its actual host-page-rounded backing request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupMappingRequest {
    region_bytes: u64,
    backing_bytes: u64,
}

impl SetupMappingRequest {
    /// Derives geometry from the same configuration used by the real setup sender.
    ///
    /// # Errors
    /// Refuses invalid layout, absent or non-power-of-two host pages, or overflow.
    pub(crate) fn for_config(
        config: crucible_qemu_shmem::RegionConfig,
    ) -> Result<Self, InstalledProcessPurposeError> {
        let layout = crucible_qemu_shmem::validate_layout_target()
            .and_then(|()| crucible_qemu_shmem::RegionLayout::for_config(config))
            .map_err(|_| InstalledProcessPurposeError::Capacity)?;
        let page = u64::try_from(rustix::param::page_size())
            .map_err(|_| InstalledProcessPurposeError::Capacity)?;
        Self::for_extent(layout.region_size, page)
    }

    fn for_extent(region_bytes: u64, page: u64) -> Result<Self, InstalledProcessPurposeError> {
        if region_bytes == 0 || region_bytes > i64::MAX as u64 || !page.is_power_of_two() {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let backing_bytes = region_bytes
            .checked_add(page - 1)
            .map(|bytes| bytes & !(page - 1))
            .filter(|bytes| *bytes != 0)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        Ok(Self {
            region_bytes,
            backing_bytes,
        })
    }

    pub(super) fn backing_bytes(self) -> u64 {
        self.backing_bytes
    }

    /// Checks the actual role extent before the already-issued carrier is emitted.
    ///
    /// # Errors
    /// Refuses a changed extent or host-page geometry. Equality corroborates the
    /// retained request; it cannot create an incarnation or its containing funds.
    pub(super) fn verify_extent(
        self,
        region_bytes: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        let page = u64::try_from(rustix::param::page_size())
            .map_err(|_| InstalledProcessPurposeError::Capacity)?;
        if Self::for_extent(region_bytes, page)? != self {
            return Err(InstalledProcessPurposeError::Identity);
        }
        Ok(())
    }

    pub(super) fn minimum_resident_bytes(
        self,
        guest: u64,
        controls: u64,
        native_preinit: u64,
        workspace: u64,
    ) -> Result<u64, InstalledProcessPurposeError> {
        guest
            .checked_add(controls)
            .and_then(|bytes| bytes.checked_add(native_preinit))
            .and_then(|bytes| bytes.checked_add(workspace))
            .and_then(|bytes| bytes.checked_add(self.backing_bytes))
            .ok_or(InstalledProcessPurposeError::Capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_partial_pages_charge_the_whole_view_once()
    -> Result<(), InstalledProcessPurposeError> {
        let exact = SetupMappingRequest::for_extent(8192, 4096)?;
        let partial = SetupMappingRequest::for_extent(8193, 4096)?;

        assert_eq!(exact.backing_bytes(), 8192);
        assert_eq!(partial.backing_bytes(), 12288);
        assert_eq!(partial.minimum_resident_bytes(10, 20, 30, 40)?, 12388);
        Ok(())
    }

    #[test]
    fn invalid_or_unrepresentable_requests_refuse_before_a_mapping() {
        for (extent, page) in [
            (0, 4096),
            (1, 0),
            (1, 3),
            (u64::MAX, 4096),
            (i64::MAX as u64 + 1, 4096),
        ] {
            assert!(SetupMappingRequest::for_extent(extent, page).is_err());
        }
    }

    #[test]
    fn the_existing_cap_must_cover_the_new_mapping_request()
    -> Result<(), InstalledProcessPurposeError> {
        let request = SetupMappingRequest::for_extent(1, 4096)?;
        let minimum = request.minimum_resident_bytes(1024, 64, 128, 256)?;

        assert!(minimum > 1024 + 64 + 128 + 256);
        assert_eq!(minimum, 5568);
        assert!(request.minimum_resident_bytes(u64::MAX, 0, 0, 0).is_err());
        Ok(())
    }

    #[test]
    fn launch_layout_and_retained_role_extent_agree() -> Result<(), InstalledProcessPurposeError> {
        let config = crucible_qemu_shmem::RegionConfig::new(1, 64);
        let request = SetupMappingRequest::for_config(config)?;
        let layout = crucible_qemu_shmem::RegionLayout::for_config(config)
            .map_err(|_| InstalledProcessPurposeError::Capacity)?;

        request.verify_extent(layout.region_size)?;
        assert!(request.verify_extent(layout.region_size + 1).is_err());
        Ok(())
    }
}
