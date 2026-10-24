//! Derives graph and archive content bounds from the installed scene policy.
//!
//! Measured executables are external byte leaves rather than entries in the
//! small source-authored content map. Their actual positional-read buffer is
//! charged separately before admission. These bounds grant no native action.

use super::*;
use crate::node_qualification::{PacketFixtureArtifact, PacketFixtureMeasurements};
use crucible_engine::node_admission::AdmissionLimits;
use crucible_engine::node_state::NativeArchiveLimits;
use crucible_node_format::ContentRef;
use std::mem::size_of;

pub(super) struct OriginalCompleteContentLimits {
    pub(super) admission: AdmissionLimits,
    pub(super) archive: NativeArchiveLimits,
    pub(super) external_fetch_bytes: usize,
}

impl OriginalCompleteContentLimits {
    pub(super) fn for_holder(
        held: &PacketCompleteReportStartupHolder,
    ) -> Result<Self, RuntimeError> {
        let maximum_total = usize::try_from(held.resources.content_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if maximum_total == 0 {
            return Err(RuntimeError::ResourceLimit);
        }

        let mut external_fetch_bytes = 0usize;
        for measurement in held.authority.graph_policy.measurements() {
            for reference in [&measurement.peer.content, &measurement.host] {
                let extent = file_extent(reference, maximum_total)?;
                external_fetch_bytes = external_fetch_bytes.max(extent);
            }
            for source in &measurement.sources {
                let extent = file_extent(&source.content, maximum_total)?;
                external_fetch_bytes = external_fetch_bytes.max(extent);
            }
        }

        let mut admission = super::graph::limits();
        admission.maximum_content_bytes = admission
            .maximum_content_bytes
            .max(external_fetch_bytes)
            .min(maximum_total);
        // VerifiedContent counts each actual fetch occurrence, including repeat
        // artifacts. It must still refuse if this declared aggregate is spent.
        admission.maximum_total_content_bytes = maximum_total;

        let mut archive = NativeArchiveLimits::default();
        archive.state.maximum_content_bytes = archive
            .state
            .maximum_content_bytes
            .max(external_fetch_bytes)
            .min(maximum_total);
        archive.state.maximum_total_content_bytes = maximum_total;
        Ok(Self {
            admission,
            archive,
            external_fetch_bytes,
        })
    }
}

fn file_extent(reference: &ContentRef, maximum_total: usize) -> Result<usize, RuntimeError> {
    let extent =
        usize::try_from(reference.length.get()).map_err(|_| RuntimeError::ResourceLimit)?;
    // CurrentFiles imposes this independent full-file read ceiling. Keep the
    // prospective route consistent with its actual owner before any allocation.
    if extent == 0 || extent > maximum_total || extent > 512 * 1024 * 1024 {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(extent)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalCompleteContentLimits>()
        + size_of::<Result<OriginalCompleteContentLimits, RuntimeError>>()
        + size_of::<&PacketCompleteReportStartupHolder>()
        + size_of::<&[PacketFixtureMeasurements; 3]>()
        + size_of::<std::slice::Iter<'static, PacketFixtureMeasurements>>()
        + size_of::<&PacketFixtureMeasurements>()
        + size_of::<[&ContentRef; 2]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 2>>()
        + size_of::<&ContentRef>()
        + size_of::<std::slice::Iter<'static, PacketFixtureArtifact>>()
        + size_of::<&PacketFixtureArtifact>()
        + size_of::<AdmissionLimits>()
        + size_of::<NativeArchiveLimits>()
        + 3 * size_of::<usize>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_measured_file_extent_requires_its_own_installed_content_budget() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let mut held = original.borrow_mut();
        let largest = held
            .authority
            .graph_policy
            .measurements()
            .iter()
            .flat_map(|one| [&one.peer.content, &one.host])
            .map(|one| one.length.get())
            .max()
            .unwrap();

        held.resources.content_bytes = crucible_node_format::U64::new(largest);
        let exact = OriginalCompleteContentLimits::for_holder(&held).unwrap();
        assert_eq!(
            exact.external_fetch_bytes,
            usize::try_from(largest).unwrap()
        );
        assert_eq!(
            exact.admission.maximum_total_content_bytes,
            usize::try_from(largest).unwrap()
        );
        assert!(exact.admission.maximum_content_bytes >= exact.external_fetch_bytes);
        assert!(exact.archive.state.maximum_content_bytes >= exact.external_fetch_bytes);

        held.resources.content_bytes =
            crucible_node_format::U64::new(largest.checked_sub(1).unwrap());
        assert!(matches!(
            OriginalCompleteContentLimits::for_holder(&held),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(held.runtime_members.iter().all(|one| one.get().is_none()));
        assert!(held.runtime_owners.borrow().actor.is_none());
        assert!(!held.native_attempted.get());
    }
}
