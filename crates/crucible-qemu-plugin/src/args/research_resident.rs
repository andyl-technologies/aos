//! Parses the experimental resident class without issuing resource authority.
//!
//! The fixed cancellation slot borrows the original process event. Its numeric
//! value cannot establish event identity, lifetime, or payment; the closed host
//! launch must prove those separately before emitting this tuple.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::{
    ParsedPluginArgs, PluginArgsParseError, PluginInheritedFds, PluginRamControlArgs,
    PluginRamResources,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResearchResidentArgs {
    pub(crate) cancellation_fd: i32,
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(key, "ram_research" | "ram_research_cancel_fd")
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    sim_fd: i32,
    inherited_fds: Option<PluginInheritedFds>,
    control: Option<PluginRamControlArgs>,
    spill_fd: Option<i32>,
    total_metadata: Option<u64>,
    resources: Option<PluginRamResources>,
) -> Result<Option<ResearchResidentArgs>, PluginArgsParseError> {
    match (
        parsed.value("ram_research"),
        parsed.value("ram_research_cancel_fd"),
    ) {
        (None, None) => return Ok(None),
        (Some("kernel-swap-v1"), Some("11")) => {}
        _ => return Err(PluginArgsParseError::InvalidResearchResident),
    }

    if control.is_some()
        || spill_fd.is_some()
        || sim_fd == 11
        || inherited_fds.is_some_and(|fds| fds.shmem_fd == 11 || fds.wake_fd == 11)
        || !resources.is_some_and(|resources| {
            resources.resident_peak_bytes > 0
                && resources.backing_peak_bytes > 0
                && resources.metadata_bytes > 0
                && resources.file_descriptors > 0
                && Some(resources.metadata_bytes) == total_metadata
        })
    {
        return Err(PluginArgsParseError::InvalidResearchResident);
    }

    Ok(Some(ResearchResidentArgs {
        cancellation_fd: 11,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> ParsedPluginArgs<'_> {
        ParsedPluginArgs::parse(text).unwrap()
    }

    fn resources() -> PluginRamResources {
        PluginRamResources {
            resident_peak_bytes: 4096,
            backing_peak_bytes: 4096,
            metadata_bytes: 1024,
            staging_bytes: 0,
            paging_io_slots: 0,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 1,
        }
    }

    #[test]
    fn classification_requires_complete_original_projection() {
        let request = parsed("ram_research=kernel-swap-v1,ram_research_cancel_fd=11");
        let accepted = parse(&request, 3, None, None, None, Some(1024), Some(resources()));
        assert_eq!(
            accepted,
            Ok(Some(ResearchResidentArgs {
                cancellation_fd: 11
            }))
        );
        assert_eq!(
            parse(&request, 3, None, None, None, Some(1024), None),
            Err(PluginArgsParseError::InvalidResearchResident)
        );
        assert_eq!(
            parse(&request, 3, None, None, None, Some(512), Some(resources())),
            Err(PluginArgsParseError::InvalidResearchResident)
        );
        assert_eq!(
            parse(&parsed("simfd=3"), 3, None, None, None, None, None),
            Ok(None)
        );
    }

    #[test]
    fn real_argument_route_retains_total_and_rejects_partial_or_duplicate_tuple() {
        const BASE: &str = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=7,network_tx_next_seq=0,storage_completed_history_epochs=1,storage_completed_history_gaps=1";
        const ENVELOPE: &str = "ram_metadata_budget=1024,ram_resident_peak=4096,ram_backing_peak=4096,ram_metadata_peak=1024,ram_staging_peak=0,ram_io_slots=0,ram_cpu_slots=1,ram_task_slots=1,ram_fd_slots=1";
        let ordinary = super::super::PluginArgs::parse(BASE).unwrap();
        assert_eq!(ordinary.research_resident(), None);

        let request =
            format!("{BASE},{ENVELOPE},ram_research=kernel-swap-v1,ram_research_cancel_fd=11");
        let args = super::super::PluginArgs::parse(&request).unwrap();
        assert_eq!(args.ram_metadata_budget(), Some(1024));
        assert_eq!(
            args.research_resident(),
            Some(ResearchResidentArgs {
                cancellation_fd: 11
            })
        );
        assert_eq!(args.ram_control(), None);

        assert_eq!(
            super::super::PluginArgs::parse(&format!(
                "{BASE},{ENVELOPE},ram_research=kernel-swap-v1"
            )),
            Err(PluginArgsParseError::InvalidResearchResident)
        );
        assert!(matches!(
            super::super::PluginArgs::parse(&format!("{request},ram_research_cancel_fd=11")),
            Err(PluginArgsParseError::DuplicateKey { key }) if key == "ram_research_cancel_fd"
        ));
        assert!(matches!(
            super::super::PluginArgs::parse(&request.replace(
                "ram_metadata_budget=1024",
                "ram_metadata_budget=18446744073709551616"
            )),
            Err(PluginArgsParseError::InvalidRamMetadataBudget)
        ));
    }

    #[test]
    fn partial_unknown_and_aliased_requests_refuse() {
        for text in [
            "ram_research=kernel-swap-v1",
            "ram_research_cancel_fd=11",
            "ram_research=kernel-swap-v2,ram_research_cancel_fd=11",
            "ram_research=kernel-swap-v1,ram_research_cancel_fd=011",
            "ram_research=kernel-swap-v1,ram_research_cancel_fd=12",
        ] {
            assert_eq!(
                parse(
                    &parsed(text),
                    3,
                    None,
                    None,
                    None,
                    Some(1024),
                    Some(resources())
                ),
                Err(PluginArgsParseError::InvalidResearchResident)
            );
        }
        let request = parsed("ram_research=kernel-swap-v1,ram_research_cancel_fd=11");
        for (sim_fd, inherited) in [
            (11, None),
            (
                3,
                Some(PluginInheritedFds {
                    shmem_fd: 11,
                    wake_fd: 12,
                }),
            ),
            (
                3,
                Some(PluginInheritedFds {
                    shmem_fd: 12,
                    wake_fd: 11,
                }),
            ),
        ] {
            assert_eq!(
                parse(
                    &request,
                    sim_fd,
                    inherited,
                    None,
                    None,
                    Some(1024),
                    Some(resources())
                ),
                Err(PluginArgsParseError::InvalidResearchResident)
            );
        }
    }
}
