//! Authenticates the selected current17 family through completed cold owners.
//!
//! Live writes and code-only loads share immutable declaration checks. The code
//! path retains its real opaque code graph and never queries archived processes.

use super::*;
use crucible_engine::{
    node_adapters::cnp::{CnpSemanticPreparation, PacketCompleteSemanticSource},
    node_admission::CompleteArchiveCodeGraph,
    node_contract::NodeRuntime,
    node_state::CompleteRestoredSettledArchiveValidation,
};

pub(super) enum FactoryPurpose17<'a> {
    OriginalWrite,
    ArchiveCode {
        factory: &'a archive_code::PacketCompleteArchiveCodeFactory,
        graph: &'a Rc<CompleteArchiveCodeGraph>,
    },
}

impl PacketCompleteCaptureFactory {
    pub(super) fn authenticate_restored17_archive_data(
        &self,
        scope: CompleteRestoredSettledArchiveValidation<'_>,
        purpose: FactoryPurpose17<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        if !self.selected_host_capture17_data()? {
            return Err(refused(
                "current17 archive requires the explicit Source3 declaration",
            ));
        }
        let live_runtime = scope.original_write_runtime_data()?;
        match &purpose {
            FactoryPurpose17::OriginalWrite if live_runtime.is_some() => self.current()?,
            FactoryPurpose17::ArchiveCode { factory, graph } if live_runtime.is_none() => {
                factory.authenticate_cold_code_graph(self, graph, scope.graph)?;
            }
            _ => {
                return Err(refused(
                    "current17 factory purpose differs from actual archive origin",
                ));
            }
        }
        authenticate_limits_data(self.limits, scope.archive_limits_data()?)?;
        let maximum = requested_maximum_data(scope.archive_limits_data()?)?;
        let sources = &self.authority.roster().sources;
        let [first, second, third] = sources.as_slice() else {
            return Err(refused("current17 factory Source roster differs"));
        };
        let declarations = [first.as_ref(), second.as_ref(), third.as_ref()];
        let measured = self.authority.capture_graph_policy().measurements();
        let [first_code, second_code, third_code] = measured.as_slice() else {
            return Err(refused(
                "current17 compiled controller measurement roster differs",
            ));
        };
        let controller_executables = [&first_code.host, &second_code.host, &third_code.host];
        let scratch = factory_counter_scratch_data(live_runtime.is_some())?;
        scope.authenticate_production_declaration_data(
            declarations,
            controller_executables,
            self.host.selection(),
            PacketFixtureMeasurements::streaming_scratch_bytes(),
            scratch,
            || {
                live_runtime
                    .map(|runtime| {
                        runtime
                            .original_retained_requested_storage_precredit_scratch_data()
                            .map_err(error)
                    })
                    .transpose()
                    .map(|scratch| scratch.unwrap_or(0))
            },
            || {
                // Every measurement in this closure follows the actual Core
                // prewalk admission, including graph/Source/runtime counters.
                self.authenticate_archive_graph_data(scope.graph)?;
                self.authenticate_archive_common_data(scope.runtime, scope.scheduling)?;
                let mut total =
                    self.actual_archive_daemon_requested_storage(maximum, live_runtime.is_some())?;
                let records = self.records.try_borrow().map_err(error)?;
                total = storage_sum(
                    [
                        total,
                        records
                            .as_ref()
                            .map(PacketCompleteCaptureRecords::retained_bytes)
                            .transpose()?
                            .unwrap_or(0),
                    ],
                    maximum,
                )?;
                drop(records);
                if let FactoryPurpose17::ArchiveCode { factory, graph } = &purpose {
                    total = storage_sum(
                        [
                            total,
                            factory.cold_additional_requested_storage_data(graph, maximum)?,
                        ],
                        maximum,
                    )?;
                }
                if let Some(runtime) = live_runtime {
                    total = storage_sum(
                        [
                            total,
                            runtime
                                .original_retained_requested_storage_precredit_data(maximum)
                                .map_err(error)?,
                        ],
                        maximum,
                    )?;
                }
                for source in sources {
                    let retained = match &purpose {
                        FactoryPurpose17::OriginalWrite => source
                            .original_complete_retained_storage_precredit_data(maximum)
                            .map_err(error)?,
                        FactoryPurpose17::ArchiveCode { .. } => source
                            .original_complete_code_retained_storage_precredit_data(maximum)
                            .map_err(error)?,
                    };
                    total = storage_sum([total, retained], maximum)?;
                }
                Ok(total)
            },
        )?;
        scope.with_completed_production_declaration_data(|completed| {
            if !std::ptr::eq(completed.archive_data(), scope.archive) {
                return Err(refused(
                    "current17 completed declaration crossed archive custody",
                ));
            }
            Ok(())
        })?;
        match purpose {
            FactoryPurpose17::OriginalWrite => self.current(),
            FactoryPurpose17::ArchiveCode { factory, graph } => {
                factory.authenticate_cold_code_graph(self, graph, scope.graph)
            }
        }
    }
}

fn factory_counter_scratch_data(live: bool) -> Result<usize, StateError> {
    let metadata_query = if live {
        let window =
            InstalledConformancePlan::original_restoration_construction_counter_scratch_data()
                .map_err(error)?;
        let node =
            CnpSemanticPreparation::original_conformance_node_retained_counter_scratch_data()
                .map_err(error)?;
        window
            .checked_add(node)
            .ok_or_else(|| refused("current17 factory metadata query overflow"))?
    } else {
        0
    };
    let fixed = size_of::<super::super::retained::Counter>() * 2
        + PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data()
        + NodeRuntime::original_retained_requested_storage_scratch_bytes()
        + CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes()
        + size_of::<[&PacketCompleteSemanticSource; 3]>()
        + size_of::<[&ContentRef; 3]>()
        + size_of::<&[PacketFixtureMeasurements; 3]>()
        + size_of::<FactoryPurpose17<'static>>()
        + size_of::<Option<&NodeRuntime>>()
        + size_of::<Result<usize, crucible_engine::node_contract::RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
        + size_of::<Rc<CompleteArchiveCodeGraph>>()
        + size_of::<std::cell::Ref<'static, Option<PacketCompleteCaptureRecords>>>()
        + size_of::<Result<usize, StateError>>()
        + size_of::<Result<(), StateError>>()
        + size_of::<[usize; 4]>()
        + crucible_node_transport::retained_metadata::original_metadata_observer_layout_bytes();
    metadata_query
        .checked_add(fixed)
        .ok_or_else(|| refused("current17 factory counter overflow"))
}

fn authenticate_limits_data(
    installed: NativeArchiveLimits,
    actual: NativeArchiveLimits,
) -> Result<(), StateError> {
    macro_rules! bound {
        ($family:ident; $($field:ident),+ $(,)?) => {
            $(if actual.$family.$field > installed.$family.$field {
                return Err(refused("current17 archive exceeds the installed factory limits"));
            })+
        };
    }
    bound!(state; maximum_record_bytes, maximum_owners_or_domains, maximum_content_bytes,
        maximum_total_content_bytes, maximum_content_objects, maximum_dependency_edges,
        maximum_dependency_depth, maximum_native_memory_bytes, maximum_native_writable_bytes,
        maximum_native_processes, maximum_native_descriptors);
    bound!(native; maximum_record_bytes, maximum_total_record_bytes, maximum_objects,
        maximum_artifact_bytes, maximum_total_artifact_bytes);
    Ok(())
}

fn storage_sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, StateError> {
    terms.into_iter().try_fold(0usize, |sum, next| {
        sum.checked_add(next)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("current17 factory requested storage exhausted"))
    })
}

fn requested_maximum_data(limits: NativeArchiveLimits) -> Result<usize, StateError> {
    let maximum = usize::try_from(limits.state.maximum_native_memory_bytes)
        .map_err(error)?
        .min(limits.state.maximum_total_content_bytes)
        .min(limits.native.maximum_total_record_bytes);
    if maximum == 0 {
        return Err(refused("current17 factory has no finite storage"));
    }
    Ok(maximum)
}
