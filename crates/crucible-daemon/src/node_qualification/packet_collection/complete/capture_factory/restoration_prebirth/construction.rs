//! Observes the actual capsule across fresh graph and inactive runtime construction.
//!
//! Prebirth observers remain strict. This separate raw owner walk never reissues
//! tickets or treats a failed constructor as an empty owner. Unknown failed
//! runtime shapes stop further admission while their original capsule remains.

use super::*;
use crucible::node_contract::{ActivationRecord, RuntimeError};
use std::{
    cell::{BorrowError, Ref},
    mem::{size_of, size_of_val},
};

impl PacketCompleteRestorationPrebirth {
    pub(super) fn construction_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        self.factory
            .authenticate_retained_code_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_fresh_construction_target_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.construction_origin_data()?;
        let Some(graph) = &self.fresh_graph else {
            return self.authenticate_native_startup_target_precredit_data(authority, plan);
        };
        let factory = self
            .fresh_factory
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        if !self.binding_attempted
            || self.failed_runtime.is_some()
            || !graph.plan().is_original_plan_data(plan)
            || !std::ptr::eq(factory.authority.as_ref(), authority)
            || !Rc::ptr_eq(&host, authority.host_source())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.source
            .authenticate_original_construction_plan_data(graph)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn original_fresh_host_node_construction_data(
        &self,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.construction_origin_data()?;
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        let row = self
            .source
            .original_archived_host_node_construction_storage_data(&host, target, maximum)?;
        Ok((
            row.retained_requested_bytes(),
            row.maximum_simultaneous_transient_bytes(),
            row.declared_counter_scratch_bytes(),
        ))
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_construction_source_data(
        &self,
        expected: &Rc<HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.construction_origin_data()?;
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        if !Rc::ptr_eq(&host, expected) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.source
            .retained_original_construction_source_storage_data(&host, maximum)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_construction_holder_data(
        &self,
        original: &Rc<RefCell<Self>>,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.construction_origin_data()?;
        if self.failed_runtime.is_some() || self.host_ticket.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = super::super::super::retained::Counter::new(maximum);
        counter
            .add(
                self.initial15_control
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .retained_requested_storage_data(counter.remaining())?,
            )
            .map_err(storage_error)?;
        counter.rc(original).map_err(storage_error)?;
        if let Some(holder) = &self.report_startup_holder {
            counter.weak(holder).map_err(storage_error)?;
        }
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        counter.rc(&host).map_err(storage_error)?;
        counter
            .add(
                self.source
                    .retained_original_construction_source_storage_data(
                        &host,
                        counter.remaining(),
                    )?,
            )
            .map_err(storage_error)?;
        counter
            .add(
                self.factory
                    .retained_host_precredit_data(counter.remaining())?,
            )
            .map_err(storage_error)?;
        counter.rc(&self.code_graph).map_err(storage_error)?;
        let allowance = counter
            .remaining()
            .checked_add(size_of_val(self.code_graph.as_ref()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let code = self
            .code_graph
            .original_retained_requested_storage_data(allowance)?;
        counter
            .add(
                code.checked_sub(size_of_val(self.code_graph.as_ref()))
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(storage_error)?;
        if let Some(graph) = &self.fresh_graph {
            counter.rc(graph).map_err(storage_error)?;
            counter
                .add(graph.original_retained_storage_precredit_data(counter.remaining())?)
                .map_err(storage_error)?;
        }
        if let Some(factory) = &self.fresh_factory {
            let graph = self
                .fresh_graph
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let archive = self.source.original_construction_source_data(graph)?;
            counter
                .add(
                    factory.original_ticketed_unobserved_restoration_storage_data(
                        archive,
                        counter.remaining(),
                    )?,
                )
                .map_err(storage_error)?;
        }
        if let Some(runtime) = &self.runtime {
            let runtime = runtime.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let graph = self
                .fresh_graph
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            counter
                .add(
                    self.source
                        .retained_original_construction_runtime_storage_data(
                            &runtime,
                            graph,
                            target,
                            counter.remaining(),
                        )?,
                )
                .map_err(storage_error)?;
        }
        if let Some(publication) = &self.publication {
            counter
                .add(publication.retained_storage_data(counter.remaining())?)
                .map_err(storage_error)?;
        }
        self.construction_origin_data()?;
        Ok(counter.bytes())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn original_fresh_construction_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        type Counter = super::super::super::retained::Counter;
        let terms = [
            Self::initial15_control_counter_scratch_data(),
            CollectingCompleteRestorationSource::original_archived_host_node_construction_counter_scratch_data(),
            CollectingCompleteRestorationSource::original_construction_source_counter_scratch_data(),
            PacketCompleteCaptureFactory::original_ticketed_unobserved_counter_scratch_data(),
            ConformanceRuntime::original_fixed_four_inactive_observer_counter_scratch_data()?,
            size_of::<&Self>(), size_of::<&Rc<RefCell<Self>>>(),
            size_of::<&InstalledPacketCompleteCollectionAuthority>(),
            size_of::<&InstalledConformancePlan>(), size_of::<&ActivationRecord>(),
            size_of::<Option<&Rc<ConformanceGraph>>>(), size_of::<&Rc<ConformanceGraph>>(),
            size_of::<Ref<'_, Self>>(), size_of::<Result<Ref<'_, Self>, BorrowError>>(),
            size_of::<Result<Ref<'_, Self>, RuntimeError>>(),
            size_of::<Counter>(), size_of::<Rc<HostSchedulingSource>>(),
            size_of::<&Rc<HostSchedulingSource>>(),
            size_of::<(usize, usize, usize)>(),
            size_of::<Result<(usize, usize, usize), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(), size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(), StateError>>(), size_of::<Result<usize, StateError>>(),
            size_of::<Result<usize, crate::node_qualification::QualificationError>>(),
            size_of::<Result<bool, crate::node_qualification::QualificationError>>(),
            size_of::<Result<(), crate::node_qualification::QualificationError>>(),
            size_of::<Option<&HostSchedulingOwner>>(),
            size_of::<Result<&HostSchedulingOwner, RuntimeError>>(),
            size_of::<Option<&Rc<PacketCompleteCaptureFactory>>>(),
            size_of::<Result<&Rc<PacketCompleteCaptureFactory>, RuntimeError>>(),
            size_of::<Result<&Rc<ConformanceGraph>, RuntimeError>>(),
            size_of::<Option<&std::rc::Weak<RefCell<crate::node_qualification::packet_collection::complete::PacketCompleteReportStartupHolder>>>>(),
            size_of::<Option<usize>>(), size_of::<[usize; 2]>(),
            size_of::<std::array::IntoIter<usize, 2>>(),
            size_of::<&Rc<PacketCompleteCaptureFactory>>(),
            size_of::<&ConformanceRuntime>(), size_of::<&CompleteArchiveCodeGraph>(),
            size_of::<Option<&ConformanceRuntime>>(),
            size_of::<Result<&ConformanceRuntime, RuntimeError>>(),
            size_of::<&publication::OriginalRestorationPublicationOwners>(),
            size_of::<std::slice::Iter<'_, usize>>(), size_of::<&usize>(),
            5 * size_of::<usize>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

fn storage_error(_: crate::node_qualification::QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}
