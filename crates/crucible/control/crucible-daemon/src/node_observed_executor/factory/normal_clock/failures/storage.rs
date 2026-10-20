//! Walks the concrete failed owners without erased publisher/backend callbacks.

use super::*;
use crate::node_qualification::{
    RetainedMetadataCounter as Counter, RetainedMetadataOwned as Owned,
};
use std::{mem::size_of, sync::Arc};

fn unknown() -> QualificationError {
    QualificationError::Refused("unsupported Clock failure owning storage")
}

impl Owned for OriginalClockFailureProgramme {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            origin,
            executions: _,
            publications,
            damage,
        } = self;
        if origin.process != std::process::id() || origin.thread != std::thread::current().id() {
            return Err(unknown());
        }
        counter.charge(origin)?;
        for fixture in publications {
            counter.charge(fixture)?;
        }
        counter.charge(damage)
    }
}

impl Owned for publication::PublicationFailure {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            catalog,
            execution: _,
            after: _,
            blobs,
            refs,
            publisher,
            original,
            error,
            gate,
            unexpected,
            before: _,
            after_status: _,
            report,
            attempted: _,
            complete: _,
        } = self;
        counter.charge(catalog)?;
        counter.charge(original)?;
        counter.charge(error)?;
        counter.charge(gate)?;
        counter.charge(unexpected)?;
        counter.charge(report)?;
        if counter.shared_header(
            Arc::as_ptr(blobs).cast(),
            size_of::<crucible_store::content_store::DirectoryBlobBackend>(),
            std::mem::align_of_val(blobs.as_ref()),
        )? {
            counter.add(
                blobs
                    .retained_configuration_requested_storage_data()
                    .ok_or_else(unknown)?,
            )?;
        }
        if counter.shared_header(
            Arc::as_ptr(refs).cast(),
            size_of::<publication::FaultRefs>(),
            std::mem::align_of_val(refs.as_ref()),
        )? {
            let publication::FaultRefs {
                inner,
                after: _,
                attempted: _,
                placed: _,
            } = refs.as_ref();
            if counter.shared_header(
                Arc::as_ptr(inner).cast(),
                size_of::<crucible_store::content_store::DirectoryRefBackend>(),
                std::mem::align_of_val(inner.as_ref()),
            )? {
                counter.add(inner.retained_configuration_requested_storage_data())?;
            }
        }
        let publication::FailurePublisher {
            stored,
            first,
            returned: _,
            calls: _,
        } = publisher;
        stored.charge_original_directory_storage_data(blobs, refs, counter)?;
        if let Some(first) = first {
            let facts = first
                .retained_requested_storage_data(counter.remaining())
                .map_err(|_| unknown())?;
            counter.core(&facts)?;
        }
        Ok(())
    }
}

impl Owned for damage::DamagedArchive {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            path,
            original_index,
            challenges,
            failures,
            manifest_challenges,
            unexpected_manifest,
            unexpected,
            restored,
            report,
            attempted: _,
            complete: _,
        } = self;
        counter.charge(path)?;
        counter.charge(original_index)?;
        counter.charge(challenges)?;
        counter.charge(manifest_challenges)?;
        if unexpected_manifest.is_some() {
            return Err(unknown());
        }
        counter.add(
            failures
                .capacity()
                .checked_mul(size_of::<crucible_engine::node_state::StateError>())
                .ok_or_else(unknown)?,
        )?;
        for error in failures {
            counter.charge(&error.component)?;
            counter.charge(&error.reason)?;
        }
        counter.add(
            unexpected
                .capacity()
                .checked_mul(size_of::<crucible_engine::node_state::NativeArchiveRecord>())
                .ok_or_else(unknown)?,
        )?;
        for record in unexpected {
            counter.charge(record)?;
        }
        counter.charge(restored)?;
        counter.charge(report)
    }
}

impl OriginalClockFailureProgramme {
    pub(in super::super) fn original_storage_scratch_data(
        &self,
    ) -> Result<usize, QualificationError> {
        if self.origin.process != std::process::id()
            || self.origin.thread != std::thread::current().id()
        {
            return Err(unknown());
        }
        let mut maximum =
            AdmittedGraph::original_retained_requested_storage_precredit_scratch_data();
        for fixture in &self.publications {
            if let Some(run) = &fixture.original {
                if let Some(runtime) = &run.runtime {
                    maximum = maximum.max(
                        runtime
                            .original_retained_requested_storage_precredit_scratch_data()
                            .map_err(|_| unknown())?,
                    );
                }
            }
        }
        maximum
            .checked_add(size_of::<
                crucible_engine::node_contract::RetainedCoreOwnerStorage<'_>,
            >())
            .ok_or_else(unknown)
    }
}
