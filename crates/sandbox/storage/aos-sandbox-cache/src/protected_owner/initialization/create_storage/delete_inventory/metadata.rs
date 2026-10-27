//! Retains finite Source-recorded metadata readers on the actual Cache query.
//!
//! Requests are inert descriptors. Only the already borrowed native Cache
//! supplies their real physical owner; the genuine same-C17 loan pays and
//! rejoins the independently derived reader/decoder peak before native IO.

use super::*;
use crate::physical::delete_metadata::{
    CacheDeleteMetadataModelOriginalV2, CacheDeleteMetadataReadOriginalV2,
};
use aos_sandbox_ledger_replay::delete_graph::{
    DeleteGraphMetadataDataV2, DeleteGraphMetadataRequestDataV2,
};

#[derive(Debug, thiserror::Error)]
enum MetadataFailureV1 {
    #[error(transparent)]
    Geometry(#[from] CacheHeldErrorV1),
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Funding(#[from] ControllerCacheAuditFundingErrorV1),
    #[error(transparent)]
    Read(#[from] crate::physical::delete_metadata::CacheDeleteMetadataReadClosedV2),
    #[error("the actual metadata read order differs")]
    Order,
}

#[derive(Default)]
pub(super) struct CacheDeleteMetadataOriginalsV1<'cache> {
    requests: Option<Vec<DeleteGraphMetadataRequestDataV2>>,
    geometry: Option<Result<ResourceVector, CacheHeldErrorV1>>,
    readers: Vec<CacheDeleteMetadataReadOriginalV2<'cache>>,
    models: Vec<CacheDeleteMetadataModelOriginalV2>,
    expected: usize,
    returned: Option<Result<(), MetadataFailureV1>>,
    prepared: Option<Result<(), MetadataFailureV1>>,
    pub(super) retired: bool,
}

impl CacheDeleteMetadataOriginalsV1<'_> {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.geometry)
            .or_else(|| error(&self.prepared))
            .or_else(|| self.readers.iter().find_map(CacheDeleteMetadataReadOriginalV2::failure))
            .or_else(|| error(&self.returned))
    }

    fn is_positive(&self) -> bool {
        matches!(self.returned, Some(Ok(()))) && self.models.is_empty()
            && self.readers.len() == self.expected
            && self.readers.iter().all(CacheDeleteMetadataReadOriginalV2::is_positive_v2)
    }
}

impl<'cache> CacheDeleteNativeOriginalV1<'cache> {
    /// Parks the actual Source-recorded requests and derives their native peak.
    ///
    /// This performs no read, model allocation or debit. The successful request
    /// Vec moves once from the real Source parser without a forwarding copy.
    ///
    /// # Errors
    /// Refuses repeated preparation or actual physical/decoder geometry failure.
    pub fn capture_metadata_shape_once_v2(
        &mut self,
        requests: Vec<DeleteGraphMetadataRequestDataV2>,
    ) -> Result<ResourceVector, CacheHeldClosedV1> {
        if self.payload.completed_readers != 5 || self.payload.metadata.requests.is_some() {
            return Err(CacheHeldClosedV1);
        }
        self.payload.metadata.expected = requests.len();
        self.payload.metadata.requests = Some(requests);
        self.payload.metadata.geometry = Some(self.metadata_geometry_inner_v2());
        self.payload.metadata.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(CacheHeldClosedV1)
    }

    fn metadata_geometry_inner_v2(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        let requests = self.payload.metadata.requests.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        let mut complete = ResourceVector::ZERO;
        for request in requests {
            let bytes = CacheDeleteMetadataReadOriginalV2::receiving_bytes_v2(self.originals.physical, request)?;
            complete = complete.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?)
                .with(D::OpenFiles, CacheDeleteMetadataReadOriginalV2::opened_file_bound_v2()))?;
        }
        Ok(complete)
    }

    /// Borrows the actual pure geometry error for the old upper error projection.
    ///
    /// This carries no native original, payment or physical read permission.
    pub fn metadata_geometry_failure_v2(&self) -> Option<&CacheHeldErrorV1> {
        self.payload.metadata.geometry.as_ref()?.as_ref().err()
    }

    /// Derives the semantic reader component from these same physical requests.
    ///
    /// # Errors
    /// Refuses missing requests or canonical decoder representation overflow.
    pub fn metadata_semantic_demand_v2(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        let requests = self.payload.metadata.requests.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        let mut bytes = 0usize;
        for request in requests {
            let model = CacheDeleteMetadataReadOriginalV2::semantic_receiving_bytes_v2(request)?;
            bytes = bytes.checked_add(model).ok_or(CacheHeldErrorV1::Order)?;
        }
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?))
    }

    /// Prepares the exact retained arrays after the same physical Source debit.
    ///
    /// # Errors
    /// Retains actual original/shape/admission or allocation refusal, before a
    /// later per-reader nonce result is selected by the upper programme.
    pub fn prepare_metadata_readers_once_v2(
        &mut self,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.payload.metadata.prepared.is_some() { return Err(CacheHeldClosedV1); }
        let result = (|| {
            let complete = self.metadata_geometry_inner_v2()?;
            let semantic = self.metadata_semantic_demand_v2()?;
            self.originals.construction.require_audit_funding_originals_v1(funding)?;
            funding.require_cache_shape_v1(self.identity, complete, semantic)?;
            funding.admit_complete_v1(self.identity, complete)?;
            self.payload.metadata.readers.try_reserve_exact(self.payload.metadata.expected)?;
            self.payload.metadata.models.try_reserve_exact(self.payload.metadata.expected)?;
            Ok::<_, MetadataFailureV1>(())
        })();
        self.payload.metadata.prepared = Some(result);
        if matches!(self.payload.metadata.prepared, Some(Ok(()))) { Ok(()) }
        else { Err(CacheHeldClosedV1) }
    }

    /// Opens and parses the exact requests only under the genuine financial loan.
    ///
    /// The native original independently derives both complete and decoder
    /// demand, rejoins its real Cache Controller, and checks the loan before
    /// reserving either retained Vec or opening the first actual disk entry.
    ///
    /// # Errors
    /// Retains actual affinity, debit, allocation, native, deadline and decoder debt.
    pub fn read_metadata_once_v2(
        &mut self,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
        cutoff: Option<u64>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.payload.metadata.returned.is_some() { return Err(CacheHeldClosedV1); }
        if let Err(cause) = funding.require_named_preparation_v1(self.identity) {
            self.payload.metadata.returned = Some(Err(MetadataFailureV1::Funding(cause)));
            return Err(CacheHeldClosedV1);
        }
        self.payload.metadata.returned = Some(self.read_metadata_inner_v2(cutoff));
        if self.payload.metadata.is_positive() { Ok(()) } else { Err(CacheHeldClosedV1) }
    }

    fn read_metadata_inner_v2(
        &mut self,
        cutoff: Option<u64>,
    ) -> Result<(), MetadataFailureV1> {
        if !matches!(self.payload.metadata.prepared, Some(Ok(()))) {
            return Err(MetadataFailureV1::Order);
        }
        loop {
            let request = self.payload.metadata.requests.as_mut().and_then(Vec::pop);
            let Some(request) = request else { break; };
            let cutoff = cutoff.ok_or(MetadataFailureV1::Order)?;
            self.payload.metadata.readers.push(CacheDeleteMetadataReadOriginalV2::new(
                self.originals.physical, request,
            ));
            let reader = self.payload.metadata.readers.last_mut().ok_or(MetadataFailureV1::Order)?;
            reader.run_once_v2(cutoff)?;
        }
        Ok(())
    }

    /// Returns the actual recorded request count without reading any file.
    pub fn metadata_expected_data_v2(&self) -> usize {
        self.payload.metadata.expected
    }

    /// Returns the complete local reader count without exposing a native owner.
    pub fn metadata_count_data_v2(&self) -> usize {
        self.payload.metadata.readers.len()
    }

    /// Borrows one complete native parse for the existing upper graph fold.
    ///
    /// No successful whole-query or authority claim is inferred before posts.
    pub fn metadata_data_v2(&self, index: usize) -> Option<DeleteGraphMetadataDataV2<'_>> {
        self.payload.metadata.readers.get(index)?.parsed_metadata_data_v2()
    }

    pub(super) fn retire_metadata_after_posts_v2(&mut self) {
        if !self.payload.metadata.is_positive() { std::process::abort(); }
        while let Some(reader) = self.payload.metadata.readers.pop() {
            self.payload.metadata.models.push(reader.complete_after_query_posts_v2());
        }
        self.payload.metadata.retired = true;
    }
}

impl CacheDeleteNativeOriginalV1<'_> {
    /// Borrows array-preparation debt before a later per-reader nonce failure.
    pub fn metadata_preparation_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.payload.metadata.prepared)
    }

    /// Identifies actual same-C17 rejoin debt retained by metadata preparation.
    pub fn metadata_funding_failed_data_v2(&self) -> bool {
        matches!(self.payload.metadata.prepared, Some(Err(MetadataFailureV1::Funding(_))))
            || matches!(self.payload.metadata.returned, Some(Err(MetadataFailureV1::Funding(_))))
    }
}

pub(super) fn control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;

    size_of::<Result<(), MetadataFailureV1>>().checked_mul(6)?
        .checked_add(size_of::<Vec<DeleteGraphMetadataRequestDataV2>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<DeleteGraphMetadataRequestDataV2>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<usize, crate::CacheOwnerErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), ControllerCacheAuditFundingErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&CacheHeldErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<DeleteGraphMetadataDataV2<'_>>>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut CacheDeleteNativeOriginalV1<'_>, &mut ControllerCacheAuditFundingLoanV1<'_, '_>, Option<u64>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&DeleteGraphMetadataRequestDataV2, ResourceVector, usize)>().checked_mul(3)?)
}
